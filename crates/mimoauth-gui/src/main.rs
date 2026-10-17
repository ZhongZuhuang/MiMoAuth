use std::cell::RefCell;
use std::rc::Rc;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Align, Box as GtkBox, Button, Entry, Image, Label, Orientation, Separator};
use libadwaita::prelude::*;
use libadwaita::{Application as AdwApplication, Window as AdwWindow};
use mimoauth_common::dbus::{
    Auth1ProxyBlocking, FprintDeviceProxyBlocking, FprintManagerProxyBlocking,
};

struct Strings {
    window_title: String,
    title_mimo: String,
    title_ai: String,
    title_user: String,
    brand_mimo: String,
    brand_ai: String,
    brand_user: String,
    default_desc: String,
    cancel: String,
    authenticate: String,
    failed: String,
    expired: String,
    countdown: String,
    password_ph: String,
    cmd_cap: String,
    fingerprint: String,
    fp_prompt: String,
    fp_prompt_sub: String,
    fp_timeout: String,
    fp_touch: String,
    fp_retry: String,
    fp_failed: String,
    fp_busy: String,
}

enum FpEvent {
    Available,
    Busy,
    Retry,
    Failed(&'static str),
    /// 5s with no match — fall back to the password field.
    Fallback,
    Success,
    Expired,
}

fn strings() -> Strings {
    let lang = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    let zh = lang.starts_with("zh");
    if zh {
        Strings {
            window_title: "MiMoAuth 身份验证".into(),
            title_mimo: "MiMo 正在请求权限".into(),
            title_ai: "AI 正在请求权限".into(),
            title_user: "正在请求系统权限".into(),
            brand_mimo: "由 MiMo Desktop 发起".into(),
            brand_ai: "由 AI Agent 发起".into(),
            brand_user: "来自你的终端操作".into(),
            default_desc: "某个程序请求提升权限".into(),
            cancel: "取消".into(),
            authenticate: "认证".into(),
            failed: "密码验证失败，请重试".into(),
            expired: "请求已过期或已取消".into(),
            countdown: "剩余 {s} 秒".into(),
            password_ph: "输入密码以继续".into(),
            cmd_cap: "命令".into(),
            fingerprint: "指纹".into(),
            fp_prompt: "请按指纹传感器".into(),
            fp_prompt_sub: "{s} 秒内未识别将切换为密码输入".into(),
            fp_timeout: "指纹未识别，已切换为密码输入".into(),
            fp_touch: "请触摸指纹传感器…".into(),
            fp_retry: "指纹未识别，请再试一次".into(),
            fp_failed: "指纹验证失败，请改用密码".into(),
            fp_busy: "指纹设备忙，请改用密码".into(),
        }
    } else {
        Strings {
            window_title: "MiMoAuth".into(),
            title_mimo: "MiMo is requesting access".into(),
            title_ai: "AI is requesting access".into(),
            title_user: "Requesting system access".into(),
            brand_mimo: "From MiMo Desktop".into(),
            brand_ai: "From an AI agent".into(),
            brand_user: "From your terminal session".into(),
            default_desc: "A program requests elevated privileges".into(),
            cancel: "Cancel".into(),
            authenticate: "Authenticate".into(),
            failed: "Password verification failed, try again".into(),
            expired: "Request expired or cancelled".into(),
            countdown: "{s}s remaining".into(),
            password_ph: "Password to continue".into(),
            cmd_cap: "Command".into(),
            fingerprint: "Fingerprint".into(),
            fp_prompt: "Touch the fingerprint sensor".into(),
            fp_prompt_sub: "Switching to password input in {s}s".into(),
            fp_timeout: "Not recognized — password input enabled".into(),
            fp_touch: "Touch the fingerprint sensor…".into(),
            fp_retry: "Not recognized — try again".into(),
            fp_failed: "Fingerprint failed — use the password".into(),
            fp_busy: "Fingerprint device busy — use the password".into(),
        }
    }
}

fn parse_auth_id() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--auth-id" {
            return args.next();
        }
        if let Some(id) = a.strip_prefix("--auth-id=") {
            return Some(id.to_string());
        }
    }
    None
}

fn main() {
    let auth_id = match parse_auth_id() {
        Some(id) => id,
        None => {
            eprintln!("usage: mimoauth-gui --auth-id <id>");
            std::process::exit(2);
        }
    };

    let conn = match zbus::blocking::Connection::session() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("session bus unavailable: {e}");
            std::process::exit(1);
        }
    };
    let proxy = match Auth1ProxyBlocking::new(&conn) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot create proxy: {e}");
            std::process::exit(1);
        }
    };
    let (description, command, source, remaining_ms) =
        match proxy.get_pending_request(&auth_id) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("no pending request: {e}");
                std::process::exit(1);
            }
        };

    let s = Rc::new(strings());
    let app = AdwApplication::builder()
        .application_id("org.mimoauth.AuthGui")
        .build();

    app.connect_activate(move |app| {
        let win = build_window(
            app,
            conn.clone(),
            &auth_id,
            &description,
            &command,
            &source,
            remaining_ms,
            s.clone(),
        );
        win.present();
    });

    // Our args (--auth-id) are consumed above; GTK must not parse them.
    app.run_with_args::<&str>(&[]);
}

fn set_msg(label: &Label, text: &str, is_error: bool) {
    label.remove_css_class("error");
    label.remove_css_class("dim-label");
    label.add_css_class(if is_error { "error" } else { "dim-label" });
    label.set_text(text);
    label.set_visible(true);
}

fn fp_fail(tx: &async_channel::Sender<FpEvent>, code: &'static str) {
    let _ = tx.send_blocking(FpEvent::Failed(code));
}

/// Show the fingerprint button only when a reader with enrolled prints exists.
fn probe_fingerprint(tx: async_channel::Sender<FpEvent>) {
    std::thread::spawn(move || {
        // fprintd is a system-bus service.
        let Ok(conn) = zbus::blocking::Connection::system() else {
            eprintln!("fp-probe: system bus unavailable");
            return;
        };
        let Ok(mgr) = FprintManagerProxyBlocking::new(&conn) else {
            eprintln!("fp-probe: no fprintd manager");
            return;
        };
        let dev_path = match mgr.get_default_device() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fp-probe: GetDefaultDevice failed: {e}");
                return;
            }
        };
        if dev_path.as_str() == "/" {
            eprintln!("fp-probe: no fingerprint device");
            return;
        }
        let username = std::env::var("USER").unwrap_or_default();
        let dev = match FprintDeviceProxyBlocking::builder(&conn)
            .path(dev_path.as_str())
            .and_then(|b| b.build())
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("fp-probe: device proxy failed: {e}");
                return;
            }
        };
        match dev.list_enrolled_fingers(&username) {
            Ok(fingers) if !fingers.is_empty() => {
                eprintln!("fp-probe: available ({fingers:?})");
                let _ = tx.send_blocking(FpEvent::Available);
            }
            Ok(fingers) => eprintln!("fp-probe: no enrolled fingers for {username}: {fingers:?}"),
            Err(e) => eprintln!("fp-probe: ListEnrolledFingers failed: {e}"),
        }
    });
}

/// Async fprintd verification: 5s total window, then fall back to password.
fn fingerprint_worker(
    auth_id: String,
    tx: async_channel::Sender<FpEvent>,
    fp_timeout_secs: u64,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("fp-worker: runtime: {e}");
                fp_fail(&tx, "dbus");
                return;
            }
        };
        rt.block_on(async move {
            if let Err(e) = run_fp_verify(&auth_id, &tx, fp_timeout_secs).await {
                eprintln!("fp-worker: {e}");
            }
        });
    });
}

async fn run_fp_verify(
    auth_id: &str,
    tx: &async_channel::Sender<FpEvent>,
    fp_timeout_secs: u64,
) -> Result<(), String> {
    use futures_util::StreamExt;
    use mimoauth_common::dbus::{Auth1Proxy, FprintDeviceProxy, FprintManagerProxy};
    use std::time::Duration;

    // fprintd lives on the system bus; the grant goes over the session bus.
    let conn = zbus::Connection::system()
        .await
        .map_err(|e| format!("system bus: {e}"))?;
    let mgr = FprintManagerProxy::new(&conn)
        .await
        .map_err(|e| format!("manager: {e}"))?;
    let dev_path = mgr
        .get_default_device()
        .await
        .map_err(|e| format!("GetDefaultDevice: {e}"))?;
    if dev_path.as_str() == "/" {
        fp_fail(tx, "no-device");
        return Err("no fingerprint device".into());
    }
    let dev = FprintDeviceProxy::builder(&conn)
        .path(dev_path.as_str())
        .map_err(|e| format!("proxy path: {e}"))?
        .build()
        .await
        .map_err(|e| format!("proxy build: {e}"))?;

    let username = std::env::var("USER").unwrap_or_default();
    if let Err(e) = dev.claim(&username).await {
        fp_fail(tx, "busy");
        return Err(format!("Claim({username}): {e}"));
    }

    // fprintd >= 1.90: VerifyStart takes a FINGER name; mirror fprintd-verify.
    let fingers = match dev.list_enrolled_fingers(&username).await {
        Ok(f) if f.is_empty() => {
            let _ = dev.release().await;
            fp_fail(tx, "no-device");
            return Err(format!("no enrolled fingers for {username}"));
        }
        Ok(f) => f,
        Err(e) => {
            let _ = dev.release().await;
            fp_fail(tx, "dbus");
            return Err(format!("ListEnrolledFingers: {e}"));
        }
    };
    let finger = fingers[0].clone();

    // Subscribe before VerifyStart so the first signal cannot be lost.
    let mut stream = dev
        .receive_verify_status()
        .await
        .map_err(|e| format!("signal stream: {e}"))?;
    if let Err(e) = dev.verify_start(&finger).await {
        let _ = dev.release().await;
        fp_fail(tx, "dbus");
        return Err(format!("VerifyStart({finger}): {e}"));
    }
    eprintln!("fp-worker: verify started on {finger}");
    let _ = tx.send_blocking(FpEvent::Busy);

    let session = zbus::Connection::session().await.ok();
    let auth = match &session {
        Some(c) => Auth1Proxy::new(c).await.ok(),
        None => None,
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(fp_timeout_secs.max(1));
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            // No match within 5s: stop cleanly and switch to password input.
            Err(_) => {
                eprintln!("fp-worker: 5s deadline — falling back to password");
                let _ = dev.verify_stop().await;
                let _ = dev.release().await;
                let _ = tx.send_blocking(FpEvent::Fallback);
                return Ok(());
            }
            Ok(None) => {
                let _ = dev.release().await;
                fp_fail(tx, "dbus");
                return Err("signal stream ended".into());
            }
            Ok(Some(sig)) => {
                let args = sig.args().map_err(|e| format!("signal args: {e}"))?;
                let status = args.status().to_string();
                let success = *args.success();
                match (status.as_str(), success) {
                    (_, true) => {
                        let granted = match &auth {
                            Some(p) => p
                                .fingerprint_result(auth_id, true)
                                .await
                                .ok()
                                .map(|(ok, _)| ok)
                                .unwrap_or(false),
                            None => false,
                        };
                        let _ = dev.release().await;
                        if granted {
                            let _ = tx.send_blocking(FpEvent::Success);
                            return Ok(());
                        }
                        let _ = tx.send_blocking(FpEvent::Expired);
                        return Ok(());
                    }
                    // "waiting for finger" notice — keep waiting.
                    ("verify-start", false) => continue,
                    ("verify-error", _) | ("verify-disconnected", _) => {
                        let _ = dev.release().await;
                        fp_fail(tx, "dbus");
                        return Err(format!("fatal verify status {status}"));
                    }
                    (_, false) => {
                        eprintln!("fp-worker: not recognized ({status})");
                        let _ = tx.send_blocking(FpEvent::Retry);
                    }
                }
            }
        }
    }
}

fn field(parent: &GtkBox, caption: &str, value: &str) {
    let cap = Label::new(Some(caption));
    cap.add_css_class("dim-label");
    cap.add_css_class("caption");
    cap.set_halign(Align::Start);
    parent.append(&cap);

    let val = Label::new(Some(value));
    val.add_css_class("monospace");
    val.set_halign(Align::Start);
    val.set_selectable(true);
    val.set_wrap(true);
    val.set_wrap_mode(gtk4::pango::WrapMode::Word);
    parent.append(&val);
}

#[allow(clippy::too_many_arguments)]
fn build_window(
    app: &AdwApplication,
    conn: zbus::blocking::Connection,
    auth_id: &str,
    description: &str,
    command: &str,
    source: &str,
    remaining_ms: u64,
    s: Rc<Strings>,
) -> AdwWindow {
    let win = AdwWindow::builder()
        .application(app)
        .default_width(460)
        .default_height(340)
        .title(s.window_title.as_str())
        .build();

    // Fingerprint→password fallback window is user-configurable
    // (~/.config/mimoauth/config.toml → fingerprint_timeout_secs).
    let fp_timeout_secs = mimoauth_common::config::Config::load()
        .fingerprint_timeout_secs
        .clamp(1, 120);

    let root = GtkBox::new(Orientation::Vertical, 12);
    root.set_margin_top(26);
    root.set_margin_bottom(20);
    root.set_margin_start(26);
    root.set_margin_end(26);

    // --- header: per-source icon + title (mimo / ai / user) --------------
    let header = GtkBox::new(Orientation::Horizontal, 14);
    let theme =
        gtk4::IconTheme::for_display(&gtk4::gdk::Display::default().expect("display"));
    let pick = |candidates: &'static [&'static str]| -> &'static str {
        candidates
            .iter()
            .find(|n| theme.has_icon(n))
            .copied()
            .unwrap_or("computer-symbolic")
    };
    let icon_name = match source {
        // MiMo and other agents share the machine/robot look; users get a terminal.
        "mimo" | "ai" => pick(&["bot-symbolic", "robot-symbolic", "computer-symbolic"]),
        _ => pick(&[
            "utilities-terminal-symbolic",
            "accessories-terminal-symbolic",
            "system-run-symbolic",
        ]),
    };
    let icon = Image::from_icon_name(icon_name);
    icon.set_pixel_size(44);
    icon.set_valign(Align::Center);
    header.append(&icon);

    let titles = GtkBox::new(Orientation::Vertical, 3);
    titles.set_valign(Align::Center);
    let (title_text, brand_text) = match source {
        "mimo" => (s.title_mimo.as_str(), s.brand_mimo.as_str()),
        "ai" => (s.title_ai.as_str(), s.brand_ai.as_str()),
        _ => (s.title_user.as_str(), s.brand_user.as_str()),
    };
    let title = Label::new(Some(title_text));
    title.add_css_class("title-1");
    title.set_halign(Align::Start);
    titles.append(&title);
    let brand = Label::new(Some(brand_text));
    brand.add_css_class("dim-label");
    brand.set_halign(Align::Start);
    titles.append(&brand);
    header.append(&titles);
    root.append(&header);

    // --- what is being requested ----------------------------------------
    let desc = Label::new(Some(if description.is_empty() {
        s.default_desc.as_str()
    } else {
        description
    }));
    desc.set_wrap(true);
    desc.set_halign(Align::Start);
    desc.add_css_class("heading");
    root.append(&desc);

    root.append(&Separator::new(Orientation::Horizontal));

    // --- the operation being authorized -----------------------------------
    if !command.is_empty() {
        let info = GtkBox::new(Orientation::Vertical, 10);
        field(&info, &s.cmd_cap, command);
        root.append(&info);
    }

    let error_label = Label::new(None);
    error_label.add_css_class("error");
    error_label.set_visible(false);
    error_label.set_wrap(true);
    error_label.set_halign(Align::Start);
    root.append(&error_label);

    // --- fingerprint prompt (shown instead of the password field) ---------
    let fp_prompt = GtkBox::new(Orientation::Horizontal, 12);
    fp_prompt.set_visible(false);
    let fp_big_icon = Image::from_icon_name("auth-fingerprint-symbolic");
    fp_big_icon.set_pixel_size(32);
    fp_big_icon.set_valign(Align::Center);
    fp_prompt.append(&fp_big_icon);
    let fp_text_col = GtkBox::new(Orientation::Vertical, 2);
    let fp_label = Label::new(Some(s.fp_touch.as_str()));
    fp_label.add_css_class("heading");
    fp_label.set_halign(Align::Start);
    fp_text_col.append(&fp_label);
    let fp_sub = Label::new(Some(
        &s.fp_prompt_sub.replace("{s}", &fp_timeout_secs.to_string()),
    ));
    fp_sub.add_css_class("dim-label");
    fp_sub.add_css_class("caption");
    fp_sub.set_halign(Align::Start);
    fp_text_col.append(&fp_sub);
    fp_prompt.append(&fp_text_col);
    root.append(&fp_prompt);

    // --- password ---------------------------------------------------------
    let entry = Entry::new();
    entry.set_placeholder_text(Some(s.password_ph.as_str()));
    entry.set_visibility(false);
    entry.set_invisible_char(Some('•'));
    entry.set_hexpand(true);
    entry.set_margin_top(2);
    entry.set_primary_icon_name(Some("input-keyboard-symbolic"));
    entry.set_icon_from_icon_name(
        gtk4::EntryIconPosition::Primary,
        Some("input-keyboard-symbolic"),
    );
    entry.set_secondary_icon_name(Some("view-reveal-symbolic"));
    root.append(&entry);

    // --- countdown + actions ---------------------------------------------
    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    buttons.set_margin_top(4);
    let countdown = Label::new(None);
    countdown.add_css_class("dim-label");
    countdown.set_valign(Align::Center);
    countdown.set_halign(Align::Start);
    countdown.set_xalign(0.0);
    countdown.set_hexpand(true);
    buttons.append(&countdown);

    // Fingerprint action: icon + label (icon degrades to text-only).
    let fp_button = {
        let b = Button::new();
        b.add_css_class("flat");
        let row = GtkBox::new(Orientation::Horizontal, 6);
        let theme =
            gtk4::IconTheme::for_display(&gtk4::gdk::Display::default().expect("display"));
        if let Some(icon_name) = ["auth-fingerprint-symbolic", "fingerprint-symbolic"]
            .iter()
            .find(|n| theme.has_icon(n))
        {
            let img = Image::from_icon_name(icon_name);
            img.set_pixel_size(16);
            img.set_valign(Align::Center);
            row.append(&img);
        }
        row.append(&Label::new(Some(s.fingerprint.as_str())));
        b.set_child(Some(&row));
        b
    };
    fp_button.set_valign(Align::Center);
    fp_button.set_visible(false);
    buttons.append(&fp_button);

    let cancel_btn = Button::with_label(&s.cancel);
    cancel_btn.add_css_class("flat");
    cancel_btn.set_valign(Align::Center);
    buttons.append(&cancel_btn);

    let auth_btn = Button::with_label(&s.authenticate);
    auth_btn.add_css_class("suggested-action");
    auth_btn.set_valign(Align::Center);
    buttons.append(&auth_btn);
    root.append(&buttons);

    win.set_content(Some(&root));
    // Hint to compositors that this is a dialog (they may float it).
    win.set_modal(true);


    // --- countdown -------------------------------------------------------
    let remaining = Rc::new(RefCell::new(remaining_ms));
    let countdown_c = countdown.clone();
    let s_c = s.clone();
    let win_c = win.clone();
    glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
        let mut left = remaining.borrow_mut();
        if *left <= 500 {
            countdown_c.set_text("…");
            win_c.close();
            return glib::ControlFlow::Break;
        }
        *left -= 500;
        let secs = (*left + 999) / 1000;
        countdown_c.set_text(&s_c.countdown.replace("{s}", &secs.to_string()));
        glib::ControlFlow::Continue
    });
    countdown.set_text(
        &s.countdown
            .replace("{s}", &((remaining_ms + 999) / 1000).to_string()),
    );

    // --- fingerprint: probe first, then verify by default for 5s ----------
    let (fp_tx, fp_rx) = async_channel::unbounded::<FpEvent>();
    let fp_available = Rc::new(RefCell::new(false));
    probe_fingerprint(fp_tx.clone());
    {
        let fp_button = fp_button.clone();
        let fp_prompt = fp_prompt.clone();
        let fp_label = fp_label.clone();
        let entry = entry.clone();
        let error_label = error_label.clone();
        let s = s.clone();
        let win = win.clone();
        let fp_tx = fp_tx.clone();
        let fp_available = fp_available.clone();
        let auth_id = auth_id.to_string();
        glib::spawn_future_local(async move {
            while let Ok(ev) = fp_rx.recv().await {
                match ev {
                    // Reader exists — jump straight into fingerprint mode.
                    FpEvent::Available => {
                        *fp_available.borrow_mut() = true;
                        fp_button.set_visible(true);
                        entry.set_visible(false);
                        fp_button.set_visible(false);
                        fp_prompt.set_visible(true);
                        fp_label.set_text(&s.fp_prompt);
                        error_label.set_visible(false);
                        fingerprint_worker(auth_id.clone(), fp_tx.clone(), fp_timeout_secs);
                    }
                    FpEvent::Busy => fp_label.set_text(&s.fp_prompt),
                    FpEvent::Retry => fp_label.set_text(&s.fp_retry),
                    FpEvent::Failed(code) => {
                        // Back to password mode. "busy"/transient errors keep the
                        // button for another try; a missing reader hides it for
                        // good (no fingerprint hardware → no fingerprint UI).
                        fp_prompt.set_visible(false);
                        entry.set_visible(true);
                        entry.grab_focus();
                        if code == "no-device" {
                            *fp_available.borrow_mut() = false;
                            fp_button.set_visible(false);
                        } else {
                            fp_button.set_sensitive(true);
                            if *fp_available.borrow() {
                                fp_button.set_visible(true);
                            }
                        }
                        let text = match code {
                            "busy" => &s.fp_busy,
                            _ => &s.fp_failed,
                        };
                        set_msg(&error_label, text, true);
                    }
                    FpEvent::Fallback => {
                        fp_prompt.set_visible(false);
                        entry.set_visible(true);
                        entry.grab_focus();
                        fp_button.set_sensitive(true);
                        if *fp_available.borrow() {
                            fp_button.set_visible(true);
                        }
                        set_msg(&error_label, &s.fp_timeout, false);
                    }
                    FpEvent::Success | FpEvent::Expired => win.close(),
                }
            }
        });
    }
    {
        let fp_button_c = fp_button.clone();
        let fp_tx_c = fp_tx.clone();
        let auth_id_c = auth_id.to_string();
        let entry_c = entry.clone();
        let fp_prompt_c = fp_prompt.clone();
        let fp_label_c = fp_label.clone();
        let error_label_c = error_label.clone();
        let s_c = s.clone();
        let fp_timeout_secs_c = fp_timeout_secs;
        fp_button.connect_clicked(move |_| {
            fp_button_c.set_visible(false);
            entry_c.set_visible(false);
            error_label_c.set_visible(false);
            fp_prompt_c.set_visible(true);
            fp_label_c.set_text(&s_c.fp_touch);
            fingerprint_worker(auth_id_c.clone(), fp_tx_c.clone(), fp_timeout_secs_c);
        });
    }

    // --- peek icon toggle ------------------------------------------------
    let entry_c = entry.clone();
    entry.connect_icon_press(move |_, pos| {
        if pos == gtk4::EntryIconPosition::Secondary {
            let shown = gtk4::prelude::EntryExt::is_visible(&entry_c);
            entry_c.set_visibility(!shown);
            entry_c.set_secondary_icon_name(Some(if shown {
                "view-reveal-symbolic"
            } else {
                "view-conceal-symbolic"
            }));
        } else {
            entry_c.grab_focus();
        }
    });

    // --- submit ----------------------------------------------------------
    let busy = Rc::new(RefCell::new(false));

    let submit = {
        let auth_id = auth_id.to_string();
        let proxy_conn = conn.clone();
        let entry = entry.clone();
        let auth_btn = auth_btn.clone();
        let cancel_btn = cancel_btn.clone();
        let error_label = error_label.clone();
        let s = s.clone();
        let busy = busy.clone();
        let win = win.clone();
        move || {
            if *busy.borrow() {
                return;
            }
            let password = entry.text().to_string();
            if password.is_empty() {
                return;
            }
            *busy.borrow_mut() = true;
            entry.set_sensitive(false);
            auth_btn.set_sensitive(false);
            cancel_btn.set_sensitive(false);
            fp_button.set_sensitive(false);
            error_label.set_visible(false);

            let (tx, rx) = async_channel::unbounded();
            let auth_id2 = auth_id.clone();
            let pc = proxy_conn.clone();
            std::thread::spawn(move || {
                let r = Auth1ProxyBlocking::new(&pc)
                    .and_then(|p| p.submit_password(&auth_id2, &password));
                let _ = tx.send_blocking(r);
            });

            let entry = entry.clone();
            let auth_btn = auth_btn.clone();
            let cancel_btn = cancel_btn.clone();
            let error_label = error_label.clone();
            let fp_button = fp_button.clone();
            let s = s.clone();
            let busy = busy.clone();
            let win = win.clone();
            glib::spawn_future_local(async move {
                let result = rx.recv().await.unwrap_or(Err(zbus::Error::Failure(
                    "worker died".into(),
                )));
                match result {
                    Ok((true, _)) => win.close(),
                    Ok((false, reason)) => {
                        let msg = if reason == "expired" || reason == "not-found" {
                            s.expired.clone()
                        } else {
                            s.failed.clone()
                        };
                        set_msg(&error_label, &msg, true);
                        entry.set_text("");
                        entry.set_sensitive(true);
                        entry.grab_focus();
                        auth_btn.set_sensitive(true);
                        cancel_btn.set_sensitive(true);
                        *busy.borrow_mut() = false;
                    }
                    Err(e) => {
                        set_msg(&error_label, &format!("DBus error: {e}"), true);
                        entry.set_sensitive(true);
                        auth_btn.set_sensitive(true);
                        cancel_btn.set_sensitive(true);
                        fp_button.set_sensitive(true);
                        *busy.borrow_mut() = false;
                    }
                }
            });
        }
    };

    entry.connect_activate({
        let submit = submit.clone();
        move |_| submit()
    });
    auth_btn.connect_clicked({
        let submit = submit.clone();
        move |_| submit()
    });

    // --- cancel ----------------------------------------------------------
    {
        let auth_id = auth_id.to_string();
        let conn = conn.clone();
        let win = win.clone();
        cancel_btn.connect_clicked(move |_| {
            let auth_id = auth_id.clone();
            let conn = conn.clone();
            std::thread::spawn(move || {
                if let Ok(p) = Auth1ProxyBlocking::new(&conn) {
                    let _ = p.cancel_auth(&auth_id);
                }
            });
            win.close();
        });
    }

    // --- close: tell daemon --------------------------------------------
    {
        let auth_id = auth_id.to_string();
        let conn = conn.clone();
        win.connect_close_request(move |_| {
            let auth_id = auth_id.clone();
            let conn = conn.clone();
            std::thread::spawn(move || {
                if let Ok(p) = Auth1ProxyBlocking::new(&conn) {
                    let _ = p.cancel_auth(&auth_id);
                }
            });
            glib::Propagation::Proceed
        });
    }

    // Esc = cancel (close-request above notifies the daemon).
    {
        let win_c = win.clone();
        let keys = gtk4::EventControllerKey::new();
        keys.connect_key_pressed(move |_, key, _code, _state| {
            if key == gtk4::gdk::Key::Escape {
                win_c.close();
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        win.add_controller(keys);
    }

    entry.grab_focus();
    win
}
