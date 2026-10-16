use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use mimoauth_common::dbus::Auth1ProxyBlocking;
use mimoauth_common::{AuthStatus, Outcome, RequestResult};

#[derive(Parser)]
#[command(
    name = "mimoauthctl",
    about = "MiMoAuth control tool — request, query and revoke system authorizations",
    version
)]
struct Cli {
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

/// Who is requesting elevation (dialog title/icon differ per source).
#[derive(Clone, Copy, ValueEnum)]
enum Source {
    /// The MiMo Desktop assistant
    Mimo,
    /// Another AI agent (Claude Code, codex, …)
    Ai,
    /// The human user at a terminal (sudo etc.)
    User,
}

impl Source {
    fn as_str(&self) -> &'static str {
        match self {
            Source::Mimo => "mimo",
            Source::Ai => "ai",
            Source::User => "user",
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Request authorization and wait for the result (prompts the auth dialog)
    Request {
        /// Policy action id, e.g. org.example.packagekit.install
        action: String,
        /// Human-readable description shown in the dialog
        #[arg(long, default_value = "")]
        description: String,
        /// The operation this grant will authorize (shown in the dialog),
        /// e.g. "sudo rm /opt/x". Defaults to the caller's own command line.
        #[arg(long, default_value = "")]
        command: String,
        /// Who is elevating: mimo / ai / user (default user)
        #[arg(long, value_enum, default_value_t = Source::User)]
        source: Source,
        /// Overall wait budget in milliseconds (0 = daemon default)
        #[arg(long, default_value_t = 0)]
        timeout_ms: u32,
    },
    /// Query cached authorization status (never prompts)
    Status {
        /// Action id; omit to list all cached grants for this user
        action: Option<String>,
    },
    /// Revoke cached authorization (one action, or all when omitted)
    Revoke { action: Option<String> },
    /// Show effective policy rules
    Rules,
    /// Check that mimoauthd is running
    Ping,
    /// Internal: PAM stack entry point (pam_exec). Exit 0 = authenticated,
    /// exit non-zero = fall through to the stock password stack.
    #[command(hide = true)]
    PamHook,
}

fn connect() -> Result<Auth1ProxyBlocking<'static>, String> {
    let conn = zbus::blocking::Connection::session()
        .map_err(|e| format!("cannot connect to session bus: {e}"))?;
    let proxy = Auth1ProxyBlocking::new(&conn).map_err(|e| format!("cannot reach mimoauthd: {e}"))?;
    if !proxy.ping().map_err(|e| format!("mimoauthd not responding: {e}"))? {
        return Err("mimoauthd not responding".into());
    }
    Ok(proxy)
}

fn daemon_hint() -> &'static str {
    "is mimoauthd running? try: systemctl --user start mimoauthd"
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(3)
        }
    }
}



/// Wayland socket name under /run/user/<uid>, if the session env lost it.
fn detect_wayland_socket(uid: u32) -> Option<String> {
    let entries = std::fs::read_dir(format!("/run/user/{uid}")).ok()?;
    let mut sockets: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("wayland-") && !name.ends_with(".lock") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    sockets.sort();
    sockets.pop()
}

fn has_zh() -> bool {
    let lang = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    lang.starts_with("zh")
}

/// Interactive auth on the caller's terminal (no GUI available).
fn inline_auth(
    proxy: &Auth1ProxyBlocking,
    action: &str,
    description: &str,
    command: &str,
    source: &str,
    timeout_ms: u32,
) -> Result<(String, String), String> {
    let (status, auth_id, remaining) = proxy
        .request_inline(action, description, command, source, timeout_ms)
        .map_err(|e| format!("request failed: {e}"))?;
    match status.as_str() {
        "allow" => {
            let reason = if auth_id == "cache" { "cache" } else { "" };
            return Ok(("allow".into(), reason.into()));
        }
        "" => {}
        other => return Ok((other.to_string(), auth_id)),
    }

    let zh = has_zh();
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let title = if zh { "MiMo 请求身份验证" } else { "MiMo authentication request" };
    let brand = if zh { "由 MiMo Desktop 发起" } else { "Requested by MiMo Desktop" };
    let desc = if description.is_empty() {
        if zh { "某个程序请求提升权限" } else { "A program requests elevated privileges" }
    } else {
        description
    };
    let action_cap = if zh { "动作" } else { "Action" };
    let failed = if zh { "密码验证失败，请重试" } else { "Password verification failed, try again" };
    let hint = if zh {
        "输入密码后回车；Ctrl-C 取消"
    } else {
        "Type password and press Enter; Ctrl-C cancels"
    };

    eprintln!("── {title} ──");
    eprintln!("{brand}");
    eprintln!("{desc}");
    eprintln!("{action_cap}: {action}");
    if !command.is_empty() {
        let cmd_cap = if zh { "命令" } else { "Command" };
        eprintln!("{cmd_cap}: {command}");
    }
    eprintln!("({hint})");

    loop {
        if Instant::now() >= deadline {
            let _ = proxy.cancel_auth(&auth_id);
            return Ok(("timeout".into(), "prompt-timeout".into()));
        }
        let prompt = if zh { "\n密码: " } else { "\nPassword: " };
        let password = match rpassword::prompt_password(prompt) {
            Ok(p) => p,
            Err(_) => {
                let _ = proxy.cancel_auth(&auth_id);
                return Ok(("deny".into(), "cancelled".into()));
            }
        };
        if password.is_empty() {
            continue;
        }
        match proxy.submit_password(&auth_id, &password) {
            Ok((true, _)) => return Ok(("allow".into(), String::new())),
            Ok((false, reason)) => match reason.as_str() {
                "expired" | "not-found" => {
                    return Ok(("timeout".into(), "prompt-expired".into()))
                }
                "auth-failed" => {
                    eprintln!("{failed}");
                    continue;
                }
                other => return Ok(("error".into(), other.to_string())),
            },
            Err(e) => return Ok(("error".into(), format!("dbus: {e}"))),
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.cmd {
        Cmd::Request {
            action,
            description,
            command,
            source,
            timeout_ms,
        } => {
            let proxy = connect().map_err(|e| format!("{e}; {}", daemon_hint()))?;
            let has_display = ["WAYLAND_DISPLAY", "DISPLAY"].iter().any(|k| {
                std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false)
            });
            let source = source.as_str();
            let (outcome, reason) = if has_display {
                proxy
                    .request_authorization(&action, &description, &command, source, timeout_ms)
                    .map(|(o, r, _)| (o, r))
                    .map_err(|e| format!("request failed: {e}"))?
            } else {
                inline_auth(&proxy, &action, &description, &command, source, timeout_ms)?
            };
            let outcome = match outcome.as_str() {
                "allow" => Outcome::Allow,
                "deny" => Outcome::Deny,
                "timeout" => Outcome::Timeout,
                _ => Outcome::Error,
            };
            let result = RequestResult {
                action_id: action,
                outcome,
                reason,
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string(&result).map_err(|e| e.to_string())?
                );
            } else {
                println!("outcome: {}", result.outcome.as_str());
                if !result.reason.is_empty() {
                    println!("reason: {}", result.reason);
                }
            }
            Ok(ExitCode::from(match outcome {
                Outcome::Allow => 0u8,
                Outcome::Deny => 1,
                Outcome::Timeout => 2,
                Outcome::Error => 3,
            }))
        }
        Cmd::Status { action } => {
            let proxy = connect().map_err(|e| format!("{e}; {}", daemon_hint()))?;
            match action {
                Some(action_id) => {
                    let (authorized, remaining_ms) = proxy
                        .query_authorization(&action_id)
                        .map_err(|e| format!("query failed: {e}"))?;
                    let st = AuthStatus {
                        action_id,
                        authorized,
                        remaining_ms,
                    };
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string(&st).map_err(|e| e.to_string())?
                        );
                    } else if st.authorized {
                        println!(
                            "authorized ({} ms remaining): {}",
                            st.remaining_ms, st.action_id
                        );
                    } else {
                        println!("not authorized: {}", st.action_id);
                    }
                }
                None => {
                    let grants = proxy.list_grants().map_err(|e| e.to_string())?;
                    if cli.json {
                        let list: Vec<AuthStatus> = grants
                            .into_iter()
                            .map(|(a, ms)| AuthStatus {
                                action_id: a,
                                authorized: true,
                                remaining_ms: ms,
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string(&list).map_err(|e| e.to_string())?
                        );
                    } else if grants.is_empty() {
                        println!("no cached grants");
                    } else {
                        for (a, ms) in grants {
                            println!("{ms} ms  {a}");
                        }
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Revoke { action } => {
            let proxy = connect().map_err(|e| format!("{e}; {}", daemon_hint()))?;
            let removed = proxy
                .revoke_authorization(action.as_deref().unwrap_or(""))
                .map_err(|e| format!("revoke failed: {e}"))?;
            if cli.json {
                println!("{}", serde_json::json!({ "removed": removed }));
            } else {
                println!("revoked {removed} grant(s)");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Rules => {
            let proxy = connect().map_err(|e| format!("{e}; {}", daemon_hint()))?;
            let rules = proxy.list_rules().map_err(|e| e.to_string())?;
            if cli.json {
                let list: Vec<serde_json::Value> = rules
                    .iter()
                    .map(|(p, e, u, s)| {
                        serde_json::json!({"pattern": p, "effect": e, "users": u, "source": s})
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&list).map_err(|e| e.to_string())?
                );
            } else {
                println!("{:<40} {:<16} {:<16} {}", "PATTERN", "EFFECT", "USERS", "SOURCE");
                for (p, e, u, s) in rules {
                    println!("{p:<40} {e:<16} {u:<16} {s}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::PamHook => {
            use std::io::{IsTerminal, Write};
            // pam_exec's stdio fate varies by version — log to a file as well.
            fn plog(msg: &str) {
                eprintln!("pam-hook: {msg}");
                let uid = unsafe { libc::getuid() };
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let paths = [
                    format!("/tmp/pam-hook-{}.log", std::process::id()),
                    format!("/run/user/{uid}/pam-hook.log"),
                ];
                for path in &paths {
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                    {
                        let _ = writeln!(f, "[{stamp}] {msg}");
                        return;
                    }
                }
            }
            // sudo runs PAM with euid=0; drop privileges FIRST so the
            // session-bus SO_PEERCRED check sees the invoking user (and so
            // our log files are owned by us).
            let orig_euid = unsafe { libc::geteuid() };
            let real_uid = unsafe { libc::getuid() };
            if orig_euid == 0 && real_uid != 0 {
                unsafe { libc::setuid(real_uid) };
            }
            plog(&format!(
                "invoked orig_euid={orig_euid} uid={real_uid} stdin_tty={}",
                std::io::stdin().is_terminal()
            ));
            // sudo's stdin during PAM is usually NOT a tty; the process still
            // has a controlling terminal — probe /dev/tty before giving up.
            let fd0 = std::fs::read_link("/proc/self/fd/0").unwrap_or_default();
            let tty_ok = std::io::stdin().is_terminal()
                || std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tty")
                    .is_ok();
            plog(&format!("fd0={} tty_ok={tty_ok}", fd0.display()));
            // sudo scrubs WAYLAND_DISPLAY/DISPLAY; recover the session socket
            // so the GUI agent can be spawned like it would for any caller.
            if ["WAYLAND_DISPLAY", "DISPLAY"].iter().all(|k| {
                std::env::var(k).map(|v| v.is_empty()).unwrap_or(true)
            }) {
                if let Some(wl) = detect_wayland_socket(real_uid) {
                    std::env::set_var("WAYLAND_DISPLAY", &wl);
                    plog(&format!("restored WAYLAND_DISPLAY={wl}"));
                }
            }
            // sudo scrubs the session-bus env; restore it so zbus finds the
            // user bus at /run/user/<uid>/bus (real uid = the invoking user).
            if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                let uid = unsafe { libc::getuid() };
                std::env::set_var(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path=/run/user/{uid}/bus"),
                );
                plog(&format!("restored DBUS bus for uid {uid}"));
            }
            let proxy = match connect() {
                Ok(p) => p,
                Err(e) => {
                    plog(&format!("cannot reach mimoauthd: {e}"));
                    return Ok(ExitCode::from(1));
                }
            };
            plog("connected to mimoauthd");
            // The operation sudo is running for us: SUDO_COMMAND (if present
            // already) or the invoking sudo process' own command line.
            let sudo_command = std::env::var("SUDO_COMMAND").ok().filter(|v| !v.is_empty()).or_else(|| {
                let ppid = unsafe { libc::getppid() };
                std::fs::read(format!("/proc/{ppid}/cmdline"))
                    .ok()
                    .map(|b| {
                        b.split(|c| *c == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).into_owned())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .filter(|v| !v.is_empty())
            })
            .unwrap_or_default();
            plog(&format!("sudo_command={sudo_command:?}"));
            // No description of our own: sudo scrubs LANG, so let the dialog
            // (which inherits the session locale) localize its default text.
            let desc = "";
            let has_disp = ["WAYLAND_DISPLAY", "DISPLAY"].iter().any(|k| {
                std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false)
            });
            plog(&format!("has_display={has_disp}"));
            let outcome = if has_disp {
                plog("GUI path (display available)");
                proxy
                    .request_authorization("org.mimoauth.pam.sudo", desc, &sudo_command, "user", 20_000)
                    .map(|(o, _, _)| o)
                    .unwrap_or_else(|_| "error".into())
            } else if tty_ok {
                plog("inline path (no display, tty available)");
                inline_auth(&proxy, "org.mimoauth.pam.sudo", desc, &sudo_command, "user", 20_000)
                    .map(|(o, _)| o)
                    .unwrap_or_else(|_| "error".into())
            } else {
                plog("no display and no tty — falling through");
                "error".into()
            };
            plog(&format!("outcome={outcome} display={}", has_disp));
            Ok(if outcome == "allow" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Ping => {
            match connect() {
                Ok(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"daemon": "ok"}));
                    } else {
                        println!("mimoauthd: ok");
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"daemon": "down", "error": e}));
                    } else {
                        eprintln!("mimoauthd: down ({e})");
                    }
                    Ok(ExitCode::from(3))
                }
            }
        }
    }
}
