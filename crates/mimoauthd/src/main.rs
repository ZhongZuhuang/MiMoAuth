use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mimoauth_common::cache::AuthCache;
use mimoauth_common::config::Config;
use mimoauth_common::rules::Ruleset;
use mimoauth_common::{Effect, Outcome, PeerIdentity, DBUS_NAME, DBUS_PATH};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

mod pam;

/// A prompt waiting for user authentication.
struct Pending {
    action_id: String,
    description: String,
    /// Operation this grant authorizes (e.g. "sudo rm /opt/x"), display-only.
    command: String,
    /// Who elevates: mimo | ai | user — chooses dialog title/icon.
    source: String,
    peer: PeerIdentity,
    username: String,
    keep: bool,
    deadline: Instant,
    /// None for inline requests (caller drives the result itself).
    responder: Option<mpsc::Sender<Grant>>,
}

#[derive(Clone, Copy)]
enum Grant {
    Allow,
    Deny,
}

struct State {
    cache: AuthCache,
    pending: HashMap<String, Pending>,
    /// Registered auth agent bus name (org.mimoauth.Agent1), if any.
    agent: Option<String>,
}

struct AuthService {
    state: Arc<Mutex<State>>,
    cfg: Config,
    seq: AtomicU64,
    own_uid: u32,
    conn: zbus::Connection,
}

impl AuthService {
    async fn identity(
        &self,
        sender: Option<&zbus::names::UniqueName<'_>>,
    ) -> Result<PeerIdentity, String> {
        let sender = sender.ok_or_else(|| "missing message sender".to_string())?;
        let reply = self
            .conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetConnectionCredentials",
                &(sender.to_string(),),
            )
            .await
            .map_err(|e| format!("credentials lookup failed: {e}"))?;
        let creds: HashMap<String, zbus::zvariant::OwnedValue> =
            reply.body().deserialize().map_err(|e| e.to_string())?;

        let uid = creds
            .get("UnixUserID")
            .and_then(|v| u32::try_from(v.clone()).ok())
            .ok_or_else(|| "no uid in peer credentials".to_string())?;
        let pid = creds
            .get("ProcessID")
            .and_then(|v| u32::try_from(v.clone()).ok())
            .unwrap_or(0);
        let exe = if pid > 0 {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let cmdline = if pid > 0 {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .map(|b| {
                    b.split(|c| *c == 0)
                        .filter(|s| !s.is_empty())
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(PeerIdentity {
            uid,
            pid,
            exe,
            cmdline,
        })
    }

    /// True when the session has a usable display for the GUI agent:
    /// either an inherited DISPLAY/WAYLAND_DISPLAY, or a live Wayland socket
    /// under XDG_RUNTIME_DIR (the daemon may have started before the session
    /// exported its environment).
    fn has_display() -> bool {
        ["WAYLAND_DISPLAY", "DISPLAY"].iter().any(|k| {
            std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false)
        }) || Self::wayland_socket().is_some()
    }

    /// Live Wayland socket name under $XDG_RUNTIME_DIR, if any.
    fn wayland_socket() -> Option<String> {
        let runtime = std::env::var("XDG_RUNTIME_DIR").ok()?;
        let entries = std::fs::read_dir(runtime).ok()?;
        let mut sockets: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                // Only real sockets: wayland-0, wayland-1, … (skip wayland-N.lock etc.)
                match name.strip_prefix("wayland-") {
                    Some(num) if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) => {
                        Some(name)
                    }
                    _ => None,
                }
            })
            .collect();
        sockets.sort();
        sockets.pop() // highest-numbered socket is the live session
    }

    fn spawn_gui(&self, auth_id: &str) -> Result<Child, String> {
        let mut cmd = Command::new(&self.cfg.gui_path);
        cmd.arg("--auth-id")
            .arg(auth_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true);
        // Keep the agent's stderr for diagnosis (probe/verify failures).
        let log_path = std::env::var("XDG_RUNTIME_DIR")
            .map(|d| format!("{d}/mimoauth-gui.log"))
            .unwrap_or_else(|_| "/tmp/mimoauth-gui.log".to_string());
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            cmd.stderr(std::process::Stdio::from(f));
        }
        if std::env::var("WAYLAND_DISPLAY").unwrap_or_default().is_empty() {
            if let Some(wl) = Self::wayland_socket() {
                info!("WAYLAND_DISPLAY missing in daemon env, using /run socket {wl}");
                cmd.env("WAYLAND_DISPLAY", wl);
            }
        }
        cmd.spawn().map_err(|e| format!("spawn agent: {e}"))
    }

    /// Decide agent: registered agent wins, else spawn the GUI (display needed).
    async fn activate_agent(&self, auth_id: &str) -> Result<Option<Child>, String> {
        let agent = self.state.lock().await.agent.clone();
        if let Some(bus) = agent {
            let show_args = (auth_id.to_string(),);
            let notify = self.conn.call_method(
                Some(bus.as_str()),
                "/org/mimoauth/Agent1",
                Some("org.mimoauth.Agent1"),
                "Show",
                &(show_args),
            );
            match tokio::time::timeout(Duration::from_secs(2), notify).await {
                Ok(Ok(_)) => return Ok(None),
                Ok(Err(e)) => warn!("registered agent failed ({e}), falling back to GUI"),
                Err(_) => warn!("registered agent timed out, falling back to GUI"),
            }
        }
        if !Self::has_display() {
            return Err("no-agent".into());
        }
        self.spawn_gui(auth_id).map(Some)
    }
}

/// Reap an agent child: kill it if `kill` is set, then wait so it can't zombie.
fn reap_agent(mut child: Child, kill: bool) {
    tokio::spawn(async move {
        if kill {
            let _ = child.start_kill();
        }
        let _ = child.wait().await;
    });
}

#[zbus::interface(name = "org.mimoauth.Auth1")]
impl AuthService {
    /// Blocking authorization request. Returns (outcome, reason, auth_id).
    async fn request_authorization(
        &self,
        action_id: &str,
        description: &str,
        command: &str,
        source: &str,
        timeout_ms: u32,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (String, String, String) {
        let peer = match self.identity(header.sender()).await {
            Ok(p) => p,
            Err(e) => return (Outcome::Error.as_str().to_string(), e, String::new()),
        };
        if peer.uid != self.own_uid {
            warn!("rejected foreign-uid request from uid={}", peer.uid);
            return (
                Outcome::Deny.as_str().to_string(),
                "foreign-uid".into(),
                String::new(),
            );
        }

        let username = pam::username_for_uid(peer.uid).unwrap_or_default();
        let command = if command.is_empty() {
            peer.cmdline.clone()
        } else {
            command.to_string()
        };
        let source = match source {
            "mimo" | "ai" | "user" => source.to_string(),
            _ => "user".to_string(),
        };
        let rules = Ruleset::load_or_builtin(&Ruleset::default_path());
        let (effect, matched) = rules.evaluate(action_id, &username);
        info!(
            "request action={action_id} uid={} effect={} rule={matched} cmd={command:?}",
            peer.uid,
            effect.as_str()
        );

        match effect {
            Effect::Allow => {
                return (Outcome::Allow.as_str().to_string(), String::new(), String::new())
            }
            Effect::Deny => {
                return (Outcome::Deny.as_str().to_string(), "policy-deny".into(), String::new())
            }
            Effect::AuthAdminKeep => {
                let st = self.state.lock().await;
                if st.cache.remaining(peer.uid, action_id).is_some() {
                    return (Outcome::Allow.as_str().to_string(), "cache".into(), String::new());
                }
                drop(st);
            }
            Effect::AuthAdmin => {}
        }

        let keep = effect == Effect::AuthAdminKeep;
        let wait_ms = match timeout_ms {
            0 => self.cfg.prompt_timeout_secs.saturating_mul(1000),
            t => u64::from(t.min(600_000)),
        };
        let auth_id = format!(
            "auth-{}-{}",
            self.seq.fetch_add(1, Ordering::Relaxed),
            std::process::id()
        );

        let child = match self.activate_agent(&auth_id).await {
            Ok(c) => c,
            Err(reason) => {
                warn!("cannot activate auth agent: {reason}");
                return (
                    Outcome::Error.as_str().to_string(),
                    reason,
                    String::new(),
                );
            }
        };

        let (tx, mut rx) = mpsc::channel::<Grant>(1);
        {
            let mut st = self.state.lock().await;
            st.pending.insert(
                auth_id.clone(),
                Pending {
                    action_id: action_id.to_string(),
                    description: description.to_string(),
                    command,
                    source,
                    peer,
                    username,
                    keep,
                    deadline: Instant::now() + Duration::from_millis(wait_ms),
                    responder: Some(tx),
                },
            );
        }

        let mut child = child;
        enum Ended {
            Grant(Grant),
            Timeout,
            AgentExit,
        }
        let ended = tokio::select! {
            g = rx.recv() => match g {
                Some(g) => Ended::Grant(g),
                None => Ended::AgentExit,
            },
            _ = tokio::time::sleep(Duration::from_millis(wait_ms)) => Ended::Timeout,
            _ = async {
                let Some(c) = child.as_mut() else {
                    std::future::pending::<()>().await;
                    return;
                };
                loop {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    match c.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => continue,
                        Err(_) => break,
                    }
                }
            } => {
                // The agent may have delivered a verdict just before exiting.
                match rx.try_recv() {
                    Ok(g) => Ended::Grant(g),
                    Err(_) => Ended::AgentExit,
                }
            }
        };

        let mut st = self.state.lock().await;
        let pending = st.pending.remove(&auth_id);
        let (outcome, reason) = match ended {
            Ended::Grant(Grant::Allow) => {
                if let Some(p) = &pending {
                    if p.keep {
                        st.cache.grant(
                            p.peer.uid,
                            &p.action_id,
                            Duration::from_secs(self.cfg.keep_timeout_secs),
                        );
                    }
                }
                (Outcome::Allow, String::new())
            }
            Ended::Grant(Grant::Deny) => (Outcome::Deny, "auth-failed".to_string()),
            Ended::Timeout => (Outcome::Timeout, "prompt-timeout".to_string()),
            Ended::AgentExit => (Outcome::Error, "agent-exit".to_string()),
        };
        drop(st);

        if let Some(mut c) = child {
            let kill = !matches!(outcome, Outcome::Allow);
            if kill {
                let _ = c.start_kill();
            }
            reap_agent(c, false);
        }

        (outcome.as_str().to_string(), reason, auth_id)
    }

    /// Inline request for callers without a GUI (SSH/terminal): policy is
    /// evaluated now, and a pending record is created without any agent.
    /// Returns (status, auth_id, remaining_ms); status is "allow"/"deny"/""
    /// ("" = interactive auth required, use SubmitPassword/CancelAuth).
    async fn request_inline(
        &self,
        action_id: &str,
        description: &str,
        command: &str,
        source: &str,
        timeout_ms: u32,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (String, String, u64) {
        let peer = match self.identity(header.sender()).await {
            Ok(p) => p,
            Err(e) => return (Outcome::Error.as_str().to_string(), e, 0),
        };
        if peer.uid != self.own_uid {
            return (Outcome::Deny.as_str().to_string(), "foreign-uid".into(), 0);
        }
        let username = pam::username_for_uid(peer.uid).unwrap_or_default();
        let command = if command.is_empty() {
            peer.cmdline.clone()
        } else {
            command.to_string()
        };
        let source = match source {
            "mimo" | "ai" | "user" => source.to_string(),
            _ => "user".to_string(),
        };
        let rules = Ruleset::load_or_builtin(&Ruleset::default_path());
        let (effect, _) = rules.evaluate(action_id, &username);
        info!(
            "request_inline action={action_id} uid={} effect={} cmd={command:?}",
            peer.uid,
            effect.as_str()
        );

        match effect {
            Effect::Allow => return (Outcome::Allow.as_str().to_string(), String::new(), 0),
            Effect::Deny => return (Outcome::Deny.as_str().to_string(), "policy-deny".into(), 0),
            Effect::AuthAdminKeep => {
                let st = self.state.lock().await;
                if let Some(left) = st.cache.remaining(peer.uid, action_id) {
                    return (
                        Outcome::Allow.as_str().to_string(),
                        "cache".into(),
                        left.as_millis() as u64,
                    );
                }
                drop(st);
            }
            Effect::AuthAdmin => {}
        }

        let wait_ms = match timeout_ms {
            0 => self.cfg.prompt_timeout_secs.saturating_mul(1000),
            t => u64::from(t.min(600_000)),
        };
        let auth_id = format!(
            "inline-{}-{}",
            self.seq.fetch_add(1, Ordering::Relaxed),
            std::process::id()
        );
        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        {
            let mut st = self.state.lock().await;
            st.pending.insert(
                auth_id.clone(),
                Pending {
                    action_id: action_id.to_string(),
                    description: description.to_string(),
                    command,
                    source,
                    peer,
                    username,
                    keep: effect == Effect::AuthAdminKeep,
                    deadline,
                    responder: None,
                },
            );
        }
        (String::new(), auth_id, wait_ms)
    }

    /// Cache lookup only — never prompts.
    async fn query_authorization(
        &self,
        action_id: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (bool, u64) {
        let Ok(peer) = self.identity(header.sender()).await else {
            return (false, 0);
        };
        let st = self.state.lock().await;
        match st.cache.remaining(peer.uid, action_id) {
            Some(d) => (true, d.as_millis() as u64),
            None => (false, 0),
        }
    }

    /// List cached grants for the caller.
    async fn list_grants(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Vec<(String, u64)> {
        let Ok(peer) = self.identity(header.sender()).await else {
            return Vec::new();
        };
        let mut st = self.state.lock().await;
        st.cache.purge_expired();
        st.cache
            .remaining_map(peer.uid)
            .into_iter()
            .map(|(a, d)| (a, d.as_millis() as u64))
            .collect()
    }

    /// Revoke cached grants: specific action, or all of the caller's when empty.
    async fn revoke_authorization(
        &self,
        action_id: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> u32 {
        let Ok(peer) = self.identity(header.sender()).await else {
            return 0;
        };
        let mut st = self.state.lock().await;
        st.cache.revoke(
            peer.uid,
            if action_id.is_empty() {
                None
            } else {
                Some(action_id)
            },
        )
    }

    /// Current effective rules as (pattern, effect, users, source).
    async fn list_rules(&self) -> Vec<(String, String, String, String)> {
        let rules = Ruleset::load_or_builtin(&Ruleset::default_path());
        let mut out = vec![(
            "*".to_string(),
            rules.default.as_str().to_string(),
            "*".to_string(),
            format!("{}#default", rules.origin),
        )];
        for r in &rules.rules {
            out.push((
                r.action_pattern.clone(),
                r.effect.as_str().to_string(),
                if r.users.is_empty() {
                    "*".to_string()
                } else {
                    r.users.join(",")
                },
                r.source.clone(),
            ));
        }
        out
    }

    /// What the auth agent needs to render the dialog.
    async fn get_pending_request(
        &self,
        auth_id: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(String, String, String, u64), zbus::fdo::Error> {
        let Ok(peer) = self.identity(header.sender()).await else {
            return Err(zbus::fdo::Error::Failed("credentials lookup failed".into()));
        };
        if peer.uid != self.own_uid {
            return Err(zbus::fdo::Error::Failed("foreign uid".into()));
        }
        let st = self.state.lock().await;
        let p = st
            .pending
            .get(auth_id)
            .ok_or_else(|| zbus::fdo::Error::Failed("unknown or expired auth id".into()))?;
        let remaining = p.deadline.saturating_duration_since(Instant::now());
        Ok((
            p.description.clone(),
            p.command.clone(),
            p.source.clone(),
            remaining.as_millis() as u64,
        ))
    }

    /// Password verification happens here (PAM); true = granted.
    async fn submit_password(
        &self,
        auth_id: &str,
        password: String,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (bool, String) {
        let Ok(peer) = self.identity(header.sender()).await else {
            return (false, "credentials-lookup-failed".into());
        };
        if peer.uid != self.own_uid {
            return (false, "foreign-uid".into());
        }

        let (username, service, keep, action_id) = {
            let st = self.state.lock().await;
            match st.pending.get(auth_id) {
                Some(p) => {
                    if Instant::now() > p.deadline {
                        return (false, "expired".into());
                    }
                    (
                        p.username.clone(),
                        self.cfg.pam_service.clone(),
                        p.keep,
                        p.action_id.clone(),
                    )
                }
                None => return (false, "expired".into()),
            }
        };
        if username.is_empty() {
            return (false, "no-username".into());
        }

        let mut pw_bytes = password.into_bytes();
        let user = username.clone();
        let svc = service.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let r = pam::verify_password(&user, &pw_bytes, &svc);
            for b in pw_bytes.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            r
        })
        .await;

        match outcome {
            Ok(Ok(())) => {
                let mut st = self.state.lock().await;
                // Still live? (Inline pendings are removed lazily after deadline.)
                let live = st
                    .pending
                    .get(auth_id)
                    .map(|p| Instant::now() <= p.deadline)
                    .unwrap_or(false);
                if !live {
                    return (false, "expired".into());
                }
                if keep {
                    st.cache.grant(
                        peer.uid,
                        &action_id,
                        Duration::from_secs(self.cfg.keep_timeout_secs),
                    );
                }
                if let Some(tx) = st.pending.get(auth_id).and_then(|p| p.responder.as_ref()) {
                    let _ = tx.try_send(Grant::Allow);
                }
                (true, String::new())
            }
            Ok(Err(e)) => {
                warn!(
                    "pam failure for uid={}: {e} (pam messages: {:?})",
                    peer.uid, e.messages
                );
                (false, "auth-failed".into())
            }
            Err(join_err) => {
                warn!("pam task failed: {join_err}");
                (false, "internal-error".into())
            }
        }
    }

    /// Biometric verdict relayed by a trusted local agent (same-uid GUI/TUI
    /// talking to fprintd). Mirrors submit_password's grant semantics.
    async fn fingerprint_result(
        &self,
        auth_id: &str,
        success: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (bool, String) {
        let Ok(peer) = self.identity(header.sender()).await else {
            return (false, "credentials-lookup-failed".into());
        };
        if peer.uid != self.own_uid {
            return (false, "foreign-uid".into());
        }
        if !success {
            return (false, "rejected".into());
        }
        let mut st = self.state.lock().await;
        let info = match st.pending.get(auth_id) {
            Some(p) if Instant::now() <= p.deadline => {
                (p.keep, p.action_id.clone(), p.responder.clone())
            }
            _ => return (false, "expired".into()),
        };
        let (keep, action_id, responder) = info;
        if keep {
            st.cache.grant(
                peer.uid,
                &action_id,
                Duration::from_secs(self.cfg.keep_timeout_secs),
            );
        }
        if let Some(tx) = responder {
            let _ = tx.try_send(Grant::Allow);
        }
        (true, String::new())
    }

    /// User cancelled the dialog / inline prompt.
    async fn cancel_auth(
        &self,
        auth_id: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> bool {
        let Ok(peer) = self.identity(header.sender()).await else {
            return false;
        };
        let mut st = self.state.lock().await;
        if let Some(p) = st.pending.get(auth_id) {
            if p.peer.uid != peer.uid {
                return false;
            }
        }
        if let Some(p) = st.pending.remove(auth_id) {
            if let Some(tx) = p.responder {
                let _ = tx.try_send(Grant::Deny);
            }
            return true;
        }
        false
    }

    /// Register an external auth agent (org.mimoauth.Agent1 on the caller's
    /// bus name). While registered, requests notify it instead of spawning GUI.
    async fn register_agent(
        &self,
        agent_bus: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<bool, zbus::fdo::Error> {
        let peer = self
            .identity(header.sender())
            .await
            .map_err(zbus::fdo::Error::Failed)?;
        if peer.uid != self.own_uid {
            return Err(zbus::fdo::Error::Failed("foreign uid".into()));
        }
        if !agent_bus.contains(':') && !agent_bus.contains('.') {
            return Err(zbus::fdo::Error::InvalidArgs("bad bus name".into()));
        }
        let mut st = self.state.lock().await;
        st.agent = Some(agent_bus.to_string());
        info!("registered auth agent {agent_bus}");
        Ok(true)
    }

    async fn unregister_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<bool, zbus::fdo::Error> {
        let peer = self
            .identity(header.sender())
            .await
            .map_err(zbus::fdo::Error::Failed)?;
        if peer.uid != self.own_uid {
            return Err(zbus::fdo::Error::Failed("foreign uid".into()));
        }
        let mut st = self.state.lock().await;
        Ok(st.agent.take().is_some())
    }

    async fn ping(&self) -> bool {
        true
    }
}

/// 5s loop: clear the grant cache when the screen locks, and drop stale
/// inline pendings. Lock detection = logind LockedHint + known locker processes
/// (swaylock & co. do not talk to logind).
fn spawn_session_guard(state: Arc<Mutex<State>>) {
    tokio::spawn(async move {
        // logind lives on the *system* bus.
        let sys = match zbus::Connection::system().await {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("system bus unavailable for lock detection: {e}");
                None
            }
        };
        // The session id may only appear in our env after the graphical session
        // exports it — keep retrying until it resolves.
        let mut session_path: Option<String>;
        async fn resolve_session(sys: &Option<zbus::Connection>) -> Option<String> {
            let sid = std::env::var("XDG_SESSION_ID").ok()?;
            let conn = sys.as_ref()?;
            let reply = conn
                .call_method(
                    Some("org.freedesktop.login1"),
                    "/org/freedesktop/login1",
                    Some("org.freedesktop.login1.Manager"),
                    "GetSession",
                    &(sid,),
                )
                .await
                .ok()?;
            let path: zbus::zvariant::OwnedObjectPath = reply.body().deserialize().ok()?;
            Some(path.to_string())
        }
        session_path = resolve_session(&sys).await;
        match &session_path {
            Some(p) => info!("lock detection: logind session {p} + locker processes"),
            None => info!("logind session id not ready yet — will retry; locker-process detection active"),
        }

        let lockers = [
            "swaylock",
            "gnome-screensaver",
            "kscreenlocker_greet",
            "light-locker",
            "i3lock",
            "physlock",
        ];

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Stale inline pendings (no agent process attached to them).
            {
                let mut st = state.lock().await;
                let now = Instant::now();
                st.pending.retain(|_, p| p.deadline > now);
            }

            // Late session-id import: resolve it as soon as it shows up.
            if session_path.is_none() {
                session_path = resolve_session(&sys).await;
                if let Some(p) = &session_path {
                    info!("logind session resolved: {p}");
                }
            }

            let mut locked = false;
            if let (Some(path), Some(conn)) = (&session_path, &sys) {
                if let Ok(msg) = conn
                    .call_method(
                        Some("org.freedesktop.login1"),
                        path.as_str(),
                        Some("org.freedesktop.DBus.Properties"),
                        "Get",
                        &("org.freedesktop.login1.Session", "LockedHint"),
                    )
                    .await
                {
                    if let Ok(v) = msg.body().deserialize::<zbus::zvariant::Value<'_>>() {
                        locked = bool::try_from(v).unwrap_or(false);
                    }
                }
            }
            if !locked {
                if let Ok(rd) = std::fs::read_dir("/proc") {
                    'scan: for entry in rd.flatten() {
                        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                            let comm = comm.trim();
                            if lockers.contains(&comm) {
                                locked = true;
                                break 'scan;
                            }
                        }
                    }
                }
            }

            if locked {
                let mut st = state.lock().await;
                if !st.cache.is_empty() {
                    st.cache.clear();
                    info!("screen locked — authorization cache cleared");
                }
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = Config::load();
    let filter = if cfg.verbose {
        "info,mimoauthd=debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .init();

    // Fall back to a stock PAM service when ours is not installed yet.
    let pam_service_file = format!("/etc/pam.d/{}", cfg.pam_service);
    if !std::path::Path::new(&pam_service_file).exists() {
        warn!("{pam_service_file} missing — falling back to PAM service `su`");
        cfg.pam_service = "su".into();
    }

    let conn = zbus::Connection::session().await?;

    // Bring up the persistent auth agent (best-effort). Requests use its
    // org.mimoauth.Agent1.Show hot path when registered, and fall back to
    // spawning a fresh GUI otherwise.
    {
        let mut cmd = Command::new(&cfg.gui_path);
        cmd.arg("--daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null());
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/mimoauth-gui.log")
        {
            cmd.stderr(std::process::Stdio::from(file));
        } else {
            cmd.stderr(std::process::Stdio::null());
        }
        match cmd.spawn() {
            Ok(mut child) => {
                info!("persistent auth agent spawned");
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
            Err(e) => warn!("no persistent agent ({e}); dialogs will cold-start"),
        }
    }

    let own_uid = unsafe { libc::geteuid() };
    let state = Arc::new(Mutex::new(State {
        cache: AuthCache::new(),
        pending: HashMap::new(),
        agent: None,
    }));
    let svc = AuthService {
        state: state.clone(),
        cfg,
        seq: AtomicU64::new(1),
        own_uid,
        conn: conn.clone(),
    };

    // Register the interface before owning the name, so early calls can't get lost.
    conn.object_server().at(DBUS_PATH, svc).await?;
    conn.request_name(DBUS_NAME).await?;

    spawn_session_guard(state);

    info!("mimoauthd up on {DBUS_NAME} ({DBUS_PATH})");
    std::future::pending::<()>().await;
    Ok(())
}
