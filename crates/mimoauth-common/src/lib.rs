use serde::{Deserialize, Serialize};

pub mod cache;
pub mod config;
pub mod dbus;
pub mod rules;

/// D-Bus well-known names shared by daemon, CLI and GUI.
pub const DBUS_NAME: &str = "org.mimoauth.Auth1";
pub const DBUS_PATH: &str = "/org/mimoauth/Auth1";
pub const DBUS_IFACE: &str = "org.mimoauth.Auth1";

/// Policy effect for an action, polkit-style without polkit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// No authentication required.
    Allow,
    /// Authentication required, result not cached.
    AuthAdmin,
    /// Authentication required, result cached for `keep_timeout`.
    AuthAdminKeep,
    /// Always refused.
    Deny,
}

impl Effect {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" | "yes" => Some(Effect::Allow),
            "auth_admin" | "auth" => Some(Effect::AuthAdmin),
            "auth_admin_keep" | "auth_keep" => Some(Effect::AuthAdminKeep),
            "deny" | "no" => Some(Effect::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::AuthAdmin => "auth_admin",
            Effect::AuthAdminKeep => "auth_admin_keep",
            Effect::Deny => "deny",
        }
    }
}

/// Final outcome of an authorization request, machine-readable for agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    Deny,
    Timeout,
    Error,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
            Outcome::Timeout => "timeout",
            Outcome::Error => "error",
        }
    }
}

/// Status returned by QueryAuthorization (cache lookup, never prompts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStatus {
    pub action_id: String,
    /// Whether a valid cached grant exists.
    pub authorized: bool,
    /// Milliseconds until the cached grant expires (0 when none).
    pub remaining_ms: u64,
}

/// Structured result of `mimoauthctl request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResult {
    pub action_id: String,
    pub outcome: Outcome,
    /// Human-readable reason when outcome != allow.
    pub reason: String,
}

/// Peer identity captured from D-Bus SO_PEERCRED / bus credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub uid: u32,
    pub pid: u32,
    pub exe: String,
    /// Full command line of the calling process (display-only, anti-spoofing).
    pub cmdline: String,
}

impl PeerIdentity {
    pub fn summary(&self) -> String {
        let exe = if self.exe.is_empty() {
            "unknown".to_string()
        } else {
            self.exe.clone()
        };
        format!("uid={} pid={} ({})", self.uid, self.pid, exe)
    }
}
