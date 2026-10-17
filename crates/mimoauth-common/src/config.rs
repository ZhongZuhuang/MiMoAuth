use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

/// Daemon configuration, file: `~/.config/mimoauth/config.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// PAM service name used for password verification.
    pub pam_service: String,
    /// TTL for `auth_admin_keep` grants (seconds).
    pub keep_timeout_secs: u64,
    /// How long the auth dialog waits before returning `timeout` (seconds).
    pub prompt_timeout_secs: u64,
    /// Seconds to wait for a fingerprint before falling back to password.
    pub fingerprint_timeout_secs: u64,
    /// Path to the GUI agent binary.
    pub gui_path: String,
    /// Emit debug logs.
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pam_service: "mimoauth".to_string(),
            keep_timeout_secs: 300,
            prompt_timeout_secs: 60,
            fingerprint_timeout_secs: 10,
            gui_path: dirs::home_dir()
                .map(|h| h.join(".local/bin/mimoauth-gui").display().to_string())
                .unwrap_or_else(|| "mimoauth-gui".to_string()),
            verbose: false,
        }
    }
}

impl Config {
    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mimoauth")
            .join("config.toml")
    }

    pub fn load() -> Self {
        let path = Self::path();
        match fs::read_to_string(&path) {
            Ok(raw) => match toml::from_str(&raw) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!("config {} invalid ({e}), using defaults", path.display());
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }
}
