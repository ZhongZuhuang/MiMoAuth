//! Shared D-Bus proxy for `org.mimoauth.Auth1` (used by CLI and GUI).

/// Proxy: async (`Auth1Proxy`) and blocking (`Auth1ProxyBlocking`).
#[zbus::proxy(
    interface = "org.mimoauth.Auth1",
    default_service = "org.mimoauth.Auth1",
    default_path = "/org/mimoauth/Auth1"
)]
pub trait Auth1 {
    /// Blocking request (spawns GUI/registered agent). Returns (outcome, reason, auth_id).
    /// `command` = the operation this grant will authorize (shown to the user);
    /// empty = fall back to the caller's own command line.
    /// `source` ∈ mimo | ai | user — drives dialog title/icon (who elevates).
    fn request_authorization(
        &self,
        action_id: &str,
        description: &str,
        command: &str,
        source: &str,
        timeout_ms: u32,
    ) -> zbus::Result<(String, String, String)>;

    /// Agent-less request for terminals. Returns (status, auth_id, remaining_ms):
    /// status "" = interactive auth required via SubmitPassword/CancelAuth;
    /// status allow/deny/error = final, auth_id carries reason or "cache".
    fn request_inline(
        &self,
        action_id: &str,
        description: &str,
        command: &str,
        source: &str,
        timeout_ms: u32,
    ) -> zbus::Result<(String, String, u64)>;

    /// Cache lookup only, never prompts. Returns (authorized, remaining_ms).
    fn query_authorization(&self, action_id: &str) -> zbus::Result<(bool, u64)>;

    /// Caller's cached grants: (action_id, remaining_ms).
    fn list_grants(&self) -> zbus::Result<Vec<(String, u64)>>;

    /// Revoke one action, or all caller grants when `action_id` is empty.
    /// Returns how many grants were removed.
    fn revoke_authorization(&self, action_id: &str) -> zbus::Result<u32>;

    /// Effective rules: (pattern, effect, users, source).
    fn list_rules(&self) -> zbus::Result<Vec<(String, String, String, String)>>;

    /// Dialog details for the auth agent:
    /// (description, command, source, remaining_ms).
    fn get_pending_request(
        &self,
        auth_id: &str,
    ) -> zbus::Result<(String, String, String, u64)>;

    /// Submit password; true = granted.
    fn submit_password(&self, auth_id: &str, password: &str) -> zbus::Result<(bool, String)>;

    /// Cancel a pending dialog.
    fn cancel_auth(&self, auth_id: &str) -> zbus::Result<bool>;

    /// Biometric verdict from a trusted local agent (fingerprint via fprintd).
    /// true = grant; false = rejected (agent may retry).
    fn fingerprint_result(&self, auth_id: &str, success: bool) -> zbus::Result<(bool, String)>;

    /// Register an external agent (caller's bus name) for auth prompts.
    fn register_agent(&self, agent_bus: &str) -> zbus::Result<bool>;

    fn unregister_agent(&self) -> zbus::Result<bool>;

    fn ping(&self) -> zbus::Result<bool>;
}

/// fprintd (fingerprint reader) — Manager at a fixed path.
#[zbus::proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
pub trait FprintManager {
    /// Empty path "/" means no device.
    fn get_default_device(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

/// fprintd device — path varies; build with `FprintDeviceProxy::builder`.
#[zbus::proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
pub trait FprintDevice {
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, username: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;

    #[zbus(signal)]
    fn verify_status(&self, status: &str, success: bool) -> zbus::Result<()>;
}
