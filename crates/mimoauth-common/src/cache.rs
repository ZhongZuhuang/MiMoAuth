use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Session-level authorization cache for `auth_admin_keep`.
///
/// Not serialized anywhere: dropped together with the daemon (i.e. the
/// user session), which satisfies "cache dies with the session".
#[derive(Debug, Default)]
pub struct AuthCache {
    entries: HashMap<(u32, String), Instant>,
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, uid: u32, action_id: &str, ttl: Duration) {
        self.entries
            .insert((uid, action_id.to_string()), Instant::now() + ttl);
    }

    /// Remaining lifetime if a live grant exists.
    pub fn remaining(&self, uid: u32, action_id: &str) -> Option<Duration> {
        let exp = *self
            .entries
            .iter()
            .find(|((u, a), _)| *u == uid && a == action_id)
            .map(|(_, exp)| exp)?;
        let now = Instant::now();
        if exp <= now {
            None
        } else {
            Some(exp - now)
        }
    }

    pub fn revoke(&mut self, uid: u32, action_id: Option<&str>) -> u32 {
        // Drop this user's expired leftovers first so counts reflect live grants.
        let now = Instant::now();
        self.entries.retain(|(u, _), exp| !(*u == uid && *exp <= now));
        match action_id {
            Some(a) if !a.is_empty() => {
                if self.entries.remove(&(uid, a.to_string())).is_some() {
                    1
                } else {
                    0
                }
            }
            _ => {
                let before = self.entries.len();
                self.entries.retain(|(u, _), _| *u != uid);
                (before - self.entries.len()) as u32
            }
        }
    }

    /// Drop expired entries.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, exp| *exp > now);
    }

    /// Clear every grant (screen locked / session event).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All live grants for one uid: (action, remaining).
    pub fn remaining_map(&self, uid: u32) -> Vec<(String, Duration)> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|((u, _), exp)| *u == uid && **exp > now)
            .map(|((_, a), exp)| (a.clone(), *exp - now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_and_expire_and_revoke() {
        let mut c = AuthCache::new();
        c.grant(1000, "a.b", Duration::from_millis(30));
        assert!(c.remaining(1000, "a.b").is_some());
        assert!(c.remaining(1001, "a.b").is_none());
        std::thread::sleep(Duration::from_millis(40));
        assert!(c.remaining(1000, "a.b").is_none());

        c.grant(1000, "x", Duration::from_secs(60));
        c.grant(1001, "y", Duration::from_secs(60));
        assert_eq!(c.revoke(1000, Some("x")), 1);
        assert_eq!(c.revoke(1000, Some("x")), 0);
        assert_eq!(c.revoke(1000, None), 0); // 1000 has no remaining entries
        assert_eq!(c.revoke(1001, None), 1);
    }
}
