use std::fs;
use std::path::{Path, PathBuf};

use globset::Glob;
use serde::Deserialize;

use crate::Effect;

pub const ACTION_NAMESPACE: &str = "org.mimoauth.";

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("cannot read rules file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse rules file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid rule #{index}: {msg}")]
    Invalid { index: usize, msg: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// Glob pattern matched against the full action id.
    pub action: String,
    pub effect: String,
    /// Optional uid-name allowlist; empty means "all users".
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RulesFile {
    /// Fallback effect when no rule matches.
    #[serde(default = "default_effect")]
    pub default: String,
    #[serde(default)]
    pub rule: Vec<Rule>,
}

fn default_effect() -> String {
    "auth_admin".to_string()
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub action_pattern: String,
    pub pattern: globset::GlobMatcher,
    pub effect: Effect,
    pub users: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct Ruleset {
    pub default: Effect,
    pub rules: Vec<CompiledRule>,
    pub origin: String,
}

impl Ruleset {
    /// Built-in rules used when no file exists yet.
    pub fn builtin() -> Self {
        let rules = vec![
            ("org.mimoauth.session.status", "allow"),
            ("org.mimoauth.session.revoke", "allow"),
            ("org.mimoauth.session.rules", "allow"),
        ];
        let compiled = rules
            .iter()
            .enumerate()
            .map(|(i, (pat, eff))| CompiledRule {
                action_pattern: pat.to_string(),
                pattern: Glob::new(pat).expect("builtin glob").compile_matcher(),
                effect: Effect::parse(eff).expect("builtin effect"),
                users: Vec::new(),
                source: format!("builtin#{}", i + 1),
            })
            .collect();
        Ruleset {
            default: Effect::AuthAdmin,
            rules: compiled,
            origin: "builtin".to_string(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, RulesError> {
        let raw = fs::read_to_string(path).map_err(|source| RulesError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let parsed: RulesFile = toml::from_str(&raw).map_err(|source| RulesError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        let default = Effect::parse(&parsed.default).ok_or_else(|| RulesError::Invalid {
            index: 0,
            msg: format!("unknown default effect `{}`", parsed.default),
        })?;

        let mut rules = Vec::with_capacity(parsed.rule.len());
        for (i, r) in parsed.rule.into_iter().enumerate() {
            let effect = Effect::parse(&r.effect).ok_or_else(|| RulesError::Invalid {
                index: i + 1,
                msg: format!("unknown effect `{}`", r.effect),
            })?;
            let glob = Glob::new(&r.action).map_err(|e| RulesError::Invalid {
                index: i + 1,
                msg: e.to_string(),
            })?;
            rules.push(CompiledRule {
                action_pattern: r.action.clone(),
                pattern: glob.compile_matcher(),
                effect,
                users: r.users,
                source: if r.source.is_empty() {
                    path.display().to_string()
                } else {
                    r.source
                },
            });
        }

        Ok(Ruleset {
            default,
            rules,
            origin: path.display().to_string(),
        })
    }

    /// Load from `path` if present, otherwise builtin rules.
    pub fn load_or_builtin(path: &Path) -> Self {
        match Self::load(path) {
            Ok(rs) => rs,
            Err(e) => {
                tracing::warn!("rules falling back to builtin: {e}");
                Self::builtin()
            }
        }
    }

    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mimoauth")
            .join("rules.toml")
    }

    /// Last matching rule wins (general rules first, specific overrides later);
    /// user-scoped rules only apply to the listed users.
    pub fn evaluate(&self, action_id: &str, user: &str) -> (Effect, String) {
        let mut hit: Option<(Effect, String)> = None;
        for r in &self.rules {
            if !r.pattern.is_match(action_id) {
                continue;
            }
            if !r.users.is_empty() && !r.users.iter().any(|u| u == user) {
                continue;
            }
            hit = Some((r.effect, r.action_pattern.clone()));
        }
        hit.unwrap_or((self.default, "default".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_allows_status() {
        let rs = Ruleset::builtin();
        assert_eq!(
            rs.evaluate("org.mimoauth.session.status", "alice").0,
            Effect::Allow
        );
        assert_eq!(
            rs.evaluate("org.example.sudo", "alice").0,
            Effect::AuthAdmin
        );
    }

    #[test]
    fn first_match_wins_and_user_scope() {
        let toml = r#"
default = "auth_admin"
[[rule]]
action = "org.example.*"
effect = "deny"
[[rule]]
action = "org.example.safe"
effect = "allow"
[[rule]]
action = "org.example.alice"
effect = "allow"
users = ["alice"]
"#;
        let dir = std::env::temp_dir().join("mimoauth-rules-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.toml");
        std::fs::write(&path, toml).unwrap();
        let rs = Ruleset::load(&path).unwrap();

        assert_eq!(rs.evaluate("org.example.other", "bob").0, Effect::Deny);
        assert_eq!(rs.evaluate("org.example.alice", "bob").0, Effect::Deny);
        assert_eq!(rs.evaluate("org.example.alice", "alice").0, Effect::Allow);
        assert_eq!(rs.evaluate("unknown.action", "bob").0, Effect::AuthAdmin);
    }
}
