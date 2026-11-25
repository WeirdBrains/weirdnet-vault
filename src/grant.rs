//! Grants: the identities approved to use or retrieve a secret.
use crate::error::{Result, VaultError};
use crate::policy::Action;
use crate::scope::Scope;
use crate::secret::SecretId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// What a grant approves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantAction {
    /// Use the value inside the server process.
    Use,
    /// Retrieve the value.
    Reveal,
}

impl GrantAction {
    /// `use` or `reveal`.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantAction::Use => "use",
            GrantAction::Reveal => "reveal",
        }
    }

    /// Parses `use` or `reveal`.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "use" => Ok(GrantAction::Use),
            "reveal" | "retrieve" => Ok(GrantAction::Reveal),
            other => Err(VaultError::invalid("grant action", format!("{other:?}: use or reveal"))),
        }
    }

    /// The vault action it approves.
    pub fn action(self) -> Action {
        match self {
            GrantAction::Use => Action::Use,
            GrantAction::Reveal => Action::Reveal,
        }
    }

    pub(crate) fn of(action: Action) -> Option<Self> {
        match action {
            Action::Use => Some(GrantAction::Use),
            Action::Reveal => Some(GrantAction::Reveal),
            _ => None,
        }
    }
}

impl fmt::Display for GrantAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a grant covers: one secret, or every secret in a scope (and below it).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantTarget {
    /// One secret.
    Secret(SecretId),
    /// Every secret in this scope or below it.
    Scope(Scope),
}

/// A grant's id (a random UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantId(pub(crate) String);

impl GrantId {
    pub(crate) fn random() -> Self {
        GrantId(uuid::Uuid::new_v4().to_string())
    }

    /// Parses a UUID.
    pub fn parse(s: &str) -> Result<Self> {
        uuid::Uuid::parse_str(s.trim()).map(|u| GrantId(u.hyphenated().to_string())).map_err(|_| VaultError::invalid("grant id", format!("{s:?}")))
    }

    /// The text form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An approval for one identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The id (to revoke it).
    pub id: GrantId,
    /// What it covers.
    pub target: GrantTarget,
    /// Who it approves.
    pub identity: String,
    /// What it approves.
    pub actions: BTreeSet<GrantAction>,
    /// When it stops counting (ms since the Unix epoch), if ever.
    pub expires_at: Option<i64>,
    /// Who granted it.
    pub granted_by: String,
    /// When.
    pub granted_at: i64,
}

impl Grant {
    /// True if it has not expired at `now`.
    pub fn is_active(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|e| now < e)
    }

    /// True if it approves `action` for a secret in `scope` with id `id`, at `now`.
    pub fn covers(&self, id: &SecretId, scope: &Scope, action: GrantAction, now: i64) -> bool {
        self.is_active(now)
            && self.actions.contains(&action)
            && match &self.target {
                GrantTarget::Secret(s) => s == id,
                GrantTarget::Scope(s) => s.contains(scope),
            }
    }
}

pub(crate) fn actions_text(actions: &BTreeSet<GrantAction>) -> String {
    actions.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(",")
}

pub(crate) fn parse_actions(s: &str) -> Result<BTreeSet<GrantAction>> {
    s.split(',').filter(|p| !p.is_empty()).map(GrantAction::parse).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_cover_scope_secret_and_expiry() {
        let id = SecretId::random();
        let scope = Scope::new(["t", "a"]).unwrap();
        let mut g = Grant {
            id: GrantId::random(),
            target: GrantTarget::Scope(Scope::new(["t"]).unwrap()),
            identity: "bob".into(),
            actions: [GrantAction::Use].into(),
            expires_at: Some(100),
            granted_by: "admin".into(),
            granted_at: 0,
        };
        assert!(g.covers(&id, &scope, GrantAction::Use, 99));
        assert!(!g.covers(&id, &scope, GrantAction::Use, 100));
        assert!(!g.covers(&id, &scope, GrantAction::Reveal, 0));
        g.target = GrantTarget::Secret(SecretId::random());
        assert!(!g.covers(&id, &scope, GrantAction::Use, 0));
        assert_eq!(parse_actions(&actions_text(&[GrantAction::Reveal, GrantAction::Use].into())).unwrap().len(), 2);
        assert!(GrantAction::parse("delete").is_err());
    }
}
