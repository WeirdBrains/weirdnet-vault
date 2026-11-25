//! Callers, actions and the `Authorize` hook, with a small role policy.
use crate::error::{Result, VaultError};
use crate::scope::{Environment, Scope};
use crate::secret::SecretMeta;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::RwLock;

/// Who is asking: an identity the app has authenticated (a Weirdnet user id, a device peer id,
/// an API-key id, ...) bound to an environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Caller {
    /// The identity.
    pub identity: String,
    /// The environment this caller or context is bound to.
    pub environment: Environment,
}

impl Caller {
    /// A caller bound to `environment`.
    pub fn new(identity: impl Into<String>, environment: Environment) -> Self {
        Caller { identity: identity.into(), environment }
    }

    /// A caller bound to [`Environment::Live`].
    pub fn live(identity: impl Into<String>) -> Self {
        Caller::new(identity, Environment::Live)
    }

    /// A caller bound to [`Environment::Test`] (dry-run).
    pub fn test(identity: impl Into<String>) -> Self {
        Caller::new(identity, Environment::Test)
    }
}

/// What a caller wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// List metadata under a scope.
    List,
    /// Read one secret's metadata, versions and grants.
    ReadMeta,
    /// Create a secret with its first value.
    Create,
    /// Stage, promote, discard, revert or retire a version.
    Rotate,
    /// Delete a secret and all its versions.
    Delete,
    /// Use a value inside the server process without returning it.
    Use,
    /// Retrieve a value.
    Reveal,
    /// Add or revoke grants.
    Grant,
    /// Query the audit log.
    Audit,
    /// Take a snapshot of the vault.
    Backup,
}

impl Action {
    /// Every action.
    pub const ALL: [Action; 10] = [
        Action::List,
        Action::ReadMeta,
        Action::Create,
        Action::Rotate,
        Action::Delete,
        Action::Use,
        Action::Reveal,
        Action::Grant,
        Action::Audit,
        Action::Backup,
    ];

    /// The snake-case name (`read_meta`, `use`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Action::List => "list",
            Action::ReadMeta => "read_meta",
            Action::Create => "create",
            Action::Rotate => "rotate",
            Action::Delete => "delete",
            Action::Use => "use",
            Action::Reveal => "reveal",
            Action::Grant => "grant",
            Action::Audit => "audit",
            Action::Backup => "backup",
        }
    }

    /// Parses [`as_str`](Action::as_str) names (`-` works for `_`).
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().to_ascii_lowercase().replace('-', "_");
        Action::ALL.into_iter().find(|a| a.as_str() == s).ok_or_else(|| VaultError::invalid("action", format!("{s:?}")))
    }

    /// True for actions that only read metadata (`List`, `ReadMeta`, `Audit`).
    pub fn is_metadata_read(self) -> bool {
        matches!(self, Action::List | Action::ReadMeta | Action::Audit)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One request, as the [`Authorize`] hook sees it.
#[derive(Debug, Clone, Copy)]
pub struct AccessRequest<'a> {
    /// Who.
    pub caller: &'a Caller,
    /// What.
    pub action: Action,
    /// Where: the secret's scope, the scope being listed, created in, granted on or audited.
    pub scope: &'a Scope,
    /// The secret, when the request is about one.
    pub secret: Option<&'a SecretMeta>,
    /// For [`Action::Grant`]: the identity being granted or revoked.
    pub grantee: Option<&'a str>,
}

/// The hook's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Go ahead.
    Allow,
    /// Refuse, with a reason that is safe to show and to record.
    Deny(String),
}

impl Decision {
    /// A refusal.
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny(reason.into())
    }
}

/// The app's access policy. Every vault call asks it, after the environment check and (for
/// [`Action::Use`] and [`Action::Reveal`]) the grant check.
///
/// Any `Fn(&AccessRequest) -> Decision` is an `Authorize`, so an app can bridge its own policy:
///
/// ```
/// use weirdnet_vault::{AccessRequest, Action, Authorize, Decision};
/// let read_only = |r: &AccessRequest<'_>| {
///     if r.action.is_metadata_read() { Decision::Allow } else { Decision::deny("read-only") }
/// };
/// let _: &dyn Authorize = &read_only;
/// ```
pub trait Authorize: Send + Sync {
    /// Decide one request.
    fn authorize(&self, request: &AccessRequest<'_>) -> Decision;
}

impl<F> Authorize for F
where
    F: Fn(&AccessRequest<'_>) -> Decision + Send + Sync,
{
    fn authorize(&self, request: &AccessRequest<'_>) -> Decision {
        self(request)
    }
}

#[derive(Default)]
struct RoleState {
    roles: BTreeMap<String, BTreeSet<Action>>,
    members: BTreeMap<String, BTreeSet<(Scope, String)>>,
}

/// A small role policy: roles are named sets of actions, and identities hold roles on scopes
/// (a role on a scope covers everything below it). It can change while the vault runs.
///
/// Nothing is built in. [`RolePolicy::with_example_roles`] defines the usual four:
///
/// | Role | Actions |
/// | --- | --- |
/// | `viewer` | `List`, `ReadMeta` |
/// | `trader` | viewer + `Use` |
/// | `auditor` | viewer + `Audit` |
/// | `admin` | every action |
///
/// Roles say what an identity may do in general; `Use` and `Reveal` also need a grant on the
/// secret (see [`Vault::grant`](crate::Vault::grant)).
///
/// ```
/// use weirdnet_vault::{Action, RolePolicy, Scope};
/// let policy = RolePolicy::with_example_roles();
/// let tenant = Scope::new(["tenant-7"]).unwrap();
/// policy.assign("alice", &tenant, "trader").unwrap();
/// assert!(policy.allows("alice", &tenant.child("provider-a").unwrap(), Action::Use));
/// assert!(!policy.allows("alice", &tenant, Action::Reveal));
/// ```
#[derive(Default)]
pub struct RolePolicy {
    state: RwLock<RoleState>,
}

impl fmt::Debug for RolePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.read();
        f.debug_struct("RolePolicy").field("roles", &s.roles).field("members", &s.members).finish()
    }
}

impl RolePolicy {
    /// No roles, no members: everything is denied.
    pub fn new() -> Self {
        Self::default()
    }

    /// `viewer`, `trader`, `auditor` and `admin` (see the type docs), with no members.
    pub fn with_example_roles() -> Self {
        let p = RolePolicy::new();
        let viewer = [Action::List, Action::ReadMeta];
        p.define_role("viewer", &viewer);
        p.define_role("trader", &[viewer[0], viewer[1], Action::Use]);
        p.define_role("auditor", &[viewer[0], viewer[1], Action::Audit]);
        p.define_role("admin", &Action::ALL);
        p
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, RoleState> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, RoleState> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Define (or redefine) a role.
    pub fn define_role(&self, name: &str, actions: &[Action]) {
        self.write().roles.insert(name.to_string(), actions.iter().copied().collect());
    }

    /// Remove a role and every assignment of it.
    pub fn remove_role(&self, name: &str) {
        let mut s = self.write();
        s.roles.remove(name);
        for held in s.members.values_mut() {
            held.retain(|(_, r)| r != name);
        }
        s.members.retain(|_, held| !held.is_empty());
    }

    /// Give `identity` the role `role` on `scope`.
    pub fn assign(&self, identity: &str, scope: &Scope, role: &str) -> Result<()> {
        let mut s = self.write();
        if !s.roles.contains_key(role) {
            return Err(VaultError::NotFound(format!("role {role:?}")));
        }
        s.members.entry(identity.to_string()).or_default().insert((scope.clone(), role.to_string()));
        Ok(())
    }

    /// Take the role `role` on `scope` away from `identity`.
    pub fn unassign(&self, identity: &str, scope: &Scope, role: &str) {
        let mut s = self.write();
        if let Some(held) = s.members.get_mut(identity) {
            held.remove(&(scope.clone(), role.to_string()));
            if held.is_empty() {
                s.members.remove(identity);
            }
        }
    }

    /// The roles `identity` holds, with their scopes.
    pub fn roles_of(&self, identity: &str) -> Vec<(Scope, String)> {
        self.read().members.get(identity).map(|h| h.iter().cloned().collect()).unwrap_or_default()
    }

    /// True if one of `identity`'s roles on a scope containing `scope` allows `action`.
    pub fn allows(&self, identity: &str, scope: &Scope, action: Action) -> bool {
        let s = self.read();
        s.members
            .get(identity)
            .is_some_and(|held| held.iter().any(|(on, role)| on.contains(scope) && s.roles.get(role).is_some_and(|acts| acts.contains(&action))))
    }
}

impl Authorize for RolePolicy {
    fn authorize(&self, r: &AccessRequest<'_>) -> Decision {
        if self.allows(&r.caller.identity, r.scope, r.action) {
            Decision::Allow
        } else {
            let scope = if r.scope.is_root() { "the root scope".to_string() } else { r.scope.to_string() };
            Decision::deny(format!("no role allows {} on {scope}", r.action))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_round_trip() {
        for a in Action::ALL {
            assert_eq!(Action::parse(a.as_str()).unwrap(), a);
            assert_eq!(serde_json::to_string(&a).unwrap(), format!("\"{}\"", a.as_str()));
        }
        assert_eq!(Action::parse("read-meta").unwrap(), Action::ReadMeta);
        assert!(Action::parse("steal").is_err());
    }

    #[test]
    fn role_policy_scopes_and_changes() {
        let p = RolePolicy::with_example_roles();
        let t = Scope::new(["t1"]).unwrap();
        let acct = t.child("a").unwrap();
        let other = Scope::new(["t2"]).unwrap();
        p.assign("v", &t, "viewer").unwrap();
        p.assign("a", &Scope::root(), "admin").unwrap();
        assert!(p.assign("x", &t, "nope").is_err());
        assert!(p.allows("v", &acct, Action::List));
        assert!(!p.allows("v", &acct, Action::Use));
        assert!(!p.allows("v", &other, Action::List));
        assert!(p.allows("a", &other, Action::Delete));
        p.unassign("v", &t, "viewer");
        assert!(!p.allows("v", &acct, Action::List));
        p.remove_role("admin");
        assert!(!p.allows("a", &other, Action::Delete));
        assert!(p.roles_of("a").is_empty());
    }
}
