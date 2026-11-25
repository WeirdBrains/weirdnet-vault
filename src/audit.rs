//! The hash-chained, append-only audit log.
use crate::error::{Result, VaultError};
use crate::policy::Action;
use crate::scope::{Environment, Scope};
use crate::secret::SecretId;
use serde::{Deserialize, Serialize};

/// The `prev_hash` of the first record: 64 zeros.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DOMAIN: &[u8] = b"weirdnet-vault/v1/audit\0";
/// The longest detail text kept, in bytes.
pub const MAX_DETAIL: usize = 512;
/// The most records one query returns.
pub const MAX_LIMIT: usize = 10_000;

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Done.
    Allowed,
    /// Refused (no grant, policy, environment).
    Denied,
    /// Allowed but failed (not found, conflict, storage).
    Failed,
}

impl Outcome {
    /// `allowed`, `denied` or `failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        }
    }

    /// Parses [`as_str`](Outcome::as_str) names.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "allowed" => Ok(Outcome::Allowed),
            "denied" => Ok(Outcome::Denied),
            "failed" => Ok(Outcome::Failed),
            other => Err(VaultError::invalid("outcome", format!("{other:?}"))),
        }
    }
}

/// One audit record. It says who did what, where and when, and how it ended; it never holds a
/// secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Position in the log, from 1, without gaps.
    pub seq: u64,
    /// When (ms since the Unix epoch).
    pub at: i64,
    /// The caller's identity.
    pub actor: String,
    /// The caller's environment.
    pub environment: Environment,
    /// What was asked.
    pub action: Action,
    /// Where.
    pub scope: Scope,
    /// The secret, if any.
    pub secret_id: Option<SecretId>,
    /// The version, if any.
    pub version: Option<u32>,
    /// How it ended.
    pub outcome: Outcome,
    /// A short note: a reason, a grantee, a count.
    pub detail: String,
    /// The previous record's hash ([`GENESIS`] for the first).
    pub prev_hash: String,
    /// This record's hash.
    pub hash: String,
}

fn field(h: &mut blake3::Hasher, b: &[u8]) {
    h.update(&(b.len() as u64).to_le_bytes());
    h.update(b);
}

impl AuditRecord {
    /// The hash this record should have: BLAKE3 over a domain label, `prev_hash` and every
    /// field, each length-prefixed.
    pub fn expected_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        field(&mut h, self.prev_hash.as_bytes());
        h.update(&self.seq.to_le_bytes());
        h.update(&self.at.to_le_bytes());
        field(&mut h, self.actor.as_bytes());
        field(&mut h, self.environment.as_str().as_bytes());
        field(&mut h, self.action.as_str().as_bytes());
        field(&mut h, self.scope.as_str().as_bytes());
        field(&mut h, self.secret_id.as_ref().map(|s| s.as_str()).unwrap_or("").as_bytes());
        match self.version {
            Some(v) => {
                h.update(&[1]);
                h.update(&v.to_le_bytes());
            }
            None => {
                h.update(&[0]);
            }
        }
        field(&mut h, self.outcome.as_str().as_bytes());
        field(&mut h, self.detail.as_bytes());
        h.finalize().to_hex().to_string()
    }

    /// True if [`hash`](AuditRecord::hash) matches the fields.
    pub fn is_intact(&self) -> bool {
        self.hash == self.expected_hash()
    }
}

/// Checks a contiguous run of records: each is intact, follows the one before (or
/// `prev_hash`, when given) and has the next sequence number. Returns the failing `seq`.
pub fn verify_chain(records: &[AuditRecord], prev_hash: Option<&str>) -> Result<()> {
    let mut prev: Option<(&str, u64)> = prev_hash.map(|h| (h, 0));
    for (i, r) in records.iter().enumerate() {
        let linked = match prev {
            Some((h, s)) => r.prev_hash == h && (i == 0 || r.seq == s + 1),
            None => true,
        };
        if !linked || !r.is_intact() {
            return Err(VaultError::AuditBroken(r.seq));
        }
        prev = Some((&r.hash, r.seq));
    }
    Ok(())
}

/// The newest record's position and hash. Publish it somewhere else (another node, a signed
/// note) to make a rewritten log detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHead {
    /// The newest `seq` (0 when the log is empty).
    pub seq: u64,
    /// Its hash ([`GENESIS`] when empty).
    pub hash: String,
}

/// Filters for [`Vault::audit`](crate::Vault::audit). Everything is optional; records come
/// back oldest first.
///
/// ```
/// use weirdnet_vault::{Action, AuditQuery};
/// let q = AuditQuery::new().between(1_000, 2_000).actor("alice").action(Action::Reveal).limit(50);
/// assert_eq!(q.limit, 50);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditQuery {
    /// From this time (inclusive, ms).
    pub from: Option<i64>,
    /// Until this time (exclusive, ms).
    pub to: Option<i64>,
    /// Only records in this scope or below it.
    pub scope: Option<Scope>,
    /// Only this actor.
    pub actor: Option<String>,
    /// Only this action.
    pub action: Option<Action>,
    /// Only this outcome.
    pub outcome: Option<Outcome>,
    /// Only records after this `seq` (paging).
    pub after_seq: Option<u64>,
    /// At most this many (1 to 10 000; 500 by default).
    pub limit: usize,
}

impl Default for AuditQuery {
    fn default() -> Self {
        AuditQuery { from: None, to: None, scope: None, actor: None, action: None, outcome: None, after_seq: None, limit: 500 }
    }
}

impl AuditQuery {
    /// Everything, 500 at a time.
    pub fn new() -> Self {
        Self::default()
    }
    /// `from <= at < to`.
    pub fn between(mut self, from: i64, to: i64) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }
    /// From this time on.
    pub fn since(mut self, from: i64) -> Self {
        self.from = Some(from);
        self
    }
    /// Before this time.
    pub fn until(mut self, to: i64) -> Self {
        self.to = Some(to);
        self
    }
    /// In this scope or below it.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }
    /// By this actor.
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }
    /// For this action.
    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }
    /// With this outcome.
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }
    /// After this `seq`.
    pub fn after(mut self, seq: u64) -> Self {
        self.after_seq = Some(seq);
        self
    }
    /// At most `n`.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, prev: &str) -> AuditRecord {
        let mut r = AuditRecord {
            seq,
            at: seq as i64 * 10,
            actor: "alice".into(),
            environment: Environment::Live,
            action: Action::Use,
            scope: Scope::new(["t"]).unwrap(),
            secret_id: None,
            version: Some(1),
            outcome: Outcome::Allowed,
            detail: "active".into(),
            prev_hash: prev.into(),
            hash: String::new(),
        };
        r.hash = r.expected_hash();
        r
    }

    #[test]
    fn chain_verifies_and_detects_changes() {
        let a = rec(1, GENESIS);
        let b = rec(2, &a.hash);
        let c = rec(3, &b.hash);
        let chain = vec![a, b, c];
        verify_chain(&chain, Some(GENESIS)).unwrap();
        verify_chain(&chain[1..], None).unwrap();
        let mut bad = chain.clone();
        bad[1].actor = "mallory".into();
        assert!(matches!(verify_chain(&bad, Some(GENESIS)), Err(VaultError::AuditBroken(2))));
        let mut gap = chain.clone();
        gap.remove(1);
        assert!(matches!(verify_chain(&gap, Some(GENESIS)), Err(VaultError::AuditBroken(3))));
        let mut v = chain[0].clone();
        v.version = None;
        assert!(!v.is_intact());
    }
}
