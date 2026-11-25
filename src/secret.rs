//! Secret ids, metadata, new-secret requests and plaintext.
use crate::error::{Result, VaultError};
use crate::scope::{Environment, Scope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroizing;

/// A secret's id (a random UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretId(String);

impl SecretId {
    pub(crate) fn random() -> Self {
        SecretId(uuid::Uuid::new_v4().to_string())
    }

    /// Parses a UUID.
    pub fn parse(s: &str) -> Result<Self> {
        uuid::Uuid::parse_str(s.trim()).map(|u| SecretId(u.hyphenated().to_string())).map_err(|_| VaultError::invalid("secret id", format!("{s:?}")))
    }

    /// The text form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretId {
    type Err = VaultError;
    fn from_str(s: &str) -> Result<Self> {
        SecretId::parse(s)
    }
}

impl TryFrom<String> for SecretId {
    type Error = VaultError;
    fn try_from(s: String) -> Result<Self> {
        SecretId::parse(&s)
    }
}

impl From<SecretId> for String {
    fn from(s: SecretId) -> String {
        s.0
    }
}

/// Free-form labels.
pub type Labels = BTreeMap<String, String>;

/// Where a version stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionState {
    /// Serving reads.
    Active,
    /// Staged by a rotation, not yet serving.
    Pending,
    /// The version before the last promotion, kept until retired.
    Previous,
    /// Replaced and wiped.
    Retired,
    /// A pending version dropped before promotion, wiped.
    Discarded,
}

impl VersionState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VersionState::Active => "active",
            VersionState::Pending => "pending",
            VersionState::Previous => "previous",
            VersionState::Retired => "retired",
            VersionState::Discarded => "discarded",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "active" => VersionState::Active,
            "pending" => VersionState::Pending,
            "previous" => VersionState::Previous,
            "retired" => VersionState::Retired,
            "discarded" => VersionState::Discarded,
            other => return Err(VaultError::Storage(format!("unknown version state {other:?}"))),
        })
    }
}

/// Which version to use or retrieve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Which {
    /// The active version.
    #[default]
    Active,
    /// The staged version (to try new credentials before promoting them).
    Pending,
    /// The version before the last promotion.
    Previous,
}

impl Which {
    /// `active`, `pending` or `previous`.
    pub fn as_str(self) -> &'static str {
        match self {
            Which::Active => "active",
            Which::Pending => "pending",
            Which::Previous => "previous",
        }
    }
}

/// One version's metadata (never its value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMeta {
    /// Its number, from 1.
    pub version: u32,
    /// Where it stands.
    pub state: VersionState,
    /// When it was stored (ms since the Unix epoch).
    pub created_at: i64,
    /// Who stored it.
    pub created_by: String,
}

/// A secret's metadata: the only secret type that is serializable, and so the only one safe
/// to send to clients or MCP. It never holds a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecretMeta {
    /// The id.
    pub id: SecretId,
    /// The scope it lives in.
    pub scope: Scope,
    /// Its name, unique per scope and environment.
    pub name: String,
    /// A free-form kind such as `api-key` or `password`.
    pub kind: String,
    /// Test or live; fixed at creation.
    pub environment: Environment,
    /// Labels.
    pub labels: Labels,
    /// When it was created (ms since the Unix epoch).
    pub created_at: i64,
    /// Who created it.
    pub created_by: String,
    /// When it last changed.
    pub updated_at: i64,
    /// The version serving reads.
    pub active_version: u32,
    /// A staged version, if a rotation is pending.
    pub pending_version: Option<u32>,
    /// The version before the last promotion, if still kept.
    pub previous_version: Option<u32>,
}

impl SecretMeta {
    /// The version number `which` points at, if there is one.
    pub fn version(&self, which: Which) -> Option<u32> {
        match which {
            Which::Active => Some(self.active_version),
            Which::Pending => self.pending_version,
            Which::Previous => self.previous_version,
        }
    }
}

/// The most labels a secret may have.
pub const MAX_LABELS: usize = 64;

fn check_text(what: &'static str, s: &str, max: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && s.trim().is_empty()) || s.len() > max || s.chars().any(char::is_control) {
        return Err(VaultError::invalid(
            what,
            format!("must be {}1 to {max} bytes without control characters", if allow_empty { "0 or " } else { "" }),
        ));
    }
    Ok(())
}

pub(crate) fn check_identity(s: &str) -> Result<()> {
    check_text("identity", s, 256, false)
}

/// What to create.
///
/// ```
/// use weirdnet_vault::{Environment, NewSecret, Scope};
/// let new = NewSecret::new(Scope::new(["tenant-7", "provider-a"]).unwrap(), "api", Environment::Test)
///     .kind("api-key")
///     .label("owner", "desk-1");
/// assert_eq!(new.kind, "api-key");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewSecret {
    /// The scope it goes in.
    pub scope: Scope,
    /// Its name (1 to 128 bytes), unique per scope and environment.
    pub name: String,
    /// A free-form kind (1 to 64 bytes); `secret` by default.
    pub kind: String,
    /// Test or live.
    pub environment: Environment,
    /// Labels (up to 64; keys 1 to 64 bytes, values up to 512).
    pub labels: Labels,
}

impl NewSecret {
    /// A secret named `name` in `scope`, of kind `secret`, with no labels.
    pub fn new(scope: Scope, name: impl Into<String>, environment: Environment) -> Self {
        NewSecret { scope, name: name.into(), kind: "secret".into(), environment, labels: Labels::new() }
    }

    /// Set the kind.
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = kind.into();
        self
    }

    /// Add a label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        check_text("name", &self.name, 128, false)?;
        check_text("kind", &self.kind, 64, false)?;
        check_labels(&self.labels)
    }
}

pub(crate) fn check_labels(labels: &Labels) -> Result<()> {
    if labels.len() > MAX_LABELS {
        return Err(VaultError::invalid("labels", format!("at most {MAX_LABELS}")));
    }
    for (k, v) in labels {
        check_text("label key", k, 64, false)?;
        check_text("label value", v, 512, true)?;
    }
    Ok(())
}

/// A secret value in memory: wiped on drop, never cloned, printed or serialized.
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Plaintext(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as UTF-8.
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).map_err(|_| VaultError::invalid("value", "not UTF-8"))
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext(<{} bytes redacted>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_labels_and_plaintext() {
        let id = SecretId::random();
        assert_eq!(SecretId::parse(id.as_str()).unwrap(), id);
        assert!(SecretId::parse("nope").is_err());
        let p = Plaintext::new(Zeroizing::new(b"hunter2".to_vec()));
        assert_eq!(format!("{p:?}"), "Plaintext(<7 bytes redacted>)");
        assert_eq!(p.as_str().unwrap(), "hunter2");
        let n = NewSecret::new(Scope::root(), "", Environment::Test);
        assert!(n.validate().is_err());
        let n = NewSecret::new(Scope::root(), "ok", Environment::Test).label("k", "v\n");
        assert!(n.validate().is_err());
        let mut l = Labels::new();
        for i in 0..65 {
            l.insert(format!("k{i}"), String::new());
        }
        assert!(check_labels(&l).is_err());
    }
}
