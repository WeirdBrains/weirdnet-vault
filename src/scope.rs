//! Scopes (hierarchical keys) and environments.
use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// The longest scope segment, in bytes.
pub const MAX_SEGMENT: usize = 128;
/// The most segments a scope may have.
pub const MAX_DEPTH: usize = 16;

/// A hierarchical key such as `tenant-7/provider-a`. A scope contains itself and every scope
/// below it; the empty scope is the root and contains everything.
///
/// Segments are 1 to 128 characters from `A-Z a-z 0-9 - _ . : @ +`.
///
/// ```
/// use weirdnet_vault::Scope;
/// let tenant = Scope::new(["tenant-7"]).unwrap();
/// let account = tenant.child("provider-a").unwrap();
/// assert!(tenant.contains(&account));
/// assert!(!account.contains(&tenant));
/// assert_eq!(account.to_string(), "tenant-7/provider-a");
/// assert_eq!("tenant-7/provider-a".parse::<Scope>().unwrap(), account);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Scope(String);

fn check_segment(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= MAX_SEGMENT
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@' | b'+'));
    if ok { Ok(()) } else { Err(VaultError::invalid("scope segment", format!("{s:?}"))) }
}

impl Scope {
    /// The root scope (contains everything).
    pub fn root() -> Self {
        Scope(String::new())
    }

    /// A scope from its segments, outermost first.
    pub fn new<I, S>(segments: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Scope::root();
        for s in segments {
            out = out.child(s.as_ref())?;
        }
        Ok(out)
    }

    /// Parses `a/b/c` (the empty string is the root).
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() { Ok(Scope::root()) } else { Scope::new(s.split('/')) }
    }

    /// This scope with one more segment.
    pub fn child(&self, segment: &str) -> Result<Self> {
        check_segment(segment)?;
        if self.depth() >= MAX_DEPTH {
            return Err(VaultError::invalid("scope", format!("deeper than {MAX_DEPTH} segments")));
        }
        Ok(if self.0.is_empty() { Scope(segment.to_string()) } else { Scope(format!("{}/{segment}", self.0)) })
    }

    /// The enclosing scope (`None` for the root).
    pub fn parent(&self) -> Option<Scope> {
        if self.0.is_empty() {
            return None;
        }
        Some(match self.0.rfind('/') {
            Some(i) => Scope(self.0[..i].to_string()),
            None => Scope::root(),
        })
    }

    /// The segments, outermost first (none for the root).
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }

    /// How many segments.
    pub fn depth(&self) -> usize {
        self.segments().count()
    }

    /// The text form, `a/b/c`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for the root.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// True if `other` is this scope or lies below it.
    pub fn contains(&self, other: &Scope) -> bool {
        self.0.is_empty()
            || other.0 == self.0
            || (other.0.len() > self.0.len() && other.0.starts_with(&self.0) && other.0.as_bytes()[self.0.len()] == b'/')
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Scope {
    type Err = VaultError;
    fn from_str(s: &str) -> Result<Self> {
        Scope::parse(s)
    }
}

impl TryFrom<String> for Scope {
    type Error = VaultError;
    fn try_from(s: String) -> Result<Self> {
        Scope::parse(&s)
    }
}

impl From<Scope> for String {
    fn from(s: Scope) -> String {
        s.0
    }
}

/// Which world a secret belongs to, enforced on every call.
///
/// A caller bound to [`Environment::Test`] (dry-run, paper, sandbox) can never use, retrieve,
/// change or delete a [`Environment::Live`] secret, whatever the policy says. A `Live` caller
/// may touch both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    /// Dry-run, paper or sandbox credentials.
    Test,
    /// Real credentials.
    Live,
}

impl Environment {
    /// `test` or `live`.
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Test => "test",
            Environment::Live => "live",
        }
    }

    /// `test` (or `dry-run`, `paper`, `sandbox`) or `live`, in any case.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "test" | "dry-run" | "dryrun" | "paper" | "sandbox" => Ok(Environment::Test),
            "live" => Ok(Environment::Live),
            other => Err(VaultError::invalid("environment", format!("{other:?}: test or live"))),
        }
    }

    /// True if a caller bound to `self` may act on a secret of `secret`.
    pub fn may_touch(self, secret: Environment) -> bool {
        self == Environment::Live || secret == Environment::Test
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Environment {
    type Err = VaultError;
    fn from_str(s: &str) -> Result<Self> {
        Environment::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_nest_and_validate() {
        let root = Scope::root();
        let a = Scope::new(["a"]).unwrap();
        let ab = a.child("b").unwrap();
        let abc = Scope::parse("ab/c").unwrap();
        assert!(root.contains(&ab) && a.contains(&ab) && ab.contains(&ab));
        assert!(!a.contains(&abc), "prefix match must stop at a segment boundary");
        assert!(!ab.contains(&a));
        assert_eq!(ab.parent(), Some(a.clone()));
        assert_eq!(a.parent(), Some(Scope::root()));
        assert_eq!(root.parent(), None);
        assert_eq!(ab.segments().collect::<Vec<_>>(), ["a", "b"]);
        for bad in ["", "a b", "a//b", "/a", "a/", "é"] {
            assert!(Scope::parse(bad).is_err() || bad.is_empty(), "{bad:?}");
        }
        assert!(Scope::new(["x".repeat(129)]).is_err());
        assert!(Scope::new(std::iter::repeat_n("x", 17)).is_err());
        let j = serde_json::to_string(&ab).unwrap();
        assert_eq!(j, "\"a/b\"");
        assert_eq!(serde_json::from_str::<Scope>(&j).unwrap(), ab);
        assert!(serde_json::from_str::<Scope>("\"a b\"").is_err());
    }

    #[test]
    fn environments_parse_and_gate() {
        assert_eq!(Environment::parse("Dry-Run").unwrap(), Environment::Test);
        assert_eq!(Environment::parse("live").unwrap(), Environment::Live);
        assert!(Environment::parse("prod").is_err());
        assert!(Environment::Live.may_touch(Environment::Test));
        assert!(Environment::Live.may_touch(Environment::Live));
        assert!(Environment::Test.may_touch(Environment::Test));
        assert!(!Environment::Test.may_touch(Environment::Live));
    }
}
