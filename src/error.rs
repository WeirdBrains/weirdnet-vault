//! Vault errors. None of them carries a secret value, a key or a password.
use crate::policy::Action;
use crate::scope::Environment;

/// Everything that can go wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The caller is not allowed to do this (no grant, the policy said no, or retrieval is off).
    #[error("denied: {0}")]
    Denied(String),
    /// A caller bound to one environment asked for a secret of another.
    #[error("a {caller} caller may not {action} a {secret} secret")]
    EnvironmentMismatch {
        /// The caller's environment.
        caller: Environment,
        /// The secret's environment.
        secret: Environment,
        /// What was asked.
        action: Action,
    },
    /// No such secret, version or grant.
    #[error("not found: {0}")]
    NotFound(String),
    /// The request clashes with the current state (a name taken, a rotation already pending).
    #[error("conflict: {0}")]
    Conflict(String),
    /// A name, value or argument is not valid.
    #[error("invalid {what}: {msg}")]
    Invalid {
        /// What.
        what: &'static str,
        /// Why.
        msg: String,
    },
    /// A wrong key or password, or a key that does not belong to this vault.
    #[error("could not unlock: {0}")]
    Unlock(String),
    /// Sealing or opening failed.
    #[error("crypto: {0}")]
    Crypto(String),
    /// The database failed.
    #[error("storage: {0}")]
    Storage(String),
    /// A key store (keychain, secret store) failed.
    #[error("key store: {0}")]
    KeyStore(String),
    /// The audit chain does not verify at this sequence number.
    #[error("audit log does not verify at record {0}")]
    AuditBroken(u64),
    /// A file operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl VaultError {
    pub(crate) fn invalid(what: &'static str, msg: impl Into<String>) -> Self {
        VaultError::Invalid { what, msg: msg.into() }
    }

    /// True for refusals (`Denied`, `EnvironmentMismatch`), which the audit log records as
    /// denied rather than failed.
    pub fn is_refusal(&self) -> bool {
        matches!(self, VaultError::Denied(_) | VaultError::EnvironmentMismatch { .. })
    }
}

impl From<weirdnet_keys::KeysError> for VaultError {
    fn from(e: weirdnet_keys::KeysError) -> Self {
        use weirdnet_keys::KeysError as K;
        match e {
            K::Unlock(m) => VaultError::Unlock(m),
            K::NotInitialized(_) => VaultError::NotFound("the vault's keys are not initialized".into()),
            K::Io(e) => VaultError::Io(e),
            K::Invalid { what, msg } => VaultError::Invalid { what, msg },
            other => VaultError::Crypto(other.to_string()),
        }
    }
}

impl From<weirdnet_storage::StorageError> for VaultError {
    fn from(e: weirdnet_storage::StorageError) -> Self {
        use weirdnet_storage::StorageError as S;
        match e {
            S::WrongKey { .. } => VaultError::Unlock(e.to_string()),
            S::Io(e) => VaultError::Io(e),
            other => VaultError::Storage(other.to_string()),
        }
    }
}

impl From<weirdnet_storage::rusqlite::Error> for VaultError {
    fn from(e: weirdnet_storage::rusqlite::Error) -> Self {
        VaultError::Storage(e.to_string())
    }
}

/// `Result` with [`VaultError`].
pub type Result<T, E = VaultError> = std::result::Result<T, E>;
