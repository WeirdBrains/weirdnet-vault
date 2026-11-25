//! An encrypted secret and credential store for Weirdnet servers and apps.
//!
//! - **Per-entry sealed values** in a SQLCipher database: each version of each value is sealed
//!   on its own (XChaCha20-Poly1305, bound to its secret, version, environment and scope), with
//!   metadata (name, kind, labels, scope) beside it. Plaintext only lives in [`Plaintext`],
//!   which is wiped on drop and never serialized.
//! - **Scoped access**: every call goes through an environment check, per-identity
//!   [grants](Grant) for `Use` and `Reveal`, and the app's [`Authorize`] hook.
//! - **Use without revealing**: [`Vault::use_secret`] hands the value to a closure inside the
//!   process; [`Vault::reveal`] retrieves it for approved identities, also
//!   [sealed to a recipient key](Vault::reveal_sealed).
//! - **Environments**: a caller bound to [`Environment::Test`] can never touch a live secret.
//! - **Rotation without downtime**: stage, try, promote, roll back, retire.
//! - **A hash-chained, append-only audit log** with time-range queries.
//! - **Keys** from a password (weirdnet-keys keyring, [`VaultHome`]), an OS keychain
//!   ([`KeychainStore`], feature `keychain`), a weirdnet-sync secret store (feature `sync`) or
//!   the caller.
//! - [`AsyncVault`] for Tokio (feature `tokio`, on by default), an `Authorize` over
//!   weirdnet-access (feature `access`) and metadata-only MCP tools (feature `mcp`).
//!
//! ```
//! use std::sync::Arc;
//! use weirdnet_vault::*;
//!
//! # fn main() -> Result<()> {
//! let policy = Arc::new(RolePolicy::with_example_roles());
//! let tenant = Scope::new(["tenant-7"])?;
//! let account = tenant.child("provider-a")?;
//! policy.assign("admin", &Scope::root(), "admin")?;
//! policy.assign("bot", &tenant, "trader")?;
//! policy.assign("alice", &tenant, "viewer")?;
//!
//! let vault = Vault::open_in_memory(policy.clone(), VaultOptions::new())?;
//! let admin = Caller::live("admin");
//! let key = vault.create(&admin, NewSecret::new(account.clone(), "api", Environment::Live).kind("api-key"), b"key:secret")?;
//! vault.grant(&admin, GrantTarget::Scope(account.clone()), "bot", &[GrantAction::Use], None)?;
//!
//! // The bot signs with the key; the key never comes back.
//! let signed = vault.use_secret(&Caller::live("bot"), &key.id, |s| s.len())?;
//! assert_eq!(signed, 10);
//! // It may not retrieve it, and a viewer may only see metadata.
//! assert!(vault.reveal(&Caller::live("bot"), &key.id).is_err());
//! assert_eq!(vault.list(&Caller::live("alice"), &tenant)?.len(), 1);
//! assert!(vault.use_secret(&Caller::live("alice"), &key.id, |_| ()).is_err());
//! // A dry-run context never reaches a live secret.
//! assert!(matches!(vault.use_secret(&Caller::test("bot"), &key.id, |_| ()), Err(VaultError::EnvironmentMismatch { .. })));
//! vault.verify_audit()?;
//! # Ok(()) }
//! ```
//!
//! See the [design](https://github.com/WeirdBrains/weirdnet-vault/blob/main/docs/design/vault.md).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "access")]
pub mod access;
#[cfg(feature = "tokio")]
mod asynch;
mod audit;
mod crypto;
mod error;
mod grant;
mod home;
mod keystore;
#[cfg(feature = "mcp")]
pub mod mcp;
mod policy;
mod recipient;
mod scope;
mod secret;
mod store;
mod vault;

#[cfg(feature = "tokio")]
pub use asynch::AsyncVault;
pub use audit::{AuditHead, AuditQuery, AuditRecord, GENESIS, MAX_DETAIL, MAX_LIMIT, Outcome, verify_chain};
pub use error::{Result, VaultError};
pub use grant::{Grant, GrantAction, GrantId, GrantTarget};
pub use home::VaultHome;
#[cfg(feature = "keychain")]
pub use keystore::KeychainStore;
#[cfg(feature = "sync")]
pub use keystore::SyncSecrets;
pub use keystore::{KeyStore, MemoryKeyStore, load_or_create_key};
pub use policy::{AccessRequest, Action, Authorize, Caller, Decision, RolePolicy};
pub use recipient::RecipientSealed;
pub use scope::{Environment, MAX_DEPTH, MAX_SEGMENT, Scope};
pub use secret::{Labels, MAX_LABELS, NewSecret, Plaintext, SecretId, SecretMeta, VersionMeta, VersionState, Which};
pub use vault::{Clock, Vault, VaultOptions};
pub use weirdnet_keys::exchange::ExchangeSecret;
pub use weirdnet_keys::keyring::InitOutput;
pub use weirdnet_keys::{Key32, SecretString, Zeroizing};
