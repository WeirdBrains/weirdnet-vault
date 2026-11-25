//! `AsyncVault`: the vault for Tokio servers.
use crate::audit::{AuditHead, AuditQuery, AuditRecord};
use crate::error::{Result, VaultError};
use crate::grant::{Grant, GrantAction, GrantId, GrantTarget};
use crate::policy::Caller;
use crate::recipient::RecipientSealed;
use crate::scope::Scope;
use crate::secret::{NewSecret, Plaintext, SecretId, SecretMeta, VersionMeta, Which};
use crate::vault::Vault;
use std::path::PathBuf;
use std::sync::Arc;
use weirdnet_keys::Key32;
use zeroize::Zeroizing;

/// A cheap-to-clone handle that runs every vault call on Tokio's blocking pool, so database
/// and crypto work never stalls the runtime.
///
/// ```
/// # use std::sync::Arc;
/// # use weirdnet_vault::*;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// let policy = Arc::new(|_: &AccessRequest<'_>| Decision::Allow);
/// let vault = AsyncVault::new(Vault::open_in_memory(policy, VaultOptions::new())?);
/// let admin = Caller::live("admin");
/// let scope = Scope::new(["tenant-7", "provider-a"])?;
/// let meta = vault.create(admin.clone(), NewSecret::new(scope, "api", Environment::Live), b"k:s".to_vec().into()).await?;
/// vault.grant(admin.clone(), GrantTarget::Secret(meta.id.clone()), "bot".into(), vec![GrantAction::Use], None).await?;
/// let n = vault.use_secret(Caller::live("bot"), meta.id, |s| s.len()).await?;
/// assert_eq!(n, 3);
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct AsyncVault {
    inner: Arc<Vault>,
}

impl AsyncVault {
    /// Wrap a vault.
    pub fn new(vault: Vault) -> Self {
        AsyncVault { inner: Arc::new(vault) }
    }

    /// Wrap a shared vault.
    pub fn from_arc(vault: Arc<Vault>) -> Self {
        AsyncVault { inner: vault }
    }

    /// The vault (for sync code on a blocking thread).
    pub fn vault(&self) -> &Arc<Vault> {
        &self.inner
    }

    /// Run any vault call on the blocking pool.
    pub async fn run<R, F>(&self, f: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&Vault) -> Result<R> + Send + 'static,
    {
        let v = self.inner.clone();
        tokio::task::spawn_blocking(move || f(&v)).await.map_err(|e| VaultError::Storage(format!("vault task failed: {e}")))?
    }

    /// [`Vault::create`].
    pub async fn create(&self, caller: Caller, new: NewSecret, value: Zeroizing<Vec<u8>>) -> Result<SecretMeta> {
        self.run(move |v| v.create(&caller, new, &value)).await
    }

    /// [`Vault::meta`].
    pub async fn meta(&self, caller: Caller, id: SecretId) -> Result<SecretMeta> {
        self.run(move |v| v.meta(&caller, &id)).await
    }

    /// [`Vault::versions`].
    pub async fn versions(&self, caller: Caller, id: SecretId) -> Result<Vec<VersionMeta>> {
        self.run(move |v| v.versions(&caller, &id)).await
    }

    /// [`Vault::list`].
    pub async fn list(&self, caller: Caller, prefix: Scope) -> Result<Vec<SecretMeta>> {
        self.run(move |v| v.list(&caller, &prefix)).await
    }

    /// [`Vault::use_secret`]; `f` runs on the blocking pool.
    pub async fn use_secret<R, F>(&self, caller: Caller, id: SecretId, f: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&Plaintext) -> R + Send + 'static,
    {
        self.run(move |v| v.use_secret(&caller, &id, f)).await
    }

    /// [`Vault::use_version`].
    pub async fn use_version<R, F>(&self, caller: Caller, id: SecretId, which: Which, f: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&Plaintext) -> R + Send + 'static,
    {
        self.run(move |v| v.use_version(&caller, &id, which, f)).await
    }

    /// [`Vault::reveal`].
    pub async fn reveal(&self, caller: Caller, id: SecretId) -> Result<Plaintext> {
        self.run(move |v| v.reveal(&caller, &id)).await
    }

    /// [`Vault::reveal_sealed`].
    pub async fn reveal_sealed(&self, caller: Caller, id: SecretId, recipient: [u8; 32]) -> Result<RecipientSealed> {
        self.run(move |v| v.reveal_sealed(&caller, &id, &recipient)).await
    }

    /// [`Vault::stage_rotation`].
    pub async fn stage_rotation(&self, caller: Caller, id: SecretId, value: Zeroizing<Vec<u8>>) -> Result<SecretMeta> {
        self.run(move |v| v.stage_rotation(&caller, &id, &value)).await
    }

    /// [`Vault::promote`].
    pub async fn promote(&self, caller: Caller, id: SecretId) -> Result<SecretMeta> {
        self.run(move |v| v.promote(&caller, &id)).await
    }

    /// [`Vault::discard_pending`].
    pub async fn discard_pending(&self, caller: Caller, id: SecretId) -> Result<SecretMeta> {
        self.run(move |v| v.discard_pending(&caller, &id)).await
    }

    /// [`Vault::revert`].
    pub async fn revert(&self, caller: Caller, id: SecretId) -> Result<SecretMeta> {
        self.run(move |v| v.revert(&caller, &id)).await
    }

    /// [`Vault::retire_previous`].
    pub async fn retire_previous(&self, caller: Caller, id: SecretId) -> Result<SecretMeta> {
        self.run(move |v| v.retire_previous(&caller, &id)).await
    }

    /// [`Vault::delete`].
    pub async fn delete(&self, caller: Caller, id: SecretId) -> Result<()> {
        self.run(move |v| v.delete(&caller, &id)).await
    }

    /// [`Vault::grant`].
    pub async fn grant(
        &self,
        caller: Caller,
        target: GrantTarget,
        identity: String,
        actions: Vec<GrantAction>,
        expires_at: Option<i64>,
    ) -> Result<Grant> {
        self.run(move |v| v.grant(&caller, target, &identity, &actions, expires_at)).await
    }

    /// [`Vault::revoke`].
    pub async fn revoke(&self, caller: Caller, grant: GrantId) -> Result<()> {
        self.run(move |v| v.revoke(&caller, &grant)).await
    }

    /// [`Vault::grants`].
    pub async fn grants(&self, caller: Caller, target: GrantTarget) -> Result<Vec<Grant>> {
        self.run(move |v| v.grants(&caller, &target)).await
    }

    /// [`Vault::audit`].
    pub async fn audit(&self, caller: Caller, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        self.run(move |v| v.audit(&caller, &query)).await
    }

    /// [`Vault::verify_audit`].
    pub async fn verify_audit(&self) -> Result<AuditHead> {
        self.run(|v| v.verify_audit()).await
    }

    /// [`Vault::snapshot_to`].
    pub async fn snapshot_to(&self, caller: Caller, dest: PathBuf, key: Option<Key32>) -> Result<()> {
        self.run(move |v| v.snapshot_to(&caller, &dest, key.as_ref())).await
    }
}
