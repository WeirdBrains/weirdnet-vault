//! The vault.
use crate::audit::{AuditHead, AuditQuery, AuditRecord, Outcome};
use crate::error::{Result, VaultError};
use crate::grant::{Grant, GrantAction, GrantId, GrantTarget};
use crate::home::{VaultHome, now_ms};
use crate::keystore::{KeyStore, load_or_create_key};
use crate::policy::{AccessRequest, Action, Authorize, Caller, Decision};
use crate::recipient::RecipientSealed;
use crate::scope::{Environment, Scope};
use crate::secret::{NewSecret, Plaintext, SecretId, SecretMeta, VersionMeta, VersionState, Which, check_identity};
use crate::store::{self, Event};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use weirdnet_keys::keyring::{self, InitOutput};
use weirdnet_keys::{Key32, SecretString};
use weirdnet_storage::rusqlite::Connection;

/// The time source (ms since the Unix epoch). Tests pass their own.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> i64 + Send + Sync>);

impl Clock {
    /// The system clock.
    pub fn system() -> Self {
        Clock(Arc::new(now_ms))
    }

    /// Any function.
    pub fn from_fn(f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        Clock(Arc::new(f))
    }

    /// Now.
    pub fn now(&self) -> i64 {
        (self.0)()
    }
}

impl Default for Clock {
    fn default() -> Self {
        Clock::system()
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}

/// Vault-wide settings.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VaultOptions {
    /// Whether [`Action::Reveal`] is possible at all (on by default). With it off, approved
    /// identities can still [`use_secret`](Vault::use_secret).
    pub allow_reveal: bool,
    /// Whether allowed `List` and `ReadMeta` calls and audit queries are recorded (on by
    /// default). Value access, changes, grants and refusals are always recorded.
    pub audit_metadata_reads: bool,
    /// The largest value, in bytes (64 KiB by default).
    pub max_value_len: usize,
    /// The time source.
    pub clock: Clock,
}

impl Default for VaultOptions {
    fn default() -> Self {
        VaultOptions { allow_reveal: true, audit_metadata_reads: true, max_value_len: 64 * 1024, clock: Clock::system() }
    }
}

impl VaultOptions {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }
    /// Turn retrieval on or off.
    pub fn allow_reveal(mut self, on: bool) -> Self {
        self.allow_reveal = on;
        self
    }
    /// Record metadata reads or not.
    pub fn audit_metadata_reads(mut self, on: bool) -> Self {
        self.audit_metadata_reads = on;
        self
    }
    /// The largest value.
    pub fn max_value_len(mut self, n: usize) -> Self {
        self.max_value_len = n;
        self
    }
    /// The time source.
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }
}

#[derive(Clone, Copy)]
enum Step {
    Promote,
    Discard,
    Revert,
    Retire,
}

/// An open vault. It is `Send + Sync`; share it with `Arc` (or use
/// [`AsyncVault`](crate::AsyncVault) from Tokio).
///
/// Every call takes the [`Caller`] and runs the environment check, the grant check (for
/// `Use` and `Reveal`) and the [`Authorize`] hook, and records the outcome in the audit log.
pub struct Vault {
    conn: Mutex<Connection>,
    dek: Key32,
    entry: Key32,
    authz: Arc<dyn Authorize>,
    opts: VaultOptions,
    path: Option<PathBuf>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault").field("path", &self.path).field("opts", &self.opts).finish_non_exhaustive()
    }
}

impl Vault {
    fn from_conn(mut conn: Connection, dek: Key32, authz: Arc<dyn Authorize>, opts: VaultOptions, path: Option<PathBuf>) -> Result<Self> {
        let entry = store::prepare(&mut conn, &dek, opts.clock.now())?;
        Ok(Vault { conn: Mutex::new(conn), dek, entry, authz, opts, path })
    }

    /// Open (or create) the vault database at `path`, keyed with `dek`.
    pub fn open_with_key(path: &Path, dek: &Key32, authz: Arc<dyn Authorize>, opts: VaultOptions) -> Result<Self> {
        let conn = weirdnet_storage::open(path, Some(&dek.0), "vault")?;
        Self::from_conn(conn, dek.clone(), authz, opts, Some(path.to_path_buf()))
    }

    /// A vault in memory, keyed with a random key (tests, examples).
    pub fn open_in_memory(authz: Arc<dyn Authorize>, opts: VaultOptions) -> Result<Self> {
        let dek = Key32::random()?;
        let conn = weirdnet_storage::open_in_memory()?;
        weirdnet_storage::apply_key(&conn, Some(&dek.0))?;
        Self::from_conn(conn, dek, authz, opts, None)
    }

    /// Open (or create) the vault at `path` with the key stored under `key_name` in `store`
    /// (created and stored on first use).
    pub fn open_with_keystore(path: &Path, store: &dyn KeyStore, key_name: &str, authz: Arc<dyn Authorize>, opts: VaultOptions) -> Result<Self> {
        let dek = load_or_create_key(store, key_name)?;
        Self::open_with_key(path, &dek, authz, opts)
    }

    /// Create a password-protected vault in `home`. Show the returned recovery words and
    /// shards to the user once, then drop them.
    pub fn init(home: &VaultHome, password: &SecretString, authz: Arc<dyn Authorize>, opts: VaultOptions) -> Result<(Self, InitOutput)> {
        let out = keyring::init(home, password)?;
        let v = Self::unlock(home, password, authz, opts)?;
        Ok((v, out))
    }

    /// Open the vault in `home` with its password.
    pub fn unlock(home: &VaultHome, password: &SecretString, authz: Arc<dyn Authorize>, opts: VaultOptions) -> Result<Self> {
        let dek = keyring::unlock_with_password(home, password)?;
        Self::open_with_key(&home.database(), &dek, authz, opts)
    }

    /// Open the vault in `home` with its master key (from the recovery words or shards).
    pub fn unlock_with_master(home: &VaultHome, master: &Key32, authz: Arc<dyn Authorize>, opts: VaultOptions) -> Result<Self> {
        let dek = keyring::unlock_with_master(home, master)?;
        Self::open_with_key(&home.database(), &dek, authz, opts)
    }

    /// The database file (`None` in memory).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The settings.
    pub fn options(&self) -> &VaultOptions {
        &self.opts
    }

    fn now(&self) -> i64 {
        self.opts.clock.now()
    }

    fn guard(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        conn: &Connection,
        caller: &Caller,
        action: Action,
        scope: &Scope,
        secret_id: Option<&SecretId>,
        version: Option<u32>,
        outcome: Outcome,
        detail: impl Into<String>,
    ) -> Result<AuditRecord> {
        store::append_audit(conn, Event { caller, action, scope, secret_id, version, outcome, detail: detail.into() }, self.now())
    }

    #[allow(clippy::too_many_arguments)]
    fn refuse<T>(
        &self,
        conn: &Connection,
        caller: &Caller,
        action: Action,
        scope: &Scope,
        secret_id: Option<&SecretId>,
        version: Option<u32>,
        err: VaultError,
    ) -> Result<T> {
        let outcome = if err.is_refusal() { Outcome::Denied } else { Outcome::Failed };
        let detail = match &err {
            VaultError::Denied(why) => why.clone(),
            other => other.to_string(),
        };
        self.record(conn, caller, action, scope, secret_id, version, outcome, detail)?;
        Err(err)
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        conn: &Connection,
        caller: &Caller,
        action: Action,
        scope: &Scope,
        secret: Option<&SecretMeta>,
        grantee: Option<&str>,
        env: Option<Environment>,
    ) -> Result<()> {
        if let Some(env) = env
            && !action.is_metadata_read()
            && !caller.environment.may_touch(env)
        {
            return Err(VaultError::EnvironmentMismatch { caller: caller.environment, secret: env, action });
        }
        if let (Some(ga), Some(m)) = (GrantAction::of(action), secret)
            && !store::has_grant(conn, &caller.identity, m, ga, self.now())?
        {
            return Err(VaultError::Denied(format!("{} has no {ga} grant for this secret", caller.identity)));
        }
        match self.authz.authorize(&AccessRequest { caller, action, scope, secret, grantee }) {
            Decision::Allow => {}
            Decision::Deny(r) => return Err(VaultError::Denied(r)),
        }
        if action == Action::Reveal && !self.opts.allow_reveal {
            return Err(VaultError::Denied("retrieval is turned off for this vault".into()));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn gate(
        &self,
        conn: &Connection,
        caller: &Caller,
        action: Action,
        scope: &Scope,
        secret: Option<&SecretMeta>,
        grantee: Option<&str>,
        env: Option<Environment>,
    ) -> Result<()> {
        match self.check(conn, caller, action, scope, secret, grantee, env) {
            Ok(()) => Ok(()),
            Err(e) => self.refuse(conn, caller, action, scope, secret.map(|s| &s.id), None, e),
        }
    }

    fn load(&self, conn: &Connection, caller: &Caller, action: Action, id: &SecretId) -> Result<SecretMeta> {
        match store::get_secret(conn, id)? {
            Some(m) => Ok(m),
            None => self.refuse(conn, caller, action, &Scope::root(), Some(id), None, VaultError::NotFound(format!("secret {id}"))),
        }
    }

    fn check_len(&self, value: &[u8]) -> Result<()> {
        if value.len() > self.opts.max_value_len {
            return Err(VaultError::invalid("value", format!("larger than {} bytes", self.opts.max_value_len)));
        }
        Ok(())
    }

    fn meta_read(&self, conn: &Connection, caller: &Caller, m: &SecretMeta, detail: &str) -> Result<()> {
        self.gate(conn, caller, Action::ReadMeta, &m.scope, Some(m), None, Some(m.environment))?;
        if self.opts.audit_metadata_reads {
            self.record(conn, caller, Action::ReadMeta, &m.scope, Some(&m.id), None, Outcome::Allowed, detail)?;
        }
        Ok(())
    }

    // ----- metadata -----

    /// One secret's metadata (`ReadMeta`).
    pub fn meta(&self, caller: &Caller, id: &SecretId) -> Result<SecretMeta> {
        let conn = self.guard();
        let m = self.load(&conn, caller, Action::ReadMeta, id)?;
        self.meta_read(&conn, caller, &m, "meta")?;
        Ok(m)
    }

    /// Find a secret by scope, name and environment (`ReadMeta`).
    pub fn find(&self, caller: &Caller, scope: &Scope, name: &str, environment: Environment) -> Result<SecretMeta> {
        let conn = self.guard();
        let Some(m) = store::find_secret(&conn, scope, name, environment)? else {
            return self.refuse(
                &conn,
                caller,
                Action::ReadMeta,
                scope,
                None,
                None,
                VaultError::NotFound(format!("{environment} secret {name:?} in {scope}")),
            );
        };
        self.meta_read(&conn, caller, &m, "find")?;
        Ok(m)
    }

    /// One secret's versions (`ReadMeta`).
    pub fn versions(&self, caller: &Caller, id: &SecretId) -> Result<Vec<VersionMeta>> {
        let conn = self.guard();
        let m = self.load(&conn, caller, Action::ReadMeta, id)?;
        self.meta_read(&conn, caller, &m, "versions")?;
        store::versions(&conn, id)
    }

    /// The secrets in `prefix` (and below it) the caller may list (`List`, checked per secret).
    pub fn list(&self, caller: &Caller, prefix: &Scope) -> Result<Vec<SecretMeta>> {
        let conn = self.guard();
        let all = store::list_secrets(&conn, prefix)?;
        let mut shown = Vec::new();
        for m in all {
            if self.check(&conn, caller, Action::List, &m.scope, Some(&m), None, None).is_ok() {
                shown.push(m);
            }
        }
        if self.opts.audit_metadata_reads {
            self.record(&conn, caller, Action::List, prefix, None, None, Outcome::Allowed, format!("{} shown", shown.len()))?;
        }
        Ok(shown)
    }

    // ----- values -----

    /// Create a secret with its first value (`Create`).
    pub fn create(&self, caller: &Caller, new: NewSecret, value: &[u8]) -> Result<SecretMeta> {
        new.validate()?;
        self.check_len(value)?;
        let mut conn = self.guard();
        self.gate(&conn, caller, Action::Create, &new.scope, None, None, Some(new.environment))?;
        if store::find_secret(&conn, &new.scope, &new.name, new.environment)?.is_some() {
            let e = VaultError::Conflict(format!("a {} secret named {:?} already exists in {}", new.environment, new.name, new.scope));
            return self.refuse(&conn, caller, Action::Create, &new.scope, None, None, e);
        }
        let now = self.now();
        let m = SecretMeta {
            id: SecretId::random(),
            scope: new.scope,
            name: new.name,
            kind: new.kind,
            environment: new.environment,
            labels: new.labels,
            created_at: now,
            created_by: caller.identity.clone(),
            updated_at: now,
            active_version: 1,
            pending_version: None,
            previous_version: None,
        };
        let tx = conn.transaction()?;
        store::insert_secret(&tx, &m)?;
        store::insert_version(&tx, &self.entry, &m, 1, VersionState::Active, value, &caller.identity, now)?;
        self.record(&tx, caller, Action::Create, &m.scope, Some(&m.id), Some(1), Outcome::Allowed, format!("name={:?} kind={:?}", m.name, m.kind))?;
        tx.commit()?;
        Ok(m)
    }

    fn open_value(&self, caller: &Caller, id: &SecretId, which: Which, action: Action) -> Result<(Plaintext, SecretMeta, u32)> {
        let conn = self.guard();
        let m = self.load(&conn, caller, action, id)?;
        self.gate(&conn, caller, action, &m.scope, Some(&m), None, Some(m.environment))?;
        let Some(version) = m.version(which) else {
            return self.refuse(
                &conn,
                caller,
                action,
                &m.scope,
                Some(id),
                None,
                VaultError::NotFound(format!("secret {id} has no {} version", which.as_str())),
            );
        };
        let pt = match store::read_value(&conn, &self.entry, &m, version) {
            Ok(p) => p,
            Err(e) => return self.refuse(&conn, caller, action, &m.scope, Some(id), Some(version), e),
        };
        self.record(&conn, caller, action, &m.scope, Some(id), Some(version), Outcome::Allowed, which.as_str())?;
        Ok((pt, m, version))
    }

    /// Use the active value inside this process (`Use`, needs a `Use` grant). Only `f`'s
    /// result comes back; the value is wiped when `f` returns. The vault is not locked while
    /// `f` runs.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use weirdnet_vault::*;
    /// # fn main() -> Result<()> {
    /// # let vault = Vault::open_in_memory(Arc::new(|_: &AccessRequest<'_>| Decision::Allow), VaultOptions::new())?;
    /// # let admin = Caller::live("admin");
    /// # let scope = Scope::new(["tenant-7", "provider-a"])?;
    /// # let id = vault.create(&admin, NewSecret::new(scope, "api", Environment::Live), b"key:secret")?.id;
    /// # vault.grant(&admin, GrantTarget::Secret(id.clone()), "bot", &[GrantAction::Use], None)?;
    /// let bot = Caller::live("bot");
    /// let signature_len = vault.use_secret(&bot, &id, |s| s.len())?;
    /// assert_eq!(signature_len, 10);
    /// # Ok(()) }
    /// ```
    pub fn use_secret<R>(&self, caller: &Caller, id: &SecretId, f: impl FnOnce(&Plaintext) -> R) -> Result<R> {
        self.use_version(caller, id, Which::Active, f)
    }

    /// [`use_secret`](Vault::use_secret) on a chosen version, for example
    /// [`Which::Pending`] to try new credentials before promoting them.
    pub fn use_version<R>(&self, caller: &Caller, id: &SecretId, which: Which, f: impl FnOnce(&Plaintext) -> R) -> Result<R> {
        let (pt, _, _) = self.open_value(caller, id, which, Action::Use)?;
        Ok(f(&pt))
    }

    /// Retrieve the active value (`Reveal`, needs a `Reveal` grant and
    /// [`VaultOptions::allow_reveal`]).
    pub fn reveal(&self, caller: &Caller, id: &SecretId) -> Result<Plaintext> {
        self.reveal_version(caller, id, Which::Active)
    }

    /// Retrieve a chosen version.
    pub fn reveal_version(&self, caller: &Caller, id: &SecretId, which: Which) -> Result<Plaintext> {
        Ok(self.open_value(caller, id, which, Action::Reveal)?.0)
    }

    /// Retrieve the active value sealed to `recipient`'s X25519 public key (`Reveal`).
    pub fn reveal_sealed(&self, caller: &Caller, id: &SecretId, recipient: &[u8; 32]) -> Result<RecipientSealed> {
        let (pt, m, v) = self.open_value(caller, id, Which::Active, Action::Reveal)?;
        RecipientSealed::seal(&m.id, v, recipient, pt.as_bytes())
    }

    // ----- rotation -----

    /// Stage a new value as the pending version (`Rotate`). The active version keeps serving.
    pub fn stage_rotation(&self, caller: &Caller, id: &SecretId, value: &[u8]) -> Result<SecretMeta> {
        self.check_len(value)?;
        let mut conn = self.guard();
        let mut m = self.load(&conn, caller, Action::Rotate, id)?;
        self.gate(&conn, caller, Action::Rotate, &m.scope, Some(&m), None, Some(m.environment))?;
        if let Some(p) = m.pending_version {
            let e = VaultError::Conflict(format!("v{p} is already pending; promote or discard it first"));
            return self.refuse(&conn, caller, Action::Rotate, &m.scope, Some(id), Some(p), e);
        }
        let now = self.now();
        let tx = conn.transaction()?;
        let v = store::take_version(&tx, id)?;
        store::insert_version(&tx, &self.entry, &m, v, VersionState::Pending, value, &caller.identity, now)?;
        m.pending_version = Some(v);
        m.updated_at = now;
        store::set_pointers(&tx, &m, now)?;
        self.record(&tx, caller, Action::Rotate, &m.scope, Some(id), Some(v), Outcome::Allowed, format!("staged v{v}"))?;
        tx.commit()?;
        Ok(m)
    }

    fn step(&self, caller: &Caller, id: &SecretId, step: Step) -> Result<SecretMeta> {
        let mut conn = self.guard();
        let mut m = self.load(&conn, caller, Action::Rotate, id)?;
        self.gate(&conn, caller, Action::Rotate, &m.scope, Some(&m), None, Some(m.environment))?;
        let missing = match step {
            Step::Promote | Step::Discard => m.pending_version.is_none().then_some("no pending version"),
            Step::Revert | Step::Retire => m.previous_version.is_none().then_some("no previous version"),
        };
        if let Some(why) = missing {
            return self.refuse(&conn, caller, Action::Rotate, &m.scope, Some(id), None, VaultError::Conflict(why.into()));
        }
        let now = self.now();
        let tx = conn.transaction()?;
        let (v, detail) = match step {
            Step::Promote => {
                let p = m.pending_version.take().unwrap_or(m.active_version);
                let mut detail = format!("promoted v{p}; v{} kept as previous", m.active_version);
                if let Some(old) = m.previous_version {
                    store::set_state(&tx, id, old, VersionState::Retired)?;
                    detail.push_str(&format!("; retired v{old}"));
                }
                store::set_state(&tx, id, m.active_version, VersionState::Previous)?;
                store::set_state(&tx, id, p, VersionState::Active)?;
                m.previous_version = Some(m.active_version);
                m.active_version = p;
                (p, detail)
            }
            Step::Discard => {
                let p = m.pending_version.take().unwrap_or(m.active_version);
                store::set_state(&tx, id, p, VersionState::Discarded)?;
                (p, format!("discarded v{p}"))
            }
            Step::Revert => {
                let prev = m.previous_version.unwrap_or(m.active_version);
                store::set_state(&tx, id, m.active_version, VersionState::Previous)?;
                store::set_state(&tx, id, prev, VersionState::Active)?;
                let detail = format!("reverted to v{prev}; v{} kept as previous", m.active_version);
                m.previous_version = Some(m.active_version);
                m.active_version = prev;
                (prev, detail)
            }
            Step::Retire => {
                let prev = m.previous_version.take().unwrap_or(m.active_version);
                store::set_state(&tx, id, prev, VersionState::Retired)?;
                (prev, format!("retired v{prev}"))
            }
        };
        m.updated_at = now;
        store::set_pointers(&tx, &m, now)?;
        self.record(&tx, caller, Action::Rotate, &m.scope, Some(id), Some(v), Outcome::Allowed, detail)?;
        tx.commit()?;
        Ok(m)
    }

    /// Make the pending version active; the old active version is kept as previous
    /// (`Rotate`). An older previous version is retired.
    pub fn promote(&self, caller: &Caller, id: &SecretId) -> Result<SecretMeta> {
        self.step(caller, id, Step::Promote)
    }

    /// Drop the pending version (roll back before promotion; `Rotate`).
    pub fn discard_pending(&self, caller: &Caller, id: &SecretId) -> Result<SecretMeta> {
        self.step(caller, id, Step::Discard)
    }

    /// Swap the active and previous versions (roll back after promotion; `Rotate`).
    pub fn revert(&self, caller: &Caller, id: &SecretId) -> Result<SecretMeta> {
        self.step(caller, id, Step::Revert)
    }

    /// Wipe the previous version once the new one is confirmed (`Rotate`).
    pub fn retire_previous(&self, caller: &Caller, id: &SecretId) -> Result<SecretMeta> {
        self.step(caller, id, Step::Retire)
    }

    /// Delete a secret, its versions and its grants (`Delete`). The audit log keeps its
    /// history.
    pub fn delete(&self, caller: &Caller, id: &SecretId) -> Result<()> {
        let mut conn = self.guard();
        let m = self.load(&conn, caller, Action::Delete, id)?;
        self.gate(&conn, caller, Action::Delete, &m.scope, Some(&m), None, Some(m.environment))?;
        let tx = conn.transaction()?;
        store::wipe_all(&tx, id)?;
        tx.execute("DELETE FROM secrets WHERE id = ?1", [id.as_str()])?;
        self.record(&tx, caller, Action::Delete, &m.scope, Some(id), None, Outcome::Allowed, format!("deleted {:?}", m.name))?;
        tx.commit()?;
        Ok(())
    }

    // ----- grants -----

    fn grant_target(
        &self,
        conn: &Connection,
        caller: &Caller,
        action: Action,
        target: &GrantTarget,
    ) -> Result<(Scope, Option<SecretMeta>, Environment)> {
        Ok(match target {
            GrantTarget::Secret(id) => {
                let m = self.load(conn, caller, action, id)?;
                (m.scope.clone(), Some(m.clone()), m.environment)
            }
            // A scope-wide grant can reach live secrets.
            GrantTarget::Scope(s) => (s.clone(), None, Environment::Live),
        })
    }

    /// Approve `identity` for `actions` on `target`, until `expires_at` if given (`Grant`).
    /// A scope-wide grant needs a live caller.
    pub fn grant(&self, caller: &Caller, target: GrantTarget, identity: &str, actions: &[GrantAction], expires_at: Option<i64>) -> Result<Grant> {
        check_identity(identity)?;
        if actions.is_empty() {
            return Err(VaultError::invalid("grant", "no actions"));
        }
        let conn = self.guard();
        let now = self.now();
        if expires_at.is_some_and(|e| e <= now) {
            return Err(VaultError::invalid("expiry", "already past"));
        }
        let (scope, secret, env) = self.grant_target(&conn, caller, Action::Grant, &target)?;
        self.gate(&conn, caller, Action::Grant, &scope, secret.as_ref(), Some(identity), Some(env))?;
        let g = Grant {
            id: GrantId::random(),
            target,
            identity: identity.to_string(),
            actions: actions.iter().copied().collect(),
            expires_at,
            granted_by: caller.identity.clone(),
            granted_at: now,
        };
        store::insert_grant(&conn, &g)?;
        let until = g.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into());
        let detail = format!("granted {} to {}: {} (expires {until})", g.id, g.identity, crate::grant::actions_text(&g.actions));
        self.record(&conn, caller, Action::Grant, &scope, secret.as_ref().map(|m| &m.id), None, Outcome::Allowed, detail)?;
        Ok(g)
    }

    /// Revoke a grant (`Grant`).
    pub fn revoke(&self, caller: &Caller, grant: &GrantId) -> Result<()> {
        let conn = self.guard();
        let Some(g) = store::get_grant(&conn, grant)? else {
            return self.refuse(&conn, caller, Action::Grant, &Scope::root(), None, None, VaultError::NotFound(format!("grant {grant}")));
        };
        let (scope, secret, env) = self.grant_target(&conn, caller, Action::Grant, &g.target)?;
        self.gate(&conn, caller, Action::Grant, &scope, secret.as_ref(), Some(&g.identity), Some(env))?;
        store::delete_grant(&conn, grant)?;
        self.record(
            &conn,
            caller,
            Action::Grant,
            &scope,
            secret.as_ref().map(|m| &m.id),
            None,
            Outcome::Allowed,
            format!("revoked {} from {}", g.id, g.identity),
        )?;
        Ok(())
    }

    /// The grants on exactly `target` (`ReadMeta`).
    pub fn grants(&self, caller: &Caller, target: &GrantTarget) -> Result<Vec<Grant>> {
        let conn = self.guard();
        let (scope, secret, _) = self.grant_target(&conn, caller, Action::ReadMeta, target)?;
        self.gate(&conn, caller, Action::ReadMeta, &scope, secret.as_ref(), None, None)?;
        if self.opts.audit_metadata_reads {
            self.record(&conn, caller, Action::ReadMeta, &scope, secret.as_ref().map(|m| &m.id), None, Outcome::Allowed, "grants")?;
        }
        store::grants_on(&conn, target)
    }

    /// Every grant that applies to a secret: on it, or on a scope containing it (`ReadMeta`).
    pub fn grants_covering(&self, caller: &Caller, id: &SecretId) -> Result<Vec<Grant>> {
        let conn = self.guard();
        let m = self.load(&conn, caller, Action::ReadMeta, id)?;
        self.meta_read(&conn, caller, &m, "grants covering")?;
        store::grants_covering(&conn, &m)
    }

    // ----- audit -----

    /// Query the audit log (`Audit` on the query's scope, or the root).
    pub fn audit(&self, caller: &Caller, query: &AuditQuery) -> Result<Vec<AuditRecord>> {
        let conn = self.guard();
        let scope = query.scope.clone().unwrap_or_default();
        self.gate(&conn, caller, Action::Audit, &scope, None, None, None)?;
        let out = store::query_audit(&conn, query)?;
        if self.opts.audit_metadata_reads {
            self.record(&conn, caller, Action::Audit, &scope, None, None, Outcome::Allowed, format!("{} records", out.len()))?;
        }
        Ok(out)
    }

    /// Check the whole audit chain and return its head.
    pub fn verify_audit(&self) -> Result<AuditHead> {
        store::verify_audit(&self.guard())
    }

    /// The newest audit record's position and hash.
    pub fn audit_head(&self) -> Result<AuditHead> {
        store::head(&self.guard())
    }

    // ----- backup -----

    /// Copy the vault to `dest` (`Backup`, needs a live caller). With `key`, the copy is keyed
    /// with it and opens with [`Vault::open_with_key`]; without, it keeps the current database
    /// key. The backup is recorded before the copy, so the copy holds its own record.
    pub fn snapshot_to(&self, caller: &Caller, dest: &Path, key: Option<&Key32>) -> Result<()> {
        if self.path.as_deref().is_some_and(|p| p == dest) {
            return Err(VaultError::invalid("snapshot", "the destination is the vault itself"));
        }
        let conn = self.guard();
        let root = Scope::root();
        self.gate(&conn, caller, Action::Backup, &root, None, None, Some(Environment::Live))?;
        self.record(
            &conn,
            caller,
            Action::Backup,
            &root,
            None,
            None,
            Outcome::Allowed,
            if key.is_some() { "snapshot, new key" } else { "snapshot" },
        )?;
        let k = key.unwrap_or(&self.dek);
        weirdnet_storage::snapshot_to(&conn, dest, Some(&k.0))?;
        if key.is_some_and(|k| *k != self.dek) {
            let copy = weirdnet_storage::open(dest, Some(&k.0), "vault snapshot")?;
            store::add_wrap(&copy, &self.entry, k, self.now())?;
            store::remove_wrap(&copy, &self.dek)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_bound_to_their_rows() {
        let v = Vault::open_in_memory(Arc::new(|_: &AccessRequest<'_>| Decision::Allow), VaultOptions::new()).unwrap();
        let admin = Caller::live("admin");
        let s = Scope::new(["t"]).unwrap();
        let a = v.create(&admin, NewSecret::new(s.clone(), "a", Environment::Live), b"value-a").unwrap();
        let b = v.create(&admin, NewSecret::new(s, "b", Environment::Live), b"value-b").unwrap();
        for m in [&a, &b] {
            v.grant(&admin, GrantTarget::Secret(m.id.clone()), "admin", &[GrantAction::Reveal], None).unwrap();
        }
        {
            let c = v.guard();
            c.execute(
                "UPDATE versions SET nonce = (SELECT nonce FROM versions WHERE secret_id = ?2), ct = (SELECT ct FROM versions WHERE secret_id = ?2) WHERE secret_id = ?1",
                [a.id.as_str(), b.id.as_str()],
            )
            .unwrap();
            let raw: String = c.query_row("SELECT group_concat(ct) FROM versions", [], |r| r.get(0)).unwrap();
            assert!(!raw.contains(&hex::encode(b"value-b")), "values are sealed in the database");
            assert!(c.execute("UPDATE audit SET actor = 'x'", []).is_err(), "audit updates are refused");
            assert!(c.execute("DELETE FROM audit", []).is_err(), "audit deletes are refused");
        }
        assert!(matches!(v.reveal(&admin, &a.id), Err(VaultError::Crypto(_))));
        assert_eq!(v.reveal(&admin, &b.id).unwrap().as_bytes(), b"value-b");
        v.verify_audit().unwrap();
    }
}
