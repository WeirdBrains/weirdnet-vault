//! A vault folder whose database key the weirdnet-keys keyring keeps (password, master key,
//! recovery words and shards).
use crate::error::{Result, VaultError};
use crate::store;
use std::path::{Path, PathBuf};
use weirdnet_keys::keyring::{EncryptedDatabase, KeyFiles};
use weirdnet_keys::{Key32, Profile};

/// A vault folder: `envelope.toml`, `service/` (the keyring's files) and `vault.db`.
///
/// It implements weirdnet-keys' `KeyFiles` and `EncryptedDatabase`, so every keyring
/// operation works on it: [`Vault::init`](crate::Vault::init) and the unlock calls, and, with
/// the vault closed, `weirdnet_keys::keyring::rotate` (new service key and password),
/// `rekey` (new database key; values are not resealed) and `recover`.
#[derive(Debug, Clone)]
pub struct VaultHome {
    dir: PathBuf,
    profile: Profile,
}

impl VaultHome {
    /// A vault in `dir`, with the default weirdnet-keys profile.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        VaultHome { dir: dir.into(), profile: Profile::WEIRDNET }
    }

    /// A vault in `dir` whose keys use `profile`'s labels.
    pub fn with_profile(dir: impl Into<PathBuf>, profile: Profile) -> Self {
        VaultHome { dir: dir.into(), profile }
    }

    /// The folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The database file.
    pub fn database(&self) -> PathBuf {
        self.dir.join("vault.db")
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl KeyFiles for VaultHome {
    type Error = VaultError;

    fn profile(&self) -> Profile {
        self.profile
    }
    fn home(&self) -> PathBuf {
        self.dir.clone()
    }
    fn envelope(&self) -> PathBuf {
        self.dir.join("envelope.toml")
    }
    fn service_keys_dir(&self) -> PathBuf {
        self.dir.join("service")
    }
    fn prepare(&self) -> Result<()> {
        weirdnet_storage::files::ensure_dir(&self.dir)?;
        weirdnet_storage::files::ensure_dir(&self.service_keys_dir())?;
        Ok(())
    }
    fn ensure_dir(&self, dir: &Path) -> Result<()> {
        Ok(weirdnet_storage::files::ensure_dir(dir)?)
    }
    fn write_private(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        Ok(weirdnet_storage::files::write_private(path, bytes)?)
    }
}

impl EncryptedDatabase for VaultHome {
    fn database_exists(&self) -> bool {
        self.database().exists()
    }

    fn encrypt_plaintext(&self, dek: &Key32) -> Result<()> {
        weirdnet_storage::encrypt_plaintext_in_place(&self.database(), &dek.0)?;
        self.open_keyed(dek)
    }

    fn open_keyed(&self, dek: &Key32) -> Result<()> {
        let mut c = weirdnet_storage::open(&self.database(), Some(&dek.0), "vault")?;
        store::prepare(&mut c, dek, now_ms())?;
        Ok(())
    }

    fn rekey_database(&self, old: &Key32, new: &Key32) -> Result<()> {
        let db = self.database();
        let mut c = weirdnet_storage::open(&db, Some(&old.0), "vault")?;
        let entry = store::prepare(&mut c, old, now_ms())?;
        store::add_wrap(&c, &entry, new, now_ms())?;
        if let Err(e) = weirdnet_storage::rekey(&c, &new.0) {
            let _ = store::remove_wrap(&c, new);
            return Err(e.into());
        }
        drop(c);
        let c = weirdnet_storage::open(&db, Some(&new.0), "vault")?;
        store::remove_wrap(&c, old)
    }

    fn remove_database(&self) {
        let db = self.database();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut p = db.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }
}
