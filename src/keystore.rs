//! Places that keep the vault's database key by name: memory, the OS keychain (feature
//! `keychain`) and weirdnet-sync secret stores (feature `sync`).
use crate::error::{Result, VaultError};
use std::collections::HashMap;
use std::sync::Mutex;
use weirdnet_keys::Key32;
use zeroize::Zeroizing;

/// Keeps secret bytes by name.
pub trait KeyStore: Send + Sync {
    /// The bytes, or `None` when nothing is stored under `name`.
    fn load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    /// Store (replace) the bytes.
    fn store(&self, name: &str, bytes: &[u8]) -> Result<()>;
    /// Forget them (no error when there is nothing).
    fn remove(&self, name: &str) -> Result<()>;
}

/// The 32-byte key stored under `name`, or a new random one, stored and read back.
pub fn load_or_create_key(store: &dyn KeyStore, name: &str) -> Result<Key32> {
    if let Some(b) = store.load(name)? {
        return Key32::from_slice(&b).map_err(|_| VaultError::KeyStore(format!("{name:?} does not hold a 32-byte key")));
    }
    let k = Key32::random()?;
    store.store(name, &k.0)?;
    match store.load(name)? {
        Some(b) if b.as_slice() == k.0.as_slice() => Ok(k),
        _ => Err(VaultError::KeyStore(format!("{name:?} did not read back after storing"))),
    }
}

/// An in-memory key store (tests, examples).
#[derive(Default)]
pub struct MemoryKeyStore {
    map: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for MemoryKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.map.lock().map(|m| m.len()).unwrap_or(0);
        write!(f, "MemoryKeyStore({n} entries)")
    }
}

impl MemoryKeyStore {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.map.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned())
    }
    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    fn remove(&self, name: &str) -> Result<()> {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
        Ok(())
    }
}

#[cfg(feature = "keychain")]
pub use keychain::KeychainStore;

#[cfg(feature = "keychain")]
mod keychain {
    use super::KeyStore;
    use crate::error::{Result, VaultError};
    use keyring_core::{CredentialStore, Entry, Error as KcError};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn kc(e: KcError) -> VaultError {
        VaultError::KeyStore(e.to_string())
    }

    /// The OS keychain: macOS Keychain, Windows Credential Manager, or the Secret Service on
    /// Linux and the BSDs. Entries are `(service, name)`.
    ///
    /// Calls block (some go over D-Bus or XPC); from async code, call them through
    /// [`AsyncVault`](crate::AsyncVault) or `spawn_blocking`.
    #[derive(Clone)]
    pub struct KeychainStore {
        store: Arc<CredentialStore>,
        service: String,
    }

    impl std::fmt::Debug for KeychainStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("KeychainStore").field("service", &self.service).finish_non_exhaustive()
        }
    }

    impl KeychainStore {
        /// This platform's keychain, with entries under `service` (for example your app id).
        pub fn native(service: &str) -> Result<Self> {
            Ok(KeychainStore { store: native_store()?, service: service.to_string() })
        }

        /// Any `keyring-core` store (another backend, or `keyring_core::mock` in tests).
        pub fn with_store(store: Arc<CredentialStore>, service: &str) -> Self {
            KeychainStore { store, service: service.to_string() }
        }

        /// The service name.
        pub fn service(&self) -> &str {
            &self.service
        }

        fn entry(&self, name: &str) -> Result<Entry> {
            Entry::new_in_store(&self.store, &self.service, name).map_err(kc)
        }
    }

    #[cfg(target_os = "macos")]
    fn native_store() -> Result<Arc<CredentialStore>> {
        Ok(apple_native_keyring_store::keychain::Store::new().map_err(kc)?)
    }

    #[cfg(target_os = "windows")]
    fn native_store() -> Result<Arc<CredentialStore>> {
        Ok(windows_native_keyring_store::Store::new().map_err(kc)?)
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
    fn native_store() -> Result<Arc<CredentialStore>> {
        Ok(zbus_secret_service_keyring_store::Store::new().map_err(kc)?)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))))]
    fn native_store() -> Result<Arc<CredentialStore>> {
        Err(VaultError::KeyStore("no native keychain on this platform; use KeychainStore::with_store".into()))
    }

    impl KeyStore for KeychainStore {
        fn load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            match self.entry(name)?.get_secret() {
                Ok(b) => Ok(Some(Zeroizing::new(b))),
                Err(KcError::NoEntry) => Ok(None),
                Err(e) => Err(kc(e)),
            }
        }
        fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
            self.entry(name)?.set_secret(bytes).map_err(kc)
        }
        fn remove(&self, name: &str) -> Result<()> {
            match self.entry(name)?.delete_credential() {
                Ok(()) | Err(KcError::NoEntry) => Ok(()),
                Err(e) => Err(kc(e)),
            }
        }
    }
}

#[cfg(feature = "sync")]
pub use sync::SyncSecrets;

#[cfg(feature = "sync")]
mod sync {
    use super::KeyStore;
    use crate::error::{Result, VaultError};
    use zeroize::Zeroizing;

    /// Any weirdnet-sync `SecretStore` (such as `FileSecrets`) as a [`KeyStore`].
    #[derive(Debug, Clone)]
    pub struct SyncSecrets<S>(pub S);

    fn se(e: weirdnet_sync::SyncError) -> VaultError {
        VaultError::KeyStore(e.to_string())
    }

    impl<S: weirdnet_sync::SecretStore> KeyStore for SyncSecrets<S> {
        fn load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            self.0.read(name).map_err(se)
        }
        fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
            self.0.write(name, bytes).map_err(se)
        }
        fn remove(&self, name: &str) -> Result<()> {
            self.0.remove(name).map_err(se)
        }
    }

    macro_rules! secret_store {
        ($t:ty) => {
            /// weirdnet-sync's `SecretStore`, so an `Identity` can keep its secrets here.
            impl weirdnet_sync::SecretStore for $t {
                fn read(&self, name: &str) -> weirdnet_sync::Result<Option<Zeroizing<Vec<u8>>>> {
                    KeyStore::load(self, name).map_err(|e| weirdnet_sync::SyncError::Io(e.to_string()))
                }
                fn write(&self, name: &str, bytes: &[u8]) -> weirdnet_sync::Result<()> {
                    KeyStore::store(self, name, bytes).map_err(|e| weirdnet_sync::SyncError::Io(e.to_string()))
                }
                fn remove(&self, name: &str) -> weirdnet_sync::Result<()> {
                    KeyStore::remove(self, name).map_err(|e| weirdnet_sync::SyncError::Io(e.to_string()))
                }
            }
        };
    }

    secret_store!(super::MemoryKeyStore);
    #[cfg(feature = "keychain")]
    secret_store!(super::KeychainStore);
}
