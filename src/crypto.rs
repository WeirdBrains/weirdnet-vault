//! Entry-key wrapping and per-entry sealing.
use crate::error::{Result, VaultError};
use crate::scope::{Environment, Scope};
use crate::secret::SecretId;
use weirdnet_keys::{Key32, Sealed, kdf::hkdf, open, seal};
use zeroize::Zeroizing;

const WRAP_INFO: &[u8] = b"weirdnet-vault/v1/entry-wrap";
pub(crate) const WRAP_AAD: &[u8] = b"weirdnet-vault/v1/entry-key";
const KEY_ID_CONTEXT: &str = "weirdnet-vault/v1/key-id";

/// The key that wraps the entry key, derived from the database key.
pub(crate) fn wrap_key(dek: &Key32) -> Result<Key32> {
    Ok(hkdf(&dek.0, None, WRAP_INFO)?)
}

/// A public id for a wrapping key (it reveals nothing about the key).
pub(crate) fn key_id(wrap: &Key32) -> String {
    hex::encode(&blake3::derive_key(KEY_ID_CONTEXT, &wrap.0)[..16])
}

fn value_aad(id: &SecretId, version: u32, env: Environment, scope: &Scope) -> Vec<u8> {
    let mut a = b"weirdnet-vault/v1/value\0".to_vec();
    for part in [id.as_str().as_bytes(), &version.to_le_bytes(), env.as_str().as_bytes(), scope.as_str().as_bytes()] {
        a.extend_from_slice(&(part.len() as u32).to_le_bytes());
        a.extend_from_slice(part);
    }
    a
}

pub(crate) fn seal_value(entry: &Key32, id: &SecretId, version: u32, env: Environment, scope: &Scope, value: &[u8]) -> Result<Sealed> {
    Ok(seal(entry, value, &value_aad(id, version, env, scope))?)
}

pub(crate) fn open_value(entry: &Key32, id: &SecretId, version: u32, env: Environment, scope: &Scope, s: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    open(entry, s, &value_aad(id, version, env, scope))
        .map_err(|_| VaultError::Crypto(format!("secret {id} v{version} does not open (tampered or moved)")))
}
