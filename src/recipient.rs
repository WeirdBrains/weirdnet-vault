//! Values sealed to a recipient's X25519 key.
use crate::error::{Result, VaultError};
use crate::secret::{Plaintext, SecretId};
use serde::{Deserialize, Serialize};
use weirdnet_keys::exchange::ExchangeSecret;
use weirdnet_keys::{Sealed, kdf::hkdf, open, seal};

const INFO: &[u8] = b"weirdnet-vault/v1/recipient";

/// A retrieved value sealed to one recipient: an ephemeral X25519 key agreement, HKDF over
/// the shared secret bound to both public keys, the secret id and version, then
/// XChaCha20-Poly1305. Only the holder of the recipient's secret key can open it, so it can
/// travel over any channel.
///
/// ```no_run
/// # fn demo(vault: &weirdnet_vault::Vault, caller: &weirdnet_vault::Caller, id: &weirdnet_vault::SecretId) -> weirdnet_vault::Result<()> {
/// use weirdnet_vault::ExchangeSecret;
/// let mine = ExchangeSecret::generate();
/// let sealed = vault.reveal_sealed(caller, id, &mine.public())?;
/// let value = sealed.open(&mine)?;
/// # let _ = value; Ok(()) }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipientSealed {
    /// The secret.
    pub secret_id: SecretId,
    /// The version sealed.
    pub version: u32,
    /// The ephemeral public key (hex).
    pub ephemeral: String,
    /// The recipient's public key (hex).
    pub recipient: String,
    /// The sealed value.
    pub sealed: Sealed,
}

fn aad(id: &SecretId, version: u32, eph: &[u8; 32], rcpt: &[u8; 32]) -> Vec<u8> {
    let mut a = INFO.to_vec();
    a.push(0);
    a.extend_from_slice(id.as_str().as_bytes());
    a.push(0);
    a.extend_from_slice(&version.to_le_bytes());
    a.extend_from_slice(eph);
    a.extend_from_slice(rcpt);
    a
}

fn transcript(eph: &[u8; 32], rcpt: &[u8; 32]) -> [u8; 64] {
    let mut t = [0u8; 64];
    t[..32].copy_from_slice(eph);
    t[32..].copy_from_slice(rcpt);
    t
}

fn key32(hexs: &str, what: &'static str) -> Result<[u8; 32]> {
    let b = hex::decode(hexs).map_err(|_| VaultError::invalid(what, "not hex"))?;
    b.try_into().map_err(|_| VaultError::invalid(what, "not 32 bytes"))
}

impl RecipientSealed {
    pub(crate) fn seal(id: &SecretId, version: u32, recipient: &[u8; 32], value: &[u8]) -> Result<Self> {
        let eph = ExchangeSecret::generate();
        let eph_pub = eph.public();
        let shared = eph.agree(recipient).ok_or_else(|| VaultError::invalid("recipient key", "low-order key"))?;
        let key = hkdf(&shared[..], Some(&transcript(&eph_pub, recipient)), INFO)?;
        let sealed = seal(&key, value, &aad(id, version, &eph_pub, recipient))?;
        Ok(RecipientSealed { secret_id: id.clone(), version, ephemeral: hex::encode(eph_pub), recipient: hex::encode(recipient), sealed })
    }

    /// Opens it with the recipient's secret key.
    pub fn open(&self, secret: &ExchangeSecret) -> Result<Plaintext> {
        let eph = key32(&self.ephemeral, "ephemeral key")?;
        let rcpt = key32(&self.recipient, "recipient key")?;
        if secret.public() != rcpt {
            return Err(VaultError::Unlock("sealed to a different recipient".into()));
        }
        let shared = secret.agree(&eph).ok_or_else(|| VaultError::invalid("ephemeral key", "low-order key"))?;
        let key = hkdf(&shared[..], Some(&transcript(&eph, &rcpt)), INFO)?;
        let v = open(&key, &self.sealed, &aad(&self.secret_id, self.version, &eph, &rcpt))?;
        Ok(Plaintext::new(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_to_one_recipient() {
        let id = SecretId::random();
        let r = ExchangeSecret::generate();
        let s = RecipientSealed::seal(&id, 3, &r.public(), b"k:s").unwrap();
        assert_eq!(s.open(&r).unwrap().as_bytes(), b"k:s");
        assert!(s.open(&ExchangeSecret::generate()).is_err());
        let mut moved = s.clone();
        moved.version = 4;
        assert!(moved.open(&r).is_err());
        assert!(RecipientSealed::seal(&id, 1, &[0u8; 32], b"x").is_err());
    }
}
