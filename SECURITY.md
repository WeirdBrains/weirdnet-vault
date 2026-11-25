# weirdnet-vault security notes

Not audited.

- **At rest.** The database is SQLCipher-encrypted with a random 256-bit key. Each version of
  each value is sealed again with XChaCha20-Poly1305 under a separate entry key, with its
  secret id, version, environment and scope as associated data, so a ciphertext moved to
  another row does not open. `PRAGMA secure_delete` is on, and retired, discarded and deleted
  versions have their ciphertext overwritten.
- **Keys.** The database key comes from the weirdnet-keys keyring (Argon2id password, master
  key, recovery words, shards), an OS keychain, a weirdnet-sync secret store or the caller.
  The entry key is stored wrapped by a key derived from the database key; a rekey re-wraps it.
- **In memory.** Values live in `Plaintext` and keys in `Key32`, both wiped on drop. `use_secret`
  wipes the value when the closure returns. What the closure returns is the caller's business.
- **Access.** The environment check comes first and cannot be overridden by policy. `Use` and
  `Reveal` need an unexpired grant and the app's `Authorize`. `Reveal` can be switched off per
  vault.
- **Audit.** Every value access, change, grant, revocation and refusal is recorded with who,
  what, where and when, never a value. Records are hash-chained (BLAKE3) and SQL triggers refuse
  updates and deletes. Someone holding the database key could rewrite the whole chain; publish
  `audit_head` elsewhere to detect that.
- **Recipient sealing.** `reveal_sealed` uses an ephemeral X25519 key and HKDF bound to both
  public keys, the secret id and the version.
