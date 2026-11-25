# weirdnet-vault

An encrypted secret and credential store for [Weird Brains](https://weirdbrains.com) servers
and apps on Weirdnet. A server keeps API credentials, tokens and passwords for many tenants and
identities; plaintext stays in the process unless an approved identity retrieves it.

- **Sealed values.** A SQLCipher database ([weirdnet-storage](https://crates.io/crates/weirdnet-storage)),
  with each version of each value sealed again on its own (XChaCha20-Poly1305 from
  [weirdnet-keys](https://crates.io/crates/weirdnet-keys)), bound to its secret, version,
  environment and scope. Metadata (name, kind, labels, scope, versions) sits beside it.
- **Scopes.** Hierarchical keys such as `tenant-7/provider-a`.
- **Checks on every call.** The environment first, then per-identity grants for `Use` and
  `Reveal`, then your `Authorize` hook, all recorded in the audit log.
- **Use without revealing.** `use_secret` hands the value to a closure inside the server and
  returns only the closure's result.
- **Approved identities.** Grant `Use` or `Reveal` per identity on a secret or a scope, with
  an optional expiry. Several identities can retrieve the same secret; revoking takes effect at
  once. Retrieved values can be sealed to the recipient's X25519 key.
- **Environments.** A caller bound to `Environment::Test` (dry-run) can never use, retrieve,
  change or delete a live secret.
- **Rotation without downtime.** Stage a pending version, try it, promote it (the old one is
  kept as previous), roll back, retire.
- **Audit log.** Who, what, where, when and how it ended, never a value. Hash-chained,
  append-only, with time-range, scope, actor, action and outcome queries.
- **Keys.** A password with recovery words and shards (the weirdnet-keys keyring), an OS
  keychain, a [weirdnet-sync](https://crates.io/crates/weirdnet-sync) secret store, or your own.
- **Tokio.** `AsyncVault` runs every call on the blocking pool.
- **Backups.** Online snapshots, keyed with the same or a new key.

The [design document](docs/design/vault.md) explains the key layout, the checks and the
decisions behind them.

```toml
[dependencies]
weirdnet-vault = "0.1"
```

## Example

```rust
use std::sync::Arc;
use weirdnet_vault::*;

let policy = Arc::new(RolePolicy::with_example_roles());
let tenant = Scope::new(["tenant-7"])?;
let account = tenant.child("provider-a")?;
policy.assign("admin", &Scope::root(), "admin")?;
policy.assign("bot", &tenant, "trader")?;

let vault = Vault::open_in_memory(policy.clone(), VaultOptions::new())?;
let admin = Caller::live("admin");
let key = vault.create(&admin, NewSecret::new(account.clone(), "api", Environment::Live), b"key:secret")?;
vault.grant(&admin, GrantTarget::Scope(account), "bot", &[GrantAction::Use], None)?;

let bot = Caller::live("bot");
let len = vault.use_secret(&bot, &key.id, |s| s.len())?;
assert_eq!(len, 10);
assert!(vault.reveal(&bot, &key.id).is_err());
assert!(vault.use_secret(&Caller::test("bot"), &key.id, |_| ()).is_err());
```

[examples/quickstart.rs](examples/quickstart.rs) goes further: two approved operators, dry-run
and live keys, recipient sealing, rotation and the audit log. Run it with
`cargo run --example quickstart`.

## Opening a vault

| How | Call |
| --- | --- |
| Password, with recovery words and shards | `Vault::init(&VaultHome::new(dir), &password, …)`, then `Vault::unlock` or `Vault::unlock_with_master` |
| A key kept in a key store | `Vault::open_with_keystore(path, &store, "vault-key", …)` |
| A key you hold | `Vault::open_with_key(path, &key, …)` |
| Tests | `Vault::open_in_memory(…)` |

With the vault closed, `weirdnet_keys::keyring::rotate`, `rekey` and `recover` work on a
`VaultHome` directly. A rekey re-wraps the entry key, so values are not resealed.

## Roles and grants

Roles are your policy: implement `Authorize` (any `Fn(&AccessRequest) -> Decision` works), or
use `RolePolicy`. `RolePolicy::with_example_roles()` defines these roles, and you assign them
per scope:

| Role | Actions |
| --- | --- |
| viewer | `List`, `ReadMeta` |
| trader | viewer + `Use` |
| auditor | viewer + `Audit` |
| admin | every action |

Grants are the vault's own approval list: `Use` and `Reveal` need both a role that allows the
action and an unexpired grant for that identity on the secret or a scope above it.

`SecretMeta` is the only secret type that implements `Serialize`, so it is what you send to
clients.

## Features

| Feature | Default | What it adds |
| --- | --- | --- |
| `tokio` | yes | `AsyncVault` |
| `vendored-openssl` | yes | builds SQLCipher's OpenSSL from source |
| `keychain` | no | `KeychainStore`: macOS Keychain, Windows Credential Manager, Secret Service |
| `sync` | no | `SyncSecrets` over any weirdnet-sync `SecretStore`; the vault's key stores implement `SecretStore` |
| `access` | no | `access::AccessAuthorizer` over [weirdnet-access](https://crates.io/crates/weirdnet-access) `enforce::decide` |
| `mcp` | no | `mcp::VaultTools`: metadata-only [weirdnet-mcp](https://crates.io/crates/weirdnet-mcp) tools |

## Licence

BSD-3-Clause, copyright Weird Brains LLC. See [LICENSE](LICENSE). Security notes are in
[SECURITY.md](SECURITY.md).
