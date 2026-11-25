# weirdnet-vault design

A generic, encrypted secret and credential store for [Weird Brains](https://weirdbrains.com)
apps. A server process (for example a Tokio service that many apps connect to over Weirdnet)
keeps API credentials, tokens and passwords for many tenants and many identities. Plaintext
never leaves the process unless an approved identity explicitly retrieves it.

The crate is app-agnostic: nothing in the API names a particular kind of app. The examples use
a server that holds exchange credentials per account, because that is the first user.

## Building blocks

The vault builds on existing Weirdnet crates instead of reimplementing them:

| Need | Crate | What is used |
| --- | --- | --- |
| Keys, sealing, key agreement | [weirdnet-keys](https://crates.io/crates/weirdnet-keys) 0.1.2 | `Key32`, XChaCha20-Poly1305 `seal`/`open`, `kdf::hkdf`, `exchange::ExchangeSecret` |
| Password- or master-key-wrapped data key | weirdnet-keys `keyring` | `KeyFiles`, `EncryptedDatabase`, `init`, `unlock_with_password`, `unlock_with_master`, `rotate`, `rekey`, `recover` |
| Encrypted database | [weirdnet-storage](https://crates.io/crates/weirdnet-storage) 0.1.1 | SQLCipher `open`, `migrate`, `rekey`, `snapshot_to`, `encrypt_plaintext_in_place`, private files |
| OS keystore secrets by name | [weirdnet-sync](https://crates.io/crates/weirdnet-sync) 0.8 | `SecretStore` (implemented for the vault's key stores, feature `sync`) |
| Role policy | [weirdnet-access](https://crates.io/crates/weirdnet-access) 0.1.2 | `enforce::decide`, `Catalog`, `RoleSet` (adapter, feature `access`) |
| MCP tools | [weirdnet-mcp](https://crates.io/crates/weirdnet-mcp) 0.6 | `Tools`, `ToolSpec` (metadata-only tools, feature `mcp`) |

## Keys

```text
password ──Argon2id──▶ service key ─┐
master key (words, shards) ─HKDF──▶ KEK ─┼─ wrap ─▶ DEK ──▶ SQLCipher (whole database)
                                         │            └─HKDF─▶ wrap key ─ wrap ─▶ entry key
OS keychain / any KeyStore ──────────────┘ (or the DEK straight from a KeyStore)
entry key ── XChaCha20-Poly1305, AAD = secret id, version, environment, scope ──▶ each value
```

- **DEK.** A random 256-bit data key keys the SQLCipher database. It comes from one of:
  the weirdnet-keys keyring (`VaultHome`: password, master key, words, shards, service-key
  rotation, rekey, recovery), a `KeyStore` (OS keychain, a weirdnet-sync `SecretStore`, or
  memory), or the caller (`Vault::open_with_key`).
- **Entry key.** A second random key, stored in the database wrapped by a key derived from
  the DEK (`HKDF(DEK, "weirdnet-vault/v1/entry-wrap")`). Each wrap row carries an id derived
  from its wrapping key, so a rekey adds the new wrap before SQLCipher re-encrypts and drops
  the old one afterwards. The entry key never changes on rekey, so values are not resealed.
- **Per-entry sealing.** Every version of every value is sealed on its own with the entry
  key. The associated data binds it to its secret id, version, environment and scope, so a
  ciphertext copied onto another row does not open. Values stay sealed in SQLite's page
  cache and are opened only for the duration of a use or a retrieval.
- **Memory.** Plaintext lives only in `Plaintext` (zeroized on drop, no `Clone`, no
  `Serialize`, redacted `Debug`). Keys are `Key32` (zeroized). Errors never carry values.

## Model

- **Scope.** A hierarchical key: `Scope::new(["tenant-7", "provider-a"])`, written
  `tenant-7/provider-a`. Segments are 1 to 128 characters from `A-Z a-z 0-9 - _ . : @ +`.
  A scope contains itself and everything below it; the empty scope is the root. One server
  hosts many tenants; each tenant has many identities.
- **Secret.** Metadata plus versions: id (UUID), scope, name, kind (free text such as
  `api-key`), environment, labels (string map), creation and update times, who created it,
  and the active, pending and previous version numbers. A name is unique per scope and
  environment, so a test key and a live key can share a name.
- **Value.** Opaque bytes up to a configurable limit (64 KiB by default). Apps that need
  several fields (key, secret, passphrase) store one small JSON document.
- **Environment.** `Environment::Test` (dry-run, paper, sandbox) or `Environment::Live`. It is
  set when a secret is created and never changes.
- **Caller.** An identity id (whatever the app authenticated: a Weirdnet user id, a device
  peer id, an API-key id) bound to an environment. `Caller::test("alice")` is a dry-run
  context.
- **`SecretMeta`.** The metadata view. It is the only secret-related type that implements
  `Serialize`, and the only one the MCP tools return. It holds no value.

## Actions

| Action | Covers |
| --- | --- |
| `List` | listing metadata under a scope |
| `ReadMeta` | one secret's metadata, its versions and its grants |
| `Create` | a new secret with its first value |
| `Rotate` | stage, promote, discard, revert, retire |
| `Delete` | deleting a secret and all its versions |
| `Use` | server-side use through a closure, without returning plaintext |
| `Reveal` | retrieving the plaintext (also sealed to a recipient key) |
| `Grant` | adding and revoking grants |
| `Audit` | querying the audit log |
| `Backup` | snapshots |

Every call runs the same checks, in order, and every outcome is audited:

1. **Environment.** A caller bound to `Test` may only touch `Test` secrets. Anything but
   `List`, `ReadMeta` and `Audit` on a `Live` secret is refused with
   `VaultError::EnvironmentMismatch`; listing shows metadata only. Scope-wide grants and
   backups can reach live secrets, so they need a `Live` caller. A `Live` caller may use test
   secrets.
2. **Grant** (`Use` and `Reveal` only). The caller's identity must hold an unexpired grant for
   that action on the secret, or on a scope that contains it.
3. **Authorize.** The app's `Authorize` hook gets the caller, the action, the scope, the
   secret's metadata (when there is one) and, for grants, the grantee. It returns `Allow` or
   `Deny(reason)`.
4. **Policy.** `VaultOptions::allow_reveal` can switch `Reveal` off for a whole vault. It is
   on by default.

### Approved identities

Retrieving a secret is a first-class, grantable action. Each secret, or each scope, keeps a
set of grants: an identity, the actions it is approved for (`Use`, `Reveal`, or both), an
optional expiry, and who granted it when. Any identity in that set may retrieve the plaintext
once `Authorize` agrees. Several identities can be approved for the same secret. Admins add
and revoke grants (`Action::Grant`); every grant, revocation and retrieval is audited.

`Use` is a separate grant for identities that should only act through the server: the server
runs `vault.use_secret(&caller, &id, |s| sign(s.as_bytes(), request))` and only the closure's
result comes back. The closure runs while the vault's lock is held, so it must be short and
must not call the vault.

### Roles

Roles belong to the app. `RolePolicy` is a small built-in `Authorize` that maps identities to
roles per scope and roles to actions, changeable at run time. Nothing is hard-coded; a typical
mapping is:

| Role | Actions |
| --- | --- |
| viewer | `List`, `ReadMeta` |
| trader | viewer + `Use` |
| auditor | viewer + `Audit` |
| admin | everything (`Create`, `Rotate`, `Delete`, `Grant`, `Reveal`, `Audit`, `Backup`, ...) |

Roles say what an identity may do in general; grants say which secrets it may use or
retrieve. A trader needs both the role and a `Use` grant on the account's scope.

With the `access` feature, `AccessAuthorizer` asks weirdnet-access `enforce::decide` instead,
with vault permissions (`vault.list`, `vault.read-meta`, ..., `vault.admin`) added to the
catalog and the app supplying the `Facts` for each request. Any closure
`Fn(&AccessRequest) -> Decision` is also an `Authorize`, so an app can bridge another policy
(for example the agent roster) without this crate depending on it.

## Rotation without downtime

1. `stage_rotation` stores the new value as the **pending** version. The active version keeps
   serving every `use_secret` and `reveal`.
2. The server can try the pending value with `use_version(…, Which::Pending, …)`, for example to
   check that new credentials work.
3. `promote` makes the pending version active. The old active version becomes **previous**
   and stays stored, so `revert` can swap back.
4. `discard_pending` drops a pending version (roll back before promotion).
5. `retire_previous` wipes the previous value once the new one is confirmed. Promoting again
   also retires the older previous value.

Retired and discarded versions keep their metadata row (number, state, time, who) but lose
their ciphertext. Every step is one database transaction with its audit record, so readers see
either the old or the new state.

## Audit log

Each record holds: sequence number, time (ms since the Unix epoch), actor identity, actor
environment, action, scope, secret id, version, outcome (`allowed`, `denied` or `failed`), a
short detail (a reason, a grantee, a count; never a value), the previous record's hash and its
own hash.

- **Hash chain.** `hash = BLAKE3("weirdnet-vault/v1/audit" ‖ prev_hash ‖ each field,
  length-prefixed)`, starting from 64 zeros. `AuditRecord::expected_hash` and
  `verify_chain` let anyone with a contiguous range check it; `Vault::verify_audit` checks
  the whole log and returns the head.
- **Append-only.** SQL triggers refuse `UPDATE` and `DELETE` on the audit table. Rewriting the
  log would need the database key and a recomputed chain; publishing `Vault::audit_head`
  somewhere else (another node, a signed note) makes that detectable.
- **Query.** `AuditQuery` filters by time range, scope prefix, actor, action and outcome, with
  `after_seq` paging and a limit. Queries need `Action::Audit` on the queried scope.
- `VaultOptions::audit_metadata_reads` (on by default) controls whether `List` and `ReadMeta`
  are recorded; value access, changes, grants and refusals are always recorded.

## Recipient sealing

`reveal_sealed(&caller, &id, &recipient_public)` seals the plaintext to the recipient's X25519
public key: an ephemeral weirdnet-keys `ExchangeSecret`, HKDF over the shared secret with both
public keys, the secret id and the version, then XChaCha20-Poly1305. The recipient opens it with
`RecipientSealed::open(&their_secret)`. This keeps the value sealed end to end even across a
hop that is not itself encrypted. On a Weirdnet sealed stream it is defence in depth.

## Async

`AsyncVault` (feature `tokio`, on by default) wraps an `Arc<Vault>` and runs each call on
Tokio's blocking pool, so database and crypto work never stalls the runtime. `use_secret`
takes a `Send + 'static` closure. The vault serializes database access through one connection
behind a mutex; calls are short.

## Key stores

`KeyStore` is the vault's view of a place that keeps the DEK by name: `load`, `store`,
`remove`. `Vault::open_with_keystore` loads the DEK, or creates and stores a random one on
first use.

- `MemoryKeyStore` for tests.
- `KeychainStore` (feature `keychain`): macOS Keychain, Windows Credential Manager, or the
  Secret Service on Linux and the BSDs, through `keyring-core` and its per-platform stores.
  Any other `keyring-core` store works too (`KeychainStore::with_store`).
- `SyncSecrets` (feature `sync`) adapts any weirdnet-sync `SecretStore` (such as
  `FileSecrets`) into a `KeyStore`, and `KeychainStore` and `MemoryKeyStore` implement
  `SecretStore`, so a weirdnet-sync `Identity` can keep its seed in the OS keychain.

## Backup and export

`snapshot_to(&caller, dest, key)` copies the live database with SQLite's online backup
(`weirdnet-storage::snapshot_to`). With no key the copy keeps the current DEK; with a new key
the copy is keyed with it and gets a matching entry-key wrap, so it opens with
`Vault::open_with_key(dest, key)` on another machine. It needs `Action::Backup` and a `Live`
caller, and is audited before the copy so the copy holds its own record.

## MCP

The `mcp` feature adds `VaultTools`, a weirdnet-mcp `Tools` implementation for metadata
management: list, show, grants, grant, revoke, promote, discard, revert, retire, delete and
audit. It never takes or returns a value, so creating and rotating values stays in the app.
A `CallerResolver` maps the bearer token to a `Caller`; every tool goes through the same
checks as the library.

## Storage and schema

The vault owns its own database file and schema (`key_wraps`, `secrets`, `versions`, `grants`,
`audit`), migrated with `weirdnet-storage::migrate`. Apps don't share it. Foreign keys cascade
deletes from secrets to versions and grants; the audit log is never deleted.

## Decisions

- Two layers of encryption (SQLCipher for the whole file, per-entry sealing for values): the
  file key protects metadata and the audit log at rest; per-entry sealing keeps values out of
  the page cache and binds each ciphertext to its row.
- Grants and roles are separate: roles are app policy through a trait; grants are the vault's
  own per-identity approval list, required for `Use` and `Reveal`.
- The environment is checked before `Authorize`, so no policy mistake can let a dry-run
  context reach a live secret.
- One SQLite connection behind a mutex: simple, consistent, and enough for a credential store
  whose operations take microseconds.
- weirdnet-sync is optional: it brings libp2p, which a vault doesn't otherwise need.
- Keychain support uses `keyring-core` and the per-platform store crates directly (not the
  `keyring` umbrella), to avoid a system D-Bus library on Linux.
