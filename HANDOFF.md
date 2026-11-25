# Handoff

Running notes for [weirdnet-vault](https://github.com/WeirdBrains/weirdnet-vault), newest first.

## 2026-11-25: released v0.1.0

- What changed: the first release, cut with `scripts/weirdnet_release.py cut --minor` from
  `f976413`: `release: v0.1.0` ([`b50c555`](https://github.com/WeirdBrains/weirdnet-vault/commit/b50c5551c7a6aa4d32c3ca87755d2b9aff9765aa)),
  tag `v0.1.0`, published to [crates.io](https://crates.io/crates/weirdnet-vault/0.1.0);
  [docs.rs](https://docs.rs/weirdnet-vault/0.1.0) built it.
- Checks: CI green on `f976413` and `b50c555` (Linux checks, macOS and Windows keychain
  jobs); the release script's fmt, clippy, test and doc checks; the
  [weirdnet-vault page](https://net.weirdbrains.com/crates/vault) example built and ran against
  0.1.0 from crates.io.
- Not tested: the native keychains against a real OS store (CI builds and tests the keychain
  feature on macOS and Windows with the mock store only).
- Left: nothing for this release.
- Next: nothing planned.

## 2026-11-25: initial crate, unreleased

- What changed: the [design](docs/design/vault.md) and the first implementation. Sealed
  per-entry values in a SQLCipher database, hierarchical scopes, test and live environments,
  the `Authorize` hook and `RolePolicy`, per-identity `Use`/`Reveal` grants with expiry,
  `use_secret` closures, retrieval and recipient sealing, rotation (stage, try, promote,
  discard, revert, retire), the hash-chained audit log with queries, keyring homes, key stores,
  snapshots, `AsyncVault`, and the `keychain`, `sync`, `access` and `mcp` features. The version
  stays 0.0.0 until the first cut (0.1.0); nothing is published.
- Commits: `92452f2` (design), `88edef8` (crate), `6aaaf31` (docs), `e31e015` (CI and release
  config), and this entry.
- Checks: `cargo fmt --check`; `cargo clippy --all-targets -D warnings` with default, no-default
  and all features; `cargo test` with default (25 tests plus 9 doc tests), no-default and all
  features (29 tests plus 9 doc tests); `cargo doc --no-deps --all-features` with
  `-D warnings`; `cargo package --locked`; `weirdnet_release.py validate`; the quickstart
  example runs.
- Not tested: the native keychains (macOS Keychain, Windows Credential Manager, Secret Service)
  against a real OS store. The keychain code runs only against `keyring-core`'s mock store, and
  the macOS and Windows CI jobs build it. Not tested on Windows, macOS or the BSDs, under heavy
  concurrent load, or with large vaults.
- Left: the first CI run on GitHub; the 0.1.0 release.
- Next: release 0.1.0 with `python3 scripts/weirdnet_release.py --dry-run`, then without
  `--dry-run`, once approved.
