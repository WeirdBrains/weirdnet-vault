# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-25

### Added

- Encrypted vault on SQLCipher with per-entry sealed values, metadata, labels and versions.
- Hierarchical scopes, test and live environments enforced on every call.
- `Authorize` hook, `RolePolicy`, and per-identity grants for using and retrieving values.
- Use-without-revealing closures, retrieval, and values sealed to a recipient key.
- Rotation without downtime: stage, try, promote, discard, revert and retire.
- Hash-chained, append-only audit log with time-range and filter queries.
- Password, master-key and recovery-word keys through the weirdnet-keys keyring; key stores.
- Snapshots that restore with the same or a new key.
- `AsyncVault` for Tokio.
- Optional OS keychain store, weirdnet-sync `SecretStore` interop, weirdnet-access authorizer
  and metadata-only weirdnet-mcp tools.
