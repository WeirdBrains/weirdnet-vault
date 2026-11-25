# weirdnet-vault agents

The collective `AGENTS.md` in `WeirdBrains/weirdnet-agents` is mandatory and wins on conflict.

- Build outside the source checkout, with `CARGO_TARGET_DIR` on a scratch disk; clean targets afterwards.
- Never log, print or commit secret values, keys or passwords; errors and audit details never carry them.
- `SecretMeta` is the only secret type that may implement `Serialize`. Keep `Plaintext` without `Clone`,
  `Serialize` or a revealing `Debug`.
- The environment check runs before grants and `Authorize`; keep it that way.
- The schema is append-only: add migrations, never edit a shipped one. Never weaken the audit triggers.
