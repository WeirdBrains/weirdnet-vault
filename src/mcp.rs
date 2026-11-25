//! Metadata-only MCP tools over weirdnet-mcp (feature `mcp`).
//!
//! [`VaultTools`] lists and shows secrets, manages grants, moves rotations along, deletes and
//! reads the audit log. No tool takes or returns a value: creating and rotating values stays in
//! the app. Every tool runs as the [`Caller`] the [`CallerResolver`] finds for the bearer
//! token, through the same checks as the library.
use crate::audit::{AuditQuery, Outcome};
use crate::grant::{GrantAction, GrantId, GrantTarget};
use crate::policy::{Action, Caller};
use crate::scope::Scope;
use crate::secret::SecretId;
use crate::vault::Vault;
use serde_json::{Value, json};
use std::sync::Arc;
use weirdnet_mcp::{Param, ParamType, ToolError, ToolSpec, Tools, args};

/// Maps a bearer token to a caller (`None`: not signed in).
pub trait CallerResolver: Send + Sync {
    /// The caller for `token`.
    fn caller(&self, token: Option<&str>) -> Option<Caller>;
}

impl<F> CallerResolver for F
where
    F: Fn(Option<&str>) -> Option<Caller> + Send + Sync,
{
    fn caller(&self, token: Option<&str>) -> Option<Caller> {
        self(token)
    }
}

const ID: Param = Param::required("id", ParamType::String, "Secret id.");
const ACTIONS: &[&str] = &["use", "reveal"];
const ACTION_NAMES: &[&str] = &["list", "read_meta", "create", "rotate", "delete", "use", "reveal", "grant", "audit", "backup"];
const OUTCOMES: &[&str] = &["allowed", "denied", "failed"];

const fn tool(name: &'static str, description: &'static str, params: &'static [Param], read_only: bool, destructive: bool) -> ToolSpec {
    ToolSpec { name, description, params, auth: true, read_only, destructive, open_world: false }
}

static SPECS: &[ToolSpec] = &[
    tool(
        "vault_list",
        "List secret metadata (never values) in a scope and below it.",
        &[Param::optional("scope", ParamType::String, "Scope such as tenant/provider; empty for everything.")],
        true,
        false,
    ),
    tool("vault_show", "One secret's metadata and versions (never values).", &[ID], true, false),
    tool(
        "vault_grants",
        "Grants on a secret (id) or a scope.",
        &[Param::optional("id", ParamType::String, "Secret id."), Param::optional("scope", ParamType::String, "Scope.")],
        true,
        false,
    ),
    tool(
        "vault_grant",
        "Approve an identity to use or retrieve a secret (id) or every secret in a scope.",
        &[
            Param::optional("id", ParamType::String, "Secret id."),
            Param::optional("scope", ParamType::String, "Scope."),
            Param::required("identity", ParamType::String, "Identity to approve."),
            Param::required("actions", ParamType::Array(&ParamType::Enum(ACTIONS)), "What it may do."),
            Param::optional("expires_at", ParamType::Integer, "Expiry, ms since the Unix epoch."),
        ],
        false,
        false,
    ),
    tool("vault_revoke", "Revoke a grant.", &[Param::required("grant_id", ParamType::String, "Grant id.")], false, true),
    tool("vault_promote", "Make a secret's pending version active (the old one is kept as previous).", &[ID], false, false),
    tool("vault_discard", "Drop a secret's pending version.", &[ID], false, true),
    tool("vault_revert", "Swap a secret's active and previous versions.", &[ID], false, false),
    tool("vault_retire", "Wipe a secret's previous version.", &[ID], false, true),
    tool("vault_delete", "Delete a secret and all its versions.", &[ID], false, true),
    tool(
        "vault_audit",
        "Query the audit log by time range, scope, actor, action and outcome.",
        &[
            Param::optional("from", ParamType::Integer, "From (inclusive), ms since the Unix epoch."),
            Param::optional("to", ParamType::Integer, "Until (exclusive), ms since the Unix epoch."),
            Param::optional("scope", ParamType::String, "Scope and below."),
            Param::optional("actor", ParamType::String, "Identity."),
            Param::optional("action", ParamType::Enum(ACTION_NAMES), "Action."),
            Param::optional("outcome", ParamType::Enum(OUTCOMES), "Outcome."),
            Param::optional("after_seq", ParamType::Integer, "Only records after this sequence number."),
            Param::optional("limit", ParamType::Integer, "At most this many (default 500)."),
        ],
        true,
        false,
    ),
    tool("vault_verify_audit", "Check the audit log's hash chain and return its head.", &[], true, false),
];

/// The vault's MCP tools.
pub struct VaultTools<R> {
    vault: Arc<Vault>,
    resolver: R,
}

impl<R> std::fmt::Debug for VaultTools<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultTools").field("vault", &self.vault).finish_non_exhaustive()
    }
}

impl<R: CallerResolver> VaultTools<R> {
    /// Tools over `vault`, with callers from `resolver`.
    pub fn new(vault: Arc<Vault>, resolver: R) -> Self {
        VaultTools { vault, resolver }
    }

    /// The tool table.
    pub fn specs() -> &'static [ToolSpec] {
        SPECS
    }
}

fn te(e: impl std::fmt::Display) -> ToolError {
    ToolError(e.to_string())
}

fn id(a: &Value) -> Result<SecretId, ToolError> {
    SecretId::parse(args::string(a, "id").map_err(ToolError)?).map_err(te)
}

fn scope(a: &Value) -> Result<Scope, ToolError> {
    Scope::parse(args::opt_string(a, "scope").unwrap_or("")).map_err(te)
}

fn target(a: &Value) -> Result<GrantTarget, ToolError> {
    match (args::opt_string(a, "id"), args::opt_string(a, "scope")) {
        (Some(_), None) => Ok(GrantTarget::Secret(id(a)?)),
        (None, Some(_)) => Ok(GrantTarget::Scope(scope(a)?)),
        _ => Err(ToolError("give exactly one of id or scope".into())),
    }
}

fn opt_int(a: &Value, k: &str) -> Option<i64> {
    a.get(k).and_then(Value::as_i64)
}

fn json<T: serde::Serialize>(v: &T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(te)
}

impl<R: CallerResolver> Tools for VaultTools<R> {
    fn specs(&self) -> &[ToolSpec] {
        SPECS
    }

    fn call(&self, tool: &ToolSpec, a: &Value, token: Option<&str>) -> Result<Value, ToolError> {
        let caller = self.resolver.caller(token).ok_or_else(|| ToolError("sign in first".into()))?;
        let v = &self.vault;
        match tool.name {
            "vault_list" => json(&v.list(&caller, &scope(a)?).map_err(te)?),
            "vault_show" => {
                let i = id(a)?;
                let meta = v.meta(&caller, &i).map_err(te)?;
                let versions = v.versions(&caller, &i).map_err(te)?;
                Ok(json!({ "secret": json(&meta)?, "versions": json(&versions)? }))
            }
            "vault_grants" => json(&v.grants(&caller, &target(a)?).map_err(te)?),
            "vault_grant" => {
                let actions = args::strings(a, "actions")
                    .map_err(ToolError)?
                    .iter()
                    .map(|s| GrantAction::parse(s))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(te)?;
                let identity = args::string(a, "identity").map_err(ToolError)?;
                json(&v.grant(&caller, target(a)?, identity, &actions, opt_int(a, "expires_at")).map_err(te)?)
            }
            "vault_revoke" => {
                let g = GrantId::parse(args::string(a, "grant_id").map_err(ToolError)?).map_err(te)?;
                v.revoke(&caller, &g).map_err(te)?;
                Ok(json!({ "revoked": g }))
            }
            "vault_promote" => json(&v.promote(&caller, &id(a)?).map_err(te)?),
            "vault_discard" => json(&v.discard_pending(&caller, &id(a)?).map_err(te)?),
            "vault_revert" => json(&v.revert(&caller, &id(a)?).map_err(te)?),
            "vault_retire" => json(&v.retire_previous(&caller, &id(a)?).map_err(te)?),
            "vault_delete" => {
                let i = id(a)?;
                v.delete(&caller, &i).map_err(te)?;
                Ok(json!({ "deleted": i }))
            }
            "vault_audit" => {
                let mut q = AuditQuery::new();
                q.from = opt_int(a, "from");
                q.to = opt_int(a, "to");
                if args::opt_string(a, "scope").is_some() {
                    q.scope = Some(scope(a)?);
                }
                q.actor = args::opt_string(a, "actor").map(str::to_string);
                q.action = args::opt_string(a, "action").map(Action::parse).transpose().map_err(te)?;
                q.outcome = args::opt_string(a, "outcome").map(Outcome::parse).transpose().map_err(te)?;
                q.after_seq = opt_int(a, "after_seq").map(|s| s.max(0) as u64);
                if let Some(l) = opt_int(a, "limit") {
                    q.limit = l.max(0) as usize;
                }
                json(&v.audit(&caller, &q).map_err(te)?)
            }
            "vault_verify_audit" => json(&v.verify_audit().map_err(te)?),
            other => Err(ToolError(format!("unknown tool {other}"))),
        }
    }
}
