//! A server that keeps credentials for several tenants, lets a bot sign with them without
//! seeing them, approves two operators to retrieve one, rotates it without downtime and checks
//! the audit log.
//!
//! cargo run --example quickstart
use std::sync::Arc;
use weirdnet_vault::*;

fn main() -> Result<()> {
    let policy = Arc::new(RolePolicy::with_example_roles());
    policy.define_role("operator", &[Action::List, Action::ReadMeta, Action::Reveal]);
    let tenant = Scope::new(["tenant-7"])?;
    let account = tenant.child("provider-a")?;
    policy.assign("admin", &Scope::root(), "admin")?;
    policy.assign("bot", &tenant, "trader")?;
    policy.assign("ops-1", &tenant, "operator")?;
    policy.assign("ops-2", &tenant, "operator")?;

    // A real server opens a file: Vault::open_with_keystore, Vault::unlock (password) or
    // Vault::open_with_key.
    let vault = Vault::open_in_memory(policy.clone(), VaultOptions::new())?;
    let admin = Caller::live("admin");

    let live =
        vault.create(&admin, NewSecret::new(account.clone(), "api", Environment::Live).kind("api-key"), b"{\"key\":\"k1\",\"secret\":\"s1\"}")?;
    let paper =
        vault.create(&admin, NewSecret::new(account.clone(), "api", Environment::Test).kind("api-key"), b"{\"key\":\"p1\",\"secret\":\"p1\"}")?;

    // The bot may use both; it never gets the plaintext back.
    vault.grant(&admin, GrantTarget::Scope(account.clone()), "bot", &[GrantAction::Use], None)?;
    let sign = |s: &Plaintext| format!("signed with {} bytes of credentials", s.len());
    println!("{}", vault.use_secret(&Caller::live("bot"), &live.id, sign)?);
    // In dry-run mode it only reaches the paper key.
    let dry = Caller::test("bot");
    println!("{}", vault.use_secret(&dry, &paper.id, sign)?);
    println!("dry-run on live: {}", vault.use_secret(&dry, &live.id, sign).unwrap_err());

    // Two operators may retrieve the live key; anyone else is refused.
    for who in ["ops-1", "ops-2"] {
        vault.grant(&admin, GrantTarget::Secret(live.id.clone()), who, &[GrantAction::Reveal], None)?;
    }
    let me = ExchangeSecret::generate();
    let sealed = vault.reveal_sealed(&Caller::live("ops-1"), &live.id, &me.public())?;
    println!("ops-1 opened {} bytes sealed to its key", sealed.open(&me)?.len());
    println!("bot reveal: {}", vault.reveal(&Caller::live("bot"), &live.id).unwrap_err());

    // Rotate without downtime: stage, try, promote; the old value stays until retired.
    vault.stage_rotation(&admin, &live.id, b"{\"key\":\"k2\",\"secret\":\"s2\"}")?;
    let works = vault.use_version(&Caller::live("bot"), &live.id, Which::Pending, |s| !s.is_empty())?;
    if works {
        vault.promote(&admin, &live.id)?;
        vault.retire_previous(&admin, &live.id)?;
    }

    // Metadata is safe to send to clients.
    for m in vault.list(&admin, &tenant)? {
        println!("{}", serde_json::to_string(&m).expect("metadata serializes"));
    }

    let head = vault.verify_audit()?;
    println!("audit log verified: {} records, head {}", head.seq, &head.hash[..16]);
    for r in vault.audit(&admin, &AuditQuery::new().action(Action::Reveal))? {
        println!("#{} {} {} {} {}", r.seq, r.actor, r.action, r.outcome.as_str(), r.detail);
    }
    Ok(())
}
