use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use weirdnet_vault::*;

fn allow_all() -> Arc<dyn Authorize> {
    Arc::new(|_: &AccessRequest<'_>| Decision::Allow)
}

struct Fixture {
    vault: Vault,
    policy: Arc<RolePolicy>,
    time: Arc<AtomicI64>,
    tenant: Scope,
    account: Scope,
}

fn fixture() -> Fixture {
    fixture_with(VaultOptions::new())
}

fn fixture_with(opts: VaultOptions) -> Fixture {
    let policy = Arc::new(RolePolicy::with_example_roles());
    let tenant = Scope::new(["tenant-7"]).unwrap();
    let account = tenant.child("provider-a").unwrap();
    policy.assign("admin", &Scope::root(), "admin").unwrap();
    policy.assign("bot", &tenant, "trader").unwrap();
    policy.assign("alice", &tenant, "viewer").unwrap();
    policy.assign("auditor", &Scope::root(), "auditor").unwrap();
    policy.define_role("retriever", &[Action::List, Action::ReadMeta, Action::Reveal]);
    for who in ["ops-1", "ops-2", "ops-3"] {
        policy.assign(who, &tenant, "retriever").unwrap();
    }
    let time = Arc::new(AtomicI64::new(1_000_000));
    let t = time.clone();
    let opts = opts.clock(Clock::from_fn(move || t.load(Ordering::SeqCst)));
    let vault = Vault::open_in_memory(policy.clone(), opts).unwrap();
    Fixture { vault, policy, time, tenant, account }
}

fn admin() -> Caller {
    Caller::live("admin")
}

impl Fixture {
    fn live_secret(&self, name: &str, value: &[u8]) -> SecretMeta {
        self.vault.create(&admin(), NewSecret::new(self.account.clone(), name, Environment::Live).kind("api-key"), value).unwrap()
    }
    fn advance(&self, ms: i64) {
        self.time.fetch_add(ms, Ordering::SeqCst);
    }
    fn now(&self) -> i64 {
        self.time.load(Ordering::SeqCst)
    }
}

#[test]
fn approved_identities_can_retrieve_and_others_cannot() {
    let f = fixture();
    let s = f.live_secret("api", b"key:secret");
    let target = GrantTarget::Secret(s.id.clone());
    let g1 = f.vault.grant(&admin(), target.clone(), "ops-1", &[GrantAction::Reveal], None).unwrap();
    f.vault.grant(&admin(), target.clone(), "ops-2", &[GrantAction::Reveal], None).unwrap();

    // Two approved identities can both retrieve.
    for who in ["ops-1", "ops-2"] {
        assert_eq!(f.vault.reveal(&Caller::live(who), &s.id).unwrap().as_bytes(), b"key:secret");
    }
    // An unapproved one is refused, though its role would allow it.
    assert!(matches!(f.vault.reveal(&Caller::live("ops-3"), &s.id), Err(VaultError::Denied(_))));
    // A revoked one is refused.
    f.vault.revoke(&admin(), &g1.id).unwrap();
    assert!(matches!(f.vault.reveal(&Caller::live("ops-1"), &s.id), Err(VaultError::Denied(_))));
    assert!(f.vault.reveal(&Caller::live("ops-2"), &s.id).is_ok());
    // A grant alone is not enough: the role must allow it too.
    f.vault.grant(&admin(), target.clone(), "alice", &[GrantAction::Reveal], None).unwrap();
    assert!(matches!(f.vault.reveal(&Caller::live("alice"), &s.id), Err(VaultError::Denied(_))));

    let grants = f.vault.grants(&admin(), &target).unwrap();
    assert_eq!(grants.iter().map(|g| g.identity.as_str()).collect::<Vec<_>>(), ["ops-2", "alice"]);

    let log = f.vault.audit(&Caller::live("auditor"), &AuditQuery::new().action(Action::Reveal)).unwrap();
    let outcomes: Vec<_> = log.iter().map(|r| (r.actor.as_str(), r.outcome)).collect();
    assert!(outcomes.contains(&("ops-1", Outcome::Allowed)));
    assert!(outcomes.contains(&("ops-3", Outcome::Denied)));
    assert!(outcomes.contains(&("ops-1", Outcome::Denied)));
    let grants_log = f.vault.audit(&Caller::live("auditor"), &AuditQuery::new().action(Action::Grant)).unwrap();
    assert!(grants_log.iter().any(|r| r.detail.starts_with("revoked")));
    assert_eq!(grants_log.iter().filter(|r| r.detail.starts_with("granted")).count(), 3);
}

#[test]
fn grants_expire_and_cover_scopes() {
    let f = fixture();
    let s = f.live_secret("api", b"v");
    let until = f.now() + 1_000;
    f.vault.grant(&admin(), GrantTarget::Scope(f.tenant.clone()), "ops-1", &[GrantAction::Reveal], Some(until)).unwrap();
    assert!(f.vault.reveal(&Caller::live("ops-1"), &s.id).is_ok());
    f.advance(1_000);
    assert!(matches!(f.vault.reveal(&Caller::live("ops-1"), &s.id), Err(VaultError::Denied(_))));
    assert!(f.vault.grant(&admin(), GrantTarget::Scope(f.tenant.clone()), "ops-1", &[GrantAction::Reveal], Some(f.now())).is_err());
    assert!(f.vault.grant(&admin(), GrantTarget::Scope(f.tenant.clone()), "ops-1", &[], None).is_err());
    // A grant on another scope doesn't cover this secret.
    f.vault.grant(&admin(), GrantTarget::Scope(Scope::new(["tenant-8"]).unwrap()), "ops-2", &[GrantAction::Reveal], None).unwrap();
    assert!(f.vault.reveal(&Caller::live("ops-2"), &s.id).is_err());
    assert_eq!(f.vault.grants_covering(&admin(), &s.id).unwrap().len(), 1);
}

#[test]
fn use_runs_inside_and_is_separate_from_reveal() {
    let f = fixture();
    let s = f.live_secret("api", b"key:secret");
    // No grant yet: even a trader is refused.
    assert!(matches!(f.vault.use_secret(&Caller::live("bot"), &s.id, |_| ()), Err(VaultError::Denied(_))));
    f.vault.grant(&admin(), GrantTarget::Scope(f.account.clone()), "bot", &[GrantAction::Use], None).unwrap();
    let sig = f.vault.use_secret(&Caller::live("bot"), &s.id, |p| p.as_bytes().iter().map(|b| *b as u32).sum::<u32>()).unwrap();
    assert_eq!(sig, b"key:secret".iter().map(|b| *b as u32).sum::<u32>());
    // A Use grant doesn't allow retrieval, and the trader role has no Reveal.
    assert!(f.vault.reveal(&Caller::live("bot"), &s.id).is_err());
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "bot", &[GrantAction::Reveal], None).unwrap();
    assert!(matches!(f.vault.reveal(&Caller::live("bot"), &s.id), Err(VaultError::Denied(m)) if m.contains("no role")));
    // Viewers see metadata only.
    let alice = Caller::live("alice");
    assert_eq!(f.vault.list(&alice, &f.tenant).unwrap().len(), 1);
    assert_eq!(f.vault.meta(&alice, &s.id).unwrap().name, "api");
    assert!(f.vault.use_secret(&alice, &s.id, |_| ()).is_err());
    assert!(f.vault.list(&Caller::live("stranger"), &Scope::root()).unwrap().is_empty());
}

#[test]
fn a_dry_run_caller_never_reaches_a_live_secret() {
    // Even with an allow-everything policy and grants for both actions.
    let vault = Vault::open_in_memory(allow_all(), VaultOptions::new()).unwrap();
    let scope = Scope::new(["tenant-7", "provider-a"]).unwrap();
    let live = vault.create(&admin(), NewSecret::new(scope.clone(), "api", Environment::Live), b"live-key").unwrap();
    let test = vault.create(&admin(), NewSecret::new(scope.clone(), "api", Environment::Test), b"paper-key").unwrap();
    for id in [&live.id, &test.id] {
        vault.grant(&admin(), GrantTarget::Secret(id.clone()), "bot", &[GrantAction::Use, GrantAction::Reveal], None).unwrap();
    }
    let dry = Caller::test("bot");
    let mismatch = |r: Result<()>| matches!(r, Err(VaultError::EnvironmentMismatch { caller: Environment::Test, secret: Environment::Live, .. }));
    assert!(mismatch(vault.use_secret(&dry, &live.id, |_| ())));
    assert!(mismatch(vault.reveal(&dry, &live.id).map(|_| ())));
    assert!(mismatch(vault.use_version(&dry, &live.id, Which::Active, |_| ())));
    assert!(mismatch(vault.reveal_sealed(&dry, &live.id, &ExchangeSecret::generate().public()).map(|_| ())));
    assert!(mismatch(vault.stage_rotation(&dry, &live.id, b"x").map(|_| ())));
    assert!(mismatch(vault.delete(&dry, &live.id)));
    assert!(mismatch(vault.create(&dry, NewSecret::new(scope.clone(), "other", Environment::Live), b"x").map(|_| ())));
    assert!(mismatch(vault.grant(&dry, GrantTarget::Secret(live.id.clone()), "x", &[GrantAction::Use], None).map(|_| ())));
    assert!(mismatch(vault.grant(&dry, GrantTarget::Scope(scope.clone()), "x", &[GrantAction::Use], None).map(|_| ())));
    assert!(mismatch(vault.snapshot_to(&dry, std::path::Path::new("/nonexistent/x.db"), None)));
    // The test secret works from the dry-run context, and the live caller reaches both.
    assert_eq!(vault.use_secret(&dry, &test.id, |s| s.as_bytes().to_vec()).unwrap(), b"paper-key");
    assert_eq!(vault.reveal(&Caller::live("bot"), &live.id).unwrap().as_bytes(), b"live-key");
    assert_eq!(vault.reveal(&Caller::live("bot"), &test.id).unwrap().as_bytes(), b"paper-key");
    // Metadata is still visible.
    assert_eq!(vault.list(&dry, &scope).unwrap().len(), 2);
    let denied = vault.audit(&admin(), &AuditQuery::new().actor("bot").outcome(Outcome::Denied)).unwrap();
    assert!(denied.len() >= 6 && denied.iter().all(|r| r.environment == Environment::Test));
}

#[test]
fn rotation_stages_promotes_and_rolls_back() {
    let f = fixture();
    let s = f.live_secret("api", b"v1");
    let bot = Caller::live("bot");
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "bot", &[GrantAction::Use], None).unwrap();
    let read = |w: Which| f.vault.use_version(&bot, &s.id, w, |p| p.as_bytes().to_vec());

    let m = f.vault.stage_rotation(&admin(), &s.id, b"v2").unwrap();
    assert_eq!((m.active_version, m.pending_version), (1, Some(2)));
    assert_eq!(read(Which::Active).unwrap(), b"v1", "readers keep the active version");
    assert_eq!(read(Which::Pending).unwrap(), b"v2", "the pending version can be tried");
    assert!(matches!(f.vault.stage_rotation(&admin(), &s.id, b"v3"), Err(VaultError::Conflict(_))));

    let m = f.vault.promote(&admin(), &s.id).unwrap();
    assert_eq!((m.active_version, m.pending_version, m.previous_version), (2, None, Some(1)));
    assert_eq!(read(Which::Active).unwrap(), b"v2");
    assert_eq!(read(Which::Previous).unwrap(), b"v1", "the previous version is kept");

    let m = f.vault.revert(&admin(), &s.id).unwrap();
    assert_eq!((m.active_version, m.previous_version), (1, Some(2)));
    assert_eq!(read(Which::Active).unwrap(), b"v1");
    let m = f.vault.revert(&admin(), &s.id).unwrap();
    assert_eq!(m.active_version, 2);

    f.vault.stage_rotation(&admin(), &s.id, b"bad").unwrap();
    let m = f.vault.discard_pending(&admin(), &s.id).unwrap();
    assert_eq!((m.active_version, m.pending_version), (2, None));
    assert!(read(Which::Pending).is_err());

    let m = f.vault.retire_previous(&admin(), &s.id).unwrap();
    assert_eq!(m.previous_version, None);
    assert!(f.vault.retire_previous(&admin(), &s.id).is_err());
    let states: Vec<_> = f.vault.versions(&admin(), &s.id).unwrap().into_iter().map(|v| (v.version, v.state)).collect();
    assert_eq!(states, [(1, VersionState::Retired), (2, VersionState::Active), (3, VersionState::Discarded)]);

    // Promoting again retires the older previous version.
    f.vault.stage_rotation(&admin(), &s.id, b"v4").unwrap();
    f.vault.promote(&admin(), &s.id).unwrap();
    f.vault.stage_rotation(&admin(), &s.id, b"v5").unwrap();
    let m = f.vault.promote(&admin(), &s.id).unwrap();
    assert_eq!((m.active_version, m.previous_version), (5, Some(4)));
    assert_eq!(f.vault.versions(&admin(), &s.id).unwrap()[1].state, VersionState::Retired);
    // Traders can't rotate.
    assert!(f.vault.stage_rotation(&bot, &s.id, b"x").is_err());

    let steps = f.vault.audit(&admin(), &AuditQuery::new().action(Action::Rotate).outcome(Outcome::Allowed)).unwrap();
    assert_eq!(steps.len(), 11);
}

#[test]
fn readers_keep_working_during_rotation() {
    let f = fixture();
    let s = f.live_secret("api", b"old");
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "bot", &[GrantAction::Use], None).unwrap();
    let vault = Arc::new(f.vault);
    let reader = {
        let (v, id) = (vault.clone(), s.id.clone());
        std::thread::spawn(move || {
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..300 {
                seen.insert(v.use_secret(&Caller::live("bot"), &id, |p| p.as_bytes().to_vec()).unwrap());
            }
            seen
        })
    };
    for i in 0..20 {
        vault.stage_rotation(&admin(), &s.id, format!("new-{i}").as_bytes()).unwrap();
        vault.promote(&admin(), &s.id).unwrap();
    }
    let seen = reader.join().unwrap();
    assert!(seen.iter().all(|v| v == b"old" || v.starts_with(b"new-")));
    vault.verify_audit().unwrap();
}

#[test]
fn admins_create_and_delete_others_cannot() {
    let f = fixture();
    let new = || NewSecret::new(f.account.clone(), "api", Environment::Live);
    assert!(matches!(f.vault.create(&Caller::live("bot"), new(), b"x"), Err(VaultError::Denied(_))));
    let s = f.vault.create(&admin(), new().label("desk", "1"), b"x").unwrap();
    assert!(matches!(f.vault.create(&admin(), new(), b"y"), Err(VaultError::Conflict(_))));
    assert_eq!(f.vault.find(&admin(), &f.account, "api", Environment::Live).unwrap().id, s.id);
    assert!(f.vault.find(&admin(), &f.account, "api", Environment::Test).is_err());
    assert!(f.vault.delete(&Caller::live("alice"), &s.id).is_err());
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "ops-1", &[GrantAction::Reveal], None).unwrap();
    f.vault.delete(&admin(), &s.id).unwrap();
    assert!(matches!(f.vault.meta(&admin(), &s.id), Err(VaultError::NotFound(_))));
    assert!(f.vault.grants(&admin(), &GrantTarget::Scope(f.account.clone())).unwrap().is_empty());
    // Too large.
    let big = vec![0u8; 64 * 1024 + 1];
    assert!(matches!(f.vault.create(&admin(), new(), &big), Err(VaultError::Invalid { .. })));
    // Policy changes apply at once.
    f.policy.unassign("admin", &Scope::root(), "admin");
    assert!(f.vault.create(&admin(), new(), b"x").is_err());
}

#[test]
fn reveal_can_be_turned_off() {
    let f = fixture_with(VaultOptions::new().allow_reveal(false));
    let s = f.live_secret("api", b"x");
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "ops-1", &[GrantAction::Reveal, GrantAction::Use], None).unwrap();
    assert!(matches!(f.vault.reveal(&Caller::live("ops-1"), &s.id), Err(VaultError::Denied(m)) if m.contains("turned off")));
    assert!(f.vault.reveal(&admin(), &s.id).is_err());
}

#[test]
fn audit_records_who_what_when_and_never_values() {
    let f = fixture();
    let s = f.live_secret("api", b"TOP-SECRET-VALUE");
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "ops-1", &[GrantAction::Reveal], None).unwrap();
    let t1 = f.now();
    f.advance(10);
    let _ = f.vault.reveal(&Caller::live("ops-1"), &s.id).unwrap();
    f.advance(10);
    let t2 = f.now();
    let _ = f.vault.reveal(&Caller::live("ops-2"), &s.id);
    f.advance(10);
    f.vault.stage_rotation(&admin(), &s.id, b"NEXT-SECRET-VALUE").unwrap();

    let auditor = Caller::live("auditor");
    let all = f.vault.audit(&auditor, &AuditQuery::new()).unwrap();
    verify_chain(&all, Some(GENESIS)).unwrap();
    let text = serde_json::to_string(&all).unwrap();
    assert!(!text.contains("SECRET-VALUE"));

    let window = f.vault.audit(&auditor, &AuditQuery::new().between(t1 + 1, t2)).unwrap();
    assert_eq!(window.len(), 1);
    let r = &window[0];
    assert_eq!((r.actor.as_str(), r.action, r.outcome, r.version), ("ops-1", Action::Reveal, Outcome::Allowed, Some(1)));
    assert_eq!(r.secret_id.as_ref(), Some(&s.id));
    assert_eq!(r.scope, f.account);

    let by_scope = f.vault.audit(&auditor, &AuditQuery::new().scope(f.tenant.clone()).action(Action::Rotate)).unwrap();
    assert_eq!(by_scope.len(), 1);
    assert!(f.vault.audit(&auditor, &AuditQuery::new().scope(Scope::new(["tenant-8"]).unwrap()).action(Action::Rotate)).unwrap().is_empty());
    let denied = f.vault.audit(&auditor, &AuditQuery::new().actor("ops-2")).unwrap();
    assert_eq!(denied[0].outcome, Outcome::Denied);
    let page = f.vault.audit(&auditor, &AuditQuery::new().after(2).limit(2)).unwrap();
    assert_eq!(page.iter().map(|r| r.seq).collect::<Vec<_>>(), [3, 4]);
    verify_chain(&page, Some(&all[1].hash)).unwrap();
    assert!(f.vault.audit(&auditor, &AuditQuery::new().limit(0)).is_err());
    // Only auditors and admins may query.
    assert!(matches!(f.vault.audit(&Caller::live("alice"), &AuditQuery::new()), Err(VaultError::Denied(_))));

    let head = f.vault.verify_audit().unwrap();
    assert_eq!(head, f.vault.audit_head().unwrap());
    assert!(head.seq as usize > all.len());
}

#[test]
fn metadata_reads_can_go_unrecorded() {
    let f = fixture_with(VaultOptions::new().audit_metadata_reads(false));
    let s = f.live_secret("api", b"x");
    let before = f.vault.audit_head().unwrap().seq;
    f.vault.list(&admin(), &Scope::root()).unwrap();
    f.vault.meta(&admin(), &s.id).unwrap();
    assert_eq!(f.vault.audit_head().unwrap().seq, before);
    let _ = f.vault.meta(&Caller::live("stranger"), &s.id);
    assert_eq!(f.vault.audit_head().unwrap().seq, before + 1, "refusals are always recorded");
}

#[test]
fn values_seal_to_a_recipient() {
    let f = fixture();
    let s = f.live_secret("api", b"key:secret");
    f.vault.grant(&admin(), GrantTarget::Secret(s.id.clone()), "ops-1", &[GrantAction::Reveal], None).unwrap();
    let me = ExchangeSecret::generate();
    let sealed = f.vault.reveal_sealed(&Caller::live("ops-1"), &s.id, &me.public()).unwrap();
    assert!(!serde_json::to_string(&sealed).unwrap().contains("key:secret"));
    assert_eq!(sealed.open(&me).unwrap().as_bytes(), b"key:secret");
    assert!(sealed.open(&ExchangeSecret::generate()).is_err());
}

#[test]
fn metadata_serializes_without_values() {
    let f = fixture();
    let s = f.live_secret("api", b"key:secret");
    let j = serde_json::to_value(&s).unwrap();
    assert_eq!(j["environment"], "live");
    assert_eq!(j["scope"], "tenant-7/provider-a");
    assert!(!j.to_string().contains("key:secret"));
}

#[test]
fn password_home_unlocks_rekeys_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let home = VaultHome::new(dir.path().join("vault"));
    let pw = SecretString::from("correct horse");
    let (v, out) = Vault::init(&home, &pw, allow_all(), VaultOptions::new()).unwrap();
    let s = v.create(&admin(), NewSecret::new(Scope::root(), "api", Environment::Live), b"value").unwrap();
    v.grant(&admin(), GrantTarget::Secret(s.id.clone()), "admin", &[GrantAction::Reveal], None).unwrap();
    drop(v);
    assert!(Vault::unlock(&home, &SecretString::from("wrong"), allow_all(), VaultOptions::new()).is_err());
    let v = Vault::unlock(&home, &pw, allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(v.reveal(&admin(), &s.id).unwrap().as_bytes(), b"value");
    drop(v);

    let master = weirdnet_keys::words::from_words(&out.words).unwrap();
    weirdnet_keys::keyring::rekey(&home, &master).unwrap();
    let v = Vault::unlock_with_master(&home, &master, allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(v.reveal(&admin(), &s.id).unwrap().as_bytes(), b"value", "values survive a rekey");
    v.verify_audit().unwrap();
    drop(v);

    let new_pw = SecretString::from("battery staple");
    weirdnet_keys::keyring::recover(&home, &master, &new_pw).unwrap();
    let v = Vault::unlock(&home, &new_pw, allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(v.reveal(&admin(), &s.id).unwrap().as_bytes(), b"value");
}

#[test]
fn key_store_opens_the_same_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let keys = MemoryKeyStore::new();
    let v = Vault::open_with_keystore(&path, &keys, "vault-key", allow_all(), VaultOptions::new()).unwrap();
    let s = v.create(&admin(), NewSecret::new(Scope::root(), "api", Environment::Test), b"value").unwrap();
    drop(v);
    let v = Vault::open_with_keystore(&path, &keys, "vault-key", allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(v.meta(&admin(), &s.id).unwrap().name, "api");
    drop(v);
    let other = MemoryKeyStore::new();
    assert!(Vault::open_with_keystore(&path, &other, "vault-key", allow_all(), VaultOptions::new()).is_err());
    keys.store("bad", b"short").unwrap();
    assert!(load_or_create_key(&keys, "bad").is_err());
}

#[test]
fn snapshots_restore_with_their_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let key = Key32::random().unwrap();
    let v = Vault::open_with_key(&path, &key, allow_all(), VaultOptions::new()).unwrap();
    let s = v.create(&admin(), NewSecret::new(Scope::root(), "api", Environment::Live), b"value").unwrap();
    v.grant(&admin(), GrantTarget::Secret(s.id.clone()), "admin", &[GrantAction::Reveal], None).unwrap();

    let same = dir.path().join("same.db");
    v.snapshot_to(&admin(), &same, None).unwrap();
    let new_key = Key32::random().unwrap();
    let moved = dir.path().join("moved.db");
    v.snapshot_to(&admin(), &moved, Some(&new_key)).unwrap();
    assert!(v.snapshot_to(&admin(), &path, None).is_err());

    let a = Vault::open_with_key(&same, &key, allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(a.reveal(&admin(), &s.id).unwrap().as_bytes(), b"value");
    let b = Vault::open_with_key(&moved, &new_key, allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(b.reveal(&admin(), &s.id).unwrap().as_bytes(), b"value");
    assert!(b.audit(&admin(), &AuditQuery::new().action(Action::Backup)).unwrap().len() == 2);
    b.verify_audit().unwrap();
    assert!(Vault::open_with_key(&moved, &key, allow_all(), VaultOptions::new()).is_err());
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn async_vault_runs_off_the_runtime() {
    let vault = AsyncVault::new(Vault::open_in_memory(allow_all(), VaultOptions::new()).unwrap());
    let scope = Scope::new(["t", "a"]).unwrap();
    let m = vault.create(admin(), NewSecret::new(scope.clone(), "api", Environment::Live), b"k".to_vec().into()).await.unwrap();
    vault.grant(admin(), GrantTarget::Scope(scope.clone()), "bot".into(), vec![GrantAction::Use], None).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (v, id) = (vault.clone(), m.id.clone());
        tasks.push(tokio::spawn(async move { v.use_secret(Caller::live("bot"), id, |p| p.len()).await }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap(), 1);
    }
    vault.stage_rotation(admin(), m.id.clone(), b"k2".to_vec().into()).await.unwrap();
    vault.promote(admin(), m.id.clone()).await.unwrap();
    assert_eq!(vault.list(admin(), scope).await.unwrap()[0].active_version, 2);
    vault.verify_audit().await.unwrap();
}
