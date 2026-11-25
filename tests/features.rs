//! Tests for the optional features.
#![allow(unused_imports)]
use std::sync::Arc;
use weirdnet_vault::*;

#[allow(dead_code)]
fn allow_all() -> Arc<dyn Authorize> {
    Arc::new(|_: &AccessRequest<'_>| Decision::Allow)
}

#[cfg(feature = "keychain")]
#[test]
fn keychain_store_keeps_the_vault_key() {
    let store = KeychainStore::with_store(keyring_core::mock::Store::new().unwrap(), "weirdnet-vault-test");
    assert_eq!(store.service(), "weirdnet-vault-test");
    assert!(store.load("k").unwrap().is_none());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let admin = Caller::live("admin");
    let v = Vault::open_with_keystore(&path, &store, "vault-key", allow_all(), VaultOptions::new()).unwrap();
    let s = v.create(&admin, NewSecret::new(Scope::root(), "api", Environment::Live), b"value").unwrap();
    drop(v);
    assert_eq!(store.load("vault-key").unwrap().unwrap().len(), 32);
    let v = Vault::open_with_keystore(&path, &store, "vault-key", allow_all(), VaultOptions::new()).unwrap();
    assert_eq!(v.meta(&admin, &s.id).unwrap().name, "api");
    store.remove("vault-key").unwrap();
    store.remove("vault-key").unwrap();
    assert!(store.load("vault-key").unwrap().is_none());
}

#[cfg(feature = "sync")]
#[test]
fn sync_secret_stores_interoperate() {
    use weirdnet_sync::{FileSecrets, SecretStore};
    let dir = tempfile::tempdir().unwrap();
    let files = SyncSecrets(FileSecrets::new(dir.path()));
    let k = load_or_create_key(&files, "vault-key").unwrap();
    assert_eq!(load_or_create_key(&files, "vault-key").unwrap(), k);
    files.remove("vault-key").unwrap();
    // The vault's stores serve weirdnet-sync identities too.
    let mem = MemoryKeyStore::new();
    SecretStore::write(&mem, "seed", b"abc").unwrap();
    assert_eq!(SecretStore::read(&mem, "seed").unwrap().unwrap().as_slice(), b"abc");
    SecretStore::remove(&mem, "seed").unwrap();
    assert!(SecretStore::read(&mem, "seed").unwrap().is_none());
}

#[cfg(feature = "access")]
#[test]
fn access_authorizer_uses_weirdnet_access_roles() {
    use weirdnet_access::{Facts, Role, RoleSet, Settings};
    use weirdnet_vault::access::{self, AccessAuthorizer};
    let catalog = access::vault_catalog().unwrap();
    let roles = RoleSet::new(
        &catalog,
        vec![
            Role { id: "owner".into(), name: "owner".into(), rank: 100, perms: vec!["*".into()], builtin: true },
            Role { id: "trader".into(), name: "trader".into(), rank: 50, perms: vec![access::USE.into()], builtin: false },
            Role { id: "viewer".into(), name: "viewer".into(), rank: 10, perms: vec![access::LIST.into()], builtin: false },
        ],
    )
    .unwrap();
    let authz = AccessAuthorizer::new(catalog, roles, Settings::default(), |r: &AccessRequest<'_>| {
        let role = match r.caller.identity.as_str() {
            "bot" => Some("trader"),
            "alice" => Some("viewer"),
            _ => None,
        };
        Facts {
            user: Some(r.caller.identity.clone()),
            is_owner: r.caller.identity == "owner",
            trusted: true,
            membership_role: role.map(str::to_string),
            ..Facts::default()
        }
    });
    let v = Vault::open_in_memory(Arc::new(authz), VaultOptions::new()).unwrap();
    let owner = Caller::live("owner");
    let scope = Scope::new(["t"]).unwrap();
    let s = v.create(&owner, NewSecret::new(scope.clone(), "api", Environment::Live), b"k").unwrap();
    v.grant(&owner, GrantTarget::Scope(scope.clone()), "bot", &[GrantAction::Use, GrantAction::Reveal], None).unwrap();
    v.grant(&owner, GrantTarget::Scope(scope.clone()), "alice", &[GrantAction::Use], None).unwrap();
    assert_eq!(v.use_secret(&Caller::live("bot"), &s.id, |p| p.len()).unwrap(), 1);
    // vault.use implies read-meta and list.
    assert_eq!(v.list(&Caller::live("bot"), &scope).unwrap().len(), 1);
    assert!(v.reveal(&Caller::live("bot"), &s.id).is_err());
    assert!(v.use_secret(&Caller::live("alice"), &s.id, |_| ()).is_err());
    assert_eq!(v.list(&Caller::live("alice"), &scope).unwrap().len(), 1);
    assert!(v.meta(&Caller::live("alice"), &s.id).is_err());
    assert!(v.list(&Caller::live("stranger"), &scope).unwrap().is_empty());
}

#[cfg(feature = "mcp")]
#[test]
fn mcp_tools_manage_metadata_and_never_values() {
    use serde_json::{Value, json};
    use weirdnet_mcp::{Server, ServerInfo, ToolSpec};
    use weirdnet_vault::mcp::VaultTools;

    assert!(ToolSpec::check(VaultTools::<fn(Option<&str>) -> Option<Caller>>::specs()).is_ok());
    let policy = Arc::new(RolePolicy::with_example_roles());
    policy.assign("admin", &Scope::root(), "admin").unwrap();
    policy.assign("alice", &Scope::root(), "viewer").unwrap();
    let vault = Arc::new(Vault::open_in_memory(policy, VaultOptions::new()).unwrap());
    let scope = Scope::new(["tenant-7", "provider-a"]).unwrap();
    let s = vault.create(&Caller::live("admin"), NewSecret::new(scope, "api", Environment::Live), b"TOP-SECRET").unwrap();
    let resolver = |t: Option<&str>| match t {
        Some("admin-token") => Some(Caller::live("admin")),
        Some("alice-token") => Some(Caller::live("alice")),
        _ => None,
    };
    let server = Server::new(
        ServerInfo { name: "vault".into(), title: "Vault".into(), version: "0.1.0".into(), instructions: String::new() },
        VaultTools::new(vault.clone(), resolver),
    );
    let call = |token: Option<&str>, name: &str, args: Value| -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
        server.handle(token, msg).unwrap()
    };
    let is_error = |r: &Value| r["result"]["isError"] == json!(true);

    let list = call(Some("alice-token"), "vault_list", json!({"scope": "tenant-7"}));
    assert!(!is_error(&list), "{list}");
    let text = list.to_string();
    assert!(text.contains(s.id.as_str()) && !text.contains("TOP-SECRET"));

    let show = call(Some("admin-token"), "vault_show", json!({"id": s.id}));
    assert!(show.to_string().contains("\"versions\"") && !show.to_string().contains("TOP-SECRET"));

    let g = call(Some("admin-token"), "vault_grant", json!({"id": s.id, "identity": "bot", "actions": ["use"]}));
    assert!(!is_error(&g), "{g}");
    let denied = call(Some("alice-token"), "vault_grant", json!({"id": s.id, "identity": "alice", "actions": ["reveal"]}));
    assert!(is_error(&denied));
    let anon = call(None, "vault_list", json!({}));
    assert!(is_error(&anon));
    let audit = call(Some("admin-token"), "vault_audit", json!({"action": "grant"}));
    assert!(!is_error(&audit) && audit.to_string().contains("denied"));
    let verify = call(Some("admin-token"), "vault_verify_audit", json!({}));
    assert!(!is_error(&verify), "{verify}");
    let del = call(Some("admin-token"), "vault_delete", json!({"id": s.id}));
    assert!(!is_error(&del));
    assert!(vault.meta(&Caller::live("admin"), &s.id).is_err());
    let tools = server.handle(None, json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).unwrap();
    for t in tools["result"]["tools"].as_array().unwrap() {
        let schema = t["inputSchema"].to_string();
        assert!(!schema.contains("\"value\""), "no tool takes a value: {schema}");
    }
}
