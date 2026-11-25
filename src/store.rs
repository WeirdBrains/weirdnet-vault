//! The vault's schema and row access.
use crate::audit::{AuditHead, AuditQuery, AuditRecord, GENESIS, MAX_DETAIL, MAX_LIMIT, Outcome};
use crate::crypto::{self, WRAP_AAD};
use crate::error::{Result, VaultError};
use crate::grant::{Grant, GrantAction, GrantId, GrantTarget, actions_text, parse_actions};
use crate::policy::{Action, Caller};
use crate::scope::{Environment, Scope};
use crate::secret::{Labels, Plaintext, SecretId, SecretMeta, VersionMeta, VersionState};
use weirdnet_keys::{Key32, Sealed, open, seal};
use weirdnet_storage::rusqlite::{self, Connection, OptionalExtension, ToSql, params};

pub(crate) const MIGRATIONS: &[&str] = &["
CREATE TABLE key_wraps (
  key_id TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  ct TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  environment TEXT NOT NULL,
  labels TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  active_version INTEGER NOT NULL,
  pending_version INTEGER,
  previous_version INTEGER,
  next_version INTEGER NOT NULL,
  UNIQUE (scope, name, environment)
);
CREATE INDEX secrets_scope ON secrets(scope);
CREATE TABLE versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  state TEXT NOT NULL,
  nonce TEXT,
  ct TEXT,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (secret_id, version)
);
CREATE TABLE grants (
  id TEXT PRIMARY KEY,
  secret_id TEXT REFERENCES secrets(id) ON DELETE CASCADE,
  scope TEXT,
  identity TEXT NOT NULL,
  actions TEXT NOT NULL,
  expires_at INTEGER,
  granted_by TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  CHECK ((secret_id IS NULL) <> (scope IS NULL))
);
CREATE INDEX grants_identity ON grants(identity);
CREATE INDEX grants_secret ON grants(secret_id);
CREATE TABLE audit (
  seq INTEGER PRIMARY KEY,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  environment TEXT NOT NULL,
  action TEXT NOT NULL,
  scope TEXT NOT NULL,
  secret_id TEXT,
  version INTEGER,
  outcome TEXT NOT NULL,
  detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX audit_at ON audit(at);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
"];

/// Migrate, set the pragmas and return the entry key (created on first open).
pub(crate) fn prepare(conn: &mut Connection, dek: &Key32, now: i64) -> Result<Key32> {
    weirdnet_storage::migrate(conn, MIGRATIONS, MIGRATIONS.len(), |_, _| Ok::<(), VaultError>(()))?;
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    let wrap = crypto::wrap_key(dek)?;
    let kid = crypto::key_id(&wrap);
    let row: Option<(String, String)> =
        conn.query_row("SELECT nonce, ct FROM key_wraps WHERE key_id = ?1", [&kid], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    if let Some((nonce, ct)) = row {
        let k = open(&wrap, &Sealed { nonce, ct }, WRAP_AAD)?;
        return Ok(Key32::from_slice(&k)?);
    }
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM key_wraps", [], |r| r.get(0))?;
    if count > 0 {
        return Err(VaultError::Unlock("this key does not unwrap the vault's entry key".into()));
    }
    let entry = Key32::random()?;
    put_wrap(conn, &entry, &wrap, now)?;
    Ok(entry)
}

fn put_wrap(conn: &Connection, entry: &Key32, wrap: &Key32, now: i64) -> Result<()> {
    let s = seal(wrap, &entry.0, WRAP_AAD)?;
    conn.execute(
        "INSERT OR REPLACE INTO key_wraps (key_id, nonce, ct, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![crypto::key_id(wrap), s.nonce, s.ct, now],
    )?;
    Ok(())
}

/// Wrap the entry key for another database key too.
pub(crate) fn add_wrap(conn: &Connection, entry: &Key32, dek: &Key32, now: i64) -> Result<()> {
    put_wrap(conn, entry, &crypto::wrap_key(dek)?, now)
}

/// Drop the entry-key wrap for a database key.
pub(crate) fn remove_wrap(conn: &Connection, dek: &Key32) -> Result<()> {
    conn.execute("DELETE FROM key_wraps WHERE key_id = ?1", [crypto::key_id(&crypto::wrap_key(dek)?)])?;
    Ok(())
}

const SECRET_COLS: &str =
    "id, scope, name, kind, environment, labels, created_at, created_by, updated_at, active_version, pending_version, previous_version";

type SecretRow = (String, String, String, String, String, String, i64, String, i64, i64, Option<i64>, Option<i64>);

fn secret_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?))
}

fn version_num(v: i64) -> Result<u32> {
    u32::try_from(v).map_err(|_| VaultError::Storage(format!("bad version {v}")))
}

fn to_meta(t: SecretRow) -> Result<SecretMeta> {
    let labels: Labels = serde_json::from_str(&t.5).map_err(|e| VaultError::Storage(format!("labels: {e}")))?;
    Ok(SecretMeta {
        id: SecretId::parse(&t.0)?,
        scope: Scope::parse(&t.1)?,
        name: t.2,
        kind: t.3,
        environment: Environment::parse(&t.4)?,
        labels,
        created_at: t.6,
        created_by: t.7,
        updated_at: t.8,
        active_version: version_num(t.9)?,
        pending_version: t.10.map(version_num).transpose()?,
        previous_version: t.11.map(version_num).transpose()?,
    })
}

pub(crate) fn get_secret(conn: &Connection, id: &SecretId) -> Result<Option<SecretMeta>> {
    let row = conn.query_row(&format!("SELECT {SECRET_COLS} FROM secrets WHERE id = ?1"), [id.as_str()], secret_row).optional()?;
    row.map(to_meta).transpose()
}

pub(crate) fn find_secret(conn: &Connection, scope: &Scope, name: &str, env: Environment) -> Result<Option<SecretMeta>> {
    let row = conn
        .query_row(
            &format!("SELECT {SECRET_COLS} FROM secrets WHERE scope = ?1 AND name = ?2 AND environment = ?3"),
            params![scope.as_str(), name, env.as_str()],
            secret_row,
        )
        .optional()?;
    row.map(to_meta).transpose()
}

pub(crate) fn list_secrets(conn: &Connection, prefix: &Scope) -> Result<Vec<SecretMeta>> {
    let sub = format!("{}/", prefix.as_str());
    let mut st = conn.prepare(&format!(
        "SELECT {SECRET_COLS} FROM secrets WHERE ?1 = '' OR scope = ?1 OR substr(scope, 1, length(?2)) = ?2 ORDER BY scope, name, environment"
    ))?;
    let rows = st.query_map(params![prefix.as_str(), sub], secret_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(to_meta).collect()
}

pub(crate) fn insert_secret(conn: &Connection, m: &SecretMeta) -> Result<()> {
    let labels = serde_json::to_string(&m.labels).map_err(|e| VaultError::Storage(e.to_string()))?;
    conn.execute(
        "INSERT INTO secrets (id, scope, name, kind, environment, labels, created_at, created_by, updated_at, active_version, next_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            m.id.as_str(),
            m.scope.as_str(),
            m.name,
            m.kind,
            m.environment.as_str(),
            labels,
            m.created_at,
            m.created_by,
            m.updated_at,
            m.active_version,
            m.active_version + 1
        ],
    )?;
    Ok(())
}

/// Write the version pointers back.
pub(crate) fn set_pointers(conn: &Connection, m: &SecretMeta, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE secrets SET active_version = ?2, pending_version = ?3, previous_version = ?4, updated_at = ?5 WHERE id = ?1",
        params![m.id.as_str(), m.active_version, m.pending_version, m.previous_version, now],
    )?;
    Ok(())
}

/// Take the next version number.
pub(crate) fn take_version(conn: &Connection, id: &SecretId) -> Result<u32> {
    let v: i64 = conn.query_row("SELECT next_version FROM secrets WHERE id = ?1", [id.as_str()], |r| r.get(0))?;
    conn.execute("UPDATE secrets SET next_version = next_version + 1 WHERE id = ?1", [id.as_str()])?;
    version_num(v)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_version(
    conn: &Connection,
    entry: &Key32,
    m: &SecretMeta,
    version: u32,
    state: VersionState,
    value: &[u8],
    by: &str,
    now: i64,
) -> Result<()> {
    let s = crypto::seal_value(entry, &m.id, version, m.environment, &m.scope, value)?;
    conn.execute(
        "INSERT INTO versions (secret_id, version, state, nonce, ct, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![m.id.as_str(), version, state.as_str(), s.nonce, s.ct, now, by],
    )?;
    Ok(())
}

pub(crate) fn set_state(conn: &Connection, id: &SecretId, version: u32, state: VersionState) -> Result<()> {
    let wipe = matches!(state, VersionState::Retired | VersionState::Discarded);
    let sql = if wipe {
        "UPDATE versions SET state = ?3, nonce = NULL, ct = NULL WHERE secret_id = ?1 AND version = ?2"
    } else {
        "UPDATE versions SET state = ?3 WHERE secret_id = ?1 AND version = ?2"
    };
    conn.execute(sql, params![id.as_str(), version, state.as_str()])?;
    Ok(())
}

pub(crate) fn wipe_all(conn: &Connection, id: &SecretId) -> Result<()> {
    conn.execute("UPDATE versions SET nonce = NULL, ct = NULL WHERE secret_id = ?1", [id.as_str()])?;
    Ok(())
}

pub(crate) fn read_value(conn: &Connection, entry: &Key32, m: &SecretMeta, version: u32) -> Result<Plaintext> {
    let row: Option<(Option<String>, Option<String>)> = conn
        .query_row("SELECT nonce, ct FROM versions WHERE secret_id = ?1 AND version = ?2", params![m.id.as_str(), version], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    match row {
        Some((Some(nonce), Some(ct))) => {
            Ok(Plaintext::new(crypto::open_value(entry, &m.id, version, m.environment, &m.scope, &Sealed { nonce, ct })?))
        }
        Some(_) => Err(VaultError::NotFound(format!("secret {} v{version} was wiped", m.id))),
        None => Err(VaultError::NotFound(format!("secret {} v{version}", m.id))),
    }
}

pub(crate) fn versions(conn: &Connection, id: &SecretId) -> Result<Vec<VersionMeta>> {
    let mut st = conn.prepare("SELECT version, state, created_at, created_by FROM versions WHERE secret_id = ?1 ORDER BY version")?;
    let rows = st
        .query_map([id.as_str()], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(v, s, at, by)| Ok(VersionMeta { version: version_num(v)?, state: VersionState::parse(&s)?, created_at: at, created_by: by }))
        .collect()
}

const GRANT_COLS: &str = "id, secret_id, scope, identity, actions, expires_at, granted_by, granted_at";

type GrantRow = (String, Option<String>, Option<String>, String, String, Option<i64>, String, i64);

fn grant_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
}

fn to_grant(t: GrantRow) -> Result<Grant> {
    let target = match (t.1, t.2) {
        (Some(s), None) => GrantTarget::Secret(SecretId::parse(&s)?),
        (None, Some(s)) => GrantTarget::Scope(Scope::parse(&s)?),
        _ => return Err(VaultError::Storage("grant without a single target".into())),
    };
    Ok(Grant { id: GrantId(t.0), target, identity: t.3, actions: parse_actions(&t.4)?, expires_at: t.5, granted_by: t.6, granted_at: t.7 })
}

pub(crate) fn insert_grant(conn: &Connection, g: &Grant) -> Result<()> {
    let (sid, scope) = match &g.target {
        GrantTarget::Secret(s) => (Some(s.as_str()), None),
        GrantTarget::Scope(s) => (None, Some(s.as_str())),
    };
    conn.execute(
        &format!("INSERT INTO grants ({GRANT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
        params![g.id.as_str(), sid, scope, g.identity, actions_text(&g.actions), g.expires_at, g.granted_by, g.granted_at],
    )?;
    Ok(())
}

pub(crate) fn get_grant(conn: &Connection, id: &GrantId) -> Result<Option<Grant>> {
    let row = conn.query_row(&format!("SELECT {GRANT_COLS} FROM grants WHERE id = ?1"), [id.as_str()], grant_row).optional()?;
    row.map(to_grant).transpose()
}

pub(crate) fn delete_grant(conn: &Connection, id: &GrantId) -> Result<()> {
    conn.execute("DELETE FROM grants WHERE id = ?1", [id.as_str()])?;
    Ok(())
}

/// Grants on exactly this target.
pub(crate) fn grants_on(conn: &Connection, target: &GrantTarget) -> Result<Vec<Grant>> {
    let (sql, arg) = match target {
        GrantTarget::Secret(s) => (format!("SELECT {GRANT_COLS} FROM grants WHERE secret_id = ?1 ORDER BY granted_at, rowid"), s.as_str()),
        GrantTarget::Scope(s) => (format!("SELECT {GRANT_COLS} FROM grants WHERE scope = ?1 ORDER BY granted_at, rowid"), s.as_str()),
    };
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map([arg], grant_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(to_grant).collect()
}

/// Every grant that applies to this secret (on it, or on a scope containing it).
pub(crate) fn grants_covering(conn: &Connection, m: &SecretMeta) -> Result<Vec<Grant>> {
    let mut st = conn.prepare(&format!("SELECT {GRANT_COLS} FROM grants WHERE secret_id = ?1 OR scope IS NOT NULL ORDER BY granted_at, rowid"))?;
    let rows = st.query_map([m.id.as_str()], grant_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    let all = rows.into_iter().map(to_grant).collect::<Result<Vec<_>>>()?;
    Ok(all
        .into_iter()
        .filter(|g| match &g.target {
            GrantTarget::Secret(_) => true,
            GrantTarget::Scope(s) => s.contains(&m.scope),
        })
        .collect())
}

pub(crate) fn has_grant(conn: &Connection, identity: &str, m: &SecretMeta, action: GrantAction, now: i64) -> Result<bool> {
    let mut st = conn.prepare(&format!("SELECT {GRANT_COLS} FROM grants WHERE identity = ?1 AND (secret_id = ?2 OR scope IS NOT NULL)"))?;
    let rows = st.query_map(params![identity, m.id.as_str()], grant_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    for r in rows {
        if to_grant(r)?.covers(&m.id, &m.scope, action, now) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One event to record.
pub(crate) struct Event<'a> {
    pub caller: &'a Caller,
    pub action: Action,
    pub scope: &'a Scope,
    pub secret_id: Option<&'a SecretId>,
    pub version: Option<u32>,
    pub outcome: Outcome,
    pub detail: String,
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_DETAIL {
        let mut cut = MAX_DETAIL;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

pub(crate) fn head(conn: &Connection) -> Result<AuditHead> {
    let row: Option<(i64, String)> =
        conn.query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    Ok(match row {
        Some((seq, hash)) => AuditHead { seq: seq as u64, hash },
        None => AuditHead { seq: 0, hash: GENESIS.into() },
    })
}

pub(crate) fn append_audit(conn: &Connection, ev: Event<'_>, at: i64) -> Result<AuditRecord> {
    let h = head(conn)?;
    let mut rec = AuditRecord {
        seq: h.seq + 1,
        at,
        actor: ev.caller.identity.clone(),
        environment: ev.caller.environment,
        action: ev.action,
        scope: ev.scope.clone(),
        secret_id: ev.secret_id.cloned(),
        version: ev.version,
        outcome: ev.outcome,
        detail: truncate(ev.detail),
        prev_hash: h.hash,
        hash: String::new(),
    };
    rec.hash = rec.expected_hash();
    conn.execute(
        "INSERT INTO audit (seq, at, actor, environment, action, scope, secret_id, version, outcome, detail, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            rec.seq as i64,
            rec.at,
            rec.actor,
            rec.environment.as_str(),
            rec.action.as_str(),
            rec.scope.as_str(),
            rec.secret_id.as_ref().map(|s| s.as_str()),
            rec.version,
            rec.outcome.as_str(),
            rec.detail,
            rec.prev_hash,
            rec.hash
        ],
    )?;
    Ok(rec)
}

const AUDIT_COLS: &str = "seq, at, actor, environment, action, scope, secret_id, version, outcome, detail, prev_hash, hash";

type AuditRow = (i64, i64, String, String, String, String, Option<String>, Option<i64>, String, String, String, String);

fn audit_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?))
}

fn to_record(t: AuditRow) -> Result<AuditRecord> {
    Ok(AuditRecord {
        seq: t.0 as u64,
        at: t.1,
        actor: t.2,
        environment: Environment::parse(&t.3)?,
        action: Action::parse(&t.4)?,
        scope: Scope::parse(&t.5)?,
        secret_id: t.6.as_deref().map(SecretId::parse).transpose()?,
        version: t.7.map(version_num).transpose()?,
        outcome: Outcome::parse(&t.8)?,
        detail: t.9,
        prev_hash: t.10,
        hash: t.11,
    })
}

pub(crate) fn query_audit(conn: &Connection, q: &AuditQuery) -> Result<Vec<AuditRecord>> {
    if q.limit == 0 || q.limit > MAX_LIMIT {
        return Err(VaultError::invalid("limit", format!("1 to {MAX_LIMIT}")));
    }
    let mut sql = format!("SELECT {AUDIT_COLS} FROM audit WHERE 1 = 1");
    let mut args: Vec<Box<dyn ToSql>> = Vec::new();
    let mut add = |cond: &str, v: Box<dyn ToSql>| {
        args.push(v);
        sql.push_str(&cond.replace('?', &format!("?{}", args.len())));
    };
    if let Some(s) = q.after_seq {
        add(" AND seq > ?", Box::new(s as i64));
    }
    if let Some(f) = q.from {
        add(" AND at >= ?", Box::new(f));
    }
    if let Some(t) = q.to {
        add(" AND at < ?", Box::new(t));
    }
    if let Some(a) = &q.actor {
        add(" AND actor = ?", Box::new(a.clone()));
    }
    if let Some(a) = q.action {
        add(" AND action = ?", Box::new(a.as_str()));
    }
    if let Some(o) = q.outcome {
        add(" AND outcome = ?", Box::new(o.as_str()));
    }
    if let Some(s) = q.scope.as_ref().filter(|s| !s.is_root()) {
        add(" AND (scope = ?", Box::new(s.as_str().to_string()));
        add(" OR substr(scope, 1, length(?))", Box::new(format!("{}/", s.as_str())));
        add(" = ?)", Box::new(format!("{}/", s.as_str())));
    }
    sql.push_str(&format!(" ORDER BY seq LIMIT {}", q.limit));
    let mut st = conn.prepare(&sql)?;
    let refs: Vec<&dyn ToSql> = args.iter().map(|b| b.as_ref()).collect();
    let rows = st.query_map(refs.as_slice(), audit_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(to_record).collect()
}

/// Walk the whole log; return the head or the first broken `seq`.
pub(crate) fn verify_audit(conn: &Connection) -> Result<AuditHead> {
    let mut st = conn.prepare(&format!("SELECT {AUDIT_COLS} FROM audit ORDER BY seq"))?;
    let mut rows = st.query([])?;
    let mut prev_hash = GENESIS.to_string();
    let mut expect = 1u64;
    while let Some(r) = rows.next()? {
        let rec = to_record(audit_row(r)?)?;
        if rec.seq != expect || rec.prev_hash != prev_hash || !rec.is_intact() {
            return Err(VaultError::AuditBroken(rec.seq));
        }
        prev_hash = rec.hash;
        expect += 1;
    }
    Ok(AuditHead { seq: expect - 1, hash: prev_hash })
}
