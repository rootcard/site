//! SQLite storage for the host: the identity, challenge and session stores of `rootcard-host`, following the schema of
//! rootcard's ARCHITECTURE.md §3.1. One connection behind a mutex: the site runs as a single process, so the mutex is
//! the compare-and-swap boundary ([HST-19]) and SQLite's transactions make each change atomic on disk.

use rootcard::json::{Value, canonical, parse_json};
use rootcard::log::LogState;
use rootcard::messages::Purpose;
use rootcard_host::store::{
    ChallengeStore, Expected, HandleKey, IdentityStore, Insert, Issued, Session, SessionStore, StoreError, Stored,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

/// How long an expired challenge is kept so that it still answers `challenge_expired` (one more lifetime).
const CHALLENGE_GRACE: i64 = 60;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS identities (
  account     TEXT PRIMARY KEY,
  realm       TEXT NOT NULL,
  username_lc TEXT NOT NULL,
  tag         TEXT NOT NULL,
  claimed     INTEGER NOT NULL,
  events      TEXT NOT NULL,
  state       TEXT NOT NULL,
  version_seq INTEGER NOT NULL,
  version     TEXT NOT NULL,
  vault       TEXT,
  vault_rev   INTEGER,
  public      TEXT,
  public_rev  INTEGER,
  changed     INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS identities_handle ON identities (realm, username_lc, tag) WHERE claimed = 1;
CREATE INDEX IF NOT EXISTS identities_lookup ON identities (realm, username_lc, tag);
CREATE INDEX IF NOT EXISTS identities_changed ON identities (changed);
CREATE TABLE IF NOT EXISTS challenges (
  nonce   BLOB PRIMARY KEY,
  account TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS challenges_expires ON challenges (expires);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY,
  account    TEXT NOT NULL,
  instance   BLOB NOT NULL,
  last_used  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_last_used ON sessions (last_used);
";

/// The database, shared by the three stores.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError(e.to_string())
}

impl Db {
    /// Open (or create) the database file.
    pub fn open(path: &Path) -> Result<Db, StoreError> {
        Db::from_connection(Connection::open(path).map_err(err)?)
    }

    /// An in-memory database, for tests.
    #[cfg(test)]
    pub fn memory() -> Result<Db, StoreError> {
        Db::from_connection(Connection::open_in_memory().map_err(err)?)
    }

    fn from_connection(conn: Connection) -> Result<Db, StoreError> {
        conn.execute_batch(SCHEMA).map_err(err)?;
        Ok(Db(Arc::new(Mutex::new(conn))))
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.0.lock().map_err(|_| StoreError("lock poisoned".into()))
    }

    /// Delete expired challenges and idle sessions (called periodically).
    pub fn sweep(&self, now: i64) -> Result<(), StoreError> {
        let c = self.conn()?;
        c.execute(
            "DELETE FROM challenges WHERE expires < ?1",
            params![now - CHALLENGE_GRACE],
        )
        .map_err(err)?;
        c.execute(
            "DELETE FROM sessions WHERE last_used < ?1",
            params![now - rootcard_host::SESSION_IDLE],
        )
        .map_err(err)?;
        Ok(())
    }

    /// The number of identities whose home is this host (with a vault), for the front page.
    pub fn count(&self) -> Result<i64, StoreError> {
        self.conn()?
            .query_row("SELECT COUNT(*) FROM identities WHERE vault IS NOT NULL", [], |r| {
                r.get(0)
            })
            .map_err(err)
    }
}

fn json_text(v: &Value) -> String {
    // Canonical JSON is UTF-8 by construction.
    String::from_utf8_lossy(&canonical(v)).into_owned()
}

fn parse(text: &str) -> Result<Value, StoreError> {
    parse_json(text.as_bytes()).map_err(|e| StoreError(format!("corrupt row: {e}")))
}

fn version_text(v: &rootcard::log::Version) -> String {
    rootcard::encoding::base64url_encode(&v.hash)
}

struct Row {
    events: String,
    state: String,
    vault: Option<String>,
    public: Option<String>,
}

fn decode(row: Row) -> Result<Stored, StoreError> {
    let events = match parse(&row.events)? {
        Value::Array(a) => a,
        _ => return Err(StoreError("corrupt row: events".into())),
    };
    let state = LogState::from_value(&parse(&row.state)?).map_err(|e| StoreError(format!("corrupt row: {e}")))?;
    Ok(Stored {
        events,
        state,
        vault: row.vault.as_deref().map(parse).transpose()?,
        public: row.public.as_deref().map(parse).transpose()?,
    })
}

fn next_changed(c: &Connection) -> Result<i64, StoreError> {
    c.query_row("SELECT COALESCE(MAX(changed), 0) + 1 FROM identities", [], |r| r.get(0))
        .map_err(err)
}

impl IdentityStore for Db {
    fn load(&self, account: &str) -> Result<Option<Stored>, StoreError> {
        let row = self
            .conn()?
            .query_row(
                "SELECT events, state, vault, public FROM identities WHERE account = ?1",
                params![account],
                |r| {
                    Ok(Row {
                        events: r.get(0)?,
                        state: r.get(1)?,
                        vault: r.get(2)?,
                        public: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(err)?;
        row.map(decode).transpose()
    }

    fn insert(&self, new: &Stored, claim: bool) -> Result<Insert, StoreError> {
        let mut c = self.conn()?;
        let tx = c.transaction().map_err(err)?;
        let account = new.state.account.as_str();
        let exists: bool = tx
            .query_row("SELECT 1 FROM identities WHERE account = ?1", params![account], |_| {
                Ok(true)
            })
            .optional()
            .map_err(err)?
            .unwrap_or(false);
        if exists {
            return Ok(Insert::Exists);
        }
        let key = HandleKey::of(&new.state);
        if claim {
            // Only identities registered here reserve a handle ([HST-4]).
            let taken: bool = tx
                .query_row(
                    "SELECT 1 FROM identities WHERE realm = ?1 AND username_lc = ?2 AND tag = ?3 AND claimed = 1",
                    params![key.realm, key.username, key.tag],
                    |_| Ok(true),
                )
                .optional()
                .map_err(err)?
                .unwrap_or(false);
            if taken {
                return Ok(Insert::HandleTaken);
            }
        }
        let changed = next_changed(&tx)?;
        tx.execute(
            "INSERT INTO identities (account, realm, username_lc, tag, claimed, events, state, version_seq, version,
               vault, vault_rev, public, public_rev, changed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                account,
                key.realm,
                key.username,
                key.tag,
                claim,
                json_text(&Value::Array(new.events.clone())),
                json_text(&new.state.to_value()),
                new.state.version.seq,
                version_text(&new.state.version),
                new.vault.as_ref().map(json_text),
                new.vault_rev(),
                new.public.as_ref().map(json_text),
                new.public_rev(),
                changed,
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(Insert::Done)
    }

    fn swap(&self, account: &str, expected: &Expected, new: &Stored) -> Result<bool, StoreError> {
        let mut c = self.conn()?;
        let tx = c.transaction().map_err(err)?;
        let changed = next_changed(&tx)?;
        let n = tx
            .execute(
                "UPDATE identities SET events = ?1, state = ?2, version_seq = ?3, version = ?4, vault = ?5,
                   vault_rev = ?6, public = ?7, public_rev = ?8, changed = ?9
                 WHERE account = ?10 AND version_seq = ?11 AND version = ?12
                   AND vault_rev IS ?13 AND public_rev IS ?14",
                params![
                    json_text(&Value::Array(new.events.clone())),
                    json_text(&new.state.to_value()),
                    new.state.version.seq,
                    version_text(&new.state.version),
                    new.vault.as_ref().map(json_text),
                    new.vault_rev(),
                    new.public.as_ref().map(json_text),
                    new.public_rev(),
                    changed,
                    account,
                    expected.version.seq,
                    version_text(&expected.version),
                    expected.vault_rev,
                    expected.public_rev,
                ],
            )
            .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(n == 1)
    }

    fn by_handle(&self, key: &HandleKey) -> Result<Vec<String>, StoreError> {
        let c = self.conn()?;
        let mut st = c
            .prepare(
                "SELECT account FROM identities WHERE realm = ?1 AND username_lc = ?2 AND tag = ?3 ORDER BY account",
            )
            .map_err(err)?;
        let rows = st
            .query_map(params![key.realm, key.username, key.tag], |r| r.get::<_, String>(0))
            .map_err(err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(err)
    }

    fn changes(&self, since: u64, limit: usize) -> Result<(u64, Vec<String>), StoreError> {
        let c = self.conn()?;
        let since = i64::try_from(since).unwrap_or(i64::MAX);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut st = c
            .prepare("SELECT account, changed FROM identities WHERE changed > ?1 ORDER BY changed LIMIT ?2")
            .map_err(err)?;
        let rows = st
            .query_map(params![since, limit], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(err)?;
        let mut cursor = since;
        let mut out = Vec::new();
        for row in rows {
            let (account, changed) = row.map_err(err)?;
            cursor = cursor.max(changed);
            out.push(account);
        }
        Ok((u64::try_from(cursor).unwrap_or(0), out))
    }
}

impl ChallengeStore for Db {
    fn put(&self, nonce: [u8; 32], issued: Issued) -> Result<(), StoreError> {
        let c = self.conn()?;
        // Anyone may request a challenge, so expired ones are dropped on every insert. A challenge lives 60 s, so
        // `issued.expires - 60` is the current time.
        c.execute(
            "DELETE FROM challenges WHERE expires < ?1",
            params![issued.expires - 60 - CHALLENGE_GRACE],
        )
        .map_err(err)?;
        c.execute(
            "INSERT OR REPLACE INTO challenges (nonce, account, purpose, expires) VALUES (?1, ?2, ?3, ?4)",
            params![&nonce[..], issued.account, issued.purpose.as_str(), issued.expires],
        )
        .map_err(err)?;
        Ok(())
    }

    fn take(&self, nonce: &[u8; 32]) -> Result<Option<Issued>, StoreError> {
        let c = self.conn()?;
        let row = c
            .query_row(
                "DELETE FROM challenges WHERE nonce = ?1 RETURNING account, purpose, expires",
                params![&nonce[..]],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()
            .map_err(err)?;
        row.map(|(account, purpose, expires)| {
            Ok(Issued {
                account,
                purpose: Purpose::parse(&purpose).map_err(|e| StoreError(format!("corrupt row: {e}")))?,
                expires,
            })
        })
        .transpose()
    }
}

impl SessionStore for Db {
    fn put(&self, token_hash: [u8; 32], session: Session) -> Result<(), StoreError> {
        let c = self.conn()?;
        c.execute(
            "INSERT OR REPLACE INTO sessions (token_hash, account, instance, last_used) VALUES (?1, ?2, ?3, ?4)",
            params![
                &token_hash[..],
                session.account,
                &session.instance[..],
                session.last_used
            ],
        )
        .map_err(err)?;
        Ok(())
    }

    fn get(&self, token_hash: &[u8; 32]) -> Result<Option<Session>, StoreError> {
        let c = self.conn()?;
        let row = c
            .query_row(
                "SELECT account, instance, last_used FROM sessions WHERE token_hash = ?1",
                params![&token_hash[..]],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()
            .map_err(err)?;
        row.map(|(account, instance, last_used)| {
            let instance: [u8; 32] = instance
                .try_into()
                .map_err(|_| StoreError("corrupt row: instance".into()))?;
            Ok(Session {
                account,
                instance,
                last_used,
            })
        })
        .transpose()
    }

    fn touch(&self, token_hash: &[u8; 32], now: i64) -> Result<(), StoreError> {
        self.conn()?
            .execute(
                "UPDATE sessions SET last_used = ?1 WHERE token_hash = ?2",
                params![now, &token_hash[..]],
            )
            .map_err(err)?;
        Ok(())
    }

    fn remove(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        self.conn()?
            .execute("DELETE FROM sessions WHERE token_hash = ?1", params![&token_hash[..]])
            .map_err(err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rootcard::id::inception;
    use rootcard::log::{VerifyOptions, verify_log};
    use rootcard::recovery::derive_recovery_keys;

    fn identity(seed: u8, username: &str) -> Stored {
        let keys = derive_recovery_keys(&[seed; 32], "global", username);
        let inc = Value::Object(inception(&keys, "global", username).expect("inception"));
        let options = VerifyOptions {
            realms: vec!["global".into()],
            now: None,
        };
        let state = verify_log(std::slice::from_ref(&inc), &options).expect("log");
        Stored {
            events: vec![inc],
            state,
            vault: None,
            public: None,
        }
    }

    #[test]
    fn identities() {
        let db = Db::memory().expect("db");
        let a = identity(1, "Astra");
        let account = a.state.account.clone();
        assert_eq!(db.insert(&a, true).expect("insert"), Insert::Done);
        assert_eq!(db.insert(&a, true).expect("insert"), Insert::Exists);
        assert_eq!(db.load(&account).expect("load"), Some(a.clone()));
        assert_eq!(db.load("nobody").expect("load"), None);
        let key = HandleKey::of(&a.state);
        assert_eq!(db.by_handle(&key).expect("by handle"), vec![account.clone()]);

        // Compare-and-swap: only against the stored values ([HST-19]).
        let mut b = a.clone();
        b.public = Some(Value::Object(rootcard::json::Map::new().with("rev", 1i64)));
        assert!(db.swap(&account, &a.expected(), &b).expect("swap"));
        assert!(!db.swap(&account, &a.expected(), &b).expect("stale swap"));
        assert_eq!(db.load(&account).expect("load"), Some(b.clone()));

        let other = identity(2, "Bob");
        assert_eq!(db.insert(&other, false).expect("insert"), Insert::Done);
        let (cursor, changed) = db.changes(0, 10).expect("changes");
        assert_eq!(changed, vec![account.clone(), other.state.account.clone()]);
        assert_eq!(db.changes(cursor, 10).expect("changes").1, Vec::<String>::new());
    }

    #[test]
    fn challenges_are_taken_once() {
        let db = Db::memory().expect("db");
        let issued = Issued {
            account: "A".into(),
            purpose: Purpose::Login,
            expires: 1000,
        };
        ChallengeStore::put(&db, [1; 32], issued.clone()).expect("put");
        assert_eq!(db.take(&[1; 32]).expect("take"), Some(issued));
        assert_eq!(db.take(&[1; 32]).expect("take"), None);
        // Expired challenges are dropped when new ones arrive.
        let old = Issued {
            account: "A".into(),
            purpose: Purpose::Fetch,
            expires: 100,
        };
        ChallengeStore::put(&db, [2; 32], old).expect("put");
        let new = Issued {
            account: "A".into(),
            purpose: Purpose::Fetch,
            expires: 1000,
        };
        ChallengeStore::put(&db, [3; 32], new).expect("put");
        assert_eq!(db.take(&[2; 32]).expect("take"), None);
    }

    #[test]
    fn sessions() {
        let db = Db::memory().expect("db");
        let s = Session {
            account: "A".into(),
            instance: [9; 32],
            last_used: 10,
        };
        SessionStore::put(&db, [4; 32], s.clone()).expect("put");
        db.touch(&[4; 32], 20).expect("touch");
        assert_eq!(db.get(&[4; 32]).expect("get").map(|s| s.last_used), Some(20));
        db.sweep(20 + rootcard_host::SESSION_IDLE + 1).expect("sweep");
        assert_eq!(db.get(&[4; 32]).expect("get"), None);
        SessionStore::put(&db, [5; 32], s).expect("put");
        db.remove(&[5; 32]).expect("remove");
        assert_eq!(db.get(&[5; 32]).expect("get"), None);
    }
}
