//! SQLite: every envelope this node holds (as JSON, keyed by envelope id), the decrypted header + text when this node
//! can read it, a local integer id per envelope (the compat API's message number), and the compat API's bookkeeping
//! (names seen, MCPL push cursors).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use mailcore::addr::norm;
use mailcore::{Envelope, Verified};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde_json::json;

pub const PAGE: i64 = 1000;
pub const PAGE_CHARS: usize = 4_000_000;
pub const MAX_TEXT: i64 = 100_000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  env_id TEXT NOT NULL UNIQUE,
  day TEXT NOT NULL,
  ts TEXT NOT NULL,
  sender TEXT NOT NULL,
  sender_sub TEXT NOT NULL,
  recipient TEXT NOT NULL,
  thread TEXT NOT NULL,
  mode TEXT NOT NULL,
  text TEXT,
  files TEXT NOT NULL DEFAULT '[]',
  readers TEXT,
  verified INTEGER NOT NULL DEFAULT 1,
  imported INTEGER,
  parents TEXT NOT NULL,
  env TEXT NOT NULL,
  received INTEGER NOT NULL,
  attest TEXT NOT NULL DEFAULT 'token',
  blobs TEXT NOT NULL DEFAULT '[]');
CREATE INDEX IF NOT EXISTS messages_thread ON messages (thread, id);
CREATE INDEX IF NOT EXISTS messages_imported ON messages (imported);
CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS uploads (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL,
  size INTEGER NOT NULL, key TEXT NOT NULL, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_day ON messages (day, env_id);
CREATE INDEX IF NOT EXISTS messages_sender ON messages (sender_sub, ts);
CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY, sub TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursors (sub TEXT PRIMARY KEY, last_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS used_tokens (name TEXT NOT NULL, jti TEXT NOT NULL, exp INTEGER NOT NULL,
  PRIMARY KEY (name, jti));
CREATE INDEX IF NOT EXISTS used_tokens_exp ON used_tokens (exp);
";

/// What a reader sees of a row it may read; `text` is None only for rows this node cannot decrypt (never shown).
#[derive(Clone, Debug)]
pub struct Row {
    pub id: i64,
    pub env_id: String,
    pub ts: String,
    pub sender: String,
    pub sender_sub: String,
    pub recipient: String,
    pub thread: String,
    pub mode: String,
    pub text: Option<String>,
    pub len: i64,
    pub files: String,
    pub readers: Option<String>,
    pub verified: bool,
    pub imported: Option<i64>,
    pub parents: Vec<String>,
    pub attest: String,
}

/// Attachment metadata as clients see it (the blob key never leaves the node).
pub fn public_files(files: &str) -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_str(files).unwrap_or(json!([]));
    if let Some(a) = v.as_array_mut() {
        for f in a {
            if let Some(o) = f.as_object_mut() {
                o.remove("key");
            }
        }
    }
    v
}

impl Row {
    /// Members mode: any caller with a valid token (as on the old server). Private: the sender and the members it was
    /// addressed to, and only if this node could decrypt it.
    pub fn visible_to(&self, viewer: &str) -> bool {
        self.text.is_some()
            && (self.mode == "members"
                || self.readers.as_deref().is_some_and(|r| r.contains(&format!(",{},", norm(viewer)))))
    }

    pub fn to_message(&self) -> serde_json::Value {
        let text = self.text.clone().unwrap_or_default();
        let shown = text.chars().count() as i64;
        let mut m = json!({
            "id": self.id, "ts": self.ts, "from": self.sender, "to": self.recipient, "thread": self.thread,
            "text": text, "files": public_files(&self.files),
            "len": self.len, "sub": self.sender_sub, "verified": self.verified,
            "env": self.env_id, "mode": self.mode, "attest": self.attest,
        });
        if self.len > shown {
            m["truncated"] = json!(self.len);
        }
        if let Some(old) = self.imported {
            m["imported"] = json!(old);
        }
        m
    }
}

#[derive(Default, Debug, Clone)]
pub struct Query {
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub latest: Option<i64>,
    pub limit: Option<i64>,
    pub thread: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub q: Option<String>,
}

pub struct Store {
    db: Mutex<Connection>,
}

const COLS: &str = "id, env_id, ts, sender, sender_sub, recipient, thread, mode, substr(text, 1, ?) AS text, \
                    length(text) AS len, files, readers, verified, imported, parents, attest";

fn visible_sql() -> &'static str {
    "(text IS NOT NULL AND (mode = 'members' OR instr(readers, ?) > 0))"
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let parents: String = r.get(14)?;
    Ok(Row {
        id: r.get(0)?,
        env_id: r.get(1)?,
        ts: r.get(2)?,
        sender: r.get(3)?,
        sender_sub: r.get(4)?,
        recipient: r.get(5)?,
        thread: r.get(6)?,
        mode: r.get(7)?,
        text: r.get(8)?,
        len: r.get::<_, Option<i64>>(9)?.unwrap_or(0),
        files: r.get(10)?,
        readers: r.get(11)?,
        verified: r.get::<_, i64>(12)? != 0,
        imported: r.get(13)?,
        parents: serde_json::from_str(&parents).unwrap_or_default(),
        attest: r.get(15)?,
    })
}

fn like_prefix(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let db = Connection::open(path)?;
        // The store holds the plaintext of everything this node can read (private mail included), attachment keys and
        // the bearer tokens inside token-attested envelopes: readable by this user only, whatever the umask. SQLite
        // gives its -wal/-shm files the database's mode; older ones are fixed here too.
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let mut p = path.as_os_str().to_owned();
                p.push(suffix);
                if std::path::Path::new(&p).exists() {
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        db.execute_batch(SCHEMA)?;
        // agent_sig: the sender's signature of an agent-signed message, on the first copy this node stored. A member
        // node can read members-mode mail, so it can re-encrypt someone's signed message into a new envelope (new id,
        // same signature): such a replay is kept hidden (mode 'dup', no text) so day hashes still agree between nodes.
        let has_sig_col =
            db.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = 'agent_sig'")?.exists([])?;
        if !has_sig_col {
            db.execute_batch("ALTER TABLE messages ADD COLUMN agent_sig TEXT;")?;
        }
        db.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS messages_agent_sig ON messages (agent_sig) WHERE agent_sig IS NOT NULL;",
        )?;
        if !has_sig_col {
            db.execute_batch(
                "UPDATE OR IGNORE messages SET agent_sig = json_extract(env, '$.attest.sig') \
                 WHERE json_extract(env, '$.attest.kind') = 'agent';",
            )?;
        }
        Ok(Store { db: Mutex::new(db) })
    }

    pub fn has(&self, env_id: &str) -> Result<bool> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT 1 FROM messages WHERE env_id = ?", [env_id], |_| Ok(())).optional()?.is_some())
    }

    /// The visible row of an agent-signed message, by its sender signature (canonical base64url).
    pub fn by_agent_sig(&self, sig: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db
            .query_row(&format!("SELECT {COLS} FROM messages WHERE agent_sig = ?"), params![MAX_TEXT, sig], read_row)
            .optional()?)
    }

    /// Stores a verified envelope. Returns None if it was already here (the envelope id is the dedupe key), or if it
    /// is another envelope carrying an agent-signed message already here (stored hidden, see agent_sig).
    /// `files`: the body's attachment list as JSON (with blob keys; "[]" when unreadable). `id_floor`: new
    /// non-imported mail is numbered from here up, so the old server's numbers below it stay free for imports.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        env: &Envelope,
        v: &Verified,
        text: Option<&str>,
        files: &str,
        readers: Option<&str>,
        received_ms: i64,
        id_floor: i64,
    ) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        let json = serde_json::to_string(env)?;
        let parents = serde_json::to_string(&env.parents)?;
        let max: i64 = db.query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |r| r.get(0))?;
        // Imported history keeps its old number when that number is still above every local number (the import runs
        // in old-id order before the node takes new mail). Numbers only grow in arrival order, because clients' `after`
        // cursors, SSE and MCPL push depend on it: old mail the bridge copies in after new mail exists gets a new number
        // (its old one stays in `imported`).
        // Only numbers in the range the old server can have used, and on a node with an id_floor only numbers below it
        // (the floor reserves them for imports): an import can never move numbering past new mail or near i64::MAX.
        let explicit = match v.imported {
            Some(old)
                if old > 0
                    && old <= mailcore::envelope::MAX_OLD_ID
                    && old as i64 > max
                    && (id_floor <= 1 || (old as i64) < id_floor) =>
            {
                Some(old as i64)
            }
            _ => None,
        };
        let explicit = match explicit {
            Some(x) => Some(x),
            None if v.imported.is_none() && max < id_floor => Some(id_floor),
            None => None, // AUTOINCREMENT: above the highest id ever used
        };
        let agent_sig = match &env.attest {
            mailcore::Attest::Agent { sig, .. } => mailcore::b64u_decode(sig).map(|b| mailcore::b64u(&b)),
            _ => None,
        };
        let replay = match &agent_sig {
            Some(sig) => db.query_row("SELECT 1 FROM messages WHERE agent_sig = ?", [sig], |_| Ok(())).optional()?.is_some(),
            None => false,
        };
        let n = db.execute(
            "INSERT OR IGNORE INTO messages (id, env_id, day, ts, sender, sender_sub, recipient, thread, mode, text, \
             readers, verified, imported, parents, env, received, attest, blobs, files, agent_sig) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                if replay { None } else { explicit },
                env.id,
                env.day(),
                env.ts,
                env.from,
                v.sender_sub,
                env.to,
                env.thread,
                if replay { "dup" } else { env.mode.as_str() },
                if replay { None } else { text },
                if replay { None } else { readers },
                v.verified as i64,
                v.imported.map(|x| x as i64),
                parents,
                json,
                received_ms,
                v.attest,
                serde_json::to_string(&env.blobs)?,
                if replay { "[]" } else { files },
                if replay { None } else { agent_sig }
            ],
        )?;
        if n == 0 || replay {
            return Ok(None);
        }
        let row = db.query_row(
            &format!("SELECT {COLS} FROM messages WHERE env_id = ?"),
            params![MAX_TEXT, env.id],
            read_row,
        )?;
        Ok(Some(row))
    }

    pub fn last_id(&self) -> Result<i64> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |r| r.get(0))?)
    }

    /// One message by local number, else by its old-server number: an import that reached this node after newer mail
    /// got a new local number (see insert), but agents still cite the old server's.
    pub fn get(&self, id: i64, viewer: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        let mut row = db
            .query_row(&format!("SELECT {COLS} FROM messages WHERE id = ?"), params![MAX_TEXT, id], read_row)
            .optional()?;
        if row.is_none() {
            row = db
                .query_row(&format!("SELECT {COLS} FROM messages WHERE imported = ? LIMIT 1"), params![MAX_TEXT, id], read_row)
                .optional()?;
        }
        Ok(row.filter(|r| r.visible_to(viewer)))
    }

    /// The old server's query(): rows in local-id order, at most `limit` (1000) or PAGE_CHARS of text.
    pub fn query(&self, q: &Query, viewer: &str, text_cap: i64) -> Result<(Vec<Row>, bool)> {
        let mut wh = vec![visible_sql().to_string()];
        let mut args: Vec<Value> = vec![Value::Integer(text_cap), Value::Text(format!(",{},", norm(viewer)))];
        if let Some(a) = q.after {
            wh.push("id > ?".into());
            args.push(Value::Integer(a));
        }
        if let Some(b) = q.before {
            wh.push("id < ?".into());
            args.push(Value::Integer(b));
        }
        if let Some(t) = &q.thread {
            wh.push("thread = ?".into());
            args.push(Value::Text(t.clone()));
        }
        if let Some(f) = &q.from {
            wh.push("sender LIKE ? ESCAPE '\\'".into());
            args.push(Value::Text(like_prefix(f)));
        }
        if let Some(t) = &q.to {
            wh.push("recipient LIKE ? ESCAPE '\\'".into());
            args.push(Value::Text(like_prefix(t)));
        }
        if let Some(s) = &q.q {
            wh.push("instr(lower(text), lower(?)) > 0".into());
            args.push(Value::Text(s.clone()));
        }
        let limit = q.latest.or(q.limit).unwrap_or(PAGE).min(PAGE);
        args.push(Value::Integer(limit));
        let sql = format!(
            "SELECT {COLS} FROM messages WHERE {} ORDER BY id {} LIMIT ?",
            wh.join(" AND "),
            if q.latest.is_some() { "DESC" } else { "ASC" }
        );
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&sql)?;
        let mut rows = Vec::new();
        let mut chars = 0usize;
        let mut more = false;
        for r in st.query_map(params_from_iter(args), read_row)? {
            let r = r?;
            chars += r.text.as_deref().map_or(0, |t| t.len()) + 200;
            if !rows.is_empty() && chars > PAGE_CHARS {
                more = true;
                break;
            }
            rows.push(r);
        }
        if rows.len() as i64 == limit {
            more = true;
        }
        if q.latest.is_some() {
            rows.reverse();
        }
        Ok((rows, more))
    }

    /// A page of rows in (lo, hi) whose recipient contains one of `needles` (a prefilter for addressedTo), not sent by
    /// any of `subs`. Used by the inbox tool and MCPL backlog.
    pub fn addressed_page(
        &self,
        viewer: &str,
        lo: i64,
        hi: i64,
        subs: &[String],
        needles: &[String],
        ascending: bool,
        text_cap: i64,
    ) -> Result<Vec<Row>> {
        let mut args: Vec<Value> = vec![Value::Integer(text_cap), Value::Text(format!(",{},", norm(viewer)))];
        args.push(Value::Integer(lo));
        args.push(Value::Integer(hi));
        let subs_sql = vec!["?"; subs.len().max(1)].join(", ");
        if subs.is_empty() {
            args.push(Value::Text(String::new()));
        }
        args.extend(subs.iter().map(|s| Value::Text(s.clone())));
        let needle_sql = needles
            .iter()
            .map(|_| "instr(replace(lower(recipient), '/', '.'), ?) > 0")
            .collect::<Vec<_>>()
            .join(" OR ");
        args.extend(needles.iter().map(|s| Value::Text(s.clone())));
        let sql = format!(
            "SELECT {COLS} FROM messages WHERE {} AND id > ? AND id < ? AND sender_sub NOT IN ({subs_sql}) AND ({needle_sql}) \
             ORDER BY id {} LIMIT 500",
            visible_sql(),
            if ascending { "ASC" } else { "DESC" }
        );
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&sql)?;
        let rows = st.query_map(params_from_iter(args), read_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn thread_rows(&self, viewer: &str, limit: i64) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(&format!(
            "SELECT m.thread, t.n, m.id, m.ts, m.sender, m.recipient, substr(m.text, 1, 300) AS snippet
             FROM (SELECT thread, COUNT(*) AS n, MAX(id) AS last FROM messages WHERE {} GROUP BY thread) t
             JOIN messages m ON m.id = t.last ORDER BY m.id DESC LIMIT ?",
            visible_sql()
        ))?;
        let rows = st
            .query_map(params![format!(",{},", norm(viewer)), limit], |r| {
                Ok(json!({
                    "thread": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)?, "id": r.get::<_, i64>(2)?,
                    "ts": r.get::<_, String>(3)?, "sender": r.get::<_, String>(4)?,
                    "recipient": r.get::<_, String>(5)?, "snippet": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// All rows of a thread the viewer may read, in the causal thread order every node agrees on.
    pub fn thread_causal(&self, thread: &str, viewer: &str, text_cap: i64) -> Result<Vec<Row>> {
        let rows: Vec<Row> = {
            let db = self.db.lock().unwrap();
            let mut st = db.prepare(&format!("SELECT {COLS} FROM messages WHERE thread = ?"))?;
            let r = st.query_map(params![text_cap, thread], read_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            r
        };
        let items: Vec<mailcore::order::Item> = rows
            .iter()
            .map(|r| mailcore::order::Item { id: &r.env_id, ts: &r.ts, parents: &r.parents })
            .collect();
        let order = mailcore::order::thread_order(&items);
        Ok(order.into_iter().map(|i| rows[i].clone()).filter(|r| r.visible_to(viewer)).collect())
    }

    /// Thread heads: envelopes of the thread no other envelope of it names as a parent (latest 16 by ts).
    pub fn heads(&self, thread: &str) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id, ts, parents FROM messages WHERE thread = ?")?;
        let rows: Vec<(String, String, String)> =
            st.query_map([thread], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut referenced = HashSet::new();
        for (_, _, p) in &rows {
            for id in serde_json::from_str::<Vec<String>>(p).unwrap_or_default() {
                referenced.insert(id);
            }
        }
        let mut heads: Vec<(String, String)> =
            rows.into_iter().filter(|(id, _, _)| !referenced.contains(id)).map(|(id, ts, _)| (ts, id)).collect();
        heads.sort();
        heads.reverse();
        heads.truncate(mailcore::envelope::MAX_PARENTS);
        let mut ids: Vec<String> = heads.into_iter().map(|(_, id)| id).collect();
        ids.sort();
        Ok(ids)
    }

    /// Anti-entropy: BLAKE3 over the sorted envelope ids of each day (the day is the envelope's ts date).
    pub fn day_hashes(&self) -> Result<BTreeMap<String, String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT day, env_id FROM messages ORDER BY day, env_id")?;
        let mut out = BTreeMap::new();
        let mut cur: Option<(String, blake3::Hasher, u64)> = None;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let day: String = r.get(0)?;
            let id: String = r.get(1)?;
            if cur.as_ref().map(|c| &c.0) != Some(&day) {
                if let Some((d, h, n)) = cur.take() {
                    out.insert(d, format!("{n}:{}", h.finalize().to_hex()));
                }
                cur = Some((day.clone(), blake3::Hasher::new(), 0));
            }
            let c = cur.as_mut().unwrap();
            c.1.update(id.as_bytes());
            c.1.update(b"\n");
            c.2 += 1;
        }
        if let Some((d, h, n)) = cur {
            out.insert(d, format!("{n}:{}", h.finalize().to_hex()));
        }
        Ok(out)
    }

    pub fn ids_for_day(&self, day: &str) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id FROM messages WHERE day = ? ORDER BY env_id")?;
        let ids = st.query_map([day], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }

    pub fn envelopes(&self, ids: &[String]) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env FROM messages WHERE env_id = ?")?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(e) = st.query_row([id], |r| r.get::<_, String>(0)).optional()? {
                out.push(e);
            }
        }
        Ok(out)
    }

    /// The same sender's identical message within the repeat window (a client resending after a dropped answer).
    pub fn repeat(&self, sub: &str, since_ts: &str, to: &str, thread: &str, text: &str) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db
            .query_row(
                &format!(
                    "SELECT {COLS} FROM messages WHERE sender_sub = ? AND ts > ? AND recipient = ? AND thread = ? \
                     AND text = ? AND files = '[]' ORDER BY id DESC LIMIT 1"
                ),
                params![MAX_TEXT, sub, since_ts, to, thread, text],
                read_row,
            )
            .optional()?)
    }

    /// Records an agent token's jti as used. Ok(false): it was used before (a replay). Rows are kept until the token
    /// expires (plus the clock skew), so the check survives a restart; expired rows are dropped as new ones come in.
    pub fn use_token(&self, name: &str, jti: &str, exp_ms: i64, now_ms: i64) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let fresh = db.execute(
            "INSERT OR IGNORE INTO used_tokens (name, jti, exp) VALUES (?, ?, ?)",
            params![norm(name), jti, exp_ms + mailcore::agent_token::SKEW_S * 1000],
        )? == 1;
        if fresh && db.last_insert_rowid() % 256 == 0 {
            db.execute("DELETE FROM used_tokens WHERE exp < ?", params![now_ms])?;
        }
        Ok(fresh)
    }

    pub fn seen(&self, name: &str, sub: &str, at_ms: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO names (name, sub, seen) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET \
             sub = excluded.sub, seen = MAX(seen, excluded.seen)",
            params![name.chars().take(120).collect::<String>(), sub, at_ms],
        )?;
        Ok(())
    }

    /// Every sender already in the store becomes a known name (imports included), for stores written before imports
    /// were recorded. Members keep their sub; only `seen` moves forward.
    pub fn names_from_messages(&self) -> Result<usize> {
        let db = self.db.lock().unwrap();
        Ok(db.execute(
            "INSERT INTO names (name, sub, seen) SELECT sender, sender_sub, MAX(received) FROM messages \
             WHERE sender != '' AND sender_sub != '' GROUP BY sender \
             ON CONFLICT(name) DO UPDATE SET seen = MAX(seen, excluded.seen)",
            [],
        )?)
    }

    /// (name, sub, seen ms), most recently active first.
    pub fn names(&self, limit: i64) -> Result<Vec<(String, String, i64)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT name, sub, seen FROM names ORDER BY seen DESC LIMIT ?")?;
        let rows = st.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn cursor(&self, sub: &str) -> Result<Option<i64>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT last_id FROM cursors WHERE sub = ?", [sub], |r| r.get(0)).optional()?)
    }

    pub fn advance_cursor(&self, sub: &str, id: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO cursors (sub, last_id) VALUES (?, ?) ON CONFLICT(sub) DO UPDATE SET \
             last_id = MAX(last_id, excluded.last_id)",
            params![sub, id],
        )?;
        Ok(())
    }

    /// The row an old-server message was imported as, if any.
    pub fn by_imported(&self, old_id: i64) -> Result<Option<Row>> {
        let db = self.db.lock().unwrap();
        Ok(db
            .query_row(&format!("SELECT {COLS} FROM messages WHERE imported = ? LIMIT 1"), params![MAX_TEXT, old_id], read_row)
            .optional()?)
    }

    /* Attachments */

    pub fn put_blob(&self, id: &str, data: &[u8], now_ms: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO blobs (id, data, size, created) VALUES (?, ?, ?, ?)",
            params![id, data, data.len() as i64, now_ms],
        )?;
        Ok(())
    }

    pub fn get_blob(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT data FROM blobs WHERE id = ?", [id], |r| r.get(0)).optional()?)
    }

    /// Blob ids some stored envelope references that this node does not hold yet.
    /// Members-mode envelopes stored without a readable body (written before this node was on the member list).
    pub fn unreadable(&self, limit: usize) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT env_id FROM messages WHERE text IS NULL AND mode = 'members' ORDER BY id LIMIT ?")?;
        let out = st.query_map([limit as i64], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(out)
    }

    /// Fills in the body of a row stored unreadable (after a grant). False if it already had one.
    pub fn set_body(&self, env_id: &str, text: &str, files: &str) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let n = db.execute("UPDATE messages SET text = ?, files = ? WHERE env_id = ? AND text IS NULL", (text, files, env_id))?;
        Ok(n > 0)
    }

    pub fn missing_blobs(&self) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT blobs FROM messages WHERE blobs != '[]'")?;
        let lists: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        let mut have = db.prepare("SELECT 1 FROM blobs WHERE id = ?")?;
        let mut out = Vec::new();
        for l in lists {
            for id in serde_json::from_str::<Vec<String>>(&l).unwrap_or_default() {
                if have.query_row([&id], |_| Ok(())).optional()?.is_none() && !out.contains(&id) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_upload(&self, id: &str, owner: &str, name: &str, ty: &str, size: i64, key: &str, now_ms: i64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT OR REPLACE INTO uploads (id, owner, name, type, size, key, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, owner, name, ty, size, key, now_ms],
        )?;
        Ok(())
    }

    pub fn uploaded_bytes(&self, owner: &str) -> Result<i64> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT COALESCE(SUM(size), 0) FROM uploads WHERE owner = ?", [owner], |r| r.get(0))?)
    }

    /// File references {id, name, type, size, key} the viewer may use: its own upload first, then the attachments with
    /// this id of messages it can read, oldest first. Several messages can name one blob, and a member node can write
    /// one naming someone else's blob with a wrong key, so callers use the first whose key opens the blob.
    pub fn find_files(&self, id: &str, viewer: &str, viewer_sub: &str) -> Result<Vec<serde_json::Value>> {
        let db = self.db.lock().unwrap();
        let mut out = Vec::new();
        let up = db
            .query_row(
                "SELECT name, type, size, key FROM uploads WHERE id = ? AND owner = ?",
                [id, viewer_sub],
                |r| {
                    Ok(json!({ "id": id, "name": r.get::<_, String>(0)?, "type": r.get::<_, String>(1)?,
                               "size": r.get::<_, i64>(2)?, "key": r.get::<_, String>(3)? }))
                },
            )
            .optional()?;
        out.extend(up);
        let mut st = db.prepare(&format!(
            "SELECT files FROM messages WHERE instr(blobs, ?) > 0 AND {} ORDER BY id LIMIT 20",
            visible_sql()
        ))?;
        let rows: Vec<String> = st
            .query_map(params![id, format!(",{},", norm(viewer))], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for files in rows {
            let v: serde_json::Value = serde_json::from_str(&files).unwrap_or(json!([]));
            for f in v.as_array().into_iter().flatten() {
                if f["id"] == json!(id) && f.get("key").is_some() && !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<i64> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_an_older_store_adds_and_backfills_agent_sig() {
        let path = std::env::temp_dir().join(format!("mailnode-store-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(SCHEMA).unwrap();
            for (i, id) in ["a", "b"].iter().enumerate() {
                db.execute(
                    "INSERT INTO messages (env_id, day, ts, sender, sender_sub, recipient, thread, mode, text, parents, env, received) \
                     VALUES (?, 'd', 't', 's', 'ss', 'all', 't', 'members', 'x', '[]', ?, ?)",
                    params![id, r#"{"attest":{"kind":"agent","sig":"SIG"}}"#, i as i64],
                )
                .unwrap();
            }
        }
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let store = Store::open(&path).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let row = store.by_agent_sig("SIG").unwrap().expect("backfilled");
        assert_eq!(row.env_id, "a", "an existing duplicate keeps only the first copy indexed");
        drop(store);
        Store::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
    }
}
