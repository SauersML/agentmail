//! The node's mail logic, shared by the compat API, MCPL and replication: accept a local send (seal, sign, store,
//! announce), accept a replicated envelope (verify, decrypt if we can, store), and the old server's read-side rules
//! (names, reaches, addressed rows, message formatting).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use mailcore::addr::{self, addressed_to, is_broadcast, norm};
use mailcore::envelope::{Draft, Grant};
use mailcore::keys::Seed;
use mailcore::{now_millis, now_ts, ts_from_millis, Attest, Body, Envelope, MemberList, Mode};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use unicode_normalization::UnicodeNormalization;

use crate::config::Renamed;
use crate::store::{Row, Store, MAX_TEXT};

pub const MAX_FIELD: usize = 120;
const REPEAT_MS: i64 = 10 * 60 * 1000;
const RATE_WINDOW_MS: i64 = 3_600_000;
const SCAN_ROWS: usize = 50_000;

/// An HTTP-style error: status and message, as the old server's HttpError.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
    pub retry_after: Option<u32>,
}

impl ApiError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        ApiError { status, message: message.into(), retry_after: None }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("{e:#}");
        ApiError::new(500, "server error")
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::from(anyhow::Error::from(e))
    }
}

/// Whoever presented a valid token.
#[derive(Clone, Debug)]
pub struct Caller {
    pub name: String,
    pub sub: String,
    pub exp_ms: i64,
}

pub struct Posted {
    pub row: Row,
    pub reaches: Vec<String>,
    pub repeated: bool,
}

/// What goes out on the gossip topic from the API side (member lists are announced by the network task).
pub enum Outbound {
    Envelope(Envelope),
}

/// Node settings beyond the store and keys.
#[derive(Default)]
pub struct Opts {
    pub identities: Vec<(String, Seed)>,
    pub renamed: Vec<Renamed>,
    /// Where the latest adopted member list is kept.
    pub members_path: Option<std::path::PathBuf>,
    /// Base URL written into attachment links.
    pub public_url: String,
}

/// A file reference {id, name, type, size, key} and the plaintext, when the blob is on this node.
type FileRef = (Value, Option<Vec<u8>>);

pub const MAX_FILE: usize = 25 * 1024 * 1024;
pub const MAX_FILES: usize = mailcore::envelope::MAX_BLOBS;
const MAX_FILES_PER_SUB: i64 = 1024 * 1024 * 1024;

pub struct Node {
    pub store: Store,
    pub members: RwLock<MemberList>,
    pub operator: mailcore::keys::PublicKey,
    pub seed: Seed,
    pub opts: Opts,
    pub events: broadcast::Sender<Arc<Row>>,
    pub outbound: mpsc::UnboundedSender<Outbound>,
    rates: Mutex<HashMap<(String, &'static str), Vec<i64>>>,
    touched: Mutex<HashMap<String, i64>>,
    auth_seen: Mutex<HashSet<(String, &'static str)>>,
}

impl Node {
    pub fn new(
        store: Store,
        members: MemberList,
        operator: mailcore::keys::PublicKey,
        seed: Seed,
        opts: Opts,
        outbound: mpsc::UnboundedSender<Outbound>,
    ) -> Node {
        let (events, _) = broadcast::channel(4096);
        Node {
            store,
            members: RwLock::new(members),
            operator,
            seed,
            opts,
            events,
            outbound,
            rates: Mutex::new(HashMap::new()),
            touched: Mutex::new(HashMap::new()),
            auth_seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn members_seq(&self) -> u64 {
        self.members.read().unwrap().seq
    }

    /// Adopts `list` if it is signed by the pinned operator, for this network, and newer than ours. Returns whether
    /// it was adopted (the caller re-announces it and updates peers).
    pub fn adopt_members(&self, list: &MemberList) -> Result<bool> {
        list.verify(&self.operator)?;
        let mut cur = self.members.write().unwrap();
        if list.network != cur.network || list.seq <= cur.seq {
            return Ok(false);
        }
        *cur = list.clone();
        drop(cur);
        for m in &list.members {
            let _ = self.store.seen(&m.name, &m.sub, 0);
        }
        if let Some(p) = &self.opts.members_path {
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_string_pretty(list)?)?;
            std::fs::rename(&tmp, p)?;
        }
        tracing::info!("adopted member list seq {} ({} members, {} nodes)", list.seq, list.members.len(), list.nodes.len());
        Ok(true)
    }

    /* Identity */

    /// Verify a node-bound, single-use token against the current member key.
    pub fn verify(&self, token: &str) -> Result<Caller, ApiError> {
        let now = now_millis();
        use mailcore::agent_token::Refusal;
        let checked = {
            let members = self.members.read().unwrap();
            mailcore::agent_token::verify(token, &members, &self.seed.public(), now)
        };
        let c = checked.map_err(|r| match r {
            Refusal::NotMember(s) => ApiError::new(403, format!("{s}; ask its operator to add you")),
            Refusal::Bad(s) => ApiError::new(401, format!("token refused: {s}")),
        })?;
        if !self.store.use_token(&c.name, &c.jti, c.exp_ms, now)? {
            return Err(ApiError::new(401, "token refused: already used (agent tokens are single-use; mint a fresh one)"));
        }
        self.note_auth(&c.name, "agent-token");
        self.touch(&c.name, &c.sub);
        Ok(Caller { name: c.name, sub: c.sub, exp_ms: c.exp_ms })
    }

    /// Logs the first sign-in of each name with each kind of token (debug-level for every later one). Never the token.
    fn note_auth(&self, name: &str, auth: &'static str) {
        let mut seen = self.auth_seen.lock().unwrap();
        if seen.len() < 10_000 && seen.insert((norm(name), auth)) {
            tracing::info!("{name:?} signed in with an {auth} token");
        } else {
            tracing::debug!("{name:?} used an {auth} token");
        }
    }

    /// seen() at most once an hour per name, so reading the mailbox also makes a name known.
    pub fn touch(&self, name: &str, sub: &str) {
        let key = format!("{name}\u{0}{sub}");
        let now = now_millis();
        let mut t = self.touched.lock().unwrap();
        if t.get(&key).is_some_and(|&x| x > now - 3_600_000) {
            return;
        }
        if t.len() > 10_000 {
            t.clear();
        }
        t.insert(key, now);
        drop(t);
        let _ = self.store.seen(name, sub, now);
    }

    fn rate(&self, sub: &str, kind: &'static str, max: usize) -> Result<(), ApiError> {
        let now = now_millis();
        let mut r = self.rates.lock().unwrap();
        let v = r.entry((sub.to_string(), kind)).or_default();
        v.retain(|&t| t > now - RATE_WINDOW_MS);
        if v.len() >= max {
            return Err(ApiError {
                status: 429,
                message: format!("rate limit: at most {max} {kind} per hour per sender"),
                retry_after: Some(600),
            });
        }
        v.push(now);
        Ok(())
    }

    /* Writing */

    pub fn post(&self, who: &Caller, body: &Value) -> Result<Posted, ApiError> {
        let bad_files = || ApiError::new(400, format!("files must be a list of at most {MAX_FILES} file ids from POST /api/files"));
        let file_ids: Vec<String> = match body.get("files") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) if a.len() <= MAX_FILES => {
                a.iter().map(|x| x.as_str().map(|s| s.to_string()).ok_or_else(bad_files)).collect::<Result<_, _>>()?
            }
            _ => return Err(bad_files()),
        };
        let mut files = Vec::new();
        for id in &file_ids {
            let f = self
                .usable_file(id, who)?
                .map(|(f, _)| f)
                .ok_or_else(|| ApiError::new(400, format!("unknown file id {}", id.chars().take(40).collect::<String>())))?;
            files.push(f);
        }
        let to_v = body.get("to");
        if to_v.is_none() || to_v == Some(&Value::Null) || to_v == Some(&json!("")) {
            return Err(ApiError::new(
                400,
                "to is required: names (sauersml.glead), a team prefix ending in a dot (will.), or all",
            ));
        }
        let to = field(to_v.unwrap(), "to", valid_to)?;
        let thread = field(body.get("thread").unwrap_or(&json!("general")), "thread", |s| {
            !s.chars().any(|c| c.is_control())
        })?;
        let text = clean_text(body.get("text"), !files.is_empty())?;
        let mode = match body.get("mode").and_then(|m| m.as_str()) {
            None | Some("members") => Mode::Members,
            Some("private") => Mode::Private,
            Some(_) => return Err(ApiError::new(400, "mode must be members or private")),
        };
        let since = ts_from_millis(now_millis() - REPEAT_MS);
        if files.is_empty() {
            if let Some(row) = self.store.repeat(&who.sub, &since, &to, &thread, &text)? {
                if row.mode == mode.as_str() {
                    let reaches = self.reaches(&to, &who.sub)?;
                    return Ok(Posted { row, reaches, repeated: true });
                }
            }
        }
        self.rate(&who.sub, "message", 120)?;
        if is_broadcast(&to) {
            self.rate(&who.sub, "broadcast", 20)?;
        }
        let _ = self.store.seen(&who.name, &who.sub, now_millis());

        let members = self.members.read().unwrap().clone();
        let recipients = match mode {
            Mode::Members => members.all_keys(),
            Mode::Private => {
                let keys = members.private_keys(&to, &who.name);
                let addressed = members.members.iter().any(|m| addressed_to(&to, &[m.name.as_str()]));
                if !addressed {
                    return Err(ApiError::new(400, "private mail goes only to names on the member list; none matches"));
                }
                keys
            }
        };
        // Signed by the sender's own key (islandmail.py sends `signed: {ts, salt, sig}`), or token-attested.
        let (ts, attest, salt) = match body.get("signed").filter(|s| s.is_object()) {
            Some(s) => {
                let raw_thread = body.get("thread").and_then(|t| t.as_str()).unwrap_or("general");
                if body["to"].as_str() != Some(to.as_str())
                    || raw_thread != thread
                    || body["text"].as_str() != Some(text.as_str())
                {
                    return Err(ApiError::new(400, "signed post: to, thread and text must be sent already normalized (NFC, no control or format characters, \\n line ends)"));
                }
                let ts = s["ts"].as_str().unwrap_or("").to_string();
                let t = mailcore::parse_ts(&ts).ok_or_else(|| ApiError::new(400, "signed post: ts must be YYYY-MM-DDTHH:MM:SS.mmmZ"))?;
                if (t - now_millis()).abs() > 300_000 {
                    return Err(ApiError::new(400, "signed post: ts is more than 5 minutes from the node's clock"));
                }
                let salt = s["salt"]
                    .as_str()
                    .and_then(mailcore::b64u_decode)
                    .filter(|b| b.len() == 16)
                    .ok_or_else(|| ApiError::new(400, "signed post: salt must be 16 bytes, base64url"))?;
                let m = members
                    .member_by_name(&who.name)
                    .ok_or_else(|| ApiError::new(403, format!("signed post: {} is not on the member list", who.name)))?;
                let key = mailcore::keys::parse_key(&m.key)?;
                let digest = mailcore::envelope::post_digest(&salt, &text, &file_ids);
                let st = mailcore::envelope::post_statement(&who.name, &to, &thread, mode, &ts, &digest);
                let sig = s["sig"].as_str().unwrap_or("").to_string();
                let ok = mailcore::b64u_decode(&sig).is_some_and(|b| mailcore::keys::verify(&key, st.as_bytes(), &b));
                if !ok {
                    return Err(ApiError::new(401, format!("signed post: signature does not verify against {}'s key on the member list", who.name)));
                }
                // Canonical encoding (the one every node dedupes by); a client resending the same signed post gets
                // the first copy back instead of a second envelope.
                let sig = mailcore::b64u_decode(&sig).map(|b| mailcore::b64u(&b)).unwrap_or(sig);
                if let Some(row) = self.store.by_agent_sig(&sig)? {
                    let reaches = self.reaches(&row.recipient, &who.sub)?;
                    return Ok(Posted { row, reaches, repeated: true });
                }
                (ts, Attest::Agent { key: m.key.clone(), digest, sig }, mailcore::b64u(&salt))
            }
            // The node holds the caller's own agent key (identities_dir) and it is the caller's key on the member list:
            // sign for it, so the envelope carries a signature instead of the caller's bearer token (README.md, Security).
            None => {
                let (key, seed) = self.local_key(&members, who).ok_or_else(|| ApiError::new(400,
                    "sign the post with your agent key or configure identities_dir on this node"))?;
                let salt = mailcore::random_bytes::<16>();
                let ts = now_ts();
                let digest = mailcore::envelope::post_digest(&salt, &text, &file_ids);
                let st = mailcore::envelope::post_statement(&who.name, &to, &thread, mode, &ts, &digest);
                let sig = mailcore::b64u(&seed.sign(st.as_bytes()));
                (ts, Attest::Agent { key, digest, sig }, mailcore::b64u(&salt))
            }
        };
        let parents = self.store.heads(&thread)?;
        let b = Body { text: text.clone(), files: files.clone(), salt };
        let env = Envelope::seal(
            Draft {
                thread: &thread,
                parents,
                ts,
                from: &who.name,
                to: &to,
                mode,
                body: &b,
                blobs: file_ids.clone(),
                attest,
                recipients: &recipients,
            },
            &self.seed,
        )?;
        // Refuse to write what no other node would accept (e.g. this node is not on the member list).
        let v = env
            .verify(&members, now_millis())
            .and_then(|v| env.check_body(&b).map(|_| v))
            .map_err(|e| ApiError::new(503, format!("this node cannot write mail: {e}")))?;
        let readers = (mode == Mode::Private).then(|| readers_for(&members, &to, &who.name));
        let files_json = serde_json::to_string(&files).map_err(anyhow::Error::from)?;
        let row = self
            .store
            .insert(&env, &v, Some(&text), &files_json, readers.as_deref(), now_millis())?
            .ok_or_else(|| ApiError::new(500, "envelope id collision"))?;
        let _ = self.events.send(Arc::new(row.clone()));
        let _ = self.outbound.send(Outbound::Envelope(env));
        let reaches = self.reaches(&to, &who.sub)?;
        Ok(Posted { row, reaches, repeated: false })
    }

    /// The caller's agent key, if this node holds it: an identity named like the caller whose public key is the one
    /// the member list gives that name, with the same sub as the caller's token. (member-list key string, seed)
    fn local_key(&self, members: &MemberList, who: &Caller) -> Option<(String, Seed)> {
        let m = members.member_by_name(&who.name).filter(|m| m.sub == who.sub)?;
        let k = mailcore::keys::parse_key(&m.key).ok()?;
        self.opts
            .identities
            .iter()
            .find(|(n, s)| mailcore::addr::same(n, &who.name) && s.public() == k)
            .map(|(_, s)| (m.key.clone(), s.clone()))
    }

    /// POST /api/files: encrypt and keep the upload until a message attaches it.
    pub fn upload(&self, who: &Caller, name: &str, ty: &str, data: &[u8]) -> Result<Value, ApiError> {
        if data.len() > MAX_FILE {
            return Err(ApiError::new(413, format!("body is over {MAX_FILE} bytes")));
        }
        self.rate(&who.sub, "upload", 60)?;
        if self.store.uploaded_bytes(&who.sub)? + data.len() as i64 > MAX_FILES_PER_SUB {
            return Err(ApiError::new(507, "you have stored the most attachments one sender may"));
        }
        let (blob, key) = mailcore::crypto::seal_blob(data)?;
        let id = blake3::hash(&blob).to_hex().to_string();
        let now = now_millis();
        self.store.put_blob(&id, &blob, now)?;
        self.store.add_upload(&id, &who.sub, name, ty, data.len() as i64, &mailcore::b64u(&key), now)?;
        Ok(json!({ "id": id, "name": name, "type": ty, "size": data.len() }))
    }

    /// The file reference {id, name, type, size, key} for `id` the viewer may use, and the plaintext if the blob is
    /// here: the first reference (own upload, then readable messages, oldest first) whose key opens the blob, so a
    /// message written with a wrong key for someone else's blob cannot shadow the real one.
    fn usable_file(&self, id: &str, who: &Caller) -> Result<Option<FileRef>, ApiError> {
        let refs = self.store.find_files(id, &who.name, &who.sub)?;
        let Some(first) = refs.first().cloned() else { return Ok(None) };
        let Some(blob) = self.store.get_blob(id)? else { return Ok(Some((first, None))) };
        for f in refs {
            let key: Option<[u8; 32]> = f["key"].as_str().and_then(mailcore::b64u_decode).and_then(|k| k.try_into().ok());
            if let Some(Ok(plain)) = key.map(|k| mailcore::crypto::open_blob(&blob, &k)) {
                return Ok(Some((f, Some(plain))));
            }
        }
        Ok(None)
    }

    /// GET /api/files/{id}: (metadata, plaintext) for a viewer allowed to read a message carrying it.
    pub fn download(&self, id: &str, who: &Caller) -> Result<(Value, Vec<u8>), ApiError> {
        match self.usable_file(id, who)? {
            None => Err(ApiError::new(404, "no such file")),
            Some((_, None)) => Err(ApiError::new(404, "that file has not reached this node yet; try again soon")),
            Some((f, Some(plain))) => Ok((f, plain)),
        }
    }

    /// A replicated envelope. Ok(None): already here. Err: refused (bad signature, token, member, shape).
    pub fn ingest(&self, env: Envelope) -> Result<Option<Arc<Row>>> {
        if self.store.has(&env.id)? {
            return Ok(None);
        }
        let members = self.members.read().unwrap().clone();
        let v = env.verify(&members, now_millis())?;
        let mut body = env.open(&self.seed).unwrap_or(None);
        if body.is_none() {
            for (_, s) in &self.opts.identities {
                if let Ok(Some(b)) = env.open(s) {
                    body = Some(b);
                    break;
                }
            }
        }
        if let Some(b) = &body {
            env.check_body(b)?;
        }
        let files_json = body.as_ref().map(|b| serde_json::to_string(&b.files)).transpose()?.unwrap_or_else(|| "[]".into());
        let text: Option<String> = body.map(|b| b.text.chars().take(MAX_TEXT as usize).collect());
        let readers = (env.mode == Mode::Private).then(|| readers_for(&members, &env.to, &env.from));
        let Some(row) =
            self.store.insert(&env, &v, text.as_deref(), &files_json, readers.as_deref(), now_millis())?
        else {
            return Ok(None);
        };
        let _ = self.store.seen(&env.from, &v.sender_sub, env.ts_ms());
        let row = Arc::new(row);
        let _ = self.events.send(row.clone());
        Ok(Some(row))
    }

    /// Grants for a node that joined later: members-mode envelopes only (private mail stays with its recipients), and
    /// only to a node on the current member list.
    pub fn grants_for(&self, ids: &[String], to: &mailcore::keys::PublicKey) -> Result<BTreeMap<String, Grant>> {
        let mut out = BTreeMap::new();
        if !self.members.read().unwrap().is_node(to) {
            return Ok(out);
        }
        for raw in self.store.envelopes(ids)? {
            let env: Envelope = serde_json::from_str(&raw)?;
            if env.mode == Mode::Members {
                if let Ok(Some(g)) = env.grant(&self.seed, to) {
                    out.insert(env.id.clone(), g);
                }
            }
        }
        Ok(out)
    }

    /// Fills in a body this node could not read, from a grant. True if the row is readable now.
    pub fn apply_grant(&self, id: &str, g: &Grant) -> Result<bool> {
        let Some(raw) = self.store.envelopes(&[id.to_string()])?.pop() else { return Ok(false) };
        let env: Envelope = serde_json::from_str(&raw)?;
        let body = env.open_grant(g, &self.seed)?;
        env.check_body(&body)?;
        let text: String = body.text.chars().take(MAX_TEXT as usize).collect();
        self.store.set_body(id, &text, &serde_json::to_string(&body.files)?)
    }

    /* Names */

    fn renames(&self) -> impl Iterator<Item = &Renamed> {
        self.opts.renamed.iter().filter(|r| !r.name.is_empty() && !r.sub.is_empty() && !r.now.is_empty())
    }

    /// The names mail to this agent may be addressed to: its own, and the names it had before a rename.
    pub fn names_of(&self, name: &str, sub: &str) -> Vec<String> {
        let mut v = vec![name.to_string()];
        v.extend(self.renames().filter(|r| r.now_sub == sub && addr::same(&r.now, name)).map(|r| r.name.clone()));
        v
    }

    pub fn subs_of(&self, sub: &str) -> Vec<String> {
        let mut v = vec![sub.to_string()];
        v.extend(self.renames().filter(|r| r.now_sub == sub).map(|r| r.sub.clone()));
        v
    }

    pub fn known_names(&self, limit: i64) -> Result<Vec<(String, String, i64)>> {
        let rows = self.store.names(limit)?;
        let present: std::collections::HashSet<&str> = rows.iter().map(|r| r.1.as_str()).collect();
        let gone: std::collections::HashSet<String> = self
            .renames()
            .filter(|r| present.contains(r.now_sub.as_str()))
            .map(|r| format!("{}\u{0}{}", norm(&r.name), r.sub))
            .collect();
        Ok(rows.iter().filter(|r| !gone.contains(&format!("{}\u{0}{}", norm(&r.0), r.1))).cloned().collect())
    }

    pub fn names_list(&self, prefix: &str) -> Result<Vec<Value>> {
        let p = norm(prefix);
        Ok(self
            .known_names(1000)?
            .into_iter()
            .filter(|r| p.is_empty() || norm(&r.0).starts_with(&p))
            .map(|r| json!({ "name": r.0, "sub": r.1, "last_active": ts_from_millis(r.2) }))
            .collect())
    }

    pub fn reaches(&self, to: &str, sender_sub: &str) -> Result<Vec<String>> {
        let mut out: Vec<String> = self
            .known_names(5000)?
            .into_iter()
            .filter(|r| {
                let names = self.names_of(&r.0, &r.1);
                let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                r.1 != sender_sub && addressed_to(to, &refs)
            })
            .map(|r| r.0)
            .collect();
        out.sort();
        Ok(out)
    }

    /// Mail addressed to `name` with ids in (after, before), not sent by it; newest first unless `ascending`.
    pub fn addressed_rows(
        &self,
        name: &str,
        sub: &str,
        after: i64,
        before: i64,
        limit: usize,
        text_cap: i64,
        ascending: bool,
    ) -> Result<Vec<Row>> {
        let names = self.names_of(name, sub);
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let subs = self.subs_of(sub);
        let mut needles = vec!["all".to_string(), "*".to_string()];
        for n in &names {
            let n = norm(n);
            for (i, c) in n.char_indices() {
                if c == '.' {
                    needles.push(n[..=i].to_string());
                }
            }
            needles.push(n);
        }
        needles.sort();
        needles.dedup();
        let (mut lo, mut hi) = (after, before);
        let mut rows = Vec::new();
        let mut scanned = 0;
        loop {
            let page = self.store.addressed_page(name, lo, hi, &subs, &needles, ascending, text_cap)?;
            if page.is_empty() {
                break;
            }
            let n = page.len();
            let last = page[n - 1].id;
            rows.extend(page.into_iter().filter(|r| addressed_to(&r.recipient, &refs)));
            scanned += n;
            if ascending {
                lo = last;
            } else {
                hi = last;
            }
            if rows.len() >= limit || scanned >= SCAN_ROWS || n < 500 {
                break;
            }
        }
        rows.truncate(limit);
        Ok(rows)
    }
}

/// ",name1,name2," of the member names a private envelope is for: the sender and every member `to` addresses.
pub fn readers_for(members: &MemberList, to: &str, from: &str) -> String {
    let mut names: Vec<String> = members
        .members
        .iter()
        .filter(|m| addressed_to(to, &[m.name.as_str()]))
        .map(|m| norm(&m.name))
        .collect();
    names.push(norm(from));
    names.sort();
    names.dedup();
    format!(",{},", names.join(","))
}

/* Field rules, as the old server */

fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E
        | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0)
}

fn is_bidi(c: char) -> bool {
    matches!(c as u32, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

/// /^[\w*][\w.@/:+#*, -]*$/ with JS's ASCII \w.
fn valid_to(s: &str) -> bool {
    let w = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if w(c) || c == '*' => {}
        _ => return false,
    }
    cs.all(|c| w(c) || ".@/:+#*, -".contains(c))
}

pub fn field(v: &Value, name: &str, ok: impl Fn(&str) -> bool) -> Result<String, ApiError> {
    let s: String = v.as_str().map(|s| s.nfc().filter(|c| !is_format_char(*c)).collect::<String>()).unwrap_or_default();
    let s = s.trim().to_string();
    if s.is_empty() || s.encode_utf16().count() > MAX_FIELD || !ok(&s) {
        return Err(ApiError::new(400, format!("{name} must be 1-{MAX_FIELD} characters, like sauersml.glead or will.")));
    }
    Ok(s)
}

/// The old server's fileName(): the last path segment, no format/control characters or quotes, at most 200 chars.
pub fn file_name(raw: Option<&str>) -> String {
    let base = raw.unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = base
        .nfc()
        .filter(|&c| !is_format_char(c) && !(c as u32 <= 0x1F || c as u32 == 0x7F || c == '"'))
        .collect::<String>()
        .trim()
        .chars()
        .take(200)
        .collect();
    if s.is_empty() { "file".into() } else { s }
}

/// The old server's mimeType(): a plain type/subtype or application/octet-stream.
pub fn mime_type(raw: Option<&str>) -> String {
    let t = raw.unwrap_or("").split(';').next().unwrap_or("").trim().to_lowercase();
    let ok_part = |p: &str| {
        let mut cs = p.chars();
        cs.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && cs.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".+-".contains(c))
    };
    match t.split_once('/') {
        Some((a, b)) if ok_part(a) && ok_part(b) => t,
        _ => "application/octet-stream".into(),
    }
}

pub fn clean_text(v: Option<&Value>, allow_empty: bool) -> Result<String, ApiError> {
    let Some(s) = v.and_then(|v| v.as_str()) else { return Err(ApiError::new(400, "text must be a string")) };
    let s: String = s.nfc().collect::<String>().replace("\r\n", "\n").replace('\r', "\n");
    let s: String = s
        .chars()
        .filter(|&c| !matches!(c as u32, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F) && !is_bidi(c))
        .collect();
    if s.encode_utf16().count() > MAX_TEXT as usize {
        return Err(ApiError::new(413, format!("text is over {MAX_TEXT} characters; attach it as a file")));
    }
    if s.trim().is_empty() && !allow_empty {
        return Err(ApiError::new(400, "text is empty"));
    }
    Ok(s)
}

impl Node {
    pub fn fmt(&self, r: &Row, max_text: usize) -> String {
        format_message(r, max_text, &self.opts.public_url)
    }
}

/// Whatever some reader treats as the end of a line: \n, \r, VT, FF, the information separators, NEL, and the Unicode
/// line and paragraph separators.
fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}'..='\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// A header field kept on the header line: line breaks and other control characters become spaces.
fn one_line(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || is_line_break(c) { ' ' } else { c }).collect()
}

/// The old server's formatMessage: one header line the mailbox writes, then the sender's text, every line quoted.
/// Replicated text and header fields come from other nodes unfiltered, so every kind of line break starts a new quoted
/// line and none can appear in the header: a line that does not start with '> ' is always the mailbox's own.
pub fn format_message(r: &Row, max_text: usize, base: &str) -> String {
    let text = r.text.clone().unwrap_or_default();
    let shown: String = text.chars().take(max_text).collect();
    let full = r.len.max(text.chars().count() as i64);
    let shown_n = shown.chars().count() as i64;
    let body = if full > shown_n {
        format!("{shown}\n[… {} more characters; get #{} for all of it]", full - shown_n, r.id)
    } else {
        shown
    };
    let files = crate::store::public_files(&r.files);
    let body = match files.as_array() {
        Some(a) if !a.is_empty() => {
            let list: Vec<String> = a
                .iter()
                .map(|f| {
                    let id = f["id"].as_str().unwrap_or("");
                    let url = format!("{base}/api/files/{id}");
                    format!("{} ({} bytes) {url}", f["name"].as_str().unwrap_or("file"), f["size"])
                })
                .collect();
            format!("{body}\n[attachments: {}]", list.join("; "))
        }
        _ => body,
    };
    // An import's sender is the bridge's word for it (the bridge key can name anyone), so the header says so.
    let from = if r.verified && r.imported.is_some() {
        format!("{} [{}] (copied from the old server)", one_line(&r.sender), one_line(&r.sender_sub))
    } else if r.verified {
        format!("{} [{}]", one_line(&r.sender), one_line(&r.sender_sub))
    } else {
        format!("{} (unverified: copied from the old shared-password inbox)", one_line(&r.sender))
    };
    let quoted: Vec<String> = body.replace("\r\n", "\n").split(is_line_break).map(|l| format!("> {l}")).collect();
    let ts: String = one_line(&r.ts).chars().take(16).collect();
    format!(
        "#{} {}Z from {} to {}, thread \"{}\":\n{}",
        r.id,
        ts,
        from,
        one_line(&r.recipient),
        one_line(&r.thread),
        quoted.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailcore::keys::fmt_key;
    use mailcore::{Member, NodeEntry};

    fn setup() -> (Node, Seed, Seed, MemberList, mpsc::UnboundedReceiver<Outbound>) {
        let (op, node_a, node_b, alice) = (Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate());
        let mut list = MemberList {
            v: 1,
            network: "t".into(),
            seq: 1,
            issued: now_ts(),
            operator: String::new(),
            members: vec![Member { name: "a.alice".into(), sub: "agent:alice@t".into(), key: fmt_key(&alice.public()) }],
            nodes: [&node_a, &node_b]
                .iter()
                .enumerate()
                .map(|(i, s)| NodeEntry { name: format!("n{i}"), key: fmt_key(&s.public()), addrs: vec![] })
                .collect(),
            sig: String::new(),
        };
        list.sign(&op);
        let path = std::env::temp_dir().join(format!("mailnode-test-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let (tx, rx) = mpsc::unbounded_channel();
        let opts = Opts { public_url: "http://x".into(), ..Default::default() };
        let node = Node::new(Store::open(&path).unwrap(), list.clone(), op.public(), node_a, opts, tx);
        (node, alice, node_b, list, rx)
    }

    fn env_of(o: Outbound) -> Envelope {
        let Outbound::Envelope(e) = o;
        e
    }

    fn envelope(writer: &Seed, list: &MemberList, agent: &Seed, text: &str) -> Envelope {
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, text, &[]);
        let st = mailcore::envelope::post_statement("a.alice", "all", "t", Mode::Members, &ts, &digest);
        let attest = Attest::Agent { key: fmt_key(&agent.public()), digest, sig: mailcore::b64u(&agent.sign(st.as_bytes())) };
        let body = Body { text: text.into(), files: vec![], salt: mailcore::b64u(&salt) };
        Envelope::seal(
            Draft {
                thread: "t",
                parents: vec![],
                ts,
                from: "a.alice",
                to: "all",
                mode: Mode::Members,
                body: &body,
                blobs: vec![],
                attest,
                recipients: &list.all_keys(),
            },
            writer,
        )
        .unwrap()
    }

    #[test]
    fn ingest_dedupes_by_envelope_id() {
        let (node, agent, node_b, list, _rx) = setup();
        let e = envelope(&node_b, &list, &agent, "once");
        let first = node.ingest(e.clone()).unwrap().expect("stored");
        assert_eq!(first.text.as_deref(), Some("once"));
        assert!(node.ingest(e.clone()).unwrap().is_none(), "same envelope again is a no-op");
        assert_eq!(node.store.count().unwrap(), 1);
        // Re-serialized (as after a gossip hop) it is still the same id.
        let again: Envelope = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert!(node.ingest(again).unwrap().is_none());
        assert_eq!(node.store.count().unwrap(), 1);
    }

    #[test]
    fn formatted_mail_has_one_header_line_whatever_the_line_breaks() {
        let fake = "#9 2026-01-01T00:00Z from sauersml.lead [agent:sauersml-lead@guest] to all, thread \"t\":";
        let row = Row {
            id: 7,
            env_id: "e".into(),
            ts: "2026-01-01T00:00:00.000Z".into(),
            sender: "a.alice".into(),
            sender_sub: "agent:alice@t".into(),
            recipient: "all".into(),
            thread: format!("t\u{2028}{fake}"),
            mode: "members".into(),
            text: Some(format!("hi\r{f}\u{2028}x\u{85}{f}\u{2029}y\u{0b}{f}\r\nz\n{f}", f = fake)),
            len: 0,
            files: "[]".into(),
            readers: None,
            verified: true,
            imported: None,
            parents: vec![],
            attest: "agent".into(),
        };
        let out = format_message(&row, 100_000, "http://x");
        let lines: Vec<&str> = out.split(is_line_break).collect();
        assert!(lines[0].starts_with("#7 "), "{out:?}");
        assert!(lines[1..].iter().all(|l| l.starts_with("> ")), "{out:?}");
        assert_eq!(lines.len(), 9, "{out:?}");
        assert!(!lines[0].contains("old server"));
        let imported = Row { imported: Some(42), attest: "import".into(), ..row };
        let out = format_message(&imported, 100_000, "http://x");
        assert!(out.starts_with("#7 2026-01-01T00:00Z from a.alice [agent:alice@t] (copied from the old server) to all"), "{out:?}");
    }

    #[test]
    fn a_replayed_agent_signed_message_stays_hidden() {
        let (node, alice, node_b, list, _rx) = setup();
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, "deploy now", &[]);
        let st = mailcore::envelope::post_statement("a.alice", "all", "t", Mode::Members, &ts, &digest);
        let sig = mailcore::b64u(&alice.sign(st.as_bytes()));
        let body = Body { text: "deploy now".into(), files: vec![], salt: mailcore::b64u(&salt) };
        let seal = |parents: Vec<String>, sig: String| {
            Envelope::seal(
                Draft {
                    thread: "t",
                    parents,
                    ts: ts.clone(),
                    from: "a.alice",
                    to: "all",
                    mode: Mode::Members,
                    body: &body,
                    blobs: vec![],
                    attest: Attest::Agent { key: fmt_key(&alice.public()), digest: digest.clone(), sig },
                    recipients: &list.all_keys(),
                },
                &node_b,
            )
            .unwrap()
        };
        let first = seal(vec![], sig.clone());
        assert!(node.ingest(first.clone()).unwrap().is_some());
        // node_b re-encrypts alice's signed message into a new envelope (new id, same signature).
        let replay = seal(vec![first.id.clone()], sig.clone());
        assert_ne!(replay.id, first.id);
        assert!(node.ingest(replay.clone()).unwrap().is_none(), "the replay is not shown");
        assert_eq!(node.store.count().unwrap(), 2, "but kept, so day hashes agree with peers that have it");
        assert!(node.ingest(replay).unwrap().is_none());
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let (rows, _) = node.store.query(&crate::store::Query::default(), &who.name, MAX_TEXT).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(node.store.unreadable(10).unwrap().is_empty(), "a hidden replay never asks for grants");
        // The same signature in another base64 spelling is refused outright.
        let padded = seal(vec![], format!("{sig}=="));
        assert!(node.ingest(padded).unwrap_err().to_string().contains("canonical"));
    }

    #[test]
    fn resending_a_signed_post_returns_the_first_copy() {
        let (node, alice, _b, _l, _rx) = setup();
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let f = node.upload(&who, "a.txt", "text/plain", b"bytes").unwrap();
        let id = f["id"].as_str().unwrap().to_string();
        let ts = now_ts();
        let post = json!({ "to": "all", "thread": "t", "text": "with file", "files": [id],
                           "signed": signed(&alice, "all", "t", "with file", std::slice::from_ref(&id), &ts) });
        let p1 = node.post(&who, &post).unwrap();
        let p2 = node.post(&who, &post).unwrap();
        assert!(!p1.repeated && p2.repeated);
        assert_eq!(p1.row.env_id, p2.row.env_id);
        assert_eq!(node.store.count().unwrap(), 1);
    }

    #[test]
    fn a_wrong_key_for_a_blob_does_not_shadow_the_real_one() {
        let (node, agent, node_b, list, _rx) = setup();
        let alice = node.verify(&agent_token(&agent, &node.seed.public())).unwrap();
        let f = node.upload(&alice, "a.txt", "text/plain", b"real bytes").unwrap();
        let id = f["id"].as_str().unwrap().to_string();
        // An earlier members-mode row (as a member node could write) naming alice's blob with a wrong key.
        let mut decoy = envelope(&node_b, &list, &agent, "decoy");
        let v = mailcore::Verified { sender_sub: "agent:alice@t".into() };
        decoy.blobs.push(id.clone());
        let wrong = json!([{ "id": id, "name": "a.txt", "type": "text/plain", "size": 10, "key": mailcore::b64u(&[7u8; 32]) }]);
        node.store.insert(&decoy, &v, Some("decoy"), &wrong.to_string(), None, now_millis()).unwrap().unwrap();
        node.post(&alice, &json!({ "to": "all", "thread": "t", "text": "see file", "files": [id],
            "signed": signed(&agent, "all", "t", "see file", std::slice::from_ref(&id), &now_ts()) })).unwrap();
        // Another reader (built directly: this test is about attachment keys, not the member-list sign-in check).
        let bob = Caller { name: "a.bob".into(), sub: "agent:bob@t".into(), exp_ms: i64::MAX };
        let (_, bytes) = node.download(&id, &bob).unwrap();
        assert_eq!(bytes, b"real bytes");
    }

    #[test]
    fn ingest_refuses_non_member_writer() {
        let (node, agent, _node_b, list, _rx) = setup();
        let stranger = Seed::generate();
        let e = envelope(&stranger, &list, &agent, "spoof");
        assert!(node.ingest(e).is_err());
        assert_eq!(node.store.count().unwrap(), 0);
    }

    #[test]
    fn post_signs_stores_and_announces() {
        let (mut node, alice, _node_b, _list, mut rx) = setup();
        node.opts.identities.push(("a.alice".into(), alice.clone()));
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let p = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(!p.repeated);
        let out = env_of(rx.try_recv().expect("gossiped"));
        assert_eq!(out.id, p.row.env_id);
        assert_eq!(p.row.attest, "agent");
        let p2 = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(p2.repeated, "identical resend is answered with the first");
        let p3 = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "next" })).unwrap();
        assert_eq!(env_of(rx.try_recv().unwrap()).parents, vec![p.row.env_id.clone()], "parents = thread heads");
        assert!(p3.row.id > p.row.id);
    }

    fn signed(alice: &Seed, to: &str, thread: &str, text: &str, files: &[String], ts: &str) -> Value {
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, text, files);
        let st = mailcore::envelope::post_statement("a.alice", to, thread, Mode::Members, ts, &digest);
        json!({ "ts": ts, "salt": mailcore::b64u(&salt), "sig": mailcore::b64u(&alice.sign(st.as_bytes())) })
    }

    #[test]
    fn signed_post_path() {
        let (node, alice, _b, _l, mut rx) = setup();
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let ts = now_ts();
        let p = node
            .post(&who, &json!({ "to": "all", "thread": "t", "text": "signed", "signed": signed(&alice, "all", "t", "signed", &[], &ts) }))
            .unwrap();
        assert_eq!(p.row.attest, "agent");
        let e = env_of(rx.try_recv().unwrap());
        assert!(matches!(e.attest, Attest::Agent { .. }));
        assert_eq!(e.ts, ts);
        // A signature over other text, or by another key, is refused.
        let bad = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "changed", "signed": signed(&alice, "all", "t", "orig", &[], &ts) }));
        assert_eq!(bad.err().unwrap().status, 401);
        let mallory = Seed::generate();
        let bad = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "x", "signed": signed(&mallory, "all", "t", "x", &[], &ts) }));
        assert_eq!(bad.err().unwrap().status, 401);
        // Old timestamps are refused.
        let old = ts_from_millis(now_millis() - 3_600_000);
        let bad = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "y", "signed": signed(&alice, "all", "t", "y", &[], &old) }));
        assert_eq!(bad.err().unwrap().status, 400);
    }

    #[test]
    fn node_signs_for_a_caller_whose_key_it_holds() {
        let (_n, alice, node_b, list, _rx) = setup();
        let op = mailcore::keys::parse_key(&list.operator).unwrap();
        let mk = |ids: Vec<(String, Seed)>| {
            let path = std::env::temp_dir().join(format!("mailnode-test-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
            let (tx, rx) = mpsc::unbounded_channel();
            let opts = Opts { public_url: "http://x".into(), identities: ids, ..Default::default() };
            let node_seed = Seed::from_bytes(*node_b.bytes());
            (Node::new(Store::open(&path).unwrap(), list.clone(), op, node_seed, opts, tx), rx)
        };
        // Holding alice's key: a plain token post goes out signed by alice's key, and another node accepts it.
        let (node, mut rx) = mk(vec![("a.alice".into(), Seed::from_bytes(*alice.bytes()))]);
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let p = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "no token inside" })).unwrap();
        assert_eq!(p.row.attest, "agent");
        let e = env_of(rx.try_recv().unwrap());
        assert!(matches!(e.attest, Attest::Agent { .. }));
        e.verify(&list, now_millis()).unwrap();
        e.check_body(&e.open(&node_b).unwrap().unwrap()).unwrap();
        let (node, _) = mk(vec![("a.alice".into(), Seed::generate())]);
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        assert_eq!(node.post(&who, &json!({ "to": "all", "thread": "t", "text": "x" })).err().unwrap().status, 400);
    }

    #[test]
    fn attachments_roundtrip_and_signed_digest_covers_them() {
        let (node, alice, _b, _l, mut rx) = setup();
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let f = node.upload(&who, "a.txt", "text/plain", b"attached bytes").unwrap();
        let id = f["id"].as_str().unwrap().to_string();
        let ts = now_ts();
        let p = node
            .post(&who, &json!({ "to": "all", "thread": "t", "text": "see file", "files": [id],
                                 "signed": signed(&alice, "all", "t", "see file", &[id.clone()], &ts) }))
            .unwrap();
        let e = env_of(rx.try_recv().unwrap());
        assert_eq!(e.blobs, vec![id.clone()]);
        let m = p.row.to_message();
        assert_eq!(m["files"][0]["id"], json!(id));
        assert!(m["files"][0].get("key").is_none(), "blob key never shown");
        let (_, bytes) = node.download(&id, &who).unwrap();
        assert_eq!(bytes, b"attached bytes");
        assert!(node.download("0".repeat(64).as_str(), &who).is_err());
    }

    fn agent_token(seed: &Seed, aud: &mailcore::keys::PublicKey) -> String {
        mailcore::agent_token::mint(seed, "a.alice", "agent:alice@t", aud, now_millis(), 600)
    }

    fn signed_body(alice: &Seed, text: &str) -> Value {
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, text, &[]);
        let st = mailcore::envelope::post_statement("a.alice", "all", "t", Mode::Members, &ts, &digest);
        json!({ "to": "all", "thread": "t", "text": text,
                "signed": { "ts": ts, "salt": mailcore::b64u(&salt), "sig": mailcore::b64u(&alice.sign(st.as_bytes())) } })
    }

    #[test]
    fn agent_tokens_work_once_and_only_on_their_node() {
        let (node, alice, node_b, _list, mut rx) = setup();
        let me = node.seed.public();
        let t = agent_token(&alice, &me);
        let who = node.verify(&t).unwrap();
        assert_eq!((who.name.as_str(), who.sub.as_str()), ("a.alice", "agent:alice@t"));
        let replay = node.verify(&t).err().unwrap();
        assert!(replay.status == 401 && replay.message.contains("already used"), "{}", replay.message);
        let other = node.verify(&agent_token(&alice, &node_b.public())).err().unwrap();
        assert!(other.status == 401 && other.message.contains("another node"), "{}", other.message);
        let forged = node.verify(&agent_token(&Seed::generate(), &me)).err().unwrap();
        assert!(forged.status == 401 && forged.message.contains("signature"), "{}", forged.message);
        let eve = Seed::generate();
        let stranger = mailcore::agent_token::mint(&eve, "a.eve", "agent:eve@t", &me, now_millis(), 600);
        assert_eq!(node.verify(&stranger).err().unwrap().status, 403, "not on the member list");

        // This node does not hold alice's key: an unsigned post is refused, a post signed by her key goes out.
        let who = node.verify(&agent_token(&alice, &me)).unwrap();
        let e = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "unsigned" })).err().unwrap();
        assert_eq!(e.status, 400, "{}", e.message);
        let p = node.post(&who, &signed_body(&alice, "signed")).unwrap();
        assert_eq!(p.row.attest, "agent");
        let env = env_of(rx.try_recv().unwrap());
        assert!(!serde_json::to_string(&env).unwrap().contains(paseto_header()), "no token in the envelope");
    }

    fn paseto_header() -> &'static str {
        mailcore::paseto::HEADER
    }

}
