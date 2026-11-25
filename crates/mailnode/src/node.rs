//! The node's mail logic, shared by the HTTP API, MCPL and replication: certify this host's agents, accept a local
//! send (seal, sign, store, announce), accept a replicated envelope, certificate or revocation (verify, decrypt if we
//! can, store), and the read-side rules (names, reaches, addressed rows, message formatting).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use mailcore::addr::{addressed_to, is_broadcast, norm};
use mailcore::cert::{agent_sub, live_certs, valid_name};
use mailcore::envelope::{Draft, Grant};
use mailcore::keys::{fmt_key, PublicKey, Seed};
use mailcore::{
    now_millis, now_ts, ts_from_millis, Attest, Body, Cert, Envelope, KnownCerts, MemberList, Mode, NodeEntry, Revocation,
};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use unicode_normalization::UnicodeNormalization;

use crate::store::{Row, Store, MAX_TEXT};

pub const MAX_FIELD: usize = 120;
const REPEAT_MS: i64 = 10 * 60 * 1000;
const RATE_WINDOW_MS: i64 = 3_600_000;
const SCAN_ROWS: usize = 50_000;
/// New certificates this node issues through POST /api/agents in an hour.
pub const MAX_ISSUANCES: usize = 60;

/// An HTTP-style error: status and message.
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

/// Whoever presented a valid agent token: an agent certified by this node.
#[derive(Clone, Debug)]
pub struct Caller {
    /// The name as certified.
    pub name: String,
    /// "agent:{name}@{this node's name}"
    pub sub: String,
    pub kind: String,
    pub exp_ms: i64,
    /// How the caller signed in: always "agent-token" (PASETO v4.public, signed by the agent's certified key).
    pub auth: &'static str,
    /// The certified key that signed the token, and its certificate from this node.
    pub key: PublicKey,
    pub cert: Cert,
}

#[derive(Debug)]
pub struct Posted {
    pub row: Row,
    pub reaches: Vec<String>,
    pub repeated: bool,
}

/// What goes out on the gossip topic from the API side (member lists are announced by the network task).
pub enum Outbound {
    Envelope(Box<Envelope>),
    Cert(Cert),
    Revocation(Revocation),
}

/// Node settings beyond the store and keys.
#[derive(Default)]
pub struct Opts {
    /// (name, seed) of the identity files in identities_dir: agents of this host whose keys this node holds.
    pub identities: Vec<(String, Seed)>,
    /// Where the latest adopted member list is kept.
    pub members_path: Option<std::path::PathBuf>,
    /// Base URL written into attachment links.
    pub public_url: String,
}

/// The known certificates as they stood when an envelope was written: a revocation counts against envelopes dated at
/// or after it. Mail a key sent before its revocation was valid when its node wrote it, so it still replicates to every
/// node (a node joining later reads it too, and day hashes agree); the revoking node itself takes nothing new from the
/// key (its sign-in is refused), so nothing later can carry an earlier date unless that node is the one lying.
struct AsOf<'a> {
    store: &'a Store,
    ts_ms: i64,
}

impl KnownCerts for AsOf<'_> {
    fn revoked(&self, cert: &Cert) -> bool {
        self.store.revoked_at(&cert.node, &cert.key).is_some_and(|at| at <= self.ts_ms)
    }

    fn certs_for(&self, name: &str) -> Vec<Cert> {
        self.store.certs_for(name)
    }
}

/// A file reference {id, name, type, size, key} and the plaintext, when the blob is on this node.
type FileRef = (Value, Option<Vec<u8>>);

pub const MAX_FILE: usize = 25 * 1024 * 1024;
pub const MAX_FILES: usize = mailcore::envelope::MAX_BLOBS;
const MAX_FILES_PER_SUB: i64 = 1024 * 1024 * 1024;

pub struct Node {
    pub store: Store,
    pub members: RwLock<MemberList>,
    pub operator: PublicKey,
    pub seed: Seed,
    pub opts: Opts,
    pub events: broadcast::Sender<Arc<Row>>,
    pub outbound: mpsc::UnboundedSender<Outbound>,
    rates: Mutex<HashMap<(String, &'static str), Vec<i64>>>,
    touched: Mutex<HashMap<String, i64>>,
    auth_seen: Mutex<HashSet<String>>,
}

impl Node {
    pub fn new(
        store: Store,
        members: MemberList,
        operator: PublicKey,
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
        if let Some(p) = &self.opts.members_path {
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_string_pretty(list)?)?;
            std::fs::rename(&tmp, p)?;
        }
        tracing::info!("adopted member list seq {} ({} nodes)", list.seq, list.nodes.len());
        self.certify_held();
        Ok(true)
    }

    /* Certificates */

    /// This node's entry on the current member list.
    pub fn my_entry(&self) -> Option<NodeEntry> {
        self.members.read().unwrap().node_by_key(&self.seed.public()).cloned()
    }

    /// POST /api/agents: certify `{name, key, ts, sig}` (sig: the agent's issuance proof). Returns (200 or 201, cert).
    pub fn certify(&self, body: &Value) -> Result<(u16, Cert), ApiError> {
        let s = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let name = s("name");
        let now = now_millis();
        let me = self.seed.public();
        let key = mailcore::cert::check_issuance(name, s("key"), s("ts"), s("sig"), &me, now)
            .map_err(|e| ApiError::new(400, format!("{e:#}")))?;
        let members = self.members.read().unwrap().clone();
        let entry = members
            .node_by_key(&me)
            .ok_or_else(|| ApiError::new(503, "this node is not on the member list, so it cannot certify agents"))?;
        if !entry.covers(name) {
            return Err(ApiError::new(
                403,
                format!("{name} is not in this host's names: {}", entry.namespace().join(", ")),
            ));
        }
        let (me_s, key_s) = (fmt_key(&me), fmt_key(&key));
        if self.store.node_revoked(&me_s, &key_s) {
            return Err(ApiError::new(403, "this key was revoked by this host; make a new key and ask again"));
        }
        let live = live_certs(&self.store, &members, name, &me);
        if let Some(c) = live.iter().find(|c| c.key == key_s) {
            return Ok((200, c.clone()));
        }
        if let Some(c) = self.store.cert_by(&me_s, &key_s)? {
            return Err(ApiError::new(409, format!("this key is already certified here as {}", c.name)));
        }
        if !live.is_empty() {
            return Err(ApiError::new(
                409,
                format!(
                    "{name} is taken on this host; pick another name, or the host owner runs `mailnode revoke CONFIG {name}`"
                ),
            ));
        }
        self.rate("", "new certificates", MAX_ISSUANCES)?;
        let cert = self.issue(name, &key, &entry.name)?;
        Ok((201, cert))
    }

    /// Signs, stores and announces a new cert from this node.
    fn issue(&self, name: &str, key: &PublicKey, node_name: &str) -> Result<Cert> {
        let now = now_millis();
        let cert = Cert::issue(&self.seed, name, key, &now_ts());
        if !self.store.add_cert(&cert, now)? {
            anyhow::bail!("a certificate for this key from this node is already stored");
        }
        let _ = self.store.seen(&cert.name, &agent_sub(&cert.name, node_name), now);
        tracing::info!("certified {name:?} with key {}", cert.key);
        let _ = self.outbound.send(Outbound::Cert(cert.clone()));
        Ok(cert)
    }

    /// identities_dir: every held identity whose name is in this node's namespace, that has no live cert from this
    /// node and whose key this node has not revoked, gets a cert (the node holds the seed: no proof needed). Run at
    /// startup and after each member-list update. Returns the certs issued.
    pub fn certify_held(&self) -> Vec<Cert> {
        let me = self.seed.public();
        let me_s = fmt_key(&me);
        let members = self.members.read().unwrap().clone();
        let Some(entry) = members.node_by_key(&me) else { return vec![] };
        let mut out = Vec::new();
        for (name, seed) in &self.opts.identities {
            if !valid_name(name) || !entry.covers(name) {
                tracing::debug!("identity {name:?} is not in this host's names; not certified");
                continue;
            }
            let key = seed.public();
            let key_s = fmt_key(&key);
            if self.store.node_revoked(&me_s, &key_s) || !live_certs(&self.store, &members, name, &me).is_empty() {
                continue;
            }
            match self.store.cert_by(&me_s, &key_s) {
                Ok(Some(c)) => {
                    tracing::warn!("identity {name:?}: its key is already certified here as {:?}; not certified", c.name);
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("identity {name:?}: {e:#}");
                    continue;
                }
            }
            match self.issue(name, &key, &entry.name) {
                Ok(c) => out.push(c),
                Err(e) => tracing::warn!("identity {name:?}: {e:#}"),
            }
        }
        out
    }

    /// A cert from a peer: stored if it verifies against the current member list. Ok(true) if it is new here.
    pub fn accept_cert(&self, c: &Cert) -> Result<bool> {
        c.verify(&self.members.read().unwrap())?;
        let new = self.store.add_cert(c, now_millis())?;
        if new {
            if let Some(n) = self.members.read().unwrap().node_by_key(&c.node_key()?) {
                let _ = self.store.seen(&c.name, &agent_sub(&c.name, &n.name), 0);
            }
        }
        Ok(new)
    }

    /// A revocation from a peer or POST /api/revocations: stored if it verifies. Ok(true) if it is new here.
    pub fn accept_revocation(&self, r: &Revocation) -> Result<bool> {
        r.verify(&self.members.read().unwrap())?;
        self.store.add_revocation(r, now_millis())
    }

    /// POST /api/revocations: a valid revocation is stored and, when new here, announced. Ok(true) if new.
    pub fn revoke(&self, r: &Revocation) -> Result<bool, ApiError> {
        let new = self.accept_revocation(r).map_err(|e| ApiError::new(400, format!("revocation refused: {e:#}")))?;
        if new {
            tracing::info!("revocation of {:?} (key {}) by {}", r.name, r.key, r.node);
            let _ = self.outbound.send(Outbound::Revocation(r.clone()));
        }
        Ok(new)
    }

    /// GET /api/agents: every known cert.
    pub fn agents(&self) -> Result<Vec<Value>> {
        let members = self.members.read().unwrap().clone();
        Ok(self
            .store
            .certs(-1)?
            .into_iter()
            .map(|c| {
                let node_name = c.node_key().ok().and_then(|k| members.node_by_key(&k)).map(|n| n.name.clone());
                json!({
                    "name": c.name, "key": c.key, "node": c.node, "node_name": node_name.unwrap_or_default(),
                    "issued": c.issued, "revoked": self.store.revoked(&c),
                })
            })
            .collect())
    }

    /// Known certs that count now: valid against the current member list and not revoked.
    fn live_known(&self, members: &MemberList) -> Result<Vec<Cert>> {
        Ok(self.store.certs(-1)?.into_iter().filter(|c| c.verify(members).is_ok() && !self.store.revoked(c)).collect())
    }

    /// The identity this node holds for the caller's certified key, if any (identities_dir).
    fn held_seed(&self, who: &Caller) -> Option<&Seed> {
        self.opts.identities.iter().find(|(_, s)| s.public() == who.key).map(|(_, s)| s)
    }

    /* Identity */

    /// A caller's bearer token: an agent token (PASETO v4.public) signed by the key of an unrevoked certificate this
    /// node issued for the token's name, for this node (aud), live now, used once.
    pub fn verify(&self, token: &str) -> Result<Caller, ApiError> {
        use mailcore::agent_token::Refusal;
        let now = now_millis();
        if !mailcore::agent_token::is_agent_token(token) {
            return Err(ApiError::new(
                401,
                "token refused: this node accepts only agent tokens signed by your certified key (islandmail.py makes them)",
            ));
        }
        let members = self.members.read().unwrap().clone();
        let me = self.seed.public();
        let c = mailcore::agent_token::verify(token, &self.store, &members, &me, now).map_err(|r| match r {
            Refusal::NotCertified(s) => ApiError::new(403, s),
            Refusal::Bad(s) => ApiError::new(401, format!("token refused: {s}")),
        })?;
        if !self.store.use_token(&c.name, &c.jti, c.exp_ms, now)? {
            return Err(ApiError::new(401, "token refused: already used (agent tokens are single-use; mint a fresh one)"));
        }
        let node_name = members.node_by_key(&me).map(|n| n.name.clone()).unwrap_or_default();
        let sub = agent_sub(&c.name, &node_name);
        self.note_auth(&c.name);
        self.touch(&c.name, &sub);
        Ok(Caller { name: c.name, sub, kind: "agent".into(), exp_ms: c.exp_ms, auth: "agent-token", key: c.key, cert: c.cert })
    }

    /// Logs the first sign-in of each name (debug-level for every later one). Never the token.
    fn note_auth(&self, name: &str) {
        let mut seen = self.auth_seen.lock().unwrap();
        if seen.len() < 10_000 && seen.insert(norm(name)) {
            tracing::info!("{name:?} signed in with an agent token");
        } else {
            tracing::debug!("{name:?} used an agent token");
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
                message: if sub.is_empty() {
                    format!("rate limit: at most {max} {kind} per hour on this host; try again later")
                } else {
                    format!("rate limit: at most {max} {kind} per hour per sender")
                },
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
        let me = self.seed.public();
        let recipients = match mode {
            Mode::Members => members.node_keys(),
            Mode::Private => {
                let certs = self.store.certs(-1)?;
                mailcore::private_recipients(&members, &to, &me, &certs, &|c| self.store.revoked(c))
                    .ok_or_else(|| ApiError::new(400, format!("no known agent matches {to}")))?
            }
        };
        // Signed by the sender's own certified key (islandmail.py sends `signed: {ts, salt, sig}`), signed by this
        // node with the sender's key when it holds it (identities_dir), or vouched for by this node.
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
                    .filter(|b| (16..=64).contains(&b.len()))
                    .ok_or_else(|| ApiError::new(400, "signed post: salt must be 16-64 bytes, base64url"))?;
                let digest = mailcore::envelope::post_digest(&salt, &text, &file_ids);
                let st = mailcore::envelope::post_statement(&who.name, &to, &thread, mode, &ts, &digest);
                let sig = s["sig"].as_str().unwrap_or("").to_string();
                let sig_bytes = mailcore::b64u_decode(&sig).unwrap_or_default();
                let cert = live_certs(&self.store, &members, &who.name, &me)
                    .into_iter()
                    .find(|c| c.agent_key().is_ok_and(|k| mailcore::keys::verify(&k, st.as_bytes(), &sig_bytes)))
                    .ok_or_else(|| {
                        ApiError::new(401, format!("signed post: signature does not verify against {}'s certified key", who.name))
                    })?;
                // Canonical encoding (the one every node dedupes by); a client resending the same signed post gets
                // the first copy back instead of a second envelope.
                let sig = mailcore::b64u(&sig_bytes);
                if let Some(row) = self.store.by_agent_sig(&sig)? {
                    let reaches = self.reaches(&row.recipient, &who.sub)?;
                    return Ok(Posted { row, reaches, repeated: true });
                }
                (ts, Attest::Agent { key: cert.key.clone(), digest, sig, cert }, mailcore::b64u(&salt))
            }
            None => match self.held_seed(who) {
                Some(seed) => {
                    let salt = mailcore::random_bytes::<16>();
                    let ts = now_ts();
                    let digest = mailcore::envelope::post_digest(&salt, &text, &file_ids);
                    let st = mailcore::envelope::post_statement(&who.name, &to, &thread, mode, &ts, &digest);
                    let sig = mailcore::b64u(&seed.sign(st.as_bytes()));
                    let cert = who.cert.clone();
                    (ts, Attest::Agent { key: cert.key.clone(), digest, sig, cert }, mailcore::b64u(&salt))
                }
                None => (now_ts(), Attest::Node, String::new()),
            },
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
            .verify(&members, &self.store, now_millis())
            .and_then(|v| env.check_body(&b).map(|_| v))
            .map_err(|e| ApiError::new(503, format!("this node cannot write mail: {e:#}")))?;
        let readers = match mode {
            Mode::Private => Some(self.readers_for(&members, &to, &who.name)?),
            Mode::Members => None,
        };
        let files_json = serde_json::to_string(&files).map_err(anyhow::Error::from)?;
        let row = self
            .store
            .insert(&env, &v, Some(&text), &files_json, readers.as_deref(), now_millis())?
            .ok_or_else(|| ApiError::new(500, "envelope id collision"))?;
        let _ = self.events.send(Arc::new(row.clone()));
        let _ = self.outbound.send(Outbound::Envelope(Box::new(env)));
        let reaches = self.reaches(&to, &who.sub)?;
        Ok(Posted { row, reaches, repeated: false })
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

    /// A replicated envelope. Ok(None): already here. Err: refused (bad signature, certificate, member, shape).
    pub fn ingest(&self, env: Envelope) -> Result<Option<Arc<Row>>> {
        if self.store.has(&env.id)? {
            return Ok(None);
        }
        let members = self.members.read().unwrap().clone();
        let v = env.verify(&members, &AsOf { store: &self.store, ts_ms: env.ts_ms() }, now_millis())?;
        // The sender's cert travels in the envelope and has just been verified: keep it (first per node and key).
        if let Attest::Agent { cert, .. } = &env.attest {
            let _ = self.store.add_cert(cert, now_millis());
        }
        let body = env.open(&self.seed).unwrap_or(None);
        if let Some(b) = &body {
            env.check_body(b)?;
        }
        let files_json = body.as_ref().map(|b| serde_json::to_string(&b.files)).transpose()?.unwrap_or_else(|| "[]".into());
        let text: Option<String> = body.map(|b| b.text.chars().take(MAX_TEXT as usize).collect());
        let readers = match env.mode {
            Mode::Private => Some(self.readers_for(&members, &env.to, &env.from)?),
            Mode::Members => None,
        };
        let Some(row) = self.store.insert(&env, &v, text.as_deref(), &files_json, readers.as_deref(), now_millis())? else {
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

    /// Known names: every name with a live cert (valid on the current list, not revoked) and every name seen in
    /// messages or sign-ins, as (name, sub, last seen ms), most recently active first.
    pub fn known_names(&self, limit: i64) -> Result<Vec<(String, String, i64)>> {
        let members = self.members.read().unwrap().clone();
        let mut rows = self.store.names(limit.max(0))?;
        let mut have: HashSet<String> = rows.iter().map(|r| norm(&r.0)).collect();
        for c in self.live_known(&members)? {
            let Some(n) = c.node_key().ok().and_then(|k| members.node_by_key(&k)) else { continue };
            if have.insert(norm(&c.name)) {
                rows.push((c.name.clone(), agent_sub(&c.name, &n.name), 0));
            }
        }
        rows.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit.max(0) as usize);
        Ok(rows)
    }

    /// ",name1,name2," of the names a private envelope is for: the sender and every live cert's name `to` addresses.
    pub fn readers_for(&self, members: &MemberList, to: &str, from: &str) -> Result<String> {
        let mut names: Vec<String> = self
            .live_known(members)?
            .iter()
            .filter(|c| addressed_to(to, &[c.name.as_str()]))
            .map(|c| norm(&c.name))
            .collect();
        names.push(norm(from));
        names.sort();
        names.dedup();
        Ok(format!(",{},", names.join(",")))
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
            .filter(|r| r.1 != sender_sub && addressed_to(to, &[r.0.as_str()]))
            .map(|r| r.0)
            .collect();
        out.sort();
        Ok(out)
    }

    /// Mail addressed to `name` with ids in (after, before), not sent by it; newest first unless `ascending`.
    #[allow(clippy::too_many_arguments)]
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
        let refs = [name];
        let subs = [sub.to_string()];
        let mut needles = vec!["all".to_string(), "*".to_string()];
        let n = norm(name);
        for (i, c) in n.char_indices() {
            if c == '.' {
                needles.push(n[..=i].to_string());
            }
        }
        needles.push(n);
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

/* Field rules */

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

/// An attachment's file name: the last path segment, no format/control characters or quotes, at most 200 chars.
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

/// An attachment's type: a plain type/subtype or application/octet-stream.
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

/// A message as the mailbox shows it: one header line, then the sender's text, every line quoted.
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
    let from = format!("{} [{}]", one_line(&r.sender), one_line(&r.sender_sub));
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
    use crate::testutil::{list, next_env, node, proof, sign_in, signed, token};

    /// Two member nodes: A ("a." plus the exact name "solo") and B ("b."), and the operator.
    struct Net2 {
        op: Seed,
        a_seed: Seed,
        b_seed: Seed,
        list: MemberList,
        a: Node,
        a_rx: mpsc::UnboundedReceiver<Outbound>,
        b: Node,
    }

    fn net2() -> Net2 {
        let (op, a_seed, b_seed) = (Seed::generate(), Seed::generate(), Seed::generate());
        let list = list(&op, &[("a", &a_seed, &["a.", "solo"]), ("b", &b_seed, &[])], 1);
        let (a, a_rx) = node(&list, &op, &a_seed, vec![]);
        let (b, _) = node(&list, &op, &b_seed, vec![]);
        Net2 { op, a_seed, b_seed, list, a, a_rx, b }
    }

    fn seal(writer: &Seed, list: &MemberList, from: &str, attest: Attest, body: &Body, parents: Vec<String>, ts: &str) -> Envelope {
        Envelope::seal(
            Draft {
                thread: "t",
                parents,
                ts: ts.to_string(),
                from,
                to: "all",
                mode: Mode::Members,
                body,
                blobs: vec![],
                attest,
                recipients: &list.node_keys(),
            },
            writer,
        )
        .unwrap()
    }

    fn status(r: Result<(u16, Cert), ApiError>) -> u16 {
        match r {
            Ok((s, _)) => s,
            Err(e) => e.status,
        }
    }

    #[test]
    fn issuance_answers_400_403_409_200_201() {
        let n = net2();
        let me = n.a_seed.public();
        let alice = Seed::generate();
        // Bad proof: signed by another key, or for another node.
        let mut bad = proof(&alice, "a.alice", &me);
        bad["key"] = json!(fmt_key(&Seed::generate().public()));
        assert_eq!(status(n.a.certify(&bad)), 400);
        assert_eq!(status(n.a.certify(&proof(&alice, "a.alice", &n.b_seed.public()))), 400);
        assert_eq!(status(n.a.certify(&proof(&alice, "all", &me))), 400, "not a valid name");
        // Outside this host's names: another host's namespace, or nobody's.
        let e = n.a.certify(&proof(&alice, "b.alice", &me)).unwrap_err();
        assert_eq!(e.status, 403);
        assert!(e.message.contains("not in this host's names: a., solo"), "{}", e.message);
        assert_eq!(status(n.a.certify(&proof(&alice, "zed", &me))), 403);
        // New, then the same name and key again.
        let (st, c1) = n.a.certify(&proof(&alice, "a.alice", &me)).unwrap();
        assert_eq!(st, 201);
        c1.verify(&n.list).unwrap();
        let (st, c2) = n.a.certify(&proof(&alice, "A.Alice", &me)).unwrap();
        assert_eq!((st, &c2.sig), (200, &c1.sig), "idempotent, whatever the case");
        assert_eq!(status(n.a.certify(&proof(&alice, "solo", &me))), 409, "this key is already certified here as a.alice");
        // The name is taken by another key.
        let e = n.a.certify(&proof(&Seed::generate(), "a.alice", &me)).unwrap_err();
        assert_eq!(e.status, 409);
        assert!(e.message.contains("mailnode revoke CONFIG a.alice"), "{}", e.message);
        // An exact name in the namespace works.
        assert_eq!(status(n.a.certify(&proof(&Seed::generate(), "solo", &me))), 201);
    }

    #[test]
    fn issuance_is_rate_limited() {
        let n = net2();
        let me = n.a_seed.public();
        for i in 0..MAX_ISSUANCES {
            assert_eq!(status(n.a.certify(&proof(&Seed::generate(), &format!("a.x{i}"), &me))), 201);
        }
        let e = n.a.certify(&proof(&Seed::generate(), "a.late", &me)).unwrap_err();
        assert_eq!(e.status, 429);
        assert!(e.retry_after.is_some());
        // A taken name still answers 409 (the limit counts only new certificates).
        assert_eq!(status(n.a.certify(&proof(&Seed::generate(), "a.x0", &me))), 409);
    }

    #[test]
    fn another_nodes_cert_for_the_same_key_neither_blocks_nor_replaces_ours() {
        let n = net2();
        let k = Seed::generate();
        // B certifies K first (as B's own name) and A learns it before certifying K itself.
        let (_, from_b) = n.b.certify(&proof(&k, "b.k", &n.b_seed.public())).unwrap();
        assert!(n.a.accept_cert(&from_b).unwrap());
        let (st, from_a) = n.a.certify(&proof(&k, "a.k", &n.a_seed.public())).unwrap();
        assert_eq!(st, 201);
        // Arriving again (or a forged second cert from B for the key) changes nothing on A.
        assert!(!n.a.accept_cert(&from_b).unwrap());
        let me = fmt_key(&n.a_seed.public());
        assert_eq!(n.a.store.cert_by(&me, &from_a.key).unwrap().unwrap().sig, from_a.sig);
        let who = n.a.verify(&token(&k, "a.k", &n.a)).unwrap();
        assert_eq!((who.name.as_str(), who.sub.as_str()), ("a.k", "agent:a.k@a"));
        assert_eq!(n.a.agents().unwrap().len(), 2);
    }

    #[test]
    fn revocation_counts_only_against_its_own_nodes_cert() {
        let mut n = net2();
        let k = Seed::generate();
        let (_, from_b) = n.b.certify(&proof(&k, "b.k", &n.b_seed.public())).unwrap();
        let _ = sign_in(&n.a, &k, "a.k");
        n.b.accept_cert(&from_b).unwrap();
        // B revokes its own cert for K: A's cert for K stays live.
        let rb = Revocation::sign(&n.b_seed, "b.k", &k.public(), &now_ts());
        assert!(n.a.revoke(&rb).unwrap());
        assert!(!n.a.revoke(&rb).unwrap(), "known already");
        n.b.revoke(&rb).unwrap();
        let who = n.a.verify(&token(&k, "a.k", &n.a)).expect("sign-in on A still works");
        let body = json!({ "to": "all", "thread": "t", "text": "still here", "signed": signed(&k, "a.k", "all", "t", "still here", &[]) });
        n.a.post(&who, &body).unwrap();
        let before = next_env(&mut n.a_rx);
        assert!(n.b.ingest(before.clone()).unwrap().is_some(), "B accepts A's envelopes for K");
        // A node cannot revoke another host's agent: B's signature over A's cert is refused.
        let forged = Revocation::sign(&n.b_seed, "a.k", &k.public(), &now_ts());
        assert_eq!(n.a.revoke(&forged).unwrap_err().status, 400);
        // A revokes its own cert: sign-in, and new envelopes from K through A, are refused; the name is free again.
        let ra = Revocation::sign(&n.a_seed, "a.k", &k.public(), &now_ts());
        assert!(n.a.revoke(&ra).unwrap());
        assert_eq!(n.a.verify(&token(&k, "a.k", &n.a)).unwrap_err().status, 403);
        n.b.revoke(&ra).unwrap();
        let cert = n.a.store.cert_by(&fmt_key(&n.a_seed.public()), &fmt_key(&k.public())).unwrap().unwrap();
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, "after", &[]);
        let st = mailcore::envelope::post_statement("a.k", "all", "t", Mode::Members, &ts, &digest);
        let sig = mailcore::b64u(&k.sign(st.as_bytes()));
        let b = Body { text: "after".into(), files: vec![], salt: mailcore::b64u(&salt) };
        let late = seal(&n.a_seed, &n.list, "a.k", Attest::Agent { key: cert.key.clone(), digest, sig, cert }, &b, vec![], &ts);
        assert!(n.b.ingest(late).is_err(), "a revoked key's new envelope is refused");
        // What K sent before the revocation still replicates, also to a node that learns the revocation first.
        let (fresh, _) = node(&n.list, &n.op, &n.b_seed, vec![]);
        fresh.revoke(&ra).unwrap();
        fresh.accept_cert(&from_b).unwrap();
        assert!(fresh.ingest(before).unwrap().is_some(), "history from before the revocation is kept");
        assert_eq!(status(n.a.certify(&proof(&k, "a.k", &n.a_seed.public()))), 403, "the revoked key itself stays dead");
        let k2 = Seed::generate();
        assert_eq!(status(n.a.certify(&proof(&k2, "a.k", &n.a_seed.public()))), 201, "the name takes a new key");
        assert_eq!(n.a.verify(&token(&k2, "a.k", &n.a)).unwrap().name, "a.k");
    }

    #[test]
    fn tokens_are_single_use_for_this_node_and_certified_names_only() {
        let n = net2();
        let alice = Seed::generate();
        let _ = sign_in(&n.a, &alice, "a.alice");
        let t = token(&alice, "a.alice", &n.a);
        assert!(n.a.verify(&t).is_ok());
        let e = n.a.verify(&t).unwrap_err();
        assert!(e.status == 401 && e.message.contains("already used"), "{}", e.message);
        // Minted for node B (wrong aud), by another key, for a name A never certified, or not an agent token at all.
        let wrong_aud = mailcore::agent_token::mint(&alice, "a.alice", &n.b_seed.public(), now_millis(), 600);
        assert_eq!(n.a.verify(&wrong_aud).unwrap_err().status, 401);
        assert_eq!(n.a.verify(&token(&Seed::generate(), "a.alice", &n.a)).unwrap_err().status, 401);
        let e = n.a.verify(&token(&alice, "a.bob", &n.a)).unwrap_err();
        assert_eq!(e.status, 403);
        assert!(e.message.contains("POST /api/agents"), "{}", e.message);
        assert_eq!(n.a.verify("v2.local.not-an-agent-token").unwrap_err().status, 401);
        // A cert B issued does not let its agent sign in on A.
        let bob = Seed::generate();
        let (_, c) = n.b.certify(&proof(&bob, "b.bob", &n.b_seed.public())).unwrap();
        n.a.accept_cert(&c).unwrap();
        assert_eq!(n.a.verify(&token(&bob, "b.bob", &n.a)).unwrap_err().status, 403);
    }

    #[test]
    fn envelopes_written_on_one_node_are_verified_and_stored_by_another() {
        let mut n = net2();
        let alice = Seed::generate();
        let who = sign_in(&n.a, &alice, "a.alice");
        // Signed: the cert travels in the envelope, so B needs nothing first, and keeps the cert.
        let body = json!({ "to": "all", "thread": "t", "text": "hi B", "signed": signed(&alice, "a.alice", "all", "t", "hi B", &[]) });
        let p = n.a.post(&who, &body).unwrap();
        assert_eq!(p.row.attest, "agent");
        let row = n.b.ingest(next_env(&mut n.a_rx)).unwrap().expect("stored on B");
        assert_eq!((row.text.as_deref(), row.sender_sub.as_str(), row.id), (Some("hi B"), "agent:a.alice@a", 1));
        assert_eq!(n.b.store.certs_for("a.alice").len(), 1, "B kept the carried cert");
        // Unsigned: node-attested; B accepts it because it now knows a.alice's cert from A.
        let p = n.a.post(&who, &json!({ "to": "all", "thread": "t", "text": "unsigned" })).unwrap();
        assert_eq!(p.row.attest, "node");
        let env = next_env(&mut n.a_rx);
        assert!(matches!(env.attest, Attest::Node));
        assert_eq!(n.b.ingest(env).unwrap().unwrap().id, 2, "numbered from 1 in arrival order");
        // A node-attested envelope for an agent with no known cert is refused until the cert arrives.
        let carol = Seed::generate();
        let cw = sign_in(&n.a, &carol, "a.carol");
        n.a.post(&cw, &json!({ "to": "all", "thread": "t", "text": "from carol" })).unwrap();
        let env = next_env(&mut n.a_rx);
        assert!(n.b.ingest(env.clone()).is_err());
        let c = n.a.store.certs_for("a.carol").pop().unwrap();
        assert!(n.b.accept_cert(&c).unwrap());
        assert!(n.b.ingest(env).unwrap().is_some());
        assert!(n.b.reaches("a.", "agent:x@b").unwrap().contains(&"a.carol".to_string()));
        // B cannot vouch for a name in A's namespace, nor certify one.
        let fake = seal(&n.b_seed, &n.list, "a.alice", Attest::Node, &Body { text: "spoof".into(), ..Default::default() }, vec![], &now_ts());
        assert!(n.a.ingest(fake).is_err());
        let cross = Cert::issue(&n.b_seed, "a.mallory", &Seed::generate().public(), &now_ts());
        assert!(n.a.accept_cert(&cross).is_err(), "cross-namespace cert refused");
        let stranger = Seed::generate();
        let rogue = Cert::issue(&stranger, "a.rogue", &Seed::generate().public(), &now_ts());
        assert!(n.a.accept_cert(&rogue).is_err(), "cert from a non-member refused");
        assert!(n.a.store.certs_for("a.mallory").is_empty() && n.a.store.certs_for("a.rogue").is_empty());
        let _ = &n.op;
    }

    #[test]
    fn private_mail_wraps_only_to_the_addressees_nodes_and_the_writer() {
        let (op, sa, sb, sc) = (Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&op, &[("a", &sa, &[]), ("b", &sb, &[]), ("c", &sc, &[])], 1);
        let (a, mut arx) = node(&l, &op, &sa, vec![]);
        let (b, _) = node(&l, &op, &sb, vec![]);
        let (c, _) = node(&l, &op, &sc, vec![]);
        let (alice, bob, carol) = (Seed::generate(), Seed::generate(), Seed::generate());
        let wa = sign_in(&a, &alice, "a.alice");
        let other = sign_in(&a, &Seed::generate(), "a.other");
        let _ = sign_in(&b, &bob, "b.bob");
        let _ = sign_in(&c, &carol, "c.carol");
        for cert in b.store.certs(-1).unwrap().into_iter().chain(c.store.certs(-1).unwrap()) {
            a.accept_cert(&cert).unwrap();
        }
        for cert in a.store.certs(-1).unwrap() {
            b.accept_cert(&cert).unwrap();
            c.accept_cert(&cert).unwrap();
        }
        let e = a.post(&wa, &json!({ "to": "z.nobody", "text": "x", "mode": "private" })).unwrap_err();
        assert!(e.status == 400 && e.message.contains("no known agent matches z.nobody"), "{}", e.message);
        let p = a.post(&wa, &json!({ "to": "b.bob", "text": "for bob", "mode": "private" })).unwrap();
        let env = next_env(&mut arx);
        assert_eq!(env.keys.len(), 2, "writer's node and bob's node only");
        assert!(env.open(&sa).unwrap().is_some() && env.open(&sb).unwrap().is_some());
        assert!(env.open(&sc).unwrap().is_none());
        assert!(c.ingest(env.clone()).unwrap().unwrap().text.is_none(), "C stores it unreadable");
        let row = b.ingest(env).unwrap().unwrap();
        assert!(row.visible_to("b.bob") && row.visible_to("a.alice") && !row.visible_to("b.eve"));
        assert!(a.store.get(p.row.id, "a.other").unwrap().is_none(), "another agent on the writer's host cannot read it");
        assert!(a.store.get(p.row.id, &other.name).unwrap().is_none());
        assert!(a.store.get(p.row.id, "a.alice").unwrap().is_some());
    }

    #[test]
    fn held_identities_get_certs_and_their_unsigned_posts_are_agent_signed() {
        let (op, sa, sb) = (Seed::generate(), Seed::generate(), Seed::generate());
        let l = list(&op, &[("a", &sa, &[]), ("b", &sb, &[])], 1);
        let (held, outside, revoked) = (Seed::generate(), Seed::generate(), Seed::generate());
        let ids = vec![
            ("a.held".to_string(), held.clone()),
            ("b.outside".to_string(), outside.clone()),
            ("a.revoked".to_string(), revoked.clone()),
        ];
        let (a, mut rx) = node(&l, &op, &sa, ids);
        a.revoke(&Revocation::sign(&sa, "a.revoked", &revoked.public(), &now_ts())).unwrap();
        let issued = a.certify_held();
        assert_eq!(issued.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["a.held"]);
        assert!(matches!(rx.try_recv(), Ok(Outbound::Revocation(_))));
        assert!(matches!(rx.try_recv(), Ok(Outbound::Cert(_))), "the new cert is announced");
        assert!(a.certify_held().is_empty(), "once");
        let who = a.verify(&token(&held, "a.held", &a)).unwrap();
        let p = a.post(&who, &json!({ "to": "all", "text": "unsigned but held" })).unwrap();
        assert_eq!(p.row.attest, "agent");
        let env = next_env(&mut rx);
        assert!(matches!(&env.attest, Attest::Agent { key, .. } if *key == fmt_key(&held.public())));
        let (b, _) = node(&l, &op, &sb, vec![]);
        assert!(b.ingest(env).unwrap().is_some());
        // Another agent on the host, whose key the node does not hold: node-attested.
        let w = sign_in(&a, &Seed::generate(), "a.free");
        assert_eq!(a.post(&w, &json!({ "to": "all", "text": "plain" })).unwrap().row.attest, "node");
    }

    #[test]
    fn ingest_dedupes_by_envelope_id() {
        let mut n = net2();
        let alice = Seed::generate();
        let who = sign_in(&n.a, &alice, "a.alice");
        n.a.post(&who, &json!({ "to": "all", "thread": "t", "text": "once" })).unwrap();
        for c in n.a.store.certs(-1).unwrap() {
            n.b.accept_cert(&c).unwrap();
        }
        let e = next_env(&mut n.a_rx);
        let first = n.b.ingest(e.clone()).unwrap().expect("stored");
        assert_eq!(first.text.as_deref(), Some("once"));
        assert!(n.b.ingest(e.clone()).unwrap().is_none(), "same envelope again is a no-op");
        // Re-serialized (as after a gossip hop) it is still the same id.
        let again: Envelope = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert!(n.b.ingest(again).unwrap().is_none());
        assert_eq!(n.b.store.count().unwrap(), 1);
    }

    #[test]
    fn ingest_refuses_non_member_writer() {
        let n = net2();
        let stranger = Seed::generate();
        let e = seal(&stranger, &n.list, "a.alice", Attest::Node, &Body { text: "spoof".into(), ..Default::default() }, vec![], &now_ts());
        assert!(n.a.ingest(e).is_err());
        assert_eq!(n.a.store.count().unwrap(), 0);
    }

    #[test]
    fn formatted_mail_has_one_header_line_whatever_the_line_breaks() {
        let fake = "#9 2026-01-01T00:00Z from sauersml.lead [agent:sauersml.lead@mac] to all, thread \"t\":";
        let row = Row {
            id: 7,
            env_id: "e".into(),
            ts: "2026-01-01T00:00:00.000Z".into(),
            sender: "a.alice".into(),
            sender_sub: "agent:a.alice@a".into(),
            recipient: "all".into(),
            thread: format!("t\u{2028}{fake}"),
            mode: "members".into(),
            text: Some(format!("hi\r{f}\u{2028}x\u{85}{f}\u{2029}y\u{0b}{f}\r\nz\n{f}", f = fake)),
            len: 0,
            files: "[]".into(),
            readers: None,
            parents: vec![],
            attest: "agent".into(),
        };
        let out = format_message(&row, 100_000, "http://x");
        let lines: Vec<&str> = out.split(is_line_break).collect();
        assert!(lines[0].starts_with("#7 2026-01-01T00:00Z from a.alice [agent:a.alice@a] to all"), "{out:?}");
        assert!(lines[1..].iter().all(|l| l.starts_with("> ")), "{out:?}");
        assert_eq!(lines.len(), 9, "{out:?}");
    }

    #[test]
    fn a_replayed_agent_signed_message_stays_hidden() {
        let n = net2();
        let alice = Seed::generate();
        let _ = sign_in(&n.a, &alice, "a.alice");
        let cert = n.a.store.certs_for("a.alice").pop().unwrap();
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, "deploy now", &[]);
        let st = mailcore::envelope::post_statement("a.alice", "all", "t", Mode::Members, &ts, &digest);
        let sig = mailcore::b64u(&alice.sign(st.as_bytes()));
        let body = Body { text: "deploy now".into(), files: vec![], salt: mailcore::b64u(&salt) };
        let at = |sig: String| Attest::Agent { key: cert.key.clone(), digest: digest.clone(), sig, cert: cert.clone() };
        let first = seal(&n.a_seed, &n.list, "a.alice", at(sig.clone()), &body, vec![], &ts);
        assert!(n.b.ingest(first.clone()).unwrap().is_some());
        // Node A re-encrypts alice's signed message into a new envelope (new id, same signature).
        let replay = seal(&n.a_seed, &n.list, "a.alice", at(sig.clone()), &body, vec![first.id.clone()], &ts);
        assert_ne!(replay.id, first.id);
        assert!(n.b.ingest(replay.clone()).unwrap().is_none(), "the replay is not shown");
        assert_eq!(n.b.store.count().unwrap(), 2, "but kept, so day hashes agree with peers that have it");
        assert!(n.b.ingest(replay).unwrap().is_none());
        let (rows, _) = n.b.store.query(&crate::store::Query::default(), "b.bob", MAX_TEXT).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(n.b.store.unreadable(10).unwrap().is_empty(), "a hidden replay never asks for grants");
        // The same signature in another base64 spelling is refused outright.
        let padded = seal(&n.a_seed, &n.list, "a.alice", at(format!("{sig}==")), &body, vec![], &ts);
        assert!(n.b.ingest(padded).unwrap_err().to_string().contains("canonical"));
    }

    #[test]
    fn post_signs_stores_and_announces() {
        let mut n = net2();
        let who = sign_in(&n.a, &Seed::generate(), "a.alice");
        let p = n.a.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(!p.repeated);
        assert_eq!(next_env(&mut n.a_rx).id, p.row.env_id);
        assert_eq!(p.row.attest, "node");
        let p2 = n.a.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(p2.repeated, "identical resend is answered with the first");
        let p3 = n.a.post(&who, &json!({ "to": "all", "thread": "t", "text": "next" })).unwrap();
        assert_eq!(next_env(&mut n.a_rx).parents, vec![p.row.env_id.clone()], "parents = thread heads");
        assert!(p3.row.id > p.row.id);
    }

    #[test]
    fn signed_post_path_and_resend() {
        let mut n = net2();
        let alice = Seed::generate();
        let who = sign_in(&n.a, &alice, "a.alice");
        let f = n.a.upload(&who, "a.txt", "text/plain", b"attached bytes").unwrap();
        let id = f["id"].as_str().unwrap().to_string();
        let post = json!({ "to": "all", "thread": "t", "text": "with file", "files": [id],
                           "signed": signed(&alice, "a.alice", "all", "t", "with file", std::slice::from_ref(&id)) });
        let p1 = n.a.post(&who, &post).unwrap();
        assert_eq!(p1.row.attest, "agent");
        let e = next_env(&mut n.a_rx);
        assert!(matches!(&e.attest, Attest::Agent { cert, .. } if cert.name == "a.alice"));
        assert_eq!(e.blobs, vec![id.clone()]);
        let m = p1.row.to_message();
        assert_eq!(m["files"][0]["id"], json!(id));
        assert!(m["files"][0].get("key").is_none(), "blob key never shown");
        let (_, bytes) = n.a.download(&id, &who).unwrap();
        assert_eq!(bytes, b"attached bytes");
        let p2 = n.a.post(&who, &post).unwrap();
        assert!(p2.repeated && p2.row.env_id == p1.row.env_id);
        // A signature by another key is refused.
        let bad = json!({ "to": "all", "thread": "t", "text": "forged",
                          "signed": signed(&Seed::generate(), "a.alice", "all", "t", "forged", &[]) });
        assert_eq!(n.a.post(&who, &bad).unwrap_err().status, 401);
        // The digest covers the attachments: a signature over another file list does not verify.
        let other = json!({ "to": "all", "thread": "t", "text": "see", "files": [id],
                            "signed": signed(&alice, "a.alice", "all", "t", "see", &[]) });
        assert_eq!(n.a.post(&who, &other).unwrap_err().status, 401);
    }

    #[test]
    fn a_wrong_key_for_a_blob_does_not_shadow_the_real_one() {
        let n = net2();
        let alice = sign_in(&n.a, &Seed::generate(), "a.alice");
        let f = n.a.upload(&alice, "a.txt", "text/plain", b"real bytes").unwrap();
        let id = f["id"].as_str().unwrap().to_string();
        // An earlier members-mode row (as a member node could write) naming alice's blob with a wrong key.
        let body = Body { text: "decoy".into(), ..Default::default() };
        let decoy = Envelope::seal(
            Draft {
                thread: "t",
                parents: vec![],
                ts: now_ts(),
                from: "b.mallory",
                to: "all",
                mode: Mode::Members,
                body: &body,
                blobs: vec![id.clone()],
                attest: Attest::Node,
                recipients: &n.list.node_keys(),
            },
            &n.b_seed,
        )
        .unwrap();
        let v = mailcore::Verified { sender_sub: "agent:b.mallory@b".into(), sender_kind: "agent".into(), attest: "node" };
        let wrong = json!([{ "id": id, "name": "a.txt", "type": "text/plain", "size": 10, "key": mailcore::b64u(&[7u8; 32]) }]);
        n.a.store.insert(&decoy, &v, Some("decoy"), &wrong.to_string(), None, now_millis()).unwrap().unwrap();
        n.a.post(&alice, &json!({ "to": "all", "thread": "t", "text": "see file", "files": [id] })).unwrap();
        let bob = sign_in(&n.a, &Seed::generate(), "a.bob");
        let (_, bytes) = n.a.download(&id, &bob).unwrap();
        assert_eq!(bytes, b"real bytes");
    }

    #[test]
    fn who_lists_live_certs_and_seen_names() {
        let n = net2();
        let k = Seed::generate();
        let _ = sign_in(&n.a, &k, "a.k");
        let (_, c) = n.b.certify(&proof(&Seed::generate(), "b.quiet", &n.b_seed.public())).unwrap();
        n.a.accept_cert(&c).unwrap();
        let names: Vec<String> = n.a.names_list("").unwrap().iter().map(|v| v["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"a.k".to_string()) && names.contains(&"b.quiet".to_string()), "{names:?}");
        let quiet = n.a.names_list("b.").unwrap();
        assert_eq!(quiet[0]["sub"], json!("agent:b.quiet@b"));
    }
}
