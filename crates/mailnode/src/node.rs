//! The node's mail logic, shared by the compat API, MCPL and replication: accept a local send (seal, sign, store,
//! announce), accept a replicated envelope (verify, decrypt if we can, store), and expose local reads
//! (names, reaches, addressed rows, message formatting).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use mailcore::addr::{addressed_to, is_broadcast, norm};
use mailcore::envelope::{Draft, PostStatement};
use mailcore::keys::{fmt_key, parse_key, PublicKey, Seed};
use mailcore::members::{self, Agent};
use mailcore::{now_millis, now_ts, ts_from_millis, Attest, Body, Cert, Envelope, MemberList, Mode, Revocation};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, watch};
use unicode_normalization::UnicodeNormalization;

use crate::store::{Row, Store, MAX_TEXT};

pub const MAX_FIELD: usize = 120;
const REPEAT_MS: i64 = 10 * 60 * 1000;
const RATE_WINDOW_MS: i64 = 3_600_000;

/// An HTTP-style error: status and message, for API clients.
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
    pub key: String,
    pub name: String,
    pub sub: String,
    pub exp_ms: i64,
}

pub struct Posted {
    pub row: Row,
    pub reaches: Vec<String>,
    pub repeated: bool,
}

/// Node settings beyond the store and keys.
#[derive(Default)]
pub struct Opts {
    pub identities: Vec<(String, Seed)>,
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
    /// Who this host accepts now: pinned agents and live certificates (`MemberList::agents`). Kept current by
    /// `refresh` whenever the trust file, a certificate or a revocation changes.
    roster: RwLock<Vec<Agent>>,
    /// Serialize local issuance decisions with other claims, owner revocations and namespace edits.
    issuance: Mutex<()>,
    /// Bumped on every trust change, so open sessions re-check their caller at once.
    pub trust: watch::Sender<u64>,
    /// Certificates and revocations to gossip (JSON, tagged {"cert": …} or {"revocation": …}).
    pub trust_out: broadcast::Sender<String>,
    pub encryption_key: RwLock<Option<mailcore::node_key::NodeEncryptionKey>>,
    pub seed: Seed,
    pub opts: Opts,
    pub events: broadcast::Sender<i64>,
    pub outbound: mpsc::Sender<Envelope>,
    rates: Mutex<HashMap<(String, &'static str), Vec<i64>>>,
    touched: Mutex<HashMap<String, i64>>,
    auth_seen: Mutex<HashSet<(String, &'static str)>>,
}

impl Node {
    pub fn new(
        store: Store,
        members: MemberList,
        seed: Seed,
        opts: Opts,
        outbound: mpsc::Sender<Envelope>,
    ) -> Node {
        let (events, _) = broadcast::channel(4096);
        let (trust_out, _) = broadcast::channel(256);
        let node = Node {
            store,
            encryption_key: RwLock::new(None),
            roster: RwLock::new(Vec::new()),
            issuance: Mutex::new(()),
            trust: watch::channel(0).0,
            trust_out,
            members: RwLock::new(members),
            seed,
            opts,
            events,
            outbound,
            rates: Mutex::new(HashMap::new()),
            touched: Mutex::new(HashMap::new()),
            auth_seen: Mutex::new(HashSet::new()),
        };
        node.refresh();
        node
    }

    /// Recompute who this host accepts (now: any known revocation counts) and wake open sessions.
    pub fn refresh(&self) {
        let list = self.members.read().unwrap();
        let mut roster = self.roster.write().unwrap();
        // Serialize snapshot publication so a slow refresh cannot reinstate a revoked certificate.
        *roster = match self.store.certs_at(None, i64::MAX).and_then(|c| crate::homes::current(&self.store, c, i64::MAX)) {
            Ok(certs) => list.agents(&certs, &|_| None, i64::MAX),
            Err(e) => {
                tracing::error!("reading certificate state: {e:#}");
                list.agents(&[], &|_| None, i64::MAX)
            }
        };
        self.trust.send_modify(|g| *g += 1);
    }

    pub fn current_encryption_key(&self) -> Option<mailcore::node_key::NodeEncryptionKey> {
        let epoch = now_millis().div_euclid(mailcore::node_key::ROTATION_MS);
        self.encryption_key.read().unwrap().as_ref().filter(|k| k.epoch == epoch).cloned()
    }

    /// Signed current-interval records for the node identities in the requested audience.
    pub fn recipient_node_keys(&self, members: &MemberList, audience: &[PublicKey]) -> Result<Vec<mailcore::node_key::NodeEncryptionKey>> {
        let now = now_millis();
        let nodes: HashSet<_> = members.nodes.iter().map(|n| n.key.as_str()).collect();
        let pins: Vec<_> = audience.iter().map(fmt_key).filter(|key| nodes.contains(key.as_str())).collect();
        let epoch = now.div_euclid(mailcore::node_key::ROTATION_MS);
        let mut records = self.store.peer_encryption_keys(&pins, epoch)?;
        if let Some(own) = self.current_encryption_key().filter(|k| pins.contains(&k.node)) {
            records.push(own);
        }
        for record in &records {
            anyhow::ensure!(pins.contains(&record.node), "encryption key outside requested audience");
            record.verify(&parse_key(&record.node)?, &members.network, now)?;
        }
        Ok(records)
    }

    pub fn agents(&self) -> Vec<Agent> {
        self.roster.read().unwrap().clone()
    }

    fn me(&self) -> PublicKey {
        self.seed.public()
    }
    pub fn members_seq(&self) -> u64 {
        self.members.read().unwrap().seq
    }

    /// Reload only from the local configuration file. Remote input never changes peer trust.
    pub fn reload_members(&self, list: &MemberList) -> Result<bool> {
        let _guard = self.issuance.lock().unwrap();
        let mut cur = self.members.write().unwrap();
        if *list == *cur { return Ok(false); }
        anyhow::ensure!(list.network == cur.network && list.seq > cur.seq, "trust changes require the same network and a higher revision");
        anyhow::ensure!(list.is_node(&self.seed.public()), "local node key missing from trust file");
        self.store.bind_roster(&self.seed.public(), list)?;
        *cur = list.clone();
        drop(cur);
        self.refresh();
        for m in &list.members {
            let _ = self.store.seen(&m.name, &m.sub, 0);
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
            let roster = self.roster.read().unwrap();
            mailcore::agent_token::verify(token, &roster, &self.seed.public(), now)
        };
        let c = checked.map_err(|r| match r {
            Refusal::NotMember(s) => ApiError::new(403, format!(
                "{s}; islandmail.py gets a certificate from this node on first use (POST /api/agents), or pin the agent in this host's trust file")),
            Refusal::Bad(s) => ApiError::new(401, format!("token refused: {s}")),
        })?;
        if !self.store.use_token(&c.name, &c.jti, c.exp_ms, now)? {
            return Err(ApiError::new(401, "token refused: already used (agent tokens are single-use; mint a fresh one)"));
        }
        self.note_auth(&c.name, "agent-token");
        self.touch(&c.name, &c.sub);
        Ok(Caller { key: c.key, name: c.name, sub: c.sub, exp_ms: c.exp_ms })
    }

    pub fn active(&self, who: &Caller) -> bool {
        let me = self.me();
        who.exp_ms > now_millis() && self.roster.read().unwrap().iter().any(|a| {
            mailcore::addr::same(&a.name, &who.name) && fmt_key(&a.key) == who.key && a.sub == who.sub
                && (a.pinned || a.homes.contains(&me))
        })
    }

    /// The caller's entry in the roster.
    fn agent_of(&self, agents: &[Agent], who: &Caller) -> Result<Agent, ApiError> {
        parse_key(&who.key).ok().and_then(|k| members::find(agents, &who.name, &k)).filter(|a| a.sub == who.sub).cloned()
            .ok_or_else(|| ApiError::new(401, "session expired or membership changed"))
    }

    /// A certificate to carry in the sender's envelopes (this node's own first), so receivers can check the sender
    /// before certificates replicate. None for an agent known here only by its pin.
    fn carried(&self, a: &Agent, at_ms: i64) -> Option<Cert> {
        let me = fmt_key(&self.me());
        a.certs.iter().filter(|c| c.issued_by(at_ms)).min_by_key(|c| c.node != me).cloned()
    }

    /* Certificates */

    /// POST /api/agents (loopback API): certify an agent of this host. Ok((status, {"cert": …})).
    pub fn certify(&self, body: &Value) -> Result<(u16, Value), ApiError> {
        let f = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let (name, key) = (f("name"), f("key"));
        let me = self.me();
        let k = mailcore::cert::check_issuance(name, key, f("ts"), f("sig"), &me, now_millis())
            .map_err(|e| ApiError::new(400, format!("certificate request refused: {e}")))?;
        if mailcore::home::is_home_name(name) || body.get("aid1").is_some() {
            return self.certify_home(body, name, key, k);
        }
        let _guard = self.issuance.lock().unwrap();
        let list = self.members.read().unwrap().clone();
        let mine = list.node_by_key(&me).ok_or_else(|| ApiError::new(503, "this node is not in its own trust file"))?;
        if !mine.covers(name) {
            let ns = if mine.names.is_empty() { "none".to_string() } else { mine.names.join(", ") };
            return Err(ApiError::new(403, format!(
                "{name} is not in this host's names ({ns}); add it to this node's \"names\" in the trust file")));
        }
        if self.store.revoked_at(&fmt_key(&me), key)?.is_some() {
            return Err(ApiError::new(403, "this node revoked that key; make a new one"));
        }
        if !list.permits_agent_key(name, &k) {
            return Err(ApiError::new(409, "agent name, subject or key conflicts with a pin in this host's trust file"));
        }
        if let Some(c) = self.store.cert(&fmt_key(&me), key)? {
            if !mailcore::addr::same(&c.name, name) {
                return Err(ApiError::new(409, format!("this key is already certified here as {}", c.name)));
            }
            return Ok((200, json!({ "cert": c })));
        }
        let agents = self.agents();
        if let Some(a) = members::named(&agents, name).find(|a| a.key != k) {
            let by = if a.homes.contains(&me) { "this node".to_string() } else {
                a.homes.iter().filter_map(|h| list.node_by_key(h)).map(|n| n.name.clone()).collect::<Vec<_>>().join(", ")
            };
            return Err(ApiError::new(409, format!(
                "{name} is already certified by {by} with another key; use that key (copy its identity file) or pick another name")));
        }
        self.rate("node", "certificate", 60)?;
        let cert = Cert::issue(&self.seed, name, &k, &now_ts());
        self.store.put_cert(&cert)?;
        self.refresh();
        let _ = self.trust_out.send(json!({ "cert": cert }).to_string());
        tracing::info!("certified {name} {}", fmt_key(&k));
        Ok((201, json!({ "cert": cert })))
    }

    /// POST /api/agents with an `aid1` token: certify a home name (`local@suffix`) whose home this host trusts. Body
    /// {name, key, ts, sig, aid1, jti, pop, rekey?}: `sig` as for local names; `pop` is the agent key's proof of
    /// possession of the token at `ts` (`aid1::present_statement`); `rekey` {key, sig} hands the name over from its
    /// pinned key. The certificate carries the token and proof, so peers check it against their own trust file.
    fn certify_home(&self, body: &Value, name: &str, key: &str, k: PublicKey) -> Result<(u16, Value), ApiError> {
        use mailcore::home::{HomeProof, Rekey};
        let f = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !mailcore::home::is_home_name(name) {
            return Err(ApiError::new(400, "an aid1 token enrolls only a home name (name@home-suffix); local names need none"));
        }
        if body.get("aid1").is_none() {
            return Err(ApiError::new(403, format!(
                "{name} is under a home's suffix: enroll with a key-bound aid1 token from that home (islandmail.py enroll)")));
        }
        let rekey = match body.get("rekey") {
            None | Some(Value::Null) => None,
            Some(v) => Some(serde_json::from_value::<Rekey>(v.clone()).map_err(|_| ApiError::new(400, "rekey must be {key, sig}"))?),
        };
        let proof = HomeProof { aid1: f("aid1"), ts: f("ts"), jti: f("jti"), pop: f("pop"), rekey };
        let now = now_millis();
        let me = self.me();
        let _guard = self.issuance.lock().unwrap();
        let list = self.members.read().unwrap().clone();
        let homes: Vec<_> = list.homes.iter().filter(|h| h.covers(name)).collect();
        if homes.is_empty() {
            return Err(ApiError::new(403, format!("no home in this host's trust file vouches for {name}")));
        }
        let mut why = String::new();
        let Some(token) = homes.iter().find_map(|h| h.check(name, key, &proof, now).map_err(|e| why = format!("{e:#}")).ok()) else {
            tracing::warn!("enrollment of {name} refused: {why}");
            return Err(ApiError::new(403, format!("enrollment refused: {why}")));
        };
        // Peers refuse a certificate dated before the token's iat; a home clock slightly ahead dates it at iat.
        let issued = now.max((token.iat * 1000.0).ceil() as i64);
        if self.store.revoked_at(&fmt_key(&me), key)?.is_some() {
            return Err(ApiError::new(403, "this node revoked that key; make a new one"));
        }
        if !list.permits_agent_key(name, &k) {
            return Err(ApiError::new(409, "agent name, subject or key conflicts with a pin in this host's trust file"));
        }
        if let Some(c) = self.store.cert(&fmt_key(&me), key)? {
            if !mailcore::addr::same(&c.name, name) {
                return Err(ApiError::new(409, format!("this key is already certified here as {}", c.name)));
            }
            return Ok((200, json!({ "cert": c })));
        }
        let cert = Cert::issue_home(&self.seed, name, &k, &ts_from_millis(issued), proof);
        if !list.accepts(&cert) {
            return Err(ApiError::new(403, "enrollment refused: the certificate would not verify under this trust file"));
        }
        if let Err(why) = crate::homes::admit(&self.store, &cert, false)? {
            return Err(ApiError::new(409, format!("{name} is pinned to another key here: {why}")));
        }
        if !self.store.use_token(name, &format!("pop:{}", cert.home.as_ref().map_or("", |p| &p.jti)), now + 600_000, now)? {
            return Err(ApiError::new(401, "proof of possession already used; sign a fresh one"));
        }
        self.rate("node", "certificate", 60)?;
        let _ = crate::homes::admit(&self.store, &cert, true)?;
        self.store.put_cert(&cert)?;
        self.refresh();
        let _ = self.trust_out.send(json!({ "cert": cert }).to_string());
        tracing::info!("certified {name} {} with a token from its home", fmt_key(&k));
        Ok((201, json!({ "cert": cert })))
    }

    /// POST /api/revocations: the host owner (holding the node key) revokes this node's certificates for a name.
    /// Body {name, ts, sig}: sig is the node key's signature over `revoke_statement`.
    pub fn revoke(&self, body: &Value) -> Result<Vec<Revocation>, ApiError> {
        let f = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let (name, ts) = (f("name"), f("ts"));
        let me = self.me();
        let t = mailcore::parse_ts(ts).ok_or_else(|| ApiError::new(400, "ts must be YYYY-MM-DDTHH:MM:SS.mmmZ"))?;
        let sig = mailcore::b64u_decode(f("sig")).unwrap_or_default();
        if (t - now_millis()).abs() > 300_000
            || !mailcore::keys::verify(&me, revoke_statement(name, &fmt_key(&me), ts).as_bytes(), &sig) {
            return Err(ApiError::new(401, "revocation requests are signed by this node's key (mailnode revoke CONFIG NAME)"));
        }
        let _guard = self.issuance.lock().unwrap();
        let out = self.store.revoke_local(&self.seed, name, t)?
            .ok_or_else(|| ApiError::new(409, "revocation request already used or superseded"))?;
        for r in &out {
            let _ = self.trust_out.send(json!({ "revocation": r }).to_string());
            tracing::info!("revoked {} {}", r.name, r.key);
        }
        self.refresh();
        Ok(out)
    }

    /// A certificate from a peer: kept if this host trusts its node for the name. Ok(true) when new here.
    pub fn take_cert(&self, c: &Cert) -> Result<bool> {
        anyhow::ensure!(self.members.read().unwrap().accepts(c), "certificate for {:?} from a node not trusted for that name", c.name);
        if let Err(why) = crate::homes::admit(&self.store, c, true)? {
            anyhow::bail!("certificate for {:?} refused: {why}", c.name);
        }
        let new = self.store.put_cert(c)?;
        if new { self.refresh(); }
        Ok(new)
    }

    /// A revocation from a peer: kept if signed by a node on the trust file. Ok(true) when new here.
    pub fn take_revocation(&self, r: &Revocation) -> Result<bool> {
        r.check()?;
        anyhow::ensure!(self.members.read().unwrap().is_node(&parse_key(&r.node)?), "revocation from a node that is not trusted");
        let new = self.store.put_revocation(r)?;
        if new { self.refresh(); }
        Ok(new)
    }

    /// Held identities (identities_dir) in this node's names get a certificate at startup, so the node can sign for
    /// them.
    pub fn certify_identities(&self) {
        let me = self.me();
        let Some(mine) = self.members.read().unwrap().node_by_key(&me).cloned() else { return };
        for (name, seed) in &self.opts.identities {
            if !mine.covers(name) || !mailcore::cert::valid_name(name) { continue; }
            let key = fmt_key(&seed.public());
            let ts = now_ts();
            let sig = mailcore::b64u(&seed.sign(mailcore::cert::certify_statement(name, &key, &fmt_key(&me), &ts).as_bytes()));
            match self.certify(&json!({ "name": name, "key": key, "ts": ts, "sig": sig })) {
                Ok((201, _)) => tracing::info!("certified held identity {name}"),
                Ok(_) => {}
                Err(e) => tracing::warn!("held identity {name}: {}", e.message),
            }
        }
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
        if !self.active(who) {
            return Err(ApiError::new(401, "session expired or membership changed"));
        }
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
                "to is required: names (sauersml.glead), a team prefix ending in a dot (ops.), or all",
            ));
        }
        let to = field(to_v.unwrap(), "to", valid_to)?;
        let thread = field(body.get("thread").unwrap_or(&json!("general")), "thread", |s| {
            !s.chars().any(|c| c.is_control())
        })?;
        let text = clean_text(body.get("text"), !files.is_empty())?;
        let mode = match body.get("mode") {
            None => Mode::Members,
            Some(v) => serde_json::from_value(v.clone()).map_err(|_| ApiError::new(400, "mode must be members or private"))?,
        };
        self.rate(&who.sub, "message", 120)?;
        if is_broadcast(&to) {
            self.rate(&who.sub, "broadcast", 20)?;
        }
        let _ = self.store.seen(&who.name, &who.sub, now_millis());

        let members = self.members.read().unwrap().clone();
        let agents = self.agents();
        let me_agent = self.agent_of(&agents, who)?;
        // Room fields: the signed JSON a client sends, or (when the node signs) built from room/reply_to/event.
        let meta_raw = match body.get("meta") {
            Some(Value::String(m)) => m.clone(),
            Some(Value::Null) | None if body.get("signed").is_none() => build_meta(body, &text, &thread)?,
            Some(Value::Null) | None => String::new(),
            Some(_) => return Err(ApiError::new(400, "meta must be the JSON text of the room fields")),
        };
        let meta = mailcore::room::Meta::parse(&meta_raw).map_err(|e| ApiError::new(400, format!("{e}")))?;
        let recipients = match &meta.room {
            Some(room) => {
                if *room != thread {
                    return Err(ApiError::new(400, "meta.room must be the thread"));
                }
                let plan = self.room_plan(room, &who.name, meta.event.as_ref(), &members, &agents)?;
                if plan.to != to || plan.mode != mode {
                    return Err(ApiError::new(400, format!(
                        "a post in room {room} goes to {:?} in {} mode (GET /api/recipients?room=…)", plan.to, plan.mode.as_str())));
                }
                plan.keys
            }
            None => {
                if !meta.grant.is_empty() && mode != Mode::Private {
                    return Err(ApiError::new(400, "key grants are private mail to the new member"));
                }
                Self::recipients(&members, &agents, &to, &who.name, mode)?
            }
        };
        // Accept the client signature or sign with the caller's enrolled local key.
        let (ts, attest, salt) = match body.get("signed") {
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
                let key = me_agent.key;
                let digest = mailcore::envelope::post_digest_meta(&salt, &text, &files, &meta_raw)?;
                let st = PostStatement {
                    from: &who.name, sub: &me_agent.sub, to: &to, thread: &thread, mode,
                    ts: &ts, digest: &digest, blobs: &file_ids, recipients: &recipients,
                }.signing_bytes(&members);
                let sig = s["sig"].as_str().unwrap_or("").to_string();
                let ok = mailcore::b64u_decode(&sig).is_some_and(|b| mailcore::keys::verify(&key, &st, &b));
                if !ok {
                    return Err(ApiError::new(401, format!("signed post: signature does not verify against {}'s key", who.name)));
                }
                // Canonical encoding (the one every node dedupes by); a client resending the same signed post gets
                // the first copy back instead of a second envelope.
                let sig = mailcore::b64u_decode(&sig).map(|b| mailcore::b64u(&b)).unwrap_or(sig);
                if let Some(row) = self.store.by_agent_sig(&sig)?.filter(|row| row.visible_to(who)) {
                    let reaches = self.reaches(&row.recipient, &who.sub);
                    return Ok(Posted { row, reaches, repeated: true });
                }
                (ts, Attest::Agent { key: fmt_key(&key), digest, sig, cert: self.carried(&me_agent, t) }, mailcore::b64u(&salt))
            }
            // The node holds the caller's own agent key (identities_dir) and it is the caller's key on the member list:
            // sign for it, so the envelope carries a signature instead of the caller's bearer token (README.md, Security).
            None => {
                let (key, seed) = self.local_key(who).ok_or_else(|| ApiError::new(400,
                    "sign the post with your agent key or configure identities_dir on this node"))?;
                if file_ids.is_empty() && meta.event.is_none() && meta.grant.is_empty() {
                    let since = ts_from_millis(now_millis() - REPEAT_MS);
                    if let Some(row) = self.store.repeat(who, &since, &to, &thread, &text)?
                        .filter(|r| r.mode == mode.as_str() && r.visible_to(who) && r.sealed_to(&recipients)) {
                        let reaches = self.reaches(&to, &who.sub);
                        return Ok(Posted { row, reaches, repeated: true });
                    }
                }
                let salt = mailcore::random_bytes::<16>();
                let t = now_millis();
                let ts = ts_from_millis(t);
                let digest = mailcore::envelope::post_digest_meta(&salt, &text, &files, &meta_raw)?;
                let st = PostStatement {
                    from: &who.name, sub: &me_agent.sub, to: &to, thread: &thread, mode,
                    ts: &ts, digest: &digest, blobs: &file_ids, recipients: &recipients,
                }.signing_bytes(&members);
                let sig = mailcore::b64u(&seed.sign(&st));
                (ts, Attest::Agent { key, digest, sig, cert: self.carried(&me_agent, t) }, mailcore::b64u(&salt))
            }
        };
        let parents = self.store.heads(&thread)?;
        let b = Body { text: text.clone(), files: files.clone(), salt, meta: meta_raw.clone() };
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
            .verify(&members, &agents, now_millis())
            .and_then(|v| env.check_body(&b).map(|_| v))
            .map_err(|e| ApiError::new(503, format!("this node cannot write mail: {e}")))?;
        let readers = (mode == Mode::Private).then(|| readers_of(&agents, &env));
        let files_json = serde_json::to_string(&files).map_err(anyhow::Error::from)?;
        let extra = crate::store::Extra::of(&meta_raw, &meta);
        let row = match self.store.insert_with(&env, &v, Some(&text), &files_json, readers.as_deref(), now_millis(), &extra)? {
            Some(row) => row,
            None => {
                let Attest::Agent { sig, .. } = &env.attest;
                let row = self.store.by_agent_sig(sig)?.filter(|r| r.visible_to(who))
                    .ok_or_else(|| ApiError::new(409, "signed message already stored"))?;
                let reaches = self.reaches(&to, &who.sub);
                return Ok(Posted { row, reaches, repeated: true });
            }
        };
        if !meta.grant.is_empty() {
            self.apply_grant(&env, &meta, &agents)?;
        }
        let _ = self.events.send(row.id);
        let _ = self.outbound.try_send(env);
        let reaches = match &meta.room {
            Some(_) if !to.starts_with("room:") => self.reaches(&to, &who.sub),
            Some(room) => self.room_reaches(room, &who.name),
            None => self.reaches(&to, &who.sub),
        };
        Ok(Posted { row, reaches, repeated: false })
    }

    /// The caller's agent key, if this node holds it: an identity named like the caller with the caller's key
    /// (which the token check already tied to the pin or certificate). (key string, seed)
    fn local_key(&self, who: &Caller) -> Option<(String, Seed)> {
        self.opts
            .identities
            .iter()
            .find(|(n, s)| mailcore::addr::same(n, &who.name) && fmt_key(&s.public()) == who.key)
            .map(|(_, s)| (who.key.clone(), s.clone()))
    }

    /// The exact keys a post is sealed to. Members mode: every pinned agent and node key and every certified agent
    /// key. Private: each addressed agent's and the sender's key and home nodes.
    pub fn recipients(members: &MemberList, agents: &[Agent], to: &str, from: &str, mode: Mode)
                      -> Result<Vec<PublicKey>, ApiError> {
        if mode == Mode::Members {
            let mut keys = members.all_keys();
            keys.extend(agents.iter().map(|a| a.key));
            keys.sort();
            keys.dedup();
            if keys.len() > mailcore::envelope::MAX_KEYS {
                return Err(ApiError::new(503, "more recipient keys than an envelope holds"));
            }
            return Ok(keys);
        }
        if !agents.iter().any(|a| addressed_to(to, &[&a.name])) {
            return Err(ApiError::new(400, "no trusted agent matches the private recipient"));
        }
        Ok(members::private_keys(agents, to, from))
    }

    /// POST /api/files: encrypt and keep the upload until a message attaches it.
    pub fn upload(&self, who: &Caller, name: &str, ty: &str, data: &[u8]) -> Result<Value, ApiError> {
        if !self.active(who) { return Err(ApiError::new(401, "session expired or membership changed")); }
        if data.len() > MAX_FILE {
            return Err(ApiError::new(413, format!("body is over {MAX_FILE} bytes")));
        }
        self.rate(&who.sub, "upload", 60)?;
        let (blob, key) = mailcore::crypto::seal_blob(data)?;
        let id = blake3::hash(&blob).to_hex().to_string();
        if !self.store.save_upload(&id, &blob, &who.key, name, ty, data.len() as i64,
                                   &mailcore::b64u(&key), now_millis(), MAX_FILES_PER_SUB)? {
            return Err(ApiError::new(507, "attachment storage quota exceeded"));
        }
        Ok(json!({ "id": id, "name": name, "type": ty, "size": data.len() }))
    }

    /// The file reference {id, name, type, size, key} for `id` the viewer may use, and the plaintext if the blob is
    /// here: the first reference (own upload, then readable messages, oldest first) whose key opens the blob, so a
    /// message written with a wrong key for someone else's blob cannot shadow the real one.
    fn usable_file(&self, id: &str, who: &Caller) -> Result<Option<FileRef>, ApiError> {
        if !mailcore::envelope::is_id(id) { return Ok(None); }
        let refs = self.store.find_files(id, who)?;
        let Some(first) = refs.first().cloned() else { return Ok(None) };
        let Some(blob) = self.store.get_blob(id)? else { return Ok(Some((first, None))) };
        for f in refs {
            let key: Option<[u8; 32]> = f["key"].as_str().and_then(mailcore::b64u_decode).and_then(|k| k.try_into().ok());
            if let Some(Ok(plain)) = key.map(|k| mailcore::crypto::open_blob(&blob, &k)) {
                if f["size"].as_u64() == Some(plain.len() as u64) { return Ok(Some((f, Some(plain)))); }
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
        // Who this host accepted as the sender at the envelope's time: pins, stored certificates and the one the
        // envelope carries. A revocation counts against mail dated at or after it.
        let carried = env.carried_cert().filter(|c| members.accepts(c)
            && crate::homes::admit(&self.store, c, true).is_ok_and(|r| r.is_ok())).cloned();
        let ts = env.ts_ms();
        let mut certs = self.store.certs_at(Some(&env.from), ts)?;
        if let Some(c) = &carried {
            if self.store.revoked_at(&c.node, &c.key)?.is_none_or(|t| ts < t) {
                certs.push(c.clone());
            }
        }
        let certs = crate::homes::current(&self.store, certs, ts)?;
        let at = members.agents(&certs, &|_| None, ts);
        let v = env.verify(&members, &at, now_millis())?;
        let keys = std::iter::once(&self.seed).chain(self.opts.identities.iter().map(|(_, s)| s));
        let mut body = env.open_for(keys)?;
        if let Some(b) = &body {
            env.check_body(b)?;
            anyhow::ensure!(b.text.encode_utf16().count() <= MAX_TEXT as usize, "message exceeds text limit");
        }
        // Key grants that arrived before the envelope: keep the ones whose key opens it, in its own room.
        let grants = self.checked_grants(&env)?;
        if body.is_none() {
            if let Some((_, b)) = grants.first() {
                env.check_body(b)?;
                anyhow::ensure!(b.text.encode_utf16().count() <= MAX_TEXT as usize, "message exceeds text limit");
                body = Some(b.clone());
            }
        }
        // Keep the carried certificate (best effort: a node at its certificate cap still delivers the mail).
        if let Some(c) = &carried {
            if self.store.put_cert(c).unwrap_or(false) {
                self.refresh();
            }
        }
        let files_json = body.as_ref().map(|b| serde_json::to_string(&b.files)).transpose()?.unwrap_or_else(|| "[]".into());
        let (meta_raw, meta) = match &body {
            Some(b) => match mailcore::room::Meta::parse(&b.meta) {
                Ok(m) => (b.meta.clone(), m),
                Err(e) => {
                    tracing::warn!("message {} has invalid room fields, shown as plain mail: {e:#}", &env.id[..12]);
                    (String::new(), Default::default())
                }
            },
            None => (String::new(), Default::default()),
        };
        let extra = crate::store::Extra::of(&meta_raw, &meta);
        let text = body.map(|b| b.text);
        let agents = self.agents();
        let readers = (env.mode == Mode::Private).then(|| readers_of(&agents, &env));
        let Some(row) =
            self.store.insert_with(&env, &v, text.as_deref(), &files_json, readers.as_deref(), now_millis(), &extra)?
        else {
            return Ok(None);
        };
        if env.mode == Mode::Private {
            let granted: Vec<String> = self.store.grants_for(&env.id)?.into_iter().flat_map(|g| g.2).collect();
            if !granted.is_empty() {
                self.store.add_readers(&env.id, &names_with_keys(&agents, &granted))?;
            }
        }
        if !meta.grant.is_empty() {
            self.apply_grant(&env, &meta, &agents)?;
        }
        let _ = self.store.seen(&env.from, &v.sender_sub, env.ts_ms());
        let row = Arc::new(row);
        let _ = self.events.send(row.id);
        Ok(Some(row))
    }

    /* Names */

    pub fn names_list(&self, prefix: &str) -> Result<Vec<Value>> {
        let p = norm(prefix);
        Ok(self
            .store.names(&self.agents().iter()
                .map(|a| mailcore::Member { name: a.name.clone(), sub: a.sub.clone(), key: fmt_key(&a.key) })
                .collect::<Vec<_>>())?
            .into_iter()
            .filter(|r| p.is_empty() || norm(&r.0).starts_with(&p))
            .map(|r| json!({ "name": r.0, "sub": r.1, "last_active": ts_from_millis(r.2) }))
            .collect())
    }

    pub fn reaches(&self, to: &str, sender_sub: &str) -> Vec<String> {
        let agents = self.roster.read().unwrap();
        let mut out: Vec<_> = agents.iter()
            .filter(|m| m.sub != sender_sub && addressed_to(to, &[&m.name]))
            .map(|m| m.name.clone()).collect();
        out.sort();
        out.dedup();
        out
    }

}

/// ",name,…," readers of a private envelope. A room post (`to` = room:…) is for the agents its content key was
/// wrapped to (the room's members when it was sent); other private mail for the sender and whom `to` addresses.
pub fn readers_of(agents: &[Agent], env: &Envelope) -> String {
    if !env.to.starts_with("room:") {
        return readers_for(agents, &env.to, &env.from);
    }
    let wrapped: Vec<String> = env.keys.iter().map(|w| w.to.trim_end_matches('=').to_string()).collect();
    let mut names = names_with_keys(agents, &wrapped);
    names.push(norm(&env.from));
    names.sort();
    names.dedup();
    format!(",{},", names.join(","))
}

/// Normalized names of the agents whose keys are among `keys` (fmt_key strings).
pub fn names_with_keys(agents: &[Agent], keys: &[String]) -> Vec<String> {
    let set: HashSet<&str> = keys.iter().map(|k| k.trim_end_matches('=')).collect();
    let mut out: Vec<String> = agents.iter().filter(|a| set.contains(fmt_key(&a.key).as_str())).map(|a| norm(&a.name)).collect();
    out.sort();
    out.dedup();
    out
}

/// The room fields of a post the node signs itself: from `room` (true, or the room id), `reply_to` and `event`,
/// with the text's @mentions. Empty when there are none.
fn build_meta(body: &Value, text: &str, thread: &str) -> Result<String, ApiError> {
    let mut m = mailcore::room::Meta { mentions: mailcore::room::mentions_in(text), ..Default::default() };
    match body.get("room") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => m.room = Some(thread.to_string()),
        Some(Value::String(r)) => m.room = Some(r.clone()),
        Some(_) => return Err(ApiError::new(400, "room must be true or the room id")),
    }
    if let Some(r) = body.get("reply_to").and_then(|r| r.as_str()) {
        m.reply_to = Some(r.to_string());
    }
    if let Some(e) = body.get("event").filter(|e| !e.is_null()) {
        m.event = Some(serde_json::from_value(e.clone()).map_err(|e| ApiError::new(400, format!("invalid event: {e}")))?);
    }
    if m.is_empty() {
        return Ok(String::new());
    }
    serde_json::to_string(&m).map_err(|e| ApiError::from(anyhow::Error::from(e)))
}

/// Where a room post goes: its `to`, mode, exact keys and (private rooms) member names.
pub struct Plan {
    pub to: String,
    pub mode: Mode,
    pub keys: Vec<PublicKey>,
    pub names: Option<Vec<String>>,
}

/// ",name1,name2," of the member names a private envelope is for: the sender and every member `to` addresses.
pub fn readers_for(agents: &[Agent], to: &str, from: &str) -> String {
    let mut names: Vec<String> = agents
        .iter()
        .filter(|m| addressed_to(to, &[m.name.as_str()]))
        .map(|m| norm(&m.name))
        .collect();
    names.push(norm(from));
    names.sort();
    names.dedup();
    format!(",{},", names.join(","))
}

/// What the host owner signs with the node key to revoke this node's certificates for `name`.
pub fn revoke_statement(name: &str, node: &str, ts: &str) -> String {
    format!("agent-mail-revoke-request|v1|{name}|{node}|{ts}")
}

/* Input validation */

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
        return Err(ApiError::new(400, format!("{name} must be 1-{MAX_FIELD} characters, like sauersml.glead or ops.")));
    }
    Ok(s)
}

/// Use the last path segment, no format/control characters or quotes, at most 200 chars.
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

/// Use a plain type/subtype or application/octet-stream.
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
    fn local_keys(&self) -> impl Iterator<Item = &Seed> {
        std::iter::once(&self.seed).chain(self.opts.identities.iter().map(|(_, s)| s))
    }

    /// The room as this node folds the membership events it can read. None: a room with no events here (a plain
    /// thread, or a room this node has not heard of).
    pub fn room_state(&self, id: &str) -> Result<Option<mailcore::room::State>> {
        use mailcore::room;
        if room::dm_pair(id).is_some() {
            return Ok(Some(room::fold(id, &mut [])));
        }
        let rows = self.store.room_events(id)?;
        if rows.is_empty() {
            return Ok(None);
        }
        let metas: Vec<(String, String, String, room::Meta)> = rows.into_iter()
            .filter_map(|(e, ts, from, raw)| room::Meta::parse(&raw).ok().map(|m| (e, ts, from, m))).collect();
        let mut events: Vec<room::Folded> = metas.iter()
            .filter_map(|(id, ts, from, m)| m.event.as_ref().map(|event| room::Folded { id, ts, from, event })).collect();
        Ok(Some(room::fold(id, &mut events)))
    }

    /// Where a post in `room` by `from` goes, with an optional membership event.
    pub fn room_plan(&self, room: &str, from: &str, event: Option<&mailcore::room::Event>, members: &MemberList,
                     agents: &[Agent]) -> Result<Plan, ApiError> {
        let state = self.room_state(room)?;
        let (private, names) = mailcore::room::plan(room, state.as_ref(), from, event)
            .map_err(|e| ApiError::new(if e.to_string().contains("no room") { 404 } else { 403 }, format!("{e}")))?;
        if !private {
            let keys = Self::recipients(members, agents, "all", from, Mode::Members)?;
            return Ok(Plan { to: mailcore::room::room_to(room), mode: Mode::Members, keys, names: None });
        }
        let names = names.unwrap_or_default();
        let to = match mailcore::room::dm_pair(room) {
            Some((a, b)) => if norm(from) == a { b } else { a },
            None => mailcore::room::room_to(room),
        };
        let mut keys = Vec::new();
        for a in agents.iter().filter(|a| names.contains(&norm(&a.name)) || mailcore::addr::same(&a.name, from)) {
            keys.push(a.key);
            keys.extend(a.homes.iter().copied());
        }
        keys.sort();
        keys.dedup();
        if keys.len() > mailcore::envelope::MAX_KEYS {
            return Err(ApiError::new(503, "more recipient keys than an envelope holds"));
        }
        Ok(Plan { to, mode: Mode::Private, keys, names: Some(names) })
    }

    /// Who a room post reaches: the members (private) or the room's participants, not the sender.
    fn room_reaches(&self, room: &str, from: &str) -> Vec<String> {
        let state = self.room_state(room).ok().flatten();
        let mut out: Vec<String> = match state {
            Some(s) if s.private() || !s.members.is_empty() => s.members.keys().cloned().collect(),
            _ => self.store.room_senders(room).unwrap_or_default(),
        };
        out.retain(|n| !mailcore::addr::same(n, from));
        out.sort();
        out.dedup();
        out
    }

    /// Grants held for `env` whose key opens it in its own room, with the bodies they open; others are dropped.
    fn checked_grants(&self, env: &Envelope) -> Result<Vec<(String, Body)>> {
        let mut out = Vec::new();
        for (ck, thread, _) in self.store.grants_for(&env.id)? {
            let key: Option<[u8; 32]> = mailcore::b64u_decode(&ck).and_then(|k| k.try_into().ok());
            match key.filter(|_| thread == env.thread).map(|k| env.open_with(&k)) {
                Some(Ok(b)) if env.check_body(&b).is_ok() => out.push((ck, b)),
                _ => self.store.drop_grant(&env.id, &ck)?,
            }
        }
        Ok(out)
    }

    /// A key grant this node can read: the grant envelope's recipients may now read each listed envelope of the
    /// same room. Grants for envelopes not here yet wait for them (`ingest` checks them on arrival).
    fn apply_grant(&self, grant: &Envelope, meta: &mailcore::room::Meta, agents: &[Agent]) -> Result<()> {
        let keys: Vec<String> = grant.keys.iter().map(|w| w.to.trim_end_matches('=').to_string()).collect();
        let names = names_with_keys(agents, &keys);
        for item in &meta.grant {
            let Some((raw, has_text, _)) = self.store.env_state(&item.env)? else {
                self.store.put_grant(&item.env, &keys, &item.ck, &grant.id, &grant.thread)?;
                continue;
            };
            let env: Envelope = serde_json::from_str(&raw)?;
            let Some(ck) = mailcore::b64u_decode(&item.ck).and_then(|k| <[u8; 32]>::try_from(k).ok()) else { continue };
            if env.thread != grant.thread || env.mode != Mode::Private {
                continue;
            }
            let Ok(b) = env.open_with(&ck) else { continue };
            if env.check_body(&b).is_err() {
                continue;
            }
            self.store.put_grant(&item.env, &keys, &item.ck, &grant.id, &grant.thread)?;
            if !has_text {
                let meta = mailcore::room::Meta::parse(&b.meta).unwrap_or_default();
                let raw_meta = if meta.is_empty() { String::new() } else { b.meta.clone() };
                let files = serde_json::to_string(&b.files)?;
                self.store.fill_body(&item.env, &b.text, &files, &crate::store::Extra::of(&raw_meta, &meta))?;
            }
            self.store.add_readers(&item.env, &names)?;
        }
        Ok(())
    }

    /// Content keys of a private room's messages the caller can read, to re-wrap for a new member (key grants).
    /// A since-join room grants only its membership events, so the new member's node knows the room.
    pub fn room_keys(&self, who: &Caller, room: &str) -> Result<Vec<Value>, ApiError> {
        if !self.active(who) {
            return Err(ApiError::new(401, "session expired or membership changed"));
        }
        let state = self.room_state(room)?.ok_or_else(|| ApiError::new(404, format!("no room {room} here")))?;
        if !state.private() || !state.is_member(&who.name) {
            return Err(ApiError::new(403, "key grants are for members of a private room"));
        }
        let events_only = state.history == mailcore::room::History::SinceJoin;
        let mut out = Vec::new();
        for (env_id, raw, granted) in self.store.room_envelopes(room, who, events_only)? {
            let env: Envelope = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
            let ck = match env.content_key(self.local_keys())? {
                Some(k) => mailcore::b64u(&k),
                None => match granted { Some(k) => k, None => continue },
            };
            out.push(json!({ "env": env_id, "ck": ck }));
        }
        Ok(out)
    }

    /// One room as the caller sees it: kind, topic, members, creator, history, whether the caller is a member.
    pub fn room_info(&self, who: &Caller, room: &str, senders: &[String]) -> Result<Value, ApiError> {
        use mailcore::room::Kind;
        let state = self.room_state(room)?;
        let me = norm(&who.name);
        Ok(match state {
            Some(s) => {
                let label = match (&s.kind, mailcore::room::dm_pair(room)) {
                    (Kind::Dm, Some((a, b))) => if a == me { b } else { a },
                    _ => room.to_string(),
                };
                let members: Vec<&String> = s.members.keys().collect();
                json!({ "id": room, "label": label, "kind": s.kind, "topic": s.topic, "creator": s.creator,
                        "history": s.history.as_str(), "members": members, "former": s.former,
                        "member": s.is_member(&who.name), "created": s.created })
            }
            None => json!({ "id": room, "label": room, "kind": "open", "topic": "", "creator": null, "history": "full",
                            "members": senders, "participants": true, "member": senders.iter().any(|n| norm(n) == me),
                            "created": mailcore::room::creator_of(room).is_none() }),
        })
    }

    /// The caller's rooms, latest activity first, with unread counts.
    pub fn rooms(&self, who: &Caller) -> Result<Vec<Value>, ApiError> {
        let mut out = Vec::new();
        for r in self.store.room_rows(who, 500)? {
            let room = r["room"].as_str().unwrap_or("").to_string();
            let senders: Vec<String> = r["senders"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let mut info = self.room_info(who, &room, &senders)?;
            for k in ["n", "unread", "unread_mentions"] {
                info[k] = r[k].clone();
            }
            info["last"] = json!({ "id": r["id"], "ts": r["ts"], "from": r["sender"], "snippet": r["snippet"], "kind": r["last_kind"] });
            out.push(info);
        }
        Ok(out)
    }

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
    s.chars().map(|c| if c.is_control() || is_line_break(c) || is_bidi(c) { ' ' } else { c }).collect()
}

/// Format one header line from the mailbox, then the sender's text, every line quoted.
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
    let quoted: Vec<String> = body.replace("\r\n", "\n").split(is_line_break).map(|l| format!("> {}", one_line(l))).collect();
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

    fn setup() -> (Node, Seed, Seed, MemberList, mpsc::Receiver<Envelope>) {
        let (node_a, node_b, alice) = (Seed::generate(), Seed::generate(), Seed::generate());
        let list = MemberList {
            v: 2,
            network: mailcore::b64u(&mailcore::random_bytes::<32>()),
            seq: 1,
            members: vec![Member { name: "a.alice".into(), sub: "agent:alice@t".into(), key: fmt_key(&alice.public()) }],
            nodes: [&node_a, &node_b]
                .iter()
                .enumerate()
                .map(|(i, s)| NodeEntry { name: format!("n{i}"), key: fmt_key(&s.public()), addrs: vec![], names: vec![] })
                .collect(),
            homes: vec![],
        };
        let path = std::env::temp_dir().join(format!("mailnode-test-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let (tx, rx) = mpsc::channel(32);
        let opts = Opts { public_url: "http://x".into(), ..Default::default() };
        let store = Store::open(&path).unwrap();
        store.bind_roster(&node_a.public(), &list).unwrap();
        let node = Node::new(store, list.clone(), node_a, opts, tx);
        (node, alice, node_b, list, rx)
    }

    fn envelope(writer: &Seed, list: &MemberList, agent: &Seed, text: &str) -> Envelope {
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, text, &[]).unwrap();
        let st = PostStatement {
            from: "a.alice", sub: "agent:alice@t", to: "all", thread: "t", mode: Mode::Members,
            ts: &ts, digest: &digest, blobs: &[], recipients: &list.all_keys(),
        }.signing_bytes(list);
        let attest = Attest::Agent { key: fmt_key(&agent.public()), digest, sig: mailcore::b64u(&agent.sign(&st)), cert: None };
        let body = Body { text: text.into(), files: vec![], salt: mailcore::b64u(&salt), meta: String::new() };
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
    fn padded_wire_keys_work_in_mailbox_lookups() {
        let (node, alice, writer, list, _rx) = setup();
        let mut env = envelope(&writer, &list, &alice, "padded keys");
        for wrap in &mut env.keys {
            wrap.to.push('=');
        }
        let Attest::Agent { key, .. } = &mut env.attest;
        key.push('=');
        env.sig = mailcore::b64u(&writer.sign(&env.signing_bytes()));
        let row = node.ingest(env).unwrap().unwrap();
        let viewer = Caller {
            name: "a.alice".into(), sub: "agent:alice@t".into(), key: fmt_key(&alice.public()), exp_ms: i64::MAX,
        };
        assert!(node.store.get(row.id, &viewer).unwrap().is_some());
        assert_eq!(node.store.query(&Default::default(), &viewer, 100).unwrap().0.len(), 1);
        assert!(node.store.repeat(&viewer, "", "all", "t", "padded keys").unwrap().is_some());
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
            wrapped_to: String::new(),
            kind: "mail".into(),
            meta: None,
            mentions: None,
            reply_to: None,
        };
        let out = format_message(&row, 100_000, "http://x");
        let lines: Vec<&str> = out.split(is_line_break).collect();
        assert!(lines[0].starts_with("#7 "), "{out:?}");
        assert!(lines[1..].iter().all(|l| l.starts_with("> ")), "{out:?}");
        assert_eq!(lines.len(), 9, "{out:?}");

    }

    #[test]
    fn a_replayed_agent_signed_message_stays_hidden() {
        let (node, alice, node_b, list, _rx) = setup();
        let ts = now_ts();
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, "deploy now", &[]).unwrap();
        let st = PostStatement {
            from: "a.alice", sub: "agent:alice@t", to: "all", thread: "t", mode: Mode::Members,
            ts: &ts, digest: &digest, blobs: &[], recipients: &list.all_keys(),
        }.signing_bytes(&list);
        let sig = mailcore::b64u(&alice.sign(&st));
        let body = Body { text: "deploy now".into(), files: vec![], salt: mailcore::b64u(&salt), meta: String::new() };
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
                    attest: Attest::Agent { key: fmt_key(&alice.public()), digest: digest.clone(), sig, cert: None },
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
        let (rows, _) = node.store.query(&crate::store::Query::default(), &who, MAX_TEXT).unwrap();
        assert_eq!(rows.len(), 1);
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
                           "signed": signed(&_l, &alice, "all", "t", "with file", std::slice::from_ref(&f), &ts) });
        let p1 = node.post(&who, &post).unwrap();
        let p2 = node.post(&who, &post).unwrap();
        assert!(!p1.repeated && p2.repeated);
        assert_eq!(p1.row.env_id, p2.row.env_id);
        assert_eq!(node.store.count().unwrap(), 1);
    }

    #[test]
    fn a_wrong_key_for_a_blob_does_not_shadow_the_real_one() {
        let (node, agent, node_b, mut list, _rx) = setup();
        let bob_key = fmt_key(&Seed::generate().public());
        list.members.push(Member { name:"a.bob".into(), sub:"agent:bob@t".into(), key:bob_key.clone() });
        *node.members.write().unwrap() = list.clone();
        node.refresh();
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
            "signed": signed(&list, &agent, "all", "t", "see file", std::slice::from_ref(&f), &now_ts()) })).unwrap();
        // Another reader (built directly: this test is about attachment keys, not the member-list sign-in check).
        let bob = Caller { key: bob_key, name: "a.bob".into(), sub: "agent:bob@t".into(), exp_ms: i64::MAX };
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
    fn rotating_an_agent_key_revokes_sessions_and_private_history() {
        let (mut node, alice, _, _, _) = setup();
        node.opts.identities.push(("a.alice".into(), alice.clone()));
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let file = node.upload(&who, "note", "text/plain", b"private").unwrap();
        let private = node.post(&who, &json!({"to": "a.alice", "mode": "private", "text": "archive",
                                              "files": [file["id"]]})).unwrap().row;
        assert!(node.store.get(private.id, &who).unwrap().is_some());
        let replacement = Seed::generate();
        node.members.write().unwrap().members[0].key = fmt_key(&replacement.public());
        node.refresh();
        assert!(!node.active(&who));
        let fresh = node.verify(&agent_token(&replacement, &node.seed.public())).unwrap();
        assert!(node.store.get(private.id, &fresh).unwrap().is_none());
        assert!(node.store.query(&Default::default(), &fresh, MAX_TEXT).unwrap().0.is_empty());
        assert!(node.download(file["id"].as_str().unwrap(), &fresh).is_err());
    }

    #[test]
    fn resending_after_enrollment_seals_to_the_current_recipients() {
        let (mut node, alice, _, mut list, _rx) = setup();
        node.opts.identities.push(("a.alice".into(), alice.clone()));
        let who = node.verify(&agent_token(&alice, &node.me())).unwrap();
        let post = json!({"to":"all","text":"meeting notes"});
        let before = node.post(&who, &post).unwrap();
        let bob = Seed::generate();
        list.seq += 1;
        list.members.push(Member { name: "a.bob".into(), sub: "agent:bob".into(), key: fmt_key(&bob.public()) });
        node.reload_members(&list).unwrap();
        let after = node.post(&who, &post).unwrap();
        assert!(!after.repeated);
        let bob = node.verify(&mailcore::agent_token::mint(&bob, "a.bob", "agent:bob", &node.me(), now_millis(), 60)).unwrap();
        assert!(!before.row.visible_to(&bob) && after.row.visible_to(&bob));
        assert_eq!(node.post(&who, &post).unwrap().row.env_id, after.row.env_id);
    }

    #[test]
    fn post_signs_stores_and_announces() {
        let (mut node, alice, _node_b, _list, mut rx) = setup();
        node.opts.identities.push(("a.alice".into(), alice.clone()));
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let p = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(!p.repeated);
        let out = rx.try_recv().expect("gossiped");
        assert_eq!(out.id, p.row.env_id);
        assert_eq!(p.row.to_message()["attest"], "agent");
        let p2 = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(p2.repeated, "identical resend is answered with the first");
        for invalid in [json!({"to":"all","thread":"t","text":"hi","signed":null}),
                        json!({"to":"all","thread":"t","text":"hi","mode":false})] {
            assert!(node.post(&who, &invalid).is_err());
        }
        let p3 = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "next" })).unwrap();
        assert_eq!(rx.try_recv().unwrap().parents, vec![p.row.env_id.clone()], "parents = thread heads");
        assert!(p3.row.id > p.row.id);
    }

    fn signed(list: &MemberList, alice: &Seed, to: &str, thread: &str, text: &str, files: &[Value], ts: &str) -> Value {
        let salt = mailcore::random_bytes::<16>();
        let digest = mailcore::envelope::post_digest(&salt, text, files).unwrap();
        let ids: Vec<_> = files.iter().map(|f| f["id"].as_str().unwrap().to_owned()).collect();
        let st = PostStatement {
            from: "a.alice", sub: "agent:alice@t", to, thread, mode: Mode::Members,
            ts, digest: &digest, blobs: &ids, recipients: &list.all_keys(),
        }.signing_bytes(list);
        json!({ "ts": ts, "salt": mailcore::b64u(&salt), "sig": mailcore::b64u(&alice.sign(&st)) })
    }

    #[test]
    fn signed_post_path() {
        let (node, alice, _b, _l, mut rx) = setup();
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let ts = now_ts();
        let p = node
            .post(&who, &json!({ "to": "all", "thread": "t", "text": "signed", "signed": signed(&_l, &alice, "all", "t", "signed", &[], &ts) }))
            .unwrap();
        assert_eq!(p.row.to_message()["attest"], "agent");
        let e = rx.try_recv().unwrap();
        assert!(matches!(e.attest, Attest::Agent { .. }));
        assert_eq!(e.ts, ts);
        // A signature over other text, or by another key, is refused.
        let bad = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "changed", "signed": signed(&_l, &alice, "all", "t", "orig", &[], &ts) }));
        assert_eq!(bad.err().unwrap().status, 401);
        let mallory = Seed::generate();
        let bad = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "x", "signed": signed(&_l, &mallory, "all", "t", "x", &[], &ts) }));
        assert_eq!(bad.err().unwrap().status, 401);
        // Old timestamps are refused.
        let old = ts_from_millis(now_millis() - 3_600_000);
        let bad = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "y", "signed": signed(&_l, &alice, "all", "t", "y", &[], &old) }));
        assert_eq!(bad.err().unwrap().status, 400);
    }

    #[test]
    fn node_signs_for_a_caller_whose_key_it_holds() {
        let (_n, alice, node_b, list, _rx) = setup();
        let mk = |ids: Vec<(String, Seed)>| {
            let path = std::env::temp_dir().join(format!("mailnode-test-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
            let (tx, rx) = mpsc::channel(32);
            let opts = Opts { public_url: "http://x".into(), identities: ids };
            let node_seed = Seed::from_bytes(*node_b.bytes());
            (Node::new(Store::open(&path).unwrap(), list.clone(), node_seed, opts, tx), rx)
        };
        // Holding alice's key: a plain token post goes out signed by alice's key, and another node accepts it.
        let (node, mut rx) = mk(vec![("a.alice".into(), Seed::from_bytes(*alice.bytes()))]);
        let who = node.verify(&agent_token(&alice, &node.seed.public())).unwrap();
        let p = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "no token inside" })).unwrap();
        assert_eq!(p.row.to_message()["attest"], "agent");
        let e = rx.try_recv().unwrap();
        assert!(matches!(e.attest, Attest::Agent { .. }));
        e.verify(&list, &list.agents(&[], &|_| None, 0), now_millis()).unwrap();
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
                                 "signed": signed(&_l, &alice, "all", "t", "see file", std::slice::from_ref(&f), &ts) }))
            .unwrap();
        let e = rx.try_recv().unwrap();
        let body = e.open(&node.seed).unwrap().unwrap();
        for (field, replacement) in [("name", json!("different.txt")), ("type", json!("application/json")), ("size", json!(1))] {
            let mut changed = body.clone();
            changed.files[0][field] = replacement;
            assert!(e.check_body(&changed).is_err());
        }
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
        let p = node.post(&who, &json!({"to":"all", "thread":"t", "text":"signed", "signed":signed(&_list, &alice, "all", "t", "signed", &[], &now_ts())})).unwrap();
        assert_eq!(p.row.to_message()["attest"], "agent");
        let env = rx.try_recv().unwrap();
        assert!(!serde_json::to_string(&env).unwrap().contains(paseto_header()), "no token in the envelope");
    }

    fn paseto_header() -> &'static str {
        mailcore::paseto::HEADER
    }


    /* Node-certified agents */

    /// Nodes "mac" (names hypha, h.) and "pod" (names hypha), a third node "ops" (names ops.); one network.
    fn homes() -> (Node, Node, Seed, MemberList) {
        let (mac, pod, ops) = (Seed::generate(), Seed::generate(), Seed::generate());
        let names = [vec!["hypha".to_string(), "h.".into()], vec!["hypha".into()], vec!["ops.".into()]];
        let list = MemberList {
            v: 2,
            network: mailcore::b64u(&mailcore::random_bytes::<32>()),
            seq: 1,
            members: vec![],
            nodes: [&mac, &pod, &ops].iter().zip(names).enumerate()
                .map(|(i, (s, names))| NodeEntry { name: ["mac", "pod", "ops"][i].into(), key: fmt_key(&s.public()), addrs: vec![], names })
                .collect(),
            homes: vec![],
        };
        list.validate().unwrap();
        let mk = |seed: Seed| {
            let path = std::env::temp_dir().join(format!("mailnode-test-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
            let (tx, _rx) = mpsc::channel(32);
            Node::new(Store::open(&path).unwrap(), list.clone(), seed, Opts { public_url: "http://x".into(), ..Default::default() }, tx)
        };
        (mk(mac), mk(pod), ops, list)
    }

    fn proof(agent: &Seed, name: &str, node: &Node) -> Value {
        let (key, ts) = (fmt_key(&agent.public()), now_ts());
        let st = mailcore::cert::certify_statement(name, &key, &fmt_key(&node.seed.public()), &ts);
        json!({ "name": name, "key": key, "ts": ts, "sig": mailcore::b64u(&agent.sign(st.as_bytes())) })
    }

    fn token(agent: &Seed, name: &str, node: &Node) -> String {
        mailcore::agent_token::mint(agent, name, &format!("agent:{name}"), &node.seed.public(), now_millis(), 600)
    }

    fn revoke_request(node: &Node, name: &str) -> Value {
        let ts = now_ts();
        let st = revoke_statement(name, &fmt_key(&node.seed.public()), &ts);
        json!({ "name": name, "ts": ts, "sig": mailcore::b64u(&node.seed.sign(st.as_bytes())) })
    }

    fn status<T>(r: Result<T, ApiError>) -> u16 {
        r.err().map_or(0, |e| e.status)
    }

    #[test]
    fn concurrent_local_claims_issue_one_key_per_name() {
        let (node, _, _, _) = homes();
        let requests = [proof(&Seed::generate(), "hypha", &node), proof(&Seed::generate(), "hypha", &node)];
        let barrier = std::sync::Barrier::new(requests.len());
        let mut codes = std::thread::scope(|scope| {
            let calls: Vec<_> = requests.iter().map(|req| scope.spawn(|| {
                barrier.wait();
                node.certify(req).map_or_else(|e| e.status, |(status, _)| status)
            })).collect();
            calls.into_iter().map(|thread| thread.join().unwrap()).collect::<Vec<_>>()
        });
        codes.sort();
        assert_eq!(codes, [201, 409]);
        assert_eq!(node.store.certs_at(Some("hypha"), i64::MAX).unwrap().len(), 1);
    }

    #[test]
    fn issuance_checks_in_order() {
        let (mac, pod, _, _) = homes();
        let (hypha, other) = (Seed::generate(), Seed::generate());
        let mut bad = proof(&hypha, "hypha", &mac);
        bad["name"] = json!("h.x");
        assert_eq!(status(mac.certify(&bad)), 400, "proof signed for another name");
        assert_eq!(status(mac.certify(&proof(&hypha, "hypha", &pod))), 400, "proof for another node");
        let e = mac.certify(&proof(&hypha, "ops.x", &mac)).unwrap_err();
        assert_eq!(e.status, 403);
        assert!(e.message.contains("hypha, h."), "{}", e.message);
        assert_eq!(status(mac.certify(&proof(&pod.seed, "h.node", &mac))), 409);
        assert_eq!(mac.certify(&proof(&hypha, "hypha", &mac)).unwrap().0, 201);
        assert_eq!(mac.certify(&proof(&hypha, "hypha", &mac)).unwrap().0, 200, "idempotent");
        assert_eq!(status(mac.certify(&proof(&other, "hypha", &mac))), 409, "name taken by another key");
        assert_eq!(status(mac.certify(&proof(&hypha, "h.alias", &mac))), 409, "key already certified as another name");
        // The certified agent signs in at once.
        let who = mac.verify(&token(&hypha, "hypha", &mac)).unwrap();
        assert_eq!(who.sub, "agent:hypha");
        // A second home must use the same key: the mac's cert reached the pod, and another key is refused there.
        let c: Cert = serde_json::from_value(mac.certify(&proof(&hypha, "hypha", &mac)).unwrap().1["cert"].clone()).unwrap();
        assert!(pod.take_cert(&c).unwrap());
        assert_eq!(status(pod.certify(&proof(&other, "hypha", &pod))), 409);
        assert_eq!(pod.certify(&proof(&hypha, "hypha", &pod)).unwrap().0, 201);
        for i in 0..70 {
            let r = mac.certify(&proof(&Seed::generate(), &format!("h.a{i}"), &mac));
            if let Err(e) = r {
                assert_eq!(e.status, 429);
                assert!(i >= 55, "limit is 60 an hour, hit after {i}");
                return;
            }
        }
        panic!("no rate limit");
    }

    #[test]
    fn certs_are_keyed_by_node_and_key() {
        let (mac, pod, ops, list) = homes();
        let hypha = Seed::generate();
        // A trusted node squatting on hypha's key under a name of its own does not block the mac's cert.
        let squat = Cert::issue(&ops, "ops.hypha", &hypha.public(), &now_ts());
        assert!(list.accepts(&squat));
        assert!(mac.take_cert(&squat).unwrap());
        assert_eq!(mac.certify(&proof(&hypha, "hypha", &mac)).unwrap().0, 201);
        assert!(mac.verify(&token(&hypha, "hypha", &mac)).is_ok());
        assert_eq!(mac.store.certs_at(None, i64::MAX).unwrap().len(), 2);
        // Out of namespace, or from an untrusted node: refused, never stored.
        assert!(pod.take_cert(&Cert::issue(&ops, "hypha", &Seed::generate().public(), &now_ts())).is_err());
        assert!(pod.take_cert(&Cert::issue(&Seed::generate(), "ops.x", &Seed::generate().public(), &now_ts())).is_err());
        assert!(pod.store.certs_at(None, i64::MAX).unwrap().is_empty());
        // No trusted node can crowd out the others: at most MAX_CERTS_PER_NODE from each.
        for i in 0..crate::store::MAX_CERTS_PER_NODE {
            pod.store.put_cert(&Cert::issue(&ops, &format!("ops.a{i}"), &Seed::generate().public(), &now_ts())).unwrap();
        }
        assert!(pod.take_cert(&Cert::issue(&ops, "ops.more", &Seed::generate().public(), &now_ts())).is_err());
        assert!(pod.take_cert(&Cert::issue(&mac.seed, "hypha", &hypha.public(), &now_ts())).unwrap());
    }

    #[test]
    fn revocation_is_scoped_to_its_node_and_its_time() {
        let (mut mac, pod, ops, _) = homes();
        let hypha = Seed::generate();
        mac.opts.identities.push(("hypha".into(), hypha.clone()));
        let (_, c) = mac.certify(&proof(&hypha, "hypha", &mac)).unwrap();
        let cert: Cert = serde_json::from_value(c["cert"].clone()).unwrap();
        let who = mac.verify(&token(&hypha, "hypha", &mac)).unwrap();
        let before = mac.post(&who, &json!({"to": "all", "text": "before"})).unwrap();
        let env_before: Envelope = serde_json::from_str(&mac.store.envelopes(std::slice::from_ref(&before.row.env_id)).unwrap()[0]).unwrap();
        // Another node's revocation of the same key does not touch the mac's cert.
        let foreign = Revocation::sign(&ops, "hypha", &hypha.public(), &now_ts());
        assert!(mac.take_revocation(&foreign).unwrap());
        assert!(mac.active(&who));
        assert!(mac.verify(&token(&hypha, "hypha", &mac)).is_ok());
        // The mac's own revocation: sign-in and open sessions end at once, the pod refuses new mail, old mail stays.
        let mut trust = mac.trust.subscribe();
        trust.mark_unchanged();
        let request = revoke_request(&mac, "hypha");
        let revoked = mac.revoke(&request).unwrap();
        assert_eq!(revoked.len(), 1);
        assert!(trust.has_changed().unwrap(), "sessions are woken");
        assert!(!mac.active(&who));
        assert_eq!(status(mac.verify(&token(&hypha, "hypha", &mac))), 403);
        assert!(pod.take_cert(&cert).unwrap());
        assert!(pod.take_revocation(&revoked[0]).unwrap());
        assert!(pod.ingest(env_before).unwrap().is_some(), "mail dated before the revocation is still accepted");
        let late = envelope_from(&mac, &hypha, "hypha", "after", Some(cert));
        assert!(pod.ingest(late).is_err(), "mail dated after it is refused");
        assert_eq!(status(mac.certify(&proof(&hypha, "hypha", &mac))), 403, "a revoked key stays revoked");
        let fresh = Seed::generate();
        assert_eq!(mac.certify(&proof(&fresh, "hypha", &mac)).unwrap().0, 201, "the name takes a new key");
        assert_eq!(status(mac.revoke(&request)), 409);
        assert!(mac.verify(&token(&fresh, "hypha", &mac)).is_ok(), "the replacement key remains live");
        assert!(mac.revoke(&json!({"name": "hypha", "ts": now_ts(), "sig": "AAAA"})).is_err(), "needs the node key");
    }

    /// An envelope `writer` writes for a certified agent, signed by the agent, carrying `cert`.
    fn envelope_from(writer: &Node, agent: &Seed, name: &str, text: &str, cert: Option<Cert>) -> Envelope {
        let list = writer.members.read().unwrap().clone();
        let (ts, salt) = (now_ts(), mailcore::random_bytes::<16>());
        let digest = mailcore::envelope::post_digest(&salt, text, &[]).unwrap();
        let keys = list.all_keys();
        let st = PostStatement { from: name, sub: &format!("agent:{name}"), to: "all", thread: "t", mode: Mode::Members,
                                 ts: &ts, digest: &digest, blobs: &[], recipients: &keys }.signing_bytes(&list);
        let attest = Attest::Agent { key: fmt_key(&agent.public()), digest, sig: mailcore::b64u(&agent.sign(&st)), cert };
        let body = Body { text: text.into(), files: vec![], salt: mailcore::b64u(&salt), meta: String::new() };
        Envelope::seal(Draft { thread: "t", parents: vec![], ts, from: name, to: "all", mode: Mode::Members, body: &body,
                               blobs: vec![], attest, recipients: &keys }, &writer.seed).unwrap()
    }

    #[test]
    fn one_agent_two_homes() {
        let (mut mac, mut pod, _, _) = homes();
        let (hypha, h_bob) = (Seed::generate(), Seed::generate());
        mac.opts.identities.push(("hypha".into(), hypha.clone()));
        pod.opts.identities.push(("hypha".into(), hypha.clone()));
        mac.opts.identities.push(("h.bob".into(), h_bob.clone()));
        mac.certify_identities();
        pod.certify_identities();
        // Certificates replicate both ways; both nodes certify the same name and key without conflict.
        for c in mac.store.certs_at(None, i64::MAX).unwrap() { pod.take_cert(&c).unwrap(); }
        for c in pod.store.certs_at(None, i64::MAX).unwrap() { mac.take_cert(&c).unwrap(); }
        let a: Vec<_> = mac.agents().into_iter().filter(|a| a.name == "hypha").collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].homes.len(), 2);
        // bob writes private mail to hypha at the mac; hypha signs in at the pod and reads it there.
        let bob = mac.verify(&token(&h_bob, "h.bob", &mac)).unwrap();
        let p = mac.post(&bob, &json!({"to": "hypha", "mode": "private", "text": "for hypha only"})).unwrap();
        let env: Envelope = serde_json::from_str(&mac.store.envelopes(std::slice::from_ref(&p.row.env_id)).unwrap()[0]).unwrap();
        assert!(env.open(&pod.seed).unwrap().is_some(), "wrapped to the pod's node key");
        let row = pod.ingest(env).unwrap().expect("stored at the pod");
        let at_pod = pod.verify(&token(&hypha, "hypha", &pod)).unwrap();
        let got = pod.store.get(row.id, &at_pod).unwrap().expect("hypha reads it at the pod");
        assert_eq!(got.text.as_deref(), Some("for hypha only"));
        let at_mac = mac.verify(&token(&hypha, "hypha", &mac)).unwrap();
        assert!(mac.store.get(p.row.id, &at_mac).unwrap().is_some(), "and at the mac");
        // hypha writes from the pod; the mac accepts it (pod's cert travels in the envelope) and can read the reply.
        let r = pod.post(&at_pod, &json!({"to": "h.bob", "mode": "private", "text": "reply"})).unwrap();
        let env: Envelope = serde_json::from_str(&pod.store.envelopes(std::slice::from_ref(&r.row.env_id)).unwrap()[0]).unwrap();
        assert!(env.carried_cert().is_some_and(|c| c.node == fmt_key(&pod.seed.public())));
        let row = mac.ingest(env).unwrap().unwrap();
        assert!(mac.store.get(row.id, &bob).unwrap().is_some());
    }
}
