//! The node's mail logic, shared by the compat API, MCPL and replication: accept a local send (seal, sign, store,
//! announce), accept a replicated envelope (verify, decrypt if we can, store), and the old server's read-side rules
//! (names, reaches, addressed rows, message formatting).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use mailcore::addr::{self, addressed_to, is_broadcast, norm};
use mailcore::envelope::Draft;
use mailcore::keys::Seed;
use mailcore::{now_millis, now_ts, ts_from_millis, Attest, Body, Envelope, MemberList, Mode, TokenPolicy};
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
    pub kind: String,
    pub token: String,
    pub exp_ms: i64,
}

pub struct Posted {
    pub row: Row,
    pub reaches: Vec<String>,
    pub repeated: bool,
}

pub struct Node {
    pub store: Store,
    pub members: RwLock<MemberList>,
    pub policy: TokenPolicy,
    pub seed: Seed,
    pub identities: Vec<(String, Seed)>,
    pub renamed: Vec<Renamed>,
    pub events: broadcast::Sender<Arc<Row>>,
    pub outbound: mpsc::UnboundedSender<Envelope>,
    rates: Mutex<HashMap<(String, &'static str), Vec<i64>>>,
    touched: Mutex<HashMap<String, i64>>,
}

impl Node {
    pub fn new(
        store: Store,
        members: MemberList,
        policy: TokenPolicy,
        seed: Seed,
        identities: Vec<(String, Seed)>,
        renamed: Vec<Renamed>,
        outbound: mpsc::UnboundedSender<Envelope>,
    ) -> Node {
        let (events, _) = broadcast::channel(4096);
        Node {
            store,
            members: RwLock::new(members),
            policy,
            seed,
            identities,
            renamed,
            events,
            outbound,
            rates: Mutex::new(HashMap::new()),
            touched: Mutex::new(HashMap::new()),
        }
    }

    /* Identity */

    /// The old server's verify(): an aid1 token for audience mail, live now, never a one-time sign-in token.
    pub fn verify(&self, token: &str) -> Result<Caller, ApiError> {
        let now = now_millis();
        let p = mailcore::token::verify_now(token, &self.policy, now as f64 / 1000.0).map_err(|r| {
            ApiError::new(401, format!("token refused: {r}. Get a fresh one from https://{}", self.policy.iss))
        })?;
        if p.jti.is_some() {
            return Err(ApiError::new(401, "token refused: a one-time sign-in token works only to sign in"));
        }
        self.touch(&p.name, &p.sub);
        Ok(Caller { name: p.name, sub: p.sub, kind: p.kind, token: token.to_string(), exp_ms: (p.exp * 1000.0) as i64 })
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
        if body.get("files").is_some_and(|f| !f.is_null() && f.as_array().is_none_or(|a| !a.is_empty())) {
            return Err(ApiError::new(400, "attachments are not supported by mailnode yet (phase 2); send text only"));
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
        let text = clean_text(body.get("text"))?;
        let mode = match body.get("mode").and_then(|m| m.as_str()) {
            None | Some("members") => Mode::Members,
            Some("private") => Mode::Private,
            Some(_) => return Err(ApiError::new(400, "mode must be members or private")),
        };
        let since = ts_from_millis(now_millis() - REPEAT_MS);
        if let Some(row) = self.store.repeat(&who.sub, &since, &to, &thread, &text)? {
            if row.mode == mode.as_str() {
                let reaches = self.reaches(&to, &who.sub)?;
                return Ok(Posted { row, reaches, repeated: true });
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
        let parents = self.store.heads(&thread)?;
        let b = Body { text: text.clone(), files: vec![] };
        let env = Envelope::seal(
            Draft {
                thread: &thread,
                parents,
                ts: now_ts(),
                from: &who.name,
                to: &to,
                mode,
                body: &b,
                attest: Attest::Aid1 { token: who.token.clone() },
                recipients: &recipients,
            },
            &self.seed,
        )?;
        // Refuse to write what no other node would accept (e.g. this node is not on the member list).
        let v = env
            .verify(&members, &self.policy, now_millis())
            .map_err(|e| ApiError::new(503, format!("this node cannot write mail: {e}")))?;
        let readers = (mode == Mode::Private).then(|| readers_for(&members, &to, &who.name));
        let row = self
            .store
            .insert(&env, &v, Some(&text), readers.as_deref(), now_millis())?
            .ok_or_else(|| ApiError::new(500, "envelope id collision"))?;
        let _ = self.events.send(Arc::new(row.clone()));
        let _ = self.outbound.send(env);
        let reaches = self.reaches(&to, &who.sub)?;
        Ok(Posted { row, reaches, repeated: false })
    }

    /// A replicated envelope. Ok(None): already here. Err: refused (bad signature, token, member, shape).
    pub fn ingest(&self, env: Envelope) -> Result<Option<Arc<Row>>> {
        if self.store.has(&env.id)? {
            return Ok(None);
        }
        let members = self.members.read().unwrap().clone();
        let v = env.verify(&members, &self.policy, now_millis())?;
        let mut body = env.open(&self.seed).unwrap_or(None);
        if body.is_none() {
            for (_, s) in &self.identities {
                if let Ok(Some(b)) = env.open(s) {
                    body = Some(b);
                    break;
                }
            }
        }
        let text: Option<String> = body.map(|b| b.text.chars().take(MAX_TEXT as usize).collect());
        let readers = (env.mode == Mode::Private).then(|| readers_for(&members, &env.to, &env.from));
        let Some(row) = self.store.insert(&env, &v, text.as_deref(), readers.as_deref(), now_millis())? else {
            return Ok(None);
        };
        if v.imported.is_none() {
            let _ = self.store.seen(&env.from, &v.sender_sub, env.ts_ms());
        }
        let row = Arc::new(row);
        let _ = self.events.send(row.clone());
        Ok(Some(row))
    }

    /* Names */

    fn renames(&self) -> impl Iterator<Item = &Renamed> {
        self.renamed.iter().filter(|r| !r.name.is_empty() && !r.sub.is_empty() && !r.now.is_empty())
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

pub fn clean_text(v: Option<&Value>) -> Result<String, ApiError> {
    let Some(s) = v.and_then(|v| v.as_str()) else { return Err(ApiError::new(400, "text must be a string")) };
    let s: String = s.nfc().collect::<String>().replace("\r\n", "\n").replace('\r', "\n");
    let s: String = s
        .chars()
        .filter(|&c| !matches!(c as u32, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F) && !is_bidi(c))
        .collect();
    if s.encode_utf16().count() > MAX_TEXT as usize {
        return Err(ApiError::new(413, format!("text is over {MAX_TEXT} characters; attach it as a file")));
    }
    if s.trim().is_empty() {
        return Err(ApiError::new(400, "text is empty"));
    }
    Ok(s)
}

/// The old server's formatMessage: one header line the mailbox writes, then the sender's text, every line quoted.
pub fn format_message(r: &Row, max_text: usize) -> String {
    let text = r.text.clone().unwrap_or_default();
    let shown: String = text.chars().take(max_text).collect();
    let full = r.len.max(text.chars().count() as i64);
    let shown_n = shown.chars().count() as i64;
    let body = if full > shown_n {
        format!("{shown}\n[… {} more characters; get #{} for all of it]", full - shown_n, r.id)
    } else {
        shown
    };
    let from = if r.verified {
        format!("{} [{}]", r.sender, r.sender_sub)
    } else {
        format!("{} (unverified: copied from the old shared-password inbox)", r.sender)
    };
    let quoted: Vec<String> = body.split('\n').map(|l| format!("> {l}")).collect();
    let ts: String = r.ts.chars().take(16).collect();
    format!("#{} {}Z from {} to {}, thread \"{}\":\n{}", r.id, ts, from, r.recipient, r.thread, quoted.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailcore::keys::fmt_key;
    use mailcore::{Member, NodeEntry};

    fn setup() -> (Node, Seed, Seed, MemberList, mpsc::UnboundedReceiver<Envelope>) {
        let (home, op, node_a, node_b, alice) = (Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate(), Seed::generate());
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
            bridges: vec![],
            sig: String::new(),
        };
        list.sign(&op);
        let policy = TokenPolicy { home_key: home.public(), iss: "h".into(), aud: "mail".into(), scope: "mail:use".into() };
        let path = std::env::temp_dir().join(format!("mailnode-test-{}.sqlite", mailcore::b64u(&mailcore::random_bytes::<9>())));
        let (tx, rx) = mpsc::unbounded_channel();
        let node = Node::new(Store::open(&path).unwrap(), list.clone(), policy, node_a, vec![], vec![], tx);
        (node, home, node_b, list, rx)
    }

    fn token(home: &Seed) -> String {
        let now = now_millis() as f64 / 1000.0;
        mailcore::token::mint(
            home,
            &mailcore::Aid1Payload {
                v: 1,
                iss: "h".into(),
                sub: "agent:alice@t".into(),
                kind: "agent".into(),
                name: "a.alice".into(),
                aud: "mail".into(),
                scopes: vec!["mail:use".into()],
                claims: None,
                iat: now,
                exp: now + 600.0,
                jti: None,
            },
        )
    }

    fn envelope(writer: &Seed, list: &MemberList, home: &Seed, text: &str) -> Envelope {
        let body = Body { text: text.into(), files: vec![] };
        Envelope::seal(
            Draft {
                thread: "t",
                parents: vec![],
                ts: now_ts(),
                from: "a.alice",
                to: "all",
                mode: Mode::Members,
                body: &body,
                attest: Attest::Aid1 { token: token(home) },
                recipients: &list.all_keys(),
            },
            writer,
        )
        .unwrap()
    }

    #[test]
    fn ingest_dedupes_by_envelope_id() {
        let (node, home, node_b, list, _rx) = setup();
        let e = envelope(&node_b, &list, &home, "once");
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
    fn ingest_refuses_non_member_writer() {
        let (node, home, _node_b, list, _rx) = setup();
        let stranger = Seed::generate();
        let e = envelope(&stranger, &list, &home, "spoof");
        assert!(node.ingest(e).is_err());
        assert_eq!(node.store.count().unwrap(), 0);
    }

    #[test]
    fn post_signs_stores_and_announces() {
        let (node, home, _node_b, _list, mut rx) = setup();
        let who = node.verify(&token(&home)).unwrap();
        let p = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(!p.repeated);
        let out = rx.try_recv().expect("gossiped");
        assert_eq!(out.id, p.row.env_id);
        let p2 = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "hi" })).unwrap();
        assert!(p2.repeated, "identical resend is answered with the first");
        let p3 = node.post(&who, &json!({ "to": "all", "thread": "t", "text": "next" })).unwrap();
        assert_eq!(rx.try_recv().unwrap().parents, vec![p.row.env_id.clone()], "parents = thread heads");
        assert!(p3.row.id > p.row.id);
    }
}
