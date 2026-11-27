//! Rooms. Every thread is a room: a plain thread name is an open room, `creator/name` is a room its creator made
//! (open or private), and `dm:a+b` is the private room of two agents. Room facts travel inside message bodies as a
//! signed `meta` object (covered by the sender's digest): membership events, mentions, replies and key grants.
//! Nodes never enforce membership; each folds the events it can read into the state below, the same way everywhere.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::addr::norm;

/// Most key grants one message carries, and most mentions.
pub const MAX_GRANTS: usize = 1000;
pub const MAX_MENTIONS: usize = 32;
pub const MAX_META: usize = 256 * 1024;
pub const MAX_TOPIC: usize = 300;
pub const MAX_ROOM_MEMBERS: usize = 200;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum History {
    /// A member who joins can read the room's earlier messages (the adder sends key grants).
    #[default]
    #[serde(rename = "full")]
    Full,
    /// Only what is sent after joining.
    #[serde(rename = "since-join")]
    SinceJoin,
}

impl History {
    pub fn as_str(&self) -> &'static str {
        match self {
            History::Full => "full",
            History::SinceJoin => "since-join",
        }
    }
}

/// A membership event, carried in a room message's meta.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Event {
    Create {
        #[serde(default)]
        private: bool,
        #[serde(default)]
        history: History,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        topic: String,
        /// Members besides the creator.
        #[serde(default)]
        members: Vec<String>,
    },
    Add { members: Vec<String> },
    Leave {},
    Remove { members: Vec<String> },
    Topic { topic: String },
    /// The creator's word on its members' keys and home nodes, for hosts that do not trust those nodes: such a host
    /// accepts mail in this room (and nowhere else) written by a listed node for its listed agent. The latest vouch
    /// replaces earlier ones; membership still comes from the other events.
    Vouch { members: Vec<VouchEntry> },
}

/// One vouched member: its name, sub and key, and the nodes that write for it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VouchEntry {
    pub name: String,
    pub sub: String,
    pub key: String,
    pub nodes: Vec<String>,
}

/// Most nodes one vouched member lists.
pub const MAX_VOUCH_NODES: usize = 8;

impl Event {
    /// Names this event brings into the room (they receive the event itself).
    pub fn added(&self) -> &[String] {
        match self {
            Event::Create { members, .. } | Event::Add { members } => members,
            _ => &[],
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Event::Create { .. } => 0,
            Event::Add { .. } | Event::Topic { .. } | Event::Vouch { .. } => 1,
            Event::Leave {} | Event::Remove { .. } => 2,
        }
    }

    /// One line for people: "created the room", "added alice, bob".
    pub fn describe(&self) -> String {
        match self {
            Event::Create { private, history, topic, members } => {
                let mut s = format!("created this {} room", if *private { "private" } else { "open" });
                if *private && *history == History::SinceJoin {
                    s.push_str(" (new members see only later messages)");
                }
                if !members.is_empty() {
                    s.push_str(&format!(" with {}", members.join(", ")));
                }
                if !topic.is_empty() {
                    s.push_str(&format!("; topic: {topic}"));
                }
                s
            }
            Event::Add { members } => format!("added {}", members.join(", ")),
            Event::Leave {} => "left the room".into(),
            Event::Remove { members } => format!("removed {}", members.join(", ")),
            Event::Topic { topic } => format!("set the topic: {topic}"),
            Event::Vouch { members } => format!("vouched for the nodes of {}",
                members.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ")),
        }
    }
}

/// One re-wrapped content key: the envelope it opens and the key (b64url, 32 bytes).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GrantItem {
    pub env: String,
    pub ck: String,
}

/// The signed room fields of a message body. Absent fields stay out of the JSON.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// The room this message was posted in (equal to the envelope's thread).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<String>,
    /// Envelope id of the message this one answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant: Vec<GrantItem>,
}

impl Meta {
    pub fn is_empty(&self) -> bool {
        *self == Meta::default()
    }

    /// Parse and bound a meta string (the exact bytes the sender signed). Empty: no meta.
    pub fn parse(raw: &str) -> Result<Meta> {
        if raw.is_empty() {
            return Ok(Meta::default());
        }
        ensure!(raw.len() <= MAX_META, "meta is over {MAX_META} bytes");
        let m: Meta = serde_json::from_str(raw).map_err(|e| anyhow!("invalid meta: {e}"))?;
        ensure!(!m.is_empty(), "empty meta must be omitted");
        if let Some(r) = &m.room {
            ensure!(valid_room_id(r), "invalid room id");
        }
        ensure!(m.mentions.len() <= MAX_MENTIONS && m.mentions.iter().all(|n| crate::cert::valid_name(n)), "invalid mentions");
        if let Some(r) = &m.reply_to {
            ensure!(crate::envelope::is_id(r), "reply_to must be an envelope id");
        }
        ensure!(m.grant.len() <= MAX_GRANTS, "at most {MAX_GRANTS} key grants per message");
        for g in &m.grant {
            ensure!(crate::envelope::is_id(&g.env), "grant names an invalid envelope id");
            ensure!(crate::b64u_decode(&g.ck).is_some_and(|k| k.len() == 32), "grant key must be 32 bytes");
        }
        if let Some(e) = &m.event {
            ensure!(m.room.is_some() && m.grant.is_empty(), "a membership event belongs to a room post");
            let names = match e {
                Event::Create { members, topic, .. } => {
                    ensure!(topic.chars().count() <= MAX_TOPIC, "topic is too long");
                    members.as_slice()
                }
                Event::Add { members } | Event::Remove { members } => {
                    ensure!(!members.is_empty(), "name at least one member");
                    members.as_slice()
                }
                Event::Topic { topic } => {
                    ensure!(topic.chars().count() <= MAX_TOPIC, "topic is too long");
                    &[]
                }
                Event::Leave {} => &[],
                Event::Vouch { members } => {
                    ensure!(members.len() <= MAX_ROOM_MEMBERS, "invalid member names");
                    for v in members {
                        ensure!(crate::cert::valid_name(&v.name), "invalid member names");
                        ensure!(crate::cert::valid_sub(&v.sub), "invalid vouched sub");
                        ensure!(crate::keys::parse_key(&v.key).is_ok(), "invalid vouched key");
                        ensure!((1..=MAX_VOUCH_NODES).contains(&v.nodes.len())
                                && v.nodes.iter().all(|n| crate::keys::parse_key(n).is_ok()), "invalid vouched nodes");
                    }
                    &[]
                }
            };
            ensure!(names.len() <= MAX_ROOM_MEMBERS && names.iter().all(|n| crate::cert::valid_name(n)), "invalid member names");
        }
        Ok(m)
    }
}

/// A room id: a thread name (open room), `creator/name`, or a DM id.
pub fn valid_room_id(id: &str) -> bool {
    !id.is_empty() && id.chars().count() <= 100 && !id.chars().any(|c| c.is_control())
}

/// The DM room of two agents; the same whichever of them asks.
pub fn dm_id(a: &str, b: &str) -> String {
    let (a, b) = (norm(a), norm(b));
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    format!("dm:{x}+{y}")
}

pub fn dm_pair(id: &str) -> Option<(String, String)> {
    let (a, b) = id.strip_prefix("dm:")?.split_once('+')?;
    (crate::cert::valid_name(a) && crate::cert::valid_name(b) && dm_id(a, b) == id).then(|| (a.to_string(), b.to_string()))
}

/// The creator part of `creator/name`.
pub fn creator_of(id: &str) -> Option<&str> {
    let (c, name) = id.split_once('/')?;
    (crate::cert::valid_name(c) && crate::cert::valid_name(name)).then_some(c)
}

/// `to` of a room post that is not a DM: it addresses no agent, so only mentions wake anyone.
pub fn room_to(id: &str) -> String {
    if id.chars().all(|c| c.is_ascii_alphanumeric() || "._:/+-@".contains(c)) && id.len() <= 100 {
        format!("room:{id}")
    } else {
        "room:".into()
    }
}

/// `@name` mentions in text, normalized, at most MAX_MENTIONS.
pub fn mentions_in(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' && (i == 0 || !(word(chars[i - 1]) || chars[i - 1] == '@')) {
            let mut j = i + 1;
            while j < chars.len() && (word(chars[j]) || chars[j] == '.' || chars[j] == '-') {
                j += 1;
            }
            let name: String = chars[i + 1..j].iter().collect::<String>().trim_end_matches(['.', '-']).to_lowercase();
            if crate::cert::valid_name(&name) && !out.contains(&name) && out.len() < MAX_MENTIONS {
                out.push(name);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Open,
    Private,
    Dm,
}

/// What a node knows of a room from the events it can read.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct State {
    pub id: String,
    pub kind: Kind,
    pub creator: Option<String>,
    pub history: History,
    pub topic: String,
    /// Current members (normalized name) and when each (last) joined.
    pub members: BTreeMap<String, String>,
    /// Earlier members who left or were removed.
    pub former: BTreeSet<String>,
    /// Whether a create event was seen (namespaced rooms exist only after one).
    pub created: bool,
}

impl State {
    pub fn is_member(&self, name: &str) -> bool {
        self.members.contains_key(&norm(name))
    }

    pub fn private(&self) -> bool {
        self.kind != Kind::Open
    }
}

/// One readable event: (envelope id, ts, sender, event).
pub struct Folded<'a> {
    pub id: &'a str,
    pub ts: &'a str,
    pub from: &'a str,
    pub event: &'a Event,
}

/// Fold a room's events in time order; at the same timestamp a leave or remove comes after an add (it wins).
/// Unauthorized events are skipped: any member adds (anyone, in an open room), a member leaves, the creator
/// removes others, a member sets the topic.
pub fn fold(id: &str, events: &mut [Folded<'_>]) -> State {
    if let Some((a, b)) = dm_pair(id) {
        let members = [(a, String::new()), (b, String::new())].into_iter().collect();
        return State { id: id.into(), kind: Kind::Dm, creator: None, history: History::Full, topic: String::new(),
                       members, former: BTreeSet::new(), created: true };
    }
    let creator = creator_of(id).map(norm);
    let mut s = State { id: id.into(), kind: Kind::Open, creator: creator.clone(), history: History::Full,
                        topic: String::new(), members: BTreeMap::new(), former: BTreeSet::new(), created: creator.is_none() };
    events.sort_by(|x, y| (x.ts, x.event.rank(), x.id).cmp(&(y.ts, y.event.rank(), y.id)));
    for e in events.iter() {
        let from = norm(e.from);
        let member = s.members.contains_key(&from);
        let may_write = member || s.kind == Kind::Open;
        match e.event {
            Event::Create { private, history, topic, members } => {
                if s.created || creator.as_deref() != Some(from.as_str()) {
                    continue;
                }
                s.created = true;
                s.kind = if *private { Kind::Private } else { Kind::Open };
                s.history = *history;
                s.topic.clone_from(topic);
                for m in std::iter::once(&from).chain(members.iter()) {
                    s.members.insert(norm(m), e.ts.to_string());
                }
            }
            _ if !s.created => {}
            Event::Add { members } => {
                if !may_write {
                    continue;
                }
                for m in members {
                    let m = norm(m);
                    s.former.remove(&m);
                    s.members.entry(m).or_insert_with(|| e.ts.to_string());
                }
            }
            Event::Leave {} => {
                if s.members.remove(&from).is_some() {
                    s.former.insert(from);
                }
            }
            Event::Remove { members } => {
                for m in members {
                    let m = norm(m);
                    if (m == from || s.creator.as_deref() == Some(from.as_str())) && s.members.remove(&m).is_some() {
                        s.former.insert(m);
                    }
                }
            }
            Event::Topic { topic } => {
                if may_write {
                    s.topic.clone_from(topic);
                }
            }
            // Read by the node (`vouched`), not part of membership.
            Event::Vouch { .. } => {}
        }
    }
    s
}

/// Who a new room post goes to. `state`: the room as this node folds it (None: no events here). Returns
/// (private, member names to wrap to; None means every member key of the network).
pub fn plan(id: &str, state: Option<&State>, from: &str, event: Option<&Event>) -> Result<(bool, Option<Vec<String>>)> {
    ensure!(valid_room_id(id), "invalid room id");
    if let Some((a, b)) = dm_pair(id) {
        ensure!(event.is_none(), "a DM has no membership events");
        ensure!(norm(from) == a || norm(from) == b, "this DM belongs to {a} and {b}");
        return Ok((true, Some(vec![a, b])));
    }
    if id.starts_with("dm:") {
        bail!("a DM id is dm:NAME+NAME, sorted and in lower case");
    }
    let from_n = norm(from);
    if let Some(Event::Create { private, members, .. }) = event {
        let creator = creator_of(id).ok_or_else(|| anyhow!("a new room is named CREATOR/NAME"))?;
        ensure!(norm(creator) == from_n, "only {creator} can create {id}");
        ensure!(state.is_none_or(|s| !s.created), "{id} already exists");
        let mut names: Vec<String> = std::iter::once(from_n).chain(members.iter().map(|m| norm(m))).collect();
        names.sort();
        names.dedup();
        return Ok((*private, private.then_some(names)));
    }
    let state = match state {
        Some(s) if s.created => s,
        _ if creator_of(id).is_some() => bail!("no room {id} here (private rooms are invite-only)"),
        _ if id.contains('/') => bail!("room names are CREATOR/NAME with letters, digits, dots, underscores or hyphens"),
        // A plain thread: an open room that needs no create event.
        _ => return Ok((false, None)),
    };
    if let Some(Event::Vouch { .. }) = event {
        ensure!(state.creator.as_deref() == Some(from_n.as_str()), "only the room's creator vouches for its members");
    }
    if !state.private() {
        return Ok((false, None));
    }
    ensure!(state.is_member(from), "you are not a member of {id}");
    if let Some(Event::Remove { members }) = event {
        let creator = state.creator.as_deref() == Some(from_n.as_str());
        ensure!(creator || members.iter().all(|m| norm(m) == from_n), "only the creator removes others; use leave");
    }
    let mut names: Vec<String> = state.members.keys().cloned().collect();
    if let Some(e) = event {
        names.extend(e.added().iter().map(|m| norm(m)));
    }
    names.sort();
    names.dedup();
    ensure!(names.len() <= MAX_ROOM_MEMBERS, "a room has at most {MAX_ROOM_MEMBERS} members");
    Ok((true, Some(names)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev<'a>(id: &'a str, ts: &'a str, from: &'a str, event: &'a Event) -> Folded<'a> {
        Folded { id, ts, from, event }
    }

    #[test]
    fn dm_ids_are_symmetric() {
        assert_eq!(dm_id("dana", "Ops.Bob"), dm_id("ops.bob", "DANA"));
        assert_eq!(dm_id("b", "a"), "dm:a+b");
        assert_eq!(dm_pair("dm:a+b"), Some(("a".into(), "b".into())));
        assert_eq!(dm_pair("dm:b+a"), None);
        assert!(room_to("dana/plan") == "room:dana/plan" && room_to("a b") == "room:");
    }

    #[test]
    fn mentions() {
        assert_eq!(mentions_in("hi @Alice and @ops.bob. mail a@b.c @@x @a_1-"), vec!["alice", "ops.bob", "a_1"]);
        assert_eq!(dm_pair(&dm_id("p.bob", "fable")), Some(("fable".into(), "p.bob".into())));
        assert_eq!(creator_of("fable/plan"), Some("fable"));
    }

    #[test]
    fn membership_folds_with_rights_and_leave_wins_ties() {
        let create = Event::Create { private: true, history: History::Full, topic: "t".into(), members: vec!["bob".into()] };
        let add_carol = Event::Add { members: vec!["carol".into()] };
        let leave = Event::Leave {};
        let remove_bob = Event::Remove { members: vec!["bob".into()] };
        let add_eve = Event::Add { members: vec!["eve".into()] };
        let mut events = vec![
            ev("2", "2026-01-01T00:00:02.000Z", "bob", &add_carol),
            ev("1", "2026-01-01T00:00:01.000Z", "dana", &create),
            // carol leaves at the same time someone re-adds her: the leave wins.
            ev("3", "2026-01-01T00:00:03.000Z", "carol", &leave),
            ev("4", "2026-01-01T00:00:03.000Z", "bob", &add_carol),
            // eve is not a member: her add does nothing. bob cannot remove others... but may remove himself.
            ev("5", "2026-01-01T00:00:04.000Z", "eve", &add_eve),
        ];
        let s = fold("dana/plan", &mut events);
        assert_eq!(s.kind, Kind::Private);
        assert_eq!(s.members.keys().collect::<Vec<_>>(), ["bob", "dana"]);
        assert!(s.former.contains("carol"));
        let mut events = vec![ev("1", "2026-01-01T00:00:01.000Z", "dana", &create),
                              ev("2", "2026-01-01T00:00:02.000Z", "dana", &remove_bob)];
        let s = fold("dana/plan", &mut events);
        assert_eq!(s.members.keys().collect::<Vec<_>>(), ["dana"]);
        // A create by someone other than the id's creator is ignored.
        let mut events = vec![ev("1", "2026-01-01T00:00:01.000Z", "eve", &create)];
        assert!(!fold("dana/plan", &mut events).created);
    }

    #[test]
    fn plans_follow_membership() {
        let create = Event::Create { private: true, history: History::Full, topic: String::new(), members: vec!["bob".into()] };
        assert_eq!(plan("dana/x", None, "dana", Some(&create)).unwrap(), (true, Some(vec!["bob".into(), "dana".into()])));
        assert!(plan("dana/x", None, "bob", Some(&create)).is_err());
        assert!(plan("dana/x", None, "dana", None).is_err());
        let mut events = vec![ev("1", "2026-01-01T00:00:01.000Z", "dana", &create)];
        let s = fold("dana/x", &mut events);
        assert!(plan("dana/x", Some(&s), "eve", None).is_err());
        let add = Event::Add { members: vec!["carol".into()] };
        assert_eq!(plan("dana/x", Some(&s), "bob", Some(&add)).unwrap().1.unwrap(), ["bob", "carol", "dana"]);
        assert!(plan("dana/x", Some(&s), "bob", Some(&Event::Remove { members: vec!["dana".into()] })).is_err());
        assert_eq!(plan("general", None, "eve", None).unwrap(), (false, None));
        assert_eq!(plan(&dm_id("a", "b"), None, "a", None).unwrap(), (true, Some(vec!["a".into(), "b".into()])));
        assert!(plan(&dm_id("a", "b"), None, "c", None).is_err());
        // Only the creator vouches, and a vouch changes no membership.
        let vouch = Event::Vouch { members: vec![] };
        assert!(plan("dana/x", Some(&s), "bob", Some(&vouch)).is_err());
        assert_eq!(plan("dana/x", Some(&s), "dana", Some(&vouch)).unwrap().1.unwrap(), ["bob", "dana"]);
        let mut events = vec![ev("1", "2026-01-01T00:00:01.000Z", "dana", &create), ev("2", "2026-01-01T00:00:02.000Z", "dana", &vouch)];
        assert_eq!(fold("dana/x", &mut events).members.keys().collect::<Vec<_>>(), ["bob", "dana"]);
    }

    #[test]
    fn meta_is_bounded() {
        assert!(Meta::parse("").unwrap().is_empty());
        assert!(Meta::parse("{}").is_err());
        assert!(Meta::parse(r#"{"room":"x","extra":1}"#).is_err());
        let m = Meta::parse(r#"{"room":"dana/x","event":{"op":"add","members":["bob"]}}"#).unwrap();
        assert_eq!(m.event, Some(Event::Add { members: vec!["bob".into()] }));
        assert!(Meta::parse(r#"{"event":{"op":"leave"}}"#).is_err());
        assert!(Meta::parse(r#"{"grant":[{"env":"x","ck":"y"}]}"#).is_err());
        let k = crate::keys::fmt_key(&crate::keys::Seed::generate().public());
        let vouch = |name: &str, nodes: &str| format!(r#"{{"room":"dana/x","event":{{"op":"vouch","members":[{{"name":"{name}","sub":"agent:{name}","key":"{k}","nodes":[{nodes}]}}]}}}}"#);
        assert!(Meta::parse(&vouch("bob", &format!("\"{k}\""))).is_ok());
        assert!(Meta::parse(&vouch("bob", "")).is_err(), "a vouched member names at least one node");
        assert!(Meta::parse(&vouch("bob", "\"x\"")).is_err(), "nodes are keys");
        assert!(Meta::parse(&vouch("a b", &format!("\"{k}\""))).is_err());
    }
}
