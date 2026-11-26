//! Display order of a room: by signed timestamp (ties by envelope hash), with each reply placed under the message it
//! answers (after that message and its earlier replies). A timestamp more than `MAX_AHEAD_MS` past the time this node
//! received the envelope counts as the receipt time, so a fast clock cannot pin a message to the bottom. Nodes that
//! received the same set at about the same time agree on the order; arrival still drives watch and wake.

use std::collections::HashMap;

pub const MAX_AHEAD_MS: i64 = 5 * 60_000;

/// When a message sorts: its signed time, clamped to at most `MAX_AHEAD_MS` after receipt.
pub fn display_ms(ts_ms: i64, received_ms: i64) -> i64 {
    ts_ms.min(received_ms.saturating_add(MAX_AHEAD_MS))
}

pub struct Item<'a> {
    /// Envelope hash.
    pub id: &'a str,
    /// `display_ms`.
    pub at: i64,
    /// Envelope hash of the message this one answers.
    pub reply_to: Option<&'a str>,
}

/// Indices of `items` in display order: roots by (at, id), each followed depth-first by its replies, also by (at, id).
/// A reply whose parent is not in `items` is a root.
pub fn room_order(items: &[Item<'_>]) -> Vec<usize> {
    let index: HashMap<&str, usize> = items.iter().enumerate().map(|(i, it)| (it.id, i)).collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); items.len()];
    let mut roots = Vec::new();
    for (i, it) in items.iter().enumerate() {
        match it.reply_to.and_then(|p| index.get(p).copied()).filter(|&p| p != i) {
            Some(p) => children[p].push(i),
            None => roots.push(i),
        }
    }
    let key = |&i: &usize| (items[i].at, items[i].id);
    roots.sort_by_key(key);
    for c in &mut children {
        c.sort_by_key(key);
    }
    let mut out = Vec::with_capacity(items.len());
    let mut seen = vec![false; items.len()];
    let walk = |start: usize, out: &mut Vec<usize>, seen: &mut Vec<bool>| {
        let mut stack = vec![start];
        while let Some(i) = stack.pop() {
            if std::mem::replace(&mut seen[i], true) {
                continue;
            }
            out.push(i);
            stack.extend(children[i].iter().rev().copied());
        }
    };
    for &r in &roots {
        walk(r, &mut out, &mut seen);
    }
    // Content hashes cannot form a reply cycle, but a malformed set must not lose rows.
    let mut rest: Vec<usize> = (0..items.len()).filter(|&i| !seen[i]).collect();
    rest.sort_by_key(key);
    for r in rest {
        walk(r, &mut out, &mut seen);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(v: &[(&str, i64, Option<&str>)]) -> Vec<String> {
        let items: Vec<Item> = v.iter().map(|&(id, at, reply_to)| Item { id, at, reply_to }).collect();
        room_order(&items).into_iter().map(|i| v[i].0.to_string()).collect()
    }

    #[test]
    fn time_order_with_replies_under_their_parent() {
        let v = [("a", 10, None), ("b", 20, None), ("c", 30, Some("a")), ("d", 20, None), ("e", 25, Some("c")),
                 ("f", 5, Some("missing")), ("g", 40, Some("a"))];
        let first = order(&v);
        assert_eq!(first, ["f", "a", "c", "e", "g", "b", "d"]);
        for rot in 1..v.len() {
            let mut w = v.to_vec();
            w.rotate_left(rot);
            w.reverse();
            assert_eq!(order(&w), first, "same set, any input order");
        }
    }

    #[test]
    fn fast_clocks_are_clamped_to_receipt() {
        assert_eq!(display_ms(1_000_000, 1_000_000), 1_000_000);
        assert_eq!(display_ms(1_000_000 + MAX_AHEAD_MS, 1_000_000), 1_000_000 + MAX_AHEAD_MS);
        assert_eq!(display_ms(9_000_000_000, 1_000_000), 1_000_000 + MAX_AHEAD_MS);
        assert_eq!(display_ms(5, 1_000_000), 5, "an old timestamp keeps its place");
    }

    #[test]
    fn cycles_do_not_lose_rows() {
        assert_eq!(order(&[("x", 1, Some("y")), ("y", 2, Some("x"))]).len(), 2);
    }
}
