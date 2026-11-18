//! Per-thread order: a topological order of the `parents` DAG (a message after every parent this node has), and among
//! messages that are ready at the same time, ascending (ts, id). It depends only on the set of envelopes, so every
//! node holding the same set computes the same order. Parents a node does not (yet) have are ignored.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

pub struct Item<'a> {
    pub id: &'a str,
    pub ts: &'a str,
    pub parents: &'a [String],
}

/// Indices of `items` in thread order.
pub fn thread_order(items: &[Item<'_>]) -> Vec<usize> {
    let index: HashMap<&str, usize> = items.iter().enumerate().map(|(i, it)| (it.id, i)).collect();
    let mut pending = vec![0usize; items.len()];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); items.len()];
    for (i, it) in items.iter().enumerate() {
        let mut ps: Vec<usize> = it.parents.iter().filter_map(|p| index.get(p.as_str()).copied()).filter(|&p| p != i).collect();
        ps.sort_unstable();
        ps.dedup();
        pending[i] = ps.len();
        for p in ps {
            children[p].push(i);
        }
    }
    let key = |i: usize| Reverse((items[i].ts, items[i].id, i));
    let mut ready: BinaryHeap<_> = (0..items.len()).filter(|&i| pending[i] == 0).map(key).collect();
    let mut out = Vec::with_capacity(items.len());
    let mut done = vec![false; items.len()];
    while let Some(Reverse((_, _, i))) = ready.pop() {
        out.push(i);
        done[i] = true;
        for &c in &children[i] {
            pending[c] -= 1;
            if pending[c] == 0 {
                ready.push(key(c));
            }
        }
    }
    // A cycle cannot be built from content hashes, but a malformed set must not lose rows: append them by (ts, id).
    if out.len() < items.len() {
        let mut rest: Vec<usize> = (0..items.len()).filter(|&i| !done[i]).collect();
        rest.sort_by_key(|&i| (items[i].ts, items[i].id));
        out.extend(rest);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(order: &[usize], v: &[(String, String, Vec<String>)]) -> Vec<String> {
        order.iter().map(|&i| v[i].0.clone()).collect()
    }

    #[test]
    fn deterministic_and_causal() {
        // c replies to b, but b's clock is ahead: c still comes after b. d and e are concurrent replies to a.
        let v: Vec<(String, String, Vec<String>)> = vec![
            ("a".into(), "2026-01-01T00:00:00.000Z".into(), vec![]),
            ("b".into(), "2026-01-01T00:00:09.000Z".into(), vec!["a".into()]),
            ("c".into(), "2026-01-01T00:00:05.000Z".into(), vec!["b".into()]),
            ("e".into(), "2026-01-01T00:00:01.000Z".into(), vec!["a".into()]),
            ("d".into(), "2026-01-01T00:00:01.000Z".into(), vec!["a".into(), "missing".into()]),
        ];
        let items: Vec<Item> = v.iter().map(|(i, t, p)| Item { id: i, ts: t, parents: p }).collect();
        let first = ids(&thread_order(&items), &v);
        assert_eq!(first, ["a", "d", "e", "b", "c"]);
        // Same set in any input order: same result.
        for rot in 1..v.len() {
            let mut w = v.clone();
            w.rotate_left(rot);
            w.reverse();
            let items: Vec<Item> = w.iter().map(|(i, t, p)| Item { id: i, ts: t, parents: p }).collect();
            assert_eq!(ids(&thread_order(&items), &w), first);
        }
    }
}
