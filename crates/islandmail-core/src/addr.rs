//! Addressing: `to` is names separated by commas or spaces, team prefixes ending in '.', or
//! all / *. Case-insensitive.

pub fn norm(s: &str) -> String {
    s.trim().to_lowercase()
}

pub fn same(a: &str, b: &str) -> bool {
    norm(a) == norm(b)
}

fn items(to: &str) -> impl Iterator<Item = String> + '_ {
    to.split(|c: char| c == ',' || c.is_whitespace()).map(norm).filter(|s| !s.is_empty())
}

/// Whether mail to `to` reaches an agent known by any of `names`.
pub fn addressed_to(to: &str, names: &[&str]) -> bool {
    let ns: Vec<String> = names.iter().map(|n| norm(n)).collect();
    items(to).any(|i| i == "all" || i == "*" || ns.iter().any(|n| *n == i || (i.ends_with('.') && n.starts_with(&i))))
}

pub fn is_broadcast(to: &str) -> bool {
    items(to).any(|i| i == "all" || i == "*" || i.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addressing() {
        assert!(addressed_to("sauersml.lead", &["SauersML.Lead"]));
        assert!(!addressed_to("sauersml/lead", &["sauersml.lead"]));
        assert!(addressed_to("ops., hypha", &["ops.orchestrator"]));
        assert!(addressed_to("all", &["x"]));
        assert!(addressed_to("*", &["x"]));
        assert!(!addressed_to("ops.", &["sauersml.lead"]));
        assert!(!addressed_to("sauersml.lea", &["sauersml.lead"]));
        assert!(is_broadcast("a, ops."));
        assert!(!is_broadcast("a, b"));
    }
}
