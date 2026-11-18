//! Domain blocklist ("NetShield"-style ad/tracker/malware filtering).
//!
//! Matching is by suffix on label boundaries: blocking `ads.example` also
//! blocks `x.ads.example` but not `badads.example`.

use std::collections::HashSet;

#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    domains: HashSet<String>,
    allow: HashSet<String>,
}

pub fn normalize(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    pub fn insert(&mut self, domain: &str) {
        let d = normalize(domain);
        if !d.is_empty() && d.contains('.') {
            self.domains.insert(d);
        }
    }

    /// Explicitly allowed domains win over blocked parents.
    pub fn allow(&mut self, domain: &str) {
        self.allow.insert(normalize(domain));
    }

    /// Load hosts-file (`0.0.0.0 ads.example`) or plain domain-per-line lists.
    /// Comments (`#`, `!`) and adblock-style `||domain^` lines are handled.
    pub fn load_text(&mut self, text: &str) -> usize {
        let before = self.domains.len();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('!') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let first = parts.next().unwrap_or("");
            let domain = if first == "0.0.0.0" || first == "127.0.0.1" || first == "::" {
                match parts.next() {
                    Some(d) => d,
                    None => continue,
                }
            } else {
                first
            };
            let domain = domain.trim_start_matches("||").trim_end_matches('^');
            if domain == "localhost" || domain.contains('/') || domain.contains('*') {
                continue;
            }
            self.insert(domain);
        }
        self.domains.len() - before
    }

    fn suffixes(domain: &str) -> impl Iterator<Item = &str> {
        let mut idx = Some(0usize);
        std::iter::from_fn(move || {
            let i = idx?;
            let rest = &domain[i..];
            idx = rest.find('.').map(|p| i + p + 1);
            Some(rest)
        })
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let d = normalize(domain);
        if Self::suffixes(&d).any(|s| self.allow.contains(s)) {
            return false;
        }
        let blocked = Self::suffixes(&d).any(|s| self.domains.contains(s));
        blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching_respects_labels() {
        let mut b = Blocklist::new();
        b.insert("ads.example.com");
        assert!(b.is_blocked("ads.example.com"));
        assert!(b.is_blocked("x.y.ADS.example.com."));
        assert!(!b.is_blocked("badads.example.com"));
        assert!(!b.is_blocked("example.com"));
    }

    #[test]
    fn loads_hosts_and_adblock_formats() {
        let mut b = Blocklist::new();
        let n = b.load_text(
            "# comment\n0.0.0.0 tracker.io\n127.0.0.1 localhost\n||doubleclick.net^\nmalware.test # inline\n! adblock comment\n*.wild.card\n",
        );
        assert_eq!(n, 3);
        assert!(b.is_blocked("ad.doubleclick.net"));
        assert!(b.is_blocked("tracker.io"));
        assert!(b.is_blocked("malware.test"));
        assert!(!b.is_blocked("localhost"));
    }

    #[test]
    fn allowlist_overrides() {
        let mut b = Blocklist::new();
        b.insert("example.com");
        b.allow("good.example.com");
        assert!(b.is_blocked("bad.example.com"));
        assert!(!b.is_blocked("api.good.example.com"));
    }
}
