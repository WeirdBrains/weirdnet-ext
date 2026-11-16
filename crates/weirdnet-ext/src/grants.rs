//! What the user granted an extension, and checks against it.

use crate::manifest::Capability;
use serde::{Deserialize, Serialize};

/// Granted capabilities. A capability with patterns allows only targets matching one of
/// them; without patterns it allows any target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants(pub Vec<Capability>);

/// `*` matches any run of characters (including none); everything else matches itself.
pub fn glob(pattern: &str, s: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), s.as_bytes());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

impl Grants {
    /// Nothing granted.
    pub fn none() -> Self {
        Self::default()
    }

    /// True if `name` is granted for `target` (a URL or site; `None` for capabilities without
    /// a target).
    pub fn allows(&self, name: &str, target: Option<&str>) -> bool {
        self.0.iter().any(|c| c.name == name && (c.patterns.is_empty() || target.is_some_and(|t| c.patterns.iter().any(|p| glob(p, t)))))
    }

    /// Removes a capability (takes effect on the next call).
    pub fn revoke(&mut self, name: &str) {
        self.0.retain(|c| c.name != name);
    }

    /// The wire form.
    pub fn to_proto(&self) -> Vec<weirdnet_ext_proto::v1::Capability> {
        self.0.iter().map(|c| weirdnet_ext_proto::v1::Capability { name: c.name.clone(), patterns: c.patterns.clone() }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("https://*.example.com/*", "https://a.example.com/x/y"));
        assert!(!glob("https://*.example.com/*", "https://example.org/"));
        assert!(glob("*", ""));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(!glob("a*b*c", "aXXbYY"));
        assert!(glob("exact", "exact") && !glob("exact", "exactly"));
    }

    #[test]
    fn grants_check_patterns_and_revoke() {
        let mut g = Grants(vec![Capability::new("storage"), Capability::with_patterns("net.fetch", &["https://api.example.com/*"])]);
        assert!(g.allows("storage", None));
        assert!(g.allows("net.fetch", Some("https://api.example.com/v1")));
        assert!(!g.allows("net.fetch", Some("https://evil.test/")));
        assert!(!g.allows("net.fetch", None));
        assert!(!g.allows("page.read", None));
        g.revoke("storage");
        assert!(!g.allows("storage", None));
    }
}
