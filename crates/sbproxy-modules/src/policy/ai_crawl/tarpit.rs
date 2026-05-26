//! AI-crawler tarpit (WOR-810).
//!
//! A deterministic, capped maze of invisible `nofollow` links served to
//! an unauthorized crawler instead of a hard 402/block, to waste its
//! crawl budget. Every link points at another path under the same
//! origin, which is itself tarpitted, so the crawler wanders a
//! self-perpetuating labyrinth. The page is deterministic (a re-crawl
//! sees the same maze and gains nothing) and bounded (link count is
//! clamped) so it is cheap to generate and cannot self-DoS the proxy.

use std::fmt::Write as _;

/// Maximum links per tarpit page. Clamps the configured value so a
/// misconfiguration cannot make a single response unbounded.
pub const MAX_TARPIT_LINKS: usize = 64;

/// Default link count when tarpit is enabled without an explicit count.
pub const DEFAULT_TARPIT_LINKS: usize = 24;

/// A small deterministic hash of `path` mixed with `i`, used to derive
/// stable synthetic sub-path slugs (FNV-1a over the bytes plus the
/// index). Deterministic so the maze is stable across re-crawls.
fn slug_hash(path: &str, i: usize) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in path.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= i as u64;
    h.wrapping_mul(0x100000001b3)
}

/// Generate a deterministic tarpit HTML page seeded by `path`, with
/// `links` invisible `nofollow` links to synthetic sub-paths (clamped to
/// `[1, MAX_TARPIT_LINKS]`). The links are hidden (`display:none`) and
/// `nofollow`/`noindex` so a real browser sees only a benign stub while
/// a crawler that ignores those hints follows them deeper into the maze.
pub fn generate_maze(path: &str, links: usize) -> String {
    let n = links.clamp(1, MAX_TARPIT_LINKS);
    let base = path.trim_end_matches('/');
    let mut out = String::with_capacity(320 + n * 72);
    out.push_str(
        "<!doctype html><html><head><meta name=\"robots\" content=\"noindex,nofollow\">\
         <title>Loading</title></head><body><p>Loading content...</p>\
         <ul style=\"display:none\">",
    );
    for i in 0..n {
        let slug = format!("p{:x}", slug_hash(base, i));
        // Links stay relative to the requested path so every follow
        // keeps hitting the tarpit on the same origin.
        let _ = write!(
            out,
            "<li><a rel=\"nofollow\" href=\"{base}/{slug}\">{slug}</a></li>"
        );
    }
    out.push_str("</ul></body></html>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maze_is_deterministic_for_the_same_path() {
        assert_eq!(generate_maze("/docs", 10), generate_maze("/docs", 10));
    }

    #[test]
    fn maze_differs_by_path() {
        assert_ne!(generate_maze("/docs", 10), generate_maze("/blog", 10));
    }

    #[test]
    fn link_count_is_clamped() {
        let big = generate_maze("/x", 10_000);
        assert_eq!(big.matches("<a ").count(), MAX_TARPIT_LINKS);
        let small = generate_maze("/x", 0);
        assert_eq!(small.matches("<a ").count(), 1);
    }

    #[test]
    fn links_are_nofollow_and_hidden_and_relative() {
        let m = generate_maze("/docs", 5);
        assert!(m.contains("display:none"));
        assert!(m.contains("rel=\"nofollow\""));
        assert!(m.contains("noindex,nofollow"));
        assert!(m.contains("href=\"/docs/p"));
    }
}
