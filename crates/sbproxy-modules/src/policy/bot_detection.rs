//! Bot detection helper.
//!
//! Blocks requests whose User-Agent matches any deny-list entry
//! (case-insensitive substring). An optional allow-list exempts
//! User-Agents that would otherwise be denied. Distinct from the
//! `Policy` enum (this is consumed directly by the request pipeline
//! in `sbproxy-core`).

use serde::Deserialize;

/// Bot detection configuration. Blocks requests based on User-Agent patterns.
///
/// If `deny_list` is non-empty, any User-Agent containing a denied pattern
/// (case-insensitive substring match) is blocked with 403.
/// If `allow_list` is non-empty, a User-Agent matching an allowed pattern
/// is exempted from the deny check.
#[derive(Debug, Deserialize)]
pub struct BotDetection {
    /// Master switch for bot detection on this origin.
    #[serde(default)]
    pub enabled: bool,
    /// Mode of operation (`block`, `log`, etc.).
    #[serde(default)]
    pub mode: Option<String>,
    /// User-Agent substrings (case-insensitive) that are blocked.
    #[serde(default)]
    pub deny_list: Vec<String>,
    /// User-Agent substrings (case-insensitive) that are exempted.
    #[serde(default)]
    pub allow_list: Vec<String>,
}

impl BotDetection {
    /// Build a BotDetection from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check if the given User-Agent should be blocked.
    /// Returns true if the request should be allowed, false if blocked.
    pub fn check_user_agent(&self, user_agent: &str) -> bool {
        if !self.enabled {
            return true;
        }

        let ua_lower = user_agent.to_lowercase();

        // Check allow list first: if the UA matches any allowed pattern, allow.
        for pattern in &self.allow_list {
            if ua_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        // Check deny list: if the UA matches any denied pattern, block.
        for pattern in &self.deny_list {
            if ua_lower.contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        // Default: allow
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_detection_from_config() {
        let json = serde_json::json!({
            "enabled": true,
            "mode": "block",
            "deny_list": ["badcrawler", "evilbot"],
            "allow_list": ["goodbot"]
        });
        let bot = BotDetection::from_config(json).unwrap();
        assert!(bot.enabled);
        assert_eq!(bot.deny_list, vec!["badcrawler", "evilbot"]);
        assert_eq!(bot.allow_list, vec!["goodbot"]);
    }

    #[test]
    fn bot_detection_blocks_denied_ua() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["badcrawler".to_string(), "evilbot".to_string()],
            allow_list: vec![],
        };
        assert!(!bot.check_user_agent("badcrawler/1.0"));
        assert!(!bot.check_user_agent("evilbot/2.0"));
        assert!(!bot.check_user_agent("Mozilla/5.0 badcrawler"));
    }

    #[test]
    fn bot_detection_allows_normal_ua() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["badcrawler".to_string()],
            allow_list: vec![],
        };
        assert!(bot.check_user_agent("Mozilla/5.0"));
        assert!(bot.check_user_agent("curl/7.68.0"));
    }

    #[test]
    fn bot_detection_allow_list_overrides_deny() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["bot".to_string()],
            allow_list: vec!["goodbot".to_string()],
        };
        // "goodbot" matches the allow list, so it passes even though "bot" is denied.
        assert!(bot.check_user_agent("goodbot/1.0"));
        // "badbot" does NOT match the allow list, and "bot" is denied.
        assert!(!bot.check_user_agent("badbot/1.0"));
    }

    #[test]
    fn bot_detection_case_insensitive() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["BadCrawler".to_string()],
            allow_list: vec![],
        };
        assert!(!bot.check_user_agent("BADCRAWLER/1.0"));
        assert!(!bot.check_user_agent("badcrawler/1.0"));
    }

    #[test]
    fn bot_detection_disabled_allows_all() {
        let bot = BotDetection {
            enabled: false,
            mode: None,
            deny_list: vec!["badcrawler".to_string()],
            allow_list: vec![],
        };
        assert!(bot.check_user_agent("badcrawler/1.0"));
    }
}
