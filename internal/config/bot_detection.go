// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

// BotDetectionConfig configures bot detection for an origin.
// When enabled, incoming requests are checked against allow/deny lists and
// optionally verified via reverse DNS for known good bots.
type BotDetectionConfig struct {
	Enabled       bool     `json:"enabled"`
	Mode          string   `json:"mode"`            // "block", "challenge", "log" (default: "log")
	AllowList     []string `json:"allow_list"`      // Known good bot patterns matched against User-Agent
	DenyList      []string `json:"deny_list"`       // Known bad bot patterns matched against User-Agent
	ChallengeType string   `json:"challenge_type"`  // "js" (default) or "captcha"
	VerifyGoodBot bool     `json:"verify_good_bot"` // Verify good bots via reverse DNS lookup
}
