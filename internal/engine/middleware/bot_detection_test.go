package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBotDetectionMiddleware_Disabled(t *testing.T) {
	handler := BotDetectionMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestBotDetectionMiddleware_DisabledConfig(t *testing.T) {
	config := &BotDetectionConfig{Enabled: false}
	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "SemrushBot/1.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when disabled, got %d", rr.Code)
	}
}

func TestBotDetectionMiddleware_BlockMode_DenyList(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled: true,
		Mode:    "block",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		userAgent  string
		wantStatus int
	}{
		{"semrush blocked", "SemrushBot/7.0", http.StatusForbidden},
		{"ahrefs blocked", "AhrefsBot/7.0", http.StatusForbidden},
		{"mj12 blocked", "MJ12bot/v1.4.8", http.StatusForbidden},
		{"censys blocked", "censys/1.0", http.StatusForbidden},
		{"normal browser allowed", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", http.StatusOK},
		{"curl allowed (not in default deny)", "curl/7.68.0", http.StatusOK},
		{"empty UA allowed", "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("user-agent %q: expected %d, got %d", tt.userAgent, tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestBotDetectionMiddleware_BlockMode_CustomDenyList(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled:  true,
		Mode:     "block",
		DenyList: []string{"evil-scraper", "bad-crawler"},
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		userAgent  string
		wantStatus int
	}{
		{"custom deny blocked", "evil-scraper/1.0", http.StatusForbidden},
		{"custom deny case insensitive", "Evil-Scraper/2.0", http.StatusForbidden},
		{"custom deny partial match", "Mozilla/5.0 bad-crawler", http.StatusForbidden},
		{"semrush NOT blocked with custom list", "SemrushBot/7.0", http.StatusOK},
		{"normal browser allowed", "Mozilla/5.0", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("user-agent %q: expected %d, got %d", tt.userAgent, tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestBotDetectionMiddleware_AllowList_GoodBot(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled:   true,
		Mode:      "block",
		AllowList: []string{"googlebot", "bingbot"},
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		userAgent  string
		wantStatus int
	}{
		{"googlebot allowed", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", http.StatusOK},
		{"bingbot allowed", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", http.StatusOK},
		{"semrush still blocked", "SemrushBot/7.0", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("user-agent %q: expected %d, got %d", tt.userAgent, tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestBotDetectionMiddleware_ChallengeMode(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled:       true,
		Mode:          "challenge",
		ChallengeType: "js",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "SemrushBot/7.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Checking your browser") {
		t.Error("expected JS challenge page content")
	}
	if !strings.Contains(body, "<script>") {
		t.Error("expected JavaScript in challenge page")
	}
	if !strings.Contains(body, "_sb_bot_check") {
		t.Error("expected bot check cookie in challenge page")
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %s", ct)
	}
}

func TestBotDetectionMiddleware_CaptchaChallenge(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled:       true,
		Mode:          "challenge",
		ChallengeType: "captcha",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "AhrefsBot/7.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Verification Required") {
		t.Error("expected captcha challenge page content")
	}
}

func TestBotDetectionMiddleware_LogMode(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled: true,
		Mode:    "log",
	}

	reached := false
	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "SemrushBot/7.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Log mode should allow the request through to the next handler
	if !reached {
		t.Error("log mode should allow request through to next handler")
	}
}

func TestBotDetectionMiddleware_DefaultGoodBots(t *testing.T) {
	// Default good bots from the goodBotDomains map should be allowed
	config := &BotDetectionConfig{
		Enabled: true,
		Mode:    "block",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	goodBotUAs := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
		"facebot",
	}

	for _, ua := range goodBotUAs {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", ua)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("good bot %q should be allowed, got %d", ua, rr.Code)
		}
	}
}

func TestBotDetectionMiddleware_BlockResponseContent(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled: true,
		Mode:    "block",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "AhrefsBot/7.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if rr.Body.String() != "Access Denied" {
		t.Errorf("expected 'Access Denied' body, got %q", rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", ct)
	}
}

func TestParseClientAuthType(t *testing.T) {
	// This tests the TLS client auth type parsing from service package
	// We test the helper functions in bot_detection instead
}

func TestMatchesDNSSuffix(t *testing.T) {
	tests := []struct {
		hostnames []string
		suffixes  []string
		expected  bool
	}{
		{[]string{"crawl-66-249-66-1.googlebot.com."}, []string{".googlebot.com.", ".google.com."}, true},
		{[]string{"msnbot-157-55-39-1.search.msn.com."}, []string{".search.msn.com."}, true},
		{[]string{"evil.example.com."}, []string{".googlebot.com.", ".google.com."}, false},
		{[]string{}, []string{".googlebot.com."}, false},
		{[]string{"host.example.com."}, []string{}, false},
	}

	for _, tt := range tests {
		result := matchesDNSSuffix(tt.hostnames, tt.suffixes)
		if result != tt.expected {
			t.Errorf("matchesDNSSuffix(%v, %v) = %v, want %v",
				tt.hostnames, tt.suffixes, result, tt.expected)
		}
	}
}

func TestNewBotDetectionState(t *testing.T) {
	config := BotDetectionConfig{
		Enabled:   true,
		Mode:      "block",
		AllowList: []string{"MyGoodBot"},
		DenyList:  []string{"MyBadBot", "EvilScraper"},
	}

	state := newBotDetectionState(config)

	// Check deny patterns are lowercased
	if len(state.denyPatterns) != 2 {
		t.Errorf("expected 2 deny patterns (custom list replaces defaults), got %d", len(state.denyPatterns))
	}
	for _, p := range state.denyPatterns {
		if p != strings.ToLower(p) {
			t.Errorf("deny pattern %q should be lowercased", p)
		}
	}

	// Check allow patterns are lowercased
	if len(state.allowPatterns) != 1 {
		t.Errorf("expected 1 allow pattern, got %d", len(state.allowPatterns))
	}
	if state.allowPatterns[0] != "mygoodbot" {
		t.Errorf("expected 'mygoodbot', got %q", state.allowPatterns[0])
	}
}

func TestNewBotDetectionState_DefaultDenyList(t *testing.T) {
	config := BotDetectionConfig{
		Enabled: true,
		Mode:    "block",
	}

	state := newBotDetectionState(config)

	// With empty DenyList, default patterns should be used
	if len(state.denyPatterns) != len(defaultDenyPatterns) {
		t.Errorf("expected %d default deny patterns, got %d", len(defaultDenyPatterns), len(state.denyPatterns))
	}
}

func TestIsAllowedBot(t *testing.T) {
	state := newBotDetectionState(BotDetectionConfig{
		Enabled:   true,
		AllowList: []string{"mybot"},
	})

	// Custom allow list
	if _, ok := state.isAllowedBot("MyBot/1.0"); !ok {
		t.Error("expected mybot to be allowed")
	}

	// Default good bots
	if _, ok := state.isAllowedBot("Googlebot/2.1"); !ok {
		t.Error("expected Googlebot to be allowed via default good bot domains")
	}

	// Unknown bot
	if _, ok := state.isAllowedBot("RandomBot/1.0"); ok {
		t.Error("expected RandomBot to not be in allow list")
	}
}

func TestIsDeniedBot(t *testing.T) {
	state := newBotDetectionState(BotDetectionConfig{
		Enabled: true,
	})

	if _, ok := state.isDeniedBot("SemrushBot/7.0"); !ok {
		t.Error("expected SemrushBot to be denied by default")
	}

	if _, ok := state.isDeniedBot("Mozilla/5.0"); ok {
		t.Error("expected normal browser to not be denied")
	}
}
