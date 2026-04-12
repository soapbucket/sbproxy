package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBotDetection_E2E_BlockMode_KnownBadBot verifies that a request from a
// known bad bot user-agent returns 403 in block mode via a real HTTP server.
func TestBotDetection_E2E_BlockMode_KnownBadBot(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled: true,
		Mode:    "block",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/page", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "SemrushBot/7.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for bad bot, got %d", resp.StatusCode)
	}
}

// TestBotDetection_E2E_AllowList_Googlebot verifies that a request from
// Googlebot (default good bot) passes through even in block mode.
func TestBotDetection_E2E_AllowList_Googlebot(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled:   true,
		Mode:      "block",
		AllowList: []string{"googlebot"},
	}

	reached := false
	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for Googlebot, got %d", resp.StatusCode)
	}
	if !reached {
		t.Error("handler should have been reached for allowed good bot")
	}
}

// TestBotDetection_E2E_ChallengeMode_ReturnsHTMLWithJS verifies that challenge
// mode returns an HTML page containing a JavaScript challenge.
func TestBotDetection_E2E_ChallengeMode_ReturnsHTMLWithJS(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled:       true,
		Mode:          "challenge",
		ChallengeType: "js",
	}

	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "AhrefsBot/7.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for challenge, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %s", ct)
	}

	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	if !strings.Contains(bodyStr, "<script>") {
		t.Error("challenge page should contain a <script> tag")
	}
	if !strings.Contains(bodyStr, "Checking your browser") {
		t.Error("challenge page should contain browser check text")
	}
}

// TestBotDetection_E2E_LogMode_PassesThrough verifies that log mode allows the
// request to pass through to the backend handler while still detecting the bot.
func TestBotDetection_E2E_LogMode_PassesThrough(t *testing.T) {
	config := &BotDetectionConfig{
		Enabled: true,
		Mode:    "log",
	}

	reached := false
	handler := BotDetectionMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/page", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "MJ12bot/v1.4.8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("log mode should return 200, got %d", resp.StatusCode)
	}
	if !reached {
		t.Error("log mode should pass the request through to the handler")
	}
}
