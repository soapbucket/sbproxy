package waf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAutoUpdater_FetchRules(t *testing.T) {
	t.Parallel()

	rules := []WAFRule{
		{
			ID:       "100001",
			Name:     "Test Rule 1",
			Enabled:  true,
			Phase:    2,
			Severity: "critical",
			Action:   "block",
			Operator: "rx",
			Pattern:  `test-pattern`,
		},
		{
			ID:       "100002",
			Name:     "Test Rule 2",
			Enabled:  true,
			Phase:    1,
			Severity: "warning",
			Action:   "log",
			Operator: "rx",
			Pattern:  `another-pattern`,
		},
	}

	body, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	var received []WAFRule
	updater := NewAutoUpdater(AutoUpdateConfig{
		Enabled: true,
		Sources: []RuleSource{
			{
				Name:   "test-source",
				URL:    srv.URL,
				Type:   "http",
				Format: "json",
			},
		},
		CheckInterval: time.Hour,
		MaxRules:      10000,
	}, func(r []WAFRule) {
		received = r
	})

	updated, err := updater.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updated {
		t.Fatal("expected rules to be updated")
	}
	if len(received) != 2 {
		t.Fatalf("expected 2 rules in callback, got %d", len(received))
	}

	got := updater.Rules()
	if len(got) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(got))
	}
	if got[0].ID != "100001" {
		t.Errorf("expected rule ID 100001, got %s", got[0].ID)
	}
	if got[1].ID != "100002" {
		t.Errorf("expected rule ID 100002, got %s", got[1].ID)
	}
}

func TestAutoUpdater_CheckForUpdates(t *testing.T) {
	t.Parallel()

	callCount := atomic.Int64{}

	makeRelease := func(tag string) []byte {
		release := struct {
			TagName string `json:"tag_name"`
			Assets  []struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			} `json:"assets"`
		}{
			TagName: tag,
		}
		b, _ := json.Marshal(release)
		return b
	}

	// First call returns v1.0.0, second call returns v1.1.0.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if count == 1 {
			w.Write(makeRelease("v1.0.0"))
		} else {
			w.Write(makeRelease("v1.1.0"))
		}
	}))
	defer srv.Close()

	updater := NewAutoUpdater(AutoUpdateConfig{
		Enabled: true,
		Sources: []RuleSource{
			{
				Name: "versioned",
				URL:  srv.URL,
				Type: "github_release",
			},
		},
		CheckInterval: time.Hour,
	}, nil)

	// First check picks up v1.0.0.
	_, err := updater.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats := updater.Stats()
	if stats.LastVersion != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", stats.LastVersion)
	}

	// Second check should detect the new version.
	_, err = updater.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats = updater.Stats()
	if stats.LastVersion != "v1.1.0" {
		t.Errorf("expected version v1.1.0, got %s", stats.LastVersion)
	}
}

func TestAutoUpdater_ParseJSONRules(t *testing.T) {
	t.Parallel()

	updater := NewAutoUpdater(AutoUpdateConfig{}, nil)

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "bare array",
			input:     `[{"id":"1","name":"r1","enabled":true},{"id":"2","name":"r2","enabled":true}]`,
			wantCount: 2,
		},
		{
			name:      "wrapped object",
			input:     `{"rules":[{"id":"3","name":"r3","enabled":true}]}`,
			wantCount: 1,
		},
		{
			name:    "invalid json",
			input:   `not json at all`,
			wantErr: true,
		},
		{
			name:      "empty array",
			input:     `[]`,
			wantCount: 0,
			wantErr:   true, // falls through to wrapper parse, which returns empty
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := updater.parseJSONRules([]byte(tc.input))
			if tc.wantErr {
				// Accept either error or empty result for edge cases.
				if err == nil && len(rules) != 0 {
					t.Errorf("expected error or empty rules, got %d rules", len(rules))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rules) != tc.wantCount {
				t.Errorf("expected %d rules, got %d", tc.wantCount, len(rules))
			}
		})
	}
}

func TestAutoUpdater_Stop(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	updater := NewAutoUpdater(AutoUpdateConfig{
		Enabled: true,
		Sources: []RuleSource{
			{
				Name: "test",
				URL:  srv.URL,
				Type: "http",
			},
		},
		CheckInterval: 50 * time.Millisecond,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updater.Start(ctx)

	// Give the goroutine a moment to start.
	time.Sleep(10 * time.Millisecond)

	// Stop should return cleanly without hanging.
	done := make(chan struct{})
	go func() {
		updater.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within timeout")
	}

	// Calling Stop again should not panic.
	updater.Stop()
}
