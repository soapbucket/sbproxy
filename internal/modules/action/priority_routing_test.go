package action

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelectByPriority_FromHeader(t *testing.T) {
	cfg := PriorityConfig{
		Header:  "X-Priority",
		Default: "normal",
		Routes: map[string]string{
			"high":   "https://high.example.com",
			"normal": "https://normal.example.com",
			"low":    "https://low.example.com",
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Priority", "high")

	result := SelectByPriority(r, cfg)
	if result != "https://high.example.com" {
		t.Errorf("got %q, want %q", result, "https://high.example.com")
	}
}

func TestSelectByPriority_Default(t *testing.T) {
	cfg := PriorityConfig{
		Header:  "X-Priority",
		Default: "normal",
		Routes: map[string]string{
			"high":   "https://high.example.com",
			"normal": "https://normal.example.com",
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// No X-Priority header set.

	result := SelectByPriority(r, cfg)
	if result != "https://normal.example.com" {
		t.Errorf("got %q, want %q", result, "https://normal.example.com")
	}
}

func TestSelectByPriority_NoMatch(t *testing.T) {
	cfg := PriorityConfig{
		Header:  "X-Priority",
		Default: "normal",
		Routes: map[string]string{
			"high": "https://high.example.com",
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	result := SelectByPriority(r, cfg)
	if result != "" {
		t.Errorf("got %q, want empty string", result)
	}
}

func TestSelectByPriority_NoHeader_NoDefault(t *testing.T) {
	cfg := PriorityConfig{
		Routes: map[string]string{
			"high": "https://high.example.com",
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	result := SelectByPriority(r, cfg)
	if result != "" {
		t.Errorf("got %q, want empty string", result)
	}
}

func TestSelectByPriority_HeaderOverridesDefault(t *testing.T) {
	cfg := PriorityConfig{
		Header:  "X-Priority",
		Default: "low",
		Routes: map[string]string{
			"high": "https://high.example.com",
			"low":  "https://low.example.com",
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Priority", "high")

	result := SelectByPriority(r, cfg)
	if result != "https://high.example.com" {
		t.Errorf("got %q, want %q", result, "https://high.example.com")
	}
}
