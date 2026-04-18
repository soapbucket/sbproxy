package action

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatchHeaderRoute_ExactMatch(t *testing.T) {
	rules := []HeaderRouteRule{
		{Header: "X-Region", Value: "us-east", Upstream: "https://us-east.example.com"},
		{Header: "X-Region", Value: "eu-west", Upstream: "https://eu-west.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Region", "eu-west")

	upstream, ok := MatchHeaderRoute(r, rules)
	if !ok {
		t.Fatal("expected match")
	}
	if upstream != "https://eu-west.example.com" {
		t.Errorf("got %q, want %q", upstream, "https://eu-west.example.com")
	}
}

func TestMatchHeaderRoute_RegexMatch(t *testing.T) {
	rules := []HeaderRouteRule{
		{Header: "X-Version", Pattern: `^v[0-9]+$`, Upstream: "https://versioned.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Version", "v42")

	upstream, ok := MatchHeaderRoute(r, rules)
	if !ok {
		t.Fatal("expected match")
	}
	if upstream != "https://versioned.example.com" {
		t.Errorf("got %q, want %q", upstream, "https://versioned.example.com")
	}
}

func TestMatchHeaderRoute_NoMatch(t *testing.T) {
	rules := []HeaderRouteRule{
		{Header: "X-Region", Value: "us-east", Upstream: "https://us-east.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Region", "ap-south")

	_, ok := MatchHeaderRoute(r, rules)
	if ok {
		t.Fatal("expected no match")
	}
}

func TestMatchHeaderRoute_MissingHeader(t *testing.T) {
	rules := []HeaderRouteRule{
		{Header: "X-Region", Value: "us-east", Upstream: "https://us-east.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, ok := MatchHeaderRoute(r, rules)
	if ok {
		t.Fatal("expected no match when header is missing")
	}
}

func TestMatchHeaderRoute_FirstMatchWins(t *testing.T) {
	rules := []HeaderRouteRule{
		{Header: "X-Env", Value: "prod", Upstream: "https://first.example.com"},
		{Header: "X-Env", Value: "prod", Upstream: "https://second.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Env", "prod")

	upstream, ok := MatchHeaderRoute(r, rules)
	if !ok {
		t.Fatal("expected match")
	}
	if upstream != "https://first.example.com" {
		t.Errorf("got %q, want first match", upstream)
	}
}

func TestMatchHeaderRoute_InvalidRegex(t *testing.T) {
	rules := []HeaderRouteRule{
		{Header: "X-Test", Pattern: "[invalid", Upstream: "https://invalid.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Test", "value")

	_, ok := MatchHeaderRoute(r, rules)
	if ok {
		t.Fatal("expected no match for invalid regex")
	}
}

func TestMatchHeaderRoute_EmptyRules(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, ok := MatchHeaderRoute(r, nil)
	if ok {
		t.Fatal("expected no match for empty rules")
	}
}

func TestMatchHeaderRoute_ExactMatchPriorityOverRegex(t *testing.T) {
	// When a rule has Value set, Pattern is ignored.
	rules := []HeaderRouteRule{
		{Header: "X-Test", Value: "exact", Pattern: ".*", Upstream: "https://exact.example.com"},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Test", "exact")

	upstream, ok := MatchHeaderRoute(r, rules)
	if !ok {
		t.Fatal("expected match")
	}
	if upstream != "https://exact.example.com" {
		t.Errorf("got %q", upstream)
	}
}
