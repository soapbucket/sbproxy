package config

import (
	"testing"
)

func TestSelectErrorPage_MatchByStatus(t *testing.T) {
	pages := []ErrorPage{
		{Status: []int{404}, ContentType: "text/html", Body: "not found"},
		{Status: []int{500}, ContentType: "text/html", Body: "server error"},
	}

	result := SelectErrorPage(pages, 404, "")
	if result == nil {
		t.Fatal("expected a matching page")
	}
	if result.Body != "not found" {
		t.Errorf("body = %q, want %q", result.Body, "not found")
	}
}

func TestSelectErrorPage_CatchAll(t *testing.T) {
	pages := []ErrorPage{
		{Status: []int{404}, ContentType: "text/html", Body: "not found"},
		{ContentType: "text/html", Body: "generic error"},
	}

	result := SelectErrorPage(pages, 503, "")
	if result == nil {
		t.Fatal("expected catch-all page")
	}
	if result.Body != "generic error" {
		t.Errorf("body = %q, want %q", result.Body, "generic error")
	}
}

func TestSelectErrorPage_Empty(t *testing.T) {
	result := SelectErrorPage(nil, 404, "")
	if result != nil {
		t.Error("expected nil for empty pages")
	}
}

func TestSelectErrorPage_NoMatch(t *testing.T) {
	pages := []ErrorPage{
		{Status: []int{404}, ContentType: "text/html", Body: "not found"},
	}

	result := SelectErrorPage(pages, 500, "")
	if result != nil {
		t.Error("expected nil when no match and no catch-all")
	}
}

func TestSelectErrorPage_ContentNegotiation(t *testing.T) {
	pages := []ErrorPage{
		{Status: []int{404}, ContentType: "text/html", Body: "<h1>Not Found</h1>"},
		{Status: []int{404}, ContentType: "application/json", Body: `{"error":"not found"}`},
	}

	result := SelectErrorPage(pages, 404, "application/json")
	if result == nil {
		t.Fatal("expected a matching page")
	}
	if result.ContentType != "application/json" {
		t.Errorf("content type = %q, want application/json", result.ContentType)
	}
}

func TestSelectErrorPage_ContentNegotiation_Wildcard(t *testing.T) {
	pages := []ErrorPage{
		{Status: []int{500}, ContentType: "text/html", Body: "error"},
		{Status: []int{500}, ContentType: "application/json", Body: `{"error":"error"}`},
	}

	result := SelectErrorPage(pages, 500, "*/*")
	if result == nil {
		t.Fatal("expected a matching page")
	}
	// Wildcard should match the first candidate.
	if result.ContentType != "text/html" {
		t.Errorf("content type = %q, want text/html (first match for wildcard)", result.ContentType)
	}
}

func TestSelectErrorPage_ContentNegotiation_Quality(t *testing.T) {
	pages := []ErrorPage{
		{Status: []int{404}, ContentType: "text/html", Body: "html"},
		{Status: []int{404}, ContentType: "application/json", Body: "json"},
	}

	result := SelectErrorPage(pages, 404, "text/html;q=0.5, application/json;q=0.9")
	if result == nil {
		t.Fatal("expected a matching page")
	}
	if result.ContentType != "application/json" {
		t.Errorf("content type = %q, want application/json (higher quality)", result.ContentType)
	}
}

func TestSelectErrorPage_DefaultContentType(t *testing.T) {
	// Pages with empty ContentType should default to text/html.
	pages := []ErrorPage{
		{Status: []int{404}, Body: "default html"},
	}

	result := SelectErrorPage(pages, 404, "text/html")
	if result == nil {
		t.Fatal("expected a matching page")
	}
	if result.Body != "default html" {
		t.Errorf("body = %q, want %q", result.Body, "default html")
	}
}
