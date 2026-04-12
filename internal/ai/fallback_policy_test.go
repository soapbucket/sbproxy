package ai

import (
	"testing"
)

func TestFallbackPolicyOpenAI(t *testing.T) {
	body := []byte(`{"error":{"message":"The response was filtered","type":"invalid_request_error","code":"content_policy_violation"}}`)
	if !isContentPolicyError(400, body) {
		t.Fatal("expected OpenAI content_policy_violation to be detected")
	}
}

func TestFallbackPolicyAzureContentFilter(t *testing.T) {
	body := []byte(`{"error":{"message":"The response was filtered due to the prompt triggering Azure OpenAI's content management policy.","type":"invalid_request_error","code":"content_filter"}}`)
	if !isContentPolicyError(400, body) {
		t.Fatal("expected Azure content_filter to be detected")
	}
}

func TestFallbackPolicyAzureContentFilterSubstring(t *testing.T) {
	// Azure sometimes uses a more specific code like "content_filter_policy"
	body := []byte(`{"error":{"message":"Content filtered","type":"server_error","code":"content_filter_policy"}}`)
	if !isContentPolicyError(400, body) {
		t.Fatal("expected Azure content_filter substring to be detected")
	}
}

func TestFallbackPolicyAnthropicBlocked(t *testing.T) {
	body := []byte(`{"error":{"type":"content_blocked","message":"Output blocked by content filtering policy"}}`)
	if !isContentPolicyError(400, body) {
		t.Fatal("expected Anthropic content_blocked to be detected")
	}
}

func TestFallbackPolicyAnthropicTopLevel(t *testing.T) {
	// Some Anthropic responses use top-level type field.
	body := []byte(`{"type":"content_blocked","message":"This content has been blocked"}`)
	if !isContentPolicyError(400, body) {
		t.Fatal("expected Anthropic top-level content_blocked to be detected")
	}
}

func TestFallbackPolicyNonPolicyError(t *testing.T) {
	// A normal 400 error that is NOT a content policy issue.
	body := []byte(`{"error":{"message":"Invalid model","type":"invalid_request_error","code":"model_not_found"}}`)
	if isContentPolicyError(400, body) {
		t.Fatal("expected non-policy error to NOT match")
	}
}

func TestFallbackPolicyWrongStatusCode(t *testing.T) {
	// Content policy errors only trigger on 400.
	body := []byte(`{"error":{"message":"Content filtered","type":"invalid_request_error","code":"content_policy_violation"}}`)
	if isContentPolicyError(500, body) {
		t.Fatal("expected 500 status to NOT match content policy")
	}
	if isContentPolicyError(429, body) {
		t.Fatal("expected 429 status to NOT match content policy")
	}
}

func TestFallbackPolicyEmptyBody(t *testing.T) {
	if isContentPolicyError(400, nil) {
		t.Fatal("expected nil body to NOT match")
	}
	if isContentPolicyError(400, []byte{}) {
		t.Fatal("expected empty body to NOT match")
	}
}

func TestFallbackPolicyMalformedJSON(t *testing.T) {
	if isContentPolicyError(400, []byte("not json")) {
		t.Fatal("expected malformed JSON to NOT match")
	}
}

func TestFallbackPolicyServerError(t *testing.T) {
	// A 500 with content_policy_violation code should NOT match (wrong status).
	body := []byte(`{"error":{"code":"content_policy_violation","message":"internal error"}}`)
	if isContentPolicyError(500, body) {
		t.Fatal("expected 500 to NOT match even with policy code")
	}
}
