package pii

import (
	"strings"
	"testing"
)

// TestPII_E2E_EmailMasked verifies that a body containing an email address gets
// the email replaced with [REDACTED-EMAIL] in mask mode.
func TestPII_E2E_EmailMasked(t *testing.T) {
	input := `{"user": "john", "email": "john.doe@example.com", "role": "admin"}`
	result := Redact(input, nil, ModeMask)

	if strings.Contains(result, "john.doe@example.com") {
		t.Error("email should be redacted from output")
	}
	if !strings.Contains(result, "[REDACTED-EMAIL]") {
		t.Errorf("expected [REDACTED-EMAIL] in output, got: %s", result)
	}
	// Verify surrounding text is preserved
	if !strings.Contains(result, `"user": "john"`) {
		t.Error("non-PII fields should be preserved")
	}
}

// TestPII_E2E_CreditCardMasked verifies that a body containing a credit card
// number gets masked. The Luhn algorithm validates the card number before
// flagging it as PII.
func TestPII_E2E_CreditCardMasked(t *testing.T) {
	// 4111111111111111 is a well-known Visa test number that passes Luhn
	input := `Payment with card 4111111111111111 processed successfully`
	result := Redact(input, []string{"credit_card"}, ModeMask)

	if strings.Contains(result, "4111111111111111") {
		t.Error("credit card number should be redacted from output")
	}
	if !strings.Contains(result, "****-****-****-1111") {
		t.Errorf("expected masked credit card in output, got: %s", result)
	}

	// Verify Luhn validation: an invalid card number should NOT be redacted
	invalidInput := `Number 1234567890123456 is not a valid card`
	invalidResult := Redact(invalidInput, []string{"credit_card"}, ModeMask)
	if !strings.Contains(invalidResult, "1234567890123456") {
		t.Error("invalid card number (fails Luhn) should not be redacted")
	}
}

// TestPII_E2E_AWSKeyDetected verifies that AWS access keys (AKIA prefix) are
// detected and redacted.
func TestPII_E2E_AWSKeyDetected(t *testing.T) {
	input := `Config: access_key=AKIAIOSFODNN7EXAMPLE secret=hidden`
	result := Redact(input, []string{"aws_key"}, ModeMask)

	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS access key should be redacted from output")
	}
	// The AWS key detector uses a partial mask showing first 4 + stars
	if !strings.Contains(result, "AKIA") {
		t.Error("AWS key redaction should preserve AKIA prefix hint")
	}
}

// TestPII_E2E_HashMode verifies that hash mode produces a sha256 prefix.
func TestPII_E2E_HashMode(t *testing.T) {
	input := `User email: alice@example.org is registered`
	result := Redact(input, []string{"email"}, ModeHash)

	if strings.Contains(result, "alice@example.org") {
		t.Error("email should be replaced in hash mode")
	}
	if !strings.Contains(result, "sha256:") {
		t.Errorf("hash mode should produce sha256: prefix, got: %s", result)
	}
}

// TestPII_E2E_MultiplePIITypesInSameBody verifies that multiple PII types
// within the same body are all detected and redacted in a single pass.
func TestPII_E2E_MultiplePIITypesInSameBody(t *testing.T) {
	input := `User john@acme.com has SSN 123-45-6789 and card 4111111111111111`
	result := Redact(input, nil, ModeMask)

	// Email should be redacted
	if strings.Contains(result, "john@acme.com") {
		t.Error("email should be redacted")
	}

	// SSN should be redacted
	if strings.Contains(result, "123-45-6789") {
		t.Error("SSN should be redacted")
	}

	// Credit card should be redacted
	if strings.Contains(result, "4111111111111111") {
		t.Error("credit card should be redacted")
	}

	// Verify non-PII text is preserved
	if !strings.Contains(result, "User") || !strings.Contains(result, "has") {
		t.Error("non-PII text should be preserved")
	}

	// Verify specific redaction markers are present
	if !strings.Contains(result, "[REDACTED-EMAIL]") {
		t.Error("expected [REDACTED-EMAIL] marker")
	}
	if !strings.Contains(result, "***-**-6789") {
		t.Error("expected SSN partial mask (***-**-6789)")
	}
	if !strings.Contains(result, "****-****-****-1111") {
		t.Error("expected credit card partial mask")
	}
}

// TestPII_E2E_RedactBytes verifies the byte-slice variant works identically.
func TestPII_E2E_RedactBytes(t *testing.T) {
	input := []byte(`Contact: support@example.com`)
	result := RedactBytes(input, []string{"email"}, ModeMask)

	if strings.Contains(string(result), "support@example.com") {
		t.Error("email should be redacted in byte variant")
	}
	if !strings.Contains(string(result), "[REDACTED-EMAIL]") {
		t.Errorf("expected [REDACTED-EMAIL], got: %s", string(result))
	}
}

// TestPII_E2E_CleanTextUnchanged verifies that text with no PII is returned
// without modification.
func TestPII_E2E_CleanTextUnchanged(t *testing.T) {
	input := `This is a perfectly clean message with no sensitive data.`
	result := Redact(input, nil, ModeMask)

	if result != input {
		t.Errorf("clean text should be unchanged, got: %s", result)
	}
}
