package vault

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecretValue_String(t *testing.T) {
	sv := NewSecretValue("super-secret-password")

	got := sv.String()
	if got != "[REDACTED]" {
		t.Errorf("String() = %q, want %q", got, "[REDACTED]")
	}

	// Ensure fmt.Sprintf also uses String()
	formatted := fmt.Sprintf("value: %s", sv)
	if formatted != "value: [REDACTED]" {
		t.Errorf("Sprintf(%%s) = %q, want %q", formatted, "value: [REDACTED]")
	}

	// Verify %v also uses String()
	formatted = fmt.Sprintf("value: %v", sv)
	if formatted != "value: [REDACTED]" {
		t.Errorf("Sprintf(%%v) = %q, want %q", formatted, "value: [REDACTED]")
	}
}

func TestSecretValue_GoString(t *testing.T) {
	sv := NewSecretValue("secret")

	got := sv.GoString()
	if got != "SecretValue{[REDACTED]}" {
		t.Errorf("GoString() = %q, want %q", got, "SecretValue{[REDACTED]}")
	}

	// Verify %#v uses GoString()
	formatted := fmt.Sprintf("%#v", sv)
	if formatted != "SecretValue{[REDACTED]}" {
		t.Errorf("Sprintf(%%#v) = %q, want %q", formatted, "SecretValue{[REDACTED]}")
	}
}

func TestSecretValue_Value(t *testing.T) {
	sv := NewSecretValue("my-actual-secret")

	got := sv.Value()
	if got != "my-actual-secret" {
		t.Errorf("Value() = %q, want %q", got, "my-actual-secret")
	}
}

func TestSecretValue_MarshalJSON(t *testing.T) {
	sv := NewSecretValue("should-not-appear")

	data, err := json.Marshal(sv)
	if err != nil {
		t.Fatalf("MarshalJSON() error: %v", err)
	}

	if string(data) != `"[REDACTED]"` {
		t.Errorf("MarshalJSON() = %s, want %s", string(data), `"[REDACTED]"`)
	}

	// Also test in a struct
	type Config struct {
		Key SecretValue `json:"key"`
	}
	cfg := Config{Key: NewSecretValue("hidden")}
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON(struct) error: %v", err)
	}
	if string(data) != `{"key":"[REDACTED]"}` {
		t.Errorf("MarshalJSON(struct) = %s, want %s", string(data), `{"key":"[REDACTED]"}`)
	}
}

func TestSecretValue_MarshalText(t *testing.T) {
	sv := NewSecretValue("should-not-appear")

	data, err := sv.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error: %v", err)
	}
	if string(data) != "[REDACTED]" {
		t.Errorf("MarshalText() = %q, want %q", string(data), "[REDACTED]")
	}
}

func TestSecretValue_Equal(t *testing.T) {
	sv1 := NewSecretValue("password123")
	sv2 := NewSecretValue("password123")
	sv3 := NewSecretValue("different")
	sv4 := NewSecretValue("")

	if !sv1.Equal(sv2) {
		t.Error("Equal() should return true for identical values")
	}
	if sv1.Equal(sv3) {
		t.Error("Equal() should return false for different values")
	}
	if sv1.Equal(sv4) {
		t.Error("Equal() should return false for empty vs non-empty")
	}

	// Empty values should be equal
	sv5 := NewSecretValue("")
	if !sv4.Equal(sv5) {
		t.Error("Equal() should return true for two empty values")
	}
}

func TestSecretValue_IsEmpty(t *testing.T) {
	empty := NewSecretValue("")
	nonEmpty := NewSecretValue("value")

	if !empty.IsEmpty() {
		t.Error("IsEmpty() should return true for empty value")
	}
	if nonEmpty.IsEmpty() {
		t.Error("IsEmpty() should return false for non-empty value")
	}
}

func TestSecretValue_NoLeakInError(t *testing.T) {
	sv := NewSecretValue("super-secret")

	// Ensure the secret value doesn't leak through common formatting patterns
	errMsg := fmt.Sprintf("failed to authenticate with token %s", sv)
	if errMsg != "failed to authenticate with token [REDACTED]" {
		t.Errorf("secret leaked in error message: %q", errMsg)
	}

	errMsg = fmt.Sprintf("token: %v", sv)
	if errMsg != "token: [REDACTED]" {
		t.Errorf("secret leaked with %%v: %q", errMsg)
	}
}
