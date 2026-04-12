package identity

import (
	"context"
	"testing"
	"time"
)

func TestPrincipal_HasPermission(t *testing.T) {
	p := &Principal{
		Permissions: []string{"chat", "embeddings", "admin"},
	}

	if !p.HasPermission("chat") {
		t.Error("expected HasPermission(chat) = true")
	}
	if !p.HasPermission("admin") {
		t.Error("expected HasPermission(admin) = true")
	}
	if p.HasPermission("delete") {
		t.Error("expected HasPermission(delete) = false")
	}

	// Nil principal.
	var nilP *Principal
	if nilP.HasPermission("chat") {
		t.Error("expected nil principal HasPermission = false")
	}
}

func TestPrincipal_HasModel(t *testing.T) {
	t.Run("empty models allows all", func(t *testing.T) {
		p := &Principal{Models: nil}
		if !p.HasModel("gpt-4o") {
			t.Error("expected empty Models to allow all models")
		}
		if !p.HasModel("claude-3") {
			t.Error("expected empty Models to allow all models")
		}
	})

	t.Run("restricted models", func(t *testing.T) {
		p := &Principal{Models: []string{"gpt-4o", "gpt-3.5-turbo"}}
		if !p.HasModel("gpt-4o") {
			t.Error("expected HasModel(gpt-4o) = true")
		}
		if p.HasModel("claude-3") {
			t.Error("expected HasModel(claude-3) = false")
		}
	})

	t.Run("nil principal", func(t *testing.T) {
		var nilP *Principal
		if nilP.HasModel("gpt-4o") {
			t.Error("expected nil principal HasModel = false")
		}
	})
}

func TestPrincipal_IsExpired(t *testing.T) {
	t.Run("no expiry", func(t *testing.T) {
		p := &Principal{ExpiresAt: nil}
		if p.IsExpired() {
			t.Error("expected no-expiry principal to not be expired")
		}
	})

	t.Run("future expiry", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		p := &Principal{ExpiresAt: &future}
		if p.IsExpired() {
			t.Error("expected future-expiry principal to not be expired")
		}
	})

	t.Run("past expiry", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		p := &Principal{ExpiresAt: &past}
		if !p.IsExpired() {
			t.Error("expected past-expiry principal to be expired")
		}
	})

	t.Run("nil principal", func(t *testing.T) {
		var nilP *Principal
		if !nilP.IsExpired() {
			t.Error("expected nil principal to be expired")
		}
	})
}

func TestPrincipal_Context(t *testing.T) {
	ctx := context.Background()

	// No principal in context.
	if got := PrincipalFromContext(ctx); got != nil {
		t.Errorf("expected nil principal from empty context, got %+v", got)
	}

	// Store and retrieve.
	p := &Principal{
		ID:     "user-123",
		Type:   CredentialJWT,
		UserID: "uid-456",
		Groups: []string{"admin"},
	}

	ctx = ContextWithPrincipal(ctx, p)
	got := PrincipalFromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil principal from context")
	}
	if got.ID != "user-123" {
		t.Errorf("expected ID user-123, got %s", got.ID)
	}
	if got.UserID != "uid-456" {
		t.Errorf("expected UserID uid-456, got %s", got.UserID)
	}
	if got.Type != CredentialJWT {
		t.Errorf("expected type jwt, got %s", got.Type)
	}
}
