package identity

import (
	"context"
	"sync"
	"testing"
)

func TestStaticConnector_Resolve_Found(t *testing.T) {
	c := NewStaticConnector([]StaticPermission{
		{
			Credential:  "kW5nR8tM3pJ6",
			Type:        "api_key",
			Principal:   "user-1",
			Permissions: []string{"read"},
		},
	})

	perm, err := c.Resolve(context.Background(), "api_key", "kW5nR8tM3pJ6")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil {
		t.Fatal("expected non-nil permission")
	}
	if perm.Principal != "user-1" {
		t.Errorf("expected principal user-1, got %s", perm.Principal)
	}
	if len(perm.Permissions) != 1 || perm.Permissions[0] != "read" {
		t.Errorf("unexpected permissions: %v", perm.Permissions)
	}
}

func TestStaticConnector_Resolve_NotFound(t *testing.T) {
	c := NewStaticConnector([]StaticPermission{
		{
			Credential: "kW5nR8tM3pJ6",
			Type:       "api_key",
			Principal:  "user-1",
		},
	})

	perm, err := c.Resolve(context.Background(), "api_key", "sk-unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm != nil {
		t.Fatal("expected nil permission for unknown credential")
	}
}

func TestStaticConnector_Resolve_WithGroups(t *testing.T) {
	c := NewStaticConnector([]StaticPermission{
		{
			Credential:  "jwt-token-abc",
			Type:        "jwt",
			Principal:   "admin-1",
			Groups:      []string{"admins", "engineering"},
			Models:      []string{"gpt-4o"},
			Permissions: []string{"read", "write", "admin"},
		},
	})

	perm, err := c.Resolve(context.Background(), "jwt", "jwt-token-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil {
		t.Fatal("expected non-nil permission")
	}
	if len(perm.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(perm.Groups))
	}
	if len(perm.Models) != 1 || perm.Models[0] != "gpt-4o" {
		t.Errorf("unexpected models: %v", perm.Models)
	}
	if len(perm.Permissions) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(perm.Permissions))
	}
	if perm.CachedAt.IsZero() {
		t.Error("CachedAt should be set")
	}
}

func TestStaticConnector_Reload(t *testing.T) {
	c := NewStaticConnector([]StaticPermission{
		{Credential: "key-1", Type: "api_key", Principal: "user-1"},
	})

	// Verify initial state.
	perm, _ := c.Resolve(context.Background(), "api_key", "key-1")
	if perm == nil || perm.Principal != "user-1" {
		t.Fatal("expected initial permission")
	}

	// Reload with new permissions.
	c.Reload([]StaticPermission{
		{Credential: "key-2", Type: "api_key", Principal: "user-2"},
	})

	// Old credential should be gone.
	perm, _ = c.Resolve(context.Background(), "api_key", "key-1")
	if perm != nil {
		t.Error("expected old credential to be removed after reload")
	}

	// New credential should be present.
	perm, _ = c.Resolve(context.Background(), "api_key", "key-2")
	if perm == nil || perm.Principal != "user-2" {
		t.Error("expected new credential after reload")
	}
}

func TestStaticConnector_ConcurrentAccess(t *testing.T) {
	c := NewStaticConnector([]StaticPermission{
		{Credential: "key-1", Type: "api_key", Principal: "user-1"},
	})

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent reads.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = c.Resolve(context.Background(), "api_key", "key-1")
			}
		}()
	}

	// Concurrent reload.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Reload([]StaticPermission{
				{Credential: "key-1", Type: "api_key", Principal: "user-1"},
			})
		}()
	}

	wg.Wait()
}
