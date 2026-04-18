package ai

import (
	"testing"
)

func TestNewMultiAccountManager(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "primary", APIKey: "key-1"},
		{Name: "secondary", APIKey: "key-2"},
	}

	mgr := NewMultiAccountManager(accounts)
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if mgr.Size() != 2 {
		t.Errorf("expected 2 accounts, got %d", mgr.Size())
	}
}

func TestMultiAccountManager_Next_RoundRobin(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "a", APIKey: "key-a"},
		{Name: "b", APIKey: "key-b"},
		{Name: "c", APIKey: "key-c"},
	}

	mgr := NewMultiAccountManager(accounts)

	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		acct := mgr.Next()
		if acct == nil {
			t.Fatalf("unexpected nil account on call %d", i)
		}
		seen[acct.Name]++
	}

	for _, name := range []string{"a", "b", "c"} {
		if seen[name] != 3 {
			t.Errorf("expected account %q selected 3 times, got %d", name, seen[name])
		}
	}
}

func TestMultiAccountManager_Next_SkipsDisabled(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "a", APIKey: "key-a"},
		{Name: "b", APIKey: "key-b"},
	}

	mgr := NewMultiAccountManager(accounts)
	mgr.DisableAccount("a")

	for i := 0; i < 5; i++ {
		acct := mgr.Next()
		if acct == nil {
			t.Fatal("expected non-nil account")
		}
		if acct.Name != "b" {
			t.Errorf("expected account 'b', got %q", acct.Name)
		}
	}
}

func TestMultiAccountManager_Next_AllDisabled(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "a", APIKey: "key-a"},
		{Name: "b", APIKey: "key-b"},
	}

	mgr := NewMultiAccountManager(accounts)
	mgr.DisableAccount("a")
	mgr.DisableAccount("b")

	acct := mgr.Next()
	if acct != nil {
		t.Error("expected nil when all accounts disabled")
	}
}

func TestMultiAccountManager_Next_Empty(t *testing.T) {
	mgr := NewMultiAccountManager(nil)
	acct := mgr.Next()
	if acct != nil {
		t.Error("expected nil for empty manager")
	}
}

func TestMultiAccountManager_GetByName(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "primary", APIKey: "key-1", OrgID: "org-1"},
		{Name: "secondary", APIKey: "key-2"},
	}

	mgr := NewMultiAccountManager(accounts)

	acct := mgr.GetByName("primary")
	if acct == nil {
		t.Fatal("expected to find 'primary'")
	}
	if acct.APIKey != "key-1" {
		t.Errorf("expected APIKey 'key-1', got %q", acct.APIKey)
	}
	if acct.OrgID != "org-1" {
		t.Errorf("expected OrgID 'org-1', got %q", acct.OrgID)
	}

	acct = mgr.GetByName("nonexistent")
	if acct != nil {
		t.Error("expected nil for nonexistent account")
	}
}

func TestMultiAccountManager_DisableEnable(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "a", APIKey: "key-a"},
		{Name: "b", APIKey: "key-b"},
	}

	mgr := NewMultiAccountManager(accounts)

	// Disable 'a'.
	mgr.DisableAccount("a")
	active := mgr.ActiveAccounts()
	if len(active) != 1 {
		t.Errorf("expected 1 active account, got %d", len(active))
	}
	if active[0].Name != "b" {
		t.Errorf("expected active account 'b', got %q", active[0].Name)
	}

	// Re-enable 'a'.
	mgr.EnableAccount("a")
	active = mgr.ActiveAccounts()
	if len(active) != 2 {
		t.Errorf("expected 2 active accounts, got %d", len(active))
	}
}

func TestMultiAccountManager_ActiveAccounts(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "a", APIKey: "key-a"},
		{Name: "b", APIKey: "key-b"},
		{Name: "c", APIKey: "key-c"},
	}

	mgr := NewMultiAccountManager(accounts)

	active := mgr.ActiveAccounts()
	if len(active) != 3 {
		t.Errorf("expected 3 active accounts, got %d", len(active))
	}

	mgr.DisableAccount("b")
	active = mgr.ActiveAccounts()
	if len(active) != 2 {
		t.Errorf("expected 2 active accounts, got %d", len(active))
	}
}

func TestMultiAccountManager_DisableNonexistent(t *testing.T) {
	mgr := NewMultiAccountManager([]AccountConfig{
		{Name: "a", APIKey: "key-a"},
	})

	// Should not panic.
	mgr.DisableAccount("nonexistent")
	mgr.EnableAccount("nonexistent")

	active := mgr.ActiveAccounts()
	if len(active) != 1 {
		t.Errorf("expected 1 active account, got %d", len(active))
	}
}

func TestMultiAccountManager_Weight(t *testing.T) {
	accounts := []AccountConfig{
		{Name: "primary", APIKey: "key-1", Weight: 3},
		{Name: "secondary", APIKey: "key-2", Weight: 1},
	}

	mgr := NewMultiAccountManager(accounts)

	// Verify weights are preserved.
	acct := mgr.GetByName("primary")
	if acct.Weight != 3 {
		t.Errorf("expected weight 3, got %d", acct.Weight)
	}
}
