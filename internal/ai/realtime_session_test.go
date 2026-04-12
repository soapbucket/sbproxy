package ai

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestRealtimeSessionManager_Create(t *testing.T) {
	tests := []struct {
		name      string
		max       int
		principal string
		provider  string
		model     string
		wantErr   bool
	}{
		{
			name:      "basic create",
			max:       10,
			principal: "user-1",
			provider:  "openai",
			model:     "gpt-4o-realtime",
		},
		{
			name:      "default max sessions",
			max:       0,
			principal: "user-2",
			provider:  "openai",
			model:     "gpt-4o-realtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewRealtimeSessionManager(tt.max)
			s, err := m.Create(tt.principal, tt.provider, tt.model)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if s.ID == "" {
				t.Error("expected non-empty session ID")
			}
			if s.PrincipalID != tt.principal {
				t.Errorf("PrincipalID = %q, want %q", s.PrincipalID, tt.principal)
			}
			if s.ProviderName != tt.provider {
				t.Errorf("ProviderName = %q, want %q", s.ProviderName, tt.provider)
			}
			if s.Model != tt.model {
				t.Errorf("Model = %q, want %q", s.Model, tt.model)
			}
			if !s.Active {
				t.Error("expected session to be active")
			}
			if s.StartTime.IsZero() {
				t.Error("expected non-zero start time")
			}
		})
	}
}

func TestRealtimeSessionManager_MaxSessions(t *testing.T) {
	m := NewRealtimeSessionManager(2)

	s1, err := m.Create("u1", "openai", "gpt-4o")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = m.Create("u2", "openai", "gpt-4o")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}

	// Third should fail.
	_, err = m.Create("u3", "openai", "gpt-4o")
	if err != ErrMaxSessionsReached {
		t.Fatalf("expected ErrMaxSessionsReached, got %v", err)
	}

	// Close one, then creating should succeed.
	m.Close(s1.ID)

	_, err = m.Create("u3", "openai", "gpt-4o")
	if err != nil {
		t.Fatalf("create after close: %v", err)
	}
}

func TestRealtimeSessionManager_Get(t *testing.T) {
	m := NewRealtimeSessionManager(10)

	s, _ := m.Create("u1", "openai", "gpt-4o")

	tests := []struct {
		name   string
		id     string
		wantOK bool
	}{
		{"existing", s.ID, true},
		{"missing", "rt_nonexistent", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := m.Get(tt.id)
			if ok != tt.wantOK {
				t.Fatalf("Get(%q) ok = %v, want %v", tt.id, ok, tt.wantOK)
			}
			if ok && got.ID != tt.id {
				t.Errorf("Get returned session with ID %q, want %q", got.ID, tt.id)
			}
		})
	}
}

func TestRealtimeSessionManager_Close(t *testing.T) {
	m := NewRealtimeSessionManager(10)

	s, _ := m.Create("u1", "openai", "gpt-4o")

	// Close it.
	m.Close(s.ID)

	got, ok := m.Get(s.ID)
	if !ok {
		t.Fatal("session should still be retrievable after close")
	}
	if got.Active {
		t.Error("session should be inactive after close")
	}
	if got.Duration <= 0 {
		t.Error("expected positive duration after close")
	}

	// Double close should be safe (no-op).
	m.Close(s.ID)

	// Close non-existent should not panic.
	m.Close("rt_doesnotexist")
}

func TestRealtimeSessionManager_TrackTokens(t *testing.T) {
	m := NewRealtimeSessionManager(10)
	s, _ := m.Create("u1", "openai", "gpt-4o")

	tests := []struct {
		name    string
		in, out int64
		wantIn  int64
		wantOut int64
	}{
		{"first batch", 100, 200, 100, 200},
		{"second batch", 50, 75, 150, 275},
		{"zero values", 0, 0, 150, 275},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.TrackTokens(s.ID, tt.in, tt.out)
			if atomic.LoadInt64(&s.TokensIn) != tt.wantIn {
				t.Errorf("TokensIn = %d, want %d", s.TokensIn, tt.wantIn)
			}
			if atomic.LoadInt64(&s.TokensOut) != tt.wantOut {
				t.Errorf("TokensOut = %d, want %d", s.TokensOut, tt.wantOut)
			}
		})
	}

	// Track tokens on non-existent session should not panic.
	m.TrackTokens("rt_ghost", 10, 20)
}

func TestRealtimeSessionManager_ActiveSessions(t *testing.T) {
	m := NewRealtimeSessionManager(10)

	s1, _ := m.Create("u1", "openai", "gpt-4o")
	m.Create("u2", "openai", "gpt-4o")
	m.Create("u3", "anthropic", "claude")

	active := m.ActiveSessions()
	if len(active) != 3 {
		t.Fatalf("ActiveSessions() = %d, want 3", len(active))
	}

	m.Close(s1.ID)
	active = m.ActiveSessions()
	if len(active) != 2 {
		t.Fatalf("ActiveSessions() after close = %d, want 2", len(active))
	}
}

func TestRealtimeSessionManager_SessionsByPrincipal(t *testing.T) {
	m := NewRealtimeSessionManager(10)

	m.Create("alice", "openai", "gpt-4o")
	m.Create("alice", "anthropic", "claude")
	m.Create("bob", "openai", "gpt-4o")

	aliceSessions := m.SessionsByPrincipal("alice")
	if len(aliceSessions) != 2 {
		t.Fatalf("SessionsByPrincipal(alice) = %d, want 2", len(aliceSessions))
	}

	bobSessions := m.SessionsByPrincipal("bob")
	if len(bobSessions) != 1 {
		t.Fatalf("SessionsByPrincipal(bob) = %d, want 1", len(bobSessions))
	}

	emptySessions := m.SessionsByPrincipal("nobody")
	if len(emptySessions) != 0 {
		t.Fatalf("SessionsByPrincipal(nobody) = %d, want 0", len(emptySessions))
	}
}

func TestRealtimeSessionManager_ConcurrentAccess(t *testing.T) {
	m := NewRealtimeSessionManager(1000)

	var wg sync.WaitGroup
	var created int64

	// Spawn many goroutines creating and closing sessions.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := m.Create("user", "openai", "gpt-4o")
			if err != nil {
				return
			}
			atomic.AddInt64(&created, 1)
			m.TrackTokens(s.ID, 10, 20)
			m.Close(s.ID)
		}()
	}

	wg.Wait()

	if created == 0 {
		t.Fatal("expected at least some sessions to be created")
	}

	active := m.ActiveSessions()
	if len(active) != 0 {
		t.Errorf("expected 0 active sessions after all closed, got %d", len(active))
	}
}
