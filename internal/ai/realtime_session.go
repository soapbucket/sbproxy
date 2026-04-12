// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// RealtimeSession tracks a single WebSocket realtime session with a provider.
type RealtimeSession struct {
	ID           string        `json:"id"`
	PrincipalID  string        `json:"principal_id"`
	ProviderName string        `json:"provider_name"`
	Model        string        `json:"model"`
	StartTime    time.Time     `json:"start_time"`
	TokensIn     int64         `json:"tokens_in"`
	TokensOut    int64         `json:"tokens_out"`
	CostEstimate float64       `json:"cost_estimate"`
	Duration     time.Duration `json:"duration"`
	Active       bool          `json:"active"`

	mu sync.Mutex `json:"-"`
}

// RealtimeSessionManager manages active realtime/WebSocket sessions.
type RealtimeSessionManager struct {
	sessions    sync.Map // sessionID -> *RealtimeSession
	maxSessions int
	count       int64 // atomic count of active sessions
}

var (
	// ErrMaxSessionsReached is returned when the session limit is reached.
	ErrMaxSessionsReached = errors.New("realtime: maximum sessions reached")
	// ErrSessionNotFound is returned when a session ID does not exist.
	ErrSessionNotFound = errors.New("realtime: session not found")
)

// NewRealtimeSessionManager creates a manager with the given max concurrent sessions.
func NewRealtimeSessionManager(maxSessions int) *RealtimeSessionManager {
	if maxSessions <= 0 {
		maxSessions = 100
	}
	return &RealtimeSessionManager{
		maxSessions: maxSessions,
	}
}

// generateSessionID produces a random hex session identifier.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rt_" + hex.EncodeToString(b), nil
}

// Create starts a new realtime session, returning an error if the limit is reached.
func (m *RealtimeSessionManager) Create(principalID, provider, model string) (*RealtimeSession, error) {
	current := atomic.LoadInt64(&m.count)
	if current >= int64(m.maxSessions) {
		return nil, ErrMaxSessionsReached
	}

	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	s := &RealtimeSession{
		ID:           id,
		PrincipalID:  principalID,
		ProviderName: provider,
		Model:        model,
		StartTime:    time.Now(),
		Active:       true,
	}

	// Check-and-store: another goroutine may have stored a session concurrently,
	// so we re-check the count after incrementing.
	newCount := atomic.AddInt64(&m.count, 1)
	if newCount > int64(m.maxSessions) {
		atomic.AddInt64(&m.count, -1)
		return nil, ErrMaxSessionsReached
	}

	m.sessions.Store(id, s)
	return s, nil
}

// Get returns the session for the given ID, or false if not found.
func (m *RealtimeSessionManager) Get(sessionID string) (*RealtimeSession, bool) {
	val, ok := m.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	s, ok := val.(*RealtimeSession)
	return s, ok
}

// Close marks a session as inactive and records its duration.
func (m *RealtimeSessionManager) Close(sessionID string) {
	val, ok := m.sessions.Load(sessionID)
	if !ok {
		return
	}
	s, ok := val.(*RealtimeSession)
	if !ok {
		return
	}
	s.mu.Lock()
	if !s.Active {
		s.mu.Unlock()
		return
	}
	s.Active = false
	s.Duration = time.Since(s.StartTime)
	s.mu.Unlock()
	atomic.AddInt64(&m.count, -1)
}

// TrackTokens atomically adds input and output token counts for a session.
func (m *RealtimeSessionManager) TrackTokens(sessionID string, input, output int64) {
	val, ok := m.sessions.Load(sessionID)
	if !ok {
		return
	}
	s, ok := val.(*RealtimeSession)
	if !ok {
		return
	}
	atomic.AddInt64(&s.TokensIn, input)
	atomic.AddInt64(&s.TokensOut, output)
}

// ActiveSessions returns all currently active sessions.
func (m *RealtimeSessionManager) ActiveSessions() []*RealtimeSession {
	var result []*RealtimeSession
	m.sessions.Range(func(_, value any) bool {
		s, ok := value.(*RealtimeSession)
		if !ok {
			return true
		}
		s.mu.Lock()
		active := s.Active
		s.mu.Unlock()
		if active {
			result = append(result, s)
		}
		return true
	})
	return result
}

// SessionsByPrincipal returns all sessions (active and inactive) for a principal.
func (m *RealtimeSessionManager) SessionsByPrincipal(principalID string) []*RealtimeSession {
	var result []*RealtimeSession
	m.sessions.Range(func(_, value any) bool {
		s, ok := value.(*RealtimeSession)
		if ok && s.PrincipalID == principalID {
			result = append(result, s)
		}
		return true
	})
	return result
}
