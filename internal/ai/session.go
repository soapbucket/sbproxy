// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"hash/fnv"
	"io"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// shardedMutex is an array of mutexes for lock sharding
type shardedMutex [16]sync.Mutex

// lock acquires the shard lock for the given key
func (sm *shardedMutex) lock(key string) {
	h := fnv.New32a()
	h.Write([]byte(key))
	shard := int(h.Sum32() % 16)
	sm[shard].Lock()
}

// unlock releases the shard lock for the given key
func (sm *shardedMutex) unlock(key string) {
	h := fnv.New32a()
	h.Write([]byte(key))
	shard := int(h.Sum32() % 16)
	sm[shard].Unlock()
}

// SessionTracker tracks agent sessions using a cacher backend.
type SessionTracker struct {
	cache   cacher.Cacher
	ttl     time.Duration
	sharded shardedMutex // 16-way sharded mutex for parallelized session tracking
}

// SessionData holds accumulated data for a session.
type SessionData struct {
	SessionID    string    `json:"session_id"`
	Agent        string    `json:"agent,omitempty"`
	APIKey       string    `json:"api_key,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	RequestCount int       `json:"request_count"`
	TotalTokens  int       `json:"total_tokens"`
	TotalCostUSD float64   `json:"total_cost_usd"`
}

// NewSessionTracker creates a session tracker backed by the given cacher.
func NewSessionTracker(cache cacher.Cacher, ttl time.Duration) *SessionTracker {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &SessionTracker{
		cache: cache,
		ttl:   ttl,
	}
}

const sessionPrefix = "ai:session:"

// Track records a request for the given session.
// Returns the updated session data and whether this was the first request (new session).
func (st *SessionTracker) Track(ctx context.Context, sessionID, agent, apiKey string, tokens int, costUSD float64) (*SessionData, bool, error) {
	st.sharded.lock(sessionID)
	defer st.sharded.unlock(sessionID)

	key := sessionPrefix + sessionID
	isNew := false

	// Try to load existing session
	data, err := st.load(ctx, key)
	if err != nil {
		// New session
		isNew = true
		data = &SessionData{
			SessionID: sessionID,
			Agent:     agent,
			APIKey:    apiKey,
			StartedAt: time.Now(),
		}
	}

	// Update session data
	data.LastActiveAt = time.Now()
	data.RequestCount++
	data.TotalTokens += tokens
	data.TotalCostUSD += costUSD
	if data.Agent == "" && agent != "" {
		data.Agent = agent
	}

	// Save with refreshed TTL
	if err := st.save(ctx, key, data); err != nil {
		return nil, false, fmt.Errorf("session track: save: %w", err)
	}

	return data, isNew, nil
}

// Get retrieves session data by ID.
func (st *SessionTracker) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	key := sessionPrefix + sessionID
	return st.load(ctx, key)
}

func (st *SessionTracker) load(ctx context.Context, key string) (*SessionData, error) {
	reader, err := st.cache.Get(ctx, "sessions", key)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var data SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (st *SessionTracker) save(ctx context.Context, key string, data *SessionData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return st.cache.PutWithExpires(ctx, "sessions", key, bytes.NewReader(raw), st.ttl)
}
