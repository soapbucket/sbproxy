package ai

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEnforcer(t *testing.T, cfg *AgentSessionConfig) (*AgentSessionEnforcer, *SessionTracker) {
	t.Helper()
	cache := newTestCacher(t)
	t.Cleanup(func() { cache.Close() })
	tracker := NewSessionTracker(cache, 5*time.Minute)
	enforcer := NewAgentSessionEnforcer(cfg, tracker)
	return enforcer, tracker
}

func TestAgentSessionEnforcer_MaxIterations(t *testing.T) {
	tests := []struct {
		name         string
		maxIter      int
		requests     int
		wantErr      bool
		wantErrCode  string
	}{
		{"under limit", 5, 3, false, ""},
		{"at limit", 5, 5, true, "session_iteration_limit"},
		{"over limit", 3, 4, true, "session_iteration_limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{
				MaxIterations: tt.maxIter,
			})
			ctx := context.Background()

			for i := 0; i < tt.requests; i++ {
				err := enforcer.RecordRequest(ctx, "sess-iter", "agent", "key", 10, 0.001)
				require.NoError(t, err)
			}

			err := enforcer.CheckLimits(ctx, "sess-iter")
			if tt.wantErr {
				require.Error(t, err)
				aiErr, ok := err.(*AIError)
				require.True(t, ok)
				assert.Equal(t, tt.wantErrCode, aiErr.Code)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAgentSessionEnforcer_MaxTokens(t *testing.T) {
	tests := []struct {
		name        string
		maxTokens   int64
		tokenBatch  int
		batches     int
		wantErr     bool
		wantErrCode string
	}{
		{"under limit", 1000, 100, 5, false, ""},
		{"at limit", 1000, 200, 5, true, "session_token_limit"},
		{"over limit", 500, 200, 3, true, "session_token_limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{
				MaxTokensPerSession: tt.maxTokens,
			})
			ctx := context.Background()

			for i := 0; i < tt.batches; i++ {
				err := enforcer.RecordRequest(ctx, "sess-tok", "agent", "key", tt.tokenBatch, 0.001)
				require.NoError(t, err)
			}

			err := enforcer.CheckLimits(ctx, "sess-tok")
			if tt.wantErr {
				require.Error(t, err)
				aiErr, ok := err.(*AIError)
				require.True(t, ok)
				assert.Equal(t, tt.wantErrCode, aiErr.Code)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAgentSessionEnforcer_MaxDuration(t *testing.T) {
	enforcer, tracker := newTestEnforcer(t, &AgentSessionConfig{
		MaxDuration: 100 * time.Millisecond,
	})
	ctx := context.Background()

	// Record a request to create the session.
	err := enforcer.RecordRequest(ctx, "sess-dur", "agent", "key", 10, 0.001)
	require.NoError(t, err)

	// Immediately should be within limits.
	err = enforcer.CheckLimits(ctx, "sess-dur")
	assert.NoError(t, err)

	// Manually backdate the session start time to simulate duration exceeded.
	data, getErr := tracker.Get(ctx, "sess-dur")
	require.NoError(t, getErr)
	data.StartedAt = time.Now().Add(-200 * time.Millisecond)

	// Re-save with the backdated start time through Track (to update the cache).
	// We use a small trick: lock, load, modify, save through the tracker's internals.
	// Instead, just wait a bit past the duration.
	time.Sleep(110 * time.Millisecond)

	err = enforcer.CheckLimits(ctx, "sess-dur")
	require.Error(t, err)
	aiErr, ok := err.(*AIError)
	require.True(t, ok)
	assert.Equal(t, "session_duration_limit", aiErr.Code)

	_ = data // used above for inspection
}

func TestAgentSessionEnforcer_TPM(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{
		TPMPerAgent: 500,
	})
	ctx := context.Background()

	// Record enough tokens to exceed the TPM limit.
	for i := 0; i < 3; i++ {
		err := enforcer.RecordRequest(ctx, "sess-tpm", "agent", "key", 200, 0.01)
		require.NoError(t, err)
	}

	// Now check - 600 tokens recorded, limit is 500.
	err := enforcer.CheckLimits(ctx, "sess-tpm")
	require.Error(t, err)
	aiErr, ok := err.(*AIError)
	require.True(t, ok)
	assert.Equal(t, "session_rate_limit", aiErr.Code)
	assert.Contains(t, aiErr.Message, "tokens per minute")
}

func TestAgentSessionEnforcer_RPM(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{
		RPMPerAgent: 3,
	})
	ctx := context.Background()

	// Record 3 requests to hit the limit.
	for i := 0; i < 3; i++ {
		err := enforcer.RecordRequest(ctx, "sess-rpm", "agent", "key", 10, 0.001)
		require.NoError(t, err)
	}

	// Now check - 3 requests, limit is 3.
	err := enforcer.CheckLimits(ctx, "sess-rpm")
	require.Error(t, err)
	aiErr, ok := err.(*AIError)
	require.True(t, ok)
	assert.Equal(t, "session_rate_limit", aiErr.Code)
	assert.Contains(t, aiErr.Message, "requests per minute")
}

func TestAgentSessionEnforcer_NoLimits(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		enforcer, _ := newTestEnforcer(t, nil)
		ctx := context.Background()

		// Record many requests with a nil config.
		for i := 0; i < 100; i++ {
			err := enforcer.RecordRequest(ctx, "sess-nil", "agent", "key", 10000, 100.0)
			require.NoError(t, err)
		}

		err := enforcer.CheckLimits(ctx, "sess-nil")
		assert.NoError(t, err)
	})

	t.Run("zero config", func(t *testing.T) {
		enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{})
		ctx := context.Background()

		for i := 0; i < 100; i++ {
			err := enforcer.RecordRequest(ctx, "sess-zero", "agent", "key", 10000, 100.0)
			require.NoError(t, err)
		}

		err := enforcer.CheckLimits(ctx, "sess-zero")
		assert.NoError(t, err)
	})
}

func TestAgentSessionEnforcer_MultipleLimits(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{
		MaxIterations:       10,
		MaxTokensPerSession: 5000,
		RPMPerAgent:         20,
		TPMPerAgent:         10000,
	})
	ctx := context.Background()

	// Record 5 requests with 800 tokens each (4000 total) - within all limits.
	for i := 0; i < 5; i++ {
		err := enforcer.RecordRequest(ctx, "sess-multi", "agent", "key", 800, 0.05)
		require.NoError(t, err)
	}

	err := enforcer.CheckLimits(ctx, "sess-multi")
	assert.NoError(t, err)

	// Record 2 more (7 total, 5600 tokens) - exceeds token limit.
	for i := 0; i < 2; i++ {
		err := enforcer.RecordRequest(ctx, "sess-multi", "agent", "key", 800, 0.05)
		require.NoError(t, err)
	}

	err = enforcer.CheckLimits(ctx, "sess-multi")
	require.Error(t, err)
	aiErr, ok := err.(*AIError)
	require.True(t, ok)
	// Could be either token limit - it depends on check ordering.
	// Rate limits are checked first, then iteration, then token, then duration.
	assert.Equal(t, "session_token_limit", aiErr.Code)
}

func TestAgentSessionEnforcer_NonexistentSession(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, &AgentSessionConfig{
		MaxIterations: 5,
	})
	ctx := context.Background()

	// Checking limits on a session that does not exist should return nil.
	err := enforcer.CheckLimits(ctx, "nonexistent-session")
	assert.NoError(t, err)
}

func TestAgentRateTracker_SlidingWindow(t *testing.T) {
	tracker := newAgentRateTracker(100 * time.Millisecond)

	// Record some requests.
	tracker.RecordRequest("key-1")
	tracker.RecordRequest("key-1")
	tracker.RecordTokens("key-1", 500)

	assert.Equal(t, 2, tracker.RequestsInWindow("key-1"))
	assert.Equal(t, int64(500), tracker.TokensInWindow("key-1"))

	// Wait for the window to expire.
	time.Sleep(120 * time.Millisecond)

	// Old entries should be pruned.
	assert.Equal(t, 0, tracker.RequestsInWindow("key-1"))
	assert.Equal(t, int64(0), tracker.TokensInWindow("key-1"))

	// New entries should work.
	tracker.RecordRequest("key-1")
	tracker.RecordTokens("key-1", 100)
	assert.Equal(t, 1, tracker.RequestsInWindow("key-1"))
	assert.Equal(t, int64(100), tracker.TokensInWindow("key-1"))
}

func TestAgentRateTracker_Concurrent(t *testing.T) {
	tracker := newAgentRateTracker(time.Minute)

	var wg sync.WaitGroup
	const goroutines = 50
	const requestsPerGoroutine = 20

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				tracker.RecordRequest("concurrent-key")
				tracker.RecordTokens("concurrent-key", 10)
				_ = tracker.RequestsInWindow("concurrent-key")
				_ = tracker.TokensInWindow("concurrent-key")
			}
		}()
	}
	wg.Wait()

	// All requests should be recorded.
	totalRequests := tracker.RequestsInWindow("concurrent-key")
	totalTokens := tracker.TokensInWindow("concurrent-key")
	assert.Equal(t, goroutines*requestsPerGoroutine, totalRequests)
	assert.Equal(t, int64(goroutines*requestsPerGoroutine*10), totalTokens)
}

func TestAgentRateTracker_MultipleKeys(t *testing.T) {
	tracker := newAgentRateTracker(time.Minute)

	tracker.RecordRequest("key-a")
	tracker.RecordRequest("key-a")
	tracker.RecordRequest("key-b")
	tracker.RecordTokens("key-a", 100)
	tracker.RecordTokens("key-b", 200)

	assert.Equal(t, 2, tracker.RequestsInWindow("key-a"))
	assert.Equal(t, 1, tracker.RequestsInWindow("key-b"))
	assert.Equal(t, int64(100), tracker.TokensInWindow("key-a"))
	assert.Equal(t, int64(200), tracker.TokensInWindow("key-b"))
}
