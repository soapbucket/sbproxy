package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockChecker is a mock health checker for testing
type mockChecker struct {
	name   string
	status string
	err    error
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Check() (string, error) {
	return m.status, m.err
}

// countingChecker tracks how many times Check is called.
type countingChecker struct {
	name      string
	status    string
	callCount *int
}

func (c *countingChecker) Name() string { return c.name }

func (c *countingChecker) Check() (string, error) {
	*c.callCount++
	return c.status, nil
}

func TestInitialize(t *testing.T) {
	// Reset global manager
	globalManager = nil
	once = *new(sync.Once)

	mgr := Initialize()
	assert.NotNil(t, mgr)
	assert.True(t, mgr.IsLive())
	assert.False(t, mgr.IsReady())
	assert.NotZero(t, mgr.startTime)
}

func TestGetManager(t *testing.T) {
	// Reset global manager
	globalManager = nil
	once = *new(sync.Once)

	mgr1 := GetManager()
	mgr2 := GetManager()
	assert.Same(t, mgr1, mgr2, "GetManager should return the same instance")
}

func TestRegisterChecker(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	checker := &mockChecker{name: "test", status: "ok", err: nil}
	mgr.RegisterChecker(checker)

	assert.Len(t, mgr.checkers, 1)
	assert.Contains(t, mgr.checkers, "test")
}

func TestSetReadyLive(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.live.Store(true)
	mgr.ready.Store(false)

	assert.True(t, mgr.IsLive())
	assert.False(t, mgr.IsReady())

	mgr.SetReady(true)
	assert.True(t, mgr.IsReady())

	mgr.SetLive(false)
	assert.False(t, mgr.IsLive())
}

func TestGetStatus_AllHealthy(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	checker1 := &mockChecker{name: "database", status: "ok", err: nil}
	checker2 := &mockChecker{name: "cache", status: "ok", err: nil}

	mgr.RegisterChecker(checker1)
	mgr.RegisterChecker(checker2)

	status := mgr.GetStatus()
	assert.Equal(t, "ok", status.Status)
	assert.Len(t, status.Checks, 2)
	assert.Equal(t, "ok", status.Checks["database"])
	assert.Equal(t, "ok", status.Checks["cache"])
	assert.NotEmpty(t, status.Version)
	assert.NotEmpty(t, status.Timestamp)
	assert.NotEmpty(t, status.Uptime)
}

func TestGetStatus_Degraded(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	checker1 := &mockChecker{name: "database", status: "ok", err: nil}
	checker2 := &mockChecker{name: "cache", status: "degraded", err: nil}

	mgr.RegisterChecker(checker1)
	mgr.RegisterChecker(checker2)

	status := mgr.GetStatus()
	assert.Equal(t, "degraded", status.Status)
	assert.Equal(t, "ok", status.Checks["database"])
	assert.Equal(t, "degraded", status.Checks["cache"])
}

func TestGetStatus_Error(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	checker1 := &mockChecker{name: "database", status: "ok", err: nil}
	checker2 := &mockChecker{name: "cache", status: "", err: errors.New("connection failed")}

	mgr.RegisterChecker(checker1)
	mgr.RegisterChecker(checker2)

	status := mgr.GetStatus()
	assert.Equal(t, "error", status.Status)
	assert.Equal(t, "ok", status.Checks["database"])
	assert.Contains(t, status.Checks["cache"], "error: connection failed")
}

func TestHealthHandler_Healthy(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.live.Store(true)
	mgr.ready.Store(true)

	checker := &mockChecker{name: "test", status: "ok", err: nil}
	mgr.RegisterChecker(checker)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	mgr.HealthHandler()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var status Status
	err := json.NewDecoder(w.Body).Decode(&status)
	require.NoError(t, err)
	assert.Equal(t, "ok", status.Status)
}

func TestHealthHandler_Error(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	checker := &mockChecker{name: "test", status: "", err: errors.New("failed")}
	mgr.RegisterChecker(checker)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	mgr.HealthHandler()(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var status Status
	err := json.NewDecoder(w.Body).Decode(&status)
	require.NoError(t, err)
	assert.Equal(t, "error", status.Status)
}

func TestReadyHandler_Ready(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.ready.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()

	mgr.ReadyHandler()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "ready", response["status"])
}

func TestReadyHandler_NotReady(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.ready.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()

	mgr.ReadyHandler()(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "not_ready", response["status"])
}

func TestLiveHandler_Live(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.live.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	w := httptest.NewRecorder()

	mgr.LiveHandler()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "alive", response["status"])
}

func TestLiveHandler_NotLive(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.live.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	w := httptest.NewRecorder()

	mgr.LiveHandler()(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "dead", response["status"])
}

// --- Tests for new K8s-style endpoints ---

func TestHealthzHandler_Healthy(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}

	mgr.RegisterChecker(&mockChecker{name: "cache", status: "ok"})
	mgr.RegisterChecker(&mockChecker{name: "config", status: "ok"})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	mgr.HealthzHandler()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "ok", resp["status"])

	deps, ok := resp["dependencies"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ok", deps["cache"])
	assert.Equal(t, "ok", deps["config"])
}

func TestHealthzHandler_WithError(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}

	mgr.RegisterChecker(&mockChecker{name: "cache", status: "", err: errors.New("down")})
	mgr.RegisterChecker(&mockChecker{name: "config", status: "ok"})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	mgr.HealthzHandler()(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "error", resp["status"])

	deps := resp["dependencies"].(map[string]interface{})
	assert.Equal(t, "error", deps["cache"])
}

func TestHealthzHandler_CachesResults(t *testing.T) {
	callCount := 0
	checker := &countingChecker{
		name:      "test",
		status:    "ok",
		callCount: &callCount,
	}

	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	mgr.RegisterChecker(checker)

	// First call populates cache.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	mgr.HealthzHandler()(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, callCount)

	// Second call should use cache, not increment call count.
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w = httptest.NewRecorder()
	mgr.HealthzHandler()(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, callCount, "dependency check should be cached")
}

func TestReadyzHandler_Ready(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	mgr.ready.Store(true)
	mgr.RegisterChecker(&mockChecker{name: "cache", status: "ok"})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	mgr.ReadyzHandler()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["ready"])
}

func TestReadyzHandler_DependencyFailure(t *testing.T) {
	// Set startTime far in the past so grace period is expired.
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now().Add(-time.Hour),
		startupGrace: defaultStartupGrace,
	}
	mgr.ready.Store(true)
	mgr.RegisterChecker(&mockChecker{name: "cache", status: "", err: errors.New("unreachable")})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	mgr.ReadyzHandler()(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, false, resp["ready"])
	assert.Equal(t, "dependency_failure", resp["reason"])
}

func TestReadyzHandler_GracePeriod(t *testing.T) {
	// Within grace period, dependency failures should not cause 503.
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: 30 * time.Second,
	}
	mgr.ready.Store(false) // not yet ready
	mgr.RegisterChecker(&mockChecker{name: "cache", status: "", err: errors.New("unreachable")})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	mgr.ReadyzHandler()(w, req)

	// During grace period, should return 200 even with failures.
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["ready"])
}

func TestReadyzHandler_ShuttingDown(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	mgr.ready.Store(true)
	mgr.shuttingDown.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	mgr.ReadyzHandler()(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, false, resp["ready"])
	assert.Equal(t, "shutting_down", resp["reason"])
}

func TestLivezHandler_AlwaysAlive(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	// Even if live is false on the manager, livez always returns alive.
	mgr.live.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	w := httptest.NewRecorder()
	mgr.LivezHandler()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["alive"])
}

func TestConcurrentAccess(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
	mgr.live.Store(true)
	mgr.ready.Store(true)

	// Concurrent checker registration
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			checker := &mockChecker{name: string(rune('a' + id)), status: "ok", err: nil}
			mgr.RegisterChecker(checker)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent status checks
	for i := 0; i < 10; i++ {
		go func() {
			status := mgr.GetStatus()
			assert.NotEmpty(t, status.Status)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Len(t, mgr.checkers, 10)
}
