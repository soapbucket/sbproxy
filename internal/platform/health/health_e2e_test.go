package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHealthzE2E_ReturnsJSONWithDependencies verifies that /healthz returns a
// JSON response containing a "dependencies" map listing each registered checker.
func TestHealthzE2E_ReturnsJSONWithDependencies(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}

	mgr.RegisterChecker(&mockChecker{name: "cache", status: "ok"})
	mgr.RegisterChecker(&mockChecker{name: "config", status: "ok"})
	mgr.RegisterChecker(&mockChecker{name: "database", status: "ok"})

	srv := httptest.NewServer(mgr.HealthzHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, "ok", body["status"])

	deps, ok := body["dependencies"].(map[string]interface{})
	require.True(t, ok, "expected 'dependencies' to be a map")
	assert.Equal(t, "ok", deps["cache"])
	assert.Equal(t, "ok", deps["config"])
	assert.Equal(t, "ok", deps["database"])
}

// TestHealthzE2E_DegradedDependency verifies that a degraded dependency
// produces a "degraded" overall status but still returns HTTP 200.
func TestHealthzE2E_DegradedDependency(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}

	mgr.RegisterChecker(&mockChecker{name: "cache", status: "degraded"})
	mgr.RegisterChecker(&mockChecker{name: "config", status: "ok"})

	srv := httptest.NewServer(mgr.HealthzHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Degraded is still considered operational, so HTTP 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "degraded", body["status"])
}

// TestReadyzE2E_Returns200WhenHealthy verifies the /readyz endpoint returns 200
// with {"ready": true} when the service is ready and all dependencies are healthy.
func TestReadyzE2E_Returns200WhenHealthy(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	mgr.ready.Store(true)
	mgr.RegisterChecker(&mockChecker{name: "cache", status: "ok"})

	srv := httptest.NewServer(mgr.ReadyzHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ready"])
}

// TestReadyzE2E_Returns503WhenShuttingDown verifies /readyz returns 503 during
// graceful shutdown.
func TestReadyzE2E_Returns503WhenShuttingDown(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	mgr.ready.Store(true)
	mgr.shuttingDown.Store(true)

	srv := httptest.NewServer(mgr.ReadyzHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ready"])
	assert.Equal(t, "shutting_down", body["reason"])
}

// TestLivezE2E_AlwaysReturns200 verifies that /livez always returns 200 with
// {"alive": true}, as it is intended for K8s liveness probes and should never
// fail unless the process is hung.
func TestLivezE2E_AlwaysReturns200(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	// Even with liveness set to false and shutting down, livez should return 200.
	mgr.live.Store(false)
	mgr.shuttingDown.Store(true)

	srv := httptest.NewServer(mgr.LivezHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/livez")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["alive"])
}

// TestLivezE2E_ContentTypeJSON verifies /livez returns application/json.
func TestLivezE2E_ContentTypeJSON(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}

	srv := httptest.NewServer(mgr.LivezHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/livez")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}

// TestHealthzE2E_ShuttingDown verifies that /healthz includes shutting_down
// status when the service is shutting down.
func TestHealthzE2E_ShuttingDown(t *testing.T) {
	mgr := &Manager{
		checkers:     make(map[string]Checker),
		startTime:    time.Now(),
		startupGrace: defaultStartupGrace,
	}
	mgr.shuttingDown.Store(true)
	mgr.RegisterChecker(&mockChecker{name: "cache", status: "ok"})

	srv := httptest.NewServer(mgr.HealthzHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Shutting down is not an error, so it should still return 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "shutting_down", body["status"])
}
