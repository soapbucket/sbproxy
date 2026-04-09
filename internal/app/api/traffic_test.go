package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/capture"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSetup(t *testing.T) (*TrafficAPI, *capture.Manager) {
	t.Helper()

	msg, err := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverMemory})
	require.NoError(t, err)

	cache, err := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	require.NoError(t, err)

	ctx := context.Background()
	mgr := capture.NewManager(ctx, msg, cache)
	api := NewTrafficAPI(mgr, "")

	t.Cleanup(func() {
		mgr.Close()
		msg.Close()
		cache.Close()
	})

	return api, mgr
}

func pushTestExchanges(t *testing.T, mgr *capture.Manager, hostname string, count int) []string {
	t.Helper()

	ids := make([]string, count)
	for i := range count {
		ex := mgr.AcquireExchange()
		ex.Request = reqctx.CapturedRequest{
			Method:     "GET",
			URL:        "https://" + hostname + "/api/test",
			Path:       "/api/test",
			Host:       hostname,
			Scheme:     "https",
			RemoteAddr: "192.168.1.1:1234",
		}
		ex.Response = reqctx.CapturedResponse{
			StatusCode: 200,
			Body:       []byte(`{"index":` + string(rune('0'+i)) + `}`),
			BodySize:   12,
		}
		ex.Duration = 1000
		ids[i] = ex.ID
		mgr.Push(hostname, ex, 10*time.Minute)
	}

	// Wait for processing
	time.Sleep(300 * time.Millisecond)
	return ids
}

func TestHandleList_Success(t *testing.T) {
	api, mgr := newTestSetup(t)

	hostname := "list-test.example.com"
	pushTestExchanges(t, mgr, hostname, 5)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchanges?hostname="+hostname+"&limit=10", nil)
	rr := httptest.NewRecorder()
	api.HandleList(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		Exchanges []*reqctx.Exchange `json:"exchanges"`
		Count     int                `json:"count"`
		Hostname  string             `json:"hostname"`
		Limit     int                `json:"limit"`
		Offset    int                `json:"offset"`
	}
	err := json.NewDecoder(rr.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, 5, resp.Count)
	assert.Equal(t, hostname, resp.Hostname)
	assert.Equal(t, 10, resp.Limit)
	assert.Len(t, resp.Exchanges, 5)
}

func TestHandleList_MissingHostname(t *testing.T) {
	api, _ := newTestSetup(t)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchanges", nil)
	rr := httptest.NewRecorder()
	api.HandleList(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleList_Pagination(t *testing.T) {
	api, mgr := newTestSetup(t)

	hostname := "paginate-test.example.com"
	pushTestExchanges(t, mgr, hostname, 15)

	// Page 1
	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchanges?hostname="+hostname+"&limit=5&offset=0", nil)
	rr := httptest.NewRecorder()
	api.HandleList(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var page1 struct {
		Count int `json:"count"`
	}
	json.NewDecoder(rr.Body).Decode(&page1)
	assert.Equal(t, 5, page1.Count)

	// Page 2
	req2 := httptest.NewRequest("GET", "/_sb/api/traffic/exchanges?hostname="+hostname+"&limit=5&offset=5", nil)
	rr2 := httptest.NewRecorder()
	api.HandleList(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code)

	var page2 struct {
		Count int `json:"count"`
	}
	json.NewDecoder(rr2.Body).Decode(&page2)
	assert.Equal(t, 5, page2.Count)
}

func TestHandleList_EmptyResult(t *testing.T) {
	api, _ := newTestSetup(t)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchanges?hostname=empty.example.com&limit=10", nil)
	rr := httptest.NewRecorder()
	api.HandleList(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		Count int `json:"count"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)
	assert.Equal(t, 0, resp.Count)
}

func TestHandleGet_Success(t *testing.T) {
	api, mgr := newTestSetup(t)

	hostname := "get-test.example.com"
	ids := pushTestExchanges(t, mgr, hostname, 1)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchange?hostname="+hostname+"&id="+ids[0], nil)
	rr := httptest.NewRecorder()
	api.HandleGet(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var ex reqctx.Exchange
	err := json.NewDecoder(rr.Body).Decode(&ex)
	require.NoError(t, err)
	assert.Equal(t, ids[0], ex.ID)
	assert.Equal(t, "GET", ex.Request.Method)
}

func TestHandleGet_NotFound(t *testing.T) {
	api, _ := newTestSetup(t)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchange?hostname=missing.example.com&id=nonexistent", nil)
	rr := httptest.NewRecorder()
	api.HandleGet(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleGet_MissingParams(t *testing.T) {
	api, _ := newTestSetup(t)

	// Missing both
	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchange", nil)
	rr := httptest.NewRecorder()
	api.HandleGet(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Missing id
	req2 := httptest.NewRequest("GET", "/_sb/api/traffic/exchange?hostname=test.com", nil)
	rr2 := httptest.NewRecorder()
	api.HandleGet(rr2, req2)
	assert.Equal(t, http.StatusBadRequest, rr2.Code)
}

func TestHandleMetrics(t *testing.T) {
	api, mgr := newTestSetup(t)

	// Push some exchanges to generate metrics
	pushTestExchanges(t, mgr, "metrics.example.com", 3)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/metrics", nil)
	rr := httptest.NewRecorder()
	api.HandleMetrics(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var metrics reqctx.CaptureMetrics
	err := json.NewDecoder(rr.Body).Decode(&metrics)
	require.NoError(t, err)
	assert.Equal(t, int64(3), metrics.Captured)
	assert.Equal(t, int64(0), metrics.Dropped)
}

func TestHandleStream_MissingHostname(t *testing.T) {
	api, _ := newTestSetup(t)

	req := httptest.NewRequest("GET", "/_sb/api/traffic/stream", nil)
	rr := httptest.NewRecorder()
	api.HandleStream(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestEndToEnd_CaptureAndRetrieve is a comprehensive E2E test that verifies
// the complete flow: capture middleware -> manager -> cacher -> REST API
func TestEndToEnd_CaptureAndRetrieve(t *testing.T) {
	msg, err := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverMemory})
	require.NoError(t, err)
	defer msg.Close()

	cache, err := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	mgr := capture.NewManager(ctx, msg, cache)
	defer mgr.Close()

	hostname := "e2e-test.example.com"

	// Push 10 exchanges simulating captured traffic
	for i := range 10 {
		ex := mgr.AcquireExchange()
		ex.Request = reqctx.CapturedRequest{
			Method:      "POST",
			URL:         "https://" + hostname + "/api/v1/users",
			Path:        "/api/v1/users",
			Host:        hostname,
			Scheme:      "https",
			Headers:     http.Header{"Content-Type": {"application/json"}},
			Body:        []byte(`{"name":"user` + string(rune('0'+i)) + `"}`),
			BodySize:    20,
			ContentType: "application/json",
			RemoteAddr:  "10.0.0.1:5000",
		}
		ex.Response = reqctx.CapturedResponse{
			StatusCode:  201,
			Headers:     http.Header{"Content-Type": {"application/json"}},
			Body:        []byte(`{"id":"` + ex.ID + `","created":true}`),
			BodySize:    40,
			ContentType: "application/json",
		}
		ex.Duration = int64(i * 100) // Variable duration
		ex.Meta["request_id"] = "req-" + ex.ID
		mgr.Push(hostname, ex, 10*time.Minute)
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Create the API and verify retrieval
	api := NewTrafficAPI(mgr, "")

	// List all exchanges
	req := httptest.NewRequest("GET", "/_sb/api/traffic/exchanges?hostname="+hostname+"&limit=100", nil)
	rr := httptest.NewRecorder()
	api.HandleList(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var listResp struct {
		Exchanges []*reqctx.Exchange `json:"exchanges"`
		Count     int                `json:"count"`
	}
	err = json.NewDecoder(rr.Body).Decode(&listResp)
	require.NoError(t, err)
	assert.Equal(t, 10, listResp.Count)

	// Get a specific exchange
	firstID := listResp.Exchanges[0].ID
	getReq := httptest.NewRequest("GET", "/_sb/api/traffic/exchange?hostname="+hostname+"&id="+firstID, nil)
	getRR := httptest.NewRecorder()
	api.HandleGet(getRR, getReq)

	assert.Equal(t, http.StatusOK, getRR.Code)

	var getResp reqctx.Exchange
	err = json.NewDecoder(getRR.Body).Decode(&getResp)
	require.NoError(t, err)
	assert.Equal(t, firstID, getResp.ID)
	assert.Equal(t, "POST", getResp.Request.Method)
	assert.Equal(t, 201, getResp.Response.StatusCode)

	// Verify metrics
	metricsReq := httptest.NewRequest("GET", "/_sb/api/traffic/metrics", nil)
	metricsRR := httptest.NewRecorder()
	api.HandleMetrics(metricsRR, metricsReq)

	assert.Equal(t, http.StatusOK, metricsRR.Code)

	var metrics reqctx.CaptureMetrics
	json.NewDecoder(metricsRR.Body).Decode(&metrics)
	assert.Equal(t, int64(10), metrics.Captured)
}
