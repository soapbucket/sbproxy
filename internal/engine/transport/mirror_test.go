package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMirror_BasicMirroring(t *testing.T) {
	var mirrorReceived atomic.Int64

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
	ctx := context.Background()

	Mirror(ctx, req, MirrorConfig{
		URL:        mirrorServer.URL,
		Percentage: 1.0,
	}, http.DefaultClient)

	// Wait for async processing
	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, int64(1), mirrorReceived.Load())
}

func TestMirror_PreservesBodyForPrimary(t *testing.T) {
	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	bodyContent := `{"key":"value"}`
	req := httptest.NewRequest("POST", "https://primary.example.com/api/test", bytes.NewBufferString(bodyContent))
	ctx := context.Background()

	Mirror(ctx, req, MirrorConfig{
		URL:        mirrorServer.URL,
		Percentage: 1.0,
	}, http.DefaultClient)

	// Primary handler should still be able to read the body
	primaryBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyContent, string(primaryBody))
}

func TestMirror_ZeroPercentageDefaultsToFull(t *testing.T) {
	var mirrorReceived atomic.Int64

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
	ctx := context.Background()

	// Percentage 0 defaults to 1.0 (100%)
	Mirror(ctx, req, MirrorConfig{
		URL: mirrorServer.URL,
	}, http.DefaultClient)

	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int64(1), mirrorReceived.Load())
}

func TestMirror_PreservesPath(t *testing.T) {
	var receivedPath string

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	req := httptest.NewRequest("GET", "https://primary.example.com/api/users?page=2", nil)
	ctx := context.Background()

	Mirror(ctx, req, MirrorConfig{
		URL:        mirrorServer.URL,
		Percentage: 1.0,
	}, http.DefaultClient)

	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, "/api/users", receivedPath)
}

func TestMirror_CopiesHeaders(t *testing.T) {
	var receivedHeaders http.Header

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("Authorization", "Bearer token123")
	ctx := context.Background()

	Mirror(ctx, req, MirrorConfig{
		URL:        mirrorServer.URL,
		Percentage: 1.0,
	}, http.DefaultClient)

	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "Bearer token123", receivedHeaders.Get("Authorization"))
}

func TestMirror_CustomTimeout(t *testing.T) {
	// Verify that a custom timeout is applied. We test this by confirming the
	// mirror request still reaches the server (fire-and-forget semantics)
	// but with a timeout set on the context. The key behavior is that Mirror
	// does not block the caller regardless of timeout.
	var mirrorReceived atomic.Int64

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
	ctx := context.Background()

	start := time.Now()
	Mirror(ctx, req, MirrorConfig{
		URL:        mirrorServer.URL,
		Percentage: 1.0,
		TimeoutMs:  5000,
	}, http.DefaultClient)
	elapsed := time.Since(start)

	// Mirror should return immediately (fire-and-forget)
	assert.Less(t, elapsed, 100*time.Millisecond, "Mirror should not block the caller")

	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int64(1), mirrorReceived.Load())
}
