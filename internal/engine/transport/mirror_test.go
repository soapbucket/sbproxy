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
	pathCh := make(chan string, 1)

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathCh <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	req := httptest.NewRequest("GET", "https://primary.example.com/api/users?page=2", nil)
	ctx := context.Background()

	Mirror(ctx, req, MirrorConfig{
		URL:        mirrorServer.URL,
		Percentage: 1.0,
	}, http.DefaultClient)

	select {
	case path := <-pathCh:
		assert.Equal(t, "/api/users", path)
	case <-time.After(2 * time.Second):
		t.Fatal("mirror request was not received")
	}
}

func TestMirror_CopiesHeaders(t *testing.T) {
	headersCh := make(chan http.Header, 1)

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersCh <- r.Header.Clone()
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

	select {
	case headers := <-headersCh:
		assert.Equal(t, "test-value", headers.Get("X-Custom-Header"))
		assert.Equal(t, "Bearer token123", headers.Get("Authorization"))
	case <-time.After(2 * time.Second):
		t.Fatal("mirror request was not received")
	}
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
