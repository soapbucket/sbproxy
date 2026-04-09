// Package api exposes internal management endpoints for traffic inspection and configuration.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/capture"
	"github.com/soapbucket/sbproxy/internal/engine/handler"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)


// TrafficAPI exposes REST and SSE endpoints for the traffic capture system.
type TrafficAPI struct {
	captureManager *capture.Manager
	adminKey       string // Admin API key. Empty disables auth.
}

// NewTrafficAPI creates a new TrafficAPI. If adminKey is empty, auth is disabled.
func NewTrafficAPI(mgr *capture.Manager, adminKey string) *TrafficAPI {
	return &TrafficAPI{
		captureManager: mgr,
		adminKey:       adminKey,
	}
}

// authenticate checks if the request carries a valid admin Bearer token.
// If adminKey is empty, authentication is disabled and all requests are allowed.
func (t *TrafficAPI) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if t.adminKey == "" {
		return true
	}

	authHeader := r.Header.Get("Authorization")
	expected := fmt.Sprintf("Bearer %s", t.adminKey)
	if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expected)) != 1 {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

// HandleList handles GET /_sb/api/traffic/exchanges?hostname=<hostname>&limit=<n>&offset=<n>
// It returns historical exchanges from the cacher.
func (t *TrafficAPI) HandleList(w http.ResponseWriter, r *http.Request) {
	if !t.authenticate(w, r) {
		return
	}

	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		http.Error(w, `{"error":"hostname query parameter is required"}`, http.StatusBadRequest)
		return
	}

	opts := capture.ListOptions{}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}
	if opts.Limit == 0 || opts.Limit > 1000 {
		opts.Limit = 100 // Default limit
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			opts.Offset = offset
		}
	}

	exchanges, err := t.captureManager.List(r.Context(), hostname, opts)
	if err != nil {
		slog.Error("failed to list exchanges", "hostname", hostname, "error", err)
		http.Error(w, `{"error":"failed to retrieve exchanges"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := struct {
		Exchanges []*reqctx.Exchange `json:"exchanges"`
		Count     int                `json:"count"`
		Hostname  string             `json:"hostname"`
		Limit     int                `json:"limit"`
		Offset    int                `json:"offset"`
	}{
		Exchanges: exchanges,
		Count:     len(exchanges),
		Hostname:  hostname,
		Limit:     opts.Limit,
		Offset:    opts.Offset,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode exchanges response", "error", err)
	}
}

// HandleGet handles GET /_sb/api/traffic/exchanges/<id>?hostname=<hostname>
// It returns a single exchange by ID.
func (t *TrafficAPI) HandleGet(w http.ResponseWriter, r *http.Request) {
	if !t.authenticate(w, r) {
		return
	}

	hostname := r.URL.Query().Get("hostname")
	exchangeID := r.URL.Query().Get("id")

	if hostname == "" || exchangeID == "" {
		http.Error(w, `{"error":"hostname and id query parameters are required"}`, http.StatusBadRequest)
		return
	}

	exchange, err := t.captureManager.Get(r.Context(), hostname, exchangeID)
	if err != nil {
		http.Error(w, `{"error":"exchange not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(exchange); err != nil {
		slog.Error("failed to encode exchange response", "error", err)
	}
}

// HandleStream handles GET /_sb/api/traffic/stream?hostname=<hostname>
// It establishes an SSE connection and streams real-time exchanges from the messenger.
func (t *TrafficAPI) HandleStream(w http.ResponseWriter, r *http.Request) {
	if !t.authenticate(w, r) {
		return
	}

	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		http.Error(w, `{"error":"hostname query parameter is required"}`, http.StatusBadRequest)
		return
	}

	// Create SSE connection
	conn, err := handler.NewSSEConnection(w, r)
	if err != nil {
		http.Error(w, `{"error":"streaming not supported"}`, http.StatusInternalServerError)
		return
	}

	slog.Info("SSE traffic stream connected", "hostname", hostname)

	// Send initial comment
	if err := conn.SendComment("connected to traffic stream for " + hostname); err != nil {
		slog.Error("failed to send SSE comment", "error", err)
		return
	}

	// Subscribe to exchanges for this hostname.
	// Subscribe starts a background goroutine and returns immediately (nil on success).
	// The SSE connection stays open until the client disconnects (ctx cancelled).
	ctx := r.Context()

	if err := t.captureManager.Subscribe(ctx, hostname, func(subCtx context.Context, exchange *reqctx.Exchange) error {
		_ = subCtx
		data, err := json.Marshal(exchange)
		if err != nil {
			return nil // Skip malformed exchanges
		}

		return conn.SendEvent(handler.SSEEvent{
			ID:    exchange.ID,
			Event: "exchange",
			Data:  string(data),
		})
	}); err != nil {
		slog.Error("failed to subscribe to traffic stream", "hostname", hostname, "error", err)
		http.Error(w, `{"error":"failed to subscribe"}`, http.StatusInternalServerError)
		return
	}

	// Start heartbeat
	go handler.StartHeartbeat(ctx, conn, 30*time.Second)

	// Block until client disconnects
	<-ctx.Done()
	slog.Info("SSE traffic stream disconnected", "hostname", hostname)

	// Unsubscribe on disconnect
	if err := t.captureManager.Unsubscribe(r.Context(), hostname); err != nil {
		slog.Debug("failed to unsubscribe from traffic stream", "hostname", hostname, "error", err)
	}

	conn.Close()
}

// HandleMetrics handles GET /_sb/api/traffic/metrics
// It returns capture metrics.
func (t *TrafficAPI) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if !t.authenticate(w, r) {
		return
	}

	metrics := t.captureManager.Metrics()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		slog.Error("failed to encode capture metrics", "error", err)
	}
}
