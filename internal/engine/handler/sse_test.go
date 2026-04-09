package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSEConnection_SendEvent(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	event := SSEEvent{
		ID:    "123",
		Event: "message",
		Data:  "Hello World",
	}

	if err := conn.SendEvent(event); err != nil {
		t.Fatalf("failed to send event: %v", err)
	}

	result := w.Body.String()
	if !strings.Contains(result, "id: 123") {
		t.Error("event ID not found in output")
	}
	if !strings.Contains(result, "event: message") {
		t.Error("event type not found in output")
	}
	if !strings.Contains(result, "data: Hello World") {
		t.Error("event data not found in output")
	}
}

func TestSSEConnection_MultilineData(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	event := SSEEvent{
		Data: "Line 1\nLine 2\nLine 3",
	}

	if err := conn.SendEvent(event); err != nil {
		t.Fatalf("failed to send event: %v", err)
	}

	result := w.Body.String()
	lines := strings.Count(result, "data:")
	if lines != 3 {
		t.Errorf("expected 3 data lines, got %d", lines)
	}
}

func TestSSEConnection_SendComment(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	if err := conn.SendComment("heartbeat"); err != nil {
		t.Fatalf("failed to send comment: %v", err)
	}

	result := w.Body.String()
	if !strings.Contains(result, ": heartbeat") {
		t.Error("comment not found in output")
	}
}

func TestSSEConnection_LastEventID(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)
	r.Header.Set("Last-Event-ID", "456")

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	if conn.lastEventID != "456" {
		t.Errorf("expected last event ID 456, got %s", conn.lastEventID)
	}
}

func TestSSEConnection_Close(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	if conn.IsClosed() {
		t.Error("connection should not be closed initially")
	}

	conn.Close()

	if !conn.IsClosed() {
		t.Error("connection should be closed after Close()")
	}

	// Sending event to closed connection should fail
	event := SSEEvent{Data: "test"}
	if err := conn.SendEvent(event); err == nil {
		t.Error("expected error when sending to closed connection")
	}
}

func TestSSEConnection_Filter(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Add filter that only allows "important" events
	conn.AddFilter(func(event SSEEvent) bool {
		return event.Event == "important"
	})

	// This should be filtered out
	event1 := SSEEvent{Event: "normal", Data: "test1"}
	if err := conn.SendEvent(event1); err != nil {
		t.Fatalf("failed to send event: %v", err)
	}

	// This should pass through
	event2 := SSEEvent{Event: "important", Data: "test2"}
	if err := conn.SendEvent(event2); err != nil {
		t.Fatalf("failed to send event: %v", err)
	}

	result := w.Body.String()
	if strings.Contains(result, "test1") {
		t.Error("filtered event should not appear in output")
	}
	if !strings.Contains(result, "test2") {
		t.Error("non-filtered event should appear in output")
	}
}

func TestSSEConnectionManager(t *testing.T) {
	manager := NewSSEConnectionManager()

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/events", nil)
	conn1, _ := NewSSEConnection(w1, r1)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/events", nil)
	conn2, _ := NewSSEConnection(w2, r2)

	// Add connections
	manager.AddConnection("conn1", conn1)
	manager.AddConnection("conn2", conn2)

	if manager.Count() != 2 {
		t.Errorf("expected 2 connections, got %d", manager.Count())
	}

	// Broadcast event
	event := SSEEvent{Data: "broadcast test"}
	manager.Broadcast(event)

	if !strings.Contains(w1.Body.String(), "broadcast test") {
		t.Error("event not received by connection 1")
	}
	if !strings.Contains(w2.Body.String(), "broadcast test") {
		t.Error("event not received by connection 2")
	}

	// Remove connection
	manager.RemoveConnection("conn1")
	if manager.Count() != 1 {
		t.Errorf("expected 1 connection after removal, got %d", manager.Count())
	}

	// Close all
	manager.Close()
	if manager.Count() != 0 {
		t.Errorf("expected 0 connections after close, got %d", manager.Count())
	}
}

func TestSSEProxy(t *testing.T) {
	// Create upstream SSE server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		// Send a few events
		events := []string{
			"id: 1\ndata: event1\n\n",
			"id: 2\ndata: event2\n\n",
			"id: 3\ndata: event3\n\n",
		}

		for _, event := range events {
			w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	// Create downstream connection
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)
	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Proxy with timeout
	proxy := NewSSEProxy(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = proxy.Proxy(ctx, upstream.URL, conn)
	if err != nil && err != context.DeadlineExceeded {
		t.Fatalf("proxy failed: %v", err)
	}

	result := w.Body.String()
	if !strings.Contains(result, "event1") {
		t.Error("event1 not found in proxied output")
	}
	if !strings.Contains(result, "event2") {
		t.Error("event2 not found in proxied output")
	}
}

func TestCreateEventFilter(t *testing.T) {
	filter := CreateEventFilter("important")

	tests := []struct {
		event    SSEEvent
		expected bool
	}{
		{SSEEvent{Event: "important"}, true},
		{SSEEvent{Event: "normal"}, false},
		{SSEEvent{Event: ""}, false},
	}

	for _, tt := range tests {
		result := filter(tt.event)
		if result != tt.expected {
			t.Errorf("filter(%v) = %v, expected %v", tt.event.Event, result, tt.expected)
		}
	}
}

func TestCreateIDFilter(t *testing.T) {
	filter := CreateIDFilter("5")

	// Events before ID 5 should be filtered
	if filter(SSEEvent{ID: "1"}) {
		t.Error("event 1 should be filtered")
	}
	if filter(SSEEvent{ID: "5"}) {
		t.Error("event 5 should be filtered (it's the last seen)")
	}

	// Events after ID 5 should pass
	if !filter(SSEEvent{ID: "6"}) {
		t.Error("event 6 should not be filtered")
	}
	if !filter(SSEEvent{ID: "7"}) {
		t.Error("event 7 should not be filtered")
	}
}

func TestStartHeartbeat(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/events", nil)

	conn, err := NewSSEConnection(w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	// Start heartbeat every 100ms
	done := make(chan struct{})
	go func() {
		StartHeartbeat(ctx, conn, 100*time.Millisecond)
		close(done)
	}()
	<-done

	result := w.Body.String()
	count := strings.Count(result, "heartbeat")
	
	// Should have 2-3 heartbeats (100ms, 200ms, possibly 300ms)
	if count < 2 || count > 3 {
		t.Errorf("expected 2-3 heartbeats, got %d", count)
	}
}

