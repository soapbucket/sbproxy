package audit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMemoryAuditLogger_Log(t *testing.T) {
	tests := []struct {
		name    string
		event   AuditEvent
		wantErr bool
	}{
		{
			name: "valid event",
			event: AuditEvent{
				ID:          "evt-001",
				WorkspaceID: "ws-1",
				Type:        KeyCreated,
				ActorID:     "user-1",
				ActorType:   "user",
			},
			wantErr: false,
		},
		{
			name: "event with all fields",
			event: AuditEvent{
				ID:          "evt-002",
				Timestamp:   time.Now(),
				WorkspaceID: "ws-1",
				Type:        PolicyModified,
				ActorID:     "admin-1",
				ActorType:   "user",
				TargetType:  "policy",
				TargetID:    "pol-1",
				Details:     map[string]any{"action": "update"},
				IPAddress:   "192.168.1.1",
				UserAgent:   "test-agent/1.0",
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			event: AuditEvent{
				WorkspaceID: "ws-1",
				Type:        KeyCreated,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewMemoryAuditLogger()
			err := logger.Log(context.Background(), tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("Log() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMemoryAuditLogger_Query(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()
	now := time.Now()

	// Seed events.
	events := []AuditEvent{
		{ID: "e1", Timestamp: now.Add(-3 * time.Hour), WorkspaceID: "ws-1", Type: KeyCreated, ActorID: "user-1", ActorType: "user"},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), WorkspaceID: "ws-1", Type: PolicyModified, ActorID: "admin-1", ActorType: "user", TargetType: "policy", TargetID: "pol-1"},
		{ID: "e3", Timestamp: now.Add(-1 * time.Hour), WorkspaceID: "ws-2", Type: AccessDenied, ActorID: "user-2", ActorType: "api"},
		{ID: "e4", Timestamp: now, WorkspaceID: "ws-1", Type: KeyRevoked, ActorID: "admin-1", ActorType: "user", TargetType: "key", TargetID: "key-1"},
	}
	for _, ev := range events {
		if err := logger.Log(ctx, ev); err != nil {
			t.Fatalf("seed log: %v", err)
		}
	}

	tests := []struct {
		name    string
		query   AuditQuery
		wantIDs []string
	}{
		{
			name:    "all events",
			query:   AuditQuery{Limit: 100},
			wantIDs: []string{"e4", "e3", "e2", "e1"}, // reverse chronological
		},
		{
			name:    "filter by workspace",
			query:   AuditQuery{WorkspaceID: "ws-1", Limit: 100},
			wantIDs: []string{"e4", "e2", "e1"},
		},
		{
			name:    "filter by type",
			query:   AuditQuery{Types: []AuditEventType{KeyCreated, KeyRevoked}, Limit: 100},
			wantIDs: []string{"e4", "e1"},
		},
		{
			name:    "filter by actor",
			query:   AuditQuery{ActorID: "admin-1", Limit: 100},
			wantIDs: []string{"e4", "e2"},
		},
		{
			name:    "filter by target",
			query:   AuditQuery{TargetID: "pol-1", Limit: 100},
			wantIDs: []string{"e2"},
		},
		{
			name:    "filter by time range",
			query:   AuditQuery{StartTime: now.Add(-90 * time.Minute), EndTime: now.Add(-30 * time.Minute), Limit: 100},
			wantIDs: []string{"e3"},
		},
		{
			name:    "limit results",
			query:   AuditQuery{Limit: 2},
			wantIDs: []string{"e4", "e3"},
		},
		{
			name:    "offset results",
			query:   AuditQuery{Offset: 2, Limit: 100},
			wantIDs: []string{"e2", "e1"},
		},
		{
			name:    "combined workspace and type filter",
			query:   AuditQuery{WorkspaceID: "ws-1", Types: []AuditEventType{KeyCreated}, Limit: 100},
			wantIDs: []string{"e1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := logger.Query(ctx, tt.query)
			if err != nil {
				t.Fatalf("Query() error: %v", err)
			}

			if len(results) != len(tt.wantIDs) {
				t.Fatalf("got %d results, want %d", len(results), len(tt.wantIDs))
			}

			for i, want := range tt.wantIDs {
				if results[i].ID != want {
					t.Errorf("result[%d].ID = %q, want %q", i, results[i].ID, want)
				}
			}
		})
	}
}

func TestMemoryAuditLogger_CircularBuffer(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	// Write more than maxEvents to verify circular behavior.
	totalEvents := maxEvents + 500
	for i := 0; i < totalEvents; i++ {
		ev := AuditEvent{
			ID:          fmt.Sprintf("evt-%06d", i),
			Timestamp:   time.Now().Add(time.Duration(i) * time.Millisecond),
			WorkspaceID: "ws-1",
			Type:        KeyCreated,
			ActorID:     "user-1",
			ActorType:   "user",
		}
		if err := logger.Log(ctx, ev); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}

	// Should have exactly maxEvents.
	if logger.Len() != maxEvents {
		t.Errorf("Len() = %d, want %d", logger.Len(), maxEvents)
	}

	// The oldest event should be overwritten.
	results, err := logger.Query(ctx, AuditQuery{Limit: 1, Offset: maxEvents - 1})
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 oldest result, got %d", len(results))
	}
	// The oldest event should be evt-000500 (the first 500 were overwritten).
	wantOldestID := fmt.Sprintf("evt-%06d", 500)
	if results[0].ID != wantOldestID {
		t.Errorf("oldest event ID = %q, want %q", results[0].ID, wantOldestID)
	}

	// The newest event should be the last one written.
	newest, err := logger.Query(ctx, AuditQuery{Limit: 1})
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}
	wantNewestID := fmt.Sprintf("evt-%06d", totalEvents-1)
	if newest[0].ID != wantNewestID {
		t.Errorf("newest event ID = %q, want %q", newest[0].ID, wantNewestID)
	}
}

func TestMemoryAuditLogger_Export_JSON(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	_ = logger.Log(ctx, AuditEvent{
		ID:          "evt-1",
		Timestamp:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		WorkspaceID: "ws-1",
		Type:        KeyCreated,
		ActorID:     "user-1",
		ActorType:   "user",
	})

	reader, err := logger.Export(ctx, AuditQuery{Limit: 100}, "json")
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	body := string(data)
	if !strings.Contains(body, "evt-1") {
		t.Error("JSON export should contain event ID")
	}
	if !strings.Contains(body, "key.created") {
		t.Error("JSON export should contain event type")
	}
}

func TestMemoryAuditLogger_Export_CSV(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	_ = logger.Log(ctx, AuditEvent{
		ID:          "evt-csv-1",
		Timestamp:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		WorkspaceID: "ws-1",
		Type:        PolicyModified,
		ActorID:     "admin-1",
		ActorType:   "user",
		TargetType:  "policy",
		TargetID:    "pol-1",
		IPAddress:   "10.0.0.1",
	})

	reader, err := logger.Export(ctx, AuditQuery{Limit: 100}, "csv")
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + 1 event), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "id,timestamp,") {
		t.Errorf("CSV header unexpected: %s", lines[0])
	}
	if !strings.Contains(lines[1], "evt-csv-1") {
		t.Errorf("CSV data should contain event ID, got: %s", lines[1])
	}
}

func TestMemoryAuditLogger_Export_UnsupportedFormat(t *testing.T) {
	logger := NewMemoryAuditLogger()
	_, err := logger.Export(context.Background(), AuditQuery{}, "xml")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestMemoryAuditLogger_TimestampAutoFill(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	before := time.Now()
	err := logger.Log(ctx, AuditEvent{
		ID:          "evt-auto",
		WorkspaceID: "ws-1",
		Type:        LoginAttempt,
		ActorID:     "user-1",
		ActorType:   "user",
	})
	if err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	after := time.Now()

	results, err := logger.Query(ctx, AuditQuery{Limit: 1})
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}

	ts := results[0].Timestamp
	if ts.Before(before) || ts.After(after) {
		t.Errorf("auto-filled timestamp %v not between %v and %v", ts, before, after)
	}
}
