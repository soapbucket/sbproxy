package audit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

// AuditLogger is the interface for audit event storage and retrieval.
type AuditLogger interface {
	// Log writes an immutable audit event.
	Log(ctx context.Context, event AuditEvent) error

	// Query retrieves events matching the given filters.
	Query(ctx context.Context, query AuditQuery) ([]AuditEvent, error)

	// Export returns events in the specified format ("json" or "csv").
	Export(ctx context.Context, query AuditQuery, format string) (io.Reader, error)
}

const maxEvents = 100_000

// MemoryAuditLogger stores audit events in an in-memory circular buffer.
// Events are immutable once written (append-only).
type MemoryAuditLogger struct {
	events []AuditEvent
	head   int  // next write position
	full   bool // whether the buffer has wrapped
	mu     sync.RWMutex
}

// NewMemoryAuditLogger creates a new in-memory audit logger with a circular buffer.
func NewMemoryAuditLogger() *MemoryAuditLogger {
	return &MemoryAuditLogger{
		events: make([]AuditEvent, maxEvents),
	}
}

// Log appends an audit event to the circular buffer.
func (m *MemoryAuditLogger) Log(_ context.Context, event AuditEvent) error {
	if event.ID == "" {
		return fmt.Errorf("audit event ID is required")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.events[m.head] = event
	m.head++
	if m.head >= maxEvents {
		m.head = 0
		m.full = true
	}

	return nil
}

// Len returns the number of events currently stored.
func (m *MemoryAuditLogger) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.full {
		return maxEvents
	}
	return m.head
}

// Query retrieves events matching the given filters.
// Events are returned in reverse chronological order (newest first).
func (m *MemoryAuditLogger) Query(_ context.Context, query AuditQuery) ([]AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Build type lookup set for efficient filtering.
	typeSet := make(map[AuditEventType]bool, len(query.Types))
	for _, t := range query.Types {
		typeSet[t] = true
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}

	// Iterate backwards from newest to oldest.
	count := maxEvents
	if !m.full {
		count = m.head
	}

	var results []AuditEvent
	skipped := 0

	for i := 0; i < count; i++ {
		idx := m.head - 1 - i
		if idx < 0 {
			idx += maxEvents
		}

		ev := m.events[idx]
		if ev.ID == "" {
			continue // empty slot
		}

		if !m.matches(ev, query, typeSet) {
			continue
		}

		if skipped < query.Offset {
			skipped++
			continue
		}

		results = append(results, ev)
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

func (m *MemoryAuditLogger) matches(ev AuditEvent, q AuditQuery, typeSet map[AuditEventType]bool) bool {
	if q.WorkspaceID != "" && ev.WorkspaceID != q.WorkspaceID {
		return false
	}
	if len(typeSet) > 0 && !typeSet[ev.Type] {
		return false
	}
	if q.ActorID != "" && ev.ActorID != q.ActorID {
		return false
	}
	if q.TargetID != "" && ev.TargetID != q.TargetID {
		return false
	}
	if !q.StartTime.IsZero() && ev.Timestamp.Before(q.StartTime) {
		return false
	}
	if !q.EndTime.IsZero() && ev.Timestamp.After(q.EndTime) {
		return false
	}
	return true
}

// Export returns events in the specified format.
// Supported formats: "json", "csv".
func (m *MemoryAuditLogger) Export(ctx context.Context, query AuditQuery, format string) (io.Reader, error) {
	events, err := m.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		data, err := json.Marshal(events)
		if err != nil {
			return nil, fmt.Errorf("marshal audit events: %w", err)
		}
		return strings.NewReader(string(data)), nil

	case "csv":
		var b strings.Builder
		b.WriteString("id,timestamp,workspace_id,type,actor_id,actor_type,target_type,target_id,ip_address,user_agent\n")
		for _, ev := range events {
			fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
				csvEscape(ev.ID),
				ev.Timestamp.Format(time.RFC3339),
				csvEscape(ev.WorkspaceID),
				csvEscape(string(ev.Type)),
				csvEscape(ev.ActorID),
				csvEscape(ev.ActorType),
				csvEscape(ev.TargetType),
				csvEscape(ev.TargetID),
				csvEscape(ev.IPAddress),
				csvEscape(ev.UserAgent),
			)
		}
		return strings.NewReader(b.String()), nil

	default:
		return nil, fmt.Errorf("unsupported export format: %q", format)
	}
}

// csvEscape wraps a value in quotes if it contains commas or quotes.
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
