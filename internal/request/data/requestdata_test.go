package requestdata

import (
	"testing"
	"time"
)

// TestParseRequestID tests the request ID parsing function
func TestParseRequestID(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
		wantID    string
		wantLevel int
		wantErr   error
	}{
		{
			name:      "valid request ID",
			requestID: "abc123:1",
			wantID:    "abc123",
			wantLevel: 1,
			wantErr:   nil,
		},
		{
			name:      "valid UUID request ID",
			requestID: "550e8400-e29b-41d4-a716-446655440000:5",
			wantID:    "550e8400-e29b-41d4-a716-446655440000",
			wantLevel: 5,
			wantErr:   nil,
		},
		{
			name:      "level zero",
			requestID: "test-id:0",
			wantID:    "test-id",
			wantLevel: 0,
			wantErr:   nil,
		},
		{
			name:      "high level number",
			requestID: "test:999",
			wantID:    "test",
			wantLevel: 999,
			wantErr:   nil,
		},
		{
			name:      "missing level",
			requestID: "abc123",
			wantID:    "",
			wantLevel: 0,
			wantErr:   ErrInvalidRequestID,
		},
		{
			name:      "empty string",
			requestID: "",
			wantID:    "",
			wantLevel: 0,
			wantErr:   ErrInvalidRequestID,
		},
		{
			name:      "invalid level (not a number)",
			requestID: "abc123:xyz",
			wantID:    "",
			wantLevel: 0,
			wantErr:   ErrInvalidRequestID,
		},
		{
			name:      "too many colons",
			requestID: "abc:123:456",
			wantID:    "",
			wantLevel: 0,
			wantErr:   ErrInvalidRequestID,
		},
		{
			name:      "negative level",
			requestID: "abc:-1",
			wantID:    "abc",
			wantLevel: -1,
			wantErr:   nil, // negative levels are allowed by the implementation
		},
		{
			name:      "colon only",
			requestID: ":",
			wantID:    "",
			wantLevel: 0,
			wantErr:   ErrInvalidRequestID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotLevel, gotErr := ParseRequestID(tt.requestID)

			if gotErr != tt.wantErr {
				t.Errorf("ParseRequestID() error = %v, want %v", gotErr, tt.wantErr)
				return
			}

			if gotErr == nil {
				if gotID != tt.wantID {
					t.Errorf("ParseRequestID() ID = %v, want %v", gotID, tt.wantID)
				}
				if gotLevel != tt.wantLevel {
					t.Errorf("ParseRequestID() level = %v, want %v", gotLevel, tt.wantLevel)
				}
			}
		})
	}
}

// TestNewRequestData tests the request data creation function
func TestNewRequestData(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		depth int
	}{
		{
			name:  "basic request data",
			id:    "test-id-123",
			depth: 1,
		},
		{
			name:  "UUID request data",
			id:    "550e8400-e29b-41d4-a716-446655440000",
			depth: 3,
		},
		{
			name:  "zero depth",
			id:    "zero-depth",
			depth: 0,
		},
		{
			name:  "empty ID",
			id:    "",
			depth: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			rd := NewRequestData(tt.id, tt.depth)
			after := time.Now()

			if rd == nil {
				t.Fatal("NewRequestData returned nil")
			}

			if rd.ID != tt.id {
				t.Errorf("ID = %v, want %v", rd.ID, tt.id)
			}

			if rd.Depth != tt.depth {
				t.Errorf("Depth = %v, want %v", rd.Depth, tt.depth)
			}

			if rd.Debug != false {
				t.Error("Debug should be false by default")
			}

			// DebugHeaders, Data, Visited are nil until first use (lazy init)
			if rd.DebugHeaders != nil {
				t.Error("DebugHeaders should be nil (lazy init)")
			}

			if rd.Data != nil {
				t.Error("Data should be nil (lazy init)")
			}

			if rd.Visited != nil {
				t.Error("Visited should be nil (lazy init)")
			}

			if rd.SessionData != nil {
				t.Error("SessionData should be nil by default")
			}

			if rd.Location != nil {
				t.Error("Location should be nil by default")
			}

			if rd.UserAgent != nil {
				t.Error("UserAgent should be nil by default")
			}

			if rd.Fingerprint != nil {
				t.Error("Fingerprint should be nil by default")
			}

			// Check StartTime is set correctly
			if rd.StartTime.Before(before) || rd.StartTime.After(after) {
				t.Errorf("StartTime should be between %v and %v, got %v", before, after, rd.StartTime)
			}
		})
	}
}

// TestNewRequestDataInitialization tests that all fields are properly initialized
func TestNewRequestDataInitialization(t *testing.T) {
	rd := NewRequestData("test-id", 1)

	// Test lazy initialization via helper methods
	rd.AddDebugHeader("test-header", "test-value")
	if rd.DebugHeaders["test-header"] != "test-value" {
		t.Error("DebugHeaders map should be usable after AddDebugHeader")
	}

	rd.SetData("test-key", "test-value")
	if rd.Data["test-key"] != "test-value" {
		t.Error("Data map should be usable after SetData")
	}

	// Visited starts nil (lazy init)
	if len(rd.Visited) != 0 {
		t.Error("Visited slice should start empty")
	}
}

// BenchmarkParseRequestID benchmarks request ID parsing
func BenchmarkParseRequestID(b *testing.B) {
	b.ReportAllocs()
	requestID := "550e8400-e29b-41d4-a716-446655440000:5"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseRequestID(requestID)
	}
}

// BenchmarkNewRequestData benchmarks request data creation
func BenchmarkNewRequestData(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewRequestData("test-id-123", 1)
	}
}
