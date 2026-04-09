package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func sampleEvents() []AuditEvent {
	return []AuditEvent{
		{
			ID:          "evt-001",
			Timestamp:   time.Date(2026, 3, 13, 10, 0, 0, 0, time.UTC),
			WorkspaceID: "ws-abc",
			Type:        KeyCreated,
			ActorID:     "user-1",
			ActorType:   "user",
			TargetType:  "key",
			TargetID:    "key-1",
			Details: map[string]any{
				"model":    "gpt-4",
				"messages": []string{"hello", "world"},
				"content":  "secret prompt",
			},
			IPAddress: "10.0.0.1",
			UserAgent: "test-agent/1.0",
		},
		{
			ID:          "evt-002",
			Timestamp:   time.Date(2026, 3, 13, 11, 0, 0, 0, time.UTC),
			WorkspaceID: "ws-abc",
			Type:        AccessDenied,
			ActorID:     "user-2",
			ActorType:   "api",
			Details: map[string]any{
				"reason":   "rate_limited",
				"prompt":   "generate something",
				"response": "error: rate limited",
				"model_id": "claude-3",
			},
		},
	}
}

func TestJSONLExporter(t *testing.T) {
	tests := []struct {
		name        string
		events      []AuditEvent
		config      *ExportConfig
		wantRecords int
		checkOutput func(t *testing.T, data []byte)
	}{
		{
			name:        "basic JSONL generation",
			events:      sampleEvents(),
			config:      &ExportConfig{Format: "jsonl", PrivacyMode: "full"},
			wantRecords: 2,
			checkOutput: func(t *testing.T, data []byte) {
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				if len(lines) != 2 {
					t.Errorf("got %d lines, want 2", len(lines))
				}
				// Each line should be valid JSON.
				for i, line := range lines {
					var ev AuditEvent
					if err := json.Unmarshal([]byte(line), &ev); err != nil {
						t.Errorf("line %d: invalid JSON: %v", i, err)
					}
				}
			},
		},
		{
			name:        "privacy metadata mode strips messages",
			events:      sampleEvents(),
			config:      &ExportConfig{Format: "jsonl", PrivacyMode: "metadata"},
			wantRecords: 2,
			checkOutput: func(t *testing.T, data []byte) {
				s := string(data)
				if strings.Contains(s, "hello") {
					t.Error("metadata mode should strip messages")
				}
				if strings.Contains(s, "secret prompt") {
					t.Error("metadata mode should strip content")
				}
				if strings.Contains(s, "generate something") {
					t.Error("metadata mode should strip prompt")
				}
				// model should still be present.
				if !strings.Contains(s, "gpt-4") {
					t.Error("metadata mode should preserve model")
				}
			},
		},
		{
			name:        "privacy minimal mode strips model and messages",
			events:      sampleEvents(),
			config:      &ExportConfig{Format: "jsonl", PrivacyMode: "minimal"},
			wantRecords: 2,
			checkOutput: func(t *testing.T, data []byte) {
				s := string(data)
				if strings.Contains(s, "gpt-4") {
					t.Error("minimal mode should strip model")
				}
				if strings.Contains(s, "claude-3") {
					t.Error("minimal mode should strip model_id")
				}
				if strings.Contains(s, "hello") {
					t.Error("minimal mode should strip messages")
				}
				// Non-sensitive fields should remain.
				if !strings.Contains(s, "rate_limited") {
					t.Error("minimal mode should preserve reason")
				}
			},
		},
		{
			name:        "empty events",
			events:      []AuditEvent{},
			config:      &ExportConfig{Format: "jsonl", PrivacyMode: "full"},
			wantRecords: 0,
			checkOutput: func(t *testing.T, data []byte) {
				if len(data) != 0 {
					t.Errorf("expected empty output for no events, got %d bytes", len(data))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := encodeJSONL(tt.events, tt.config)
			if err != nil {
				t.Fatalf("encodeJSONL: %v", err)
			}
			tt.checkOutput(t, data)

			// Also test via the JSONLExporter interface.
			exp := NewJSONLExporter()
			result, err := exp.Export(context.Background(), tt.events, tt.config)
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			if result.RecordCount != tt.wantRecords {
				t.Errorf("RecordCount = %d, want %d", result.RecordCount, tt.wantRecords)
			}
		})
	}
}

func TestJSONLExporter_Gzip(t *testing.T) {
	events := sampleEvents()
	config := &ExportConfig{
		Format:       "jsonl",
		PrivacyMode:  "full",
		CompressGzip: true,
	}

	data, err := encodeJSONL(events, config)
	if err != nil {
		t.Fatalf("encodeJSONL with gzip: %v", err)
	}

	// Verify it is valid gzip.
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()

	decompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(decompressed)), "\n")
	if len(lines) != 2 {
		t.Errorf("decompressed lines = %d, want 2", len(lines))
	}
}

func TestLocalExporter(t *testing.T) {
	tmpDir := t.TempDir()
	events := sampleEvents()
	config := &ExportConfig{
		Format:      "jsonl",
		Prefix:      tmpDir,
		WorkspaceID: "ws-test",
		PrivacyMode: "full",
	}

	exp := NewLocalExporter()
	result, err := exp.Export(context.Background(), events, config)
	if err != nil {
		t.Fatalf("LocalExporter.Export: %v", err)
	}

	if result.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2", result.RecordCount)
	}
	if result.BytesWritten <= 0 {
		t.Errorf("BytesWritten = %d, want > 0", result.BytesWritten)
	}

	// Verify file exists.
	date := time.Now().Format("2006-01-02")
	expectedPath := filepath.Join(tmpDir, "ws-test", date+".jsonl")
	info, err := os.Stat(expectedPath)
	if err != nil {
		t.Fatalf("stat export file: %v", err)
	}
	if info.Size() != result.BytesWritten {
		t.Errorf("file size = %d, result.BytesWritten = %d", info.Size(), result.BytesWritten)
	}

	// Verify content is valid JSONL.
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Errorf("file lines = %d, want 2", len(lines))
	}
}

func TestLocalExporter_Gzip(t *testing.T) {
	tmpDir := t.TempDir()
	events := sampleEvents()
	config := &ExportConfig{
		Format:       "jsonl",
		Prefix:       tmpDir,
		WorkspaceID:  "ws-gz",
		PrivacyMode:  "full",
		CompressGzip: true,
	}

	exp := NewLocalExporter()
	result, err := exp.Export(context.Background(), events, config)
	if err != nil {
		t.Fatalf("LocalExporter.Export gzip: %v", err)
	}

	date := time.Now().Format("2006-01-02")
	expectedPath := filepath.Join(tmpDir, "ws-gz", date+".jsonl.gz")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Fatalf("gzip file not found: %v", err)
	}
	if result.BytesWritten <= 0 {
		t.Errorf("BytesWritten = %d, want > 0", result.BytesWritten)
	}
}

func TestS3Exporter_Stub(t *testing.T) {
	exp := NewS3Exporter()
	result, err := exp.Export(context.Background(), sampleEvents(), &ExportConfig{
		Bucket:      "my-bucket",
		Prefix:      "audit-logs",
		PrivacyMode: "full",
	})
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("S3Exporter error = %v, want ErrNotConfigured", err)
	}
	if result == nil {
		t.Fatal("S3Exporter result is nil, want non-nil with stats")
	}
	if result.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2", result.RecordCount)
	}
	if !strings.Contains(result.Destination, "s3://my-bucket") {
		t.Errorf("Destination = %q, want s3://my-bucket prefix", result.Destination)
	}
}

func TestGCSExporter_Stub(t *testing.T) {
	exp := NewGCSExporter()
	result, err := exp.Export(context.Background(), sampleEvents(), &ExportConfig{
		Bucket:      "my-gcs-bucket",
		Prefix:      "audit",
		PrivacyMode: "full",
	})
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("GCSExporter error = %v, want ErrNotConfigured", err)
	}
	if result == nil {
		t.Fatal("GCSExporter result is nil")
	}
	if !strings.Contains(result.Destination, "gs://my-gcs-bucket") {
		t.Errorf("Destination = %q, want gs://my-gcs-bucket prefix", result.Destination)
	}
}

func TestNewExporter_Factory(t *testing.T) {
	tests := []struct {
		name    string
		dest    string
		wantErr bool
	}{
		{name: "local", dest: "local"},
		{name: "s3", dest: "s3"},
		{name: "gcs", dest: "gcs"},
		{name: "unknown", dest: "azure", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp, err := NewExporter(tt.dest)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error for unknown destination")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewExporter(%q): %v", tt.dest, err)
			}
			if exp == nil {
				t.Error("expected non-nil exporter")
			}
		})
	}
}

func TestExportResult_Stats(t *testing.T) {
	exp := NewJSONLExporter()
	events := sampleEvents()
	result, err := exp.Export(context.Background(), events, &ExportConfig{
		PrivacyMode: "full",
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if result.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2", result.RecordCount)
	}
	if result.BytesWritten <= 0 {
		t.Errorf("BytesWritten = %d, want > 0", result.BytesWritten)
	}
	if result.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", result.Duration)
	}
}
