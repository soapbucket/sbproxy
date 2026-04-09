package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	json "github.com/goccy/go-json"
)

// ErrNotConfigured is returned by stub exporters that require external SDKs.
var ErrNotConfigured = errors.New("exporter not configured: required SDK not available")

// ExportConfig defines parameters for an audit log export operation.
type ExportConfig struct {
	Format       string            `json:"format"`       // "jsonl" or "csv"
	Destination  string            `json:"destination"`   // "s3", "gcs", "local"
	Bucket       string            `json:"bucket"`        // bucket name for cloud destinations
	Prefix       string            `json:"prefix"`        // path prefix or local directory
	Region       string            `json:"region"`        // cloud region
	Credentials  map[string]string `json:"credentials"`   // destination-specific credentials
	StartTime    time.Time         `json:"start_time"`    // filter start
	EndTime      time.Time         `json:"end_time"`      // filter end
	WorkspaceID  string            `json:"workspace_id"`  // scope to workspace
	PrivacyMode  string            `json:"privacy_mode"`  // "full", "metadata", "minimal"
	CompressGzip bool              `json:"compress_gzip"` // gzip the output
}

// ExportResult contains stats from a completed export.
type ExportResult struct {
	RecordCount  int           `json:"record_count"`
	BytesWritten int64         `json:"bytes_written"`
	Duration     time.Duration `json:"duration"`
	Destination  string        `json:"destination"`
	Error        string        `json:"error,omitempty"`
}

// Exporter is the interface for audit log export backends.
type Exporter interface {
	Export(ctx context.Context, events []AuditEvent, config *ExportConfig) (*ExportResult, error)
}

// NewExporter creates an Exporter for the given destination.
func NewExporter(destination string) (Exporter, error) {
	switch destination {
	case "local":
		return NewLocalExporter(), nil
	case "s3":
		return NewS3Exporter(), nil
	case "gcs":
		return NewGCSExporter(), nil
	default:
		return nil, fmt.Errorf("unknown export destination: %q", destination)
	}
}

// applyPrivacyFilter returns a copy of the event with fields redacted
// according to the privacy mode.
func applyPrivacyFilter(event AuditEvent, mode string) AuditEvent {
	switch mode {
	case "metadata":
		// Strip message content from details, keep everything else.
		if event.Details != nil {
			filtered := make(map[string]any, len(event.Details))
			for k, v := range event.Details {
				if k == "messages" || k == "message" || k == "content" || k == "prompt" || k == "response" {
					continue
				}
				filtered[k] = v
			}
			event.Details = filtered
		}
	case "minimal":
		// Strip messages and model information.
		if event.Details != nil {
			filtered := make(map[string]any, len(event.Details))
			for k, v := range event.Details {
				switch k {
				case "messages", "message", "content", "prompt", "response", "model", "model_id":
					continue
				}
				filtered[k] = v
			}
			event.Details = filtered
		}
	}
	// "full" keeps everything.
	return event
}

// encodeJSONL encodes events as newline-delimited JSON, applying privacy
// filtering and optional gzip compression. It returns the encoded bytes.
func encodeJSONL(events []AuditEvent, config *ExportConfig) ([]byte, error) {
	var buf bytes.Buffer

	privacyMode := config.PrivacyMode
	if privacyMode == "" {
		privacyMode = "full"
	}

	for _, ev := range events {
		filtered := applyPrivacyFilter(ev, privacyMode)
		line, err := json.Marshal(filtered)
		if err != nil {
			return nil, fmt.Errorf("marshal event %s: %w", ev.ID, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	if config.CompressGzip {
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		if _, err := gz.Write(buf.Bytes()); err != nil {
			return nil, fmt.Errorf("gzip write: %w", err)
		}
		if err := gz.Close(); err != nil {
			return nil, fmt.Errorf("gzip close: %w", err)
		}
		return compressed.Bytes(), nil
	}

	return buf.Bytes(), nil
}

// JSONLExporter writes events as newline-delimited JSON to a bytes buffer.
type JSONLExporter struct{}

// NewJSONLExporter creates a new JSONLExporter.
func NewJSONLExporter() *JSONLExporter {
	return &JSONLExporter{}
}

// Export encodes events as JSONL and returns the result.
func (e *JSONLExporter) Export(_ context.Context, events []AuditEvent, config *ExportConfig) (*ExportResult, error) {
	start := time.Now()

	data, err := encodeJSONL(events, config)
	if err != nil {
		return nil, err
	}

	return &ExportResult{
		RecordCount:  len(events),
		BytesWritten: int64(len(data)),
		Duration:     time.Since(start),
		Destination:  "memory",
	}, nil
}

// LocalExporter writes JSONL audit logs to the local filesystem.
type LocalExporter struct{}

// NewLocalExporter creates a new LocalExporter.
func NewLocalExporter() *LocalExporter {
	return &LocalExporter{}
}

// Export writes events as JSONL to {config.Prefix}/{workspaceID}/{date}.jsonl.
func (e *LocalExporter) Export(_ context.Context, events []AuditEvent, config *ExportConfig) (*ExportResult, error) {
	start := time.Now()

	data, err := encodeJSONL(events, config)
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(config.Prefix, config.WorkspaceID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create export directory: %w", err)
	}

	date := time.Now().Format("2006-01-02")
	ext := ".jsonl"
	if config.CompressGzip {
		ext = ".jsonl.gz"
	}
	filename := filepath.Join(dir, date+ext)

	if err := os.WriteFile(filename, data, 0o640); err != nil {
		return nil, fmt.Errorf("write export file: %w", err)
	}

	return &ExportResult{
		RecordCount:  len(events),
		BytesWritten: int64(len(data)),
		Duration:     time.Since(start),
		Destination:  filename,
	}, nil
}

// S3Exporter is a stub exporter for Amazon S3.
// It requires the AWS SDK which may not be linked in all builds.
type S3Exporter struct{}

// NewS3Exporter creates a new S3Exporter.
func NewS3Exporter() *S3Exporter {
	return &S3Exporter{}
}

// Export would upload events to S3. This is a stub that returns
// ErrNotConfigured until the AWS SDK upload path is wired in.
func (e *S3Exporter) Export(_ context.Context, events []AuditEvent, config *ExportConfig) (*ExportResult, error) {
	start := time.Now()

	// Encode the data so we can report accurate byte counts even in stub mode.
	data, err := encodeJSONL(events, config)
	if err != nil {
		return nil, err
	}

	// Stub: the actual S3 PutObject call would go here.
	// key := fmt.Sprintf("%s/%s/%s.jsonl", config.Prefix, config.WorkspaceID, time.Now().Format("2006-01-02"))
	// _, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
	//     Bucket: &config.Bucket,
	//     Key:    &key,
	//     Body:   bytes.NewReader(data),
	// })

	return &ExportResult{
		RecordCount:  len(events),
		BytesWritten: int64(len(data)),
		Duration:     time.Since(start),
		Destination:  fmt.Sprintf("s3://%s/%s", config.Bucket, config.Prefix),
		Error:        ErrNotConfigured.Error(),
	}, ErrNotConfigured
}

// GCSExporter is a stub exporter for Google Cloud Storage.
// It requires the GCS SDK which may not be linked in all builds.
type GCSExporter struct{}

// NewGCSExporter creates a new GCSExporter.
func NewGCSExporter() *GCSExporter {
	return &GCSExporter{}
}

// Export would upload events to GCS. This is a stub that returns
// ErrNotConfigured until the GCS SDK upload path is wired in.
func (e *GCSExporter) Export(_ context.Context, events []AuditEvent, config *ExportConfig) (*ExportResult, error) {
	start := time.Now()

	data, err := encodeJSONL(events, config)
	if err != nil {
		return nil, err
	}

	// Stub: the actual GCS write call would go here.
	// w := gcsClient.Bucket(config.Bucket).Object(key).NewWriter(ctx)
	// _, err = w.Write(data)
	// err = w.Close()

	return &ExportResult{
		RecordCount:  len(events),
		BytesWritten: int64(len(data)),
		Duration:     time.Since(start),
		Destination:  fmt.Sprintf("gs://%s/%s", config.Bucket, config.Prefix),
		Error:        ErrNotConfigured.Error(),
	}, ErrNotConfigured
}
