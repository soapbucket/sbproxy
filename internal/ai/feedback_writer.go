package ai

import (
	"context"
	"log/slog"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
)

// ClickHouse DDL for the ai_feedback table:
//
//	CREATE TABLE IF NOT EXISTS ai_feedback (
//	    id String,
//	    request_id String,
//	    session_id String,
//	    workspace_id String,
//	    model String,
//	    rating Int8,
//	    comment String,
//	    tags Array(String),
//	    metadata Map(String, String),
//	    created_at DateTime DEFAULT now()
//	) ENGINE = MergeTree()
//	ORDER BY (workspace_id, created_at)

// LogFeedbackWriter writes feedback as structured log entries. It is always
// available and serves as the default writer when no other writer is configured.
type LogFeedbackWriter struct{}

// Write logs the feedback record via slog.
func (w *LogFeedbackWriter) Write(_ context.Context, fb *FeedbackRecord) error {
	attrs := []any{
		"feedback_id", fb.ID,
		"request_id", fb.RequestID,
		"workspace_id", fb.WorkspaceID,
		"rating", fb.Rating,
	}
	if fb.SessionID != "" {
		attrs = append(attrs, "session_id", fb.SessionID)
	}
	if fb.Model != "" {
		attrs = append(attrs, "model", fb.Model)
	}
	if fb.Comment != "" {
		attrs = append(attrs, "comment", fb.Comment)
	}
	if len(fb.Tags) > 0 {
		attrs = append(attrs, "tags", fb.Tags)
	}
	if len(fb.Metadata) > 0 {
		attrs = append(attrs, "metadata", fb.Metadata)
	}
	slog.Info("ai feedback received", attrs...)
	return nil
}

// ClickHouseFeedbackWriter writes feedback records to a ClickHouse ai_feedback table
// using the batching HTTP writer from the logging package.
type ClickHouseFeedbackWriter struct {
	chWriter *logging.ClickHouseHTTPWriter
}

// NewClickHouseFeedbackWriter creates a writer targeting the ai_feedback table.
func NewClickHouseFeedbackWriter(cfg logging.ClickHouseWriterConfig) (*ClickHouseFeedbackWriter, error) {
	cfg.Table = "ai_feedback"
	chWriter, err := logging.NewClickHouseHTTPWriter(cfg)
	if err != nil {
		return nil, err
	}
	return &ClickHouseFeedbackWriter{chWriter: chWriter}, nil
}

// Write serializes the feedback record and writes it to the ClickHouse buffer.
func (w *ClickHouseFeedbackWriter) Write(_ context.Context, fb *FeedbackRecord) error {
	data, err := json.Marshal(fb)
	if err != nil {
		slog.Error("feedback: failed to marshal record", "error", err, "feedback_id", fb.ID)
		return err
	}
	_, err = w.chWriter.Write(data)
	if err != nil {
		slog.Error("feedback: failed to write to clickhouse", "error", err, "feedback_id", fb.ID)
	}
	return err
}

// Close flushes remaining records and stops the writer.
func (w *ClickHouseFeedbackWriter) Close() error {
	return w.chWriter.Close()
}

// CompositeFeedbackWriter writes to multiple FeedbackWriters. All writers are
// called; the first error encountered is returned but does not prevent subsequent
// writers from executing.
type CompositeFeedbackWriter struct {
	Writers []FeedbackWriter
}

// Write sends the feedback record to every configured writer.
func (w *CompositeFeedbackWriter) Write(ctx context.Context, fb *FeedbackRecord) error {
	var firstErr error
	for _, writer := range w.Writers {
		if err := writer.Write(ctx, fb); err != nil {
			slog.Error("feedback: composite writer error", "error", err, "feedback_id", fb.ID)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
