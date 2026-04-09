package ai

import (
	"context"
	"fmt"
	"net/http"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"
)

// FeedbackRequest represents user feedback on an AI response.
type FeedbackRequest struct {
	RequestID   string            `json:"request_id"`
	SessionID   string            `json:"session_id,omitempty"`
	WorkspaceID string            `json:"workspace_id"`
	Model       string            `json:"model,omitempty"`
	Rating      int               `json:"rating"`
	Comment     string            `json:"comment,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// FeedbackResponse is the response returned after storing feedback.
type FeedbackResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// FeedbackRecord is the internal representation stored by writers.
// It extends FeedbackRequest with server-generated fields.
type FeedbackRecord struct {
	ID          string            `json:"id"`
	RequestID   string            `json:"request_id"`
	SessionID   string            `json:"session_id,omitempty"`
	WorkspaceID string            `json:"workspace_id"`
	Model       string            `json:"model,omitempty"`
	Rating      int               `json:"rating"`
	Comment     string            `json:"comment,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// FeedbackWriter persists feedback records.
type FeedbackWriter interface {
	Write(ctx context.Context, feedback *FeedbackRecord) error
}

// Validate checks that the feedback request has valid fields.
func (f *FeedbackRequest) Validate() error {
	if f.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if f.WorkspaceID == "" {
		return fmt.Errorf("workspace_id is required")
	}
	// Rating must be either thumbs (-1 or 1) or a 1-5 scale value.
	switch {
	case f.Rating == -1 || f.Rating == 1:
		// Thumbs down / thumbs up - valid.
	case f.Rating >= 2 && f.Rating <= 5:
		// 1-5 scale (1 already covered above) - valid.
	default:
		return fmt.Errorf("rating must be -1, 1, or 2-5")
	}
	return nil
}

// toRecord converts a FeedbackRequest to a FeedbackRecord with generated fields.
func (f *FeedbackRequest) toRecord() *FeedbackRecord {
	return &FeedbackRecord{
		ID:          uuid.New().String(),
		RequestID:   f.RequestID,
		SessionID:   f.SessionID,
		WorkspaceID: f.WorkspaceID,
		Model:       f.Model,
		Rating:      f.Rating,
		Comment:     f.Comment,
		Tags:        f.Tags,
		Metadata:    f.Metadata,
		CreatedAt:   time.Now().UTC(),
	}
}

// handleFeedback handles POST /v1/feedback requests.
func (h *Handler) handleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, 64*1024) // 64KB max
	defer body.Close()

	var fb FeedbackRequest
	if err := json.NewDecoder(body).Decode(&fb); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid feedback body: %v", err)))
		return
	}

	if err := fb.Validate(); err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	record := fb.toRecord()

	// Resolve writer: use configured writer or fall back to log writer.
	writer := h.config.FeedbackWriter
	if writer == nil {
		writer = &LogFeedbackWriter{}
	}

	// Write asynchronously so we don't block the response.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := writer.Write(ctx, record); err != nil {
			// Error is logged inside writers; nothing else to do here.
			_ = err
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(&FeedbackResponse{
		ID:        record.ID,
		Status:    "accepted",
		Timestamp: record.CreatedAt.Format(time.RFC3339),
	})
}
