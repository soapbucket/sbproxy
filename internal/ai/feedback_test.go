package ai

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	json "github.com/goccy/go-json"
)

func TestFeedbackRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		fb      FeedbackRequest
		wantErr bool
	}{
		{
			name:    "valid thumbs up",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: 1},
			wantErr: false,
		},
		{
			name:    "valid thumbs down",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: -1},
			wantErr: false,
		},
		{
			name:    "valid 5-star",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: 5},
			wantErr: false,
		},
		{
			name:    "valid rating 3",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: 3},
			wantErr: false,
		},
		{
			name:    "missing request_id",
			fb:      FeedbackRequest{WorkspaceID: "ws-1", Rating: 1},
			wantErr: true,
		},
		{
			name:    "missing workspace_id",
			fb:      FeedbackRequest{RequestID: "req-123", Rating: 1},
			wantErr: true,
		},
		{
			name:    "rating zero is invalid",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: 0},
			wantErr: true,
		},
		{
			name:    "rating too high",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: 6},
			wantErr: true,
		},
		{
			name:    "negative rating other than -1",
			fb:      FeedbackRequest{RequestID: "req-123", WorkspaceID: "ws-1", Rating: -2},
			wantErr: true,
		},
		{
			name: "valid with all optional fields",
			fb: FeedbackRequest{
				RequestID:   "req-123",
				WorkspaceID: "ws-1",
				SessionID:   "sess-456",
				Model:       "gpt-4",
				Rating:      4,
				Comment:     "Great response",
				Tags:        []string{"helpful", "accurate"},
				Metadata:    map[string]string{"source": "ui"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fb.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// spyFeedbackWriter captures feedback records for testing.
type spyFeedbackWriter struct {
	mu      sync.Mutex
	records []*FeedbackRecord
}

func (s *spyFeedbackWriter) Write(_ context.Context, fb *FeedbackRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, fb)
	return nil
}

func TestFeedbackEndpoint(t *testing.T) {
	spy := &spyFeedbackWriter{}
	h := &Handler{
		config: &HandlerConfig{
			FeedbackWriter: spy,
		},
	}

	tests := []struct {
		name       string
		method     string
		body       any
		wantStatus int
	}{
		{
			name:   "valid feedback",
			method: http.MethodPost,
			body: FeedbackRequest{
				RequestID:   "req-abc",
				WorkspaceID: "ws-1",
				Rating:      1,
				Comment:     "test",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "wrong method",
			method:     http.MethodGet,
			body:       nil,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "missing request_id",
			method: http.MethodPost,
			body: FeedbackRequest{
				WorkspaceID: "ws-1",
				Rating:      1,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "missing workspace_id",
			method: http.MethodPost,
			body: FeedbackRequest{
				RequestID: "req-abc",
				Rating:    1,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "rating out of range",
			method: http.MethodPost,
			body: FeedbackRequest{
				RequestID:   "req-abc",
				WorkspaceID: "ws-1",
				Rating:      10,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid json",
			method:     http.MethodPost,
			body:       "not json",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyBytes []byte
			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					bodyBytes = []byte(v)
				default:
					bodyBytes, _ = json.Marshal(v)
				}
			}

			req := httptest.NewRequest(tt.method, "/v1/feedback", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.handleFeedback(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("handleFeedback() status = %d, want %d, body = %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusCreated {
				var resp FeedbackResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.ID == "" {
					t.Error("expected non-empty feedback ID in response")
				}
				if resp.Status != "accepted" {
					t.Errorf("expected status 'accepted', got %q", resp.Status)
				}
				if resp.Timestamp == "" {
					t.Error("expected non-empty timestamp in response")
				}
			}
		})
	}
}

func TestCompositeFeedbackWriter(t *testing.T) {
	spy1 := &spyFeedbackWriter{}
	spy2 := &spyFeedbackWriter{}
	composite := &CompositeFeedbackWriter{
		Writers: []FeedbackWriter{spy1, spy2},
	}

	record := &FeedbackRecord{
		ID:          "fb-123",
		RequestID:   "req-abc",
		WorkspaceID: "ws-1",
		Rating:      5,
	}

	err := composite.Write(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(spy1.records) != 1 {
		t.Errorf("spy1 got %d records, want 1", len(spy1.records))
	}
	if len(spy2.records) != 1 {
		t.Errorf("spy2 got %d records, want 1", len(spy2.records))
	}
}

func TestLogFeedbackWriter(t *testing.T) {
	w := &LogFeedbackWriter{}
	record := &FeedbackRecord{
		ID:          "fb-456",
		RequestID:   "req-xyz",
		WorkspaceID: "ws-2",
		Rating:      -1,
		Comment:     "Not helpful",
		Tags:        []string{"inaccurate"},
		Metadata:    map[string]string{"page": "chat"},
	}

	err := w.Write(context.Background(), record)
	if err != nil {
		t.Fatalf("LogFeedbackWriter.Write() error = %v", err)
	}
}
