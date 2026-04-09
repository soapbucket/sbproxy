// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// BatchStatus tracks batch job lifecycle.
type BatchStatus string

const (
	BatchStatusValidating BatchStatus = "validating"
	BatchStatusInProgress BatchStatus = "in_progress"
	BatchStatusCompleted  BatchStatus = "completed"
	BatchStatusFailed     BatchStatus = "failed"
	BatchStatusCancelled  BatchStatus = "cancelled"
	BatchStatusExpired    BatchStatus = "expired"
)

// BatchJob represents a batch processing job.
type BatchJob struct {
	ID            string            `json:"id"`
	Object        string            `json:"object"`
	Endpoint      string            `json:"endpoint"`
	InputFileID   string            `json:"input_file_id"`
	OutputFileID  string            `json:"output_file_id,omitempty"`
	ErrorFileID   string            `json:"error_file_id,omitempty"`
	Status        BatchStatus       `json:"status"`
	RequestCounts BatchCounts       `json:"request_counts"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     int64             `json:"created_at"`
	CompletedAt   *int64            `json:"completed_at,omitempty"`
	CancelledAt   *int64            `json:"cancelled_at,omitempty"`
	ExpiresAt     int64             `json:"expires_at"`
	Errors        []BatchError      `json:"errors,omitempty"`
	cancelFunc    context.CancelFunc
}

// BatchCounts tracks request completion progress.
type BatchCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// BatchError describes an error that occurred during batch processing.
type BatchError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

// BatchRequest is a single line in a JSONL batch input file.
type BatchRequest struct {
	CustomID string                 `json:"custom_id"`
	Method   string                 `json:"method"`
	URL      string                 `json:"url"`
	Body     *ChatCompletionRequest `json:"body"`
}

// BatchResponseLine is a single line in the output JSONL.
type BatchResponseLine struct {
	ID       string             `json:"id"`
	CustomID string             `json:"custom_id"`
	Response *BatchResponseBody `json:"response,omitempty"`
	Error    *BatchError        `json:"error,omitempty"`
}

// BatchResponseBody wraps the HTTP status and response body for a batch response line.
type BatchResponseBody struct {
	StatusCode int                     `json:"status_code"`
	Body       *ChatCompletionResponse `json:"body"`
}

// FileObject represents an uploaded file.
type FileObject struct {
	ID        string `json:"id"`
	Object    string `json:"object"`
	Bytes     int64  `json:"bytes"`
	CreatedAt int64  `json:"created_at"`
	Filename  string `json:"filename"`
	Purpose   string `json:"purpose"`
}

// BatchRequestExecutor processes a single ChatCompletionRequest for a batch job.
type BatchRequestExecutor func(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error)

// batchCreateRequest is the JSON body for POST /v1/batches.
type batchCreateRequest struct {
	InputFileID      string            `json:"input_file_id"`
	Endpoint         string            `json:"endpoint"`
	CompletionWindow string            `json:"completion_window"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// batchListResponse is the JSON body for GET /v1/batches.
type batchListResponse struct {
	Object  string      `json:"object"`
	Data    []*BatchJob `json:"data"`
	HasMore bool        `json:"has_more"`
}

// fileListResponse is the JSON body for GET /v1/files.
type fileListResponse struct {
	Object string        `json:"object"`
	Data   []*FileObject `json:"data"`
}

const (
	maxBatchFileSize = 100 * 1024 * 1024 // 100MB
	batchExpiry      = 24 * time.Hour
)

// generateBatchID creates a unique batch job ID.
func generateBatchID() string {
	return fmt.Sprintf("batch_%016x%08x", time.Now().UnixNano(), rand.Uint32())
}

// generateFileID creates a unique file ID.
func generateFileID() string {
	return fmt.Sprintf("file-%016x%08x", time.Now().UnixNano(), rand.Uint32())
}

// generateResponseLineID creates a unique response line ID.
func generateResponseLineID() string {
	return fmt.Sprintf("resp_%016x%08x", time.Now().UnixNano(), rand.Uint32())
}

// handleBatches routes batch API requests.
func (h *Handler) handleBatches(w http.ResponseWriter, r *http.Request, path string) {
	if h.config.BatchStore == nil {
		WriteError(w, ErrInvalidRequest("batch API is not enabled"))
		return
	}

	// path is already trimmed of "v1/" prefix, so it looks like "batches", "batches/{id}", "batches/{id}/cancel"
	parts := strings.Split(path, "/")

	switch {
	case len(parts) == 1 && r.Method == http.MethodPost:
		h.handleBatchCreate(w, r)
	case len(parts) == 1 && r.Method == http.MethodGet:
		h.handleBatchList(w, r)
	case len(parts) == 2 && r.Method == http.MethodGet:
		h.handleBatchGet(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "cancel" && r.Method == http.MethodPost:
		h.handleBatchCancel(w, r, parts[1])
	default:
		WriteError(w, ErrMethodNotAllowed())
	}
}

func (h *Handler) handleBatchCreate(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req batchCreateRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	if req.InputFileID == "" {
		WriteError(w, ErrInvalidRequest("input_file_id is required"))
		return
	}
	if req.Endpoint != "/v1/chat/completions" {
		WriteError(w, ErrInvalidRequest("only /v1/chat/completions endpoint is supported"))
		return
	}
	if req.CompletionWindow == "" {
		req.CompletionWindow = "24h"
	}

	// Verify file exists
	file, err := h.config.BatchStore.GetFile(r.Context(), req.InputFileID)
	if err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("file %q not found", req.InputFileID)))
		return
	}
	if file.Purpose != "batch" {
		WriteError(w, ErrInvalidRequest("file purpose must be 'batch'"))
		return
	}

	// Validate JSONL content
	content, err := h.config.BatchStore.GetFileContent(r.Context(), req.InputFileID)
	if err != nil {
		WriteError(w, ErrInternal("failed to read file content"))
		return
	}

	lineCount, validationErrors := validateBatchJSONL(content)
	if len(validationErrors) > 0 {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid JSONL: %s", validationErrors[0].Message)))
		return
	}
	if lineCount == 0 {
		WriteError(w, ErrInvalidRequest("batch file is empty"))
		return
	}

	now := time.Now()
	job := &BatchJob{
		ID:          generateBatchID(),
		Object:      "batch",
		Endpoint:    req.Endpoint,
		InputFileID: req.InputFileID,
		Status:      BatchStatusValidating,
		RequestCounts: BatchCounts{
			Total: lineCount,
		},
		Metadata:  req.Metadata,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(batchExpiry).Unix(),
	}

	if err := h.config.BatchStore.StoreBatch(r.Context(), job); err != nil {
		WriteError(w, ErrInternal("failed to store batch job"))
		return
	}

	// Return a snapshot before submitting to the worker pool to avoid data races.
	snapshot := *job
	snapshot.Metadata = copyStringMap(job.Metadata)

	// Submit to worker pool
	if h.config.BatchPool != nil {
		h.config.BatchPool.Submit(job.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&snapshot)
}

func (h *Handler) handleBatchGet(w http.ResponseWriter, r *http.Request, batchID string) {
	job, err := h.config.BatchStore.GetBatch(r.Context(), batchID)
	if err != nil {
		WriteError(w, ErrNotFound())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func (h *Handler) handleBatchList(w http.ResponseWriter, r *http.Request) {
	limit := 20
	after := r.URL.Query().Get("after")

	jobs, err := h.config.BatchStore.ListBatches(r.Context(), limit, after)
	if err != nil {
		WriteError(w, ErrInternal("failed to list batches"))
		return
	}

	resp := batchListResponse{
		Object:  "list",
		Data:    jobs,
		HasMore: len(jobs) >= limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleBatchCancel(w http.ResponseWriter, r *http.Request, batchID string) {
	job, err := h.config.BatchStore.GetBatch(r.Context(), batchID)
	if err != nil {
		WriteError(w, ErrNotFound())
		return
	}

	if job.Status != BatchStatusInProgress && job.Status != BatchStatusValidating {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("cannot cancel batch with status %q", job.Status)))
		return
	}

	now := time.Now().Unix()
	job.Status = BatchStatusCancelled
	job.CancelledAt = &now

	if job.cancelFunc != nil {
		job.cancelFunc()
	}

	if err := h.config.BatchStore.UpdateBatch(r.Context(), job); err != nil {
		WriteError(w, ErrInternal("failed to update batch"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// handleBatchFiles routes file API requests for batch operations.
func (h *Handler) handleBatchFiles(w http.ResponseWriter, r *http.Request, path string) {
	if h.config.BatchStore == nil {
		WriteError(w, ErrInvalidRequest("batch file API is not enabled"))
		return
	}

	// path looks like "files", "files/{id}", "files/{id}/content"
	parts := strings.Split(path, "/")

	switch {
	case len(parts) == 1 && r.Method == http.MethodPost:
		h.handleFileUpload(w, r)
	case len(parts) == 1 && r.Method == http.MethodGet:
		h.handleFileList(w, r)
	case len(parts) == 2 && r.Method == http.MethodGet:
		h.handleFileGet(w, r, parts[1])
	case len(parts) == 2 && r.Method == http.MethodDelete:
		h.handleFileDelete(w, r, parts[1])
	case len(parts) == 3 && parts[2] == "content" && r.Method == http.MethodGet:
		h.handleFileGetContent(w, r, parts[1])
	default:
		WriteError(w, ErrMethodNotAllowed())
	}
}

func (h *Handler) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// Limit upload size
	r.Body = http.MaxBytesReader(w, r.Body, maxBatchFileSize)

	if err := r.ParseMultipartForm(maxBatchFileSize); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("failed to parse multipart form: %v", err)))
		return
	}

	purpose := r.FormValue("purpose")
	if purpose == "" {
		purpose = "batch"
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("file field is required: %v", err)))
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("failed to read file: %v", err)))
		return
	}

	fileObj := &FileObject{
		ID:        generateFileID(),
		Object:    "file",
		Bytes:     int64(len(content)),
		CreatedAt: time.Now().Unix(),
		Filename:  header.Filename,
		Purpose:   purpose,
	}

	if err := h.config.BatchStore.StoreFile(r.Context(), fileObj, content); err != nil {
		WriteError(w, ErrInternal("failed to store file"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(fileObj)
}

func (h *Handler) handleFileGet(w http.ResponseWriter, r *http.Request, fileID string) {
	file, err := h.config.BatchStore.GetFile(r.Context(), fileID)
	if err != nil {
		WriteError(w, ErrNotFound())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(file)
}

func (h *Handler) handleFileGetContent(w http.ResponseWriter, r *http.Request, fileID string) {
	content, err := h.config.BatchStore.GetFileContent(r.Context(), fileID)
	if err != nil {
		WriteError(w, ErrNotFound())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(content)
}

func (h *Handler) handleFileDelete(w http.ResponseWriter, r *http.Request, fileID string) {
	if err := h.config.BatchStore.DeleteFile(r.Context(), fileID); err != nil {
		WriteError(w, ErrNotFound())
		return
	}

	resp := struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Deleted bool   `json:"deleted"`
	}{
		ID:      fileID,
		Object:  "file",
		Deleted: true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleFileList(w http.ResponseWriter, r *http.Request) {
	purpose := r.URL.Query().Get("purpose")

	files, err := h.config.BatchStore.ListFiles(r.Context(), purpose)
	if err != nil {
		WriteError(w, ErrInternal("failed to list files"))
		return
	}

	resp := fileListResponse{
		Object: "list",
		Data:   files,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// validateBatchJSONL validates a JSONL batch input file and returns the line count and any errors.
func validateBatchJSONL(content []byte) (int, []BatchError) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	var errors []BatchError
	lineNum := 0
	seenIDs := make(map[string]bool)

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var req BatchRequest
		if err := json.Unmarshal(line, &req); err != nil {
			errors = append(errors, BatchError{
				Code:    "invalid_json",
				Message: fmt.Sprintf("line %d: invalid JSON: %v", lineNum, err),
				Line:    lineNum,
			})
			continue
		}

		if req.CustomID == "" {
			errors = append(errors, BatchError{
				Code:    "missing_custom_id",
				Message: fmt.Sprintf("line %d: custom_id is required", lineNum),
				Line:    lineNum,
			})
			continue
		}

		if seenIDs[req.CustomID] {
			errors = append(errors, BatchError{
				Code:    "duplicate_custom_id",
				Message: fmt.Sprintf("line %d: duplicate custom_id %q", lineNum, req.CustomID),
				Line:    lineNum,
			})
			continue
		}
		seenIDs[req.CustomID] = true

		if req.Method != "POST" {
			errors = append(errors, BatchError{
				Code:    "invalid_method",
				Message: fmt.Sprintf("line %d: method must be POST", lineNum),
				Line:    lineNum,
			})
			continue
		}

		if req.URL != "/v1/chat/completions" {
			errors = append(errors, BatchError{
				Code:    "invalid_url",
				Message: fmt.Sprintf("line %d: url must be /v1/chat/completions", lineNum),
				Line:    lineNum,
			})
			continue
		}

		if req.Body == nil {
			errors = append(errors, BatchError{
				Code:    "missing_body",
				Message: fmt.Sprintf("line %d: body is required", lineNum),
				Line:    lineNum,
			})
		}
	}

	return lineNum, errors
}

// parseBatchRequests reads and parses all lines from a JSONL batch file.
func parseBatchRequests(content []byte) ([]BatchRequest, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	var requests []BatchRequest
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req BatchRequest
		if err := json.Unmarshal(line, &req); err != nil {
			return nil, fmt.Errorf("invalid JSONL line: %w", err)
		}
		requests = append(requests, req)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}
	return requests, nil
}

// buildOutputFile serializes batch response lines as JSONL.
func buildOutputFile(lines []*BatchResponseLine) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, line := range lines {
		if err := enc.Encode(line); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// buildErrorFile serializes batch error lines as JSONL.
func buildErrorFile(lines []*BatchResponseLine) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, line := range lines {
		if line.Error != nil {
			if err := enc.Encode(line); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

// copyStringMap returns a shallow copy of a string map.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// logBatchEvent logs a batch processing event.
func logBatchEvent(jobID string, msg string, args ...any) {
	allArgs := append([]any{"batch_id", jobID}, args...)
	slog.Info(msg, allArgs...)
}
