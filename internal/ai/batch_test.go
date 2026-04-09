package ai

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockBatchHandler creates a Handler with an in-memory batch store for testing.
func mockBatchHandler(t *testing.T, executor BatchRequestExecutor) *Handler {
	t.Helper()
	store := NewMemoryBatchStore(100)
	pool := NewBatchWorkerPool(store, executor, 2)
	pool.Start()
	t.Cleanup(func() { pool.Stop() })

	h := &Handler{
		config: &HandlerConfig{
			Providers:          []*ProviderConfig{{Name: "test", Type: "openai", APIKey: "sk-test", Enabled: boolPtr(true), Weight: 100}},
			MaxRequestBodySize: 10 * 1024 * 1024,
			BatchStore:         store,
			BatchPool:          pool,
		},
		providers: map[string]providerEntry{},
	}
	return h
}

func successExecutor(_ context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	return &ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []Choice{
			{
				Index:        0,
				Message:      Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)},
				FinishReason: batchStrPtr("stop"),
			},
		},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}, nil
}

func batchStrPtr(s string) *string { return &s }

func failingExecutor(_ context.Context, _ *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	return nil, fmt.Errorf("provider error: service unavailable")
}

func uploadTestFile(t *testing.T, h *Handler, filename string, content string) *FileObject {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte(content))
	writer.WriteField("purpose", "batch")
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	h.handleBatchFiles(w, req, "files")

	if w.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", w.Code, w.Body.String())
	}

	var file FileObject
	json.NewDecoder(w.Body).Decode(&file)
	return &file
}

func validBatchJSONL() string {
	return `{"custom_id": "req-1", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}}
{"custom_id": "req-2", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4o", "messages": [{"role": "user", "content": "World"}]}}
`
}

// ============================================================================
// File API Tests
// ============================================================================

func TestBatchFiles_Upload(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	file := uploadTestFile(t, h, "batch_input.jsonl", validBatchJSONL())

	if file.ID == "" {
		t.Error("file ID should not be empty")
	}
	if file.Object != "file" {
		t.Errorf("expected object 'file', got %q", file.Object)
	}
	if file.Purpose != "batch" {
		t.Errorf("expected purpose 'batch', got %q", file.Purpose)
	}
	if file.Bytes <= 0 {
		t.Error("file bytes should be > 0")
	}
	if file.Filename != "batch_input.jsonl" {
		t.Errorf("expected filename 'batch_input.jsonl', got %q", file.Filename)
	}
}

func TestBatchFiles_Get(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	req := httptest.NewRequest("GET", "/v1/files/"+uploaded.ID, nil)
	w := httptest.NewRecorder()
	h.handleBatchFiles(w, req, "files/"+uploaded.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var file FileObject
	json.NewDecoder(w.Body).Decode(&file)
	if file.ID != uploaded.ID {
		t.Errorf("expected ID %q, got %q", uploaded.ID, file.ID)
	}
}

func TestBatchFiles_GetContent(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	content := validBatchJSONL()
	uploaded := uploadTestFile(t, h, "test.jsonl", content)

	req := httptest.NewRequest("GET", "/v1/files/"+uploaded.ID+"/content", nil)
	w := httptest.NewRecorder()
	h.handleBatchFiles(w, req, "files/"+uploaded.ID+"/content")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	if string(body) != content {
		t.Errorf("content mismatch: got %q", string(body))
	}
}

func TestBatchFiles_Delete(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	req := httptest.NewRequest("DELETE", "/v1/files/"+uploaded.ID, nil)
	w := httptest.NewRecorder()
	h.handleBatchFiles(w, req, "files/"+uploaded.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Deleted bool `json:"deleted"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Deleted {
		t.Error("expected deleted=true")
	}

	// Verify file is gone
	getReq := httptest.NewRequest("GET", "/v1/files/"+uploaded.ID, nil)
	getW := httptest.NewRecorder()
	h.handleBatchFiles(getW, getReq, "files/"+uploaded.ID)
	if getW.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", getW.Code)
	}
}

func TestBatchFiles_List(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploadTestFile(t, h, "a.jsonl", validBatchJSONL())
	uploadTestFile(t, h, "b.jsonl", validBatchJSONL())

	req := httptest.NewRequest("GET", "/v1/files", nil)
	w := httptest.NewRecorder()
	h.handleBatchFiles(w, req, "files")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp fileListResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Data) < 2 {
		t.Errorf("expected at least 2 files, got %d", len(resp.Data))
	}
}

// ============================================================================
// Batch API Tests
// ============================================================================

func TestBatch_Create(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	body := fmt.Sprintf(`{"input_file_id": %q, "endpoint": "/v1/chat/completions", "completion_window": "24h"}`, uploaded.ID)
	req := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleBatches(w, req, "batches")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var job BatchJob
	json.NewDecoder(w.Body).Decode(&job)
	if job.ID == "" {
		t.Error("batch ID should not be empty")
	}
	if job.Object != "batch" {
		t.Errorf("expected object 'batch', got %q", job.Object)
	}
	if job.Endpoint != "/v1/chat/completions" {
		t.Errorf("expected endpoint '/v1/chat/completions', got %q", job.Endpoint)
	}
	if job.InputFileID != uploaded.ID {
		t.Errorf("expected input_file_id %q, got %q", uploaded.ID, job.InputFileID)
	}
	if job.RequestCounts.Total != 2 {
		t.Errorf("expected 2 total requests, got %d", job.RequestCounts.Total)
	}
}

func TestBatch_Get(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	body := fmt.Sprintf(`{"input_file_id": %q, "endpoint": "/v1/chat/completions", "completion_window": "24h"}`, uploaded.ID)
	createReq := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	h.handleBatches(createW, createReq, "batches")

	var created BatchJob
	json.NewDecoder(createW.Body).Decode(&created)

	getReq := httptest.NewRequest("GET", "/v1/batches/"+created.ID, nil)
	getW := httptest.NewRecorder()
	h.handleBatches(getW, getReq, "batches/"+created.ID)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getW.Code)
	}

	var job BatchJob
	json.NewDecoder(getW.Body).Decode(&job)
	if job.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, job.ID)
	}
}

func TestBatch_List(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"input_file_id": %q, "endpoint": "/v1/chat/completions", "completion_window": "24h"}`, uploaded.ID)
		req := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.handleBatches(w, req, "batches")
	}

	listReq := httptest.NewRequest("GET", "/v1/batches", nil)
	listW := httptest.NewRecorder()
	h.handleBatches(listW, listReq, "batches")

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}

	var resp batchListResponse
	json.NewDecoder(listW.Body).Decode(&resp)
	if len(resp.Data) < 3 {
		t.Errorf("expected at least 3 batches, got %d", len(resp.Data))
	}
}

func TestBatch_Cancel(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	body := fmt.Sprintf(`{"input_file_id": %q, "endpoint": "/v1/chat/completions", "completion_window": "24h"}`, uploaded.ID)
	createReq := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	h.handleBatches(createW, createReq, "batches")

	var created BatchJob
	json.NewDecoder(createW.Body).Decode(&created)

	// Wait briefly for the job to start
	time.Sleep(50 * time.Millisecond)

	cancelReq := httptest.NewRequest("POST", "/v1/batches/"+created.ID+"/cancel", nil)
	cancelW := httptest.NewRecorder()
	h.handleBatches(cancelW, cancelReq, "batches/"+created.ID+"/cancel")

	// The job may have already completed by now, so accept either outcome
	if cancelW.Code != http.StatusOK && cancelW.Code != http.StatusBadRequest {
		t.Fatalf("expected 200 or 400, got %d: %s", cancelW.Code, cancelW.Body.String())
	}
}

func TestBatch_InvalidEndpoint(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "test.jsonl", validBatchJSONL())

	body := fmt.Sprintf(`{"input_file_id": %q, "endpoint": "/v1/embeddings", "completion_window": "24h"}`, uploaded.ID)
	req := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleBatches(w, req, "batches")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatch_FileNotFound(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)

	body := `{"input_file_id": "file-nonexistent", "endpoint": "/v1/chat/completions", "completion_window": "24h"}`
	req := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleBatches(w, req, "batches")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatch_InvalidJSONL(t *testing.T) {
	h := mockBatchHandler(t, successExecutor)
	uploaded := uploadTestFile(t, h, "bad.jsonl", `not valid json at all`)

	body := fmt.Sprintf(`{"input_file_id": %q, "endpoint": "/v1/chat/completions", "completion_window": "24h"}`, uploaded.ID)
	req := httptest.NewRequest("POST", "/v1/batches", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleBatches(w, req, "batches")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Batch Worker Tests
// ============================================================================

func TestBatchWorker_ProcessJob(t *testing.T) {
	store := NewMemoryBatchStore(100)

	// Upload input file
	content := validBatchJSONL()
	fileObj := &FileObject{
		ID:        generateFileID(),
		Object:    "file",
		Bytes:     int64(len(content)),
		CreatedAt: time.Now().Unix(),
		Filename:  "input.jsonl",
		Purpose:   "batch",
	}
	store.StoreFile(context.Background(), fileObj, []byte(content))

	// Create batch job
	job := &BatchJob{
		ID:          generateBatchID(),
		Object:      "batch",
		Endpoint:    "/v1/chat/completions",
		InputFileID: fileObj.ID,
		Status:      BatchStatusValidating,
		RequestCounts: BatchCounts{
			Total: 2,
		},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(batchExpiry).Unix(),
	}
	store.StoreBatch(context.Background(), job)

	pool := NewBatchWorkerPool(store, successExecutor, 1)
	pool.Start()
	defer pool.Stop()

	pool.Submit(job.ID)

	// Wait for processing to complete
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for batch completion")
		default:
			updated, _ := store.GetBatch(context.Background(), job.ID)
			if updated != nil && updated.Status == BatchStatusCompleted {
				if updated.RequestCounts.Completed != 2 {
					t.Errorf("expected 2 completed, got %d", updated.RequestCounts.Completed)
				}
				if updated.OutputFileID == "" {
					t.Error("expected output file ID")
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestBatchWorker_PartialFailure(t *testing.T) {
	store := NewMemoryBatchStore(100)

	callCount := 0
	partialExecutor := func(_ context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
		callCount++
		if callCount%2 == 0 {
			return nil, fmt.Errorf("simulated failure")
		}
		return successExecutor(context.Background(), req)
	}

	content := validBatchJSONL()
	fileObj := &FileObject{
		ID:        generateFileID(),
		Object:    "file",
		Bytes:     int64(len(content)),
		CreatedAt: time.Now().Unix(),
		Filename:  "input.jsonl",
		Purpose:   "batch",
	}
	store.StoreFile(context.Background(), fileObj, []byte(content))

	job := &BatchJob{
		ID:          generateBatchID(),
		Object:      "batch",
		Endpoint:    "/v1/chat/completions",
		InputFileID: fileObj.ID,
		Status:      BatchStatusValidating,
		RequestCounts: BatchCounts{
			Total: 2,
		},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(batchExpiry).Unix(),
	}
	store.StoreBatch(context.Background(), job)

	pool := NewBatchWorkerPool(store, partialExecutor, 1)
	pool.Start()
	defer pool.Stop()

	pool.Submit(job.ID)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for batch completion")
		default:
			updated, _ := store.GetBatch(context.Background(), job.ID)
			if updated != nil && updated.Status == BatchStatusCompleted {
				if updated.RequestCounts.Completed != 1 {
					t.Errorf("expected 1 completed, got %d", updated.RequestCounts.Completed)
				}
				if updated.RequestCounts.Failed != 1 {
					t.Errorf("expected 1 failed, got %d", updated.RequestCounts.Failed)
				}
				if updated.ErrorFileID == "" {
					t.Error("expected error file ID for partial failure")
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestBatchWorker_Cancel(t *testing.T) {
	store := NewMemoryBatchStore(100)

	// Build a large batch so we have time to cancel
	var lines strings.Builder
	for i := 0; i < 100; i++ {
		lines.WriteString(fmt.Sprintf(`{"custom_id": "req-%d", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello %d"}]}}`, i, i))
		lines.WriteString("\n")
	}

	content := lines.String()
	fileObj := &FileObject{
		ID:        generateFileID(),
		Object:    "file",
		Bytes:     int64(len(content)),
		CreatedAt: time.Now().Unix(),
		Filename:  "input.jsonl",
		Purpose:   "batch",
	}
	store.StoreFile(context.Background(), fileObj, []byte(content))

	// Slow executor to give us time to cancel
	slowExecutor := func(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		return successExecutor(ctx, req)
	}

	job := &BatchJob{
		ID:          generateBatchID(),
		Object:      "batch",
		Endpoint:    "/v1/chat/completions",
		InputFileID: fileObj.ID,
		Status:      BatchStatusValidating,
		RequestCounts: BatchCounts{
			Total: 100,
		},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(batchExpiry).Unix(),
	}
	store.StoreBatch(context.Background(), job)

	pool := NewBatchWorkerPool(store, slowExecutor, 1)
	pool.Start()
	defer pool.Stop()

	pool.Submit(job.ID)

	// Wait for processing to start
	time.Sleep(200 * time.Millisecond)

	// Cancel the job
	updated, _ := store.GetBatch(context.Background(), job.ID)
	if updated != nil && updated.cancelFunc != nil {
		updated.cancelFunc()
	}

	// Wait for the worker to notice and stop
	time.Sleep(500 * time.Millisecond)

	final, _ := store.GetBatch(context.Background(), job.ID)
	if final == nil {
		t.Fatal("batch job not found after cancel")
	}

	// The job should have been cancelled or completed (if it finished before cancel took effect)
	if final.Status != BatchStatusCancelled && final.Status != BatchStatusCompleted {
		t.Errorf("expected cancelled or completed, got %q", final.Status)
	}

	// Should not have completed all 100 requests (if cancelled)
	if final.Status == BatchStatusCancelled && final.RequestCounts.Completed >= 100 {
		t.Error("expected fewer than 100 completed requests after cancellation")
	}
}

func TestBatchWorker_Stop(t *testing.T) {
	store := NewMemoryBatchStore(100)
	pool := NewBatchWorkerPool(store, successExecutor, 2)
	pool.Start()

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		pool.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("pool.Stop() did not return within 5 seconds")
	}
}
