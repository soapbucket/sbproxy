package ai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestFineTuneStore_CRUD(t *testing.T) {
	store := NewMemoryFineTuneStore()
	ctx := context.Background()

	job := &FineTuneJob{
		ID:           "ftjob-abc123",
		Object:       "fine_tuning.job",
		Model:        "gpt-4o-mini-2024-07-18",
		Status:       FineTuneStatusCreated,
		TrainingFile: "file-abc123",
		CreatedAt:    time.Now().Unix(),
		Provider:     "openai",
	}

	// Store
	if err := store.StoreJob(ctx, job); err != nil {
		t.Fatalf("StoreJob failed: %v", err)
	}

	// Duplicate store should fail
	if err := store.StoreJob(ctx, job); err == nil {
		t.Fatal("Expected error storing duplicate job")
	}

	// Get
	got, err := store.GetJob(ctx, "ftjob-abc123")
	if err != nil {
		t.Fatalf("GetJob failed: %v", err)
	}
	if got.ID != job.ID {
		t.Errorf("Expected ID %s, got %s", job.ID, got.ID)
	}
	if got.Model != job.Model {
		t.Errorf("Expected model %s, got %s", job.Model, got.Model)
	}
	if got.Status != FineTuneStatusCreated {
		t.Errorf("Expected status created, got %s", got.Status)
	}

	// Update
	job.Status = FineTuneStatusRunning
	if err := store.UpdateJob(ctx, job); err != nil {
		t.Fatalf("UpdateJob failed: %v", err)
	}

	got, _ = store.GetJob(ctx, "ftjob-abc123")
	if got.Status != FineTuneStatusRunning {
		t.Errorf("Expected status running after update, got %s", got.Status)
	}

	// Update nonexistent
	if err := store.UpdateJob(ctx, &FineTuneJob{ID: "nonexistent"}); err == nil {
		t.Fatal("Expected error updating nonexistent job")
	}

	// Get nonexistent
	if _, err := store.GetJob(ctx, "nonexistent"); err == nil {
		t.Fatal("Expected error getting nonexistent job")
	}

	// Delete
	if err := store.DeleteJob(ctx, "ftjob-abc123"); err != nil {
		t.Fatalf("DeleteJob failed: %v", err)
	}

	// Verify deleted
	if _, err := store.GetJob(ctx, "ftjob-abc123"); err == nil {
		t.Fatal("Expected error getting deleted job")
	}

	// Delete nonexistent
	if err := store.DeleteJob(ctx, "nonexistent"); err == nil {
		t.Fatal("Expected error deleting nonexistent job")
	}
}

func TestFineTuneStore_List(t *testing.T) {
	store := NewMemoryFineTuneStore()
	ctx := context.Background()

	// Store multiple jobs with different creation times.
	for i := 0; i < 5; i++ {
		job := &FineTuneJob{
			ID:           fmt.Sprintf("ftjob-%d", i),
			Object:       "fine_tuning.job",
			Model:        "gpt-4o-mini-2024-07-18",
			Status:       FineTuneStatusCreated,
			TrainingFile: "file-abc123",
			CreatedAt:    int64(1000 + i),
			Provider:     "openai",
		}
		if err := store.StoreJob(ctx, job); err != nil {
			t.Fatalf("StoreJob failed: %v", err)
		}
	}

	// List all with default limit.
	jobs, err := store.ListJobs(ctx, 0, "")
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}
	if len(jobs) != 5 {
		t.Fatalf("Expected 5 jobs, got %d", len(jobs))
	}

	// Should be reverse chronological.
	if jobs[0].ID != "ftjob-4" {
		t.Errorf("Expected first job ftjob-4 (newest), got %s", jobs[0].ID)
	}
	if jobs[4].ID != "ftjob-0" {
		t.Errorf("Expected last job ftjob-0 (oldest), got %s", jobs[4].ID)
	}

	// List with limit.
	jobs, err = store.ListJobs(ctx, 2, "")
	if err != nil {
		t.Fatalf("ListJobs with limit failed: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("Expected 2 jobs, got %d", len(jobs))
	}

	// List with after cursor.
	jobs, err = store.ListJobs(ctx, 10, "ftjob-3")
	if err != nil {
		t.Fatalf("ListJobs with after failed: %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("Expected 3 jobs after ftjob-3, got %d", len(jobs))
	}
	if jobs[0].ID != "ftjob-2" {
		t.Errorf("Expected first job after cursor to be ftjob-2, got %s", jobs[0].ID)
	}
}

func TestFineTuneStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryFineTuneStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	// Concurrent writes.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			job := &FineTuneJob{
				ID:           fmt.Sprintf("ftjob-concurrent-%d", idx),
				Object:       "fine_tuning.job",
				Model:        "gpt-4o-mini",
				Status:       FineTuneStatusCreated,
				TrainingFile: "file-concurrent",
				CreatedAt:    int64(1000 + idx),
				Provider:     "openai",
			}
			if err := store.StoreJob(ctx, job); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Concurrent store error: %v", err)
	}

	// Concurrent reads.
	var wg2 sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg2.Add(1)
		go func(idx int) {
			defer wg2.Done()
			_, _ = store.GetJob(ctx, fmt.Sprintf("ftjob-concurrent-%d", idx))
			_, _ = store.ListJobs(ctx, 10, "")
		}(i)
	}
	wg2.Wait()

	// Verify all 50 jobs exist.
	jobs, err := store.ListJobs(ctx, 100, "")
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}
	if len(jobs) != 50 {
		t.Errorf("Expected 50 jobs after concurrent writes, got %d", len(jobs))
	}
}

// mockFineTuneProvider creates a test server that mimics OpenAI's fine-tuning API.
func mockFineTuneProvider(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func defaultFineTuneHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path

		switch {
		case path == "/v1/fine_tuning/jobs" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(FineTuneJob{
				ID:           "ftjob-provider-1",
				Object:       "fine_tuning.job",
				Model:        "gpt-4o-mini-2024-07-18",
				Status:       FineTuneStatusCreated,
				TrainingFile: "file-abc123",
				CreatedAt:    time.Now().Unix(),
			})
		case strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(FineTuneJob{
				ID:           strings.TrimSuffix(strings.TrimPrefix(path, "/v1/fine_tuning/jobs/"), "/cancel"),
				Object:       "fine_tuning.job",
				Model:        "gpt-4o-mini-2024-07-18",
				Status:       FineTuneStatusCancelled,
				TrainingFile: "file-abc123",
				CreatedAt:    time.Now().Unix(),
			})
		case strings.HasSuffix(path, "/events"):
			json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"data": []FineTuneEvent{
					{
						Object:    "fine_tuning.job.event",
						ID:        "ftevent-1",
						CreatedAt: time.Now().Unix(),
						Level:     "info",
						Message:   "Training started",
					},
				},
			})
		case strings.HasSuffix(path, "/checkpoints"):
			json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"data":   []any{},
			})
		default:
			// GET job by ID.
			jobID := strings.TrimPrefix(path, "/v1/fine_tuning/jobs/")
			json.NewEncoder(w).Encode(FineTuneJob{
				ID:           jobID,
				Object:       "fine_tuning.job",
				Model:        "gpt-4o-mini-2024-07-18",
				Status:       FineTuneStatusRunning,
				TrainingFile: "file-abc123",
				CreatedAt:    time.Now().Unix(),
			})
		}
	}
}

func newTestFineTuneProxy(t *testing.T, providerURL string) (*FineTuneProxy, *MemoryFineTuneStore) {
	t.Helper()
	store := NewMemoryFineTuneStore()
	providers := []*ProviderConfig{
		{
			Name:    "test-openai",
			Type:    "openai",
			BaseURL: providerURL,
			APIKey:  "sk-test-key",
			Models:  []string{"gpt-4o-mini-2024-07-18", "gpt-4o-mini"},
		},
	}
	proxy := NewFineTuneProxy(store, providers)
	return proxy, store
}

func TestFineTuneProxy_CreateJob(t *testing.T) {
	mockServer := mockFineTuneProvider(t, defaultFineTuneHandler())
	defer mockServer.Close()

	proxy, store := newTestFineTuneProxy(t, mockServer.URL)

	body := `{"model": "gpt-4o-mini-2024-07-18", "training_file": "file-abc123"}`
	req := httptest.NewRequest("POST", "/v1/fine_tuning/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp FineTuneJob
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.ID != "ftjob-provider-1" {
		t.Errorf("Expected job ID ftjob-provider-1, got %s", resp.ID)
	}

	// Verify stored locally.
	stored, err := store.GetJob(context.Background(), "ftjob-provider-1")
	if err != nil {
		t.Fatalf("Job not stored locally: %v", err)
	}
	if stored.Provider != "test-openai" {
		t.Errorf("Expected provider test-openai, got %s", stored.Provider)
	}
}

func TestFineTuneProxy_GetJob(t *testing.T) {
	mockServer := mockFineTuneProvider(t, defaultFineTuneHandler())
	defer mockServer.Close()

	proxy, store := newTestFineTuneProxy(t, mockServer.URL)
	ctx := context.Background()

	// Pre-store a job.
	_ = store.StoreJob(ctx, &FineTuneJob{
		ID:           "ftjob-get-test",
		Object:       "fine_tuning.job",
		Model:        "gpt-4o-mini-2024-07-18",
		Status:       FineTuneStatusRunning,
		TrainingFile: "file-abc123",
		CreatedAt:    time.Now().Unix(),
		Provider:     "test-openai",
	})

	req := httptest.NewRequest("GET", "/v1/fine_tuning/jobs/ftjob-get-test", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp FineTuneJob
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.ID != "ftjob-get-test" {
		t.Errorf("Expected job ID ftjob-get-test, got %s", resp.ID)
	}
}

func TestFineTuneProxy_ListJobs(t *testing.T) {
	mockServer := mockFineTuneProvider(t, defaultFineTuneHandler())
	defer mockServer.Close()

	proxy, store := newTestFineTuneProxy(t, mockServer.URL)
	ctx := context.Background()

	// Pre-store some jobs.
	for i := 0; i < 3; i++ {
		_ = store.StoreJob(ctx, &FineTuneJob{
			ID:           fmt.Sprintf("ftjob-list-%d", i),
			Object:       "fine_tuning.job",
			Model:        "gpt-4o-mini-2024-07-18",
			Status:       FineTuneStatusSucceeded,
			TrainingFile: "file-abc123",
			CreatedAt:    int64(1000 + i),
			Provider:     "test-openai",
		})
	}

	req := httptest.NewRequest("GET", "/v1/fine_tuning/jobs", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp FineTuneListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Object != "list" {
		t.Errorf("Expected object 'list', got %s", resp.Object)
	}
	if len(resp.Data) != 3 {
		t.Errorf("Expected 3 jobs, got %d", len(resp.Data))
	}
}

func TestFineTuneProxy_CancelJob(t *testing.T) {
	mockServer := mockFineTuneProvider(t, defaultFineTuneHandler())
	defer mockServer.Close()

	proxy, store := newTestFineTuneProxy(t, mockServer.URL)
	ctx := context.Background()

	_ = store.StoreJob(ctx, &FineTuneJob{
		ID:           "ftjob-cancel-test",
		Object:       "fine_tuning.job",
		Model:        "gpt-4o-mini-2024-07-18",
		Status:       FineTuneStatusRunning,
		TrainingFile: "file-abc123",
		CreatedAt:    time.Now().Unix(),
		Provider:     "test-openai",
	})

	req := httptest.NewRequest("POST", "/v1/fine_tuning/jobs/ftjob-cancel-test/cancel", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify local state updated.
	job, _ := store.GetJob(ctx, "ftjob-cancel-test")
	if job.Status != FineTuneStatusCancelled {
		t.Errorf("Expected status cancelled, got %s", job.Status)
	}
}

func TestFineTuneProxy_GetEvents(t *testing.T) {
	mockServer := mockFineTuneProvider(t, defaultFineTuneHandler())
	defer mockServer.Close()

	proxy, store := newTestFineTuneProxy(t, mockServer.URL)
	ctx := context.Background()

	_ = store.StoreJob(ctx, &FineTuneJob{
		ID:           "ftjob-events-test",
		Object:       "fine_tuning.job",
		Model:        "gpt-4o-mini-2024-07-18",
		Status:       FineTuneStatusRunning,
		TrainingFile: "file-abc123",
		CreatedAt:    time.Now().Unix(),
		Provider:     "test-openai",
	})

	req := httptest.NewRequest("GET", "/v1/fine_tuning/jobs/ftjob-events-test/events", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp["object"] != "list" {
		t.Errorf("Expected object 'list', got %v", resp["object"])
	}
	data, ok := resp["data"].([]any)
	if !ok || len(data) == 0 {
		t.Error("Expected non-empty events list")
	}
}

func TestFineTuneProxy_ProviderSelection(t *testing.T) {
	var capturedAuth string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(FineTuneJob{
			ID:           "ftjob-selected",
			Object:       "fine_tuning.job",
			Model:        "gpt-4o-mini",
			Status:       FineTuneStatusCreated,
			TrainingFile: "file-abc123",
			CreatedAt:    time.Now().Unix(),
		})
	}))
	defer mockServer.Close()

	store := NewMemoryFineTuneStore()
	providers := []*ProviderConfig{
		{
			Name:    "provider-a",
			Type:    "openai",
			BaseURL: mockServer.URL,
			APIKey:  "sk-provider-a",
			Models:  []string{"special-model"},
		},
		{
			Name:    "provider-b",
			Type:    "openai",
			BaseURL: mockServer.URL,
			APIKey:  "sk-provider-b",
			Models:  []string{"gpt-4o-mini"},
		},
	}
	proxy := NewFineTuneProxy(store, providers)

	body := `{"model": "gpt-4o-mini", "training_file": "file-abc123"}`
	req := httptest.NewRequest("POST", "/v1/fine_tuning/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Should have used provider-b's API key since it supports gpt-4o-mini.
	if capturedAuth != "Bearer sk-provider-b" {
		t.Errorf("Expected provider-b auth header, got %s", capturedAuth)
	}
}

func TestFineTuneProxy_ProviderNotFound(t *testing.T) {
	store := NewMemoryFineTuneStore()
	// No providers configured.
	proxy := NewFineTuneProxy(store, nil)

	body := `{"model": "gpt-4o-mini", "training_file": "file-abc123"}`
	req := httptest.NewRequest("POST", "/v1/fine_tuning/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFineTuneProxy_MethodNotAllowed(t *testing.T) {
	mockServer := mockFineTuneProvider(t, defaultFineTuneHandler())
	defer mockServer.Close()

	proxy, _ := newTestFineTuneProxy(t, mockServer.URL)

	// DELETE on /v1/fine_tuning/jobs should not be allowed.
	req := httptest.NewRequest("DELETE", "/v1/fine_tuning/jobs", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d: %s", w.Code, w.Body.String())
	}

	// PUT on /v1/fine_tuning/jobs/some-id should not be allowed.
	req2 := httptest.NewRequest("PUT", "/v1/fine_tuning/jobs/some-id", nil)
	w2 := httptest.NewRecorder()

	proxy.ServeHTTP(w2, req2)

	if w2.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d: %s", w2.Code, w2.Body.String())
	}
}
