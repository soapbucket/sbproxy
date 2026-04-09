// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

// FineTuneJobStatus tracks fine-tuning job lifecycle.
type FineTuneJobStatus string

const (
	FineTuneStatusCreated   FineTuneJobStatus = "created"
	FineTuneStatusPending   FineTuneJobStatus = "pending"
	FineTuneStatusRunning   FineTuneJobStatus = "running"
	FineTuneStatusSucceeded FineTuneJobStatus = "succeeded"
	FineTuneStatusFailed    FineTuneJobStatus = "failed"
	FineTuneStatusCancelled FineTuneJobStatus = "cancelled"
)

// FineTuneJob tracks a fine-tuning job.
type FineTuneJob struct {
	ID              string            `json:"id"`
	Object          string            `json:"object"`
	Model           string            `json:"model"`
	FineTunedModel  string            `json:"fine_tuned_model,omitempty"`
	OrganizationID  string            `json:"organization_id,omitempty"`
	Status          FineTuneJobStatus `json:"status"`
	TrainingFile    string            `json:"training_file"`
	ValidationFile  string            `json:"validation_file,omitempty"`
	Hyperparameters map[string]any    `json:"hyperparameters,omitempty"`
	ResultFiles     []string          `json:"result_files,omitempty"`
	TrainedTokens   *int64            `json:"trained_tokens,omitempty"`
	CreatedAt       int64             `json:"created_at"`
	FinishedAt      *int64            `json:"finished_at,omitempty"`
	Provider        string            `json:"provider,omitempty"`
	Error           *FineTuneError    `json:"error,omitempty"`
}

// FineTuneError describes why a fine-tuning job failed.
type FineTuneError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// FineTuneEvent is a training progress event.
type FineTuneEvent struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	CreatedAt int64  `json:"created_at"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Type      string `json:"type,omitempty"`
}

// FineTuneListResponse wraps a list of fine-tuning jobs.
type FineTuneListResponse struct {
	Object  string         `json:"object"`
	Data    []*FineTuneJob `json:"data"`
	HasMore bool           `json:"has_more"`
}

// FineTuneStore tracks fine-tuning jobs locally.
type FineTuneStore interface {
	StoreJob(ctx context.Context, job *FineTuneJob) error
	GetJob(ctx context.Context, id string) (*FineTuneJob, error)
	UpdateJob(ctx context.Context, job *FineTuneJob) error
	ListJobs(ctx context.Context, limit int, after string) ([]*FineTuneJob, error)
	DeleteJob(ctx context.Context, id string) error
}

// MemoryFineTuneStore is an in-memory implementation of FineTuneStore.
type MemoryFineTuneStore struct {
	mu    sync.RWMutex
	jobs  map[string]*FineTuneJob
	order []string // insertion order by ID
}

// NewMemoryFineTuneStore creates a new in-memory fine-tune store.
func NewMemoryFineTuneStore() *MemoryFineTuneStore {
	return &MemoryFineTuneStore{
		jobs: make(map[string]*FineTuneJob),
	}
}

// StoreJob stores a fine-tuning job.
func (s *MemoryFineTuneStore) StoreJob(_ context.Context, job *FineTuneJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[job.ID]; exists {
		return fmt.Errorf("job %s already exists", job.ID)
	}
	clone := *job
	s.jobs[job.ID] = &clone
	s.order = append(s.order, job.ID)
	return nil
}

// GetJob retrieves a fine-tuning job by ID.
func (s *MemoryFineTuneStore) GetJob(_ context.Context, id string) (*FineTuneJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, fmt.Errorf("job %s not found", id)
	}
	clone := *job
	return &clone, nil
}

// UpdateJob updates an existing fine-tuning job.
func (s *MemoryFineTuneStore) UpdateJob(_ context.Context, job *FineTuneJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[job.ID]; !exists {
		return fmt.Errorf("job %s not found", job.ID)
	}
	clone := *job
	s.jobs[job.ID] = &clone
	return nil
}

// ListJobs returns jobs in reverse chronological order (newest first).
func (s *MemoryFineTuneStore) ListJobs(_ context.Context, limit int, after string) ([]*FineTuneJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 20
	}

	// Build sorted list by creation time descending.
	sorted := make([]*FineTuneJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		sorted = append(sorted, job)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt > sorted[j].CreatedAt
	})

	// Apply cursor (after).
	startIdx := 0
	if after != "" {
		for i, job := range sorted {
			if job.ID == after {
				startIdx = i + 1
				break
			}
		}
	}

	// Slice.
	end := startIdx + limit
	if end > len(sorted) {
		end = len(sorted)
	}
	if startIdx >= len(sorted) {
		return []*FineTuneJob{}, nil
	}

	result := make([]*FineTuneJob, 0, end-startIdx)
	for _, job := range sorted[startIdx:end] {
		clone := *job
		result = append(result, &clone)
	}
	return result, nil
}

// DeleteJob removes a fine-tuning job from the store.
func (s *MemoryFineTuneStore) DeleteJob(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[id]; !exists {
		return fmt.Errorf("job %s not found", id)
	}
	delete(s.jobs, id)
	n := 0
	for _, oid := range s.order {
		if oid != id {
			s.order[n] = oid
			n++
		}
	}
	s.order = s.order[:n]
	return nil
}

// FineTuneProxy handles fine-tuning API requests.
type FineTuneProxy struct {
	store      FineTuneStore
	httpClient *http.Client
	providers  []*ProviderConfig
}

// NewFineTuneProxy creates a new fine-tuning proxy.
func NewFineTuneProxy(store FineTuneStore, providers []*ProviderConfig) *FineTuneProxy {
	return &FineTuneProxy{
		store:      store,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		providers:  providers,
	}
}

// ServeHTTP routes fine-tuning requests.
//
//	POST   /v1/fine_tuning/jobs                      - create job
//	GET    /v1/fine_tuning/jobs                      - list jobs
//	GET    /v1/fine_tuning/jobs/{id}                 - get job
//	POST   /v1/fine_tuning/jobs/{id}/cancel          - cancel job
//	GET    /v1/fine_tuning/jobs/{id}/events           - get events (forwarded)
//	GET    /v1/fine_tuning/jobs/{id}/checkpoints      - get checkpoints (forwarded)
func (fp *FineTuneProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Normalize path: strip /v1/fine_tuning/jobs prefix.
	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimPrefix(path, "v1/")
	path = strings.TrimPrefix(path, "fine_tuning/")
	path = strings.TrimPrefix(path, "jobs")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" && r.Method == http.MethodPost:
		fp.createJob(w, r)
	case path == "" && r.Method == http.MethodGet:
		fp.listJobs(w, r)
	case !strings.Contains(path, "/") && r.Method == http.MethodGet:
		fp.getJob(w, r, path)
	case strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		jobID := strings.TrimSuffix(path, "/cancel")
		fp.cancelJob(w, r, jobID)
	case strings.HasSuffix(path, "/events") && r.Method == http.MethodGet:
		jobID := strings.TrimSuffix(path, "/events")
		fp.proxyJobSubresource(w, r, jobID, "events")
	case strings.HasSuffix(path, "/checkpoints") && r.Method == http.MethodGet:
		jobID := strings.TrimSuffix(path, "/checkpoints")
		fp.proxyJobSubresource(w, r, jobID, "checkpoints")
	default:
		WriteError(w, ErrMethodNotAllowed())
	}
}

// createJob forwards the create request to the provider and stores the result locally.
func (fp *FineTuneProxy) createJob(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		WriteError(w, ErrInvalidRequest("failed to read request body"))
		return
	}

	var createReq struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &createReq); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	provider := fp.findProvider(createReq.Model)
	if provider == nil {
		WriteError(w, &AIError{
			StatusCode: http.StatusBadRequest,
			Type:       "invalid_request_error",
			Message:    fmt.Sprintf("No provider found for model '%s'.", createReq.Model),
		})
		return
	}

	// Forward to provider.
	providerURL := strings.TrimRight(provider.BaseURL, "/") + "/v1/fine_tuning/jobs"
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, providerURL, bytes.NewReader(body))
	if err != nil {
		WriteError(w, ErrInternal("failed to create provider request"))
		return
	}
	proxyReq.Header.Set("Content-Type", "application/json")
	setProviderAuth(proxyReq, provider)

	resp, err := fp.httpClient.Do(proxyReq)
	if err != nil {
		WriteError(w, ErrProviderUnavailable(provider.Name))
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		WriteError(w, ErrInternal("failed to read provider response"))
		return
	}

	// If provider returned an error, forward it.
	if resp.StatusCode >= 400 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// Parse the job and store locally.
	var job FineTuneJob
	if err := json.Unmarshal(respBody, &job); err != nil {
		slog.Warn("finetune: failed to parse provider response for local tracking", "error", err)
		// Still return the provider response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	job.Provider = provider.Name
	if storeErr := fp.store.StoreJob(r.Context(), &job); storeErr != nil {
		slog.Warn("finetune: failed to store job locally", "job_id", job.ID, "error", storeErr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// getJob returns a locally stored job, optionally refreshing from the provider.
func (fp *FineTuneProxy) getJob(w http.ResponseWriter, r *http.Request, jobID string) {
	job, err := fp.store.GetJob(r.Context(), jobID)
	if err != nil {
		WriteError(w, &AIError{
			StatusCode: http.StatusNotFound,
			Type:       "invalid_request_error",
			Message:    fmt.Sprintf("Fine-tuning job '%s' not found.", jobID),
		})
		return
	}

	// Refresh from provider if the job is still in progress.
	if isActiveStatus(job.Status) && job.Provider != "" {
		if provider := fp.findProviderByName(job.Provider); provider != nil {
			if refreshed, refreshErr := fp.refreshJobFromProvider(r.Context(), provider, jobID); refreshErr == nil {
				refreshed.Provider = job.Provider
				if updateErr := fp.store.UpdateJob(r.Context(), refreshed); updateErr == nil {
					job = refreshed
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// listJobs returns all tracked jobs from the local store.
func (fp *FineTuneProxy) listJobs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || limit <= 0 {
			limit = 20
		}
	}

	after := r.URL.Query().Get("after")

	jobs, err := fp.store.ListJobs(r.Context(), limit, after)
	if err != nil {
		WriteError(w, ErrInternal(fmt.Sprintf("failed to list jobs: %v", err)))
		return
	}

	resp := FineTuneListResponse{
		Object:  "list",
		Data:    jobs,
		HasMore: len(jobs) == limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// cancelJob forwards the cancel request to the provider and updates local state.
func (fp *FineTuneProxy) cancelJob(w http.ResponseWriter, r *http.Request, jobID string) {
	job, err := fp.store.GetJob(r.Context(), jobID)
	if err != nil {
		WriteError(w, &AIError{
			StatusCode: http.StatusNotFound,
			Type:       "invalid_request_error",
			Message:    fmt.Sprintf("Fine-tuning job '%s' not found.", jobID),
		})
		return
	}

	if job.Provider == "" {
		WriteError(w, ErrInternal("job has no associated provider"))
		return
	}

	provider := fp.findProviderByName(job.Provider)
	if provider == nil {
		WriteError(w, ErrProviderUnavailable(job.Provider))
		return
	}

	providerURL := strings.TrimRight(provider.BaseURL, "/") + "/v1/fine_tuning/jobs/" + jobID + "/cancel"
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, providerURL, nil)
	if err != nil {
		WriteError(w, ErrInternal("failed to create cancel request"))
		return
	}
	setProviderAuth(proxyReq, provider)

	resp, err := fp.httpClient.Do(proxyReq)
	if err != nil {
		WriteError(w, ErrProviderUnavailable(provider.Name))
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		WriteError(w, ErrInternal("failed to read cancel response"))
		return
	}

	// Update local state.
	var updatedJob FineTuneJob
	if err := json.Unmarshal(respBody, &updatedJob); err == nil {
		updatedJob.Provider = job.Provider
		if updateErr := fp.store.UpdateJob(r.Context(), &updatedJob); updateErr != nil {
			slog.Warn("finetune: failed to update job after cancel", "job_id", jobID, "error", updateErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// proxyJobSubresource forwards events or checkpoints requests to the provider.
func (fp *FineTuneProxy) proxyJobSubresource(w http.ResponseWriter, r *http.Request, jobID string, subresource string) {
	job, err := fp.store.GetJob(r.Context(), jobID)
	if err != nil {
		WriteError(w, &AIError{
			StatusCode: http.StatusNotFound,
			Type:       "invalid_request_error",
			Message:    fmt.Sprintf("Fine-tuning job '%s' not found.", jobID),
		})
		return
	}

	if job.Provider == "" {
		WriteError(w, ErrInternal("job has no associated provider"))
		return
	}

	provider := fp.findProviderByName(job.Provider)
	if provider == nil {
		WriteError(w, ErrProviderUnavailable(job.Provider))
		return
	}

	fp.proxyToProvider(w, r, provider, fmt.Sprintf("/v1/fine_tuning/jobs/%s/%s", jobID, subresource))
}

// proxyToProvider forwards a request to the appropriate provider.
func (fp *FineTuneProxy) proxyToProvider(w http.ResponseWriter, r *http.Request, provider *ProviderConfig, path string) {
	providerURL := strings.TrimRight(provider.BaseURL, "/") + path

	// Copy query string.
	if r.URL.RawQuery != "" {
		providerURL += "?" + r.URL.RawQuery
	}

	var bodyReader io.Reader
	if r.Body != nil && r.Method != http.MethodGet {
		body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
		if err != nil {
			WriteError(w, ErrInvalidRequest("failed to read request body"))
			return
		}
		bodyReader = bytes.NewReader(body)
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, providerURL, bodyReader)
	if err != nil {
		WriteError(w, ErrInternal("failed to create provider request"))
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		proxyReq.Header.Set("Content-Type", ct)
	}
	setProviderAuth(proxyReq, provider)

	resp, err := fp.httpClient.Do(proxyReq)
	if err != nil {
		WriteError(w, ErrProviderUnavailable(provider.Name))
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		WriteError(w, ErrInternal("failed to read provider response"))
		return
	}

	for k, v := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "content-") || strings.HasPrefix(strings.ToLower(k), "x-") {
			w.Header()[k] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// findProvider finds the first enabled provider that supports the given model.
func (fp *FineTuneProxy) findProvider(model string) *ProviderConfig {
	for _, p := range fp.providers {
		if !p.IsEnabled() {
			continue
		}
		if p.SupportsModel(model) {
			return p
		}
	}
	// If no model-specific match, return the first enabled provider.
	for _, p := range fp.providers {
		if p.IsEnabled() {
			return p
		}
	}
	return nil
}

// findProviderByName finds a provider by its name.
func (fp *FineTuneProxy) findProviderByName(name string) *ProviderConfig {
	for _, p := range fp.providers {
		if p.Name == name && p.IsEnabled() {
			return p
		}
	}
	return nil
}

// refreshJobFromProvider fetches fresh job status from the provider.
func (fp *FineTuneProxy) refreshJobFromProvider(ctx context.Context, provider *ProviderConfig, jobID string) (*FineTuneJob, error) {
	providerURL := strings.TrimRight(provider.BaseURL, "/") + "/v1/fine_tuning/jobs/" + jobID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, providerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	setProviderAuth(req, provider)

	resp, err := fp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("provider returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var job FineTuneJob
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &job, nil
}

// setProviderAuth sets the authentication header on a request for the given provider.
func setProviderAuth(r *http.Request, provider *ProviderConfig) {
	if provider.APIKey == "" {
		return
	}
	header := "Authorization"
	if provider.AuthHeader != "" {
		header = provider.AuthHeader
	}
	prefix := "Bearer "
	if provider.AuthPrefix != "" {
		prefix = provider.AuthPrefix + " "
	}
	r.Header.Set(header, prefix+provider.APIKey)
}

// isActiveStatus returns true if the job status indicates it is still in progress.
func isActiveStatus(status FineTuneJobStatus) bool {
	switch status {
	case FineTuneStatusCreated, FineTuneStatusPending, FineTuneStatusRunning:
		return true
	default:
		return false
	}
}
