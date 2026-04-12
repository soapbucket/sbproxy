// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// BatchStore persists batch jobs and files.
type BatchStore interface {
	// File operations
	StoreFile(ctx context.Context, file *FileObject, content []byte) error
	GetFile(ctx context.Context, id string) (*FileObject, error)
	GetFileContent(ctx context.Context, id string) ([]byte, error)
	DeleteFile(ctx context.Context, id string) error
	ListFiles(ctx context.Context, purpose string) ([]*FileObject, error)

	// Batch operations
	StoreBatch(ctx context.Context, job *BatchJob) error
	GetBatch(ctx context.Context, id string) (*BatchJob, error)
	UpdateBatch(ctx context.Context, job *BatchJob) error
	ListBatches(ctx context.Context, limit int, after string) ([]*BatchJob, error)

	// Output operations
	AppendOutput(ctx context.Context, batchID string, line *BatchResponseLine) error
	GetOutput(ctx context.Context, batchID string) ([]*BatchResponseLine, error)
}

// MemoryBatchStore is an in-memory implementation of BatchStore.
type MemoryBatchStore struct {
	mu      sync.RWMutex
	files   map[string]*fileEntry
	batches map[string]*BatchJob
	outputs map[string][]*BatchResponseLine
	maxJobs int
}

type fileEntry struct {
	meta    *FileObject
	content []byte
}

// NewMemoryBatchStore creates a new in-memory batch store.
func NewMemoryBatchStore(maxJobs int) *MemoryBatchStore {
	if maxJobs <= 0 {
		maxJobs = 1000
	}
	return &MemoryBatchStore{
		files:   make(map[string]*fileEntry),
		batches: make(map[string]*BatchJob),
		outputs: make(map[string][]*BatchResponseLine),
		maxJobs: maxJobs,
	}
}

// StoreFile stores a file and its content.
func (s *MemoryBatchStore) StoreFile(_ context.Context, file *FileObject, content []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.files[file.ID] = &fileEntry{
		meta:    file,
		content: content,
	}
	return nil
}

// GetFile returns file metadata.
func (s *MemoryBatchStore) GetFile(_ context.Context, id string) (*FileObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.files[id]
	if !ok {
		return nil, fmt.Errorf("file %q not found", id)
	}
	return entry.meta, nil
}

// GetFileContent returns the raw content of a file.
func (s *MemoryBatchStore) GetFileContent(_ context.Context, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.files[id]
	if !ok {
		return nil, fmt.Errorf("file %q not found", id)
	}
	return entry.content, nil
}

// DeleteFile removes a file.
func (s *MemoryBatchStore) DeleteFile(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.files[id]; !ok {
		return fmt.Errorf("file %q not found", id)
	}
	delete(s.files, id)
	return nil
}

// ListFiles returns all files, optionally filtered by purpose.
func (s *MemoryBatchStore) ListFiles(_ context.Context, purpose string) ([]*FileObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*FileObject
	for _, entry := range s.files {
		if purpose == "" || entry.meta.Purpose == purpose {
			result = append(result, entry.meta)
		}
	}
	// Sort by creation time descending for stable output
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})
	return result, nil
}

// StoreBatch persists a new batch job by storing a copy.
func (s *MemoryBatchStore) StoreBatch(_ context.Context, job *BatchJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.batches) >= s.maxJobs {
		return fmt.Errorf("batch store full: max %d jobs", s.maxJobs)
	}
	cp := *job
	cp.Metadata = copyStringMap(job.Metadata)
	cp.cancelFunc = job.cancelFunc
	s.batches[job.ID] = &cp
	return nil
}

// GetBatch returns a copy of a batch job by ID.
func (s *MemoryBatchStore) GetBatch(_ context.Context, id string) (*BatchJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.batches[id]
	if !ok {
		return nil, fmt.Errorf("batch %q not found", id)
	}
	cp := *job
	cp.Metadata = copyStringMap(job.Metadata)
	if len(job.Errors) > 0 {
		cp.Errors = make([]BatchError, len(job.Errors))
		copy(cp.Errors, job.Errors)
	}
	cp.cancelFunc = job.cancelFunc
	return &cp, nil
}

// UpdateBatch updates an existing batch job by storing a copy.
func (s *MemoryBatchStore) UpdateBatch(_ context.Context, job *BatchJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.batches[job.ID]; !ok {
		return fmt.Errorf("batch %q not found", job.ID)
	}
	cp := *job
	cp.Metadata = copyStringMap(job.Metadata)
	if len(job.Errors) > 0 {
		cp.Errors = make([]BatchError, len(job.Errors))
		copy(cp.Errors, job.Errors)
	}
	cp.cancelFunc = job.cancelFunc
	s.batches[job.ID] = &cp
	return nil
}

// ListBatches returns copies of batch jobs with pagination.
func (s *MemoryBatchStore) ListBatches(_ context.Context, limit int, after string) ([]*BatchJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []*BatchJob
	for _, job := range s.batches {
		cp := *job
		cp.Metadata = copyStringMap(job.Metadata)
		all = append(all, &cp)
	}

	// Sort by creation time descending
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt > all[j].CreatedAt
	})

	// Apply cursor-based pagination
	var result []*BatchJob
	pastCursor := after == ""
	for _, job := range all {
		if !pastCursor {
			if job.ID == after {
				pastCursor = true
			}
			continue
		}
		result = append(result, job)
		if len(result) >= limit {
			break
		}
	}

	return result, nil
}

// AppendOutput adds a response line to a batch job's output.
func (s *MemoryBatchStore) AppendOutput(_ context.Context, batchID string, line *BatchResponseLine) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.outputs[batchID] = append(s.outputs[batchID], line)
	return nil
}

// GetOutput returns all response lines for a batch job.
func (s *MemoryBatchStore) GetOutput(_ context.Context, batchID string) ([]*BatchResponseLine, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	lines, ok := s.outputs[batchID]
	if !ok {
		return nil, nil
	}
	return lines, nil
}

// BatchWorkerPool processes batch jobs using a pool of workers.
type BatchWorkerPool struct {
	store    BatchStore
	executor BatchRequestExecutor
	workers  int
	jobs     chan string
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewBatchWorkerPool creates a new worker pool.
func NewBatchWorkerPool(store BatchStore, executor BatchRequestExecutor, workers int) *BatchWorkerPool {
	if workers <= 0 {
		workers = 2
	}
	return &BatchWorkerPool{
		store:    store,
		executor: executor,
		workers:  workers,
		jobs:     make(chan string, 1000),
		done:     make(chan struct{}),
	}
}

// Start begins processing jobs.
func (p *BatchWorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-p.done:
					return
				case jobID, ok := <-p.jobs:
					if !ok {
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), batchExpiry)
					p.processJob(ctx, jobID)
					cancel()
				}
			}
		}()
	}
}

// Submit adds a job to the processing queue.
func (p *BatchWorkerPool) Submit(jobID string) {
	select {
	case p.jobs <- jobID:
	default:
		logBatchEvent(jobID, "batch worker pool queue full, dropping job")
	}
}

// Stop gracefully stops the worker pool and waits for in-progress jobs to finish.
func (p *BatchWorkerPool) Stop() {
	close(p.done)
	p.wg.Wait()
}

// processJob processes a single batch job: reads input, executes requests, writes output.
func (p *BatchWorkerPool) processJob(ctx context.Context, jobID string) {
	defer func() {
		if r := recover(); r != nil {
			logBatchEvent(jobID, "panic in batch worker", "panic", r)
		}
	}()

	job, err := p.store.GetBatch(ctx, jobID)
	if err != nil {
		logBatchEvent(jobID, "batch job not found", "error", err)
		return
	}

	// Transition to in_progress
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	job.Status = BatchStatusInProgress
	job.cancelFunc = cancel
	if err := p.store.UpdateBatch(ctx, job); err != nil {
		logBatchEvent(jobID, "failed to update batch status", "error", err)
		return
	}

	// Read input file
	content, err := p.store.GetFileContent(ctx, job.InputFileID)
	if err != nil {
		job.Status = BatchStatusFailed
		job.Errors = append(job.Errors, BatchError{
			Code:    "input_file_error",
			Message: fmt.Sprintf("failed to read input file: %v", err),
		})
		_ = p.store.UpdateBatch(ctx, job)
		return
	}

	requests, err := parseBatchRequests(content)
	if err != nil {
		job.Status = BatchStatusFailed
		job.Errors = append(job.Errors, BatchError{
			Code:    "parse_error",
			Message: fmt.Sprintf("failed to parse input file: %v", err),
		})
		_ = p.store.UpdateBatch(ctx, job)
		return
	}

	job.RequestCounts.Total = len(requests)
	_ = p.store.UpdateBatch(ctx, job)

	logBatchEvent(jobID, "batch processing started", "total_requests", len(requests))

	// Process requests sequentially
	for i, batchReq := range requests {
		select {
		case <-jobCtx.Done():
			// Job was cancelled or context expired
			logBatchEvent(jobID, "batch processing cancelled", "completed", i)
			job, _ = p.store.GetBatch(ctx, jobID)
			if job != nil && job.Status != BatchStatusCancelled {
				job.Status = BatchStatusCancelled
				now := time.Now().Unix()
				job.CancelledAt = &now
				_ = p.store.UpdateBatch(ctx, job)
			}
			return
		default:
		}

		respLine := p.executeRequest(jobCtx, batchReq)
		_ = p.store.AppendOutput(ctx, jobID, respLine)

		// Update counts
		job, err = p.store.GetBatch(ctx, jobID)
		if err != nil {
			return
		}
		if respLine.Error != nil {
			job.RequestCounts.Failed++
		} else {
			job.RequestCounts.Completed++
		}
		_ = p.store.UpdateBatch(ctx, job)
	}

	// All done - create output files
	p.finalizeBatch(ctx, job)
}

func (p *BatchWorkerPool) executeRequest(ctx context.Context, batchReq BatchRequest) *BatchResponseLine {
	if batchReq.Body == nil {
		return &BatchResponseLine{
			ID:       generateResponseLineID(),
			CustomID: batchReq.CustomID,
			Error: &BatchError{
				Code:    "invalid_request",
				Message: "request body is required",
			},
		}
	}

	resp, err := p.executor(ctx, batchReq.Body)
	if err != nil {
		return &BatchResponseLine{
			ID:       generateResponseLineID(),
			CustomID: batchReq.CustomID,
			Error: &BatchError{
				Code:    "execution_error",
				Message: err.Error(),
			},
		}
	}

	return &BatchResponseLine{
		ID:       generateResponseLineID(),
		CustomID: batchReq.CustomID,
		Response: &BatchResponseBody{
			StatusCode: 200,
			Body:       resp,
		},
	}
}

func (p *BatchWorkerPool) finalizeBatch(ctx context.Context, job *BatchJob) {
	outputs, err := p.store.GetOutput(ctx, job.ID)
	if err != nil {
		job.Status = BatchStatusFailed
		job.Errors = append(job.Errors, BatchError{
			Code:    "output_error",
			Message: "failed to retrieve outputs",
		})
		_ = p.store.UpdateBatch(ctx, job)
		return
	}

	// Create output file
	outputData, err := buildOutputFile(outputs)
	if err != nil {
		job.Status = BatchStatusFailed
		_ = p.store.UpdateBatch(ctx, job)
		return
	}

	outputFile := &FileObject{
		ID:        generateFileID(),
		Object:    "file",
		Bytes:     int64(len(outputData)),
		CreatedAt: time.Now().Unix(),
		Filename:  "batch_output.jsonl",
		Purpose:   "batch_output",
	}
	_ = p.store.StoreFile(ctx, outputFile, outputData)
	job.OutputFileID = outputFile.ID

	// Create error file if there were failures
	if job.RequestCounts.Failed > 0 {
		errorData, err := buildErrorFile(outputs)
		if err == nil && len(errorData) > 0 {
			errorFile := &FileObject{
				ID:        generateFileID(),
				Object:    "file",
				Bytes:     int64(len(errorData)),
				CreatedAt: time.Now().Unix(),
				Filename:  "batch_errors.jsonl",
				Purpose:   "batch_output",
			}
			_ = p.store.StoreFile(ctx, errorFile, errorData)
			job.ErrorFileID = errorFile.ID
		}
	}

	now := time.Now().Unix()
	job.Status = BatchStatusCompleted
	job.CompletedAt = &now
	_ = p.store.UpdateBatch(ctx, job)

	logBatchEvent(job.ID, "batch processing completed",
		"completed", job.RequestCounts.Completed,
		"failed", job.RequestCounts.Failed,
		"total", job.RequestCounts.Total,
	)
}
