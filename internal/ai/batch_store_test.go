package ai

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryBatchStore_FilesCRUD(t *testing.T) {
	store := NewMemoryBatchStore(100)
	ctx := context.Background()

	// Create
	file := &FileObject{
		ID:        "file-test-1",
		Object:    "file",
		Bytes:     42,
		CreatedAt: time.Now().Unix(),
		Filename:  "test.jsonl",
		Purpose:   "batch",
	}
	content := []byte("test content")

	err := store.StoreFile(ctx, file, content)
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	// Read metadata
	got, err := store.GetFile(ctx, "file-test-1")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if got.Filename != "test.jsonl" {
		t.Errorf("expected filename 'test.jsonl', got %q", got.Filename)
	}

	// Read content
	data, err := store.GetFileContent(ctx, "file-test-1")
	if err != nil {
		t.Fatalf("GetFileContent: %v", err)
	}
	if string(data) != "test content" {
		t.Errorf("expected 'test content', got %q", string(data))
	}

	// Delete
	err = store.DeleteFile(ctx, "file-test-1")
	if err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	// Verify deleted
	_, err = store.GetFile(ctx, "file-test-1")
	if err == nil {
		t.Error("expected error after delete")
	}

	// Delete nonexistent
	err = store.DeleteFile(ctx, "file-nonexistent")
	if err == nil {
		t.Error("expected error deleting nonexistent file")
	}
}

func TestMemoryBatchStore_BatchCRUD(t *testing.T) {
	store := NewMemoryBatchStore(100)
	ctx := context.Background()

	job := &BatchJob{
		ID:          "batch-test-1",
		Object:      "batch",
		Endpoint:    "/v1/chat/completions",
		InputFileID: "file-1",
		Status:      BatchStatusValidating,
		RequestCounts: BatchCounts{
			Total: 10,
		},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	// Store
	err := store.StoreBatch(ctx, job)
	if err != nil {
		t.Fatalf("StoreBatch: %v", err)
	}

	// Get
	got, err := store.GetBatch(ctx, "batch-test-1")
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if got.Status != BatchStatusValidating {
		t.Errorf("expected status 'validating', got %q", got.Status)
	}

	// Update
	got.Status = BatchStatusInProgress
	err = store.UpdateBatch(ctx, got)
	if err != nil {
		t.Fatalf("UpdateBatch: %v", err)
	}

	updated, _ := store.GetBatch(ctx, "batch-test-1")
	if updated.Status != BatchStatusInProgress {
		t.Errorf("expected status 'in_progress', got %q", updated.Status)
	}

	// List
	jobs, err := store.ListBatches(ctx, 10, "")
	if err != nil {
		t.Fatalf("ListBatches: %v", err)
	}
	if len(jobs) != 1 {
		t.Errorf("expected 1 batch, got %d", len(jobs))
	}

	// Get nonexistent
	_, err = store.GetBatch(ctx, "batch-nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent batch")
	}

	// Update nonexistent
	err = store.UpdateBatch(ctx, &BatchJob{ID: "batch-nonexistent"})
	if err == nil {
		t.Error("expected error updating nonexistent batch")
	}
}

func TestMemoryBatchStore_AppendOutput(t *testing.T) {
	store := NewMemoryBatchStore(100)
	ctx := context.Background()

	batchID := "batch-output-test"

	line1 := &BatchResponseLine{
		ID:       "resp-1",
		CustomID: "req-1",
		Response: &BatchResponseBody{
			StatusCode: 200,
			Body: &ChatCompletionResponse{
				ID:     "chatcmpl-1",
				Object: "chat.completion",
			},
		},
	}
	line2 := &BatchResponseLine{
		ID:       "resp-2",
		CustomID: "req-2",
		Error: &BatchError{
			Code:    "error",
			Message: "test error",
		},
	}

	store.AppendOutput(ctx, batchID, line1)
	store.AppendOutput(ctx, batchID, line2)

	outputs, err := store.GetOutput(ctx, batchID)
	if err != nil {
		t.Fatalf("GetOutput: %v", err)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outputs))
	}
	if outputs[0].CustomID != "req-1" {
		t.Errorf("expected custom_id 'req-1', got %q", outputs[0].CustomID)
	}
	if outputs[1].Error == nil {
		t.Error("expected error on second output")
	}

	// GetOutput for nonexistent batch returns nil
	empty, err := store.GetOutput(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetOutput nonexistent: %v", err)
	}
	if empty != nil {
		t.Errorf("expected nil for nonexistent batch, got %d items", len(empty))
	}
}

func TestMemoryBatchStore_MaxJobs(t *testing.T) {
	store := NewMemoryBatchStore(3)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		err := store.StoreBatch(ctx, &BatchJob{
			ID:     fmt.Sprintf("batch-%d", i),
			Object: "batch",
			Status: BatchStatusValidating,
		})
		if err != nil {
			t.Fatalf("StoreBatch %d: %v", i, err)
		}
	}

	// Fourth should fail
	err := store.StoreBatch(ctx, &BatchJob{
		ID:     "batch-overflow",
		Object: "batch",
		Status: BatchStatusValidating,
	})
	if err == nil {
		t.Error("expected error when exceeding max jobs")
	}
}

func TestMemoryBatchStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryBatchStore(1000)
	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent file writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("file-%d", i)
			store.StoreFile(ctx, &FileObject{
				ID:        id,
				Object:    "file",
				Filename:  fmt.Sprintf("test-%d.jsonl", i),
				Purpose:   "batch",
				CreatedAt: time.Now().Unix(),
			}, []byte("content"))
		}(i)
	}

	// Concurrent batch writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.StoreBatch(ctx, &BatchJob{
				ID:        fmt.Sprintf("batch-%d", i),
				Object:    "batch",
				Status:    BatchStatusValidating,
				CreatedAt: time.Now().Unix(),
			})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.ListFiles(ctx, "")
			store.ListBatches(ctx, 100, "")
		}(i)
	}

	// Concurrent output appends
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.AppendOutput(ctx, "batch-concurrent", &BatchResponseLine{
				ID:       fmt.Sprintf("resp-%d", i),
				CustomID: fmt.Sprintf("req-%d", i),
			})
		}(i)
	}

	wg.Wait()

	// Verify counts
	files, _ := store.ListFiles(ctx, "")
	if len(files) != 50 {
		t.Errorf("expected 50 files, got %d", len(files))
	}

	batches, _ := store.ListBatches(ctx, 100, "")
	if len(batches) != 50 {
		t.Errorf("expected 50 batches, got %d", len(batches))
	}

	outputs, _ := store.GetOutput(ctx, "batch-concurrent")
	if len(outputs) != 50 {
		t.Errorf("expected 50 outputs, got %d", len(outputs))
	}
}

func TestMemoryBatchStore_ListFiles_FilterByPurpose(t *testing.T) {
	store := NewMemoryBatchStore(100)
	ctx := context.Background()

	store.StoreFile(ctx, &FileObject{ID: "f1", Object: "file", Purpose: "batch", CreatedAt: 1}, []byte("a"))
	store.StoreFile(ctx, &FileObject{ID: "f2", Object: "file", Purpose: "batch_output", CreatedAt: 2}, []byte("b"))
	store.StoreFile(ctx, &FileObject{ID: "f3", Object: "file", Purpose: "batch", CreatedAt: 3}, []byte("c"))

	batchFiles, _ := store.ListFiles(ctx, "batch")
	if len(batchFiles) != 2 {
		t.Errorf("expected 2 batch files, got %d", len(batchFiles))
	}

	allFiles, _ := store.ListFiles(ctx, "")
	if len(allFiles) != 3 {
		t.Errorf("expected 3 total files, got %d", len(allFiles))
	}
}

func TestMemoryBatchStore_ListBatches_Pagination(t *testing.T) {
	store := NewMemoryBatchStore(100)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		store.StoreBatch(ctx, &BatchJob{
			ID:        fmt.Sprintf("batch-%d", i),
			Object:    "batch",
			Status:    BatchStatusValidating,
			CreatedAt: int64(100 + i),
		})
	}

	// Get all
	all, _ := store.ListBatches(ctx, 10, "")
	if len(all) != 5 {
		t.Fatalf("expected 5, got %d", len(all))
	}

	// Get page of 2
	page1, _ := store.ListBatches(ctx, 2, "")
	if len(page1) != 2 {
		t.Fatalf("expected 2 in page1, got %d", len(page1))
	}

	// Get next page using the last ID as cursor
	page2, _ := store.ListBatches(ctx, 2, page1[len(page1)-1].ID)
	if len(page2) != 2 {
		t.Fatalf("expected 2 in page2, got %d", len(page2))
	}

	// IDs should not overlap between pages
	for _, p1 := range page1 {
		for _, p2 := range page2 {
			if p1.ID == p2.ID {
				t.Errorf("overlapping batch ID %q between pages", p1.ID)
			}
		}
	}
}
