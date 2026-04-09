package ai

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryStore_StoreAndGet(t *testing.T) {
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	resp := &ResponseObject{
		ID:        "resp_test1",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    ResponseStatusCompleted,
		Model:     "gpt-4o",
		Output: []OutputItem{
			{
				Type: "message",
				ID:   "msg_1",
				Role: "assistant",
				Content: []ContentItem{
					{Type: "output_text", Text: "Hello!"},
				},
			},
		},
	}

	if err := store.Store(context.Background(), resp); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := store.Get(context.Background(), "resp_test1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got == nil {
		t.Fatal("Expected response, got nil")
	}
	if got.ID != "resp_test1" {
		t.Errorf("Expected ID resp_test1, got %s", got.ID)
	}
	if got.Model != "gpt-4o" {
		t.Errorf("Expected model gpt-4o, got %s", got.Model)
	}
	if got.Status != ResponseStatusCompleted {
		t.Errorf("Expected status completed, got %s", got.Status)
	}
	if len(got.Output) != 1 {
		t.Fatalf("Expected 1 output item, got %d", len(got.Output))
	}
	if got.Output[0].Content[0].Text != "Hello!" {
		t.Errorf("Expected content Hello!, got %s", got.Output[0].Content[0].Text)
	}

	// Get non-existent
	got, err = store.Get(context.Background(), "resp_nonexistent")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != nil {
		t.Error("Expected nil for non-existent response")
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	resp := &ResponseObject{
		ID:        "resp_del",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    ResponseStatusCompleted,
		Model:     "gpt-4o",
	}

	_ = store.Store(context.Background(), resp)

	if err := store.Delete(context.Background(), "resp_del"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	got, _ := store.Get(context.Background(), "resp_del")
	if got != nil {
		t.Error("Expected nil after delete")
	}

	if store.Len() != 0 {
		t.Errorf("Expected store length 0, got %d", store.Len())
	}

	// Delete non-existent should not error
	if err := store.Delete(context.Background(), "resp_nonexistent"); err != nil {
		t.Fatalf("Delete of non-existent should not error: %v", err)
	}
}

func TestMemoryStore_List(t *testing.T) {
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	for i := 0; i < 5; i++ {
		_ = store.Store(context.Background(), &ResponseObject{
			ID:        fmt.Sprintf("resp_%d", i),
			Object:    "response",
			CreatedAt: time.Now().Unix(),
			Status:    ResponseStatusCompleted,
			Model:     "gpt-4o",
		})
	}

	// List all
	results, err := store.List(context.Background(), 20, "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("Expected 5 results, got %d", len(results))
	}
	if results[0].ID != "resp_0" {
		t.Errorf("Expected first result resp_0, got %s", results[0].ID)
	}
	if results[4].ID != "resp_4" {
		t.Errorf("Expected last result resp_4, got %s", results[4].ID)
	}

	// List with limit
	results, err = store.List(context.Background(), 3, "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	// List with after cursor
	results, err = store.List(context.Background(), 20, "resp_2")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 results after resp_2, got %d", len(results))
	}
	if results[0].ID != "resp_3" {
		t.Errorf("Expected first result resp_3, got %s", results[0].ID)
	}
}

func TestMemoryStore_MaxSize(t *testing.T) {
	store := NewMemoryResponseStore(3, time.Hour)
	defer store.Close()

	for i := 0; i < 5; i++ {
		_ = store.Store(context.Background(), &ResponseObject{
			ID:        fmt.Sprintf("resp_%d", i),
			Object:    "response",
			CreatedAt: time.Now().Unix(),
			Status:    ResponseStatusCompleted,
		})
	}

	if store.Len() != 3 {
		t.Errorf("Expected store length 3 after eviction, got %d", store.Len())
	}

	// Oldest entries should have been evicted
	got, _ := store.Get(context.Background(), "resp_0")
	if got != nil {
		t.Error("Expected resp_0 to be evicted")
	}
	got, _ = store.Get(context.Background(), "resp_1")
	if got != nil {
		t.Error("Expected resp_1 to be evicted")
	}

	// Newest should still exist
	got, _ = store.Get(context.Background(), "resp_4")
	if got == nil {
		t.Error("Expected resp_4 to still exist")
	}
}

func TestMemoryStore_TTLExpiry(t *testing.T) {
	// Use a very short TTL for testing
	store := NewMemoryResponseStore(100, 100*time.Millisecond)
	defer store.Close()

	_ = store.Store(context.Background(), &ResponseObject{
		ID:        "resp_old",
		Object:    "response",
		CreatedAt: time.Now().Add(-time.Hour).Unix(), // Created an hour ago
		Status:    ResponseStatusCompleted,
	})

	_ = store.Store(context.Background(), &ResponseObject{
		ID:        "resp_new",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    ResponseStatusCompleted,
	})

	// Manually trigger expiry
	store.expireOld()

	got, _ := store.Get(context.Background(), "resp_old")
	if got != nil {
		t.Error("Expected resp_old to be expired")
	}

	got, _ = store.Get(context.Background(), "resp_new")
	if got == nil {
		t.Error("Expected resp_new to still exist")
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryResponseStore(1000, time.Hour)
	defer store.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("resp_%d", idx)
			_ = store.Store(context.Background(), &ResponseObject{
				ID:        id,
				Object:    "response",
				CreatedAt: time.Now().Unix(),
				Status:    ResponseStatusCompleted,
			})
			_, _ = store.Get(context.Background(), id)
			if idx%3 == 0 {
				_ = store.Delete(context.Background(), id)
			}
		}(i)
	}
	wg.Wait()

	// Verify no panics occurred and store is consistent
	_, err := store.List(context.Background(), 100, "")
	if err != nil {
		t.Fatalf("List after concurrent access failed: %v", err)
	}
}

func TestMemoryStore_Close(t *testing.T) {
	store := NewMemoryResponseStore(100, time.Hour)
	store.Close()
	// Closing again should not panic
	store.Close()
}

func TestMemoryStore_StoreUpdate(t *testing.T) {
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	// Store initial
	_ = store.Store(context.Background(), &ResponseObject{
		ID:        "resp_update",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    ResponseStatusInProgress,
		Model:     "gpt-4o",
	})

	// Update same ID
	_ = store.Store(context.Background(), &ResponseObject{
		ID:        "resp_update",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    ResponseStatusCompleted,
		Model:     "gpt-4o",
	})

	// Should still be one entry
	if store.Len() != 1 {
		t.Errorf("Expected 1 entry after update, got %d", store.Len())
	}

	got, _ := store.Get(context.Background(), "resp_update")
	if got == nil {
		t.Fatal("Expected response after update")
	}
	if got.Status != ResponseStatusCompleted {
		t.Errorf("Expected status completed after update, got %s", got.Status)
	}
}
