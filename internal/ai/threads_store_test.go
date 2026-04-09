package ai

import (
	"sync"
	"testing"
)

func TestMemoryThreadStoreOperations(t *testing.T) {
	store := NewMemoryThreadStore()
	ctx := t.Context()

	t.Run("create and get thread", func(t *testing.T) {
		thread := &Thread{ID: "thread_abc", Object: "thread", CreatedAt: 1700000000}
		if err := store.CreateThread(ctx, thread); err != nil {
			t.Fatalf("create thread: %v", err)
		}
		got, err := store.GetThread(ctx, "thread_abc")
		if err != nil {
			t.Fatalf("get thread: %v", err)
		}
		if got.ID != "thread_abc" {
			t.Errorf("expected id=thread_abc, got %s", got.ID)
		}
	})

	t.Run("create duplicate thread", func(t *testing.T) {
		thread := &Thread{ID: "thread_abc", Object: "thread"}
		if err := store.CreateThread(ctx, thread); err == nil {
			t.Error("expected error for duplicate thread")
		}
	})

	t.Run("get nonexistent thread", func(t *testing.T) {
		_, err := store.GetThread(ctx, "thread_nope")
		if err == nil {
			t.Error("expected error for nonexistent thread")
		}
	})

	t.Run("add and list messages", func(t *testing.T) {
		msg1 := &ThreadMessage{ID: "msg_1", Object: "thread.message", ThreadID: "thread_abc", Role: "user"}
		msg2 := &ThreadMessage{ID: "msg_2", Object: "thread.message", ThreadID: "thread_abc", Role: "assistant"}
		store.AddMessage(ctx, "thread_abc", msg1)
		store.AddMessage(ctx, "thread_abc", msg2)

		msgs, err := store.ListMessages(ctx, "thread_abc", 100, 0)
		if err != nil {
			t.Fatalf("list messages: %v", err)
		}
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(msgs))
		}
		if msgs[0].ID != "msg_1" || msgs[1].ID != "msg_2" {
			t.Errorf("messages not in order: %s, %s", msgs[0].ID, msgs[1].ID)
		}
	})

	t.Run("list messages pagination", func(t *testing.T) {
		msgs, _ := store.ListMessages(ctx, "thread_abc", 1, 0)
		if len(msgs) != 1 || msgs[0].ID != "msg_1" {
			t.Errorf("expected first message, got %v", msgs)
		}
		msgs, _ = store.ListMessages(ctx, "thread_abc", 1, 1)
		if len(msgs) != 1 || msgs[0].ID != "msg_2" {
			t.Errorf("expected second message, got %v", msgs)
		}
		msgs, _ = store.ListMessages(ctx, "thread_abc", 10, 5)
		if len(msgs) != 0 {
			t.Errorf("expected empty with large offset, got %d", len(msgs))
		}
	})

	t.Run("add message to nonexistent thread", func(t *testing.T) {
		msg := &ThreadMessage{ID: "msg_x", ThreadID: "thread_nope"}
		if err := store.AddMessage(ctx, "thread_nope", msg); err == nil {
			t.Error("expected error for nonexistent thread")
		}
	})

	t.Run("create and get run", func(t *testing.T) {
		run := &Run{ID: "run_1", Object: "thread.run", ThreadID: "thread_abc", Status: "queued"}
		if err := store.CreateRun(ctx, "thread_abc", run); err != nil {
			t.Fatalf("create run: %v", err)
		}
		got, err := store.GetRun(ctx, "thread_abc", "run_1")
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if got.Status != "queued" {
			t.Errorf("expected status=queued, got %s", got.Status)
		}
	})

	t.Run("get nonexistent run", func(t *testing.T) {
		_, err := store.GetRun(ctx, "thread_abc", "run_nope")
		if err == nil {
			t.Error("expected error for nonexistent run")
		}
	})

	t.Run("update run", func(t *testing.T) {
		updated, err := store.UpdateRun(ctx, "thread_abc", "run_1", map[string]any{
			"status": "in_progress",
			"usage":  &RunUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
		})
		if err != nil {
			t.Fatalf("update run: %v", err)
		}
		if updated.Status != "in_progress" {
			t.Errorf("expected status=in_progress, got %s", updated.Status)
		}
		if updated.Usage == nil || updated.Usage.TotalTokens != 15 {
			t.Errorf("expected usage with 15 total tokens, got %v", updated.Usage)
		}
	})

	t.Run("update nonexistent run", func(t *testing.T) {
		_, err := store.UpdateRun(ctx, "thread_abc", "run_nope", map[string]any{"status": "failed"})
		if err == nil {
			t.Error("expected error for nonexistent run")
		}
	})

	t.Run("list runs", func(t *testing.T) {
		// Add a second run.
		store.CreateRun(ctx, "thread_abc", &Run{ID: "run_2", Object: "thread.run", ThreadID: "thread_abc", Status: "queued"})
		runs, err := store.ListRuns(ctx, "thread_abc", 100, 0)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		if len(runs) != 2 {
			t.Errorf("expected 2 runs, got %d", len(runs))
		}
	})

	t.Run("list runs pagination", func(t *testing.T) {
		runs, _ := store.ListRuns(ctx, "thread_abc", 1, 0)
		if len(runs) != 1 {
			t.Errorf("expected 1 run with limit=1, got %d", len(runs))
		}
	})

	t.Run("delete thread removes messages and runs", func(t *testing.T) {
		if err := store.DeleteThread(ctx, "thread_abc"); err != nil {
			t.Fatalf("delete thread: %v", err)
		}
		_, err := store.GetThread(ctx, "thread_abc")
		if err == nil {
			t.Error("expected error after delete")
		}
		_, err = store.ListMessages(ctx, "thread_abc", 10, 0)
		if err == nil {
			t.Error("expected error listing messages for deleted thread")
		}
		_, err = store.ListRuns(ctx, "thread_abc", 10, 0)
		if err == nil {
			t.Error("expected error listing runs for deleted thread")
		}
	})

	t.Run("delete nonexistent thread", func(t *testing.T) {
		if err := store.DeleteThread(ctx, "thread_nope"); err == nil {
			t.Error("expected error for nonexistent thread")
		}
	})
}

func TestMemoryThreadStoreConcurrentAccess(t *testing.T) {
	store := NewMemoryThreadStore()
	ctx := t.Context()

	// Create a thread for concurrent operations.
	thread := &Thread{ID: "thread_conc", Object: "thread", CreatedAt: 1700000000}
	if err := store.CreateThread(ctx, thread); err != nil {
		t.Fatalf("create thread: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent message additions.
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			msgID, _ := generateID("msg_")
			msg := &ThreadMessage{
				ID:       msgID,
				Object:   "thread.message",
				ThreadID: "thread_conc",
				Role:     "user",
			}
			store.AddMessage(ctx, "thread_conc", msg)
		}(i)
	}
	wg.Wait()

	msgs, err := store.ListMessages(ctx, "thread_conc", 1000, 0)
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	if len(msgs) != goroutines {
		t.Errorf("expected %d messages, got %d", goroutines, len(msgs))
	}

	// Concurrent run creation.
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			runID, _ := generateID("run_")
			run := &Run{
				ID:       runID,
				Object:   "thread.run",
				ThreadID: "thread_conc",
				Status:   "queued",
			}
			store.CreateRun(ctx, "thread_conc", run)
		}()
	}
	wg.Wait()

	runs, err := store.ListRuns(ctx, "thread_conc", 1000, 0)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != goroutines {
		t.Errorf("expected %d runs, got %d", goroutines, len(runs))
	}

	// Concurrent reads while writing.
	wg.Add(goroutines * 2)
	for range goroutines {
		go func() {
			defer wg.Done()
			store.ListMessages(ctx, "thread_conc", 100, 0)
		}()
		go func() {
			defer wg.Done()
			msgID, _ := generateID("msg_")
			msg := &ThreadMessage{
				ID:       msgID,
				Object:   "thread.message",
				ThreadID: "thread_conc",
				Role:     "user",
			}
			store.AddMessage(ctx, "thread_conc", msg)
		}()
	}
	wg.Wait()
}
