// threads_store.go defines the ThreadStore interface and its in-memory implementation.
package ai

import (
	"context"
	"fmt"
	"sync"
)

// ThreadStore defines operations for thread, message, and run persistence.
type ThreadStore interface {
	CreateThread(ctx context.Context, t *Thread) error
	GetThread(ctx context.Context, id string) (*Thread, error)
	DeleteThread(ctx context.Context, id string) error
	AddMessage(ctx context.Context, threadID string, m *ThreadMessage) error
	ListMessages(ctx context.Context, threadID string, limit, offset int) ([]*ThreadMessage, error)
	CreateRun(ctx context.Context, threadID string, run *Run) error
	GetRun(ctx context.Context, threadID, runID string) (*Run, error)
	UpdateRun(ctx context.Context, threadID, runID string, updates map[string]any) (*Run, error)
	ListRuns(ctx context.Context, threadID string, limit, offset int) ([]*Run, error)
}

// MemoryThreadStore is an in-memory thread store safe for concurrent access.
type MemoryThreadStore struct {
	mu       sync.RWMutex
	threads  map[string]*Thread
	messages map[string][]*ThreadMessage // keyed by thread ID
	runs     map[string][]*Run           // keyed by thread ID
}

// NewMemoryThreadStore creates a new in-memory thread store.
func NewMemoryThreadStore() *MemoryThreadStore {
	return &MemoryThreadStore{
		threads:  make(map[string]*Thread),
		messages: make(map[string][]*ThreadMessage),
		runs:     make(map[string][]*Run),
	}
}

func (s *MemoryThreadStore) CreateThread(_ context.Context, t *Thread) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.threads[t.ID]; exists {
		return fmt.Errorf("thread %s already exists", t.ID)
	}
	s.threads[t.ID] = t
	s.messages[t.ID] = []*ThreadMessage{}
	s.runs[t.ID] = []*Run{}
	return nil
}

func (s *MemoryThreadStore) GetThread(_ context.Context, id string) (*Thread, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.threads[id]
	if !ok {
		return nil, fmt.Errorf("thread %s not found", id)
	}
	return t, nil
}

func (s *MemoryThreadStore) DeleteThread(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.threads[id]; !ok {
		return fmt.Errorf("thread %s not found", id)
	}
	delete(s.threads, id)
	delete(s.messages, id)
	delete(s.runs, id)
	return nil
}

func (s *MemoryThreadStore) AddMessage(_ context.Context, threadID string, m *ThreadMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.threads[threadID]; !ok {
		return fmt.Errorf("thread %s not found", threadID)
	}
	s.messages[threadID] = append(s.messages[threadID], m)
	return nil
}

func (s *MemoryThreadStore) ListMessages(_ context.Context, threadID string, limit, offset int) ([]*ThreadMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.threads[threadID]; !ok {
		return nil, fmt.Errorf("thread %s not found", threadID)
	}
	msgs := s.messages[threadID]
	total := len(msgs)
	if offset >= total {
		return []*ThreadMessage{}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	result := make([]*ThreadMessage, end-offset)
	copy(result, msgs[offset:end])
	return result, nil
}

func (s *MemoryThreadStore) CreateRun(_ context.Context, threadID string, run *Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.threads[threadID]; !ok {
		return fmt.Errorf("thread %s not found", threadID)
	}
	s.runs[threadID] = append(s.runs[threadID], run)
	return nil
}

func (s *MemoryThreadStore) GetRun(_ context.Context, threadID, runID string) (*Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	runs, ok := s.runs[threadID]
	if !ok {
		return nil, fmt.Errorf("thread %s not found", threadID)
	}
	for _, r := range runs {
		if r.ID == runID {
			return r, nil
		}
	}
	return nil, fmt.Errorf("run %s not found in thread %s", runID, threadID)
}

func (s *MemoryThreadStore) UpdateRun(_ context.Context, threadID, runID string, updates map[string]any) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, ok := s.runs[threadID]
	if !ok {
		return nil, fmt.Errorf("thread %s not found", threadID)
	}
	for _, r := range runs {
		if r.ID == runID {
			if v, ok := updates["status"]; ok {
				if s, ok := v.(string); ok {
					r.Status = s
				}
			}
			if v, ok := updates["started_at"]; ok {
				if ts, ok := v.(int64); ok {
					r.StartedAt = ts
				}
			}
			if v, ok := updates["completed_at"]; ok {
				if ts, ok := v.(int64); ok {
					r.CompletedAt = ts
				}
			}
			if v, ok := updates["failed_at"]; ok {
				if ts, ok := v.(int64); ok {
					r.FailedAt = ts
				}
			}
			if v, ok := updates["usage"]; ok {
				if u, ok := v.(*RunUsage); ok {
					r.Usage = u
				}
			}
			return r, nil
		}
	}
	return nil, fmt.Errorf("run %s not found in thread %s", runID, threadID)
}

func (s *MemoryThreadStore) ListRuns(_ context.Context, threadID string, limit, offset int) ([]*Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.threads[threadID]; !ok {
		return nil, fmt.Errorf("thread %s not found", threadID)
	}
	runs := s.runs[threadID]
	total := len(runs)
	if offset >= total {
		return []*Run{}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	result := make([]*Run, end-offset)
	copy(result, runs[offset:end])
	return result, nil
}
