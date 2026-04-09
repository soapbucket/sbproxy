// Package configloader loads and validates proxy configuration from the management API or local files.
package configloader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
)

const failsafeDirEnv = "SB_FAILSAFE_DIR"

type failsafeSnapshot struct {
	Hostname       string                 `json:"hostname"`
	WorkspaceID    string                 `json:"workspace_id,omitempty"`
	Version        string                 `json:"version,omitempty"`
	Revision       string                 `json:"revision,omitempty"`
	SavedAt        time.Time              `json:"saved_at"`
	Payload        []byte                 `json:"payload"`
	FailsafeOrigin *config.FailsafeOrigin `json:"failsafe_origin,omitempty"`
}

type failsafeSnapshotStore struct {
	mu     sync.RWMutex
	dir    string
	byHost map[string]*failsafeSnapshot
}

func newFailsafeSnapshotStore() *failsafeSnapshotStore {
	return &failsafeSnapshotStore{
		dir:    resolveFailsafeSnapshotDir(),
		byHost: make(map[string]*failsafeSnapshot),
	}
}

func resolveFailsafeSnapshotDir() string {
	if dir := os.Getenv(failsafeDirEnv); dir != "" {
		return dir
	}
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "soapbucket", "proxy", "failsafe")
	}
	return filepath.Join(os.TempDir(), "soapbucket-proxy-failsafe")
}

func (s *failsafeSnapshotStore) snapshotPath(hostname string) string {
	sum := sha256.Sum256([]byte(hostname))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

func (s *failsafeSnapshotStore) save(hostname string, workspaceID string, version string, revision string, payload []byte, failsafeOrigin *config.FailsafeOrigin) {
	if hostname == "" || len(payload) == 0 {
		return
	}
	snapshot := &failsafeSnapshot{
		Hostname:       hostname,
		WorkspaceID:    workspaceID,
		Version:        version,
		Revision:       revision,
		SavedAt:        time.Now().UTC(),
		Payload:        append([]byte(nil), payload...),
		FailsafeOrigin: cloneFailsafeOrigin(failsafeOrigin),
	}

	s.mu.Lock()
	s.byHost[hostname] = snapshot
	s.mu.Unlock()

	if s.dir == "" {
		return
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		slog.Warn("failsafe snapshot directory unavailable", "dir", s.dir, "error", err)
		return
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		slog.Warn("failed to marshal failsafe snapshot", "hostname", hostname, "error", err)
		return
	}

	path := s.snapshotPath(hostname)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		slog.Warn("failed to write failsafe snapshot", "hostname", hostname, "path", tmpPath, "error", err)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		slog.Warn("failed to persist failsafe snapshot", "hostname", hostname, "path", path, "error", err)
	}
}

func (s *failsafeSnapshotStore) load(hostname string) (*failsafeSnapshot, bool) {
	if hostname == "" {
		return nil, false
	}

	s.mu.RLock()
	if snapshot, ok := s.byHost[hostname]; ok {
		cloned := cloneFailsafeSnapshot(snapshot)
		s.mu.RUnlock()
		return cloned, true
	}
	s.mu.RUnlock()

	if s.dir == "" {
		return nil, false
	}

	data, err := os.ReadFile(s.snapshotPath(hostname))
	if err != nil {
		return nil, false
	}

	var snapshot failsafeSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		slog.Warn("failed to decode failsafe snapshot", "hostname", hostname, "error", err)
		return nil, false
	}
	if snapshot.Hostname == "" || len(snapshot.Payload) == 0 {
		return nil, false
	}

	s.mu.Lock()
	s.byHost[hostname] = &snapshot
	s.mu.Unlock()

	return cloneFailsafeSnapshot(&snapshot), true
}

func cloneFailsafeSnapshot(snapshot *failsafeSnapshot) *failsafeSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	cloned.Payload = append([]byte(nil), snapshot.Payload...)
	cloned.FailsafeOrigin = cloneFailsafeOrigin(snapshot.FailsafeOrigin)
	return &cloned
}

func cloneFailsafeOrigin(failsafeOrigin *config.FailsafeOrigin) *config.FailsafeOrigin {
	if failsafeOrigin == nil {
		return nil
	}
	cloned := *failsafeOrigin
	cloned.Origin = append([]byte(nil), failsafeOrigin.Origin...)
	return &cloned
}

func (s *failsafeSnapshotStore) resetForTests() {
	s.mu.Lock()
	s.byHost = make(map[string]*failsafeSnapshot)
	s.dir = ""
	s.mu.Unlock()
}

var failsafeSnapshots = newFailsafeSnapshotStore()
