// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/redis/go-redis/v9"
)

func init() {
	Register("pebble", NewPebbleStorage)
}

// PebbleStorage implements the Storage interface using PebbleDB for local persistence
// with REST sync from backend and Redis Streams for real-time updates.
type PebbleStorage struct {
	db                *pebble.DB
	dbPath            string
	remoteURL         string        // backend sync endpoint
	clusterID         string        // optional cluster scoping for dedicated/private sync
	sharedSecret      string        // PROXY_SECRET_KEY for HMAC signing
	syncInterval      time.Duration // periodic sync interval
	configSyncMode    string        // "push" (Redis + REST), "pull" (REST only), "hybrid" (both, default)
	redisClient       *redis.Client
	syncClient        *http.Client
	bloomFilter       interface{ Add(string) } // will be set by config loader
	syncURL           string // pre-computed sync URL with cluster_id
	mu                sync.RWMutex
	done              chan struct{}
	driver            string
	wipeOnStart       bool
	strictStartupSync bool
}

// OriginListResponse represents the response from a origin list operation.
type OriginListResponse struct {
	Origins   []json.RawMessage `json:"origins"`
	Count     int               `json:"count"`
	Timestamp string            `json:"timestamp"`
}

// NewPebbleStorage creates a new PebbleDB storage driver
func NewPebbleStorage(settings Settings) (Storage, error) {
	path, ok := settings.Params[ParamPath]
	if !ok || path == "" {
		return nil, fmt.Errorf("pebble storage: path parameter required")
	}

	remoteURL, ok := settings.Params["remote_url"]
	if !ok || remoteURL == "" {
		return nil, fmt.Errorf("pebble storage: remote_url parameter required")
	}

	sharedSecret, ok := settings.Params["shared_secret"]
	if !ok || sharedSecret == "" {
		return nil, fmt.Errorf("pebble storage: shared_secret parameter required")
	}

	syncIntervalStr := settings.Params["sync_interval"]
	if syncIntervalStr == "" {
		syncIntervalStr = "5m" // default 5 minutes
	}
	syncInterval, err := time.ParseDuration(syncIntervalStr)
	if err != nil {
		return nil, fmt.Errorf("pebble storage: invalid sync_interval: %w", err)
	}

	configSyncMode := settings.Params["config_sync_mode"]
	if configSyncMode == "" {
		configSyncMode = "hybrid"
	}

	var redisClient *redis.Client
	if configSyncMode != "pull" {
		redisURL := settings.Params["redis_url"]
		if redisURL != "" {
			opt, err := redis.ParseURL(redisURL)
			if err != nil {
				return nil, fmt.Errorf("pebble storage: invalid redis_url: %w", err)
			}
			redisClient = redis.NewClient(opt)
		}
	}

	wipeOnStart := settings.Params["wipe_on_start"] == "true"
	strictStartupSync := settings.Params["strict_startup_sync"] == "true"

	ps := &PebbleStorage{
		dbPath:            path,
		remoteURL:         remoteURL,
		clusterID:         settings.Params["cluster_id"],
		sharedSecret:      sharedSecret,
		syncInterval:      syncInterval,
		configSyncMode:    configSyncMode,
		redisClient:       redisClient,
		syncClient:        &http.Client{Timeout: 30 * time.Second},
		done:              make(chan struct{}),
		driver:            "pebble",
		wipeOnStart:       wipeOnStart,
		strictStartupSync: strictStartupSync,
	}

	ps.syncURL = ps.computeSyncURL()

	return ps, nil
}

// Start initializes the storage: deletes old DB, opens PebbleDB, syncs from backend,
// populates bloom filter, and starts background sync + Redis listener goroutines.
func (ps *PebbleStorage) Start(ctx context.Context) error {
	slog.Info("starting pebble storage", "path", ps.dbPath)

	// 1. Prepare the database directory. Preserve existing state by default.
	if ps.wipeOnStart {
		if err := os.RemoveAll(ps.dbPath); err != nil {
			slog.Error("failed to remove old pebble db directory", "path", ps.dbPath, "error", err)
			return err
		}
	}
	if err := os.MkdirAll(ps.dbPath, 0755); err != nil {
		slog.Error("failed to create pebble db directory", "path", ps.dbPath, "error", err)
		return err
	}

	// 2. Open PebbleDB
	db, err := pebble.Open(ps.dbPath, &pebble.Options{
		Logger: &pebbleLogger{},
		Cache:  pebble.NewCache(64 << 20), // 64MB cache
	})
	if err != nil {
		slog.Error("failed to open pebble db", "path", ps.dbPath, "error", err)
		return err
	}
	ps.db = db

	// 3. Initial full sync from backend
	if err := ps.syncFromBackend(ctx); err != nil {
		slog.Error("initial sync from backend failed", "error", err)
		if ps.strictStartupSync {
			return err
		}
	}

	// 4. Populate bloom filter from local storage
	if ps.bloomFilter != nil {
		keys, err := ps.ListKeys(ctx)
		if err == nil {
			for _, key := range keys {
				ps.bloomFilter.Add(key)
			}
			slog.Info("populated bloom filter", "count", len(keys))
		} else {
			slog.Error("failed to populate bloom filter", "error", err)
		}
	}

	// 5. Start periodic sync goroutine
	go ps.periodicSync()

	// 6. Start Redis Streams listener if Redis is configured and sync mode allows push
	if ps.redisClient != nil && ps.configSyncMode != "pull" {
		go ps.listenRedisStreams(ctx)
	}

	slog.Info("pebble storage started successfully", "sync_mode", ps.configSyncMode, "sync_interval", ps.syncInterval)
	return nil
}

// periodicSync runs the REST sync on a timer
func (ps *PebbleStorage) periodicSync() {
	ticker := time.NewTicker(ps.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ps.done:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := ps.syncFromBackend(ctx); err != nil {
				slog.Error("periodic sync failed", "error", err)
			}
			cancel()
		}
	}
}

// syncFromBackend fetches all origins from backend REST endpoint, validates HMAC signature,
// and batches them into PebbleDB.
func (ps *PebbleStorage) syncFromBackend(ctx context.Context) error {
	// Create signed request
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	path := "/api/v1/origins/sync/"
	signature := ps.createHMAC(timestamp, path)

	req, err := http.NewRequestWithContext(ctx, "GET", ps.syncRequestURL(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("User-Agent", "SoapBucket-Proxy/1.0")

	client := ps.syncClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sync request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("sync endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var respData OriginListResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Batch write origins to PebbleDB
	batch := ps.db.NewBatch()
	defer batch.Close()

	for _, originJSON := range respData.Origins {
		var origin struct {
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(originJSON, &origin); err != nil {
			slog.Warn("failed to unmarshal origin", "error", err)
			continue
		}

		if err := batch.Set([]byte(origin.Hostname), originJSON, pebble.NoSync); err != nil {
			slog.Error("failed to write origin to batch", "hostname", origin.Hostname, "error", err)
			continue
		}
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("batch commit failed: %w", err)
	}

	slog.Info("synced origins from backend", "count", respData.Count)
	return nil
}

// createHMAC creates an HMAC-SHA256 signature for timestamp:path
func (ps *PebbleStorage) createHMAC(timestamp, path string) string {
	h := hmac.New(sha256.New, []byte(ps.sharedSecret))
	io.WriteString(h, timestamp)
	io.WriteString(h, ":")
	io.WriteString(h, path)
	return hex.EncodeToString(h.Sum(nil))
}

func (ps *PebbleStorage) syncRequestURL() string {
	if ps.syncURL != "" {
		return ps.syncURL
	}
	return ps.computeSyncURL()
}

func (ps *PebbleStorage) computeSyncURL() string {
	if ps.clusterID == "" {
		return ps.remoteURL
	}

	parsedURL, err := url.Parse(ps.remoteURL)
	if err != nil {
		return ps.remoteURL
	}

	query := parsedURL.Query()
	query.Set("cluster_id", ps.clusterID)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// listenRedisStreams subscribes to Redis Streams for real-time origin updates
func (ps *PebbleStorage) listenRedisStreams(ctx context.Context) {
	streams := []string{"origins:created", "origins:updated", "origins:deleted"}
	groupName := "proxy"
	consumer := "proxy-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Try to create consumer group (ignore if exists)
	for _, stream := range streams {
		ps.redisClient.XGroupCreateMkStream(ctx, stream, groupName, "$").Val()
	}

	for {
		select {
		case <-ps.done:
			return
		default:
		}

		results, err := ps.redisClient.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    groupName,
			Consumer: consumer,
			Streams:  append(streams, ">", ">", ">"),
			Block:    time.Second,
		}).Result()

		if err != nil && err != redis.Nil {
			slog.Error("redis read group error", "error", err)
			time.Sleep(time.Second)
			continue
		}

		if len(results) == 0 {
			continue
		}

		for _, result := range results {
			for _, msg := range result.Messages {
				ps.handleRedisStreamMessage(ctx, result.Stream, msg)
				ps.redisClient.XAck(ctx, result.Stream, groupName, msg.ID)
			}
		}
	}
}

// handleRedisStreamMessage processes a single Redis Streams message
func (ps *PebbleStorage) handleRedisStreamMessage(ctx context.Context, stream string, msg redis.XMessage) {
	hostname, ok := msg.Values["hostname"].(string)
	if !ok || hostname == "" {
		slog.Warn("invalid redis message: missing hostname", "stream", stream, "id", msg.ID)
		return
	}

	switch stream {
	case "origins:created", "origins:updated":
		configStr, ok := msg.Values["config"].(string)
		if !ok {
			slog.Warn("missing config in redis message", "hostname", hostname)
			return
		}
		if err := ps.Put(ctx, hostname, []byte(configStr)); err != nil {
			slog.Error("failed to put origin from redis", "hostname", hostname, "error", err)
		}
		if ps.bloomFilter != nil {
			ps.bloomFilter.Add(hostname)
		}
	case "origins:deleted":
		if err := ps.Delete(ctx, hostname); err != nil {
			slog.Error("failed to delete origin from redis", "hostname", hostname, "error", err)
		}
	}
}

// Get retrieves an origin config by hostname
func (ps *PebbleStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, closer, err := ps.db.Get([]byte(key))
	if err == pebble.ErrNotFound {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	cp := make([]byte, len(value))
	copy(cp, value)
	return cp, nil
}

// GetByID retrieves an origin config by ID (requires scanning)
func (ps *PebbleStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	iter, err := ps.db.NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		var origin struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(iter.Value(), &origin); err != nil {
			continue
		}
		if origin.ID == id {
			cp := make([]byte, len(iter.Value()))
			copy(cp, iter.Value())
			return cp, nil
		}
	}

	return nil, ErrKeyNotFound
}

// ListKeys returns all hostnames stored in PebbleDB
func (ps *PebbleStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	iter, err := ps.db.NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var keys []string
	for iter.First(); iter.Valid(); iter.Next() {
		keys = append(keys, string(iter.Key()))
	}

	sort.Strings(keys)
	return keys, nil
}

// ListKeysByWorkspace returns hostnames belonging to a specific workspace.
func (ps *PebbleStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	iter, err := ps.db.NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var keys []string
	for iter.First(); iter.Valid(); iter.Next() {
		var meta struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if json.Unmarshal(iter.Value(), &meta) == nil && meta.WorkspaceID == workspaceID {
			keys = append(keys, string(iter.Key()))
		}
	}

	sort.Strings(keys)
	return keys, nil
}

// Put stores or updates an origin config
func (ps *PebbleStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	return ps.db.Set([]byte(key), cp, pebble.Sync)
}

// Delete removes an origin config by hostname
func (ps *PebbleStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return ps.db.Delete([]byte(key), pebble.Sync)
}

// DeleteByPrefix removes all origins matching a prefix
func (ps *PebbleStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(prefix),
		UpperBound: keyUpperBound([]byte(prefix)),
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	batch := ps.db.NewBatch()
	defer batch.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if err := batch.Delete(iter.Key(), pebble.Sync); err != nil {
			return err
		}
	}

	return batch.Commit(pebble.Sync)
}

// ValidateProxyAPIKey delegates to HTTP backend
func (ps *PebbleStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	// Extract base URL without query params
	baseURL := ps.remoteURL
	if idx := bytes.IndexByte([]byte(baseURL), '?'); idx > 0 {
		baseURL = baseURL[:idx]
	}

	url := fmt.Sprintf("%s/origins/%s/proxy-keys/validate/", baseURL, originID)

	payload := map[string]string{"key": apiKey}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("invalid proxy API key")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validation endpoint returned %d", resp.StatusCode)
	}

	var result struct {
		KeyID   string `json:"key_id"`
		KeyName string `json:"key_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &ProxyKeyValidationResult{
		ProxyKeyID:   result.KeyID,
		ProxyKeyName: result.KeyName,
	}, nil
}

// Driver returns the driver name
func (ps *PebbleStorage) Driver() string {
	return ps.driver
}

// Close closes the PebbleDB instance and stops background goroutines
func (ps *PebbleStorage) Close() error {
	slog.Info("closing pebble storage")
	close(ps.done)

	if ps.db != nil {
		if err := ps.db.Close(); err != nil {
			slog.Error("failed to close pebble db", "error", err)
			return err
		}
	}

	if ps.redisClient != nil {
		if err := ps.redisClient.Close(); err != nil {
			slog.Error("failed to close redis client", "error", err)
		}
	}

	slog.Info("pebble storage closed")
	return nil
}

// SetBloomFilter allows the config loader to set the bloom filter for population
func (ps *PebbleStorage) SetBloomFilter(bf interface{ Add(string) }) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.bloomFilter = bf
}

// pebbleLogger implements the pebble.Logger interface
type pebbleLogger struct{}

// Infof performs the infof operation on the pebbleLogger.
func (l *pebbleLogger) Infof(format string, args ...interface{}) {
	if slog.Default().Enabled(context.Background(), slog.LevelInfo) {
		slog.Info(fmt.Sprintf(format, args...))
	}
}

// Errorf performs the errorf operation on the pebbleLogger.
func (l *pebbleLogger) Errorf(format string, args ...interface{}) {
	if slog.Default().Enabled(context.Background(), slog.LevelError) {
		slog.Error(fmt.Sprintf(format, args...))
	}
}

// Fatalf performs the fatalf operation on the pebbleLogger.
func (l *pebbleLogger) Fatalf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	slog.Error("pebble fatal error", "message", msg)
}

// keyUpperBound returns the upper bound for a prefix
func keyUpperBound(b []byte) []byte {
	end := make([]byte, len(b))
	copy(end, b)
	for i := len(end) - 1; i >= 0; i-- {
		end[i] = end[i] + 1
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}
