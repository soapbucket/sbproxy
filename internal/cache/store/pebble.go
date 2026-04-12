// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
)

// Pebble value prefix flags to distinguish TTL vs non-TTL entries
const (
	pebbleFlagNoTTL  byte = 0x00
	pebbleFlagHasTTL byte = 0x01
)

func init() {
	Register(DriverPebble, NewPebbleCacher)
}

// PebbleCacher represents a pebble cacher.
type PebbleCacher struct {
	db     *pebble.DB
	driver string
}

// Get retrieves a value from the PebbleCacher.
func (p *PebbleCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	skey := cType + "/" + key // cType/key

	// Check if context is already cancelled before starting work
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		data []byte
		done = make(chan error, 1)
	)

	go func() {
		value, closer, err := p.db.Get([]byte(skey))
		if err != nil {
			done <- err
			return
		}
		defer closer.Close()

		// Copy the data since the value is only valid until closer is called
		data = make([]byte, len(value))
		copy(data, value)

		if len(data) == 0 {
			done <- pebble.ErrNotFound
			return
		}

		// Use prefix flag byte to determine if entry has TTL
		flag := data[0]
		data = data[1:] // strip the flag byte

		if flag == pebbleFlagHasTTL && len(data) >= 8 {
			expiresAt := int64(binary.LittleEndian.Uint64(data[:8]))
			if time.Now().Unix() > expiresAt {
				// Expired - delete and return not found
				go func() { _ = p.db.Delete([]byte(skey), pebble.Sync) }()
				done <- pebble.ErrNotFound
				return
			}
			// Not expired - strip the 8-byte timestamp
			data = data[8:]
		}

		done <- nil
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-done:
		if err == pebble.ErrNotFound {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(data), nil
	}
}

// Put performs the put operation on the PebbleCacher.
func (p *PebbleCacher) Put(ctx context.Context, cType string, key string, data io.Reader) error {
	skey := cType + "/" + key // cType/key

	// Check if context is already cancelled before starting work
	if err := ctx.Err(); err != nil {
		return err
	}

	bytes, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	var done = make(chan error, 1)

	go func() {
		// Prefix with no-TTL flag byte
		flagged := make([]byte, 1+len(bytes))
		flagged[0] = pebbleFlagNoTTL
		copy(flagged[1:], bytes)
		done <- p.db.Set([]byte(skey), flagged, pebble.Sync)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// PutWithExpires performs the put with expires operation on the PebbleCacher.
func (p *PebbleCacher) PutWithExpires(ctx context.Context, cType string, key string, data io.Reader, d time.Duration) error {
	skey := cType + "/" + key // cType/key

	// Check if context is already cancelled before starting work
	if err := ctx.Err(); err != nil {
		return err
	}

	bytes, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	var done = make(chan error, 1)

	go func() {
		// Format: [flag=0x01][8-byte unix timestamp][data]
		expiresAt := time.Now().Add(d).Unix()
		valueWithExpiry := make([]byte, 1+8+len(bytes))
		valueWithExpiry[0] = pebbleFlagHasTTL
		binary.LittleEndian.PutUint64(valueWithExpiry[1:9], uint64(expiresAt))
		copy(valueWithExpiry[9:], bytes)

		done <- p.db.Set([]byte(skey), valueWithExpiry, pebble.Sync)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DeleteByPattern performs the delete by pattern operation on the PebbleCacher.
func (p *PebbleCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	spattern := cType + "/" + pattern // cType/pattern

	if len(pattern) < 2 {
		return ErrInvalidPrefix
	}

	// Check if context is already cancelled before starting work
	if err := ctx.Err(); err != nil {
		return err
	}

	var done = make(chan error, 1)

	go func() {
		batch := p.db.NewBatch()
		defer batch.Close()

		// Create iterator with prefix
		prefixBytes := []byte(spattern)
		iter, err := p.db.NewIter(&pebble.IterOptions{
			LowerBound: prefixBytes,
			UpperBound: keyUpperBound(prefixBytes),
		})
		if err != nil {
			done <- err
			return
		}
		defer iter.Close()

		// Iterate and delete keys with the prefix
		for iter.First(); iter.Valid(); iter.Next() {
			// Check for context cancellation periodically
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			default:
			}

			if err := batch.Delete(iter.Key(), pebble.Sync); err != nil {
				done <- err
				return
			}
		}

		if err := iter.Error(); err != nil {
			done <- err
			return
		}

		done <- batch.Commit(pebble.Sync)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// Delete performs the delete operation on the PebbleCacher.
func (p *PebbleCacher) Delete(ctx context.Context, cType string, key string) error {
	skey := cType + "/" + key // cType/key

	// Check if context is already cancelled before starting work
	if err := ctx.Err(); err != nil {
		return err
	}

	var done = make(chan error, 1)

	go func() {
		done <- p.db.Delete([]byte(skey), pebble.Sync)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// ListKeys performs the list keys operation on the PebbleCacher.
func (p *PebbleCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	spattern := cType + "/" + pattern // cType/pattern

	// Check if context is already cancelled before starting work
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		keys []string
		done = make(chan error, 1)
	)

	go func() {
		// Create iterator with prefix
		prefixBytes := []byte(spattern)
		iter, err := p.db.NewIter(&pebble.IterOptions{
			LowerBound: prefixBytes,
			UpperBound: keyUpperBound(prefixBytes),
		})
		if err != nil {
			done <- err
			return
		}
		defer iter.Close()

		// Iterate and collect keys
		for iter.First(); iter.Valid(); iter.Next() {
			// Check for context cancellation periodically
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			default:
			}

			keyBytes := iter.Key()
			keyStr := string(keyBytes)
			
			// Extract just the key part (remove cType prefix)
			// Key format is "cType/key"
			if strings.HasPrefix(keyStr, cType+"/") {
				key := strings.TrimPrefix(keyStr, cType+"/")
				// Check if key matches pattern
				if matched, _ := matchPattern(key, pattern); matched {
					keys = append(keys, key)
				}
			}
		}

		if err := iter.Error(); err != nil {
			done <- err
			return
		}

		done <- nil
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-done:
		return keys, err
	}
}


// Increment performs the increment operation on the PebbleCacher.
func (p *PebbleCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return p.increment(ctx, cType, key, count, 0)
}

// IncrementWithExpires performs the increment with expires operation on the PebbleCacher.
func (p *PebbleCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	return p.increment(ctx, cType, key, count, expires)
}

func (p *PebbleCacher) increment(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	reader, err := p.Get(ctx, cType, key)
	if err != nil && err != ErrNotFound {
		return 0, err
	}

	var value int64
	if reader != nil {
		data, readErr := io.ReadAll(reader)
		if readErr != nil {
			return 0, readErr
		}
		// Get already strips the flag byte and TTL prefix, so data here is the raw value
		if len(data) >= 8 {
			value = int64(binary.LittleEndian.Uint64(data[:8]))
		}
	}

	value += count
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(value))

	if expires > 0 {
		return value, p.PutWithExpires(ctx, cType, key, bytes.NewReader(data), expires)
	}
	return value, p.Put(ctx, cType, key, bytes.NewReader(data))
}

// Close releases resources held by the PebbleCacher.
func (p *PebbleCacher) Close() error {
	slog.Debug("closing pebble connection")
	
	// Close the database
	if err := p.db.Close(); err != nil {
		slog.Error("failed to close database", "error", err)
		return err
	}
	
	slog.Debug("pebble connection closed")
	return nil
}

// newPebbleCacher returns a cacher implementation
func newPebbleCacher(opt *pebble.Options, driver string, path string) (*PebbleCacher, error) {
	slog.Debug("opening pebble connection", "path", path)
	db, err := pebble.Open(path, opt)
	if err != nil {
		return nil, err
	}

	cacher := &PebbleCacher{
		db:     db,
		driver: driver,
	}

	return cacher, nil
}

// NewPebbleCacher creates and initializes a new PebbleCacher.
func NewPebbleCacher(settings Settings) (Cacher, error) {
	var (
		ok  bool
		err error
	)

	path, ok := settings.Params[SettingPath]
	if !ok || path == "" {
		return nil, ErrInvalidConfiguration
	}

	opt := &pebble.Options{
		// Use slog for logging
		Logger: &pebbleLogger{},
		
		// Cache settings (similar to Badger's block and index cache)
		Cache: pebble.NewCache(defaultBlockCacheSize),
		
		// Memory table settings
		MemTableSize:                64 << 20, // 64MB memtable
		MemTableStopWritesThreshold: 4,        // Stop writes when 4 memtables
		
		// Compaction settings
		L0CompactionThreshold: 4, // Similar to NumLevelZeroTables
		L0StopWritesThreshold: 8, // Similar to NumLevelZeroTablesStall
		
		// Disable automatic compactions on close for faster shutdown
		DisableAutomaticCompactions: false,
	}

	// Allow customization through params
	if cacheSize, ok := settings.Params[SettingBlockCacheSize]; ok {
		size, err := strconv.ParseInt(cacheSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid block_cache_size parameter: %w", err)
		}
		opt.Cache = pebble.NewCache(size)
	}

	if memTableSize, ok := settings.Params[SettingMemTableSize]; ok {
		size, err := strconv.ParseUint(memTableSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid mem_table_size parameter: %w", err)
		}
		opt.MemTableSize = size
	}

	if l0Threshold, ok := settings.Params[SettingL0CompactionThreshold]; ok {
		opt.L0CompactionThreshold, err = strconv.Atoi(l0Threshold)
		if err != nil {
			return nil, fmt.Errorf("invalid l0_compaction_threshold parameter: %w", err)
		}
	}

	if l0StopThreshold, ok := settings.Params[SettingL0StopWritesThreshold]; ok {
		opt.L0StopWritesThreshold, err = strconv.Atoi(l0StopThreshold)
		if err != nil {
			return nil, fmt.Errorf("invalid l0_stop_writes_threshold parameter: %w", err)
		}
	}

	return newPebbleCacher(opt, settings.Driver, path)
}

// pebbleLogger implements the pebble.Logger interface
type pebbleLogger struct{}

// Infof performs the infof operation on the pebbleLogger.
func (l *pebbleLogger) Infof(format string, args ...interface{}) {
	// Check if Info level is enabled before formatting to avoid fmt.Sprintf allocation
	// when logging is disabled
	if slog.Default().Enabled(context.Background(), slog.LevelInfo) {
		slog.Info(fmt.Sprintf(format, args...))
	}
}

// Errorf performs the errorf operation on the pebbleLogger.
func (l *pebbleLogger) Errorf(format string, args ...interface{}) {
	// Check if Error level is enabled before formatting to avoid fmt.Sprintf allocation
	// when logging is disabled
	if slog.Default().Enabled(context.Background(), slog.LevelError) {
		slog.Error(fmt.Sprintf(format, args...))
	}
}

// Fatalf performs the fatalf operation on the pebbleLogger.
func (l *pebbleLogger) Fatalf(format string, args ...interface{}) {
	// For fatal errors, we always need the formatted string for panic
	msg := fmt.Sprintf(format, args...)
	slog.Error(msg)
	log.Fatal(msg)
}

// Driver returns the driver name
func (p *PebbleCacher) Driver() string {
	return p.driver
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
	return nil // no upper bound
}

