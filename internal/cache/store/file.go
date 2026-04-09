// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(DriverFile, NewFileCacher)
}

// FileCacher represents a file cacher.
type FileCacher struct {
	baseDir     string
	maxSize     int64
	compression bool
	mu          sync.RWMutex
	driver      string
}

// File format constants
const (
	// Header format: {expires},{compression}
	// expires: Unix timestamp (int64), 0 means no expiration
	// compression: "none" or "gzip"
	headerFormat    = "%d,%s"
	compressionNone = "none"
	compressionGzip = "gzip"
)

// cacheHeader represents the file header information
type cacheHeader struct {
	expires     int64  // Unix timestamp, 0 means no expiration
	compression string // "none" or "gzip"
}

// safeFilenameRegex matches only safe characters for filenames
var safeFilenameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// writeCacheFile writes data to a cache file with the new header format
func writeCacheFile(filePath string, data []byte, expires time.Time, compression bool) error {
	// Create header
	var header cacheHeader
	if expires.IsZero() {
		header.expires = 0
	} else {
		header.expires = expires.Unix()
	}

	// Determine compression type
	if compression {
		header.compression = compressionGzip
	} else {
		header.compression = compressionNone
	}

	// Format header string
	headerStr := fmt.Sprintf(headerFormat, header.expires, header.compression)
	headerBytes := []byte(headerStr)
	headerLength := len(headerBytes)

	// Prepare data (compress if needed)
	var dataToWrite []byte
	if compression {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("failed to compress data: %w", err)
		}
		if err := writer.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
		dataToWrite = buf.Bytes()
	} else {
		dataToWrite = data
	}

	// Create the file content: {header_length}{header}{data}
	var fileContent bytes.Buffer

	// Write header length (4 bytes, big-endian)
	if err := binary.Write(&fileContent, binary.BigEndian, uint32(headerLength)); err != nil {
		return fmt.Errorf("failed to write header length: %w", err)
	}

	// Write header
	fileContent.Write(headerBytes)

	// Write data
	fileContent.Write(dataToWrite)

	// Write to temporary file first, then rename for atomicity
	tempFile := filePath + ".tmp"
	if err := os.WriteFile(tempFile, fileContent.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	if err := os.Rename(tempFile, filePath); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename cache file: %w", err)
	}

	return nil
}

// readCacheFile reads data from a cache file with the new header format
func readCacheFile(filePath string) ([]byte, time.Time, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, time.Time{}, err
	}

	if len(data) < 4 {
		return nil, time.Time{}, fmt.Errorf("file too short to contain header length")
	}

	// Read header length (first 4 bytes, big-endian)
	headerLength := binary.BigEndian.Uint32(data[:4])

	if len(data) < int(4+headerLength) {
		return nil, time.Time{}, fmt.Errorf("file too short to contain header")
	}

	// Read header
	headerBytes := data[4 : 4+headerLength]
	headerStr := string(headerBytes)

	// Parse header: {expires},{compression}
	var header cacheHeader
	if _, err := fmt.Sscanf(headerStr, headerFormat, &header.expires, &header.compression); err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to parse header: %w", err)
	}

	// Read data
	dataStart := 4 + headerLength
	fileData := data[dataStart:]

	// Handle compression
	if header.compression == compressionGzip {
		reader, err := gzip.NewReader(bytes.NewReader(fileData))
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to decompress data: %w", err)
		}
		fileData = decompressed
	} else if header.compression != compressionNone {
		return nil, time.Time{}, fmt.Errorf("unsupported compression: %s", header.compression)
	}

	// Convert expires timestamp to time.Time
	var expires time.Time
	if header.expires > 0 {
		expires = time.Unix(header.expires, 0)
	}

	return fileData, expires, nil
}

// validateCTypeAndKey validates that cType and key are safe for filesystem use
func validateCTypeAndKey(cType, key string) error {
	if cType == "" {
		return ErrInvalidKey // Using existing error for consistency
	}
	if key == "" {
		return ErrInvalidKey
	}

	// Check for dangerous path traversal attempts
	if strings.Contains(cType, "..") || strings.Contains(key, "..") {
		return ErrInvalidKey
	}

	// Check for path separators
	if strings.Contains(cType, "/") || strings.Contains(cType, "\\") {
		return ErrInvalidKey
	}
	if strings.Contains(key, "/") || strings.Contains(key, "\\") {
		return ErrInvalidKey
	}

	// Check for null bytes
	if strings.Contains(cType, "\x00") || strings.Contains(key, "\x00") {
		return ErrInvalidKey
	}

	// Validate cType format (alphanumeric, dots, underscores, hyphens only)
	if !safeFilenameRegex.MatchString(cType) {
		return ErrInvalidKey
	}

	// Validate key format (alphanumeric, dots, underscores, hyphens only)
	if !safeFilenameRegex.MatchString(key) {
		return ErrInvalidKey
	}

	// Check length limits to prevent excessively long filenames
	if len(cType) > 100 {
		return ErrInvalidKey
	}
	if len(key) > 200 {
		return ErrInvalidKey
	}

	return nil
}

// unsafeCharsRegex matches characters that are not safe for filenames
var unsafeCharsRegex = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeForFilesystem creates a safe filename from cType and key
func sanitizeForFilesystem(cType, key string) string {
	// Replace any remaining unsafe characters with underscores
	safeCType := unsafeCharsRegex.ReplaceAllString(cType, "_")
	safeKey := unsafeCharsRegex.ReplaceAllString(key, "_")

	// Ensure they're not empty after sanitization
	if safeCType == "" {
		safeCType = "default"
	}
	if safeKey == "" {
		safeKey = "default"
	}

	// Limit length
	if len(safeCType) > 50 {
		safeCType = safeCType[:50]
	}
	if len(safeKey) > 100 {
		safeKey = safeKey[:100]
	}

	return fmt.Sprintf("%s_%s", safeCType, safeKey)
}

// Get retrieves a value from the FileCacher.
func (f *FileCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	// Check context timeout
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Validate cType and key for filesystem safety
	if err := validateCTypeAndKey(cType, key); err != nil {
		slog.Error("invalid cType or key", "c_type", cType, "key", key, "error", err)
		return nil, err
	}

	fullKey := sanitizeForFilesystem(cType, key)
	slog.Debug("get", "c_type", cType, "key", key, "full_key", fullKey)

	filePath := f.getFilePath(fullKey)

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check context timeout again after acquiring lock
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, expires, err := readCacheFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Check if expired
	if !expires.IsZero() && time.Now().After(expires) {
		// Remove expired entry
		go f.deleteFile(filePath)
		return nil, ErrNotFound
	}

	return bytes.NewReader(data), nil
}

// Put performs the put operation on the FileCacher.
func (f *FileCacher) Put(ctx context.Context, cType string, key string, data io.Reader) error {
	// Check context timeout
	if err := ctx.Err(); err != nil {
		return err
	}

	// Validate cType and key for filesystem safety
	if err := validateCTypeAndKey(cType, key); err != nil {
		slog.Error("invalid cType or key", "c_type", cType, "key", key, "error", err)
		return err
	}

	fullKey := sanitizeForFilesystem(cType, key)
	slog.Debug("put", "c_type", cType, "key", key, "full_key", fullKey)

	bytes, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	// Check context timeout after reading data
	if err := ctx.Err(); err != nil {
		return err
	}

	err = f.putWithExpires(ctx, fullKey, bytes, time.Time{})
	if err != nil {
		return err
	}

	return nil
}

// PutWithExpires performs the put with expires operation on the FileCacher.
func (f *FileCacher) PutWithExpires(ctx context.Context, cType string, key string, data io.Reader, expires time.Duration) error {
	// Check context timeout
	if err := ctx.Err(); err != nil {
		return err
	}

	// Validate cType and key for filesystem safety
	if err := validateCTypeAndKey(cType, key); err != nil {
		slog.Error("invalid cType or key", "c_type", cType, "key", key, "error", err)
		return err
	}

	fullKey := sanitizeForFilesystem(cType, key)
	slog.Debug("putWithExpires", "c_type", cType, "key", key, "expires", expires, "full_key", fullKey)

	bytes, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	// Check context timeout after reading data
	if err := ctx.Err(); err != nil {
		return err
	}

	var expireTime time.Time
	if expires > 0 {
		expireTime = time.Now().Add(expires)
	}

	err = f.putWithExpires(ctx, fullKey, bytes, expireTime)
	if err != nil {
		return err
	}

	return nil
}

func (f *FileCacher) putWithExpires(ctx context.Context, key string, data []byte, expires time.Time) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check size limit
	if f.maxSize > 0 && int64(len(data)) > f.maxSize {
		return fmt.Errorf("data size %d exceeds max size %d", len(data), f.maxSize)
	}

	filePath := f.getFilePath(key)
	dir := filepath.Dir(filePath)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Use the new header format with compression setting
	return writeCacheFile(filePath, data, expires, f.compression)
}

// Delete performs the delete operation on the FileCacher.
func (f *FileCacher) Delete(ctx context.Context, cType string, key string) error {
	// Validate cType and key for filesystem safety
	if err := validateCTypeAndKey(cType, key); err != nil {
		slog.Error("invalid cType or key", "c_type", cType, "key", key, "error", err)
		return err
	}

	fullKey := sanitizeForFilesystem(cType, key)
	slog.Debug("delete", "c_type", cType, "key", key, "full_key", fullKey)
	filePath := f.getFilePath(fullKey)
	return f.deleteFile(filePath)
}

// DeleteByPattern performs the delete by pattern operation on the FileCacher.
func (f *FileCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	// Validate cType and pattern for filesystem safety
	if err := validateCTypeAndKey(cType, pattern); err != nil {
		slog.Error("invalid cType or pattern", "c_type", cType, "pattern", pattern, "error", err)
		return err
	}

	fullPattern := sanitizeForFilesystem(cType, pattern)
	slog.Debug("deleteByPattern", "c_type", cType, "pattern", pattern, "full_pattern", fullPattern)

	f.mu.Lock()
	defer f.mu.Unlock()

	return filepath.Walk(f.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check if this file is under the prefix
		relPath, err := filepath.Rel(f.baseDir, path)
		if err != nil {
			return err
		}

		// Convert file path back to key
		key := strings.ReplaceAll(relPath, string(os.PathSeparator), ":")
		key = strings.TrimSuffix(key, ".cache")

		// Check if key matches pattern
		if matched, _ := matchPattern(key, fullPattern); matched {
			return os.Remove(path)
		}

		return nil
	})
}

// ListKeys performs the list keys operation on the FileCacher.
func (f *FileCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	// Validate cType and pattern for filesystem safety
	if err := validateCTypeAndKey(cType, pattern); err != nil {
		slog.Error("invalid cType or pattern", "c_type", cType, "pattern", pattern, "error", err)
		return nil, err
	}

	fullPattern := sanitizeForFilesystem(cType, pattern)
	slog.Debug("list keys", "c_type", cType, "pattern", pattern, "full_pattern", fullPattern)

	f.mu.RLock()
	defer f.mu.RUnlock()

	var keys []string
	err := filepath.Walk(f.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check if this file is under the prefix
		relPath, err := filepath.Rel(f.baseDir, path)
		if err != nil {
			return nil
		}

		// Convert file path back to key
		key := strings.ReplaceAll(relPath, string(os.PathSeparator), ":")
		key = strings.TrimSuffix(key, ".cache")

		// Check if key matches pattern
		if matched, _ := matchPattern(key, fullPattern); matched {
			// Extract just the key part (remove cType prefix)
			// The key format is "cType:key" after sanitization
			parts := strings.SplitN(key, ":", 2)
			if len(parts) == 2 && parts[0] == cType {
				keys = append(keys, parts[1])
			}
		}

		return nil
	})

	return keys, err
}

// Increment performs the increment operation on the FileCacher.
func (f *FileCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	// Validate cType and key for filesystem safety
	if err := validateCTypeAndKey(cType, key); err != nil {
		slog.Error("invalid cType or key", "c_type", cType, "key", key, "error", err)
		return 0, err
	}

	fullKey := fmt.Sprintf("%s/%s", cType, key)
	slog.Debug("increment", "c_type", cType, "key", key, "count", count, "full_key", fullKey)

	f.mu.Lock()
	defer f.mu.Unlock()

	filePath := f.getFilePath(fullKey)

	// Read current value
	var currentValue int64
	fileData, expires, err := readCacheFile(filePath)

	if err != nil {
		if !os.IsNotExist(err) {
			return 0, err
		}
		// File doesn't exist, start with 0
		currentValue = 0
	} else {
		// Check if expired
		if !expires.IsZero() && time.Now().After(expires) {
			currentValue = 0
		} else {
			// Try to parse as int64
			if len(fileData) > 0 {
				if _, err := fmt.Sscanf(string(fileData), "%d", &currentValue); err != nil {
					currentValue = 0
				}
			}
		}
	}

	newValue := currentValue + count

	// Store the new value
	valueBytes := []byte(strconv.FormatInt(newValue, 10))
	if err := f.putWithExpires(ctx, fullKey, valueBytes, time.Time{}); err != nil {
		return 0, err
	}

	return newValue, nil
}

// IncrementWithExpires performs the increment with expires operation on the FileCacher.
func (f *FileCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	// Validate cType and key for filesystem safety
	if err := validateCTypeAndKey(cType, key); err != nil {
		slog.Error("invalid cType or key", "c_type", cType, "key", key, "error", err)
		return 0, err
	}

	fullKey := sanitizeForFilesystem(cType, key)
	slog.Debug("incrementWithExpires", "c_type", cType, "key", key, "count", count, "expires", expires, "full_key", fullKey)

	value, err := f.Increment(ctx, cType, key, count)
	if err != nil {
		return 0, err
	}

	// Update expiration
	expireTime := time.Now().Add(expires)
	valueBytes := []byte(strconv.FormatInt(value, 10))
	if err := f.putWithExpires(ctx, fullKey, valueBytes, expireTime); err != nil {
		return 0, err
	}

	return value, nil
}

// Close releases resources held by the FileCacher.
func (f *FileCacher) Close() error {
	slog.Debug("closing file cacher")
	return nil
}

func (f *FileCacher) getFilePath(key string) string {
	// Use the key as the filename, but sanitize it for filesystem safety
	safeKey := filepath.Base(key)
	if safeKey == "." || safeKey == ".." {
		safeKey = "default"
	}
	return filepath.Join(f.baseDir, safeKey+".cache")
}

func (f *FileCacher) deleteFile(filePath string) error {
	return os.Remove(filePath)
}

// NewFileCacher creates and initializes a new FileCacher.
func NewFileCacher(settings Settings) (Cacher, error) {
	// Get base directory from params or use default
	baseDir, ok := settings.Params[SettingBaseDir]
	if !ok {
		baseDir = defaultBaseDir
	}

	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory %s: %w", baseDir, err)
	}

	cacher := &FileCacher{
		baseDir:     baseDir,
		maxSize:     0, // No limit by default
		compression: defaultCompression,
		driver:      settings.Driver,
	}

	// Parse max size if provided
	if maxSizeStr, ok := settings.Params[SettingMaxSize]; ok {
		var maxSize int64
		if _, err := fmt.Sscanf(maxSizeStr, "%d", &maxSize); err != nil {
			return nil, fmt.Errorf("invalid max_size parameter: %w", err)
		}
		cacher.maxSize = maxSize
	}

	// Parse compression setting if provided
	if compressionStr, ok := settings.Params[SettingCompression]; ok {
		switch compressionStr {
		case "true", "1", "yes", "on":
			cacher.compression = true
		case "false", "0", "no", "off":
			cacher.compression = false
		default:
			return nil, fmt.Errorf("invalid compression parameter: %s (expected true/false)", compressionStr)
		}
	}

	slog.Debug("created file cacher", "base_dir", baseDir, "max_size", cacher.maxSize, "compression", cacher.compression)

	return cacher, nil
}


// Driver returns the driver name
func (f *FileCacher) Driver() string {
	return f.driver
}
