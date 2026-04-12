// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MetricsStorage wraps a Storage with metrics collection
type MetricsStorage struct {
	Storage
	driver string
}

// NewMetricsStorage creates a new metrics storage wrapper
func NewMetricsStorage(storage Storage, driver string) Storage {
	if storage == nil {
		return nil
	}
	return &MetricsStorage{
		Storage: storage,
		driver:  driver,
	}
}

// Get wraps the Get operation with metrics
func (ms *MetricsStorage) Get(ctx context.Context, key string) ([]byte, error) {
	startTime := time.Now()

	result, err := ms.Storage.Get(ctx, key)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "get", "error")
		metric.StorageOperation(ms.driver, "get", "error", duration)
		return nil, err
	}

	metric.StorageOperation(ms.driver, "get", "success", duration)
	metric.StorageDataSize(ms.driver, "get", int64(len(result)))
	return result, nil
}

// GetByID wraps the GetByID operation with metrics
func (ms *MetricsStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	startTime := time.Now()

	result, err := ms.Storage.GetByID(ctx, id)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "get_by_id", "error")
		metric.StorageOperation(ms.driver, "get_by_id", "error", duration)
		return nil, err
	}

	metric.StorageOperation(ms.driver, "get_by_id", "success", duration)
	metric.StorageDataSize(ms.driver, "get_by_id", int64(len(result)))
	return result, nil
}

// Put wraps the Put operation with metrics
func (ms *MetricsStorage) Put(ctx context.Context, key string, data []byte) error {
	startTime := time.Now()

	err := ms.Storage.Put(ctx, key, data)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "put", "error")
		metric.StorageOperation(ms.driver, "put", "error", duration)
		return err
	}

	metric.StorageOperation(ms.driver, "put", "success", duration)
	metric.StorageDataSize(ms.driver, "put", int64(len(data)))

	// Update storage quota usage (approximate - tracks data size)
	// Note: This is an approximation. For accurate quota tracking, storage implementations
	// should implement a QuotaUsage() method or similar
	metric.StorageQuotaUsageSet(ms.driver, int64(len(data)))

	return nil
}

// Delete wraps the Delete operation with metrics
func (ms *MetricsStorage) Delete(ctx context.Context, key string) error {
	startTime := time.Now()

	err := ms.Storage.Delete(ctx, key)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "delete", "error")
		metric.StorageOperation(ms.driver, "delete", "error", duration)
		return err
	}

	metric.StorageOperation(ms.driver, "delete", "success", duration)
	return nil
}

// DeleteByPrefix wraps the DeleteByPrefix operation with metrics
func (ms *MetricsStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	startTime := time.Now()

	err := ms.Storage.DeleteByPrefix(ctx, prefix)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "delete_by_prefix", "error")
		metric.StorageOperation(ms.driver, "delete_by_prefix", "error", duration)
		return err
	}

	metric.StorageOperation(ms.driver, "delete_by_prefix", "success", duration)
	return nil
}

// ListKeys wraps the ListKeys operation with metrics
func (ms *MetricsStorage) ListKeys(ctx context.Context) ([]string, error) {
	startTime := time.Now()

	result, err := ms.Storage.ListKeys(ctx)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "list_keys", "error")
		metric.StorageOperation(ms.driver, "list_keys", "error", duration)
		return nil, err
	}

	metric.StorageOperation(ms.driver, "list_keys", "success", duration)
	return result, nil
}

// ListKeysByWorkspace wraps the ListKeysByWorkspace operation with metrics
func (ms *MetricsStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	startTime := time.Now()

	result, err := ms.Storage.ListKeysByWorkspace(ctx, workspaceID)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "list_keys_by_workspace", "error")
		metric.StorageOperation(ms.driver, "list_keys_by_workspace", "error", duration)
		return nil, err
	}

	metric.StorageOperation(ms.driver, "list_keys_by_workspace", "success", duration)
	return result, nil
}

// Close wraps the Close operation with metrics
func (ms *MetricsStorage) Close() error {
	startTime := time.Now()

	err := ms.Storage.Close()
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.StorageOperationError(ms.driver, "close", "error")
		metric.StorageOperation(ms.driver, "close", "error", duration)
		return err
	}

	metric.StorageOperation(ms.driver, "close", "success", duration)
	return nil
}
