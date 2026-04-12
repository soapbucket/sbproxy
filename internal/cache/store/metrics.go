// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MetricsCacher wraps a Cacher with metrics collection
type MetricsCacher struct {
	Cacher
	driver string
}

// NewMetricsCacher creates a new metrics cacher wrapper
func NewMetricsCacher(cacher Cacher, driver string) Cacher {
	if cacher == nil {
		return nil
	}
	return &MetricsCacher{
		Cacher: cacher,
		driver: driver,
	}
}

// Get wraps the Get operation with metrics
func (mc *MetricsCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	startTime := time.Now()

	reader, err := mc.Cacher.Get(ctx, cType, key)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "get", "error")
		metric.CacherOperation(mc.driver, "get", "error", duration)
		return nil, err
	}

	// Read the data to get size for metrics
	data, readErr := io.ReadAll(reader)
	if readErr != nil {
		metric.CacherOperationError(mc.driver, "get", "read_error")
		metric.CacherOperation(mc.driver, "get", "error", duration)
		return nil, readErr
	}

	metric.CacherOperation(mc.driver, "get", "success", duration)
	metric.CacherDataSize(mc.driver, "get", int64(len(data)))

	return io.NopCloser(io.NewSectionReader(strings.NewReader(string(data)), 0, int64(len(data)))), nil
}

// Put wraps the Put operation with metrics
func (mc *MetricsCacher) Put(ctx context.Context, cType string, key string, value io.Reader) error {
	startTime := time.Now()

	// Read the data to get size for metrics
	data, readErr := io.ReadAll(value)
	if readErr != nil {
		metric.CacherOperationError(mc.driver, "put", "read_error")
		return readErr
	}

	err := mc.Cacher.Put(ctx, cType, key, io.NopCloser(io.NewSectionReader(strings.NewReader(string(data)), 0, int64(len(data)))))
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "put", "error")
		metric.CacherOperation(mc.driver, "put", "error", duration)
		return err
	}

	metric.CacherOperation(mc.driver, "put", "success", duration)
	metric.CacherDataSize(mc.driver, "put", int64(len(data)))
	return nil
}

// PutWithExpires wraps the PutWithExpires operation with metrics
func (mc *MetricsCacher) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, ttl time.Duration) error {
	startTime := time.Now()

	// Read the data to get size for metrics
	data, readErr := io.ReadAll(value)
	if readErr != nil {
		metric.CacherOperationError(mc.driver, "put_with_expires", "read_error")
		return readErr
	}

	err := mc.Cacher.PutWithExpires(ctx, cType, key, io.NopCloser(io.NewSectionReader(strings.NewReader(string(data)), 0, int64(len(data)))), ttl)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "put_with_expires", "error")
		metric.CacherOperation(mc.driver, "put_with_expires", "error", duration)
		return err
	}

	metric.CacherOperation(mc.driver, "put_with_expires", "success", duration)
	metric.CacherDataSize(mc.driver, "put_with_expires", int64(len(data)))
	return nil
}

// Delete wraps the Delete operation with metrics
func (mc *MetricsCacher) Delete(ctx context.Context, cType string, key string) error {
	startTime := time.Now()

	err := mc.Cacher.Delete(ctx, cType, key)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "delete", "error")
		metric.CacherOperation(mc.driver, "delete", "error", duration)
		return err
	}

	metric.CacherOperation(mc.driver, "delete", "success", duration)
	return nil
}

// DeleteByPattern wraps the DeleteByPattern operation with metrics
func (mc *MetricsCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	startTime := time.Now()

	err := mc.Cacher.DeleteByPattern(ctx, cType, pattern)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "delete_by_pattern", "error")
		metric.CacherOperation(mc.driver, "delete_by_pattern", "error", duration)
		return err
	}

	metric.CacherOperation(mc.driver, "delete_by_pattern", "success", duration)
	return nil
}

// Increment wraps the Increment operation with metrics
func (mc *MetricsCacher) Increment(ctx context.Context, cType string, key string, value int64) (int64, error) {
	startTime := time.Now()

	result, err := mc.Cacher.Increment(ctx, cType, key, value)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "increment", "error")
		metric.CacherOperation(mc.driver, "increment", "error", duration)
		return 0, err
	}

	metric.CacherOperation(mc.driver, "increment", "success", duration)
	return result, nil
}

// IncrementWithExpires wraps the IncrementWithExpires operation with metrics
func (mc *MetricsCacher) IncrementWithExpires(ctx context.Context, cType string, key string, value int64, ttl time.Duration) (int64, error) {
	startTime := time.Now()

	result, err := mc.Cacher.IncrementWithExpires(ctx, cType, key, value, ttl)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "increment_with_expires", "error")
		metric.CacherOperation(mc.driver, "increment_with_expires", "error", duration)
		return 0, err
	}

	metric.CacherOperation(mc.driver, "increment_with_expires", "success", duration)
	return result, nil
}

// Close wraps the Close operation with metrics
func (mc *MetricsCacher) Close() error {
	startTime := time.Now()

	err := mc.Cacher.Close()
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CacherOperationError(mc.driver, "close", "error")
		metric.CacherOperation(mc.driver, "close", "error", duration)
		return err
	}

	metric.CacherOperation(mc.driver, "close", "success", duration)
	return nil
}
