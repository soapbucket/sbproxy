# Zero-Copy Optimizations

This package provides zero-copy optimizations for the proxy to reduce memory allocations and improve performance when handling large responses and streaming data.

## Features

- **Buffer Pooling**: Reusable buffers to reduce GC pressure
- **Zero-Copy Copying**: Efficient data copying using pooled buffers
- **Streaming Support**: Optimized streaming for large responses
- **Memory Optimization**: Reduced allocations for common operations

## Usage

### Basic Buffer Operations

```go
import "github.com/soapbucket/sbproxy/internal/httpkit/zerocopy"

// Get a pooled buffer
buf := zerocopy.GetBuffer()
defer zerocopy.PutBuffer(buf)

// Use buffer for operations
// ... use buf ...
```

### Copying Data

```go
// Copy with automatic buffer pooling
written, err := zerocopy.CopyBuffer(dst, src)

// Copy large data with large buffer
written, err := zerocopy.CopyBufferLarge(dst, src)

// Copy with size-based optimization
written, err := zerocopy.CopyWithZeroCopy(dst, src, contentLength)
```

### Reading Bodies

```go
// Read body with pooled buffers
body, err := zerocopy.ReadAllPooled(reader)

// Read with size limit
body, err := zerocopy.ReadAllPooledWithLimit(reader, maxSize)

// Read HTTP body with zero-copy
body, err := zerocopy.ReadBodyZeroCopy(resp.Body, maxSize)
```

### Forwarding Responses

```go
// Forward response with zero-copy
err := zerocopy.ForwardResponse(responseWriter, httpResponse)

// Forward with streaming support
err := zerocopy.ForwardResponseStreaming(responseWriter, httpResponse)
```

### Streaming Writer

```go
sw := zerocopy.NewStreamingWriter(writer)
defer sw.Close()

sw.Write(data)
sw.Flush()
```

## Performance Benefits

- **Reduced Allocations**: Buffer pooling eliminates repeated allocations
- **Lower GC Pressure**: Reused buffers reduce garbage collection overhead
- **Better Throughput**: Optimized copying improves data transfer rates
- **Memory Efficiency**: Smart buffer sizing based on data size

## Configuration

Zero-copy optimizations are automatically enabled. The system chooses appropriate buffer sizes based on:
- Response size (Content-Length header)
- Transfer encoding (chunked vs. regular)
- Data size thresholds

## Best Practices

1. Always defer `PutBuffer` after `GetBuffer`
2. Use `CopyBuffer` for general copying operations
3. Use `CopyBufferLarge` for large streams (>256KB)
4. Use `ReadAllPooled` instead of `io.ReadAll` when possible
5. Use `ForwardResponseStreaming` for large responses

