// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	httpCachePrefix = "http_cache"

	// Streaming configuration
	defaultChunkSize    = 32 * 1024 // 32KB chunks
	streamingBufferSize = 64 * 1024 // 64KB buffer size

	// Compression thresholds
	compressionThreshold = 1024 // Compress responses > 1KB
)

// StreamingResponse represents a streaming HTTP response
type StreamingResponse struct {
	*http.Response
	chunkSize   int
	compressed  bool
	contentType string
	totalBytes  int64
}

// StreamingWriter handles writing streaming responses to cache
type StreamingWriter struct {
	writer        io.Writer
	chunkSize     int
	compressed    bool
	compressor    *gzip.Writer
	buffer        []byte
	totalBytes    int64
	chunksWritten int64
	mu            sync.Mutex
}

// StreamingReader handles reading streaming responses from cache
type StreamingReader struct {
	reader       io.Reader
	chunkSize    int
	compressed   bool
	decompressor *gzip.Reader
	buffer       []byte
	totalBytes   int64
	chunksRead   int64
	mu           sync.RWMutex
}

// ResponseHeader represents a response header.
type ResponseHeader struct {
	StatusCode       int         `json:"status_code"`
	Proto            string      `json:"proto"`
	ProtoMajor       int         `json:"proto_major"`
	ProtoMinor       int         `json:"proto_minor"`
	Header           http.Header `json:"header"`
	ContentLength    int64       `json:"content_length"`
	TransferEncoding []string    `json:"transfer_encoding"`
	Close            bool        `json:"close"`
	Uncompressed     bool        `json:"uncompressed"`
	Trailer          http.Header `json:"trailer"`
}

// Caching methods
func GetCachedResponse(req *http.Request, cache cacher.Cacher) (bool, *http.Response) {
	slog.Info("getting cached response", "url", req.URL.String())
	if !IsCacheable(req) {
		slog.Info("request is not cacheable", "url", req.URL.String())
		return false, nil
	}

	cacheKey := cacher.RequestCacheKey(req)

	data, err := cache.Get(req.Context(), httpCachePrefix, cacheKey)
	if err != nil {
		return false, nil
	}

	// Convert the cached data (io.Reader) to http.Response using our streaming function
	resp, err := readResponseFromStream(data)
	if err != nil {
		slog.Error("failed to read response from cache", "error", err)
		return false, nil
	}

	return true, resp
}

// GetCachedResponseStream returns a streaming response from cache
func GetCachedResponseStream(req *http.Request, cache cacher.Cacher) (bool, *StreamingResponse, error) {
	slog.Info("getting cached streaming response", "url", req.URL.String())
	if !IsCacheable(req) {
		slog.Info("request is not cacheable", "url", req.URL.String())
		return false, nil, nil
	}

	cacheKey := cacher.RequestCacheKey(req)

	data, err := cache.Get(req.Context(), httpCachePrefix, cacheKey)
	if err != nil {
		return false, nil, err
	}

	// Create streaming reader
	streamReader, err := newStreamingReader(data, defaultChunkSize)
	if err != nil {
		slog.Error("failed to create streaming reader", "error", err)
		return false, nil, err
	}

	// Read response header
	resp, err := readResponseFromStream(streamReader)
	if err != nil {
		slog.Error("failed to read response from stream", "error", err)
		return false, nil, err
	}

	// Create streaming response
	streamResp := &StreamingResponse{
		Response:    resp,
		chunkSize:   defaultChunkSize,
		compressed:  streamReader.compressed,
		contentType: resp.Header.Get("Content-Type"),
		totalBytes:  streamReader.totalBytes,
	}

	// Replace the body with our streaming reader
	streamResp.Response.Body = streamReader

	return true, streamResp, nil
}

// CacheResponse performs the cache response operation.
func CacheResponse(req *http.Request, resp *http.Response, cache cacher.Cacher) error {
	slog.Info("caching response", "url", req.URL.String())

	if !IsCacheable(req) {
		slog.Info("request is not cacheable", "url", req.URL.String())
		return nil
	}

	cacheKey := cacher.RequestCacheKey(req)

	// Create a buffer to write the response to
	var buf bytes.Buffer

	// Write response to stream using our streaming function
	if err := writeResponseToStream(&buf, resp); err != nil {
		slog.Error("failed to write response to stream", "error", err)
		return err
	}

	// Store the serialized response in cache
	return cache.Put(req.Context(), httpCachePrefix, cacheKey, &buf)
}

// CacheResponseStream caches a response using streaming for better memory efficiency
func CacheResponseStream(req *http.Request, resp *http.Response, cache cacher.Cacher) error {
	slog.Info("caching response stream", "url", req.URL.String())

	if !IsCacheable(req) {
		slog.Info("request is not cacheable", "url", req.URL.String())
		return nil
	}

	cacheKey := cacher.RequestCacheKey(req)

	// Create streaming writer
	streamWriter, err := newStreamingWriter(cache, req.Context(), httpCachePrefix, cacheKey, defaultChunkSize)
	if err != nil {
		slog.Error("failed to create streaming writer", "error", err)
		return err
	}

	// Write response to stream
	if err := writeResponseToStream(streamWriter, resp); err != nil {
		slog.Error("failed to write response to stream", "error", err)
		return err
	}

	// Close the stream writer
	if err := streamWriter.Close(); err != nil {
		slog.Error("failed to close streaming writer", "error", err)
		return err
	}

	return nil
}

// WriteResponseToStream writes an HTTP response to a stream with a header
func writeResponseToStream(w io.Writer, resp *http.Response) error {
	// Create response header
	header := &ResponseHeader{
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header,
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          resp.Trailer,
	}

	// Marshal header to JSON
	headerData, err := json.Marshal(header)
	if err != nil {
		return err
	}

	// Write header length (4 bytes, big-endian)
	headerLength := uint32(len(headerData))
	if err := binary.Write(w, binary.BigEndian, headerLength); err != nil {
		return err
	}

	// Write header data
	if _, err := w.Write(headerData); err != nil {
		return err
	}

	// Write response body with streaming
	if resp.Body != nil {
		defer resp.Body.Close()

		// Use buffered copying for better performance
		buf := make([]byte, streamingBufferSize)
		_, err := io.CopyBuffer(w, resp.Body, buf)
		return err
	}

	return nil
}

// WriteResponseToStreamChunked writes an HTTP response to a stream with chunked transfer encoding
func writeResponseToStreamChunked(w io.Writer, resp *http.Response) error {
	// Create response header
	header := &ResponseHeader{
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header,
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          resp.Trailer,
	}

	// Marshal header to JSON
	headerData, err := json.Marshal(header)
	if err != nil {
		return err
	}

	// Write header length (4 bytes, big-endian)
	headerLength := uint32(len(headerData))
	if err := binary.Write(w, binary.BigEndian, headerLength); err != nil {
		return err
	}

	// Write header data
	if _, err := w.Write(headerData); err != nil {
		return err
	}

	// Write response body with chunked transfer encoding
	if resp.Body != nil {
		defer resp.Body.Close()

		// Use chunked writing for better streaming performance
		return writeChunkedBody(w, resp.Body)
	}

	return nil
}

// writeChunkedBody writes the response body in chunks for better streaming performance
func writeChunkedBody(w io.Writer, body io.Reader) error {
	buf := make([]byte, defaultChunkSize)

	for {
		n, err := body.Read(buf)
		if n > 0 {
			// Write chunk size (4 bytes, big-endian)
			chunkSize := uint32(n)
			if err := binary.Write(w, binary.BigEndian, chunkSize); err != nil {
				return err
			}

			// Write chunk data
			if _, err := w.Write(buf[:n]); err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	// Write end-of-chunks marker (0 size)
	return binary.Write(w, binary.BigEndian, uint32(0))
}

// ReadResponseFromStream reads an HTTP response from a stream with a header
func readResponseFromStream(r io.Reader) (*http.Response, error) {
	// Read header length (4 bytes, big-endian)
	var headerLength uint32
	if err := binary.Read(r, binary.BigEndian, &headerLength); err != nil {
		return nil, err
	}

	// Read header data
	headerData := make([]byte, headerLength)
	if _, err := io.ReadFull(r, headerData); err != nil {
		return nil, err
	}

	// Unmarshal header
	var header ResponseHeader
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, err
	}

	// Create response
	resp := &http.Response{
		StatusCode:       header.StatusCode,
		Proto:            header.Proto,
		ProtoMajor:       header.ProtoMajor,
		ProtoMinor:       header.ProtoMinor,
		Header:           header.Header,
		ContentLength:    header.ContentLength,
		TransferEncoding: header.TransferEncoding,
		Close:            header.Close,
		Uncompressed:     header.Uncompressed,
		Trailer:          header.Trailer,
		Body:             io.NopCloser(r), // Remaining reader becomes the body
	}

	return resp, nil
}

// ReadResponseFromStreamChunked reads an HTTP response from a chunked stream
func readResponseFromStreamChunked(r io.Reader) (*http.Response, error) {
	// Read header length (4 bytes, big-endian)
	var headerLength uint32
	if err := binary.Read(r, binary.BigEndian, &headerLength); err != nil {
		return nil, err
	}

	// Read header data
	headerData := make([]byte, headerLength)
	if _, err := io.ReadFull(r, headerData); err != nil {
		return nil, err
	}

	// Unmarshal header
	var header ResponseHeader
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, err
	}

	// Create chunked reader for the body
	chunkedReader := &chunkedReader{reader: r}

	// Create response
	resp := &http.Response{
		StatusCode:       header.StatusCode,
		Proto:            header.Proto,
		ProtoMajor:       header.ProtoMajor,
		ProtoMinor:       header.ProtoMinor,
		Header:           header.Header,
		ContentLength:    header.ContentLength,
		TransferEncoding: header.TransferEncoding,
		Close:            header.Close,
		Uncompressed:     header.Uncompressed,
		Trailer:          header.Trailer,
		Body:             io.NopCloser(chunkedReader),
	}

	return resp, nil
}

// chunkedReader reads chunked data from a stream
type chunkedReader struct {
	reader    io.Reader
	buffer    []byte
	pos       int
	chunkSize uint32
	finished  bool
}

// Read performs the read operation on the chunkedReader.
func (cr *chunkedReader) Read(p []byte) (n int, err error) {
	if cr.finished {
		return 0, io.EOF
	}

	// If we have data in buffer, return it
	if cr.pos < len(cr.buffer) {
		n = copy(p, cr.buffer[cr.pos:])
		cr.pos += n
		return n, nil
	}

	// Read next chunk size
	if err := binary.Read(cr.reader, binary.BigEndian, &cr.chunkSize); err != nil {
		return 0, err
	}

	// If chunk size is 0, we're done
	if cr.chunkSize == 0 {
		cr.finished = true
		return 0, io.EOF
	}

	// Read chunk data
	cr.buffer = make([]byte, cr.chunkSize)
	if _, err := io.ReadFull(cr.reader, cr.buffer); err != nil {
		return 0, err
	}

	cr.pos = 0
	n = copy(p, cr.buffer)
	cr.pos = n
	return n, nil
}

// CreateResponseStream creates a stream from an HTTP response that can be read back later
func createResponseStream(resp *http.Response) (io.Reader, error) {
	var buf bytes.Buffer
	if err := writeResponseToStream(&buf, resp); err != nil {
		return nil, err
	}
	return &buf, nil
}

// CreateResponseStreamChunked creates a chunked stream from an HTTP response
func createResponseStreamChunked(resp *http.Response) (io.Reader, error) {
	var buf bytes.Buffer
	if err := writeResponseToStreamChunked(&buf, resp); err != nil {
		return nil, err
	}
	return &buf, nil
}

// newStreamingWriter creates a new streaming writer for caching responses
func newStreamingWriter(cache interface{}, ctx context.Context, prefix, key string, chunkSize int) (*StreamingWriter, error) {
	// Determine if we should compress based on content type and size
	compressed := shouldCompress(nil) // We'll determine this from the response

	writer := &StreamingWriter{
		chunkSize:  chunkSize,
		compressed: compressed,
		buffer:     make([]byte, chunkSize),
	}

	if compressed {
		// We'll set up compression when we write the first chunk
		writer.compressor = nil // Will be initialized on first write
	}

	return writer, nil
}

// newStreamingReader creates a new streaming reader for reading cached responses
func newStreamingReader(reader io.Reader, chunkSize int) (*StreamingReader, error) {
	// Read compression flag from stream
	var compressed bool
	if err := binary.Read(reader, binary.BigEndian, &compressed); err != nil {
		return nil, err
	}

	streamReader := &StreamingReader{
		reader:     reader,
		chunkSize:  chunkSize,
		compressed: compressed,
		buffer:     make([]byte, chunkSize),
	}

	if compressed {
		decompressor, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		streamReader.decompressor = decompressor
	}

	return streamReader, nil
}

// shouldCompress determines if a response should be compressed
func shouldCompress(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	// Check if already compressed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" && contentEncoding != "identity" {
		return false
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}

	// Don't compress already compressed formats
	skipTypes := []string{
		"image/", "video/", "audio/", "application/zip", "application/gzip",
		"application/x-gzip", "application/x-compress", "application/x-compressed",
	}

	for _, skipType := range skipTypes {
		if len(contentType) >= len(skipType) && contentType[:len(skipType)] == skipType {
			return false
		}
	}

	// Check size threshold
	if resp.ContentLength > 0 && resp.ContentLength < compressionThreshold {
		return false
	}

	return true
}

// Write implements io.Writer for StreamingWriter
func (sw *StreamingWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.compressor == nil && sw.compressed {
		// Initialize compressor on first write
		sw.compressor = gzip.NewWriter(sw.writer)
	}

	writer := sw.writer
	if sw.compressor != nil {
		writer = sw.compressor
	}

	n, err = writer.Write(p)
	sw.totalBytes += int64(n)
	sw.chunksWritten++
	return n, err
}

// Close implements io.Closer for StreamingWriter
func (sw *StreamingWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.compressor != nil {
		return sw.compressor.Close()
	}
	return nil
}

// Read implements io.Reader for StreamingReader
func (sr *StreamingReader) Read(p []byte) (n int, err error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	reader := sr.reader
	if sr.decompressor != nil {
		reader = sr.decompressor
	}

	n, err = reader.Read(p)
	sr.totalBytes += int64(n)
	sr.chunksRead++
	return n, err
}

// Close implements io.Closer for StreamingReader
func (sr *StreamingReader) Close() error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.decompressor != nil {
		return sr.decompressor.Close()
	}
	return nil
}

// GetStats returns statistics about the streaming operation
func (sr *StreamingReader) GetStats() (totalBytes int64, chunksRead int64) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.totalBytes, sr.chunksRead
}

// GetStats returns statistics about the streaming operation
func (sw *StreamingWriter) GetStats() (totalBytes int64, chunksWritten int64) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.totalBytes, sw.chunksWritten
}
