// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
)

// Pools for compression readers to reduce allocations
var (
	gzipReaderPool = sync.Pool{
		New: func() interface{} {
			return &gzip.Reader{}
		},
	}
	zstdReaderPool = sync.Pool{
		New: func() interface{} {
			reader, _ := zstd.NewReader(nil)
			return reader
		},
	}
)

// FixEncoding converts compressed response streams to plain text for processing
// It supports: gzip, deflate, br (brotli), zstd, snappy, and zlib
// After decompression, the Content-Encoding header is removed and the body
// is wrapped with a decompression reader that yields plain text bytes
func FixEncoding() Transformer {
	return Func(fixEncoding)
}

func fixEncoding(resp *http.Response) error {
	slog.Debug("fixEncoding for origin", "url", resp.Request.URL)

	// HEAD responses carry encoding headers but no body per HTTP spec.
	// Attempting to decompress an empty body causes EOF errors.
	if resp.Request.Method == http.MethodHead {
		slog.Debug("skipping encoding transform for HEAD request")
		return nil
	}

	encoding := resp.Header.Get("Content-Encoding")
	resp.Header.Del("Content-Encoding")
	slog.Debug("content-encoding detected", "encoding", encoding)

	if encoding == "" && resp.Header.Get("grpc-encoding") != "" {
		encoding = resp.Header.Get("grpc-encoding")
		slog.Debug("grpc-encoding detected, replacing content-encoding", "encoding", encoding)
		resp.Header.Del("grpc-encoding")
	}
	var (
		reader io.ReadCloser
		err    error
	)

	switch {
	case strings.EqualFold("gzip", encoding):
		slog.Debug("gzip compressed")
		// Use pooled gzip reader
		gz := gzipReaderPool.Get().(*gzip.Reader)
		if err = gz.Reset(resp.Body); err != nil {
			gzipReaderPool.Put(gz)
			return err
		}
		reader = &pooledGzipReader{Reader: gz, body: resp.Body}

	case strings.EqualFold("deflate", encoding):
		slog.Debug("deflate compressed")
		reader = flate.NewReader(resp.Body)

	case strings.EqualFold("br", encoding):
		slog.Debug("br compressed")
		reader = io.NopCloser(brotli.NewReader(resp.Body))

	case strings.EqualFold("zstd", encoding):
		slog.Debug("zstd compressed")
		// Use pooled zstd reader
		zstdReader := zstdReaderPool.Get().(*zstd.Decoder)
		if err = zstdReader.Reset(resp.Body); err != nil {
			zstdReaderPool.Put(zstdReader)
			return err
		}
		reader = &pooledZstdReader{Decoder: zstdReader, body: resp.Body}

	case strings.EqualFold("snappy", encoding):
		slog.Debug("snappy compressed")
		reader = io.NopCloser(snappy.NewReader(resp.Body))

	case strings.EqualFold("zlib", encoding):
		slog.Debug("zlib compressed")
		reader, err = zlib.NewReader(resp.Body)
		if err != nil {
			return err
		}

	default:
		slog.Debug("not compressed")
		// Body is already plain text, no conversion needed
		reader = resp.Body
	}

	// Remove Content-Encoding header to indicate stream is now plain text
	// Remove Content-Length as decompressed size may differ
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1

	// Replace body with decompression reader (or original if not compressed)
	// This ensures downstream transforms receive plain text bytes
	resp.Body = reader

	slog.Debug("encoding transform complete - stream converted to plain text",
		"was_compressed", encoding != "",
		"encoding", encoding)

	return nil
}

// pooledGzipReader wraps a gzip.Reader to return it to the pool on close
type pooledGzipReader struct {
	*gzip.Reader
	body io.ReadCloser
}

// Close releases resources held by the pooledGzipReader.
func (r *pooledGzipReader) Close() error {
	err := r.Reader.Close()
	if closeErr := r.body.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	gzipReaderPool.Put(r.Reader)
	return err
}

// pooledZstdReader wraps a zstd.Decoder to return it to the pool on close
type pooledZstdReader struct {
	*zstd.Decoder
	body io.ReadCloser
}

// Close releases resources held by the pooledZstdReader.
func (r *pooledZstdReader) Close() error {
	r.Decoder.Close()
	err := r.body.Close()
	zstdReaderPool.Put(r.Decoder)
	return err
}
