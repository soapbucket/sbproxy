// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ResponseCopier handles copying response with appropriate flushing
type ResponseCopier struct {
	bufferPool *sync.Pool
}

// NewResponseCopier creates a new response copier
func NewResponseCopier() *ResponseCopier {
	return &ResponseCopier{
		bufferPool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 32*1024) // 32KB buffers
				return &buf
			},
		},
	}
}

// Copy copies response to writer with specified flush strategy
func (rc *ResponseCopier) Copy(w http.ResponseWriter, resp *http.Response, strategy FlushStrategy) error {
	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Announce trailers if present
	if len(resp.Trailer) > 0 {
		trailerKeys := make([]string, 0, len(resp.Trailer))
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	// Write status
	w.WriteHeader(resp.StatusCode)

	// Flush headers for streaming responses (HTTP/2, gRPC)
	// Note: Transforms and some middleware don't support flushing, which is expected
	if strategy.IsStreaming {
		rc := http.NewResponseController(w)
		// Silently ignore flush errors - transforms buffer responses and don't support flush
		_ = rc.Flush()
	}

	// Copy body based on strategy
	var err error
	switch strategy.Type {
	case FlushImmediate:
		err = rc.copyWithImmediateFlushing(w, resp.Body)
	case FlushPeriodic:
		err = rc.copyWithPeriodicFlushing(w, resp.Body, strategy.Interval)
	case FlushBuffered:
		err = rc.copyBuffered(w, resp.Body)
	default:
		err = rc.copyBuffered(w, resp.Body)
	}

	// Copy trailers if present
	if len(resp.Trailer) > 0 {
		respController := http.NewResponseController(w)
		respController.Flush() // Ignore errors - transforms may not support flushing

		for k, vv := range resp.Trailer {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}

	return err
}

// copyWithImmediateFlushing flushes after every write
func (rc *ResponseCopier) copyWithImmediateFlushing(w http.ResponseWriter, body io.Reader) error {
	respController := http.NewResponseController(w)
	
	// Check if flushing is supported (once at the start)
	flushSupported := true
	if err := respController.Flush(); err != nil {
		flushSupported = false
	}
	
	bufPtr := rc.bufferPool.Get().(*[]byte)
	defer rc.bufferPool.Put(bufPtr)
	buf := *bufPtr

	for {
		nr, er := body.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}

		// Flush immediately after each write (only if supported)
		if flushSupported {
			respController.Flush() // Ignore errors after first check
		}
		}

		if er == io.EOF {
			break
		}
		if er != nil {
			return er
		}
	}

	return nil
}

// copyWithPeriodicFlushing uses maxLatencyWriter for periodic flushing
func (rc *ResponseCopier) copyWithPeriodicFlushing(w http.ResponseWriter, body io.Reader, interval time.Duration) error {
	mlw := &maxLatencyWriter{
		dst:     w,
		latency: interval,
	}
	defer mlw.stop()

	bufPtr := rc.bufferPool.Get().(*[]byte)
	defer rc.bufferPool.Put(bufPtr)
	buf := *bufPtr

	_, err := io.CopyBuffer(mlw, body, buf)
	return err
}

// copyBuffered uses standard io.Copy (no explicit flushing)
func (rc *ResponseCopier) copyBuffered(w http.ResponseWriter, body io.Reader) error {
	bufPtr := rc.bufferPool.Get().(*[]byte)
	defer rc.bufferPool.Put(bufPtr)
	buf := *bufPtr

	_, err := io.CopyBuffer(w, body, buf)
	return err
}

// maxLatencyWriter implements Caddy's periodic flush pattern
type maxLatencyWriter struct {
	dst          http.ResponseWriter
	latency      time.Duration
	mu           sync.Mutex
	t            *time.Timer
	flushPending bool
}

// Write performs the write operation on the maxLatencyWriter.
func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	n, err := m.dst.Write(p)
	if err != nil {
		return n, err
	}

	// Schedule flush if not already pending
	if !m.flushPending {
		if m.t == nil {
			m.t = time.AfterFunc(m.latency, m.delayedFlush)
		} else {
			m.t.Reset(m.latency)
		}
		m.flushPending = true
	}

	return n, nil
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.flushPending {
		return
	}

	rc := http.NewResponseController(m.dst)
	rc.Flush() // Ignore errors - transforms may not support flushing
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.t != nil {
		m.t.Stop()
	}

	// Final flush
	if m.flushPending {
		rc := http.NewResponseController(m.dst)
		rc.Flush() // Ignore errors - transforms may not support flushing
		m.flushPending = false
	}
}

