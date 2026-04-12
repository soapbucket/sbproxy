// Package transformer applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"io"
	"net/http"
)

// StreamingTransform is an optional interface for transforms that can process
// data without buffering the entire body. Transforms that implement this
// interface and return true from SupportsStreaming will have their data
// piped through ApplyStream instead of being fully buffered in memory.
type StreamingTransform interface {
	// SupportsStreaming reports whether this transform can operate in
	// streaming mode for the current invocation.
	SupportsStreaming() bool

	// ApplyStream reads from in, transforms the data, and writes to out.
	// The caller is responsible for closing both ends of the pipe.
	ApplyStream(in io.Reader, out io.Writer) error
}

// applyStreaming replaces the response body with a pipe that streams data
// through the given StreamingTransform. The original body is read in a
// background goroutine and the transformed output is available immediately
// as the new response body.
func applyStreaming(resp *http.Response, st StreamingTransform) error {
	if resp.Body == nil {
		return nil
	}

	pr, pw := io.Pipe()
	origBody := resp.Body

	go func() {
		err := st.ApplyStream(origBody, pw)
		// Close the original body after reading is complete.
		origBody.Close()
		// pw.CloseWithError signals the reader side. A nil err closes normally.
		pw.CloseWithError(err)
	}()

	resp.Body = pr
	// ContentLength is unknown after a streaming transform.
	resp.ContentLength = -1
	return nil
}

// wrapStreamingStage checks whether a Transformer also implements
// StreamingTransform. If it does and streaming is supported, it applies the
// transform via io.Pipe without buffering the full body. Otherwise it falls
// back to the standard Modify path and returns false.
func wrapStreamingStage(resp *http.Response, t Transformer) (used bool, err error) {
	st, ok := t.(StreamingTransform)
	if !ok || !st.SupportsStreaming() {
		return false, nil
	}
	return true, applyStreaming(resp, st)
}

// StreamingFunc is a convenience adapter that turns a plain function into a
// Transformer + StreamingTransform. Useful for simple streaming transforms.
type StreamingFunc struct {
	// ModifyFn is the fallback non-streaming path (required).
	ModifyFn func(*http.Response) error
	// StreamFn is the streaming implementation.
	StreamFn func(io.Reader, io.Writer) error
	// Streaming controls whether ApplyStream is used.
	Streaming bool
}

// Modify implements the Transformer interface.
func (sf *StreamingFunc) Modify(resp *http.Response) error {
	if sf.ModifyFn != nil {
		return sf.ModifyFn(resp)
	}
	// If no ModifyFn is set, read the body through the streaming path
	// and replace resp.Body with the result.
	if sf.StreamFn == nil || resp.Body == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := sf.StreamFn(resp.Body, &buf); err != nil {
		return err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(&buf)
	resp.ContentLength = int64(buf.Len())
	return nil
}

// SupportsStreaming implements the StreamingTransform interface.
func (sf *StreamingFunc) SupportsStreaming() bool {
	return sf.Streaming && sf.StreamFn != nil
}

// ApplyStream implements the StreamingTransform interface.
func (sf *StreamingFunc) ApplyStream(in io.Reader, out io.Writer) error {
	return sf.StreamFn(in, out)
}
