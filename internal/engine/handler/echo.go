// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

var echoBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// EchoResponse represents the response from a echo operation.
type EchoResponse struct {
	URL     string      `json:"url"`
	Method  string      `json:"method"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

// WriteTo marshals the echo response into a pooled buffer and writes directly.
func (e *EchoResponse) WriteTo(w io.Writer) (int64, error) {
	buf := echoBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer echoBufPool.Put(buf)

	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		return 0, err
	}
	// Trim trailing newline added by Encode
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	n, err := w.Write(b)
	return int64(n), err
}

// NewEchoResponse creates and initializes a new EchoResponse.
func NewEchoResponse(r *http.Request) (*EchoResponse, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	bodyString := string(body)

	return &EchoResponse{
		URL:     r.URL.String(),
		Method:  r.Method,
		Headers: r.Header,
		Body:    bodyString,
	}, nil
}

// EchoHandler performs the echo handler operation.
func EchoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/json")
	echoResponse, err := NewEchoResponse(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	echoResponse.WriteTo(w)
}
