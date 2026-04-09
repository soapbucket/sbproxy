// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// DryRunResult holds original and transformed content.
type DryRunResult struct {
	Original    string          `json:"original"`
	Transformed string          `json:"transformed"`
	Pipeline    *PipelineResult `json:"pipeline"`
	ContentType string          `json:"content_type"`
}

// DryRun wraps a transform pipeline and captures both original and transformed output.
type DryRun struct {
	pipeline *InstrumentedPipeline
}

// NewDryRun creates a new DryRun wrapper around an instrumented pipeline.
func NewDryRun(pipeline *InstrumentedPipeline) *DryRun {
	return &DryRun{
		pipeline: pipeline,
	}
}

// Execute reads the original body, runs the pipeline, and returns both versions.
func (d *DryRun) Execute(resp *http.Response) (*DryRunResult, error) {
	// Read and buffer the original body.
	var original []byte
	if resp.Body != nil {
		var err error
		original, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
	}

	contentType := resp.Header.Get("Content-Type")

	// Replace body with a copy for the pipeline to transform.
	resp.Body = io.NopCloser(bytes.NewReader(append([]byte(nil), original...)))
	resp.ContentLength = int64(len(original))

	// Execute the pipeline.
	err := d.pipeline.Modify(resp)
	if err != nil {
		return &DryRunResult{
			Original:    string(original),
			Transformed: "",
			Pipeline:    d.pipeline.Result(),
			ContentType: contentType,
		}, err
	}

	// Read the transformed body.
	var transformed []byte
	if resp.Body != nil {
		transformed, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
	}

	// Restore original body on the response so the caller can still use it.
	resp.Body = io.NopCloser(bytes.NewReader(original))
	resp.ContentLength = int64(len(original))

	return &DryRunResult{
		Original:    string(original),
		Transformed: string(transformed),
		Pipeline:    d.pipeline.Result(),
		ContentType: contentType,
	}, nil
}

// IsDryRunRequest checks if the request has the dry-run header set.
func IsDryRunRequest(r *http.Request) bool {
	return r.Header.Get("X-Sb-Transform-Dryrun") == "true"
}

// WriteDryRunResponse writes the DryRunResult as JSON to the response writer.
func WriteDryRunResponse(w http.ResponseWriter, result *DryRunResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}
