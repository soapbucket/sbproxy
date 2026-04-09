// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/cel-go/cel"
	celutil "github.com/soapbucket/sbproxy/internal/extension/cel"
)

// TrailerGeneratorImpl handles generating trailers on-the-fly
type TrailerGeneratorImpl struct {
	generators  []TrailerGenerator
	celPrograms map[int]cel.Program // compiled CEL programs keyed by generator index
	startTime   time.Time
}

// NewTrailerGeneratorImpl creates a new trailer generator.
// CEL expressions in custom trailer generators are compiled once here and
// reused on every request. If compilation fails, the generator falls back to
// the static Value at evaluation time.
func NewTrailerGeneratorImpl(generators []TrailerGenerator, startTime time.Time) *TrailerGeneratorImpl {
	tg := &TrailerGeneratorImpl{
		generators:  generators,
		celPrograms: make(map[int]cel.Program),
		startTime:   startTime,
	}

	// Pre-compile CEL expressions for custom trailer generators.
	for i, gen := range generators {
		if gen.Type != TrailerCustom || gen.Value == "" {
			continue
		}
		program, err := compileTrailerCEL(gen.Value)
		if err != nil {
			slog.Warn("failed to compile custom trailer CEL expression, will use static value",
				"trailer", gen.Name, "expression", gen.Value, "error", err)
			continue
		}
		tg.celPrograms[i] = program
	}

	return tg
}

// compileTrailerCEL compiles a CEL expression using the response environment.
// The expression can return any type; the result is converted to a string.
func compileTrailerCEL(expr string) (cel.Program, error) {
	env, err := celutil.GetResponseEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to get CEL response env: %w", err)
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast == nil {
		return nil, fmt.Errorf("CEL compilation produced nil AST")
	}
	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return program, nil
}

// WrapWriter wraps a response writer to compute trailers during write.
// The optional req parameter provides request context for CEL expression evaluation
// in custom trailers. If nil, CEL expressions fall back to their static values.
func (tg *TrailerGeneratorImpl) WrapWriter(w http.ResponseWriter, resp *http.Response, req ...*http.Request) io.Writer {
	if len(tg.generators) == 0 {
		return w
	}

	tw := &trailerWriter{
		ResponseWriter: w,
		generators:     tg.generators,
		startTime:      tg.startTime,
		hashes:         make(map[string]hash.Hash),
	}
	if len(req) > 0 {
		tw.req = req[0]
	}

	// Initialize hash generators
	for _, gen := range tg.generators {
		if gen.Type == TrailerChecksum {
			switch gen.Value {
			case "md5":
				tw.hashes[gen.Name] = md5.New()
			case "sha256":
				tw.hashes[gen.Name] = sha256.New()
			}
		}
	}

	return tw
}

// ApplyTrailers applies generated trailers to the response
func (tg *TrailerGeneratorImpl) ApplyTrailers(w http.ResponseWriter, tw *trailerWriter) {
	for i, gen := range tg.generators {
		var value string

		switch gen.Type {
		case TrailerChecksum:
			if h, ok := tw.hashes[gen.Name]; ok {
				value = hex.EncodeToString(h.Sum(nil))
			}

		case TrailerTiming:
			switch gen.Value {
			case "request_duration_ms":
				duration := time.Since(tg.startTime).Milliseconds()
				value = strconv.FormatInt(duration, 10)
			case "request_duration_sec":
				duration := time.Since(tg.startTime).Seconds()
				value = fmt.Sprintf("%.3f", duration)
			default:
				duration := time.Since(tg.startTime).Milliseconds()
				value = strconv.FormatInt(duration, 10)
			}

		case TrailerCustom:
			// Try CEL expression evaluation first, fall back to static value.
			if program, ok := tg.celPrograms[i]; ok {
				celValue, err := tg.evalTrailerCEL(program, tw)
				if err != nil {
					slog.Warn("CEL evaluation failed for custom trailer, using static value",
						"trailer", gen.Name, "error", err)
					value = gen.Value
				} else {
					value = celValue
				}
			} else {
				value = gen.Value
			}
		}

		if value != "" {
			w.Header().Add(gen.Name, value)
		}
	}
}

// evalTrailerCEL evaluates a compiled CEL program with trailer context.
// Returns the result as a string.
func (tg *TrailerGeneratorImpl) evalTrailerCEL(program cel.Program, tw *trailerWriter) (string, error) {
	vars := map[string]interface{}{
		"request":  map[string]interface{}{},
		"response": map[string]interface{}{},
		"session":  map[string]interface{}{},
		"origin":   map[string]interface{}{},
		"server":   map[string]interface{}{},
		"vars":     map[string]interface{}{},
		"features": map[string]interface{}{},
		"client":   map[string]interface{}{},
		"ctx":      map[string]interface{}{},
		"oauth_user": map[string]interface{}{},
	}

	// Populate request context if available
	if tw.req != nil {
		rc := celutil.GetRequestContext(tw.req)
		vars = rc.ToVars()
		// Add response namespace with available trailer-time data
		respMap := map[string]interface{}{
			"bytes_written": tw.bytesWritten,
			"duration_ms":   time.Since(tg.startTime).Milliseconds(),
		}
		vars["response"] = respMap
		vars["oauth_user"] = map[string]interface{}{}
	}

	out, _, err := program.Eval(vars)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", out.Value()), nil
}

// trailerWriter wraps ResponseWriter to compute hashes during writes
type trailerWriter struct {
	http.ResponseWriter
	generators   []TrailerGenerator
	startTime    time.Time
	hashes       map[string]hash.Hash
	bytesWritten int64
	req          *http.Request // optional, for CEL context
}

// Write performs the write operation on the trailerWriter.
func (tw *trailerWriter) Write(p []byte) (int, error) {
	// Write to response
	n, err := tw.ResponseWriter.Write(p)

	// Update hashes
	for _, h := range tw.hashes {
		h.Write(p[:n])
	}

	tw.bytesWritten += int64(n)

	return n, err
}

