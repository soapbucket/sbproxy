package adapters

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

// OTELCallback sends spans to an OpenTelemetry collector using OTLP/HTTP JSON.
type OTELCallback struct {
	endpoint string
	client   *http.Client
}

// NewOTELCallback creates an OpenTelemetry adapter.
func NewOTELCallback(endpoint string) *OTELCallback {
	return &OTELCallback{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "otel".
func (o *OTELCallback) Name() string { return "otel" }

// OTLP JSON format types.

type otlpExportRequest struct {
	ResourceSpans []otlpResourceSpan `json:"resourceSpans"`
}

type otlpResourceSpan struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeSpan struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpSpan struct {
	TraceID            string         `json:"traceId"`
	SpanID             string         `json:"spanId"`
	Name               string         `json:"name"`
	Kind               int            `json:"kind"`
	StartTimeUnixNano  string         `json:"startTimeUnixNano"`
	EndTimeUnixNano    string         `json:"endTimeUnixNano"`
	Attributes         []otlpKeyValue `json:"attributes"`
	Status             otlpStatus     `json:"status"`
}

type otlpKeyValue struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

type otlpStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

func otlpString(v string) otlpValue {
	return otlpValue{StringValue: &v}
}

func otlpInt(v int64) otlpValue {
	s := fmt.Sprintf("%d", v)
	return otlpValue{IntValue: &s}
}

func otlpDouble(v float64) otlpValue {
	return otlpValue{DoubleValue: &v}
}

// deriveHexID produces a hex string from the request ID bytes, padded/truncated
// to the specified byte length.
func deriveHexID(requestID string, byteLen int) string {
	src := []byte(requestID)
	out := make([]byte, byteLen)
	copy(out, src)
	return hex.EncodeToString(out)
}

// Send formats the payload as an OTLP span and POSTs it.
func (o *OTELCallback) Send(ctx context.Context, payload *callbacks.CallbackPayload) error {
	if ctx == nil {
		ctx = context.Background()
	}

	traceID := deriveHexID(payload.RequestID, 16)
	spanID := deriveHexID(payload.RequestID, 8)

	startNano := fmt.Sprintf("%d", payload.Timestamp.UnixNano())
	endNano := fmt.Sprintf("%d", payload.Timestamp.Add(payload.Duration).UnixNano())

	statusCode := 1 // OK
	statusMsg := ""
	if payload.Error != "" {
		statusCode = 2 // ERROR
		statusMsg = payload.Error
	}

	// Build attributes following OpenTelemetry gen_ai semantic conventions.
	attrs := []otlpKeyValue{
		{Key: "gen_ai.system", Value: otlpString(payload.Provider)},
		{Key: "gen_ai.request.model", Value: otlpString(payload.Model)},
		{Key: "gen_ai.usage.input_tokens", Value: otlpInt(payload.InputTokens)},
		{Key: "gen_ai.usage.output_tokens", Value: otlpInt(payload.OutputTokens)},
		{Key: "gen_ai.usage.total_tokens", Value: otlpInt(payload.TotalTokens)},
		{Key: "gen_ai.response.status_code", Value: otlpInt(int64(payload.StatusCode))},
		{Key: "gen_ai.usage.cost", Value: otlpDouble(payload.CostEstimate)},
		{Key: "soapbucket.workspace_id", Value: otlpString(payload.WorkspaceID)},
		{Key: "soapbucket.principal_id", Value: otlpString(payload.PrincipalID)},
		{Key: "soapbucket.request_id", Value: otlpString(payload.RequestID)},
	}

	for k, v := range payload.Tags {
		attrs = append(attrs, otlpKeyValue{Key: "soapbucket.tag." + k, Value: otlpString(v)})
	}

	export := otlpExportRequest{
		ResourceSpans: []otlpResourceSpan{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{
					{Key: "service.name", Value: otlpString("soapbucket-proxy")},
					{Key: "service.version", Value: otlpString("1.0.0")},
				},
			},
			ScopeSpans: []otlpScopeSpan{{
				Scope: otlpScope{
					Name:    "soapbucket.ai.callbacks",
					Version: "1.0.0",
				},
				Spans: []otlpSpan{{
					TraceID:           traceID,
					SpanID:            spanID,
					Name:              payload.Provider + "/" + payload.Model,
					Kind:              3, // CLIENT
					StartTimeUnixNano: startNano,
					EndTimeUnixNano:   endNano,
					Attributes:        attrs,
					Status: otlpStatus{
						Code:    statusCode,
						Message: statusMsg,
					},
				}},
			}},
		}},
	}

	body, err := json.Marshal(export)
	if err != nil {
		return fmt.Errorf("otel: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otel: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("otel: send failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("otel: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Health checks connectivity to the OTEL collector endpoint.
func (o *OTELCallback) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.endpoint+"/v1/health", nil)
	if err != nil {
		return fmt.Errorf("otel: health request failed: %w", err)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("otel: health check failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("otel: health check returned %d", resp.StatusCode)
	}
	return nil
}
