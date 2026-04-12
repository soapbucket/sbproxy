package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubTransport is a trivial RoundTripper that returns a fixed status code.
type stubTransport struct {
	status int
}

func (s *stubTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.status}, nil
}

// stubHistogram records observations for test assertions.
type stubHistogram struct {
	calls       int
	lastValue   float64
	lastLabels  []string
}

func (h *stubHistogram) Observe(value float64, labels ...string) {
	h.calls++
	h.lastValue = value
	h.lastLabels = labels
}

func TestMetricsRoundTripper_DisabledPassthrough(t *testing.T) {
	inner := &stubTransport{status: 200}
	mrt := NewMetricsRoundTripper(inner, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	resp, err := mrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestMetricsRoundTripper_RecordsMetrics(t *testing.T) {
	inner := &stubTransport{status: 201}
	hist := &stubHistogram{}
	mrt := NewMetricsRoundTripper(inner, hist)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", nil)
	resp, err := mrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}
	if hist.calls != 1 {
		t.Fatalf("expected 1 observation, got %d", hist.calls)
	}
	if hist.lastValue <= 0 {
		t.Fatal("expected positive duration observation")
	}
	if len(hist.lastLabels) != 2 || hist.lastLabels[0] != "POST" || hist.lastLabels[1] != "201" {
		t.Fatalf("unexpected labels: %v", hist.lastLabels)
	}
}

func BenchmarkMetricsRoundTripper_Disabled(b *testing.B) {
	inner := &stubTransport{status: 200}
	mrt := NewMetricsRoundTripper(inner, nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	b.ReportAllocs()
	for b.Loop() {
		mrt.RoundTrip(req)
	}
}
