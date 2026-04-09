package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubAction struct {
	handler http.Handler
}

func (s *stubAction) Init(*Config) error               { return nil }
func (s *stubAction) GetType() string                  { return "stub" }
func (s *stubAction) Rewrite() RewriteFn               { return nil }
func (s *stubAction) Transport() TransportFn           { return nil }
func (s *stubAction) Handler() http.Handler            { return s.handler }
func (s *stubAction) ModifyResponse() ModifyResponseFn { return nil }
func (s *stubAction) ErrorHandler() ErrorHandlerFn     { return nil }
func (s *stubAction) IsProxy() bool                    { return false }

type stubPolicy struct {
	BasePolicy
	calls int
}

func (p *stubPolicy) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls++
		w.Header().Add("X-Policy", "applied")
		next.ServeHTTP(w, r)
	})
}

func TestConfigServeHTTP_ReusesCompiledHandler(t *testing.T) {
	policy := &stubPolicy{}
	actionCalls := 0
	cfg := &Config{
		ID: "cfg-1",
		action: &stubAction{
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actionCalls++
				w.WriteHeader(http.StatusNoContent)
			}),
		},
		policies: []PolicyConfig{policy},
	}

	req1 := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	rr1 := httptest.NewRecorder()
	cfg.ServeHTTP(rr1, req1)

	if cfg.compiledHandler == nil {
		t.Fatal("expected compiled handler to be cached after first request")
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	rr2 := httptest.NewRecorder()
	cfg.ServeHTTP(rr2, req2)

	if cfg.compiledHandler == nil {
		t.Fatal("expected compiled handler to remain cached after second request")
	}
	if actionCalls != 2 {
		t.Fatalf("expected action handler to run twice, got %d", actionCalls)
	}
	if policy.calls != 2 {
		t.Fatalf("expected policy to run twice, got %d", policy.calls)
	}
	if got := rr2.Header().Values("X-Policy"); len(got) != 1 || got[0] != "applied" {
		t.Fatalf("expected compiled pipeline to preserve policy behavior, got %v", got)
	}
}
