package storage_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	storagemod "github.com/soapbucket/sbproxy/internal/modules/action/storage"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"kind":"s3","bucket":"my-bucket","region":"us-east-1"}`)
	h, err := storagemod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := storagemod.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_MissingKind(t *testing.T) {
	_, err := storagemod.New(json.RawMessage(`{"bucket":"my-bucket"}`))
	if err == nil {
		t.Fatal("expected error when kind is missing")
	}
}

func TestNew_MissingBucket(t *testing.T) {
	_, err := storagemod.New(json.RawMessage(`{"kind":"s3"}`))
	if err == nil {
		t.Fatal("expected error when bucket is missing")
	}
}

func TestNew_InvalidKind(t *testing.T) {
	_, err := storagemod.New(json.RawMessage(`{"kind":"dropbox","bucket":"my-bucket"}`))
	if err == nil {
		t.Fatal("expected error for invalid storage kind")
	}
}

func TestNew_AllValidKinds(t *testing.T) {
	kinds := []string{"s3", "azure", "google", "swift", "b2"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			raw := json.RawMessage(`{"kind":"` + kind + `","bucket":"test-bucket"}`)
			h, err := storagemod.New(raw)
			if err != nil {
				t.Fatalf("New(%s): %v", kind, err)
			}
			if h == nil {
				t.Fatal("expected handler, got nil")
			}
		})
	}
}

func TestType(t *testing.T) {
	h, _ := storagemod.New(json.RawMessage(`{"kind":"s3","bucket":"my-bucket"}`))
	if h.Type() != "storage" {
		t.Errorf("Type() = %q, want %q", h.Type(), "storage")
	}
}

func TestServeHTTP_DirectNotSupported(t *testing.T) {
	h, _ := storagemod.New(json.RawMessage(`{"kind":"s3","bucket":"my-bucket"}`))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestTransport_NotNil(t *testing.T) {
	h, _ := storagemod.New(json.RawMessage(`{"kind":"s3","bucket":"my-bucket"}`))
	rpa, ok := h.(plugin.ReverseProxyAction)
	if !ok {
		t.Fatal("handler does not implement ReverseProxyAction")
	}
	if rpa.Transport() == nil {
		t.Error("Transport() should not return nil")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("storage")
	if !ok {
		t.Error("storage action not registered in plugin registry")
	}
}
