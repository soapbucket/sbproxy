package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThreatProtectionMiddleware_ValidJSON(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	middleware := ThreatProtectionMiddleware(config)

	body := `{"name": "test", "items": [1, 2, 3], "nested": {"key": "value"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify body is still readable
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(b))
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestThreatProtectionMiddleware_DeeplyNestedJSON(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.JSON.MaxDepth = 20
	middleware := ThreatProtectionMiddleware(config)

	// Build JSON with 100 levels of nesting (exceeds max of 20)
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < 100; i++ {
		sb.WriteString(`}`)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_TooManyKeys(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.JSON.MaxKeys = 1000
	middleware := ThreatProtectionMiddleware(config)

	// Build JSON with 2000 keys (exceeds max of 1000)
	var sb strings.Builder
	sb.WriteString(`{`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(fmt.Sprintf(`"key_%d": %d`, i, i))
	}
	sb.WriteString(`}`)

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_ValidXML(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	middleware := ThreatProtectionMiddleware(config)

	body := `<?xml version="1.0"?><root><item id="1">Hello</item><item id="2">World</item></root>`
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify body is still readable
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(b))
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestThreatProtectionMiddleware_BillionLaughs(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	middleware := ThreatProtectionMiddleware(config)

	// Classic billion laughs XML bomb pattern with ENTITY declarations
	body := `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>`

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_JSONStringTooLong(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.JSON.MaxStringLength = 100
	middleware := ThreatProtectionMiddleware(config)

	longStr := strings.Repeat("a", 200)
	body := fmt.Sprintf(`{"data": "%s"}`, longStr)

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_JSONArrayTooLarge(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.JSON.MaxArraySize = 10
	middleware := ThreatProtectionMiddleware(config)

	// Build array with 20 elements
	var sb strings.Builder
	sb.WriteString(`{"items": [`)
	for i := 0; i < 20; i++ {
		if i > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(fmt.Sprintf(`%d`, i))
	}
	sb.WriteString(`]}`)

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_JSONTotalSizeExceeded(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.JSON.MaxTotalSize = 100
	middleware := ThreatProtectionMiddleware(config)

	body := `{"data": "` + strings.Repeat("x", 200) + `"}`

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_XMLTooDeep(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.XML.MaxDepth = 5
	middleware := ThreatProtectionMiddleware(config)

	// Build XML with 10 levels of nesting
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?>`)
	for i := 0; i < 10; i++ {
		sb.WriteString(fmt.Sprintf(`<level%d>`, i))
	}
	sb.WriteString(`data`)
	for i := 9; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf(`</level%d>`, i))
	}

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "text/xml")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_XMLTooManyAttributes(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.XML.MaxAttributes = 3
	middleware := ThreatProtectionMiddleware(config)

	// Build element with 5 attributes
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><root`)
	for i := 0; i < 5; i++ {
		sb.WriteString(fmt.Sprintf(` attr%d="val%d"`, i, i))
	}
	sb.WriteString(`>data</root>`)

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/xml")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_XMLTooManyChildren(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	config.XML.MaxChildren = 5
	middleware := ThreatProtectionMiddleware(config)

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><root>`)
	for i := 0; i < 10; i++ {
		sb.WriteString(fmt.Sprintf(`<item>%d</item>`, i))
	}
	sb.WriteString(`</root>`)

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/xml")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestThreatProtectionMiddleware_SkipsGET(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	middleware := ThreatProtectionMiddleware(config)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestThreatProtectionMiddleware_DisabledPassesThrough(t *testing.T) {
	config := &ThreatProtectionConfig{Enabled: false}
	middleware := ThreatProtectionMiddleware(config)

	// Even deeply nested JSON should pass when disabled
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < 100; i++ {
		sb.WriteString(`}`)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestThreatProtectionMiddleware_NonJSONXMLPassesThrough(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	middleware := ThreatProtectionMiddleware(config)

	body := "this is plain text that should pass through"
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(b))
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestThreatProtectionMiddleware_BodyRestoredAfterValidation(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	middleware := ThreatProtectionMiddleware(config)

	original := `{"key": "value", "number": 42, "list": [1, 2, 3]}`
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewBufferString(original))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, original, string(body))
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}
