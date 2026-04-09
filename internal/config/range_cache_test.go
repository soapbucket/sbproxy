package config

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- parseRangeHeader tests ---

func TestParseRangeHeader_SingleRange(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		contentLength int64
		wantStart     int64
		wantEnd       int64
		wantErr       bool
	}{
		{
			name:          "first 500 bytes",
			header:        "bytes=0-499",
			contentLength: 1000,
			wantStart:     0,
			wantEnd:       499,
		},
		{
			name:          "second 500 bytes",
			header:        "bytes=500-999",
			contentLength: 1000,
			wantStart:     500,
			wantEnd:       999,
		},
		{
			name:          "open ended range",
			header:        "bytes=500-",
			contentLength: 1000,
			wantStart:     500,
			wantEnd:       999,
		},
		{
			name:          "suffix range last 500",
			header:        "bytes=-500",
			contentLength: 1000,
			wantStart:     500,
			wantEnd:       999,
		},
		{
			name:          "suffix range larger than content",
			header:        "bytes=-2000",
			contentLength: 1000,
			wantStart:     0,
			wantEnd:       999,
		},
		{
			name:          "end clamped to content length",
			header:        "bytes=900-1500",
			contentLength: 1000,
			wantStart:     900,
			wantEnd:       999,
		},
		{
			name:          "single byte",
			header:        "bytes=0-0",
			contentLength: 1000,
			wantStart:     0,
			wantEnd:       0,
		},
		{
			name:          "last byte",
			header:        "bytes=-1",
			contentLength: 1000,
			wantStart:     999,
			wantEnd:       999,
		},
		{
			name:          "start beyond content length",
			header:        "bytes=1000-1500",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "unsupported unit",
			header:        "items=0-5",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "end less than start",
			header:        "bytes=500-100",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "zero content length",
			header:        "bytes=0-0",
			contentLength: 0,
			wantErr:       true,
		},
		{
			name:          "negative content length",
			header:        "bytes=0-0",
			contentLength: -1,
			wantErr:       true,
		},
		{
			name:          "missing dash",
			header:        "bytes=500",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "empty suffix",
			header:        "bytes=-",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "negative start",
			header:        "bytes=-0",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "non-numeric start",
			header:        "bytes=abc-500",
			contentLength: 1000,
			wantErr:       true,
		},
		{
			name:          "non-numeric end",
			header:        "bytes=0-abc",
			contentLength: 1000,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := parseRangeHeader(tt.header, tt.contentLength)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ranges: %+v", ranges)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(ranges) != 1 {
				t.Fatalf("expected 1 range, got %d", len(ranges))
			}
			if ranges[0].start != tt.wantStart {
				t.Errorf("start: got %d, want %d", ranges[0].start, tt.wantStart)
			}
			if ranges[0].end != tt.wantEnd {
				t.Errorf("end: got %d, want %d", ranges[0].end, tt.wantEnd)
			}
		})
	}
}

func TestParseRangeHeader_MultipleRanges(t *testing.T) {
	ranges, err := parseRangeHeader("bytes=0-499, 600-799, -200", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranges) != 3 {
		t.Fatalf("expected 3 ranges, got %d", len(ranges))
	}

	expected := []byteRange{
		{start: 0, end: 499},
		{start: 600, end: 799},
		{start: 800, end: 999},
	}
	for i, r := range ranges {
		if r.start != expected[i].start || r.end != expected[i].end {
			t.Errorf("range %d: got %d-%d, want %d-%d", i, r.start, r.end, expected[i].start, expected[i].end)
		}
	}
}

func TestParseRangeHeader_WhitespaceHandling(t *testing.T) {
	ranges, err := parseRangeHeader("bytes= 0 - 499 ", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].start != 0 || ranges[0].end != 499 {
		t.Errorf("got %d-%d, want 0-499", ranges[0].start, ranges[0].end)
	}
}

// --- buildContentRangeHeader tests ---

func TestBuildContentRangeHeader(t *testing.T) {
	tests := []struct {
		start, end, total int64
		want              string
	}{
		{0, 499, 1000, "bytes 0-499/1000"},
		{500, 999, 1000, "bytes 500-999/1000"},
		{0, 0, 1, "bytes 0-0/1"},
	}
	for _, tt := range tests {
		got := buildContentRangeHeader(tt.start, tt.end, tt.total)
		if got != tt.want {
			t.Errorf("buildContentRangeHeader(%d, %d, %d) = %q, want %q", tt.start, tt.end, tt.total, got, tt.want)
		}
	}
}

func TestBuildUnsatisfiedContentRange(t *testing.T) {
	got := buildUnsatisfiedContentRange(1000)
	if got != "bytes */1000" {
		t.Errorf("got %q, want %q", got, "bytes */1000")
	}
}

// --- buildMultipartRangeResponse tests ---

func TestBuildMultipartRangeResponse(t *testing.T) {
	body := []byte("Hello, World!")
	ranges := []byteRange{
		{start: 0, end: 4},
		{start: 7, end: 11},
	}

	result, boundary := buildMultipartRangeResponse(ranges, body, "text/plain")

	resultStr := string(result)

	// Verify boundary is present
	if boundary == "" {
		t.Fatal("boundary should not be empty")
	}

	// Verify structure
	if !strings.Contains(resultStr, "--"+boundary) {
		t.Error("missing boundary markers")
	}
	if !strings.Contains(resultStr, "--"+boundary+"--") {
		t.Error("missing closing boundary")
	}
	if !strings.Contains(resultStr, "Content-Type: text/plain") {
		t.Error("missing Content-Type in part")
	}
	if !strings.Contains(resultStr, "Content-Range: bytes 0-4/13") {
		t.Error("missing first Content-Range")
	}
	if !strings.Contains(resultStr, "Content-Range: bytes 7-11/13") {
		t.Error("missing second Content-Range")
	}
	if !strings.Contains(resultStr, "Hello") {
		t.Error("missing first range body")
	}
	if !strings.Contains(resultStr, "World") {
		t.Error("missing second range body")
	}
}

// --- serveRangeFromCache tests ---

func newRangeRequest(method, rangeHeader string) *http.Request {
	r := httptest.NewRequest(method, "http://example.com/file.bin", nil)
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	return r
}

func makeCachedHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/octet-stream")
	h.Set("ETag", `"abc123"`)
	h.Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
	return h
}

func TestServeRangeFromCache_SingleRange(t *testing.T) {
	body := make([]byte, 1000)
	for i := range body {
		body[i] = byte(i % 256)
	}
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-499")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected range to be served")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes 0-499/1000" {
		t.Errorf("Content-Range: got %q, want %q", cr, "bytes 0-499/1000")
	}
	if cl := resp.Header.Get("Content-Length"); cl != "500" {
		t.Errorf("Content-Length: got %q, want %q", cl, "500")
	}
	if w.Body.Len() != 500 {
		t.Errorf("body length: got %d, want 500", w.Body.Len())
	}
	// Verify correct bytes
	for i := 0; i < 500; i++ {
		if w.Body.Bytes()[i] != body[i] {
			t.Errorf("body byte %d: got %d, want %d", i, w.Body.Bytes()[i], body[i])
			break
		}
	}
}

func TestServeRangeFromCache_MultipleRanges(t *testing.T) {
	body := []byte("0123456789abcdef")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-3, 10-13")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected range to be served")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/byteranges; boundary=") {
		t.Errorf("Content-Type: got %q, want multipart/byteranges", ct)
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "0123") {
		t.Error("missing first range data")
	}
	if !strings.Contains(respBody, "abcd") {
		t.Error("missing second range data")
	}
}

func TestServeRangeFromCache_NotGetRequest(t *testing.T) {
	body := []byte("test")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodPost, "bytes=0-3")

	if serveRangeFromCache(w, r, body, headers) {
		t.Fatal("should not serve range for POST request")
	}
}

func TestServeRangeFromCache_NoRangeHeader(t *testing.T) {
	body := []byte("test")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "")

	if serveRangeFromCache(w, r, body, headers) {
		t.Fatal("should not serve range without Range header")
	}
}

func TestServeRangeFromCache_UnsatisfiableRange(t *testing.T) {
	body := []byte("test") // 4 bytes
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=10-20")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected 416 to be served")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusRequestedRangeNotSatisfiable)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes */4" {
		t.Errorf("Content-Range: got %q, want %q", cr, "bytes */4")
	}
}

func TestServeRangeFromCache_MalformedRange(t *testing.T) {
	body := []byte("test")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "items=0-3")

	// Malformed/unsupported unit should fall through (return false)
	if serveRangeFromCache(w, r, body, headers) {
		t.Fatal("should not serve range with unsupported unit")
	}
}

func TestServeRangeFromCache_HeadersCopied(t *testing.T) {
	body := []byte("Hello, World!")
	headers := makeCachedHeaders()
	headers.Set("Cache-Control", "max-age=3600")

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")

	serveRangeFromCache(w, r, body, headers)

	resp := w.Result()
	if resp.Header.Get("ETag") != `"abc123"` {
		t.Errorf("ETag not copied: got %q", resp.Header.Get("ETag"))
	}
	if resp.Header.Get("Cache-Control") != "max-age=3600" {
		t.Errorf("Cache-Control not copied: got %q", resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Last-Modified") != "Mon, 02 Jan 2006 15:04:05 GMT" {
		t.Errorf("Last-Modified not copied: got %q", resp.Header.Get("Last-Modified"))
	}
}

// --- If-Range tests ---

func TestServeRangeFromCache_IfRangeETagMatch(t *testing.T) {
	body := []byte("Hello, World!")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")
	r.Header.Set("If-Range", `"abc123"`)

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected range to be served when If-Range ETag matches")
	}
	if w.Result().StatusCode != http.StatusPartialContent {
		t.Errorf("status: got %d, want %d", w.Result().StatusCode, http.StatusPartialContent)
	}
}

func TestServeRangeFromCache_IfRangeETagMismatch(t *testing.T) {
	body := []byte("Hello, World!")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")
	r.Header.Set("If-Range", `"different-etag"`)

	served := serveRangeFromCache(w, r, body, headers)
	if served {
		t.Fatal("should not serve range when If-Range ETag does not match")
	}
}

func TestServeRangeFromCache_IfRangeWeakETag(t *testing.T) {
	body := []byte("Hello, World!")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")
	r.Header.Set("If-Range", `W/"abc123"`)

	// Weak ETags must not match for If-Range (strong comparison required)
	served := serveRangeFromCache(w, r, body, headers)
	if served {
		t.Fatal("should not serve range with weak ETag in If-Range")
	}
}

func TestServeRangeFromCache_IfRangeDateMatch(t *testing.T) {
	body := []byte("Hello, World!")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")
	r.Header.Set("If-Range", "Mon, 02 Jan 2006 15:04:05 GMT")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected range to be served when If-Range date matches")
	}
}

func TestServeRangeFromCache_IfRangeDateMismatch(t *testing.T) {
	body := []byte("Hello, World!")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")
	r.Header.Set("If-Range", "Tue, 03 Jan 2006 15:04:05 GMT")

	served := serveRangeFromCache(w, r, body, headers)
	if served {
		t.Fatal("should not serve range when If-Range date does not match")
	}
}

// --- evaluateIfRange unit tests ---

func TestEvaluateIfRange_NoETagInCache(t *testing.T) {
	h := http.Header{}
	if evaluateIfRange(`"some-etag"`, h) {
		t.Error("should return false when cached response has no ETag")
	}
}

func TestEvaluateIfRange_WeakCachedETag(t *testing.T) {
	h := http.Header{}
	h.Set("ETag", `W/"abc"`)
	if evaluateIfRange(`W/"abc"`, h) {
		t.Error("should return false with weak ETags")
	}
}

func TestEvaluateIfRange_InvalidDate(t *testing.T) {
	h := http.Header{}
	h.Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
	if evaluateIfRange("not-a-date", h) {
		t.Error("should return false for unparseable date")
	}
}

func TestEvaluateIfRange_NoLastModified(t *testing.T) {
	h := http.Header{}
	if evaluateIfRange("Mon, 02 Jan 2006 15:04:05 GMT", h) {
		t.Error("should return false when no Last-Modified in cache")
	}
}

// --- Edge cases ---

func TestServeRangeFromCache_SuffixRange(t *testing.T) {
	body := []byte("0123456789")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=-3")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected suffix range to be served")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("status: got %d, want 206", resp.StatusCode)
	}
	if w.Body.String() != "789" {
		t.Errorf("body: got %q, want %q", w.Body.String(), "789")
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes 7-9/10" {
		t.Errorf("Content-Range: got %q, want %q", cr, "bytes 7-9/10")
	}
}

func TestServeRangeFromCache_OpenEndedRange(t *testing.T) {
	body := []byte("0123456789")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=5-")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected open-ended range to be served")
	}

	if w.Body.String() != "56789" {
		t.Errorf("body: got %q, want %q", w.Body.String(), "56789")
	}
}

func TestServeRangeFromCache_EntireContent(t *testing.T) {
	body := []byte("Hello")
	headers := makeCachedHeaders()

	w := httptest.NewRecorder()
	r := newRangeRequest(http.MethodGet, "bytes=0-4")

	served := serveRangeFromCache(w, r, body, headers)
	if !served {
		t.Fatal("expected range to be served")
	}

	if w.Body.String() != "Hello" {
		t.Errorf("body: got %q, want %q", w.Body.String(), "Hello")
	}
	if cr := w.Result().Header.Get("Content-Range"); cr != "bytes 0-4/5" {
		t.Errorf("Content-Range: got %q, want %q", cr, "bytes 0-4/5")
	}
}
