package transformer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockStreamingTransform is a test double that uppercases data in streaming mode.
type mockStreamingTransform struct {
	streaming bool
}

func (m *mockStreamingTransform) Modify(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	upper := strings.ToUpper(string(data))
	resp.Body = io.NopCloser(strings.NewReader(upper))
	resp.ContentLength = int64(len(upper))
	return nil
}

func (m *mockStreamingTransform) SupportsStreaming() bool {
	return m.streaming
}

func (m *mockStreamingTransform) ApplyStream(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	_, err = out.Write([]byte(strings.ToUpper(string(data))))
	return err
}

func TestApplyStreaming(t *testing.T) {
	body := "hello world"
	resp := &http.Response{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	st := &mockStreamingTransform{streaming: true}
	if err := applyStreaming(resp, st); err != nil {
		t.Fatalf("applyStreaming returned error: %v", err)
	}

	// ContentLength should be -1 after streaming transform
	if resp.ContentLength != -1 {
		t.Errorf("expected ContentLength -1, got %d", resp.ContentLength)
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading transformed body: %v", err)
	}

	expected := "HELLO WORLD"
	if string(result) != expected {
		t.Errorf("expected %q, got %q", expected, string(result))
	}
}

func TestApplyStreaming_NilBody(t *testing.T) {
	resp := &http.Response{Body: nil}
	st := &mockStreamingTransform{streaming: true}
	if err := applyStreaming(resp, st); err != nil {
		t.Fatalf("expected nil error for nil body, got: %v", err)
	}
}

func TestWrapStreamingStage_Streaming(t *testing.T) {
	body := "test data"
	resp := &http.Response{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	st := &mockStreamingTransform{streaming: true}
	used, err := wrapStreamingStage(resp, st)
	if err != nil {
		t.Fatalf("wrapStreamingStage returned error: %v", err)
	}
	if !used {
		t.Fatal("expected streaming to be used")
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(result) != "TEST DATA" {
		t.Errorf("expected %q, got %q", "TEST DATA", string(result))
	}
}

func TestWrapStreamingStage_NotStreaming(t *testing.T) {
	body := "test data"
	resp := &http.Response{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	st := &mockStreamingTransform{streaming: false}
	used, err := wrapStreamingStage(resp, st)
	if err != nil {
		t.Fatalf("wrapStreamingStage returned error: %v", err)
	}
	if used {
		t.Fatal("expected streaming to not be used when SupportsStreaming is false")
	}
}

func TestWrapStreamingStage_NonStreamingTransformer(t *testing.T) {
	body := "test data"
	resp := &http.Response{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	// A plain Transformer that does not implement StreamingTransform
	plain := Func(func(r *http.Response) error { return nil })
	used, err := wrapStreamingStage(resp, plain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if used {
		t.Fatal("expected streaming to not be used for plain Transformer")
	}
}

func TestStreamingFunc_StreamingMode(t *testing.T) {
	sf := &StreamingFunc{
		StreamFn: func(in io.Reader, out io.Writer) error {
			data, err := io.ReadAll(in)
			if err != nil {
				return err
			}
			_, err = out.Write(bytes.ToUpper(data))
			return err
		},
		Streaming: true,
	}

	if !sf.SupportsStreaming() {
		t.Fatal("expected SupportsStreaming to be true")
	}

	body := "streaming test"
	resp := &http.Response{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	used, err := wrapStreamingStage(resp, sf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !used {
		t.Fatal("expected streaming to be used")
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(result) != "STREAMING TEST" {
		t.Errorf("expected %q, got %q", "STREAMING TEST", string(result))
	}
}

func TestStreamingFunc_FallbackModify(t *testing.T) {
	sf := &StreamingFunc{
		StreamFn: func(in io.Reader, out io.Writer) error {
			data, err := io.ReadAll(in)
			if err != nil {
				return err
			}
			_, err = out.Write(bytes.ToUpper(data))
			return err
		},
		Streaming: false, // streaming disabled, Modify should use StreamFn as fallback
	}

	body := "fallback test"
	resp := &http.Response{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	if err := sf.Modify(resp); err != nil {
		t.Fatalf("Modify returned error: %v", err)
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(result) != "FALLBACK TEST" {
		t.Errorf("expected %q, got %q", "FALLBACK TEST", string(result))
	}
	if resp.ContentLength != int64(len("FALLBACK TEST")) {
		t.Errorf("expected ContentLength %d, got %d", len("FALLBACK TEST"), resp.ContentLength)
	}
}
