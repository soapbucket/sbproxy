package response

import (
	"fmt"
	"testing"
)

func TestHash_Deterministic(t *testing.T) {
	data := []byte("hello world")
	h1 := Hash(data)
	h2 := Hash(data)
	if h1 != h2 {
		t.Errorf("expected identical hashes, got %q and %q", h1, h2)
	}
}

func TestHash_DifferentInputs(t *testing.T) {
	h1 := Hash([]byte("hello"))
	h2 := Hash([]byte("world"))
	if h1 == h2 {
		t.Error("expected different hashes for different inputs")
	}
}

func TestHash_EmptyInput(t *testing.T) {
	h := Hash([]byte{})
	if h == "" {
		t.Error("expected non-empty hash for empty input")
	}
	// SHA-256 of empty input is well-known
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if h != expected {
		t.Errorf("expected SHA-256 of empty, got %q", h)
	}
}

func TestDeduplicator_NewResponse(t *testing.T) {
	d := NewDeduplicator(100)

	provider, found := d.Check([]byte("response-1"))
	if found {
		t.Error("expected new response to not be found")
	}
	if provider != "" {
		t.Errorf("expected empty provider, got %q", provider)
	}
}

func TestDeduplicator_DuplicateDetection(t *testing.T) {
	d := NewDeduplicator(100)

	data := []byte("same response")
	d.Record(data, "openai")

	provider, found := d.Check(data)
	if !found {
		t.Fatal("expected duplicate to be found")
	}
	if provider != "openai" {
		t.Errorf("expected provider 'openai', got %q", provider)
	}
}

func TestDeduplicator_DifferentProvidersSameResponse(t *testing.T) {
	d := NewDeduplicator(100)

	data := []byte("identical response")
	d.Record(data, "provider-a")
	d.Record(data, "provider-b") // should not overwrite

	provider, found := d.Check(data)
	if !found {
		t.Fatal("expected duplicate to be found")
	}
	if provider != "provider-a" {
		t.Errorf("expected first provider 'provider-a', got %q", provider)
	}
}

func TestDeduplicator_DifferentResponses(t *testing.T) {
	d := NewDeduplicator(100)

	d.Record([]byte("response-a"), "openai")

	_, found := d.Check([]byte("response-b"))
	if found {
		t.Error("expected different response to not be found")
	}
}

func TestDeduplicator_MaxEntries(t *testing.T) {
	d := NewDeduplicator(5)

	for i := 0; i < 10; i++ {
		d.Record([]byte(fmt.Sprintf("response-%d", i)), fmt.Sprintf("provider-%d", i))
	}

	if d.Len() > 5 {
		t.Errorf("expected at most 5 entries, got %d", d.Len())
	}
}

func TestDeduplicator_Reset(t *testing.T) {
	d := NewDeduplicator(100)

	d.Record([]byte("data"), "provider")
	d.Reset()

	if d.Len() != 0 {
		t.Errorf("expected 0 entries after reset, got %d", d.Len())
	}

	_, found := d.Check([]byte("data"))
	if found {
		t.Error("expected no match after reset")
	}
}

func TestDeduplicator_DefaultMaxEntries(t *testing.T) {
	d := NewDeduplicator(0)
	if d.maxEntries != defaultMaxDedupEntries {
		t.Errorf("expected default %d, got %d", defaultMaxDedupEntries, d.maxEntries)
	}
}

func TestDeduplicator_Len(t *testing.T) {
	d := NewDeduplicator(100)
	if d.Len() != 0 {
		t.Errorf("expected 0, got %d", d.Len())
	}

	d.Record([]byte("a"), "p1")
	d.Record([]byte("b"), "p2")
	if d.Len() != 2 {
		t.Errorf("expected 2, got %d", d.Len())
	}
}
