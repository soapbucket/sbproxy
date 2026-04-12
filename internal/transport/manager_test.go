package transport

import (
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestManager_Dedup(t *testing.T) {
	m := NewManager()
	cfg := plugin.TransportConfig{
		InsecureSkipVerify: false,
		Timeout:            10 * time.Second,
		MaxIdleConns:       50,
	}

	tr1 := m.Get(cfg)
	tr2 := m.Get(cfg)

	if tr1 != tr2 {
		t.Fatal("same config should return the same transport instance")
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 transport, got %d", m.Len())
	}
}

func TestManager_Different(t *testing.T) {
	m := NewManager()

	cfg1 := plugin.TransportConfig{Timeout: 5 * time.Second}
	cfg2 := plugin.TransportConfig{Timeout: 30 * time.Second}

	tr1 := m.Get(cfg1)
	tr2 := m.Get(cfg2)

	if tr1 == tr2 {
		t.Fatal("different configs should return different transport instances")
	}
	if m.Len() != 2 {
		t.Fatalf("expected 2 transports, got %d", m.Len())
	}
}

func TestManager_Concurrent(t *testing.T) {
	m := NewManager()
	cfg := plugin.TransportConfig{
		Timeout:      15 * time.Second,
		MaxIdleConns: 25,
	}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make([]interface{}, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			results[idx] = m.Get(cfg)
		}(i)
	}
	wg.Wait()

	// All goroutines must have received the same transport.
	first := results[0]
	for i := 1; i < goroutines; i++ {
		if results[i] != first {
			t.Fatalf("goroutine %d got different transport instance", i)
		}
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 transport after concurrent access, got %d", m.Len())
	}
}
