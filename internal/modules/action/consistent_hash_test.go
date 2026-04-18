package action

import (
	"fmt"
	"testing"
)

func TestHashRing_EmptyRing(t *testing.T) {
	hr := NewHashRing(10)
	if got := hr.GetNode("key"); got != "" {
		t.Errorf("expected empty string from empty ring, got %q", got)
	}
}

func TestHashRing_SingleNode(t *testing.T) {
	hr := NewHashRing(10)
	hr.AddNode("node-a")

	// All keys should map to the only node
	for i := 0; i < 100; i++ {
		got := hr.GetNode(fmt.Sprintf("key-%d", i))
		if got != "node-a" {
			t.Errorf("expected 'node-a', got %q for key-%d", got, i)
		}
	}
}

func TestHashRing_Consistency(t *testing.T) {
	hr := NewHashRing(150)
	hr.AddNode("node-a")
	hr.AddNode("node-b")
	hr.AddNode("node-c")

	// Same key should always map to the same node
	first := hr.GetNode("session-123")
	for i := 0; i < 100; i++ {
		got := hr.GetNode("session-123")
		if got != first {
			t.Errorf("inconsistent mapping: expected %q, got %q", first, got)
		}
	}
}

func TestHashRing_Distribution(t *testing.T) {
	hr := NewHashRing(150)
	hr.AddNode("node-a")
	hr.AddNode("node-b")
	hr.AddNode("node-c")

	counts := make(map[string]int)
	total := 10000
	for i := 0; i < total; i++ {
		node := hr.GetNode(fmt.Sprintf("key-%d", i))
		counts[node]++
	}

	// Each node should get at least 15% of the keys (expecting ~33%)
	minExpected := total * 15 / 100
	for node, count := range counts {
		if count < minExpected {
			t.Errorf("node %q got only %d/%d keys, expected at least %d", node, count, total, minExpected)
		}
	}
}

func TestHashRing_AddNodeIdempotent(t *testing.T) {
	hr := NewHashRing(10)
	hr.AddNode("node-a")
	before := len(hr.sorted)

	hr.AddNode("node-a") // duplicate add
	after := len(hr.sorted)

	if before != after {
		t.Errorf("duplicate add changed ring size: %d -> %d", before, after)
	}
}

func TestHashRing_RemoveNode(t *testing.T) {
	hr := NewHashRing(10)
	hr.AddNode("node-a")
	hr.AddNode("node-b")

	hr.RemoveNode("node-a")

	// All keys should now map to node-b
	for i := 0; i < 100; i++ {
		got := hr.GetNode(fmt.Sprintf("key-%d", i))
		if got != "node-b" {
			t.Errorf("expected 'node-b' after removal, got %q", got)
		}
	}
}

func TestHashRing_RemoveNonexistent(t *testing.T) {
	hr := NewHashRing(10)
	hr.AddNode("node-a")

	// Should not panic
	hr.RemoveNode("nonexistent")

	if got := hr.GetNode("key"); got != "node-a" {
		t.Errorf("expected 'node-a', got %q", got)
	}
}

func TestHashRing_Nodes(t *testing.T) {
	hr := NewHashRing(10)
	hr.AddNode("node-a")
	hr.AddNode("node-b")
	hr.AddNode("node-c")

	nodes := hr.Nodes()
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}

	nodeSet := make(map[string]bool)
	for _, n := range nodes {
		nodeSet[n] = true
	}
	for _, expected := range []string{"node-a", "node-b", "node-c"} {
		if !nodeSet[expected] {
			t.Errorf("missing node %q", expected)
		}
	}
}

func TestHashRing_MinimalRemapping(t *testing.T) {
	hr := NewHashRing(150)
	hr.AddNode("node-a")
	hr.AddNode("node-b")

	// Record mappings before adding a third node
	total := 1000
	before := make(map[string]string, total)
	for i := 0; i < total; i++ {
		key := fmt.Sprintf("key-%d", i)
		before[key] = hr.GetNode(key)
	}

	hr.AddNode("node-c")

	// Count how many keys changed
	changed := 0
	for i := 0; i < total; i++ {
		key := fmt.Sprintf("key-%d", i)
		if hr.GetNode(key) != before[key] {
			changed++
		}
	}

	// With consistent hashing, adding 1 of 3 nodes should remap roughly 1/3.
	// Allow up to 50% to account for variance.
	maxChanged := total / 2
	if changed > maxChanged {
		t.Errorf("too many remapped keys: %d/%d (max expected %d)", changed, total, maxChanged)
	}
}

func TestHashRing_DefaultReplicas(t *testing.T) {
	hr := NewHashRing(0)
	if hr.replicas != defaultReplicas {
		t.Errorf("expected default replicas %d, got %d", defaultReplicas, hr.replicas)
	}
}
