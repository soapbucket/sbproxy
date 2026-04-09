package orchestration

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/config/callback"
)

// TestBuildDependencyGraph tests building a dependency graph
func TestBuildDependencyGraph(t *testing.T) {
	steps := []Step{
		{name: "step1", callback: &callback.Callback{URL: "http://api1"}},
		{name: "step2", callback: &callback.Callback{URL: "http://api2"}, dependsOn: []string{"step1"}},
		{name: "step3", callback: &callback.Callback{URL: "http://api3"}, dependsOn: []string{"step1", "step2"}},
	}

	graph, err := buildDependencyGraph(steps)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	if len(graph.nodes) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(graph.nodes))
	}

	// Check dependencies
	step2Node := graph.nodes["step2"]
	if len(step2Node.dependencies) != 1 {
		t.Errorf("step2 should have 1 dependency, got %d", len(step2Node.dependencies))
	}

	step3Node := graph.nodes["step3"]
	if len(step3Node.dependencies) != 2 {
		t.Errorf("step3 should have 2 dependencies, got %d", len(step3Node.dependencies))
	}
}

// TestDependencyGraph_CycleDetection tests cycle detection
func TestDependencyGraph_CycleDetection(t *testing.T) {
	tests := []struct {
		name      string
		steps     []Step
		hasCycle  bool
	}{
		{
			name: "No cycle - linear",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}},
				{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
				{name: "c", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"b"}},
			},
			hasCycle: false,
		},
		{
			name: "No cycle - diamond",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}},
				{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
				{name: "c", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
				{name: "d", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"b", "c"}},
			},
			hasCycle: false,
		},
		{
			name: "Cycle - self reference",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
			},
			hasCycle: true,
		},
		{
			name: "Cycle - circular",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"b"}},
				{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
			},
			hasCycle: true,
		},
		{
			name: "Cycle - longer chain",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"c"}},
				{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
				{name: "c", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"b"}},
			},
			hasCycle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph, err := buildDependencyGraph(tt.steps)
			if err != nil {
				t.Fatalf("Failed to build graph: %v", err)
			}

			hasCycle := graph.hasCycle()
			if hasCycle != tt.hasCycle {
				t.Errorf("Expected hasCycle=%v, got=%v", tt.hasCycle, hasCycle)
			}
		})
	}
}

// TestDependencyGraph_TopologicalSort tests topological sorting
func TestDependencyGraph_TopologicalSort(t *testing.T) {
	steps := []Step{
		{name: "c", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a", "b"}},
		{name: "a", callback: &callback.Callback{URL: "http://api"}},
		{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
	}

	graph, err := buildDependencyGraph(steps)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	sorted := graph.topologicalSort()

	// Expected order: a, b, c (or any valid topological order)
	// Verify: a comes before b and c, b comes before c
	positions := make(map[string]int)
	for i, step := range sorted {
		positions[step.name] = i
	}

	if positions["a"] >= positions["b"] {
		t.Errorf("a should come before b, got order: %v", sorted)
	}
	if positions["a"] >= positions["c"] {
		t.Errorf("a should come before c, got order: %v", sorted)
	}
	if positions["b"] >= positions["c"] {
		t.Errorf("b should come before c, got order: %v", sorted)
	}
}

// TestDependencyGraph_Levels tests level calculation for parallel execution
func TestDependencyGraph_Levels(t *testing.T) {
	steps := []Step{
		{name: "a", callback: &callback.Callback{URL: "http://api"}},
		{name: "b", callback: &callback.Callback{URL: "http://api"}},
		{name: "c", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
		{name: "d", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a", "b"}},
		{name: "e", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"c", "d"}},
	}

	graph, err := buildDependencyGraph(steps)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	levels := graph.getLevels()

	// Expected levels:
	// Level 0: a, b (no dependencies)
	// Level 1: c (depends on a)
	// Level 2: d (depends on a, b - max is level 0, so this is level 1)
	//          Actually, both a and b are at level 0, so d is at level 1
	// Level 2: e (depends on c at level 1, d at level 1, so e is at level 2)

	if len(levels) < 3 {
		t.Fatalf("Expected at least 3 levels, got %d", len(levels))
	}

	// Check level 0 contains a and b
	level0Names := make(map[string]bool)
	for _, step := range levels[0] {
		level0Names[step.name] = true
	}
	if !level0Names["a"] || !level0Names["b"] {
		t.Errorf("Level 0 should contain a and b, got: %v", levels[0])
	}

	// Check level 1 contains c and d
	level1Names := make(map[string]bool)
	for _, step := range levels[1] {
		level1Names[step.name] = true
	}
	if !level1Names["c"] || !level1Names["d"] {
		t.Errorf("Level 1 should contain c and d, got: %v", levels[1])
	}

	// Check level 2 contains e
	level2Names := make(map[string]bool)
	for _, step := range levels[2] {
		level2Names[step.name] = true
	}
	if !level2Names["e"] {
		t.Errorf("Level 2 should contain e, got: %v", levels[2])
	}
}

// TestDependencyGraph_Validate tests graph validation
func TestDependencyGraph_Validate(t *testing.T) {
	tests := []struct {
		name        string
		steps       []Step
		shouldError bool
		errorMsg    string
	}{
		{
			name: "Valid graph",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}},
				{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
			},
			shouldError: false,
		},
		{
			name: "Circular dependency",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"b"}},
				{name: "b", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"a"}},
			},
			shouldError: true,
			errorMsg:    "circular dependency",
		},
		{
			name: "Unknown dependency",
			steps: []Step{
				{name: "a", callback: &callback.Callback{URL: "http://api"}, dependsOn: []string{"unknown"}},
			},
			shouldError: true,
			errorMsg:    "unknown step",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph, err := buildDependencyGraph(tt.steps)
			
			if tt.shouldError {
				if err == nil {
					err = graph.Validate()
				}
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if graph.Validate() != nil {
					t.Errorf("Expected valid graph, got error: %v", graph.Validate())
				}
			}
		})
	}
}

