package keys

import (
	"testing"
)

func TestResolveBudget_KeyInheritsProjectBudget(t *testing.T) {
	key := &VirtualKey{ID: "k1"}
	project := &Project{
		ID:   "proj-1",
		Name: "test-project",
		Budget: &ProjectBudget{
			MaxBudgetUSD: 50.0,
			Period:       "monthly",
		},
	}

	budget, period := ResolveBudget(key, project, 100.0)
	if budget != 50.0 {
		t.Errorf("expected project budget 50.0, got %f", budget)
	}
	if period != "monthly" {
		t.Errorf("expected period 'monthly', got %q", period)
	}
}

func TestResolveBudget_KeyOverridesProject(t *testing.T) {
	key := &VirtualKey{
		ID:           "k1",
		MaxBudgetUSD: 10.0,
		BudgetPeriod: "daily",
	}
	project := &Project{
		Budget: &ProjectBudget{MaxBudgetUSD: 50.0, Period: "monthly"},
	}

	budget, period := ResolveBudget(key, project, 100.0)
	if budget != 10.0 {
		t.Errorf("expected key budget 10.0, got %f", budget)
	}
	if period != "daily" {
		t.Errorf("expected period 'daily', got %q", period)
	}
}

func TestResolveBudget_ProjectSeparateFromWorkspace(t *testing.T) {
	key := &VirtualKey{ID: "k1"}
	project := &Project{
		Budget: &ProjectBudget{MaxBudgetUSD: 25.0, Period: "daily"},
	}

	budget, period := ResolveBudget(key, project, 500.0)
	// Project budget should take precedence over workspace.
	if budget != 25.0 {
		t.Errorf("expected project budget 25.0, got %f", budget)
	}
	if period != "daily" {
		t.Errorf("expected period 'daily', got %q", period)
	}
}

func TestResolveBudget_FallsBackToWorkspace(t *testing.T) {
	key := &VirtualKey{ID: "k1"}

	budget, period := ResolveBudget(key, nil, 200.0)
	if budget != 200.0 {
		t.Errorf("expected workspace budget 200.0, got %f", budget)
	}
	if period != "monthly" {
		t.Errorf("expected period 'monthly', got %q", period)
	}
}

func TestResolveBudget_NoBudgetReturnsZero(t *testing.T) {
	key := &VirtualKey{ID: "k1"}

	budget, period := ResolveBudget(key, nil, 0)
	if budget != 0 {
		t.Errorf("expected 0, got %f", budget)
	}
	if period != "" {
		t.Errorf("expected empty period, got %q", period)
	}
}

func TestResolveTokenBudget_KeyTakesPriority(t *testing.T) {
	key := &VirtualKey{ID: "k1", MaxTokens: 1000}
	project := &Project{
		Budget: &ProjectBudget{MaxTokens: 5000},
	}

	tokens := ResolveTokenBudget(key, project)
	if tokens != 1000 {
		t.Errorf("expected 1000, got %d", tokens)
	}
}

func TestResolveTokenBudget_FallsToProject(t *testing.T) {
	key := &VirtualKey{ID: "k1"}
	project := &Project{
		Budget: &ProjectBudget{MaxTokens: 5000},
	}

	tokens := ResolveTokenBudget(key, project)
	if tokens != 5000 {
		t.Errorf("expected 5000, got %d", tokens)
	}
}

func TestResolveModels_ProjectConstrainsKey(t *testing.T) {
	key := &VirtualKey{
		AllowedModels: []string{"gpt-4", "gpt-3.5-turbo", "claude-3"},
	}
	project := &Project{
		Models: []string{"gpt-4", "claude-3"},
	}

	models := ResolveModels(key, project)
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d: %v", len(models), models)
	}
	found := map[string]bool{}
	for _, m := range models {
		found[m] = true
	}
	if !found["gpt-4"] || !found["claude-3"] {
		t.Errorf("expected gpt-4 and claude-3, got %v", models)
	}
}

func TestResolveModels_NoProjectReturnsKeyModels(t *testing.T) {
	key := &VirtualKey{
		AllowedModels: []string{"gpt-4"},
	}

	models := ResolveModels(key, nil)
	if len(models) != 1 || models[0] != "gpt-4" {
		t.Errorf("expected [gpt-4], got %v", models)
	}
}

func TestResolveModels_NoKeyModelsReturnsProjectModels(t *testing.T) {
	key := &VirtualKey{}
	project := &Project{Models: []string{"claude-3"}}

	models := ResolveModels(key, project)
	if len(models) != 1 || models[0] != "claude-3" {
		t.Errorf("expected [claude-3], got %v", models)
	}
}
