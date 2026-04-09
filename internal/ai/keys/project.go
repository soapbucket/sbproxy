package keys

// Project represents a logical grouping of virtual keys within a workspace.
// Projects provide an intermediate level in the budget hierarchy:
// workspace > project > key.
type Project struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	WorkspaceID string            `json:"workspace_id"`
	Budget      *ProjectBudget    `json:"budget,omitempty"`
	RateLimit   *ProjectRateLimit `json:"rate_limit,omitempty"`
	Models      []string          `json:"models,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// ProjectBudget defines spending limits at the project level.
type ProjectBudget struct {
	MaxBudgetUSD float64 `json:"max_budget_usd"`
	Period       string  `json:"period"` // "daily", "monthly", "total"
	MaxTokens    int64   `json:"max_tokens,omitempty"`
}

// ProjectRateLimit defines rate limits at the project level.
type ProjectRateLimit struct {
	MaxRequestsPerMin int `json:"max_requests_per_min,omitempty"`
	MaxTokensPerMin   int `json:"max_tokens_per_min,omitempty"`
}

// ProjectStore defines the interface for project CRUD operations.
type ProjectStore interface {
	GetProject(id string) (*Project, error)
	ListProjects(workspaceID string) ([]*Project, error)
}

// ResolveBudget returns the effective budget for a key, walking the hierarchy:
// key budget > project budget > workspace budget. The first non-zero budget found
// is returned. If no budget is set at any level, returns zero values.
func ResolveBudget(key *VirtualKey, project *Project, workspaceBudgetUSD float64) (maxBudgetUSD float64, period string) {
	// Level 1: Key-level budget (most specific).
	if key != nil && key.MaxBudgetUSD > 0 {
		return key.MaxBudgetUSD, key.BudgetPeriod
	}

	// Level 2: Project-level budget.
	if project != nil && project.Budget != nil && project.Budget.MaxBudgetUSD > 0 {
		return project.Budget.MaxBudgetUSD, project.Budget.Period
	}

	// Level 3: Workspace-level budget (least specific).
	if workspaceBudgetUSD > 0 {
		return workspaceBudgetUSD, "monthly"
	}

	return 0, ""
}

// ResolveTokenBudget returns the effective token budget, walking the same hierarchy.
func ResolveTokenBudget(key *VirtualKey, project *Project) int64 {
	// Key-level token budget takes priority.
	if key != nil && key.MaxTokens > 0 {
		return key.MaxTokens
	}

	// Project-level token budget.
	if project != nil && project.Budget != nil && project.Budget.MaxTokens > 0 {
		return project.Budget.MaxTokens
	}

	return 0
}

// ResolveModels returns the effective allowed models for a key, considering
// the project's model restrictions. If the project has model restrictions,
// the key's models are intersected with the project's models.
func ResolveModels(key *VirtualKey, project *Project) []string {
	if project == nil || len(project.Models) == 0 {
		if key != nil {
			return key.AllowedModels
		}
		return nil
	}

	if key == nil || len(key.AllowedModels) == 0 {
		return project.Models
	}

	// Intersection: models allowed by both key and project.
	projectSet := make(map[string]bool, len(project.Models))
	for _, m := range project.Models {
		projectSet[m] = true
	}

	var intersection []string
	for _, m := range key.AllowedModels {
		if projectSet[m] {
			intersection = append(intersection, m)
		}
	}
	return intersection
}
