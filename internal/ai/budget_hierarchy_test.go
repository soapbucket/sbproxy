package ai

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHierarchy_Resolve_MostSpecific(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 100000,
			Action:          "block",
			Priority:        50,
		},
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}, {Type: "model", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 50000,
			Action:          "block",
			Priority:        10,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"user":      "user-1",
		"model":     "gpt-4o",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 10, resolved.Priority)
	assert.Equal(t, int64(50000), resolved.TotalTokenLimit)
	assert.Len(t, resolved.Scopes, 2)
}

func TestHierarchy_Resolve_UserProvider(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}, {Type: "provider", Value: "*"}},
			Period:          "hour",
			TotalTokenLimit: 25000,
			Action:          "block",
			Priority:        20,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"user":      "user-1",
		"provider":  "openai",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 20, resolved.Priority)
	assert.Equal(t, int64(25000), resolved.TotalTokenLimit)
}

func TestHierarchy_Resolve_GroupModel(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "group", Value: "*"}, {Type: "model", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 200000,
			Action:          "block",
			Priority:        30,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"group":     "engineering",
		"model":     "gpt-4o",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 30, resolved.Priority)
}

func TestHierarchy_Resolve_GroupProvider(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "group", Value: "*"}, {Type: "provider", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 500000,
			Action:          "log",
			Priority:        40,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"group":     "engineering",
		"provider":  "anthropic",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 40, resolved.Priority)
	assert.Equal(t, "log", resolved.Action)
}

func TestHierarchy_Resolve_UserOnly(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 100000,
			Action:          "block",
			Priority:        50,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"user":      "user-1",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 50, resolved.Priority)
}

func TestHierarchy_Resolve_GroupOnly(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "group", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 300000,
			Action:          "block",
			Priority:        60,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	// No user, only group
	scopes := map[string]string{
		"workspace": "ws-1",
		"group":     "marketing",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 60, resolved.Priority)
}

func TestHierarchy_Resolve_APIKey(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "api_key", Value: "*"}},
			Period:          "hour",
			TotalTokenLimit: 50000,
			Action:          "block",
			Priority:        70,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"api_key":   "key-abc123",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 70, resolved.Priority)
}

func TestHierarchy_Resolve_Workspace(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}, {Type: "model", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 50000,
			Action:          "block",
			Priority:        10,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	// Only workspace provided, user+model limit should not match
	scopes := map[string]string{
		"workspace": "ws-1",
	}

	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, 80, resolved.Priority)
	assert.Equal(t, int64(1000000), resolved.TotalTokenLimit)
}

func TestHierarchy_Resolve_NoMatch(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}, {Type: "model", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 50000,
			Action:          "block",
			Priority:        10,
		},
	})

	// No user or model provided
	scopes := map[string]string{
		"workspace": "ws-1",
	}

	resolved := h.Resolve(scopes)
	assert.Nil(t, resolved)
}

func TestHierarchy_ResolveAll(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}, {Type: "model", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 50000,
			Action:          "block",
			Priority:        10,
		},
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 100000,
			Action:          "block",
			Priority:        50,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	scopes := map[string]string{
		"workspace": "ws-1",
		"user":      "user-1",
		"model":     "gpt-4o",
	}

	all := h.ResolveAll(scopes)
	require.Len(t, all, 3)
	// Should be ordered most specific first
	assert.Equal(t, 10, all[0].Priority)
	assert.Equal(t, 50, all[1].Priority)
	assert.Equal(t, 80, all[2].Priority)
}

func TestHierarchy_MultiGroup(t *testing.T) {
	// When a user has multiple group memberships, the resolver should return
	// both matching limits. The caller picks the most permissive if needed.
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "group", Value: "engineering"}},
			Period:          "day",
			TotalTokenLimit: 200000,
			Action:          "block",
			Priority:        60,
		},
		{
			Scopes:          []BudgetScope{{Type: "group", Value: "data-science"}},
			Period:          "day",
			TotalTokenLimit: 500000,
			Action:          "block",
			Priority:        60,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	// User is in engineering group
	scopes := map[string]string{
		"workspace": "ws-1",
		"group":     "engineering",
	}
	resolved := h.Resolve(scopes)
	require.NotNil(t, resolved)
	assert.Equal(t, int64(200000), resolved.TotalTokenLimit)

	// User is in data-science group (more permissive)
	scopes2 := map[string]string{
		"workspace": "ws-1",
		"group":     "data-science",
	}
	resolved2 := h.Resolve(scopes2)
	require.NotNil(t, resolved2)
	assert.Equal(t, int64(500000), resolved2.TotalTokenLimit)
}

func TestHierarchy_ConcurrentResolve(t *testing.T) {
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}, {Type: "model", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 50000,
			Action:          "block",
			Priority:        10,
		},
		{
			Scopes:          []BudgetScope{{Type: "workspace", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 1000000,
			Action:          "block",
			Priority:        80,
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scopes := map[string]string{
				"workspace": "ws-1",
				"user":      "user-1",
				"model":     "gpt-4o",
			}
			resolved := h.Resolve(scopes)
			assert.NotNil(t, resolved)
			assert.Equal(t, 10, resolved.Priority)
		}()
	}
	wg.Wait()
}

func TestHierarchy_SpecificScopeValue(t *testing.T) {
	// Test that a limit with a specific scope value only matches that value
	h := NewBudgetHierarchy([]HierarchicalLimit{
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "admin-user"}},
			Period:          "day",
			TotalTokenLimit: 500000,
			Action:          "block",
			Priority:        50,
		},
		{
			Scopes:          []BudgetScope{{Type: "user", Value: "*"}},
			Period:          "day",
			TotalTokenLimit: 100000,
			Action:          "block",
			Priority:        51,
		},
	})

	// Admin user gets higher limit
	adminScopes := map[string]string{"user": "admin-user"}
	resolved := h.Resolve(adminScopes)
	require.NotNil(t, resolved)
	assert.Equal(t, int64(500000), resolved.TotalTokenLimit)

	// Regular user gets standard limit
	regularScopes := map[string]string{"user": "regular-user"}
	resolved2 := h.Resolve(regularScopes)
	require.NotNil(t, resolved2)
	assert.Equal(t, int64(100000), resolved2.TotalTokenLimit)
}

func TestHierarchyScopePriority(t *testing.T) {
	assert.Equal(t, 10, hierarchyScopePriority([]string{"user", "model"}))
	assert.Equal(t, 20, hierarchyScopePriority([]string{"user", "provider"}))
	assert.Equal(t, 30, hierarchyScopePriority([]string{"group", "model"}))
	assert.Equal(t, 40, hierarchyScopePriority([]string{"group", "provider"}))
	assert.Equal(t, 50, hierarchyScopePriority([]string{"user"}))
	assert.Equal(t, 60, hierarchyScopePriority([]string{"group"}))
	assert.Equal(t, 70, hierarchyScopePriority([]string{"api_key"}))
	assert.Equal(t, 80, hierarchyScopePriority([]string{"workspace"}))
	assert.Equal(t, 100, hierarchyScopePriority([]string{}))
}
