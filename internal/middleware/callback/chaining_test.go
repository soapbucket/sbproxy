package callback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVariableChaining verifies that subsequent callbacks in a sequential chain
// can reference results from prior callbacks in their body templates.
func TestVariableChaining(t *testing.T) {
	// Callback 1: returns {"key1": "value1"}
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"key1": "value1",
		})
	}))
	defer server1.Close()

	// Callback 2: echoes the body it receives so we can verify key1 was in the template context
	var receivedBody map[string]any
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"key2": "value2",
		})
	}))
	defer server2.Close()

	// Build two callbacks: cb1 returns key1, cb2's body template references {{key1}}
	callbacksJSON := `[
		{
			"url": "` + server1.URL + `",
			"method": "GET",
			"timeout": 5
		},
		{
			"url": "` + server2.URL + `",
			"method": "POST",
			"timeout": 5,
			"body": "{\"from_cb1\": \"{{key1}}\"}"
		}
	]`

	var cbs Callbacks
	err := json.Unmarshal([]byte(callbacksJSON), &cbs)
	require.NoError(t, err)

	ctx := context.Background()
	result, err := cbs.DoSequentialWithType(ctx, map[string]any{"initial": "data"}, "test")
	require.NoError(t, err)

	// Verify callback 2 received key1 from callback 1's result
	require.NotNil(t, receivedBody, "callback 2 should have received a body")
	assert.Equal(t, "value1", receivedBody["from_cb1"],
		"callback 2's body template should resolve {{key1}} to value1 from callback 1")

	// Results are wrapped under auto-generated variable names (test_1, test_2)
	cb1Result, ok := result["test_1"].(map[string]any)
	require.True(t, ok, "test_1 should be in result")
	assert.Equal(t, "value1", cb1Result["key1"])

	cb2Result, ok := result["test_2"].(map[string]any)
	require.True(t, ok, "test_2 should be in result")
	assert.Equal(t, "value2", cb2Result["key2"])
}

// TestVariableChainingDoesNotMutateOriginalObj verifies that the original obj
// passed to DoSequentialWithType is not mutated by the chaining logic.
func TestVariableChainingDoesNotMutateOriginalObj(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"added": "by_callback"})
	}))
	defer server.Close()

	callbacksJSON := `[{"url": "` + server.URL + `", "method": "GET", "timeout": 5}]`

	var cbs Callbacks
	err := json.Unmarshal([]byte(callbacksJSON), &cbs)
	require.NoError(t, err)

	original := map[string]any{"keep": "original"}
	ctx := context.Background()
	_, err = cbs.DoSequentialWithType(ctx, original, "test")
	require.NoError(t, err)

	// Original should not have been mutated
	assert.Equal(t, map[string]any{"keep": "original"}, original)
}
