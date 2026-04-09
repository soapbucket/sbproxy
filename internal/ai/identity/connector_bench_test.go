package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func BenchmarkStaticConnector_Resolve(b *testing.B) {
	perms := make([]StaticPermission, 100)
	for i := range perms {
		perms[i] = StaticPermission{
			Credential:  "key-" + string(rune('A'+i%26)) + string(rune('0'+i/26)),
			Type:        "api_key",
			Principal:   "user-" + string(rune('A'+i%26)),
			Groups:      []string{"group-a"},
			Models:      []string{"gpt-4o"},
			Permissions: []string{"read", "write"},
		}
	}
	// Add a known key for the benchmark lookup.
	perms = append(perms, StaticPermission{
		Credential:  "bench-key",
		Type:        "api_key",
		Principal:   "bench-user",
		Groups:      []string{"bench-group"},
		Models:      []string{"gpt-4o"},
		Permissions: []string{"read"},
	})

	c := NewStaticConnector(perms)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = c.Resolve(ctx, "api_key", "bench-key")
		}
	})
}

func BenchmarkRESTConnector_Resolve(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(restResolveResponse{
			Principal:   "bench-user",
			Groups:      []string{"group-a"},
			Models:      []string{"gpt-4o"},
			Permissions: []string{"read"},
		})
	}))
	defer server.Close()

	c := NewRESTConnector(server.URL, "bench-secret", 5*time.Second)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Resolve(ctx, "api_key", "sk-bench")
	}
}
