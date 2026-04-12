package k8s

import (
	"context"
	"testing"
)

func BenchmarkReconcileHTTPRoute(b *testing.B) {
	b.ReportAllocs()

	store := newMemoryStore()
	r := NewReconciler(store, testController)

	// Set up a GatewayClass and Gateway as prerequisites
	ctx := context.Background()

	gc := GatewayClass{
		Name:           "test-class",
		ControllerName: testController,
	}
	if err := r.ReconcileGatewayClass(ctx, gc); err != nil {
		b.Fatalf("failed to reconcile GatewayClass: %v", err)
	}

	gw := Gateway{
		Name:      "test-gateway",
		Namespace: "default",
		Class:     "test-class",
		Listeners: []GatewayListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}
	if err := r.ReconcileGateway(ctx, gw); err != nil {
		b.Fatalf("failed to reconcile Gateway: %v", err)
	}

	route := HTTPRoute{
		Name:      "test-route",
		Namespace: "default",
		Hostnames: []string{"api.example.com", "www.example.com"},
		ParentRef: "default/test-gateway",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{Path: &PathMatch{Type: "PathPrefix", Value: "/api/v1"}},
				},
				BackendRefs: []BackendRef{
					{Name: "svc-api", Namespace: "default", Port: 8080, Weight: 1},
				},
				Timeouts: &RouteTimeouts{Request: "30s", BackendRequest: "10s"},
			},
			{
				Matches: []HTTPRouteMatch{
					{Path: &PathMatch{Type: "PathPrefix", Value: "/api/v2"}},
				},
				BackendRefs: []BackendRef{
					{Name: "svc-api-v2", Namespace: "default", Port: 8080, Weight: 3},
					{Name: "svc-api-v2-canary", Namespace: "default", Port: 8080, Weight: 1},
				},
			},
			{
				Matches: []HTTPRouteMatch{
					{Path: &PathMatch{Type: "Exact", Value: "/healthz"}},
				},
				BackendRefs: []BackendRef{
					{Name: "svc-health", Namespace: "default", Port: 8081},
				},
				Filters: []HTTPRouteFilter{
					{
						Type: "RequestHeaderModifier",
						RequestHeaderModifier: &HeaderModifier{
							Set: map[string]string{"X-Health-Check": "true"},
						},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := r.ReconcileHTTPRoute(ctx, route); err != nil {
			b.Fatalf("ReconcileHTTPRoute failed: %v", err)
		}
	}
}
