// reconciler.go defines the Reconciler interface for converting Gateway API resources to proxy configs.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Reconciler watches Gateway API resources and converts them to SoapBucket configs.
type Reconciler interface {
	ReconcileGatewayClass(ctx context.Context, gc GatewayClass) error
	ReconcileGateway(ctx context.Context, gw Gateway) error
	ReconcileHTTPRoute(ctx context.Context, route HTTPRoute) error
	ReconcileGRPCRoute(ctx context.Context, route GRPCRoute) error
}

// ConfigStore is the interface for storing generated configs.
type ConfigStore interface {
	Put(ctx context.Context, key string, value []byte) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// OriginConfig represents a simplified SoapBucket origin config generated from Gateway API resources.
type OriginConfig struct {
	ID        string           `json:"id"`
	Hosts     []string         `json:"hosts"`
	Paths     []string         `json:"paths,omitempty"`
	Action    map[string]any   `json:"action"`
	Auth      map[string]any   `json:"auth,omitempty"`
	Policies  []map[string]any `json:"policies,omitempty"`
	Modifiers map[string]any   `json:"modifiers,omitempty"`
}

// DefaultReconciler implements Reconciler by converting Gateway API resources to SoapBucket configs.
type DefaultReconciler struct {
	store          ConfigStore
	controllerName string
	mu             sync.RWMutex
	gateways       map[string]*Gateway
	gatewayClasses map[string]*GatewayClass
}

// NewReconciler creates a new DefaultReconciler for the given controller name.
func NewReconciler(store ConfigStore, controllerName string) *DefaultReconciler {
	return &DefaultReconciler{
		store:          store,
		controllerName: controllerName,
		gateways:       make(map[string]*Gateway),
		gatewayClasses: make(map[string]*GatewayClass),
	}
}

// ReconcileGatewayClass validates and stores a GatewayClass if it matches this controller.
func (r *DefaultReconciler) ReconcileGatewayClass(ctx context.Context, gc GatewayClass) error {
	if gc.ControllerName != r.controllerName {
		slog.DebugContext(ctx, "ignoring GatewayClass with non-matching controller",
			"class", gc.Name,
			"controller", gc.ControllerName,
			"expected", r.controllerName,
		)
		return nil
	}

	gc.Status = GatewayClassStatus{
		Accepted:    true,
		Programmed:  true,
		Message:     "Accepted by " + r.controllerName,
		LastUpdated: time.Now(),
	}

	r.mu.Lock()
	r.gatewayClasses[gc.Name] = &gc
	r.mu.Unlock()

	slog.InfoContext(ctx, "reconciled GatewayClass", "name", gc.Name)
	return nil
}

// ReconcileGateway validates and stores a Gateway if its class is accepted.
func (r *DefaultReconciler) ReconcileGateway(ctx context.Context, gw Gateway) error {
	r.mu.RLock()
	gc, ok := r.gatewayClasses[gw.Class]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown GatewayClass %q for Gateway %q", gw.Class, gw.Name)
	}
	if !gc.Status.Accepted {
		return fmt.Errorf("GatewayClass %q is not accepted", gw.Class)
	}

	if len(gw.Listeners) == 0 {
		return fmt.Errorf("Gateway %q must have at least one listener", gw.Name)
	}

	gw.Status = GatewayStatus{
		Conditions: []Condition{
			{
				Type:               "Accepted",
				Status:             "True",
				Reason:             "Accepted",
				Message:            "Gateway accepted",
				LastTransitionTime: time.Now(),
			},
			{
				Type:               "Programmed",
				Status:             "True",
				Reason:             "Programmed",
				Message:            "Gateway programmed",
				LastTransitionTime: time.Now(),
			},
		},
	}

	r.mu.Lock()
	key := gatewayKey(gw.Namespace, gw.Name)
	r.gateways[key] = &gw
	r.mu.Unlock()

	slog.InfoContext(ctx, "reconciled Gateway", "name", gw.Name, "namespace", gw.Namespace)
	return nil
}

// ReconcileHTTPRoute converts an HTTPRoute into one or more SoapBucket origin configs
// and stores them via the ConfigStore.
func (r *DefaultReconciler) ReconcileHTTPRoute(ctx context.Context, route HTTPRoute) error {
	r.mu.RLock()
	_, gwExists := r.gateways[route.ParentRef]
	r.mu.RUnlock()

	if !gwExists {
		return fmt.Errorf("parent Gateway %q not found for HTTPRoute %q", route.ParentRef, route.Name)
	}

	for i, rule := range route.Rules {
		origin := r.httpRuleToOrigin(route, rule, i)

		data, err := json.Marshal(origin)
		if err != nil {
			return fmt.Errorf("marshaling origin config for rule %d of HTTPRoute %q: %w", i, route.Name, err)
		}

		key := fmt.Sprintf("httproute/%s/%s/rule/%d", route.Namespace, route.Name, i)
		if err := r.store.Put(ctx, key, data); err != nil {
			return fmt.Errorf("storing origin config for rule %d of HTTPRoute %q: %w", i, route.Name, err)
		}
	}

	slog.InfoContext(ctx, "reconciled HTTPRoute", "name", route.Name, "rules", len(route.Rules))
	return nil
}

// ReconcileGRPCRoute converts a GRPCRoute into SoapBucket origin configs.
func (r *DefaultReconciler) ReconcileGRPCRoute(ctx context.Context, route GRPCRoute) error {
	r.mu.RLock()
	_, gwExists := r.gateways[route.ParentRef]
	r.mu.RUnlock()

	if !gwExists {
		return fmt.Errorf("parent Gateway %q not found for GRPCRoute %q", route.ParentRef, route.Name)
	}

	for i, rule := range route.Rules {
		origin := r.grpcRuleToOrigin(route, rule, i)

		data, err := json.Marshal(origin)
		if err != nil {
			return fmt.Errorf("marshaling origin config for rule %d of GRPCRoute %q: %w", i, route.Name, err)
		}

		key := fmt.Sprintf("grpcroute/%s/%s/rule/%d", route.Namespace, route.Name, i)
		if err := r.store.Put(ctx, key, data); err != nil {
			return fmt.Errorf("storing origin config for rule %d of GRPCRoute %q: %w", i, route.Name, err)
		}
	}

	slog.InfoContext(ctx, "reconciled GRPCRoute", "name", route.Name, "rules", len(route.Rules))
	return nil
}

// httpRuleToOrigin converts a single HTTPRouteRule into a SoapBucket OriginConfig.
func (r *DefaultReconciler) httpRuleToOrigin(route HTTPRoute, rule HTTPRouteRule, ruleIndex int) OriginConfig {
	origin := OriginConfig{
		ID:    fmt.Sprintf("%s-%s-rule-%d", route.Namespace, route.Name, ruleIndex),
		Hosts: route.Hostnames,
	}

	// Extract paths from matches.
	for _, m := range rule.Matches {
		if m.Path != nil {
			origin.Paths = append(origin.Paths, m.Path.Value)
		}
	}

	// Build action from backend refs.
	origin.Action = buildAction(rule.BackendRefs)

	// Apply timeouts if present.
	if rule.Timeouts != nil {
		if rule.Timeouts.Request != "" {
			origin.Action["timeout"] = rule.Timeouts.Request
		}
		if rule.Timeouts.BackendRequest != "" {
			origin.Action["backend_timeout"] = rule.Timeouts.BackendRequest
		}
	}

	// Convert filters to modifiers.
	origin.Modifiers = buildModifiers(rule.Filters)

	return origin
}

// grpcRuleToOrigin converts a single GRPCRouteRule into a SoapBucket OriginConfig.
func (r *DefaultReconciler) grpcRuleToOrigin(route GRPCRoute, rule GRPCRouteRule, ruleIndex int) OriginConfig {
	origin := OriginConfig{
		ID:    fmt.Sprintf("%s-%s-grpc-rule-%d", route.Namespace, route.Name, ruleIndex),
		Hosts: route.Hostnames,
	}

	// Extract gRPC service paths from matches.
	for _, m := range rule.Matches {
		if m.Method != nil {
			path := "/" + m.Method.Service
			if m.Method.Method != "" {
				path += "/" + m.Method.Method
			}
			origin.Paths = append(origin.Paths, path)
		}
	}

	action := buildAction(rule.BackendRefs)
	action["type"] = "grpc"
	origin.Action = action

	return origin
}

// buildAction creates the action map from a list of BackendRefs.
// A single backend produces a "proxy" action. Multiple backends produce a "loadbalancer" action
// with weighted targets.
func buildAction(refs []BackendRef) map[string]any {
	if len(refs) == 0 {
		return map[string]any{"type": "proxy"}
	}

	if len(refs) == 1 {
		return map[string]any{
			"type": "proxy",
			"url":  backendURL(refs[0]),
		}
	}

	// Multiple backends: weighted load balancing.
	targets := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		weight := ref.Weight
		if weight <= 0 {
			weight = 1
		}
		targets = append(targets, map[string]any{
			"url":    backendURL(ref),
			"weight": weight,
		})
	}

	return map[string]any{
		"type":    "loadbalancer",
		"targets": targets,
	}
}

// buildModifiers converts HTTPRoute filters into a SoapBucket modifiers map.
func buildModifiers(filters []HTTPRouteFilter) map[string]any {
	if len(filters) == 0 {
		return nil
	}

	modifiers := make(map[string]any)

	for _, f := range filters {
		switch f.Type {
		case "RequestHeaderModifier":
			if f.RequestHeaderModifier != nil {
				mod := make(map[string]any)
				if len(f.RequestHeaderModifier.Set) > 0 {
					mod["set"] = f.RequestHeaderModifier.Set
				}
				if len(f.RequestHeaderModifier.Add) > 0 {
					mod["add"] = f.RequestHeaderModifier.Add
				}
				if len(f.RequestHeaderModifier.Remove) > 0 {
					mod["remove"] = f.RequestHeaderModifier.Remove
				}
				modifiers["request_headers"] = mod
			}

		case "ResponseHeaderModifier":
			if f.ResponseHeaderModifier != nil {
				mod := make(map[string]any)
				if len(f.ResponseHeaderModifier.Set) > 0 {
					mod["set"] = f.ResponseHeaderModifier.Set
				}
				if len(f.ResponseHeaderModifier.Add) > 0 {
					mod["add"] = f.ResponseHeaderModifier.Add
				}
				if len(f.ResponseHeaderModifier.Remove) > 0 {
					mod["remove"] = f.ResponseHeaderModifier.Remove
				}
				modifiers["response_headers"] = mod
			}

		case "URLRewrite":
			if f.URLRewrite != nil {
				rewrite := make(map[string]any)
				if f.URLRewrite.Hostname != "" {
					rewrite["hostname"] = f.URLRewrite.Hostname
				}
				if f.URLRewrite.Path != nil {
					rewrite["path"] = f.URLRewrite.Path.Value
					rewrite["path_type"] = f.URLRewrite.Path.Type
				}
				modifiers["url_rewrite"] = rewrite
			}

		case "RequestRedirect":
			if f.RequestRedirect != nil {
				redirect := make(map[string]any)
				if f.RequestRedirect.Scheme != "" {
					redirect["scheme"] = f.RequestRedirect.Scheme
				}
				if f.RequestRedirect.Hostname != "" {
					redirect["hostname"] = f.RequestRedirect.Hostname
				}
				if f.RequestRedirect.Port > 0 {
					redirect["port"] = f.RequestRedirect.Port
				}
				if f.RequestRedirect.StatusCode > 0 {
					redirect["status_code"] = f.RequestRedirect.StatusCode
				}
				if f.RequestRedirect.Path != nil {
					redirect["path"] = f.RequestRedirect.Path.Value
				}
				modifiers["redirect"] = redirect
			}
		}
	}

	if len(modifiers) == 0 {
		return nil
	}
	return modifiers
}

// backendURL constructs an HTTP URL from a BackendRef.
func backendURL(ref BackendRef) string {
	host := ref.Name
	if ref.Namespace != "" {
		host = ref.Name + "." + ref.Namespace
	}
	return fmt.Sprintf("http://%s:%d", host, ref.Port)
}

// gatewayKey returns a namespaced key for a Gateway.
func gatewayKey(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}
