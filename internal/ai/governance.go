// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func authDataString(rd *reqctx.RequestData, keys ...string) string {
	if rd == nil || rd.SessionData == nil || rd.SessionData.AuthData == nil || rd.SessionData.AuthData.Data == nil {
		return ""
	}
	for _, key := range keys {
		if value, ok := rd.SessionData.AuthData.Data[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// budgetScopeValues derives concrete scope values for all supported budget scopes.
func (h *Handler) budgetScopeValues(ctx context.Context, model string, explicitTags map[string]string) map[string]string {
	scopeValues := make(map[string]string)
	rd := reqctx.GetRequestData(ctx)
	if rd != nil && rd.Config != nil {
		cp := reqctx.ConfigParams(rd.Config)
		if workspaceID := cp.GetWorkspaceID(); workspaceID != "" {
			scopeValues["workspace"] = workspaceID
		}
		if originID := cp.GetConfigID(); originID != "" {
			scopeValues["origin"] = originID
		} else if hostname := cp.GetConfigHostname(); hostname != "" {
			scopeValues["origin"] = hostname
		}
	}
	if apiKeyID := authDataString(rd, "key_id", "key_name"); apiKeyID != "" {
		scopeValues["api_key"] = apiKeyID
	}
	if model != "" {
		scopeValues["model"] = model
	}
	if rd != nil && rd.DebugHeaders != nil {
		if user := rd.DebugHeaders["X-Sb-AI-User"]; user != "" {
			scopeValues["user"] = user
		}
	}
	if _, ok := scopeValues["user"]; !ok {
		if user := authDataString(rd, "user_id", "username", "user_name"); user != "" {
			scopeValues["user"] = user
		}
	}
	tags := explicitTags
	if len(tags) == 0 && rd != nil {
		tags = h.collectTags(rd)
	}
	for key, value := range tags {
		if key == "" || value == "" {
			continue
		}
		scopeValues["tag:"+key] = value
	}
	return scopeValues
}

func stringSliceAny(raw any) []string {
	switch vals := raw.(type) {
	case []string:
		return vals
	case []any:
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func policyString(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	if value, ok := raw[key].(string); ok {
		return value
	}
	return ""
}

func (h *Handler) effectiveProviderPolicy(ctx context.Context) map[string]any {
	merged := cloneAnyMap(h.config.ProviderPolicy)
	if ent := h.aiEntitlements(ctx); ent != nil {
		if raw := ent.objectValue("provider_policy"); len(raw) > 0 {
			if merged == nil {
				merged = make(map[string]any, len(raw))
			}
			for key, value := range raw {
				merged[key] = value
			}
		}
	}
	return merged
}

// PolicyExclusion captures why a provider was excluded by policy.
type PolicyExclusion struct {
	Provider  string `json:"provider"`
	Attribute string `json:"attribute"`
	Reason    string `json:"reason"`
}

func providerAllowedByPolicy(policy map[string]any, cfg *ProviderConfig) bool {
	_, excl := providerPolicyDecision(policy, cfg)
	return excl == nil
}

// providerPolicyDecision evaluates whether a provider is allowed by policy
// and returns a PolicyExclusion if it was excluded.
func providerPolicyDecision(policy map[string]any, cfg *ProviderConfig) (bool, *PolicyExclusion) {
	if len(policy) == 0 || cfg == nil {
		return true, nil
	}
	if allowedTypes := stringSliceAny(policy["allowed_provider_types"]); len(allowedTypes) > 0 {
		matched := false
		for _, value := range allowedTypes {
			if value == cfg.GetType() {
				matched = true
				break
			}
		}
		if !matched {
			return false, &PolicyExclusion{
				Provider:  cfg.Name,
				Attribute: "allowed_provider_types",
				Reason:    "provider type " + cfg.GetType() + " not in allowed list",
			}
		}
	}
	for _, value := range stringSliceAny(policy["blocked_provider_types"]) {
		if value == cfg.GetType() {
			return false, &PolicyExclusion{
				Provider:  cfg.Name,
				Attribute: "blocked_provider_types",
				Reason:    "provider type " + cfg.GetType() + " is blocked",
			}
		}
	}
	if allowedRegions := stringSliceAny(policy["allowed_regions"]); len(allowedRegions) > 0 {
		matched := false
		for _, value := range allowedRegions {
			if strings.EqualFold(value, cfg.Region) {
				matched = true
				break
			}
		}
		if !matched {
			return false, &PolicyExclusion{
				Provider:  cfg.Name,
				Attribute: "allowed_regions",
				Reason:    "provider region " + cfg.Region + " not in allowed list",
			}
		}
	}
	for _, value := range stringSliceAny(policy["blocked_regions"]) {
		if strings.EqualFold(value, cfg.Region) {
			return false, &PolicyExclusion{
				Provider:  cfg.Name,
				Attribute: "blocked_regions",
				Reason:    "provider region " + cfg.Region + " is blocked",
			}
		}
	}
	if residency := policyString(policy, "residency"); residency != "" && !strings.EqualFold(residency, cfg.Region) {
		return false, &PolicyExclusion{
			Provider:  cfg.Name,
			Attribute: "residency",
			Reason:    "provider region " + cfg.Region + " does not match required residency " + residency,
		}
	}
	if region := policyString(policy, "region"); region != "" && !strings.EqualFold(region, cfg.Region) {
		return false, &PolicyExclusion{
			Provider:  cfg.Name,
			Attribute: "region",
			Reason:    "provider region " + cfg.Region + " does not match required region " + region,
		}
	}
	if privacyProfile := policyString(policy, "privacy_profile"); privacyProfile != "" {
		switch privacyProfile {
		case "zero_retention", "zero_data_retention":
			if cfg.GetType() != "openai" && cfg.GetType() != "azure" {
				return false, &PolicyExclusion{
					Provider:  cfg.Name,
					Attribute: "privacy_profile",
					Reason:    "provider type " + cfg.GetType() + " not eligible for " + privacyProfile,
				}
			}
		case "metadata_only":
			if cfg.GetType() == "generic" {
				return false, &PolicyExclusion{
					Provider:  cfg.Name,
					Attribute: "privacy_profile",
					Reason:    "generic providers excluded by metadata_only privacy profile",
				}
			}
		}
	}
	if retentionMode := policyString(policy, "retention_mode"); retentionMode != "" {
		switch retentionMode {
		case "zero_retention":
			if cfg.GetType() != "openai" && cfg.GetType() != "azure" {
				return false, &PolicyExclusion{
					Provider:  cfg.Name,
					Attribute: "retention_mode",
					Reason:    "provider type " + cfg.GetType() + " not eligible for zero_retention",
				}
			}
		case "metadata_only":
			if cfg.GetType() == "generic" {
				return false, &PolicyExclusion{
					Provider:  cfg.Name,
					Attribute: "retention_mode",
					Reason:    "generic providers excluded by metadata_only retention mode",
				}
			}
		}
	}
	if trainingPosture := policyString(policy, "training_posture"); trainingPosture != "" {
		switch trainingPosture {
		case "disallow", "prefer_disallow":
			if cfg.GetType() == "generic" {
				return false, &PolicyExclusion{
					Provider:  cfg.Name,
					Attribute: "training_posture",
					Reason:    "generic providers excluded by training posture " + trainingPosture,
				}
			}
		}
	}
	return true, nil
}
