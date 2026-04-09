// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// NamespaceConfig configures cache namespace partitioning.
type NamespaceConfig struct {
	// Mode determines how cache keys are partitioned.
	// Options: "global", "per_workspace", "per_user", "per_key", "custom"
	Mode string `json:"mode,omitempty"`
	// CustomHeader specifies a header to use for custom namespace partitioning.
	// Only used when Mode is "custom".
	CustomHeader string `json:"custom_header,omitempty"`
	// Template allows template-based namespace construction.
	// Example: "{{workspace}}/{{user}}" creates workspace+user scoped namespaces.
	Template string `json:"template,omitempty"`
}

// NamespaceResolver resolves cache namespace from request context.
type NamespaceResolver struct {
	config *NamespaceConfig
}

// NewNamespaceResolver creates a new namespace resolver with the given configuration.
// If cfg is nil, the resolver defaults to global mode (no namespace prefix).
func NewNamespaceResolver(cfg *NamespaceConfig) *NamespaceResolver {
	if cfg == nil {
		cfg = &NamespaceConfig{Mode: "global"}
	}
	return &NamespaceResolver{config: cfg}
}

// Resolve determines the cache namespace based on the configured mode and request context.
// For "global" mode, returns an empty string (no namespace prefix).
// For "per_workspace", extracts workspace from request context or X-SB-Workspace header.
// For "per_user", extracts user identity from X-SB-User header, Authorization header hash, or API key prefix.
// For "per_key", returns a SHA-256 hash of the full Authorization header value.
// For "custom", returns the value of the configured custom header.
func (nr *NamespaceResolver) Resolve(ctx context.Context, r *http.Request) string {
	switch nr.config.Mode {
	case "global", "":
		return ""

	case "per_workspace":
		return nr.resolveWorkspace(ctx, r)

	case "per_user":
		return nr.resolveUser(ctx, r)

	case "per_key":
		return nr.resolveKey(r)

	case "custom":
		return nr.resolveCustom(r)

	default:
		return ""
	}
}

// NamespacedKey prepends the namespace to a cache key using a pipe separator.
// If namespace is empty, the key is returned unchanged.
func NamespacedKey(namespace, key string) string {
	if namespace == "" {
		return key
	}
	return namespace + "|" + key
}

func (nr *NamespaceResolver) resolveWorkspace(ctx context.Context, r *http.Request) string {
	// Try request context first (most reliable source).
	if ctx != nil {
		rd := reqctx.GetRequestData(ctx)
		if rd != nil && rd.Config != nil {
			if wid := reqctx.ConfigParams(rd.Config).GetWorkspaceID(); wid != "" {
				return "ws:" + wid
			}
		}
	}

	// Fall back to header.
	if r != nil {
		if wid := r.Header.Get("X-SB-Workspace"); wid != "" {
			return "ws:" + wid
		}
	}

	return ""
}

func (nr *NamespaceResolver) resolveUser(ctx context.Context, r *http.Request) string {
	if r == nil {
		return ""
	}

	// Prefer explicit user header.
	if uid := r.Header.Get("X-SB-User"); uid != "" {
		return "user:" + uid
	}

	// Try context debug headers.
	if ctx != nil {
		rd := reqctx.GetRequestData(ctx)
		if rd != nil && rd.DebugHeaders != nil {
			if uid := rd.DebugHeaders["X-Sb-User-Id"]; uid != "" {
				return "user:" + uid
			}
		}
	}

	// Fall back to hashed Authorization header prefix (first 16 hex chars).
	if auth := r.Header.Get("Authorization"); auth != "" {
		h := sha256.Sum256([]byte(auth))
		return "user:" + fmt.Sprintf("%x", h[:8])
	}

	return ""
}

func (nr *NamespaceResolver) resolveKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	h := sha256.Sum256([]byte(auth))
	return "key:" + fmt.Sprintf("%x", h)
}

func (nr *NamespaceResolver) resolveCustom(r *http.Request) string {
	if r == nil || nr.config.CustomHeader == "" {
		return ""
	}
	val := r.Header.Get(nr.config.CustomHeader)
	if val == "" {
		return ""
	}
	// Sanitize: replace pipes and slashes to avoid key collisions.
	val = strings.ReplaceAll(val, "|", "_")
	return "custom:" + val
}
