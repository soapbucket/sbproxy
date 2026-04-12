// principal.go defines the Principal type representing an authenticated identity.
package identity

import (
	"context"
	"time"
)

// CredentialType identifies the authentication method.
type CredentialType string

const (
	// CredentialAPIKey represents an API key credential.
	CredentialAPIKey CredentialType = "api_key"
	// CredentialJWT represents a JWT token credential.
	CredentialJWT CredentialType = "jwt"
	// CredentialOAuth represents an OAuth bearer token credential.
	CredentialOAuth CredentialType = "oauth"
	// CredentialPersonalKey represents a SoapBucket personal key credential.
	CredentialPersonalKey CredentialType = "personal_key"
)

// Principal represents an authenticated identity.
type Principal struct {
	ID              string            `json:"id"`
	Type            CredentialType    `json:"type"`
	WorkspaceID     string            `json:"workspace_id,omitempty"`
	UserID          string            `json:"user_id,omitempty"`
	Groups          []string          `json:"groups,omitempty"`
	Models          []string          `json:"models,omitempty"`
	Permissions     []string          `json:"permissions,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	AuthenticatedAt time.Time         `json:"authenticated_at"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
}

// HasPermission checks if the principal has a specific permission.
func (p *Principal) HasPermission(perm string) bool {
	if p == nil {
		return false
	}
	for _, pp := range p.Permissions {
		if pp == perm {
			return true
		}
	}
	return false
}

// HasModel checks if the principal can use a specific model.
// An empty Models slice means all models are allowed.
func (p *Principal) HasModel(model string) bool {
	if p == nil {
		return false
	}
	if len(p.Models) == 0 {
		return true
	}
	for _, m := range p.Models {
		if m == model {
			return true
		}
	}
	return false
}

// IsExpired checks if the principal's credentials have expired.
func (p *Principal) IsExpired() bool {
	if p == nil {
		return true
	}
	if p.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*p.ExpiresAt)
}

// principalKey is the context key for storing a Principal.
type principalKey struct{}

// PrincipalFromContext extracts the Principal from context.
func PrincipalFromContext(ctx context.Context) *Principal {
	if val, ok := ctx.Value(principalKey{}).(*Principal); ok {
		return val
	}
	return nil
}

// ContextWithPrincipal stores a Principal in context.
func ContextWithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}
