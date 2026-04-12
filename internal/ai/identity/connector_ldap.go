// connector_ldap.go is a stub LDAP permission connector.
package identity

import (
	"context"
	"fmt"
)

// LDAPConnector resolves permissions from an LDAP directory.
// This is a stub implementation.
type LDAPConnector struct {
	server string
}

// NewLDAPConnector creates an LDAP-based permission connector stub.
func NewLDAPConnector(server string) *LDAPConnector {
	return &LDAPConnector{
		server: server,
	}
}

// Resolve returns ErrConnectorNotImplemented.
// A production implementation would bind to the LDAP server,
// search for the credential, and map LDAP groups to permissions.
func (l *LDAPConnector) Resolve(_ context.Context, _, _ string) (*CachedPermission, error) {
	return nil, fmt.Errorf("identity: LDAP connector: %w", ErrConnectorNotImplemented)
}
