package identity

import (
	"context"
	"errors"
	"testing"
)

func TestLDAPConnector_ReturnsNotImplemented(t *testing.T) {
	c := NewLDAPConnector("ldap://ldap.example.com:389")
	_, err := c.Resolve(context.Background(), "api_key", "tK7mR9pL2xQ4")
	if err == nil {
		t.Fatal("expected error from stub")
	}
	if !errors.Is(err, ErrConnectorNotImplemented) {
		t.Errorf("expected ErrConnectorNotImplemented, got: %v", err)
	}
}
