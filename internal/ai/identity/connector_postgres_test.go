package identity

import (
	"context"
	"errors"
	"testing"
)

func TestPostgresConnector_ReturnsNotImplemented(t *testing.T) {
	c := NewPostgresConnector("postgres://localhost/test", "SELECT * FROM perms WHERE cred = $1")
	_, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err == nil {
		t.Fatal("expected error from stub")
	}
	if !errors.Is(err, ErrConnectorNotImplemented) {
		t.Errorf("expected ErrConnectorNotImplemented, got: %v", err)
	}
}
