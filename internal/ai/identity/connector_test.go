package identity

import (
	"testing"
)

func TestNewConnector_REST(t *testing.T) {
	c, err := NewConnector(ConnectorConfig{
		Type:         "rest",
		URL:          "https://auth.example.com",
		SharedSecret: "secret123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*RESTConnector); !ok {
		t.Fatalf("expected *RESTConnector, got %T", c)
	}
}

func TestNewConnector_REST_MissingURL(t *testing.T) {
	_, err := NewConnector(ConnectorConfig{
		Type: "rest",
	})
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestNewConnector_Static(t *testing.T) {
	c, err := NewConnector(ConnectorConfig{
		Type: "static",
		Permissions: []StaticPermission{
			{Credential: "key-1", Type: "api_key", Principal: "user-1"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*StaticConnector); !ok {
		t.Fatalf("expected *StaticConnector, got %T", c)
	}
}

func TestNewConnector_Webhook(t *testing.T) {
	c, err := NewConnector(ConnectorConfig{
		Type:       "webhook",
		WebhookURL: "https://hooks.example.com/auth",
		RetryCount: 2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*WebhookConnector); !ok {
		t.Fatalf("expected *WebhookConnector, got %T", c)
	}
}

func TestNewConnector_Webhook_MissingURL(t *testing.T) {
	_, err := NewConnector(ConnectorConfig{
		Type: "webhook",
	})
	if err == nil {
		t.Fatal("expected error for missing webhook URL")
	}
}

func TestNewConnector_Postgres(t *testing.T) {
	c, err := NewConnector(ConnectorConfig{
		Type:  "postgres",
		DSN:   "postgres://localhost/test",
		Query: "SELECT principal FROM permissions WHERE credential = $1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*PostgresConnector); !ok {
		t.Fatalf("expected *PostgresConnector, got %T", c)
	}
}

func TestNewConnector_LDAP(t *testing.T) {
	c, err := NewConnector(ConnectorConfig{
		Type:       "ldap",
		LDAPServer: "ldap://ldap.example.com:389",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*LDAPConnector); !ok {
		t.Fatalf("expected *LDAPConnector, got %T", c)
	}
}

func TestNewConnector_Unknown(t *testing.T) {
	_, err := NewConnector(ConnectorConfig{
		Type: "redis",
	})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}
