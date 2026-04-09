package identity

import (
	"errors"
	"fmt"
	"time"
)

// ConnectorConfig configures a permission connector.
type ConnectorConfig struct {
	Type         string             `json:"type"`                    // "rest", "postgres", "static", "webhook", "ldap"
	URL          string             `json:"url,omitempty"`           // REST connector endpoint
	SharedSecret string             `json:"shared_secret,omitempty"` // REST connector HMAC secret
	Timeout      time.Duration      `json:"timeout,omitempty"`       // HTTP timeout for REST/webhook
	DSN          string             `json:"dsn,omitempty"`           // Postgres connection string
	Query        string             `json:"query,omitempty"`         // Postgres query template
	Permissions  []StaticPermission `json:"permissions,omitempty"`   // Static connector permissions
	WebhookURL   string             `json:"webhook_url,omitempty"`   // Webhook connector endpoint
	RetryCount   int                `json:"retry_count,omitempty"`   // Webhook retry count
	LDAPServer   string             `json:"ldap_server,omitempty"`   // LDAP server address
}

// StaticPermission defines a static permission entry.
type StaticPermission struct {
	Credential  string   `json:"credential"`
	Type        string   `json:"type"`                  // "api_key", "jwt", etc.
	Principal   string   `json:"principal"`
	Groups      []string `json:"groups,omitempty"`
	Models      []string `json:"models,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// ErrConnectorNotImplemented is returned by stub connectors.
var ErrConnectorNotImplemented = errors.New("connector type not implemented")

// NewConnector creates a PermissionConnector from the given config.
func NewConnector(config ConnectorConfig) (PermissionConnector, error) {
	switch config.Type {
	case "rest":
		if config.URL == "" {
			return nil, fmt.Errorf("identity: REST connector requires url")
		}
		timeout := config.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		return NewRESTConnector(config.URL, config.SharedSecret, timeout), nil

	case "static":
		return NewStaticConnector(config.Permissions), nil

	case "webhook":
		if config.WebhookURL == "" {
			return nil, fmt.Errorf("identity: webhook connector requires webhook_url")
		}
		timeout := config.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		retryCount := config.RetryCount
		if retryCount == 0 {
			retryCount = 3
		}
		return NewWebhookConnector(config.WebhookURL, timeout, retryCount), nil

	case "postgres":
		if config.DSN == "" {
			return nil, fmt.Errorf("identity: postgres connector requires dsn")
		}
		return NewPostgresConnector(config.DSN, config.Query), nil

	case "ldap":
		if config.LDAPServer == "" {
			return nil, fmt.Errorf("identity: LDAP connector requires ldap_server")
		}
		return NewLDAPConnector(config.LDAPServer), nil

	default:
		return nil, fmt.Errorf("identity: unknown connector type %q", config.Type)
	}
}
