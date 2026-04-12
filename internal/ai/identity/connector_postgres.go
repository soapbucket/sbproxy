// connector_postgres.go is a stub Postgres permission connector.
package identity

import (
	"context"
	"fmt"
)

// PostgresConnector resolves permissions from a Postgres database.
// This is a stub implementation. A production version would use pgx/pgxpool.
type PostgresConnector struct {
	dsn   string
	query string
}

// NewPostgresConnector creates a Postgres-based permission connector stub.
func NewPostgresConnector(dsn, query string) *PostgresConnector {
	return &PostgresConnector{
		dsn:   dsn,
		query: query,
	}
}

// Resolve returns ErrConnectorNotImplemented.
// A production implementation would execute the configured query against Postgres
// using pgx/pgxpool, binding credentialType and credential as parameters.
func (p *PostgresConnector) Resolve(_ context.Context, _, _ string) (*CachedPermission, error) {
	return nil, fmt.Errorf("identity: postgres connector: %w", ErrConnectorNotImplemented)
}
