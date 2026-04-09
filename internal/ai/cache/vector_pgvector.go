package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrNotConnected is returned by the pgvector stub when no database connection is available.
var ErrNotConnected = errors.New("pgvector: not connected (stub implementation)")

// PgvectorConfig holds configuration for the pgvector store adapter.
type PgvectorConfig struct {
	ConnectionString string `json:"connection_string"`
	Table            string `json:"table"`
}

// PgvectorStore implements VectorStore as a stub that generates SQL but does not
// execute queries. A real implementation would use a PostgreSQL driver.
type PgvectorStore struct {
	config PgvectorConfig
}

// NewPgvectorStore creates a new PgvectorStore.
func NewPgvectorStore(config PgvectorConfig) *PgvectorStore {
	if config.Table == "" {
		config.Table = "vector_entries"
	}
	return &PgvectorStore{config: config}
}

// SearchSQL returns the SQL query that would be used to search for similar vectors.
func (s *PgvectorStore) SearchSQL(limit int) string {
	return fmt.Sprintf(
		"SELECT key, namespace, embedding, response, model, created_at, last_access, ttl, "+
			"1 - (embedding <=> $1) AS similarity "+
			"FROM %s "+
			"WHERE 1 - (embedding <=> $1) >= $2 "+
			"ORDER BY embedding <=> $1 "+
			"LIMIT %d",
		s.config.Table, limit,
	)
}

// StoreSQL returns the SQL query for upserting a vector entry.
func (s *PgvectorStore) StoreSQL() string {
	return fmt.Sprintf(
		"INSERT INTO %s (key, namespace, embedding, response, model, created_at, last_access, ttl) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "+
			"ON CONFLICT (key) DO UPDATE SET "+
			"embedding = EXCLUDED.embedding, response = EXCLUDED.response, "+
			"model = EXCLUDED.model, last_access = EXCLUDED.last_access",
		s.config.Table,
	)
}

// DeleteSQL returns the SQL query for deleting a vector entry.
func (s *PgvectorStore) DeleteSQL() string {
	return fmt.Sprintf("DELETE FROM %s WHERE key = $1", s.config.Table)
}

// SizeSQL returns the SQL query for counting vector entries.
func (s *PgvectorStore) SizeSQL() string {
	return fmt.Sprintf("SELECT COUNT(*) FROM %s", s.config.Table)
}

// CreateTableSQL returns the SQL needed to create the vector table with pgvector extension.
func (s *PgvectorStore) CreateTableSQL(dims int) string {
	return fmt.Sprintf(
		"CREATE EXTENSION IF NOT EXISTS vector;\n"+
			"CREATE TABLE IF NOT EXISTS %s (\n"+
			"    key TEXT PRIMARY KEY,\n"+
			"    namespace TEXT DEFAULT '',\n"+
			"    embedding vector(%d),\n"+
			"    response BYTEA,\n"+
			"    model TEXT DEFAULT '',\n"+
			"    created_at TIMESTAMPTZ DEFAULT NOW(),\n"+
			"    last_access TIMESTAMPTZ DEFAULT NOW(),\n"+
			"    ttl INTERVAL DEFAULT '24 hours'\n"+
			");",
		s.config.Table, dims,
	)
}

// EmbeddingLiteral formats an embedding as a pgvector-compatible string literal.
func EmbeddingLiteral(embedding []float32) string {
	parts := make([]string, len(embedding))
	for i, v := range embedding {
		parts[i] = fmt.Sprintf("%g", v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// Search is a stub that returns ErrNotConnected.
func (s *PgvectorStore) Search(_ context.Context, _ []float32, _ float64, _ int) ([]VectorEntry, error) {
	return nil, ErrNotConnected
}

// Store is a stub that returns ErrNotConnected.
func (s *PgvectorStore) Store(_ context.Context, _ VectorEntry) error {
	return ErrNotConnected
}

// Delete is a stub that returns ErrNotConnected.
func (s *PgvectorStore) Delete(_ context.Context, _ string) error {
	return ErrNotConnected
}

// Size is a stub that returns ErrNotConnected.
func (s *PgvectorStore) Size(_ context.Context) (int64, error) {
	return 0, ErrNotConnected
}

// Health returns the health status of the pgvector store (always unhealthy for stub).
func (s *PgvectorStore) Health(_ context.Context) CacheHealth {
	return CacheHealth{
		StoreType: "pgvector",
		Healthy:   false,
		Error:     "stub implementation - no database connection",
	}
}

// Table returns the configured table name.
func (s *PgvectorStore) Table() string {
	return s.config.Table
}

