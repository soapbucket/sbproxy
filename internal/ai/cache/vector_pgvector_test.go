package cache

import (
	"context"
	"strings"
	"testing"
)

func TestPgvectorStore_SearchSQL(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{Table: "embeddings"})
	sql := store.SearchSQL(10)

	if !strings.Contains(sql, "embeddings") {
		t.Error("SearchSQL should reference the configured table")
	}
	if !strings.Contains(sql, "<=>") {
		t.Error("SearchSQL should use the pgvector distance operator <=>")
	}
	if !strings.Contains(sql, "LIMIT 10") {
		t.Error("SearchSQL should include the LIMIT clause")
	}
	if !strings.Contains(sql, "$1") {
		t.Error("SearchSQL should use parameterized query ($1)")
	}
	if !strings.Contains(sql, "$2") {
		t.Error("SearchSQL should use threshold parameter ($2)")
	}
}

func TestPgvectorStore_StoreSQL(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{Table: "my_vectors"})
	sql := store.StoreSQL()

	if !strings.Contains(sql, "my_vectors") {
		t.Error("StoreSQL should reference the configured table")
	}
	if !strings.Contains(sql, "INSERT INTO") {
		t.Error("StoreSQL should be an INSERT statement")
	}
	if !strings.Contains(sql, "ON CONFLICT") {
		t.Error("StoreSQL should handle upsert with ON CONFLICT")
	}
}

func TestPgvectorStore_DeleteSQL(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{Table: "vectors"})
	sql := store.DeleteSQL()

	if !strings.Contains(sql, "DELETE FROM vectors") {
		t.Error("DeleteSQL should be a DELETE statement for the configured table")
	}
	if !strings.Contains(sql, "$1") {
		t.Error("DeleteSQL should use parameterized query")
	}
}

func TestPgvectorStore_SizeSQL(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{Table: "vectors"})
	sql := store.SizeSQL()

	if !strings.Contains(sql, "SELECT COUNT(*)") {
		t.Error("SizeSQL should use COUNT(*)")
	}
	if !strings.Contains(sql, "vectors") {
		t.Error("SizeSQL should reference the configured table")
	}
}

func TestPgvectorStore_CreateTableSQL(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{Table: "embeddings"})
	sql := store.CreateTableSQL(1536)

	if !strings.Contains(sql, "CREATE EXTENSION IF NOT EXISTS vector") {
		t.Error("CreateTableSQL should enable pgvector extension")
	}
	if !strings.Contains(sql, "vector(1536)") {
		t.Error("CreateTableSQL should use the specified dimensions")
	}
	if !strings.Contains(sql, "embeddings") {
		t.Error("CreateTableSQL should reference the configured table")
	}
}

func TestPgvectorStore_DefaultTable(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{})
	if store.Table() != "vector_entries" {
		t.Errorf("default table = %q, want %q", store.Table(), "vector_entries")
	}
}

func TestPgvectorStore_StubOperations(t *testing.T) {
	store := NewPgvectorStore(PgvectorConfig{Table: "test"})
	ctx := context.Background()

	t.Run("Search returns ErrNotConnected", func(t *testing.T) {
		_, err := store.Search(ctx, make([]float32, 4), 0.5, 10)
		if err != ErrNotConnected {
			t.Errorf("Search() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("Store returns ErrNotConnected", func(t *testing.T) {
		err := store.Store(ctx, VectorEntry{Key: "k"})
		if err != ErrNotConnected {
			t.Errorf("Store() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("Delete returns ErrNotConnected", func(t *testing.T) {
		err := store.Delete(ctx, "k")
		if err != ErrNotConnected {
			t.Errorf("Delete() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("Size returns ErrNotConnected", func(t *testing.T) {
		_, err := store.Size(ctx)
		if err != ErrNotConnected {
			t.Errorf("Size() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("Health returns unhealthy", func(t *testing.T) {
		health := store.Health(ctx)
		if health.Healthy {
			t.Error("expected unhealthy for stub")
		}
		if health.StoreType != "pgvector" {
			t.Errorf("StoreType = %q, want %q", health.StoreType, "pgvector")
		}
	})
}

func TestEmbeddingLiteral(t *testing.T) {
	tests := []struct {
		name      string
		embedding []float32
		want      string
	}{
		{
			name:      "simple values",
			embedding: []float32{0.1, 0.2, 0.3},
			want:      "[0.1,0.2,0.3]",
		},
		{
			name:      "empty",
			embedding: []float32{},
			want:      "[]",
		},
		{
			name:      "single value",
			embedding: []float32{1.0},
			want:      "[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EmbeddingLiteral(tt.embedding)
			if got != tt.want {
				t.Errorf("EmbeddingLiteral() = %q, want %q", got, tt.want)
			}
		})
	}
}
