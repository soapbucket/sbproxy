package cache

import (
	"testing"
)

func TestNewVectorStore(t *testing.T) {
	tests := []struct {
		name      string
		config    VectorStoreConfig
		wantType  string
		wantErr   bool
	}{
		{
			name:     "memory store",
			config:   VectorStoreConfig{Type: "memory", MaxSize: 100},
			wantType: "*cache.MemoryVectorStore",
		},
		{
			name:     "memory store default size",
			config:   VectorStoreConfig{Type: "memory"},
			wantType: "*cache.MemoryVectorStore",
		},
		{
			name: "pinecone store",
			config: VectorStoreConfig{
				Type:      "pinecone",
				URL:       "https://my-index.pinecone.io",
				APIKey:    "key",
				Namespace: "ns",
			},
			wantType: "*cache.PineconeVectorStore",
		},
		{
			name: "qdrant store",
			config: VectorStoreConfig{
				Type:       "qdrant",
				URL:        "http://localhost:6333",
				Collection: "my-collection",
			},
			wantType: "*cache.QdrantVectorStore",
		},
		{
			name: "weaviate store",
			config: VectorStoreConfig{
				Type:       "weaviate",
				URL:        "http://localhost:8080",
				Collection: "Document",
			},
			wantType: "*cache.WeaviateVectorStore",
		},
		{
			name: "weaviate store default class",
			config: VectorStoreConfig{
				Type: "weaviate",
				URL:  "http://localhost:8080",
			},
			wantType: "*cache.WeaviateVectorStore",
		},
		{
			name: "pgvector store",
			config: VectorStoreConfig{
				Type:             "pgvector",
				ConnectionString: "postgres://localhost:5432/db",
				Collection:       "vectors",
			},
			wantType: "*cache.PgvectorStore",
		},
		{
			name: "chroma store",
			config: VectorStoreConfig{
				Type:       "chroma",
				URL:        "http://localhost:8000",
				Collection: "my-collection",
			},
			wantType: "*cache.ChromaVectorStore",
		},
		{
			name:    "unknown type",
			config:  VectorStoreConfig{Type: "unknown"},
			wantErr: true,
		},
		{
			name:    "empty type",
			config:  VectorStoreConfig{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewVectorStore(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewVectorStore() error = %v", err)
			}
			if store == nil {
				t.Fatal("expected non-nil store")
			}

			// Verify the store implements VectorStore interface.
			var _ VectorStore = store
		})
	}
}

func TestNewVectorStore_MemoryStoreIsUsable(t *testing.T) {
	store, err := NewVectorStore(VectorStoreConfig{
		Type:    "memory",
		MaxSize: 50,
	})
	if err != nil {
		t.Fatalf("NewVectorStore() error = %v", err)
	}

	// The memory store should be immediately usable.
	health := store.Health(nil)
	if !health.Healthy {
		t.Errorf("expected healthy memory store, got error: %s", health.Error)
	}
	if health.StoreType != "memory" {
		t.Errorf("StoreType = %q, want %q", health.StoreType, "memory")
	}
}
