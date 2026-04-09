package cache

import "fmt"

// VectorStoreConfig holds configuration for creating a VectorStore via the factory.
type VectorStoreConfig struct {
	Type             string `json:"type"`
	URL              string `json:"url"`
	APIKey           string `json:"api_key"`
	Collection       string `json:"collection"`
	Namespace        string `json:"namespace"`
	Dimensions       int    `json:"dimensions"`
	DistanceMetric   string `json:"distance_metric"`
	ConnectionString string `json:"connection_string"`
	MaxSize          int    `json:"max_size"`
}

// NewVectorStore creates a VectorStore adapter based on the config type.
func NewVectorStore(config VectorStoreConfig) (VectorStore, error) {
	switch config.Type {
	case "memory":
		maxSize := config.MaxSize
		if maxSize <= 0 {
			maxSize = 10000
		}
		return NewMemoryVectorStore(maxSize), nil

	case "pinecone":
		return NewPineconeVectorStore(PineconeConfig{
			URL:       config.URL,
			APIKey:    config.APIKey,
			Namespace: config.Namespace,
		}), nil

	case "qdrant":
		return NewQdrantVectorStore(QdrantConfig{
			URL:        config.URL,
			APIKey:     config.APIKey,
			Collection: config.Collection,
		}), nil

	case "weaviate":
		className := config.Collection
		if className == "" {
			className = "VectorEntry"
		}
		return NewWeaviateVectorStore(WeaviateConfig{
			URL:       config.URL,
			APIKey:    config.APIKey,
			ClassName: className,
		}), nil

	case "pgvector":
		return NewPgvectorStore(PgvectorConfig{
			ConnectionString: config.ConnectionString,
			Table:            config.Collection,
		}), nil

	case "chroma":
		return NewChromaVectorStore(ChromaConfig{
			URL:        config.URL,
			Collection: config.Collection,
		}), nil

	default:
		return nil, fmt.Errorf("unknown vector store type: %q", config.Type)
	}
}
