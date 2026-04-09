package rag

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/redis/go-redis/v9"
)

const (
	redisProviderName         = "redis"
	redisDefaultURL           = "redis://localhost:6379/0"
	redisDefaultIndex         = "rag_index"
	redisDefaultEmbedProvider = "openai"
	redisDefaultEmbedModel    = "text-embedding-3-small"
	redisDefaultEmbedDims     = 1536
	redisDefaultLLMProvider   = "openai"
	redisDefaultLLMModel      = "gpt-4o-mini"
	redisDefaultLLMBaseURL    = "https://api.openai.com"
	redisDefaultNamespace     = "default"
	redisDefaultChunkSize     = 500
	redisDefaultChunkOverlap  = 50
)

// RedisProvider implements RAG using Redis with RediSearch vector storage,
// an external embedding API, and an external LLM API for answer generation.
type RedisProvider struct {
	rdb       *redis.Client
	indexName string
	embedder  *Embedder
	chunker   *Chunker
	llmClient *HTTPClient
	llmModel  string
	namespace string
	dims      int
	logger    *slog.Logger

	indexOnce sync.Once
	indexErr  error
}

var _ Provider = (*RedisProvider)(nil)

// NewRedisProvider creates a new Redis RAG provider from configuration.
// Required config keys: embedding_api_key, llm_api_key.
// Optional keys: redis_url, index_name, embedding_provider, embedding_model,
// embedding_dimensions, llm_provider, llm_model, llm_base_url, namespace.
func NewRedisProvider(config map[string]string) (Provider, error) {
	embeddingAPIKey := config["embedding_api_key"]
	if embeddingAPIKey == "" {
		return nil, fmt.Errorf("redis: embedding_api_key is required")
	}
	llmAPIKey := config["llm_api_key"]
	if llmAPIKey == "" {
		return nil, fmt.Errorf("redis: llm_api_key is required")
	}

	redisURL := configOrDefault(config, "redis_url", redisDefaultURL)
	indexName := configOrDefault(config, "index_name", redisDefaultIndex)
	embedProvider := configOrDefault(config, "embedding_provider", redisDefaultEmbedProvider)
	embedModel := configOrDefault(config, "embedding_model", redisDefaultEmbedModel)
	llmModel := configOrDefault(config, "llm_model", redisDefaultLLMModel)
	llmBaseURL := configOrDefault(config, "llm_base_url", redisDefaultLLMBaseURL)
	namespace := configOrDefault(config, "namespace", redisDefaultNamespace)

	dims := redisDefaultEmbedDims
	if d, ok := config["embedding_dimensions"]; ok {
		parsed, err := strconv.Atoi(d)
		if err != nil {
			return nil, fmt.Errorf("redis: invalid embedding_dimensions %q: %w", d, err)
		}
		dims = parsed
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis: invalid redis_url %q: %w", redisURL, err)
	}
	rdb := redis.NewClient(opts)

	// Build the embedder.
	var embedder *Embedder
	if embedBaseURL, ok := config["embedding_base_url"]; ok && embedBaseURL != "" {
		embedder = NewEmbedderWithBaseURL(embedBaseURL, embeddingAPIKey, embedModel, dims)
	} else {
		embedder = NewEmbedder(embedProvider, embeddingAPIKey, embedModel, dims)
	}

	// Build the LLM client (OpenAI-compatible chat completions).
	llmClient := NewHTTPClient(llmBaseURL, WithBearerAuth(llmAPIKey))

	return &RedisProvider{
		rdb:       rdb,
		indexName: indexName,
		embedder:  embedder,
		chunker:   NewChunker(redisDefaultChunkSize, redisDefaultChunkOverlap),
		llmClient: llmClient,
		llmModel:  llmModel,
		namespace: namespace,
		dims:      dims,
		logger:    slog.Default(),
	}, nil
}

// Name returns "redis".
func (p *RedisProvider) Name() string { return redisProviderName }

// Ingest chunks documents, embeds them, and stores them as Redis HASH keys
// with vector embeddings for RediSearch.
func (p *RedisProvider) Ingest(ctx context.Context, docs []Document) error {
	if err := p.ensureIndex(ctx); err != nil {
		return fmt.Errorf("redis ingest: ensure index: %w", err)
	}

	for _, doc := range docs {
		chunks := p.chunker.ChunkDoc(doc)
		if len(chunks) == 0 {
			continue
		}

		// Batch embed all chunk contents.
		texts := make([]string, len(chunks))
		for i, c := range chunks {
			texts[i] = c.Content
		}

		embeddings, err := p.embedder.EmbedBatch(ctx, texts)
		if err != nil {
			return fmt.Errorf("redis ingest: embed doc %q: %w", doc.ID, err)
		}

		// Store each chunk as a Redis HASH.
		pipe := p.rdb.Pipeline()
		for i, chunk := range chunks {
			key := fmt.Sprintf("%s:doc:%s:chunk:%d", p.namespace, doc.ID, i)
			vecBytes := float32ToBytes(embeddings[i])

			pipe.HSet(ctx, key,
				"content", chunk.Content,
				"embedding", vecBytes,
				"doc_id", doc.ID,
				"doc_name", doc.Filename,
				"chunk_index", i,
			)
		}

		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("redis ingest: store doc %q: %w", doc.ID, err)
		}
	}

	return nil
}

// Query performs RAG: embed the question, search Redis for relevant chunks,
// then call an LLM to generate an answer with citations.
func (p *RedisProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	start := time.Now()
	qopts := ApplyOptions(opts)

	topK := qopts.TopK
	if topK <= 0 {
		topK = 5
	}

	ns := p.namespace
	if qopts.Namespace != "" {
		ns = qopts.Namespace
	}

	model := p.llmModel
	if qopts.Model != "" {
		model = qopts.Model
	}

	// Step 1: Retrieve relevant chunks.
	citations, chunks, err := p.searchChunks(ctx, question, topK, ns)
	if err != nil {
		return nil, fmt.Errorf("redis query: search: %w", err)
	}

	// Step 2: Call LLM with retrieved context to generate an answer.
	answer, tokensIn, tokensOut, err := p.generateAnswer(ctx, question, chunks, model, qopts)
	if err != nil {
		return nil, fmt.Errorf("redis query: generate: %w", err)
	}

	return &QueryResult{
		Answer:    answer,
		Citations: citations,
		Provider:  redisProviderName,
		Latency:   time.Since(start),
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
	}, nil
}

// Retrieve performs vector search only, returning citations without LLM generation.
func (p *RedisProvider) Retrieve(ctx context.Context, question string, topK int) ([]Citation, error) {
	if topK <= 0 {
		topK = 5
	}

	citations, _, err := p.searchChunks(ctx, question, topK, p.namespace)
	if err != nil {
		return nil, fmt.Errorf("redis retrieve: %w", err)
	}

	return citations, nil
}

// Health checks Redis connectivity and verifies the search index exists.
func (p *RedisProvider) Health(ctx context.Context) error {
	if err := p.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health: ping failed: %w", err)
	}

	// Check that the index exists via FT._LIST.
	cmd := p.rdb.Do(ctx, "FT._LIST")
	if cmd.Err() != nil {
		return fmt.Errorf("redis health: FT._LIST failed: %w", cmd.Err())
	}

	indices, err := cmd.StringSlice()
	if err != nil {
		// FT._LIST may return an interface slice; Redis is up, index check is best-effort.
		return nil
	}

	for _, idx := range indices {
		if idx == p.indexName {
			return nil
		}
	}

	return fmt.Errorf("redis health: index %q not found", p.indexName)
}

// Close closes the Redis client connection.
func (p *RedisProvider) Close() error {
	return p.rdb.Close()
}

// ensureIndex creates the RediSearch vector index if it does not already exist.
func (p *RedisProvider) ensureIndex(ctx context.Context) error {
	p.indexOnce.Do(func() {
		p.indexErr = p.createIndexIfNotExists(ctx)
	})
	return p.indexErr
}

// createIndexIfNotExists checks FT._LIST and creates the index if missing.
func (p *RedisProvider) createIndexIfNotExists(ctx context.Context) error {
	// Check existing indices.
	cmd := p.rdb.Do(ctx, "FT._LIST")
	if cmd.Err() == nil {
		if indices, err := cmd.StringSlice(); err == nil {
			for _, idx := range indices {
				if idx == p.indexName {
					return nil // Index already exists.
				}
			}
		}
	}

	// Create the index.
	prefix := p.namespace + ":doc:"
	dimStr := strconv.Itoa(p.dims)

	createCmd := p.rdb.Do(ctx, "FT.CREATE", p.indexName,
		"ON", "HASH",
		"PREFIX", "1", prefix,
		"SCHEMA",
		"content", "TEXT",
		"embedding", "VECTOR", "HNSW", "6",
		"TYPE", "FLOAT32",
		"DIM", dimStr,
		"DISTANCE_METRIC", "COSINE",
		"doc_id", "TAG",
		"doc_name", "TEXT",
		"chunk_index", "NUMERIC",
	)

	if createCmd.Err() != nil {
		return fmt.Errorf("FT.CREATE: %w", createCmd.Err())
	}

	return nil
}

// searchChunks embeds the question and performs a KNN vector search in Redis.
// Returns citations, raw chunk contents (for LLM context), and any error.
func (p *RedisProvider) searchChunks(ctx context.Context, question string, topK int, _ string) ([]Citation, []string, error) {
	// Embed the question.
	qvec, err := p.embedder.Embed(ctx, question)
	if err != nil {
		return nil, nil, fmt.Errorf("embed question: %w", err)
	}

	vecBytes := float32ToBytes(qvec)

	// Run FT.SEARCH with KNN query.
	knnQuery := fmt.Sprintf("*=>[KNN %d @embedding $vec AS score]", topK)
	cmd := p.rdb.Do(ctx, "FT.SEARCH", p.indexName, knnQuery,
		"PARAMS", "2", "vec", string(vecBytes),
		"SORTBY", "score",
		"DIALECT", "2",
	)

	if cmd.Err() != nil {
		return nil, nil, fmt.Errorf("FT.SEARCH: %w", cmd.Err())
	}

	citations, chunks, err := parseFTSearchResult(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("parse FT.SEARCH result: %w", err)
	}

	return citations, chunks, nil
}

// parseFTSearchResult parses the raw FT.SEARCH response.
// Format: [total_results, key1, [field1, value1, ...], key2, [field2, value2, ...], ...]
func parseFTSearchResult(cmd *redis.Cmd) ([]Citation, []string, error) {
	raw, err := cmd.Slice()
	if err != nil {
		return nil, nil, fmt.Errorf("read result slice: %w", err)
	}

	if len(raw) < 1 {
		return nil, nil, nil
	}

	// First element is the total count.
	total, ok := raw[0].(int64)
	if !ok {
		return nil, nil, fmt.Errorf("expected int64 total, got %T", raw[0])
	}

	if total == 0 {
		return nil, nil, nil
	}

	var citations []Citation
	var chunks []string

	// Iterate over result pairs: key, fields_array.
	i := 1
	for i < len(raw) {
		// Skip the key name.
		i++
		if i >= len(raw) {
			break
		}

		// Parse the fields array.
		fields, ok := raw[i].([]interface{})
		if !ok {
			i++
			continue
		}
		i++

		fieldMap := make(map[string]string, len(fields)/2)
		for j := 0; j+1 < len(fields); j += 2 {
			k, _ := fields[j].(string)
			v, _ := fields[j+1].(string)
			fieldMap[k] = v
		}

		content := fieldMap["content"]
		docID := fieldMap["doc_id"]
		docName := fieldMap["doc_name"]
		scoreStr := fieldMap["score"]

		score := 0.0
		if scoreStr != "" {
			if parsed, parseErr := strconv.ParseFloat(scoreStr, 64); parseErr == nil {
				// RediSearch COSINE distance: lower is better. Convert to similarity.
				score = 1.0 - parsed
			}
		}

		citations = append(citations, Citation{
			DocumentID:   docID,
			DocumentName: docName,
			Snippet:      truncateSnippet(content, 200),
			Score:        score,
		})
		chunks = append(chunks, content)
	}

	return citations, chunks, nil
}

// generateAnswer calls the LLM (OpenAI-compatible chat completions) with retrieved
// context and the user's question to produce an answer.
func (p *RedisProvider) generateAnswer(ctx context.Context, question string, chunks []string, model string, qopts *QueryOptions) (string, int, int, error) {
	if len(chunks) == 0 {
		return "No relevant documents found to answer the question.", 0, 0, nil
	}

	systemPrompt := buildRAGSystemPrompt(chunks)

	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}

	reqBody := chatCompletionRequest{
		Model:    model,
		Messages: messages,
	}

	if qopts.MaxTokens > 0 {
		reqBody.MaxTokens = qopts.MaxTokens
	}
	if qopts.Temperature > 0 {
		reqBody.Temperature = qopts.Temperature
	}

	var resp chatCompletionResponse
	if err := p.llmClient.Do(ctx, "POST", "/v1/chat/completions", reqBody, &resp); err != nil {
		return "", 0, 0, fmt.Errorf("llm chat completions: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", 0, 0, fmt.Errorf("llm: empty choices in response")
	}

	answer := resp.Choices[0].Message.Content
	tokensIn := resp.Usage.PromptTokens
	tokensOut := resp.Usage.CompletionTokens

	return answer, tokensIn, tokensOut, nil
}

// buildRAGSystemPrompt constructs a system prompt with retrieved context chunks.
func buildRAGSystemPrompt(chunks []string) string {
	var sb strings.Builder
	sb.WriteString("You are a helpful assistant that answers questions based on the provided context. ")
	sb.WriteString("Use only the information from the context below. ")
	sb.WriteString("If the context does not contain enough information to answer, say so.\n\n")
	sb.WriteString("Context:\n")
	for i, chunk := range chunks {
		sb.WriteString(fmt.Sprintf("[%d] %s\n\n", i+1, chunk))
	}
	return sb.String()
}

// Chat completion types for OpenAI-compatible API.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// float32ToBytes converts a float32 slice to a little-endian byte slice
// for storage as a Redis vector field.
func float32ToBytes(vec []float32) []byte {
	buf := make([]byte, len(vec)*4)
	for i, v := range vec {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(v))
	}
	return buf
}

// bytesToFloat32 converts a little-endian byte slice back to a float32 slice.
func bytesToFloat32(data []byte) []float32 {
	n := len(data) / 4
	vec := make([]float32, n)
	for i := 0; i < n; i++ {
		bits := binary.LittleEndian.Uint32(data[i*4:])
		vec[i] = math.Float32frombits(bits)
	}
	return vec
}

// truncateSnippet truncates text to approximately maxWords words.
func truncateSnippet(text string, maxWords int) string {
	words := strings.Fields(text)
	if len(words) <= maxWords {
		return text
	}
	return strings.Join(words[:maxWords], " ") + "..."
}

// configOrDefault returns the config value for key, or the default if empty/missing.
func configOrDefault(config map[string]string, key, defaultVal string) string {
	if v, ok := config[key]; ok && v != "" {
		return v
	}
	return defaultVal
}

// MarshalHealthJSON serializes the provider's health status for diagnostics.
func (p *RedisProvider) MarshalHealthJSON(ctx context.Context) ([]byte, error) {
	status := map[string]any{
		"provider":  redisProviderName,
		"index":     p.indexName,
		"namespace": p.namespace,
		"dims":      p.dims,
	}
	if err := p.Health(ctx); err != nil {
		status["healthy"] = false
		status["error"] = err.Error()
	} else {
		status["healthy"] = true
	}
	return json.Marshal(status)
}
