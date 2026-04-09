package rag

// QueryOption configures a RAG query.
type QueryOption func(*QueryOptions)

// QueryOptions holds all configurable options for a RAG query.
type QueryOptions struct {
	TopK        int               // Number of chunks to retrieve (default: provider-specific)
	Threshold   float64           // Minimum similarity threshold (0.0-1.0)
	Model       string            // Override the generation model
	MaxTokens   int               // Max tokens for the generated answer
	Temperature float64           // Generation temperature (0.0-1.0)
	Filter      map[string]string // Metadata filters for retrieval
	Namespace   string            // Isolation namespace (workspace, tenant, etc.)
	Stream      bool              // Enable streaming response
}

// DefaultQueryOptions returns sensible defaults.
func DefaultQueryOptions() *QueryOptions {
	return &QueryOptions{
		TopK:        5,
		Threshold:   0.7,
		Temperature: 0.1,
	}
}

// ApplyOptions merges functional options into QueryOptions.
func ApplyOptions(opts []QueryOption) *QueryOptions {
	o := DefaultQueryOptions()
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// WithTopK sets the number of chunks to retrieve.
func WithTopK(k int) QueryOption {
	return func(o *QueryOptions) { o.TopK = k }
}

// WithThreshold sets the minimum similarity threshold.
func WithThreshold(t float64) QueryOption {
	return func(o *QueryOptions) { o.Threshold = t }
}

// WithModel overrides the generation model.
func WithModel(model string) QueryOption {
	return func(o *QueryOptions) { o.Model = model }
}

// WithMaxTokens sets the max tokens for the generated answer.
func WithMaxTokens(n int) QueryOption {
	return func(o *QueryOptions) { o.MaxTokens = n }
}

// WithTemperature sets the generation temperature.
func WithTemperature(t float64) QueryOption {
	return func(o *QueryOptions) { o.Temperature = t }
}

// WithFilter adds metadata filters for retrieval.
func WithFilter(filter map[string]string) QueryOption {
	return func(o *QueryOptions) { o.Filter = filter }
}

// WithNamespace sets the isolation namespace.
func WithNamespace(ns string) QueryOption {
	return func(o *QueryOptions) { o.Namespace = ns }
}

// WithStream enables streaming response.
func WithStream(s bool) QueryOption {
	return func(o *QueryOptions) { o.Stream = s }
}
