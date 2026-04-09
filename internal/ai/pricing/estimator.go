// Package pricing - cost estimation for AI model usage (reporting only).
package pricing

// CostEstimate holds a detailed cost breakdown for a request.
type CostEstimate struct {
	Model              string  `json:"model"`
	Provider           string  `json:"provider,omitempty"`
	InputTokens        int     `json:"input_tokens"`
	OutputTokens       int     `json:"output_tokens"`
	CachedTokens       int     `json:"cached_tokens,omitempty"`
	CacheCreationTokens int   `json:"cache_creation_tokens,omitempty"`
	ReasoningTokens    int     `json:"reasoning_tokens,omitempty"`
	InputCostUSD       float64 `json:"input_cost_usd"`
	OutputCostUSD      float64 `json:"output_cost_usd"`
	CachedSavings      float64 `json:"cached_savings_usd,omitempty"`
	CacheWriteCostUSD  float64 `json:"cache_write_cost_usd,omitempty"`
	ReasoningCostUSD   float64 `json:"reasoning_cost_usd,omitempty"`
	TotalCostUSD       float64 `json:"total_cost_usd"`
	PricingSource      string  `json:"pricing_source"` // "default", "override", "unknown"
}

// BatchEstimateRequest is a single request in a batch estimate.
type BatchEstimateRequest struct {
	Model               string `json:"model"`
	InputTokens         int    `json:"input_tokens"`
	OutputTokens        int    `json:"output_tokens"`
	CachedTokens        int    `json:"cached_tokens,omitempty"`
	CacheCreationTokens int    `json:"cache_creation_tokens,omitempty"`
	ReasoningTokens     int    `json:"reasoning_tokens,omitempty"`
}

// BatchCostEstimate holds cost estimates for multiple requests.
type BatchCostEstimate struct {
	Estimates      []*CostEstimate    `json:"estimates"`
	TotalCostUSD   float64            `json:"total_cost_usd"`
	ModelBreakdown map[string]float64 `json:"model_breakdown"` // model -> total cost
}

// Estimator calculates costs from token usage for reporting.
// It NEVER enforces limits - budget enforcement is separate.
type Estimator struct {
	source *Source
}

// NewEstimator creates an Estimator backed by the given pricing source.
// A nil source is safe; all estimates will return zero costs with "unknown" source.
func NewEstimator(source *Source) *Estimator {
	return &Estimator{source: source}
}

// Estimate calculates a detailed cost breakdown for the given token counts.
// Returns a zero-cost estimate with PricingSource "unknown" if the model has no pricing data.
func (e *Estimator) Estimate(model string, inputTokens, outputTokens, cachedTokens int) *CostEstimate {
	est := &CostEstimate{
		Model:        model,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		CachedTokens: cachedTokens,
	}

	if e.source == nil {
		est.PricingSource = "unknown"
		return est
	}

	est.PricingSource = e.source.PricingSource(model)

	p := e.source.GetPricing(model)
	if p == nil {
		return est
	}

	est.InputCostUSD = float64(inputTokens) * p.InputPerMToken / 1_000_000
	est.OutputCostUSD = float64(outputTokens) * p.OutputPerMToken / 1_000_000

	if cachedTokens > 0 && p.CachedInputPerMToken > 0 {
		// Cached tokens replace regular input pricing with the lower cached rate.
		fullPrice := float64(cachedTokens) * p.InputPerMToken / 1_000_000
		cachedPrice := float64(cachedTokens) * p.CachedInputPerMToken / 1_000_000
		est.CachedSavings = fullPrice - cachedPrice

		// Adjust input cost: subtract the full-price portion, add cached-price portion.
		est.InputCostUSD -= fullPrice
		est.InputCostUSD += cachedPrice
	}

	est.TotalCostUSD = est.InputCostUSD + est.OutputCostUSD
	return est
}

// EstimateFullParams holds optional extended token counts for full cost estimation.
type EstimateFullParams struct {
	Model               string
	InputTokens         int
	OutputTokens        int
	CachedTokens        int
	CacheCreationTokens int
	ReasoningTokens     int
}

// EstimateFull calculates a detailed cost breakdown including cache-write and reasoning costs.
func (e *Estimator) EstimateFull(params EstimateFullParams) *CostEstimate {
	est := e.Estimate(params.Model, params.InputTokens, params.OutputTokens, params.CachedTokens)
	est.CacheCreationTokens = params.CacheCreationTokens
	est.ReasoningTokens = params.ReasoningTokens

	if e.source == nil {
		return est
	}

	p := e.source.GetPricing(params.Model)
	if p == nil {
		return est
	}

	// Cache write (creation) cost - charged at a premium over input price
	if params.CacheCreationTokens > 0 && p.CacheWritePerMToken > 0 {
		est.CacheWriteCostUSD = float64(params.CacheCreationTokens) * p.CacheWritePerMToken / 1_000_000
		est.TotalCostUSD += est.CacheWriteCostUSD
	}

	// Reasoning tokens - may be priced differently from regular output
	if params.ReasoningTokens > 0 && p.ReasoningPerMToken > 0 {
		est.ReasoningCostUSD = float64(params.ReasoningTokens) * p.ReasoningPerMToken / 1_000_000
		est.TotalCostUSD += est.ReasoningCostUSD
	}

	return est
}

// EstimateEmbedding calculates the cost for embedding tokens.
func (e *Estimator) EstimateEmbedding(model string, tokens int) *CostEstimate {
	est := &CostEstimate{
		Model:       model,
		InputTokens: tokens,
	}

	if e.source == nil {
		est.PricingSource = "unknown"
		return est
	}

	est.PricingSource = e.source.PricingSource(model)

	p := e.source.GetPricing(model)
	if p == nil || p.EmbeddingPerMToken == 0 {
		return est
	}

	est.InputCostUSD = float64(tokens) * p.EmbeddingPerMToken / 1_000_000
	est.TotalCostUSD = est.InputCostUSD
	return est
}

// EstimateBatch calculates cost estimates for multiple requests and returns
// an aggregate with per-model breakdown.
func (e *Estimator) EstimateBatch(requests []BatchEstimateRequest) *BatchCostEstimate {
	batch := &BatchCostEstimate{
		Estimates:      make([]*CostEstimate, 0, len(requests)),
		ModelBreakdown: make(map[string]float64),
	}

	for _, req := range requests {
		est := e.Estimate(req.Model, req.InputTokens, req.OutputTokens, req.CachedTokens)
		batch.Estimates = append(batch.Estimates, est)
		batch.TotalCostUSD += est.TotalCostUSD
		batch.ModelBreakdown[req.Model] += est.TotalCostUSD
	}

	return batch
}

// IsKnownModel returns true if the pricing source has data for the given model.
func (e *Estimator) IsKnownModel(model string) bool {
	if e.source == nil {
		return false
	}
	return e.source.GetPricing(model) != nil
}
