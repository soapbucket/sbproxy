// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// DefaultGraphQLMaxDepth is the default value for graph ql max depth.
	DefaultGraphQLMaxDepth      = 10
	// DefaultGraphQLMaxComplexity is the default value for graph ql max complexity.
	DefaultGraphQLMaxComplexity = 100
	// DefaultGraphQLMaxCost is the default value for graph ql max cost.
	DefaultGraphQLMaxCost       = 1000
	// DefaultGraphQLMaxAliases is the default maximum number of aliased fields per query.
	DefaultGraphQLMaxAliases    = 10
	// DefaultGraphQLTimeout is the default value for graph ql timeout.
	DefaultGraphQLTimeout       = 30 * time.Second
	// DefaultQueryCacheSize is the default value for query cache size.
	DefaultQueryCacheSize       = 1000
)

// GraphQL error codes
var (
	// ErrGraphQLQueryTooDeep is a sentinel error for graph ql query too deep conditions.
	ErrGraphQLQueryTooDeep          = fmt.Errorf("graphql: query exceeds maximum depth")
	// ErrGraphQLQueryTooComplex is a sentinel error for graph ql query too complex conditions.
	ErrGraphQLQueryTooComplex       = fmt.Errorf("graphql: query exceeds maximum complexity")
	// ErrGraphQLQueryTooCostly is a sentinel error for graph ql query too costly conditions.
	ErrGraphQLQueryTooCostly        = fmt.Errorf("graphql: query exceeds maximum cost")
	// ErrGraphQLInvalidQuery is a sentinel error for graph ql invalid query conditions.
	ErrGraphQLInvalidQuery          = fmt.Errorf("graphql: invalid query")
	// ErrGraphQLIntrospectionDisabled is a sentinel error for graph ql introspection disabled conditions.
	ErrGraphQLIntrospectionDisabled = fmt.Errorf("graphql: introspection is disabled")
	// ErrGraphQLTooManyAliases is a sentinel error for graph ql too many aliases conditions.
	ErrGraphQLTooManyAliases        = fmt.Errorf("graphql: query exceeds maximum aliases")
	// ErrGraphQLFieldRateLimited is a sentinel error for graph ql field rate limited conditions.
	ErrGraphQLFieldRateLimited      = fmt.Errorf("graphql: field rate limit exceeded")
)

func init() {
	loaderFns[TypeGraphQL] = NewGraphQLAction
}

// GraphQLAction represents a graph ql action.
type GraphQLAction struct {
	GraphQLConfig

	targetURL            *url.URL
	persistentQueries    map[string]string
	queryCache           *queryCache
	apqCache             *apqCache
	fieldRateLimiter     *fieldRateLimiter
	resultCache          *resultCache
	resultCacheTTL       time.Duration
	cfg                  *Config
	operationRateLimiter *operationRateLimiter
}

type queryCache struct {
	queries map[string]*cachedQuery
	mx      sync.RWMutex
}

type cachedQuery struct {
	doc    *ast.Document
	cached time.Time
}

// NewGraphQLAction creates and initializes a new GraphQLAction.
func NewGraphQLAction(data []byte) (ActionConfig, error) {
	config := &GraphQLAction{
		persistentQueries: make(map[string]string),
		queryCache: &queryCache{
			queries: make(map[string]*cachedQuery),
		},
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Validate URL
	if config.URL == "" {
		return nil, fmt.Errorf("graphql: url is required")
	}

	// Parse target URL
	var err error
	config.targetURL, err = url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("graphql: invalid url: %w", err)
	}

	// Set defaults
	if config.MaxDepth == 0 {
		config.MaxDepth = DefaultGraphQLMaxDepth
	}
	if config.MaxComplexity == 0 {
		config.MaxComplexity = DefaultGraphQLMaxComplexity
	}
	if config.MaxCost == 0 {
		config.MaxCost = DefaultGraphQLMaxCost
	}
	if config.MaxAliases == 0 {
		config.MaxAliases = DefaultGraphQLMaxAliases
	}
	if config.Timeout.Duration == 0 {
		config.Timeout = reqctx.Duration{Duration: DefaultGraphQLTimeout}
	}
	if config.QueryCacheSize == 0 {
		config.QueryCacheSize = DefaultQueryCacheSize
	}

	// Set defaults for optimization features
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = DefaultMaxBatchSize
	}
	// Note: EnableQueryBatching and EnableQueryDeduplication default to false in Go (zero value)
	// They need to be explicitly set to true in JSON, or we can set defaults here
	// For now, we'll require explicit configuration to avoid breaking existing configs

	// Parse result cache TTL
	if config.ResultCacheTTL.Duration == 0 {
		config.resultCacheTTL = DefaultResultCacheTTL
	} else {
		config.resultCacheTTL = config.ResultCacheTTL.Duration
	}

	// Initialize result cache if enabled
	if config.EnableResultCaching {
		config.resultCache = newResultCache(config.ResultCacheSize, config.resultCacheTTL)
		slog.Info("graphql: result caching enabled", "cache_size", config.ResultCacheSize, "ttl", config.resultCacheTTL)
	}

	// Load persistent queries if provided
	if len(config.PersistentQueriesMap) > 0 {
		config.persistentQueries = config.PersistentQueriesMap
		slog.Info("graphql: loaded persistent queries", "count", len(config.persistentQueries))
	}

	// Initialize APQ cache if enabled
	if config.AutomaticPersistedQueries {
		config.apqCache, err = newAPQCache(config.APQCacheSize)
		if err != nil {
			return nil, fmt.Errorf("graphql: failed to create APQ cache: %w", err)
		}
		slog.Info("graphql: APQ enabled", "cache_size", config.APQCacheSize)
	}

	// Initialize field rate limiter if configured
	if len(config.FieldRateLimits) > 0 {
		config.fieldRateLimiter = newFieldRateLimiter(config.FieldRateLimits)
		slog.Info("graphql: field rate limiting enabled", "fields", len(config.FieldRateLimits))
	}

	// Initialize per-operation rate limiter if any operation limits are configured
	if config.QueryRateLimit != nil || config.MutationRateLimit != nil || config.SubscriptionRateLimit != nil {
		config.operationRateLimiter = newOperationRateLimiter(config.QueryRateLimit, config.MutationRateLimit, config.SubscriptionRateLimit)
		slog.Info("graphql: per-operation rate limiting enabled")
	}

	// Initialize base transport with connection settings
	baseTransport := ClientConnectionTransportFn(&config.BaseConnection)

	// Wrap with GraphQL validation transport
	config.tr = &graphqlTransport{
		base:   baseTransport,
		config: config,
	}

	return config, nil
}

// Init stores the config for metrics
func (g *GraphQLAction) Init(cfg *Config) error {
	g.cfg = cfg
	return nil
}

// RefreshTransport performs the refresh transport operation on the GraphQLAction.
func (g *GraphQLAction) RefreshTransport() {
	baseTransport := ClientConnectionTransportFn(&g.BaseConnection)
	g.tr = &graphqlTransport{
		base:   baseTransport,
		config: g,
	}
}

// Rewrite modifies the request to point to the GraphQL backend
func (c *GraphQLAction) Rewrite() RewriteFn {
	return func(pr *httputil.ProxyRequest) {
		req := pr.Out

		slog.Debug("graphql: rewriting request", "target_url", c.targetURL.String())

		// Set the backend GraphQL URL
		pr.SetURL(c.targetURL)
		
		// Clear the path to use the path from targetURL
		req.URL.Path = c.targetURL.Path
		req.URL.RawPath = ""

		// Ensure it's a POST request with proper headers
		req.Method = http.MethodPost
		req.Host = c.targetURL.Host
		req.Header.Set("Host", c.targetURL.Host)
		req.Header.Set("Content-Type", "application/json")

		slog.Debug("graphql: request rewritten", "url", req.URL.String())
	}
}

// graphqlTransport wraps the base transport with GraphQL validation
type graphqlTransport struct {
	base   http.RoundTripper
	config *GraphQLAction
}

// RoundTrip performs the round trip operation on the graphqlTransport.
func (t *graphqlTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	
	// Only validate POST and GET requests
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		return t.errorResponse(r, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
	}

	// Handle batching if enabled
	if t.config.EnableQueryBatching && r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return t.errorResponse(r, "Failed to read request body", "BAD_REQUEST", http.StatusBadRequest)
		}
		r.Body.Close()

		// Try to parse as batch
		batch, err := parseBatchRequest(body)
		if err == nil && len(batch) > 1 {
			// This is a batch request
			return t.processBatchRequest(r, batch)
		}
		// Single request, restore body and continue with normal processing
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Parse GraphQL request
	gqlReq, body, err := t.config.parseGraphQLRequest(r)
	if err != nil {
		slog.Debug("graphql: failed to parse request", "error", err)
		return t.errorResponse(r, err.Error(), "BAD_REQUEST", http.StatusBadRequest)
	}

	// Restore body for downstream transport
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Handle APQ (Automatic Persisted Queries) per Apollo spec
	if t.config.AutomaticPersistedQueries && t.config.apqCache != nil {
		if gqlReq.Extensions != nil {
			if persistedQuery, ok := gqlReq.Extensions[APQExtensionKey].(map[string]interface{}); ok {
				if version, ok := persistedQuery[APQVersionKey].(float64); ok && int(version) == APQVersion {
					if sha256Hash, ok := persistedQuery[APQSHA256HashKey].(string); ok {
						// Try to get query from APQ cache
						if cachedQuery, found := t.config.apqCache.Get(sha256Hash); found {
							gqlReq.Query = cachedQuery
							slog.Debug("graphql: APQ cache hit", "hash", sha256Hash)
						} else if gqlReq.Query == "" {
							// APQ miss - client needs to send full query
							return t.errorResponse(r, "PersistedQueryNotFound", APQErrorCodeNotFound, http.StatusOK)
						} else {
							// Validate hash and cache the query
							if !validateAPQHash(gqlReq.Query, sha256Hash) {
								return t.errorResponse(r, "Query hash mismatch", "BAD_REQUEST", http.StatusBadRequest)
							}
							t.config.apqCache.Set(sha256Hash, gqlReq.Query)
							slog.Debug("graphql: APQ cached", "hash", sha256Hash)
						}
					}
				}
			}
		}
	}

	// Handle legacy persistent queries
	if !t.config.AutomaticPersistedQueries && gqlReq.Extensions != nil {
		if persistedQuery, ok := gqlReq.Extensions["persistedQuery"].(map[string]interface{}); ok {
			if sha256Hash, ok := persistedQuery["sha256Hash"].(string); ok {
				if query, exists := t.config.persistentQueries[sha256Hash]; exists {
					gqlReq.Query = query
					slog.Debug("graphql: using persistent query", "hash", sha256Hash)
				} else if gqlReq.Query == "" {
					return t.errorResponse(r, "Persisted query not found", "PERSISTED_QUERY_NOT_FOUND", http.StatusBadRequest)
				}
			}
		}
	}

	if gqlReq.Query == "" {
		return t.errorResponse(r, "Query is required", "BAD_REQUEST", http.StatusBadRequest)
	}

	// Parse and validate query
	doc, err := t.config.parseQuery(gqlReq.Query)
	if err != nil {
		slog.Debug("graphql: failed to parse query", "error", err)
		return t.errorResponse(r, "Invalid GraphQL query: "+err.Error(), "GRAPHQL_PARSE_FAILED", http.StatusBadRequest)
	}

	// Per-operation rate limiting (query vs mutation vs subscription)
	if t.config.operationRateLimiter != nil {
		opType := extractOperationType(doc)
		if err := t.config.operationRateLimiter.check(opType); err != nil {
			slog.Warn("graphql: operation rate limit exceeded", "operation_type", opType, "error", err)
			return t.errorResponse(r, err.Error(), "RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
		}
	}

	// Check if introspection is disabled
	if !t.config.EnableIntrospection && t.config.isIntrospectionQuery(doc) {
		slog.Warn("graphql: introspection query blocked")
		return t.errorResponse(r, "Introspection is disabled", "FORBIDDEN", http.StatusForbidden)
	}

	// Field-level rate limiting
	if t.config.fieldRateLimiter != nil {
		fields := extractFields(doc)
		if err := t.config.fieldRateLimiter.checkFields(fields); err != nil {
			slog.Warn("graphql: field rate limit exceeded", "error", err)
			return t.errorResponse(r, err.Error(), "RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
		}
	}

	// Analyze query depth
	depth := t.config.calculateDepth(doc)
	if depth > t.config.MaxDepth {
		slog.Warn("graphql: query too deep", "depth", depth, "max", t.config.MaxDepth)
		return t.errorResponse(r, fmt.Sprintf("Query depth %d exceeds maximum %d", depth, t.config.MaxDepth), "QUERY_TOO_DEEP", http.StatusBadRequest)
	}

	// Analyze query complexity
	complexity := t.config.calculateComplexity(doc)
	
	// Record GraphQL query complexity metric
	configID := "unknown"
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
		configData := reqctx.ConfigParams(requestData.Config)
		if id := configData.GetConfigID(); id != "" {
			configID = id
		}
	}
	operationName := gqlReq.OperationName
	if operationName == "" {
		operationName = "anonymous"
	}
	metric.GraphQLQueryComplexity(configID, operationName, float64(complexity))
	
	if complexity > t.config.MaxComplexity {
		slog.Warn("graphql: query too complex", "complexity", complexity, "max", t.config.MaxComplexity)
		return t.errorResponse(r, fmt.Sprintf("Query complexity %d exceeds maximum %d", complexity, t.config.MaxComplexity), "QUERY_TOO_COMPLEX", http.StatusBadRequest)
	}

	// Analyze alias count
	aliases := t.config.calculateAliases(doc)
	if aliases > t.config.MaxAliases {
		slog.Warn("graphql: too many aliases", "aliases", aliases, "max", t.config.MaxAliases)
		return t.errorResponse(r, fmt.Sprintf("Query alias count %d exceeds maximum %d", aliases, t.config.MaxAliases), "TOO_MANY_ALIASES", http.StatusBadRequest)
	}

	// Calculate query cost
	cost := t.config.calculateCost(doc)
	if cost > t.config.MaxCost {
		slog.Warn("graphql: query too costly", "cost", cost, "max", t.config.MaxCost)
		return t.errorResponse(r, fmt.Sprintf("Query cost %d exceeds maximum %d", cost, t.config.MaxCost), "QUERY_TOO_COSTLY", http.StatusBadRequest)
	}

	slog.Debug("graphql: query analysis",
		"depth", depth,
		"complexity", complexity,
		"aliases", aliases,
		"cost", cost,
		"operation", gqlReq.OperationName)

	// Reconstruct the request body with potentially modified GraphQL request
	reqBody, err := json.Marshal(gqlReq)
	if err != nil {
		return t.errorResponse(r, "Failed to marshal request", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
	}
	r.Body = io.NopCloser(bytes.NewReader(reqBody))
	r.ContentLength = int64(len(reqBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))

	// Forward to backend
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		slog.Error("graphql: backend request failed", "error", err)
		return t.errorResponse(r, "Backend request failed", "BACKEND_ERROR", http.StatusBadGateway)
	}

	duration := time.Since(start)
	
	// Record GraphQL execution time metric (configID already set above)
	metric.GraphQLExecutionTime(configID, operationName, duration.Seconds())
	
	// Log analytics
	t.config.logQueryAnalytics(gqlReq.OperationName, depth, complexity, cost, duration)

	slog.Debug("graphql: backend request completed", "duration", duration, "status", resp.StatusCode)
	return resp, nil
}

func (t *graphqlTransport) errorResponse(r *http.Request, message, code string, statusCode int) (*http.Response, error) {
	// Record error metric
	configID := "unknown"
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
		configData := reqctx.ConfigParams(requestData.Config)
		if id := configData.GetConfigID(); id != "" {
			configID = id
		}
	}
	errorType := code
	errorCategory := "graphql"
	if statusCode >= 400 && statusCode < 500 {
		errorCategory = "client_error"
	} else if statusCode >= 500 {
		errorCategory = "server_error"
	}
	metric.ErrorTotal(configID, errorType, errorCategory)
	
	errorResp := map[string]interface{}{
		"errors": []map[string]interface{}{
			{
				"message": message,
				"extensions": map[string]string{
					"code": code,
				},
			},
		},
	}

	body, _ := json.Marshal(errorResp)

	return &http.Response{
		Status:        http.StatusText(statusCode),
		StatusCode:    statusCode,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}, nil
}

func (c *GraphQLAction) parseGraphQLRequest(r *http.Request) (*GraphQLRequest, []byte, error) {
	gqlReq := &GraphQLRequest{}

	if r.Method == http.MethodGet {
		gqlReq.Query = r.URL.Query().Get("query")
		gqlReq.OperationName = r.URL.Query().Get("operationName")
		if variables := r.URL.Query().Get("variables"); variables != "" {
			if err := json.Unmarshal([]byte(variables), &gqlReq.Variables); err != nil {
				return nil, nil, fmt.Errorf("invalid variables: %w", err)
			}
		}
		return gqlReq, nil, nil
	}

	// POST request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read body: %w", err)
	}
	r.Body.Close()

	if err := json.Unmarshal(body, gqlReq); err != nil {
		return nil, body, fmt.Errorf("invalid JSON: %w", err)
	}

	return gqlReq, body, nil
}

func (c *GraphQLAction) parseQuery(query string) (*ast.Document, error) {
	// Check cache first
	c.queryCache.mx.RLock()
	cached, exists := c.queryCache.queries[query]
	c.queryCache.mx.RUnlock()

	if exists && time.Since(cached.cached) < 5*time.Minute {
		return cached.doc, nil
	}

	// Parse query
	src := source.NewSource(&source.Source{
		Body: []byte(query),
		Name: "GraphQL request",
	})

	doc, err := parser.Parse(parser.ParseParams{Source: src})
	if err != nil {
		return nil, err
	}

	// Cache parsed query
	c.queryCache.mx.Lock()
	c.queryCache.queries[query] = &cachedQuery{
		doc:    doc,
		cached: time.Now(),
	}
	c.queryCache.mx.Unlock()

	return doc, nil
}

func (c *GraphQLAction) isIntrospectionQuery(doc *ast.Document) bool {
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			for _, sel := range op.SelectionSet.Selections {
				if field, ok := sel.(*ast.Field); ok {
					fieldName := field.Name.Value
					if fieldName == "__schema" || fieldName == "__type" || strings.HasPrefix(fieldName, "__") {
						return true
					}
				}
			}
		}
	}
	return false
}

func (c *GraphQLAction) calculateDepth(doc *ast.Document) int {
	maxDepth := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			depth := c.calculateSelectionDepth(op.SelectionSet, 1)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
	}
	return maxDepth
}

func (c *GraphQLAction) calculateSelectionDepth(selectionSet *ast.SelectionSet, currentDepth int) int {
	if selectionSet == nil || len(selectionSet.Selections) == 0 {
		return currentDepth
	}

	maxDepth := currentDepth
	for _, sel := range selectionSet.Selections {
		depth := currentDepth

		switch s := sel.(type) {
		case *ast.Field:
			if s.SelectionSet != nil {
				depth = c.calculateSelectionDepth(s.SelectionSet, currentDepth+1)
			}
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				depth = c.calculateSelectionDepth(s.SelectionSet, currentDepth+1)
			}
		case *ast.FragmentSpread:
			// For fragment spreads, we'd need the full schema to resolve
			// For now, just add 1
			depth = currentDepth + 1
		}

		if depth > maxDepth {
			maxDepth = depth
		}
	}

	return maxDepth
}

func (c *GraphQLAction) calculateComplexity(doc *ast.Document) int {
	complexity := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			complexity += c.calculateSelectionComplexity(op.SelectionSet)
		}
	}
	return complexity
}

func (c *GraphQLAction) calculateSelectionComplexity(selectionSet *ast.SelectionSet) int {
	if selectionSet == nil || len(selectionSet.Selections) == 0 {
		return 0
	}

	complexity := 0
	for _, sel := range selectionSet.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			// Each field adds 1 to complexity
			fieldComplexity := 1

			// List fields add more complexity
			if c.isListField(s) {
				fieldComplexity = 10
			}

			// Nested selections multiply complexity
			if s.SelectionSet != nil {
				nestedComplexity := c.calculateSelectionComplexity(s.SelectionSet)
				fieldComplexity *= (nestedComplexity + 1)
			}

			complexity += fieldComplexity

		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				complexity += c.calculateSelectionComplexity(s.SelectionSet)
			}

		case *ast.FragmentSpread:
			// Add base complexity for fragment
			complexity += 5
		}
	}

	return complexity
}

func (c *GraphQLAction) isListField(field *ast.Field) bool {
	// This is a heuristic - fields with certain names are likely lists
	// In a real implementation, you'd need schema information
	name := strings.ToLower(field.Name.Value)
	return strings.HasSuffix(name, "s") || strings.Contains(name, "list") || strings.Contains(name, "all")
}

// GetType returns the type for the GraphQLAction.
func (c *GraphQLAction) GetType() string {
	return TypeGraphQL
}

// GraphQLRequest represents an inbound graph ql request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	Extensions    map[string]interface{} `json:"extensions,omitempty"`
}

// extractOperationType returns the primary operation type from a parsed GraphQL document.
// Returns "query", "mutation", or "subscription". Defaults to "query" if not determinable.
func extractOperationType(doc *ast.Document) string {
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			if op.Operation != "" {
				return op.Operation
			}
			// Default operation type in GraphQL is "query"
			return "query"
		}
	}
	return "query"
}

// operationRateLimiter enforces per-operation-type rate limits for GraphQL.
// It uses a sliding window counter per operation type (query, mutation, subscription).
type operationRateLimiter struct {
	limits   map[string]*OperationRateLimit
	counters map[string]*operationCounter
	mu       sync.Mutex
}

type operationCounter struct {
	minuteCount int
	hourCount   int
	minuteReset time.Time
	hourReset   time.Time
}

func newOperationRateLimiter(query, mutation, subscription *OperationRateLimit) *operationRateLimiter {
	orl := &operationRateLimiter{
		limits:   make(map[string]*OperationRateLimit),
		counters: make(map[string]*operationCounter),
	}
	if query != nil {
		orl.limits["query"] = query
		orl.counters["query"] = &operationCounter{}
	}
	if mutation != nil {
		orl.limits["mutation"] = mutation
		orl.counters["mutation"] = &operationCounter{}
	}
	if subscription != nil {
		orl.limits["subscription"] = subscription
		orl.counters["subscription"] = &operationCounter{}
	}
	return orl
}

// check verifies that the operation type has not exceeded its rate limit.
func (orl *operationRateLimiter) check(opType string) error {
	limit, ok := orl.limits[opType]
	if !ok {
		return nil // No limit configured for this operation type
	}

	orl.mu.Lock()
	defer orl.mu.Unlock()

	counter := orl.counters[opType]
	now := time.Now()

	// Reset minute window if expired
	if now.After(counter.minuteReset) {
		counter.minuteCount = 0
		counter.minuteReset = now.Add(time.Minute)
	}

	// Reset hour window if expired
	if now.After(counter.hourReset) {
		counter.hourCount = 0
		counter.hourReset = now.Add(time.Hour)
	}

	// Check minute limit
	if limit.RequestsPerMinute > 0 && counter.minuteCount >= limit.RequestsPerMinute {
		return fmt.Errorf("graphql: %s rate limit exceeded (%d/min)", opType, limit.RequestsPerMinute)
	}

	// Check hour limit
	if limit.RequestsPerHour > 0 && counter.hourCount >= limit.RequestsPerHour {
		return fmt.Errorf("graphql: %s rate limit exceeded (%d/hr)", opType, limit.RequestsPerHour)
	}

	counter.minuteCount++
	counter.hourCount++
	return nil
}
