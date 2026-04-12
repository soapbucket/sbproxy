// Package graphql implements the GraphQL proxy action as a self-contained leaf module.
//
// It registers itself into the pkg/plugin registry via init() under the name "graphql".
// The action validates and forwards GraphQL requests to a configured upstream, supporting:
//   - Query depth, complexity, cost, and alias limiting
//   - Automatic Persisted Queries (APQ) per Apollo spec
//   - Legacy persistent queries (hash->query map)
//   - Query result caching
//   - Query batching and deduplication
//   - Per-operation-type rate limiting (query, mutation, subscription)
//   - Field-level rate limiting
//   - Introspection blocking
//
// This package replaces the adapter-wrapped graphql in internal/modules/action/actions.go.
package graphql

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"

	internaltransport "github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("graphql", New)
}

// Default configuration values.
const (
	defaultMaxDepth      = 10
	defaultMaxComplexity = 100
	defaultMaxCost       = 1000
	defaultMaxAliases    = 10
	defaultTimeout       = 30 * time.Second
	defaultQueryCache    = 1000
	defaultResultCache   = 1000
	defaultResultTTL     = 5 * time.Minute
	defaultMaxBatch      = 10
	defaultAPQCache      = 10000

	// Field cost defaults.
	defaultFieldCost        = 1
	defaultListFieldCost    = 10
	defaultMutationCost     = 5
	defaultSubscriptionCost = 10

	// APQ constants per Apollo spec.
	apqVersion           = 1
	apqExtensionKey      = "persistedQuery"
	apqVersionKey        = "version"
	apqSHA256HashKey     = "sha256Hash"
	apqErrorCodeNotFound = "PERSISTED_QUERY_NOT_FOUND"
)

// GraphQL error codes used in responses.
var (
	errQueryTooDeep          = fmt.Errorf("graphql: query exceeds maximum depth")
	errQueryTooComplex       = fmt.Errorf("graphql: query exceeds maximum complexity")
	errQueryTooCostly        = fmt.Errorf("graphql: query exceeds maximum cost")
	errInvalidQuery          = fmt.Errorf("graphql: invalid query")
	errIntrospectionDisabled = fmt.Errorf("graphql: introspection is disabled")
	errTooManyAliases        = fmt.Errorf("graphql: query exceeds maximum aliases")
	errFieldRateLimited      = fmt.Errorf("graphql: field rate limit exceeded")
)

// Handler is the GraphQL action handler. It implements plugin.ReverseProxyAction.
type Handler struct {
	cfg                  Config
	targetURL            *url.URL
	tr                   http.RoundTripper
	persistentQueries    map[string]string
	queryCache           *queryCache
	apqCache             *apqCache
	fieldRateLimiter     *fieldRateLimiter
	resultCache          *resultCache
	resultCacheTTL       time.Duration
	operationRateLimiter *operationRateLimiter
}

// New is the ActionFactory for the graphql module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("graphql: parse config: %w", err)
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("graphql: url is required")
	}

	targetURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("graphql: invalid url: %w", err)
	}

	// Apply defaults.
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = defaultMaxDepth
	}
	if cfg.MaxComplexity == 0 {
		cfg.MaxComplexity = defaultMaxComplexity
	}
	if cfg.MaxCost == 0 {
		cfg.MaxCost = defaultMaxCost
	}
	if cfg.MaxAliases == 0 {
		cfg.MaxAliases = defaultMaxAliases
	}
	if cfg.QueryCacheSize == 0 {
		cfg.QueryCacheSize = defaultQueryCache
	}
	if cfg.MaxBatchSize == 0 {
		cfg.MaxBatchSize = defaultMaxBatch
	}

	resultCacheTTL := cfg.ResultCacheTTL.Duration
	if resultCacheTTL == 0 {
		resultCacheTTL = defaultResultTTL
	}

	h := &Handler{
		cfg:       cfg,
		targetURL: targetURL,
		persistentQueries: make(map[string]string),
		queryCache: &queryCache{
			queries: make(map[string]*cachedQuery),
		},
		resultCacheTTL: resultCacheTTL,
	}

	// Initialize transport.
	baseTransport := internaltransport.NewTransportFromConfig(cfg.connectionConfig())
	h.tr = &graphqlTransport{
		base:    baseTransport,
		handler: h,
	}

	if cfg.SkipTLSVerifyHost {
		metric.TLSInsecureSkipVerifyEnabled(cfg.URL, "graphql")
	}

	// Load persistent queries.
	if len(cfg.PersistentQueriesMap) > 0 {
		h.persistentQueries = cfg.PersistentQueriesMap
		slog.Info("graphql: loaded persistent queries", "count", len(h.persistentQueries))
	}

	// Initialize APQ cache.
	if cfg.AutomaticPersistedQueries {
		apqSize := cfg.APQCacheSize
		if apqSize == 0 {
			apqSize = defaultAPQCache
		}
		h.apqCache = newAPQCache(apqSize)
		slog.Info("graphql: APQ enabled", "cache_size", apqSize)
	}

	// Initialize result cache.
	if cfg.EnableResultCaching {
		size := cfg.ResultCacheSize
		if size == 0 {
			size = defaultResultCache
		}
		h.resultCache = newResultCache(size, resultCacheTTL)
		slog.Info("graphql: result caching enabled", "cache_size", size, "ttl", resultCacheTTL)
	}

	// Initialize field rate limiter.
	if len(cfg.FieldRateLimits) > 0 {
		h.fieldRateLimiter = newFieldRateLimiter(cfg.FieldRateLimits)
		slog.Info("graphql: field rate limiting enabled", "fields", len(cfg.FieldRateLimits))
	}

	// Initialize per-operation rate limiter.
	if cfg.QueryRateLimit != nil || cfg.MutationRateLimit != nil || cfg.SubscriptionRateLimit != nil {
		h.operationRateLimiter = newOperationRateLimiter(cfg.QueryRateLimit, cfg.MutationRateLimit, cfg.SubscriptionRateLimit)
		slog.Info("graphql: per-operation rate limiting enabled")
	}

	return h, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "graphql" }

// ServeHTTP satisfies plugin.ActionHandler. GraphQL uses ReverseProxyAction path.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "graphql: direct serving not supported; use reverse proxy path", http.StatusInternalServerError)
}

// Rewrite satisfies plugin.ReverseProxyAction.
// It sets the outbound request URL to the configured GraphQL backend.
func (h *Handler) Rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(h.targetURL)
	pr.Out.URL.Path = h.targetURL.Path
	pr.Out.URL.RawPath = ""
	pr.Out.Method = http.MethodPost
	pr.Out.Host = h.targetURL.Host
	pr.Out.Header.Set("Host", h.targetURL.Host)
	pr.Out.Header.Set("Content-Type", "application/json")
}

// Transport satisfies plugin.ReverseProxyAction.
func (h *Handler) Transport() http.RoundTripper { return h.tr }

// ModifyResponse satisfies plugin.ReverseProxyAction.
func (h *Handler) ModifyResponse(_ *http.Response) error { return nil }

// ErrorHandler satisfies plugin.ReverseProxyAction.
func (h *Handler) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("graphql: upstream error", "url", r.URL.String(), "error", err)
	body, _ := json.Marshal(map[string]interface{}{
		"errors": []map[string]interface{}{
			{"message": "upstream connection failed", "extensions": map[string]string{"code": "UPSTREAM_ERROR"}},
		},
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write(body)
}

// -- Query analysis helpers --------------------------------------------------

type queryCache struct {
	queries map[string]*cachedQuery
	mx      sync.RWMutex
}

type cachedQuery struct {
	doc    *ast.Document
	cached time.Time
}

func (h *Handler) parseQuery(query string) (*ast.Document, error) {
	h.queryCache.mx.RLock()
	cached, exists := h.queryCache.queries[query]
	h.queryCache.mx.RUnlock()
	if exists && time.Since(cached.cached) < 5*time.Minute {
		return cached.doc, nil
	}

	src := source.NewSource(&source.Source{
		Body: []byte(query),
		Name: "GraphQL request",
	})
	doc, err := parser.Parse(parser.ParseParams{Source: src})
	if err != nil {
		return nil, err
	}

	h.queryCache.mx.Lock()
	h.queryCache.queries[query] = &cachedQuery{doc: doc, cached: time.Now()}
	h.queryCache.mx.Unlock()

	return doc, nil
}

func (h *Handler) isIntrospectionQuery(doc *ast.Document) bool {
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			for _, sel := range op.SelectionSet.Selections {
				if field, ok := sel.(*ast.Field); ok {
					name := field.Name.Value
					if name == "__schema" || name == "__type" || strings.HasPrefix(name, "__") {
						return true
					}
				}
			}
		}
	}
	return false
}

func (h *Handler) calculateDepth(doc *ast.Document) int {
	max := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			d := h.calcSelectionDepth(op.SelectionSet, 1)
			if d > max {
				max = d
			}
		}
	}
	return max
}

func (h *Handler) calcSelectionDepth(ss *ast.SelectionSet, cur int) int {
	if ss == nil || len(ss.Selections) == 0 {
		return cur
	}
	max := cur
	for _, sel := range ss.Selections {
		var d int
		switch s := sel.(type) {
		case *ast.Field:
			if s.SelectionSet != nil {
				d = h.calcSelectionDepth(s.SelectionSet, cur+1)
			} else {
				d = cur
			}
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				d = h.calcSelectionDepth(s.SelectionSet, cur+1)
			} else {
				d = cur
			}
		case *ast.FragmentSpread:
			d = cur + 1
		}
		if d > max {
			max = d
		}
	}
	return max
}

func (h *Handler) calculateComplexity(doc *ast.Document) int {
	total := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			total += h.calcSelectionComplexity(op.SelectionSet)
		}
	}
	return total
}

func (h *Handler) calcSelectionComplexity(ss *ast.SelectionSet) int {
	if ss == nil || len(ss.Selections) == 0 {
		return 0
	}
	total := 0
	for _, sel := range ss.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			fc := 1
			if h.isListField(s) {
				fc = defaultListFieldCost
			}
			if s.SelectionSet != nil {
				fc *= (h.calcSelectionComplexity(s.SelectionSet) + 1)
			}
			total += fc
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				total += h.calcSelectionComplexity(s.SelectionSet)
			}
		case *ast.FragmentSpread:
			total += 5
		}
	}
	return total
}

func (h *Handler) isListField(field *ast.Field) bool {
	name := strings.ToLower(field.Name.Value)
	return strings.HasSuffix(name, "s") || strings.Contains(name, "list") || strings.Contains(name, "all")
}

func (h *Handler) calculateAliases(doc *ast.Document) int {
	count := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			count += countAliasesInSelection(op.SelectionSet)
		}
	}
	return count
}

func countAliasesInSelection(ss *ast.SelectionSet) int {
	if ss == nil || len(ss.Selections) == 0 {
		return 0
	}
	count := 0
	for _, sel := range ss.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			if s.Alias != nil && s.Alias.Value != "" {
				count++
			}
			if s.SelectionSet != nil {
				count += countAliasesInSelection(s.SelectionSet)
			}
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				count += countAliasesInSelection(s.SelectionSet)
			}
		}
	}
	return count
}

func (h *Handler) calculateCost(doc *ast.Document) int {
	total := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			switch op.Operation {
			case ast.OperationTypeMutation:
				total += defaultMutationCost
			case ast.OperationTypeSubscription:
				total += defaultSubscriptionCost
			}
			total += h.calcSelectionCost(op.SelectionSet, 1)
		}
	}
	return total
}

func (h *Handler) calcSelectionCost(ss *ast.SelectionSet, depth int) int {
	if ss == nil || len(ss.Selections) == 0 {
		return 0
	}
	total := 0
	for _, sel := range ss.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			fieldName := s.Name.Value
			fc := defaultFieldCost
			if custom, ok := h.cfg.FieldCosts[fieldName]; ok {
				fc = custom
			} else if h.isListField(s) {
				fc = defaultListFieldCost
			}
			fc *= depth
			if args := s.Arguments; args != nil {
				for _, arg := range args {
					name := strings.ToLower(arg.Name.Value)
					if name == "first" || name == "last" || name == "limit" {
						if lit, ok := arg.Value.(*ast.IntValue); ok {
							fc *= parseIntValue(lit.Value, 10)
						}
					}
				}
			}
			if s.SelectionSet != nil {
				fc += h.calcSelectionCost(s.SelectionSet, depth+1)
			}
			total += fc
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				total += h.calcSelectionCost(s.SelectionSet, depth)
			}
		case *ast.FragmentSpread:
			total += 5 * depth
		}
	}
	return total
}

func parseIntValue(val string, def int) int {
	var n int
	if _, err := fmt.Sscanf(val, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func (h *Handler) logQueryAnalytics(opName string, depth, complexity, cost int, dur time.Duration) {
	slog.Info("graphql: query executed",
		"operation", opName,
		"depth", depth,
		"complexity", complexity,
		"cost", cost,
		"duration_ms", dur.Milliseconds(),
		"max_depth", h.cfg.MaxDepth,
		"max_complexity", h.cfg.MaxComplexity,
		"max_cost", h.cfg.MaxCost,
	)
}

// -- Request parsing ----------------------------------------------------------

func parseGraphQLRequest(r *http.Request) (*Request, []byte, error) {
	req := &Request{}
	if r.Method == http.MethodGet {
		req.Query = r.URL.Query().Get("query")
		req.OperationName = r.URL.Query().Get("operationName")
		if v := r.URL.Query().Get("variables"); v != "" {
			if err := json.Unmarshal([]byte(v), &req.Variables); err != nil {
				return nil, nil, fmt.Errorf("invalid variables: %w", err)
			}
		}
		return req, nil, nil
	}
	if r.Body == nil {
		return nil, nil, fmt.Errorf("request body is required for %s", r.Method)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read body: %w", err)
	}
	r.Body.Close()
	if err := json.Unmarshal(body, req); err != nil {
		return nil, body, fmt.Errorf("invalid JSON: %w", err)
	}
	return req, body, nil
}

func parseBatchRequest(body []byte) ([]*Request, error) {
	var batch []*Request
	if err := json.Unmarshal(body, &batch); err == nil && len(batch) > 0 {
		return batch, nil
	}
	var single Request
	if err := json.Unmarshal(body, &single); err == nil {
		return []*Request{&single}, nil
	}
	return nil, fmt.Errorf("invalid GraphQL request format")
}

func extractOperationType(doc *ast.Document) string {
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			if op.Operation != "" {
				return op.Operation
			}
			return "query"
		}
	}
	return "query"
}

func extractFields(doc *ast.Document) []string {
	fields := make([]string, 0)
	seen := make(map[string]bool)
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			extractFieldsFromSelection(op.SelectionSet, &fields, seen)
		}
	}
	return fields
}

func extractFieldsFromSelection(ss *ast.SelectionSet, fields *[]string, seen map[string]bool) {
	if ss == nil {
		return
	}
	for _, sel := range ss.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			if !seen[s.Name.Value] {
				*fields = append(*fields, s.Name.Value)
				seen[s.Name.Value] = true
			}
			if s.SelectionSet != nil {
				extractFieldsFromSelection(s.SelectionSet, fields, seen)
			}
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				extractFieldsFromSelection(s.SelectionSet, fields, seen)
			}
		}
	}
}

// -- Transport ----------------------------------------------------------------

type graphqlTransport struct {
	base    http.RoundTripper
	handler *Handler
}

func (t *graphqlTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	h := t.handler

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		return errorResponse(r, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
	}

	// Handle batching.
	if h.cfg.EnableQueryBatching && r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return errorResponse(r, "Failed to read request body", "BAD_REQUEST", http.StatusBadRequest)
		}
		r.Body.Close()

		batch, err := parseBatchRequest(body)
		if err == nil && len(batch) > 1 {
			return t.processBatchRequest(r, batch)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Parse GraphQL request.
	gqlReq, body, err := parseGraphQLRequest(r)
	if err != nil {
		slog.Debug("graphql: failed to parse request", "error", err)
		return errorResponse(r, err.Error(), "BAD_REQUEST", http.StatusBadRequest)
	}
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// APQ handling.
	if h.cfg.AutomaticPersistedQueries && h.apqCache != nil {
		if gqlReq.Extensions != nil {
			if pq, ok := gqlReq.Extensions[apqExtensionKey].(map[string]interface{}); ok {
				if ver, ok := pq[apqVersionKey].(float64); ok && int(ver) == apqVersion {
					if sha256Hash, ok := pq[apqSHA256HashKey].(string); ok {
						if cached, found := h.apqCache.Get(sha256Hash); found {
							gqlReq.Query = cached
						} else if gqlReq.Query == "" {
							return errorResponse(r, "PersistedQueryNotFound", apqErrorCodeNotFound, http.StatusOK)
						} else {
							if !validateAPQHash(gqlReq.Query, sha256Hash) {
								return errorResponse(r, "Query hash mismatch", "BAD_REQUEST", http.StatusBadRequest)
							}
							h.apqCache.Set(sha256Hash, gqlReq.Query)
						}
					}
				}
			}
		}
	}

	// Legacy persistent queries.
	if !h.cfg.AutomaticPersistedQueries && gqlReq.Extensions != nil {
		if pq, ok := gqlReq.Extensions["persistedQuery"].(map[string]interface{}); ok {
			if sha256Hash, ok := pq["sha256Hash"].(string); ok {
				if query, exists := h.persistentQueries[sha256Hash]; exists {
					gqlReq.Query = query
				} else if gqlReq.Query == "" {
					return errorResponse(r, "Persisted query not found", "PERSISTED_QUERY_NOT_FOUND", http.StatusBadRequest)
				}
			}
		}
	}

	if gqlReq.Query == "" {
		return errorResponse(r, "Query is required", "BAD_REQUEST", http.StatusBadRequest)
	}

	doc, err := h.parseQuery(gqlReq.Query)
	if err != nil {
		return errorResponse(r, "Invalid GraphQL query: "+err.Error(), "GRAPHQL_PARSE_FAILED", http.StatusBadRequest)
	}

	// Per-operation rate limiting.
	if h.operationRateLimiter != nil {
		opType := extractOperationType(doc)
		if err := h.operationRateLimiter.check(opType); err != nil {
			return errorResponse(r, err.Error(), "RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
		}
	}

	// Introspection check.
	if !h.cfg.EnableIntrospection && h.isIntrospectionQuery(doc) {
		return errorResponse(r, "Introspection is disabled", "FORBIDDEN", http.StatusForbidden)
	}

	// Field rate limiting.
	if h.fieldRateLimiter != nil {
		fields := extractFields(doc)
		if err := h.fieldRateLimiter.checkFields(fields); err != nil {
			return errorResponse(r, err.Error(), "RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
		}
	}

	// Depth check.
	depth := h.calculateDepth(doc)
	if depth > h.cfg.MaxDepth {
		return errorResponse(r, fmt.Sprintf("Query depth %d exceeds maximum %d", depth, h.cfg.MaxDepth), "QUERY_TOO_DEEP", http.StatusBadRequest)
	}

	// Complexity check.
	complexity := h.calculateComplexity(doc)
	configID := extractConfigID(r)
	opName := gqlReq.OperationName
	if opName == "" {
		opName = "anonymous"
	}
	metric.GraphQLQueryComplexity(configID, opName, float64(complexity))

	if complexity > h.cfg.MaxComplexity {
		return errorResponse(r, fmt.Sprintf("Query complexity %d exceeds maximum %d", complexity, h.cfg.MaxComplexity), "QUERY_TOO_COMPLEX", http.StatusBadRequest)
	}

	// Alias count check.
	aliases := h.calculateAliases(doc)
	if aliases > h.cfg.MaxAliases {
		return errorResponse(r, fmt.Sprintf("Query alias count %d exceeds maximum %d", aliases, h.cfg.MaxAliases), "TOO_MANY_ALIASES", http.StatusBadRequest)
	}

	// Cost check.
	cost := h.calculateCost(doc)
	if cost > h.cfg.MaxCost {
		return errorResponse(r, fmt.Sprintf("Query cost %d exceeds maximum %d", cost, h.cfg.MaxCost), "QUERY_TOO_COSTLY", http.StatusBadRequest)
	}

	slog.Debug("graphql: query analysis",
		"depth", depth, "complexity", complexity, "aliases", aliases, "cost", cost,
		"operation", gqlReq.OperationName)

	// Rewrite body with potentially modified request (APQ may have updated the query).
	reqBody, err := json.Marshal(gqlReq)
	if err != nil {
		return errorResponse(r, "Failed to marshal request", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
	}
	r.Body = io.NopCloser(bytes.NewReader(reqBody))
	r.ContentLength = int64(len(reqBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))

	resp, err := t.base.RoundTrip(r)
	if err != nil {
		slog.Error("graphql: backend request failed", "error", err)
		return errorResponse(r, "Backend request failed", "BACKEND_ERROR", http.StatusBadGateway)
	}

	dur := time.Since(start)
	metric.GraphQLExecutionTime(configID, opName, dur.Seconds())
	h.logQueryAnalytics(gqlReq.OperationName, depth, complexity, cost, dur)

	return resp, nil
}

func errorResponse(r *http.Request, message, code string, statusCode int) (*http.Response, error) {
	configID := extractConfigID(r)
	errorCat := "graphql"
	if statusCode >= 400 && statusCode < 500 {
		errorCat = "client_error"
	} else if statusCode >= 500 {
		errorCat = "server_error"
	}
	metric.ErrorTotal(configID, code, errorCat)

	body, _ := json.Marshal(map[string]interface{}{
		"errors": []map[string]interface{}{
			{"message": message, "extensions": map[string]string{"code": code}},
		},
	})
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

// extractConfigID attempts to read the origin config ID from the request context.
func extractConfigID(r *http.Request) string {
	if rd := reqctx.GetRequestData(r.Context()); rd != nil && rd.Config != nil {
		if id := reqctx.ConfigParams(rd.Config).GetConfigID(); id != "" {
			return id
		}
	}
	return "unknown"
}

// -- Batch processing ---------------------------------------------------------

func (t *graphqlTransport) processBatchRequest(r *http.Request, requests []*Request) (*http.Response, error) {
	start := time.Now()
	h := t.handler
	configID := extractConfigID(r)

	// Deduplicate if enabled.
	deduplicated := requests
	indexMap := make(map[int]int)
	for i := range requests {
		indexMap[i] = i
	}
	var dedupCount int

	if h.cfg.EnableQueryDeduplication && len(requests) > 1 {
		deduplicated, _, indexMap = deduplicateQueries(requests)
		dedupCount = len(requests) - len(deduplicated)
		slog.Debug("graphql: batch deduplication",
			"original", len(requests), "deduplicated", len(deduplicated), "removed", dedupCount)
	}

	if len(deduplicated) > h.cfg.MaxBatchSize {
		return errorResponse(r, fmt.Sprintf("Batch size %d exceeds maximum %d", len(deduplicated), h.cfg.MaxBatchSize), "BATCH_TOO_LARGE", http.StatusBadRequest)
	}

	responses := make([]*Response, 0, len(deduplicated))
	cacheHits := 0

	for i, req := range deduplicated {
		var resp *Response
		cached := false

		if h.cfg.EnableResultCaching && h.resultCache != nil {
			key := generateCacheKey(req.Query, req.Variables)
			if data, found := h.resultCache.Get(key); found {
				if err := json.Unmarshal(data, &resp); err == nil {
					cached = true
					cacheHits++
					slog.Debug("graphql: result cache hit", "query_index", i)
				}
			}
		}

		if !cached {
			queryResp, err := t.processSingleQuery(r, req)
			if err != nil {
				resp = &Response{Errors: []interface{}{map[string]interface{}{
					"message":    err.Error(),
					"extensions": map[string]string{"code": "EXECUTION_ERROR"},
				}}}
			} else {
				body, err := io.ReadAll(queryResp.Body)
				queryResp.Body.Close()
				if err != nil {
					resp = &Response{Errors: []interface{}{map[string]interface{}{
						"message":    "Failed to read response",
						"extensions": map[string]string{"code": "INTERNAL_ERROR"},
					}}}
				} else if err := json.Unmarshal(body, &resp); err != nil {
					resp = &Response{Errors: []interface{}{map[string]interface{}{
						"message":    "Invalid response format",
						"extensions": map[string]string{"code": "INVALID_RESPONSE"},
					}}}
				} else if h.cfg.EnableResultCaching && h.resultCache != nil && resp.Errors == nil {
					key := generateCacheKey(req.Query, req.Variables)
					if data, err := json.Marshal(resp); err == nil {
						h.resultCache.Set(key, data)
					}
				}
			}
		}

		if h.cfg.EnableOptimizationHints {
			hints := map[string]interface{}{"cached": cached, "query_index": i}
			if dedupCount > 0 {
				hints["deduplicated"] = true
			}
			addOptimizationHints(resp, hints)
		}

		responses = append(responses, resp)
	}

	if len(indexMap) > 0 && len(indexMap) != len(responses) {
		responses = expandBatchResponse(responses, indexMap)
	}

	batchBody, err := json.Marshal(responses)
	if err != nil {
		return errorResponse(r, "Failed to marshal batch response", "INTERNAL_ERROR", http.StatusInternalServerError)
	}

	dur := time.Since(start)
	slog.Info("graphql: batch processed",
		"total_queries", len(requests),
		"deduplicated", len(deduplicated),
		"cache_hits", cacheHits,
		"duration_ms", dur.Milliseconds())

	metric.GraphQLBatchSize(configID, len(requests), len(deduplicated))
	if cacheHits > 0 {
		metric.GraphQLCacheHit(configID, cacheHits)
	}

	return &http.Response{
		Status:        http.StatusText(http.StatusOK),
		StatusCode:    http.StatusOK,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(string(batchBody))),
		ContentLength: int64(len(batchBody)),
		Request:       r,
	}, nil
}

func (t *graphqlTransport) processSingleQuery(r *http.Request, req *Request) (*http.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return errorResponse(r, "Failed to marshal request", "INTERNAL_ERROR", http.StatusInternalServerError)
	}
	single := r.Clone(r.Context())
	single.Body = io.NopCloser(bytes.NewReader(body))
	single.ContentLength = int64(len(body))
	single.Header.Set("Content-Length", strconv.Itoa(len(body)))

	// Temporarily disable batching.
	orig := t.handler.cfg.EnableQueryBatching
	t.handler.cfg.EnableQueryBatching = false
	defer func() { t.handler.cfg.EnableQueryBatching = orig }()

	return t.RoundTrip(single)
}

func deduplicateQueries(requests []*Request) ([]*Request, []int, map[int]int) {
	seen := make(map[string]int)
	dedup := make([]*Request, 0)
	indices := make([]int, 0)
	indexMap := make(map[int]int)

	for i, req := range requests {
		key := generateCacheKey(req.Query, req.Variables)
		if idx, exists := seen[key]; exists {
			indexMap[i] = idx
		} else {
			seen[key] = len(dedup)
			indexMap[i] = len(dedup)
			dedup = append(dedup, req)
			indices = append(indices, i)
		}
	}
	return dedup, indices, indexMap
}

func expandBatchResponse(batch []*Response, indexMap map[int]int) []*Response {
	if len(indexMap) == 0 {
		return batch
	}
	expanded := make([]*Response, len(indexMap))
	for orig, dedup := range indexMap {
		if dedup < len(batch) {
			expanded[orig] = batch[dedup]
		}
	}
	return expanded
}

func generateCacheKey(query string, variables map[string]interface{}) string {
	h := sha256.New()
	h.Write([]byte(query))
	if len(variables) > 0 {
		keys := make([]string, 0, len(variables))
		for k := range variables {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			if v, err := json.Marshal(variables[k]); err == nil {
				h.Write(v)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func addOptimizationHints(resp *Response, hints map[string]interface{}) {
	if resp == nil {
		return
	}
	if resp.Extensions == nil {
		resp.Extensions = make(map[string]interface{})
	}
	if resp.Extensions["optimization"] == nil {
		resp.Extensions["optimization"] = make(map[string]interface{})
	}
	opt := resp.Extensions["optimization"].(map[string]interface{})
	for k, v := range hints {
		opt[k] = v
	}
}

// -- APQ cache ----------------------------------------------------------------

type apqCache struct {
	cache   map[string]*apqEntry
	maxSize int
	mu      sync.RWMutex
}

type apqEntry struct {
	query      string
	lastAccess time.Time
}

func newAPQCache(size int) *apqCache {
	c := &apqCache{cache: make(map[string]*apqEntry), maxSize: size}
	go c.cleanupLoop()
	return c
}

func (c *apqCache) Get(hash string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[hash]
	if !ok {
		return "", false
	}
	e.lastAccess = time.Now()
	return e.query, true
}

func (c *apqCache) Set(hash, query string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}
	c.cache[hash] = &apqEntry{query: query, lastAccess: time.Now()}
}

func (c *apqCache) evictOldest() {
	var oldest string
	var oldestTime time.Time
	first := true
	for h, e := range c.cache {
		if first || e.lastAccess.Before(oldestTime) {
			oldest = h
			oldestTime = e.lastAccess
			first = false
		}
	}
	if oldest != "" {
		delete(c.cache, oldest)
	}
}

func (c *apqCache) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-1 * time.Hour)
		c.mu.Lock()
		for h, e := range c.cache {
			if e.lastAccess.Before(cutoff) {
				delete(c.cache, h)
			}
		}
		c.mu.Unlock()
	}
}

func validateAPQHash(query, provided string) bool {
	h := sha256.New()
	h.Write([]byte(query))
	return hex.EncodeToString(h.Sum(nil)) == provided
}

// -- Result cache -------------------------------------------------------------

type resultCache struct {
	cache   map[string]*cachedResult
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

type cachedResult struct {
	data      []byte
	cached    time.Time
	expiresAt time.Time
}

func newResultCache(size int, ttl time.Duration) *resultCache {
	c := &resultCache{cache: make(map[string]*cachedResult), maxSize: size, ttl: ttl}
	go c.cleanupLoop()
	return c
}

func (c *resultCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.cache[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.data, true
}

func (c *resultCache) Set(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}
	c.cache[key] = &cachedResult{data: data, cached: time.Now(), expiresAt: time.Now().Add(c.ttl)}
}

func (c *resultCache) evictOldest() {
	var oldest string
	var oldestTime time.Time
	first := true
	for k, e := range c.cache {
		if first || e.cached.Before(oldestTime) {
			oldest = k
			oldestTime = e.cached
			first = false
		}
	}
	if oldest != "" {
		delete(c.cache, oldest)
	}
}

func (c *resultCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.cache {
			if now.After(e.expiresAt) {
				delete(c.cache, k)
			}
		}
		c.mu.Unlock()
	}
}

// -- Field rate limiter -------------------------------------------------------

type fieldRateLimiter struct {
	limits    map[string]*FieldRateLimit
	usage     map[string]*fieldUsage
	mu        sync.RWMutex
	cleanupCh chan struct{}
}

type fieldUsage struct {
	minuteCounter int
	hourCounter   int
	minuteReset   time.Time
	hourReset     time.Time
	mu            sync.RWMutex
}

func newFieldRateLimiter(limits map[string]*FieldRateLimit) *fieldRateLimiter {
	rl := &fieldRateLimiter{
		limits:    limits,
		usage:     make(map[string]*fieldUsage),
		cleanupCh: make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *fieldRateLimiter) checkField(name string) error {
	limit, ok := rl.limits[name]
	if !ok {
		return nil
	}
	rl.mu.Lock()
	usage, ok := rl.usage[name]
	if !ok {
		usage = &fieldUsage{
			minuteReset: time.Now().Add(time.Minute),
			hourReset:   time.Now().Add(time.Hour),
		}
		rl.usage[name] = usage
	}
	rl.mu.Unlock()

	usage.mu.Lock()
	defer usage.mu.Unlock()

	now := time.Now()
	if now.After(usage.minuteReset) {
		usage.minuteCounter = 0
		usage.minuteReset = now.Add(time.Minute)
	}
	if now.After(usage.hourReset) {
		usage.hourCounter = 0
		usage.hourReset = now.Add(time.Hour)
	}
	if limit.RequestsPerMinute > 0 && usage.minuteCounter >= limit.RequestsPerMinute {
		return fmt.Errorf("rate limit exceeded for field '%s': %d requests per minute", name, limit.RequestsPerMinute)
	}
	if limit.RequestsPerHour > 0 && usage.hourCounter >= limit.RequestsPerHour {
		return fmt.Errorf("rate limit exceeded for field '%s': %d requests per hour", name, limit.RequestsPerHour)
	}
	usage.minuteCounter++
	usage.hourCounter++
	return nil
}

func (rl *fieldRateLimiter) checkFields(fields []string) error {
	for _, f := range fields {
		if err := rl.checkField(f); err != nil {
			return err
		}
	}
	return nil
}

func (rl *fieldRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for name, usage := range rl.usage {
				usage.mu.RLock()
				if now.After(usage.minuteReset) && now.After(usage.hourReset) &&
					usage.minuteCounter == 0 && usage.hourCounter == 0 {
					delete(rl.usage, name)
				}
				usage.mu.RUnlock()
			}
			rl.mu.Unlock()
		case <-rl.cleanupCh:
			return
		}
	}
}

// Close releases resources held by the fieldRateLimiter.
func (rl *fieldRateLimiter) Close() { close(rl.cleanupCh) }

// -- Operation rate limiter ---------------------------------------------------

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

func (orl *operationRateLimiter) check(opType string) error {
	limit, ok := orl.limits[opType]
	if !ok {
		return nil
	}
	orl.mu.Lock()
	defer orl.mu.Unlock()

	counter := orl.counters[opType]
	now := time.Now()

	if now.After(counter.minuteReset) {
		counter.minuteCount = 0
		counter.minuteReset = now.Add(time.Minute)
	}
	if now.After(counter.hourReset) {
		counter.hourCount = 0
		counter.hourReset = now.Add(time.Hour)
	}
	if limit.RequestsPerMinute > 0 && counter.minuteCount >= limit.RequestsPerMinute {
		return fmt.Errorf("graphql: %s rate limit exceeded (%d/min)", opType, limit.RequestsPerMinute)
	}
	if limit.RequestsPerHour > 0 && counter.hourCount >= limit.RequestsPerHour {
		return fmt.Errorf("graphql: %s rate limit exceeded (%d/hr)", opType, limit.RequestsPerHour)
	}
	counter.minuteCount++
	counter.hourCount++
	return nil
}

// ensure errQueryTooDeep and friends are referenced to avoid unused var error.
var _ = errQueryTooDeep
var _ = errQueryTooComplex
var _ = errQueryTooCostly
var _ = errInvalidQuery
var _ = errIntrospectionDisabled
var _ = errTooManyAliases
var _ = errFieldRateLimited
