// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/graphql-go/graphql/language/ast"
)

const (
	// DefaultAPQCacheSize is the default value for apq cache size.
	DefaultAPQCacheSize      = 10000
	// DefaultFieldCost is the default value for field cost.
	DefaultFieldCost         = 1
	// DefaultListFieldCost is the default value for list field cost.
	DefaultListFieldCost     = 10
	// DefaultMutationCost is the default value for mutation cost.
	DefaultMutationCost      = 5
	// DefaultSubscriptionCost is the default value for subscription cost.
	DefaultSubscriptionCost  = 10
)

// APQ constants per Apollo spec
const (
	// APQVersion is a constant for apq version.
	APQVersion              = 1
	// APQExtensionKey is a constant for apq extension key.
	APQExtensionKey         = "persistedQuery"
	// APQVersionKey is a constant for apq version key.
	APQVersionKey           = "version"
	// APQSHA256HashKey is a constant for apqsha256 hash key.
	APQSHA256HashKey        = "sha256Hash"
	// APQErrorCodeKey is a constant for apq error code key.
	APQErrorCodeKey         = "code"
	// APQErrorCodeNotFound is a constant for apq error code not found.
	APQErrorCodeNotFound    = "PERSISTED_QUERY_NOT_FOUND"
	// APQErrorCodeNotSupported is a constant for apq error code not supported.
	APQErrorCodeNotSupported = "PERSISTED_QUERY_NOT_SUPPORTED"
)

// apqCache implements Automatic Persisted Queries (APQ) per Apollo spec
// Simple LRU cache implementation
type apqCache struct {
	cache   map[string]*apqEntry
	maxSize int
	mu      sync.RWMutex
}

type apqEntry struct {
	query      string
	lastAccess time.Time
}

func newAPQCache(size int) (*apqCache, error) {
	if size == 0 {
		size = DefaultAPQCacheSize
	}
	
	c := &apqCache{
		cache:   make(map[string]*apqEntry),
		maxSize: size,
	}
	
	// Start cleanup goroutine
	go c.cleanupLoop()
	
	return c, nil
}

// Get retrieves a value from the apqCache.
func (c *apqCache) Get(hash string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry, exists := c.cache[hash]
	if !exists {
		return "", false
	}
	
	// Update last access time
	entry.lastAccess = time.Now()
	return entry.query, true
}

// Set stores a value in the apqCache.
func (c *apqCache) Set(hash, query string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Evict oldest entries if cache is full
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}
	
	c.cache[hash] = &apqEntry{
		query:      query,
		lastAccess: time.Now(),
	}
}

func (c *apqCache) evictOldest() {
	// Find and remove the oldest entry
	var oldestHash string
	var oldestTime time.Time
	first := true
	
	for hash, entry := range c.cache {
		if first || entry.lastAccess.Before(oldestTime) {
			oldestHash = hash
			oldestTime = entry.lastAccess
			first = false
		}
	}
	
	if oldestHash != "" {
		delete(c.cache, oldestHash)
	}
}

func (c *apqCache) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.cleanup()
	}
}

func (c *apqCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Remove entries not accessed in the last hour
	cutoff := time.Now().Add(-1 * time.Hour)
	for hash, entry := range c.cache {
		if entry.lastAccess.Before(cutoff) {
			delete(c.cache, hash)
		}
	}
}

// validateAPQHash validates that the provided hash matches the query
func validateAPQHash(query, providedHash string) bool {
	h := sha256.New()
	h.Write([]byte(query))
	computed := hex.EncodeToString(h.Sum(nil))
	return computed == providedHash
}

// fieldRateLimiter implements field-level rate limiting for GraphQL
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
	
	// Start cleanup goroutine
	go rl.cleanupLoop()
	
	return rl
}

func (rl *fieldRateLimiter) checkField(fieldName string) error {
	limit, exists := rl.limits[fieldName]
	if !exists {
		return nil // No limit configured for this field
	}
	
	rl.mu.Lock()
	usage, exists := rl.usage[fieldName]
	if !exists {
		usage = &fieldUsage{
			minuteReset: time.Now().Add(time.Minute),
			hourReset:   time.Now().Add(time.Hour),
		}
		rl.usage[fieldName] = usage
	}
	rl.mu.Unlock()
	
	usage.mu.Lock()
	defer usage.mu.Unlock()
	
	now := time.Now()
	
	// Reset minute counter if needed
	if now.After(usage.minuteReset) {
		usage.minuteCounter = 0
		usage.minuteReset = now.Add(time.Minute)
	}
	
	// Reset hour counter if needed
	if now.After(usage.hourReset) {
		usage.hourCounter = 0
		usage.hourReset = now.Add(time.Hour)
	}
	
	// Check limits
	if limit.RequestsPerMinute > 0 && usage.minuteCounter >= limit.RequestsPerMinute {
		return fmt.Errorf("rate limit exceeded for field '%s': %d requests per minute", fieldName, limit.RequestsPerMinute)
	}
	
	if limit.RequestsPerHour > 0 && usage.hourCounter >= limit.RequestsPerHour {
		return fmt.Errorf("rate limit exceeded for field '%s': %d requests per hour", fieldName, limit.RequestsPerHour)
	}
	
	// Increment counters
	usage.minuteCounter++
	usage.hourCounter++
	
	return nil
}

func (rl *fieldRateLimiter) checkFields(fields []string) error {
	for _, field := range fields {
		if err := rl.checkField(field); err != nil {
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
			rl.cleanup()
		case <-rl.cleanupCh:
			return
		}
	}
}

func (rl *fieldRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	for field, usage := range rl.usage {
		usage.mu.RLock()
		// Remove if both counters are expired and zero
		if now.After(usage.minuteReset) && now.After(usage.hourReset) && 
		   usage.minuteCounter == 0 && usage.hourCounter == 0 {
			delete(rl.usage, field)
		}
		usage.mu.RUnlock()
	}
}

// Close releases resources held by the fieldRateLimiter.
func (rl *fieldRateLimiter) Close() {
	close(rl.cleanupCh)
}

// extractFields extracts all field names from a GraphQL document
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

func extractFieldsFromSelection(selectionSet *ast.SelectionSet, fields *[]string, seen map[string]bool) {
	if selectionSet == nil {
		return
	}
	
	for _, sel := range selectionSet.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			fieldName := s.Name.Value
			if !seen[fieldName] {
				*fields = append(*fields, fieldName)
				seen[fieldName] = true
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

// calculateAliases counts the total number of aliased fields in a GraphQL document.
// An alias is when a field is requested under a different name, e.g. "myUser: user { id }".
// Attackers can use aliases to amplify queries, so limiting them is a security measure.
func (c *GraphQLAction) calculateAliases(doc *ast.Document) int {
	count := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			count += countAliasesInSelection(op.SelectionSet)
		}
	}
	return count
}

// countAliasesInSelection recursively counts aliased fields in a selection set.
func countAliasesInSelection(selectionSet *ast.SelectionSet) int {
	if selectionSet == nil || len(selectionSet.Selections) == 0 {
		return 0
	}

	count := 0
	for _, sel := range selectionSet.Selections {
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

// calculateCost calculates query cost with custom field and type costs
func (c *GraphQLAction) calculateCost(doc *ast.Document) int {
	cost := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			// Base cost for operation type
			switch op.Operation {
			case ast.OperationTypeMutation:
				cost += DefaultMutationCost
			case ast.OperationTypeSubscription:
				cost += DefaultSubscriptionCost
			}
			
			cost += c.calculateSelectionCost(op.SelectionSet, 1)
		}
	}
	return cost
}

func (c *GraphQLAction) calculateSelectionCost(selectionSet *ast.SelectionSet, depth int) int {
	if selectionSet == nil || len(selectionSet.Selections) == 0 {
		return 0
	}
	
	cost := 0
	for _, sel := range selectionSet.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			fieldName := s.Name.Value
			
			// Get custom field cost if configured
			fieldCost := DefaultFieldCost
			if customCost, exists := c.FieldCosts[fieldName]; exists {
				fieldCost = customCost
			} else if c.isListField(s) {
				fieldCost = DefaultListFieldCost
			}
			
			// Apply depth multiplier
			fieldCost *= depth
			
			// Check for list arguments (pagination)
			if args := s.Arguments; args != nil {
				for _, arg := range args {
					argName := strings.ToLower(arg.Name.Value)
					if argName == "first" || argName == "last" || argName == "limit" {
						if lit, ok := arg.Value.(*ast.IntValue); ok {
							// Multiply cost by list size
							fieldCost *= parseIntValue(lit.Value, 10)
						}
					}
				}
			}
			
			// Recursive cost for nested selections
			if s.SelectionSet != nil {
				nestedCost := c.calculateSelectionCost(s.SelectionSet, depth+1)
				fieldCost += nestedCost
			}
			
			cost += fieldCost
			
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				cost += c.calculateSelectionCost(s.SelectionSet, depth)
			}
			
		case *ast.FragmentSpread:
			// Base cost for fragment
			cost += 5 * depth
		}
	}
	
	return cost
}

func parseIntValue(val string, defaultVal int) int {
	var result int
	if _, err := fmt.Sscanf(val, "%d", &result); err != nil {
		return defaultVal
	}
	if result <= 0 {
		return defaultVal
	}
	return result
}

// logQueryAnalytics logs query analytics for monitoring
func (c *GraphQLAction) logQueryAnalytics(operationName string, depth, complexity, cost int, duration time.Duration) {
	slog.Info("graphql: query executed",
		"operation", operationName,
		"depth", depth,
		"complexity", complexity,
		"cost", cost,
		"duration_ms", duration.Milliseconds(),
		"max_depth", c.MaxDepth,
		"max_complexity", c.MaxComplexity,
		"max_cost", c.MaxCost,
	)
}

