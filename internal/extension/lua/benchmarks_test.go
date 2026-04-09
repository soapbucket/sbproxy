package lua

import (
	"net/http"
	"testing"
)

// ============================================================================
// Cache Key Generator Benchmarks
// ============================================================================

func BenchmarkCacheKeyGeneratorSimple(b *testing.B) {
	script := `
function generate_cache_key(req, ctx)
  return req.method .. ":" .. req.path
end
`
	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		b.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)
	req.RequestURI = "/api/users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gen.GenerateCacheKey(req)
	}
}

func BenchmarkCacheKeyGeneratorWithContext(b *testing.B) {
	script := `
function generate_cache_key(req, ctx)
  local country = ctx.location and ctx.location.country_code or "US"
  return req.method .. ":" .. req.path .. ":" .. country
end
`
	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		b.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)
	req.RequestURI = "/api/users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gen.GenerateCacheKey(req)
	}
}

func BenchmarkCacheKeyGeneratorComplex(b *testing.B) {
	script := `
function generate_cache_key(req, ctx)
  local key = req.method .. ":" .. req.path
  if req.query and req.query.sort then
    key = key .. ":" .. req.query.sort
  end
  if ctx.location then
    key = key .. ":" .. ctx.location.country_code
  end
  if ctx.user_agent then
    key = key .. ":" .. ctx.user_agent.device_family
  end
  return key
end
`
	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		b.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users?sort=name", nil)
	req.RequestURI = "/api/users?sort=name"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gen.GenerateCacheKey(req)
	}
}

// ============================================================================
// Rate Limit Adjuster Benchmarks
// ============================================================================

func BenchmarkRateLimitAdjusterSimple(b *testing.B) {
	script := `
function adjust_rate_limit(req, ctx)
  return {
    requests_per_minute = 60,
    burst_size = 10
  }
end
`
	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		b.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adj.AdjustRateLimits(req)
	}
}

func BenchmarkRateLimitAdjusterConditional(b *testing.B) {
	script := `
function adjust_rate_limit(req, ctx)
  -- Different limits based on request path
  if string.find(req.path, "/api/premium") then
    return {
      requests_per_minute = 600,
      requests_per_hour = 10000,
      burst_size = 100
    }
  elseif string.find(req.path, "/api") then
    return {
      requests_per_minute = 120,
      requests_per_hour = 5000,
      burst_size = 20
    }
  else
    return {
      requests_per_minute = 60,
      requests_per_hour = 1000,
      burst_size = 10
    }
  end
end
`
	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		b.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adj.AdjustRateLimits(req)
	}
}

func BenchmarkRateLimitAdjusterLocationBased(b *testing.B) {
	script := `
function adjust_rate_limit(req, ctx)
  if not ctx.location then
    return {requests_per_minute = 60, burst_size = 10}
  end

  -- US users get higher limits
  if ctx.location.country_code == "US" then
    return {requests_per_minute = 600, burst_size = 100}
  -- EU users get medium limits
  elseif ctx.location.continent == "EU" then
    return {requests_per_minute = 300, burst_size = 50}
  -- Others get lower limits
  else
    return {requests_per_minute = 120, burst_size = 20}
  end
end
`
	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		b.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adj.AdjustRateLimits(req)
	}
}

// ============================================================================
// Route Matcher Benchmarks
// ============================================================================

func BenchmarkRouteMatcherSimple(b *testing.B) {
	script := `
function select_route(req, ctx)
  return req.method == "GET"
end
`
	m, err := NewRouteMatcher(script)
	if err != nil {
		b.Fatalf("NewRouteMatcher failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(req)
	}
}

func BenchmarkRouteMatcherPathPattern(b *testing.B) {
	script := `
function select_route(req, ctx)
  return req.method == "GET" and string.find(req.path, "/api") ~= nil
end
`
	m, err := NewRouteMatcher(script)
	if err != nil {
		b.Fatalf("NewRouteMatcher failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(req)
	}
}

func BenchmarkRouteMatcherContextBased(b *testing.B) {
	script := `
function select_route(req, ctx)
  -- Only route GET requests from US users to this target
  local is_us = ctx.location and ctx.location.country_code == "US"
  local is_get = req.method == "GET"
  return is_us and is_get
end
`
	m, err := NewRouteMatcher(script)
	if err != nil {
		b.Fatalf("NewRouteMatcher failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(req)
	}
}

func BenchmarkRouteMatcherComplexLogic(b *testing.B) {
	script := `
function select_route(req, ctx)
  -- Route to this target based on multiple conditions
  if req.method ~= "GET" and req.method ~= "HEAD" then
    return false
  end

  local is_api = string.find(req.path, "/api/v2") ~= nil
  if not is_api then
    return false
  end

  local has_auth = ctx.session and ctx.session.is_authenticated
  if not has_auth then
    return false
  end

  -- Check if user is in premium tier
  local is_premium = ctx.session and ctx.session.data and ctx.session.data.tier == "premium"
  return is_premium
end
`
	m, err := NewRouteMatcher(script)
	if err != nil {
		b.Fatalf("NewRouteMatcher failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/v2/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(req)
	}
}

// ============================================================================
// Circuit Breaker Function Benchmarks
// ============================================================================

func BenchmarkCircuitBreakerSimple(b *testing.B) {
	script := `
function should_break_circuit(status, error, ctx)
  return status >= 500
end
`
	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		b.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.ShouldBreak(503, "Service Unavailable", req)
	}
}

func BenchmarkCircuitBreakerWithContext(b *testing.B) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Only break for 5xx errors for non-US users
  local is_us = ctx.location and ctx.location.country_code == "US"
  if is_us then
    return status >= 503  -- More lenient for US
  else
    return status >= 500  -- Stricter for non-US
  end
end
`
	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		b.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.ShouldBreak(500, "Internal Server Error", req)
	}
}

func BenchmarkCircuitBreakerErrorParsing(b *testing.B) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Break on specific error messages
  if error and string.find(error, "timeout", 1, true) then
    return true
  end
  if error and string.find(error, "connection refused", 1, true) then
    return true
  end
  return status >= 500
end
`
	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		b.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.ShouldBreak(500, "read timeout", req)
	}
}

func BenchmarkCircuitBreakerAdvanced(b *testing.B) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Advanced logic: break based on status, error type, and request context

  -- 5xx errors always break
  if status >= 500 then
    return true
  end

  -- Some 4xx errors break depending on context
  if status == 429 then
    -- Rate limited - only break for non-premium users
    local is_premium = ctx.session and ctx.session.data and ctx.session.data.tier == "premium"
    return not is_premium
  end

  if status == 401 or status == 403 then
    -- Auth errors only break for authenticated sessions
    local is_auth = ctx.session and ctx.session.is_authenticated
    return is_auth
  end

  return false
end
`
	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		b.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.ShouldBreak(503, "", req)
	}
}

// ============================================================================
// Comparison Benchmarks (Multiple calls to simulate real usage)
// ============================================================================

func BenchmarkCacheKeyGeneratorVsDefault(b *testing.B) {
	// Simulate the cost of custom cache key generation
	script := `
function generate_cache_key(req, ctx)
  return req.method .. ":" .. req.path .. ":" .. (ctx.location and ctx.location.country_code or "UNKNOWN")
end
`
	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		b.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)

	b.Run("CustomLua", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = gen.GenerateCacheKey(req)
		}
	})

	b.Run("SimpleConcat", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = "GET:/api/users:UNKNOWN"
		}
	})
}

func BenchmarkRateLimitAdjusterVsDefault(b *testing.B) {
	// Simulate the cost of dynamic rate limit adjustment
	script := `
function adjust_rate_limit(req, ctx)
  if string.find(req.path, "/premium") then
    return {requests_per_minute = 600, burst_size = 100}
  else
    return {requests_per_minute = 60, burst_size = 10}
  end
end
`
	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		b.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)

	b.Run("CustomLua", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = adj.AdjustRateLimits(req)
		}
	})

	b.Run("DefaultLookup", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = 60 // simulate simple lookup
		}
	})
}
