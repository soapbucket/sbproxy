// Package limits provides rate limiting, concurrency control, and failure
// policies for AI requests in the sbproxy AI gateway.
//
// # Model Rate Limiting
//
// [ModelRateLimiter] enforces per-model RPM (requests per minute) and TPM
// (tokens per minute) quotas using distributed counters backed by
// [cacher.Cacher]. Feature flag overrides allow dynamic RPM adjustment
// without config reload.
//
// # Concurrency Limiting
//
// [ConcurrencyLimiter] implements a distributed semaphore that caps the
// number of in-flight AI requests per provider. Counter keys have a TTL
// so that slots auto-recover if a process crashes without calling Release
// (crash recovery). The limiter fails open on cache errors to avoid
// blocking all requests when the cache is unavailable.
//
// # Failure Policy
//
// [FailurePolicy] determines whether a request should proceed (fail-open)
// or be rejected (fail-closed) when a subsystem encounters an error.
// Per-subsystem overrides allow safety-critical subsystems like budget
// enforcement and guardrails to fail closed while non-critical subsystems
// like rate limiting fail open. The default when no policy is configured
// is fail-open, because rejecting all requests on a transient cache error
// is worse than briefly exceeding a rate limit.
package limits
