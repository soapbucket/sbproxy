// Package response provides AI response processing utilities for the
// sbproxy AI gateway, including fake streaming and spend metrics.
//
// When a client requests streaming (stream=true) but the upstream provider
// only supports synchronous responses, this package converts the complete
// response into SSE-formatted chunks delivered at a configurable pace
// to simulate a streaming experience.
//
// The fake streamer uses [time.NewTicker] for pacing rather than
// time.Sleep to avoid goroutine scheduling jitter and ensure consistent
// chunk intervals. The sb_metadata field (usage, cost, latency) is
// attached to the final SSE chunk so that clients receive observability
// data in the same format as real streaming responses.
package response
