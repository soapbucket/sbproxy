// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	json "github.com/goccy/go-json"
	"net/http"
	"strconv"
	"strings"
)

// sbHeaderPrefix is the prefix for all SoapBucket-specific request headers.
const sbHeaderPrefix = "X-Sb-"

// RequestHeaderControls holds per-request overrides parsed from X-SB-* headers.
// These allow SDK users to control caching, logging, and metadata on a
// per-request basis without modifying the JSON body.
type RequestHeaderControls struct {
	// CacheTTL overrides the cache TTL for this request (seconds). Zero means
	// use the default; negative means skip cache.
	CacheTTL int

	// SkipCache disables cache lookup and storage for this request.
	SkipCache bool

	// SkipLog disables event logging for this request.
	SkipLog bool

	// Metadata is arbitrary key-value data attached to the request for
	// analytics and debugging. Parsed from the X-SB-Metadata header (JSON).
	Metadata map[string]string

	// Tags are labels attached to the request, parsed from the X-SB-Tags
	// header (comma-separated key=value pairs).
	Tags map[string]string
}

// ParseRequestHeaders extracts RequestHeaderControls from the incoming HTTP
// headers. Missing or unparseable headers are silently ignored, leaving the
// corresponding field at its zero value.
func ParseRequestHeaders(h http.Header) *RequestHeaderControls {
	ctrl := &RequestHeaderControls{}

	if v := h.Get("X-SB-Cache-TTL"); v != "" {
		if ttl, err := strconv.Atoi(v); err == nil {
			ctrl.CacheTTL = ttl
		}
	}

	if v := h.Get("X-SB-Skip-Cache"); v != "" {
		ctrl.SkipCache = parseBool(v)
	}

	if v := h.Get("X-SB-Skip-Log"); v != "" {
		ctrl.SkipLog = parseBool(v)
	}

	if v := h.Get("X-SB-Metadata"); v != "" {
		var meta map[string]string
		if err := json.Unmarshal([]byte(v), &meta); err == nil {
			ctrl.Metadata = meta
		}
	}

	if v := h.Get("X-SB-Tags"); v != "" {
		ctrl.Tags = parseTagsHeader(v)
	}

	return ctrl
}

// MergeTags merges header-based tags into the request body tags. Header tags
// take precedence over body tags when keys conflict.
func (c *RequestHeaderControls) MergeTags(req *ChatCompletionRequest) {
	if len(c.Tags) == 0 {
		return
	}
	if req.SBTags == nil {
		req.SBTags = make(map[string]string, len(c.Tags))
	}
	for k, v := range c.Tags {
		req.SBTags[k] = v
	}
}

// ApplyCacheControl updates the request's SBCacheControl based on header
// overrides. If the request already has cache control set in the body, header
// values override individual fields.
func (c *RequestHeaderControls) ApplyCacheControl(req *ChatCompletionRequest) {
	if !c.SkipCache && c.CacheTTL == 0 {
		return
	}
	if req.SBCacheControl == nil {
		req.SBCacheControl = &CacheControl{}
	}
	if c.SkipCache {
		req.SBCacheControl.NoCache = true
	}
	if c.CacheTTL != 0 {
		req.SBCacheControl.TTLSeconds = &c.CacheTTL
	}
}

// StripSBHeaders removes all X-SB-* headers from the request so they are not
// forwarded to the upstream provider.
func StripSBHeaders(h http.Header) {
	toDelete := make([]string, 0)
	for name := range h {
		if strings.HasPrefix(strings.ToUpper(name), strings.ToUpper(sbHeaderPrefix)) {
			toDelete = append(toDelete, name)
		}
	}
	for _, name := range toDelete {
		h.Del(name)
	}
}

// parseBool interprets common truthy string values.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// parseTagsHeader parses a comma-separated list of key=value pairs.
// Entries without an "=" are treated as keys with an empty value.
func parseTagsHeader(s string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			key := strings.TrimSpace(part[:idx])
			val := strings.TrimSpace(part[idx+1:])
			if key != "" {
				tags[key] = val
			}
		} else {
			tags[part] = ""
		}
	}
	return tags
}
