// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"net/url"
	"sort"
	"strings"
)

// SortURLParams sort URLs in order
// Optimized to parse query string only once
func SortURLParams(URL *url.URL) *url.URL {
	result := new(url.URL)
	*result = *URL

	// Parse query string only once
	query := URL.Query()
	if len(query) == 0 {
		result.RawQuery = ""
		return result
	}

	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Pre-allocate buffer for better performance
	var buf strings.Builder
	buf.Grow(len(URL.RawQuery))

	for _, key := range keys {
		values := query[key]
		sort.Strings(values)
		for _, value := range values {
			// Skip empty values
			if value == "" {
				continue
			}
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(key)
			buf.WriteByte('=')
			buf.WriteString(value)
		}
	}
	result.RawQuery = buf.String()
	return result
}
