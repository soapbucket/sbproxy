// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import "net/http"

// MergeHeader performs the merge header operation.
func MergeHeader(src1, src2 http.Header) http.Header {
	// Pre-allocate with estimated size for better performance
	header := make(http.Header, len(src1)+len(src2))

	// Copy src1 headers
	for key, values := range src1 {
		// Make a copy of the slice to avoid sharing
		header[key] = append([]string(nil), values...)
	}

	// Override/add src2 headers
	for key, values := range src2 {
		header.Del(key)
		for _, value := range values {
			header.Add(key, value)
		}
	}
	return header
}
