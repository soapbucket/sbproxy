// Package requestdata builds and propagates per-request metadata through the proxy pipeline.
package requestdata

import (
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ParseRequestID parses and returns request id from the input.
func ParseRequestID(requestID string) (string, int, error) {
	parts := strings.Split(requestID, ":")

	if len(parts) != 2 {
		return "", 0, ErrInvalidRequestID
	}

	level, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, ErrInvalidRequestID
	}

	return parts[0], level, nil
}

// NewRequestData is a compatibility helper that returns a pooled RequestData
func NewRequestData(id string, depth int) *reqctx.RequestData {
	rd := reqctx.NewRequestData()
	rd.ID = id
	rd.Depth = depth
	return rd
}
