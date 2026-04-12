// Package reqctx defines per-request context data passed through the middleware pipeline.
//
// RequestData lifecycle:
//  1. Pool: NewRequestData() acquires from sync.Pool to avoid per-request allocation.
//  2. Populate: The FastPath middleware creates it, enrichers and config loader fill it.
//  3. Use: All middleware and action handlers read/write via GetRequestData(ctx).
//  4. Release: RequestDataPool.Put() returns it to the pool after the request completes.
package reqctx

import (
	"context"
	"time"
)

// GetRequestData returns the request data.
func GetRequestData(ctx context.Context) *RequestData {
	if val, ok := ctx.Value(RequestDataKey).(*RequestData); ok {
		return val
	}
	return nil
}

// SetRequestData performs the set request data operation.
func SetRequestData(ctx context.Context, requestData *RequestData) context.Context {
	return context.WithValue(ctx, RequestDataKey, requestData)
}

// NewRequestData creates and initializes a new RequestData.
func NewRequestData() *RequestData {
	rd := RequestDataPool.Get().(*RequestData)
	if rd.Config == nil {
		rd.Config = make(map[string]any)
	}
	if rd.Secrets == nil {
		rd.Secrets = make(map[string]string)
	}
	rd.StartTime = time.Now()
	return rd
}

// RecordPolicyViolation sets error fields on RequestData for request logging.
// Call this before writing the error HTTP response so the request logger captures it.
func RecordPolicyViolation(ctx context.Context, errorType, errorMsg string) {
	if rd := GetRequestData(ctx); rd != nil {
		rd.Error = errorMsg
		rd.ErrorType = errorType
	}
}

// GetRequestID returns the request ID from the context
func GetRequestID(ctx context.Context) string {
	requestData := GetRequestData(ctx)
	if requestData != nil {
		return requestData.ID
	}
	return ""
}

// SetRequestID sets the request ID in the context
func SetRequestID(ctx context.Context, requestID string) context.Context {
	requestData := GetRequestData(ctx)
	if requestData == nil {
		requestData = NewRequestData()
	}
	requestData.ID = requestID
	return SetRequestData(ctx, requestData)
}
