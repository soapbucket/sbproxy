// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"go.uber.org/zap"
)

// --- zap AtomicLevel storage ---

var (
	applicationAtomicLevel *zap.AtomicLevel
	requestAtomicLevel     *zap.AtomicLevel
	securityAtomicLevel    *zap.AtomicLevel
	atomicLevelMu          sync.RWMutex
)

// SetApplicationAtomicLevel performs the set application atomic level operation.
func SetApplicationAtomicLevel(level *zap.AtomicLevel) {
	atomicLevelMu.Lock()
	defer atomicLevelMu.Unlock()
	applicationAtomicLevel = level
}

// GetApplicationAtomicLevel returns the application atomic level.
func GetApplicationAtomicLevel() *zap.AtomicLevel {
	atomicLevelMu.RLock()
	defer atomicLevelMu.RUnlock()
	return applicationAtomicLevel
}

// SetRequestAtomicLevel performs the set request atomic level operation.
func SetRequestAtomicLevel(level *zap.AtomicLevel) {
	atomicLevelMu.Lock()
	defer atomicLevelMu.Unlock()
	requestAtomicLevel = level
}

// GetRequestAtomicLevel returns the request atomic level.
func GetRequestAtomicLevel() *zap.AtomicLevel {
	atomicLevelMu.RLock()
	defer atomicLevelMu.RUnlock()
	return requestAtomicLevel
}

// SetSecurityAtomicLevel performs the set security atomic level operation.
func SetSecurityAtomicLevel(level *zap.AtomicLevel) {
	atomicLevelMu.Lock()
	defer atomicLevelMu.Unlock()
	securityAtomicLevel = level
}

// GetSecurityAtomicLevel returns the security atomic level.
func GetSecurityAtomicLevel() *zap.AtomicLevel {
	atomicLevelMu.RLock()
	defer atomicLevelMu.RUnlock()
	return securityAtomicLevel
}

// LogLevelHTTPHandler returns an HTTP handler that supports GET/PUT for
// runtime log level changes via zap's AtomicLevel. Wire this to your
// telemetry router at /log/level.
func LogLevelHTTPHandler() http.Handler {
	level := GetApplicationAtomicLevel()
	if level == nil {
		return http.NotFoundHandler()
	}
	return level
}

// --- backward-compat LevelHandler (slog) ---

// LevelHandler wraps a handler with a dynamic level that can be changed at runtime.
// This is preserved for backward compatibility with existing reload tests.
type LevelHandler struct {
	level   *slog.LevelVar
	handler slog.Handler
}

// NewLevelHandler creates and initializes a new LevelHandler.
func NewLevelHandler(level slog.Level, handler slog.Handler) *LevelHandler {
	var levelVar slog.LevelVar
	levelVar.Set(level)
	return &LevelHandler{
		level:   &levelVar,
		handler: handler,
	}
}

// Enabled performs the enabled operation on the LevelHandler.
func (h *LevelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

// Handle performs the handle operation on the LevelHandler.
func (h *LevelHandler) Handle(ctx context.Context, record slog.Record) error {
	return h.handler.Handle(ctx, record)
}

// WithAttrs performs the with attrs operation on the LevelHandler.
func (h *LevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LevelHandler{
		level:   h.level,
		handler: h.handler.WithAttrs(attrs),
	}
}

// WithGroup performs the with group operation on the LevelHandler.
func (h *LevelHandler) WithGroup(name string) slog.Handler {
	return &LevelHandler{
		level:   h.level,
		handler: h.handler.WithGroup(name),
	}
}

// SetLevel updates the level for the LevelHandler.
func (h *LevelHandler) SetLevel(level slog.Level) {
	h.level.Set(level)
}

// GetLevel returns the level for the LevelHandler.
func (h *LevelHandler) GetLevel() slog.Level {
	return h.level.Level()
}

// --- global level handler storage (backward compat) ---

var (
	applicationLevelHandler *LevelHandler
	requestLevelHandler     *LevelHandler
	securityLevelHandler    *LevelHandler
	levelHandlerMux         sync.RWMutex
)

// SetApplicationLevelHandler performs the set application level handler operation.
func SetApplicationLevelHandler(handler *LevelHandler) {
	levelHandlerMux.Lock()
	defer levelHandlerMux.Unlock()
	applicationLevelHandler = handler
}

// GetApplicationLevelHandler returns the application level handler.
func GetApplicationLevelHandler() *LevelHandler {
	levelHandlerMux.RLock()
	defer levelHandlerMux.RUnlock()
	return applicationLevelHandler
}

// SetRequestLevelHandler performs the set request level handler operation.
func SetRequestLevelHandler(handler *LevelHandler) {
	levelHandlerMux.Lock()
	defer levelHandlerMux.Unlock()
	requestLevelHandler = handler
}

// GetRequestLevelHandler returns the request level handler.
func GetRequestLevelHandler() *LevelHandler {
	levelHandlerMux.RLock()
	defer levelHandlerMux.RUnlock()
	return requestLevelHandler
}

// SetSecurityLevelHandler performs the set security level handler operation.
func SetSecurityLevelHandler(handler *LevelHandler) {
	levelHandlerMux.Lock()
	defer levelHandlerMux.Unlock()
	securityLevelHandler = handler
}

// GetSecurityLevelHandler returns the security level handler.
func GetSecurityLevelHandler() *LevelHandler {
	levelHandlerMux.RLock()
	defer levelHandlerMux.RUnlock()
	return securityLevelHandler
}

// SetGlobalLogLevel changes the log level for all loggers dynamically.
// Updates both zap AtomicLevels and legacy LevelHandlers.
func SetGlobalLogLevel(level slog.Level) {
	zapLevel := ParseZapLevel(zapLevelString(level))

	atomicLevelMu.RLock()
	if applicationAtomicLevel != nil {
		applicationAtomicLevel.SetLevel(zapLevel)
	}
	if requestAtomicLevel != nil {
		requestAtomicLevel.SetLevel(zapLevel)
	}
	if securityAtomicLevel != nil {
		securityAtomicLevel.SetLevel(zapLevel)
	}
	atomicLevelMu.RUnlock()

	levelHandlerMux.RLock()
	defer levelHandlerMux.RUnlock()
	if applicationLevelHandler != nil {
		applicationLevelHandler.SetLevel(level)
	}
	if requestLevelHandler != nil {
		requestLevelHandler.SetLevel(level)
	}
	if securityLevelHandler != nil {
		securityLevelHandler.SetLevel(level)
	}
}

// GetGlobalLogLevel returns the current application log level.
func GetGlobalLogLevel() slog.Level {
	atomicLevelMu.RLock()
	if applicationAtomicLevel != nil {
		level := applicationAtomicLevel.Level()
		atomicLevelMu.RUnlock()
		return slogLevelFromZap(level)
	}
	atomicLevelMu.RUnlock()

	levelHandlerMux.RLock()
	defer levelHandlerMux.RUnlock()
	if applicationLevelHandler != nil {
		return applicationLevelHandler.GetLevel()
	}
	return slog.LevelInfo
}
