// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"github.com/soapbucket/sbproxy/internal/observe/metric"

	"go.uber.org/zap/zapcore"
)

// metricsCore wraps a zapcore.Core to record log volume metrics.
type metricsCore struct {
	zapcore.Core
}

// With performs the with operation on the metricsCore.
func (c *metricsCore) With(fields []zapcore.Field) zapcore.Core {
	return &metricsCore{Core: c.Core.With(fields)}
}

// Check performs the check operation on the metricsCore.
func (c *metricsCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Core.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

// Write performs the write operation on the metricsCore.
func (c *metricsCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	logLevel := entry.Level.String()
	origin := "unknown"
	workspaceID := "unknown"

	for _, f := range fields {
		switch f.Key {
		case "origin_id", "config_id":
			if f.String != "" {
				origin = f.String
			}
		case "workspace_id":
			if f.String != "" {
				workspaceID = f.String
			}
		}
	}

	metric.LogVolume(logLevel, workspaceID, origin)
	return c.Core.Write(entry, fields)
}

// Sync performs the sync operation on the metricsCore.
func (c *metricsCore) Sync() error {
	return c.Core.Sync()
}
