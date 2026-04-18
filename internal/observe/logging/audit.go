// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"time"

	"go.uber.org/zap"
)

// AuditSource identifies what triggered a config change.
type AuditSource string

const (
	// AuditSourceFileWatch indicates a config change detected by the file watcher.
	AuditSourceFileWatch AuditSource = "file_watcher"
	// AuditSourceAPI indicates a config change pushed via the management API.
	AuditSourceAPI AuditSource = "api"
	// AuditSourceMesh indicates a config change received from mesh broadcast.
	AuditSourceMesh AuditSource = "mesh_broadcast"
	// AuditSourceStartup indicates the initial config load at startup.
	AuditSourceStartup AuditSource = "startup"
)

// LogConfigReload logs a config reload event with structured fields describing
// what changed. It writes to the application logger so that audit entries are
// captured alongside other operational logs.
func LogConfigReload(source AuditSource, changedFields []string, originsAdded, originsRemoved int) {
	logger := GetZapApplicationLogger()
	if logger == nil {
		return
	}

	fields := []zap.Field{
		zap.String("audit_event", "config_reloaded"),
		zap.String("source", string(source)),
		zap.Strings("changed_fields", changedFields),
		zap.Int("origins_added", originsAdded),
		zap.Int("origins_removed", originsRemoved),
		zap.String("timestamp", time.Now().UTC().Format(time.RFC3339)),
	}

	logger.Info("config reloaded", fields...)
}
