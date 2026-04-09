// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-viper/mapstructure/v2"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/spf13/viper"
)

// ReloadManager handles configuration hot reload
type ReloadManager struct {
	configDir      string
	configFile     string
	watcher        *fsnotify.Watcher
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.RWMutex
	lastReloadTime time.Time
	reloadCount    uint64
}

// NewReloadManager creates a new reload manager
func NewReloadManager(ctx context.Context, configDir, configFile string) (*ReloadManager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithCancel(ctx)

	rm := &ReloadManager{
		configDir:      configDir,
		configFile:     configFile,
		watcher:        watcher,
		ctx:            childCtx,
		cancel:         cancel,
		lastReloadTime: time.Now(),
	}

	return rm, nil
}

// Start begins watching for configuration changes
func (rm *ReloadManager) Start() error {
	// Determine the actual config file path to watch
	watchPath := rm.getConfigFilePath()
	if watchPath == "" {
		slog.Warn("no configuration file to watch for hot reload")
		// Still start signal handling even if no file to watch
		go rm.handleSignals()
		return nil
	}

	// Watch the directory containing the config file
	// (watching directories is more reliable than watching files)
	watchDir := filepath.Dir(watchPath)
	if err := rm.watcher.Add(watchDir); err != nil {
		slog.Error("failed to watch config directory", "error", err, "path", watchDir)
		return err
	}

	slog.Info("configuration hot reload enabled",
		"config_file", watchPath,
		"watch_dir", watchDir,
		"supports", "log_level, and future config options")

	// Start watching for file changes
	go rm.watchConfigFile(watchPath)

	// Start watching for signals
	go rm.handleSignals()

	return nil
}

// Stop stops the reload manager
func (rm *ReloadManager) Stop() {
	if rm.cancel != nil {
		rm.cancel()
	}
	if rm.watcher != nil {
		rm.watcher.Close()
	}
	slog.Info("configuration hot reload stopped")
}

// getConfigFilePath returns the actual config file path being used
func (rm *ReloadManager) getConfigFilePath() string {
	// Try to get the config file from viper
	configFile := viper.ConfigFileUsed()
	if configFile != "" {
		return configFile
	}

	// If not set in viper, construct from configDir and configFile
	if rm.configFile != "" {
		if filepath.IsAbs(rm.configFile) {
			return rm.configFile
		}
		return filepath.Join(rm.configDir, rm.configFile)
	}

	// Try common config file names in the config directory
	commonNames := []string{"sb.yaml", "sb.yml", "sb.json", "sb.toml"}
	for _, name := range commonNames {
		path := filepath.Join(rm.configDir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// watchConfigFile watches for changes to the configuration file
func (rm *ReloadManager) watchConfigFile(configPath string) {
	// Debounce timer to avoid multiple reloads for a single change
	var debounceTimer *time.Timer
	debounceDuration := 500 * time.Millisecond

	for {
		select {
		case <-rm.ctx.Done():
			return

		case event, ok := <-rm.watcher.Events:
			if !ok {
				return
			}

			// Check if this event is for our config file
			// We need to check the base name because editors may use temp files
			eventBase := filepath.Base(event.Name)
			configBase := filepath.Base(configPath)

			if eventBase != configBase {
				continue
			}

			// Only handle Write and Create events
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				slog.Debug("config file change detected", "file", event.Name, "op", event.Op.String())

				// Reset debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(debounceDuration, func() {
					rm.reloadConfiguration()
				})
			}

		case err, ok := <-rm.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("config file watcher error", "error", err)
			metric.ConfigError("reload", "watcher_error")
		}
	}
}

// handleSignals watches for SIGHUP to manually trigger reload
func (rm *ReloadManager) handleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	for {
		select {
		case <-rm.ctx.Done():
			signal.Stop(sigChan)
			return

		case sig := <-sigChan:
			slog.Info("received signal, reloading configuration", "signal", sig.String())
			rm.reloadConfiguration()
		}
	}
}

// reloadConfiguration reloads the configuration from disk
func (rm *ReloadManager) reloadConfiguration() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	startTime := time.Now()
	slog.Info("reloading configuration", "config_dir", rm.configDir, "config_file", rm.configFile)

	// Save current log level for comparison
	oldLevel := logging.GetGlobalLogLevel()

	// Reload configuration using viper
	if err := viper.ReadInConfig(); err != nil {
		slog.Error("failed to reload configuration file", "error", err)
		metric.ConfigError("reload", "read_error")
		return
	}

	// Unmarshal into global config (same decode hooks as initial load)
	if err := viper.Unmarshal(&globalConfig, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToModelsDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	)); err != nil {
		slog.Error("failed to parse reloaded configuration", "error", err)
		metric.ConfigError("reload", "parse_error")
		return
	}

	// Apply log level changes
	if err := rm.applyLogLevelChanges(oldLevel); err != nil {
		slog.Error("failed to apply log level changes", "error", err)
		metric.ConfigError("reload", "apply_error")
	}

	rm.lastReloadTime = time.Now()
	rm.reloadCount++

	duration := time.Since(startTime)
	slog.Info("configuration reloaded successfully",
		"reload_count", rm.reloadCount,
		"duration_ms", duration.Milliseconds())

	// Record successful reload metric
	metric.ConfigReloadWithDuration("success", duration)
	_ = events.Publish(events.SystemEvent{
		Type:      events.EventConfigUpdated,
		Severity:  events.SeverityInfo,
		Timestamp: time.Now(),
		Source:    "service_reload",
		Data: map[string]interface{}{
			"reload_count": rm.reloadCount,
			"duration_ms":  duration.Milliseconds(),
		},
	})
}

// applyLogLevelChanges applies log level changes from the reloaded configuration
func (rm *ReloadManager) applyLogLevelChanges(oldLevel slog.Level) error {
	// Get log level from environment or config
	// Environment variable takes precedence
	logLevelStr := os.Getenv("SB_LOG_LEVEL")
	if logLevelStr == "" {
		// Try to get from viper
		logLevelStr = viper.GetString("log_level")
		if logLevelStr == "" {
			logLevelStr = "info" // default
		}
	}

	// Parse log level string
	var newLevel slog.Level
	switch logLevelStr {
	case "debug":
		newLevel = slog.LevelDebug
	case "info":
		newLevel = slog.LevelInfo
	case "warn":
		newLevel = slog.LevelWarn
	case "error":
		newLevel = slog.LevelError
	default:
		newLevel = slog.LevelInfo
		slog.Warn("invalid log level in config, using info", "level", logLevelStr)
	}

	// Only apply if level changed
	if newLevel != oldLevel {
		logging.SetGlobalLogLevel(newLevel)
		slog.Info("log level changed",
			"old_level", oldLevel.String(),
			"new_level", newLevel.String())
		metric.ConfigChange("log_level", oldLevel.String(), newLevel.String())
	}

	return nil
}

// GetStats returns reload statistics
func (rm *ReloadManager) GetStats() (lastReload time.Time, count uint64) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.lastReloadTime, rm.reloadCount
}
