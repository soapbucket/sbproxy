// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"

	"github.com/spf13/viper"
)

// Global logger instances for different log types.
// Uses atomic.Pointer to eliminate mutex overhead on the read path
// (logger getters are called on every log statement; setters only on config reload).
var (
	securityLoggerPtr    atomic.Pointer[slog.Logger]
	requestLoggerPtr     atomic.Pointer[slog.Logger]
	applicationLoggerPtr atomic.Pointer[slog.Logger]

	zapSecurityLoggerPtr    atomic.Pointer[zap.Logger]
	zapRequestLoggerPtr     atomic.Pointer[zap.Logger]
	zapApplicationLoggerPtr atomic.Pointer[zap.Logger]
)

// --- slog getters/setters (backward compat) ---

// SetSecurityLogger performs the set security logger operation.
func SetSecurityLogger(logger *slog.Logger) {
	securityLoggerPtr.Store(logger)
}

// GetSecurityLogger returns the security logger.
func GetSecurityLogger() *slog.Logger {
	if l := securityLoggerPtr.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// SetRequestLogger performs the set request logger operation.
func SetRequestLogger(logger *slog.Logger) {
	requestLoggerPtr.Store(logger)
}

// GetRequestLogger returns the request logger.
func GetRequestLogger() *slog.Logger {
	if l := requestLoggerPtr.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// SetApplicationLogger performs the set application logger operation.
func SetApplicationLogger(logger *slog.Logger) {
	applicationLoggerPtr.Store(logger)
}

// GetApplicationLogger returns the application logger.
func GetApplicationLogger() *slog.Logger {
	if l := applicationLoggerPtr.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// --- zap getters/setters ---

// SetZapSecurityLogger performs the set zap security logger operation.
func SetZapSecurityLogger(logger *zap.Logger) {
	zapSecurityLoggerPtr.Store(logger)
}

// GetZapSecurityLogger returns the zap security logger.
func GetZapSecurityLogger() *zap.Logger {
	return zapSecurityLoggerPtr.Load()
}

// SetZapRequestLogger performs the set zap request logger operation.
func SetZapRequestLogger(logger *zap.Logger) {
	zapRequestLoggerPtr.Store(logger)
}

// GetZapRequestLogger returns the zap request logger.
func GetZapRequestLogger() *zap.Logger {
	return zapRequestLoggerPtr.Load()
}

// SetZapApplicationLogger performs the set zap application logger operation.
func SetZapApplicationLogger(logger *zap.Logger) {
	zapApplicationLoggerPtr.Store(logger)
}

// GetZapApplicationLogger returns the zap application logger.
func GetZapApplicationLogger() *zap.Logger {
	return zapApplicationLoggerPtr.Load()
}

// --- zap-native initialization functions ---

// InitApplicationLoggerZap creates a zap-based application logger and its slog bridge.
func InitApplicationLoggerZap(cfg ApplicationLoggingConfig) (*zap.Logger, *slog.Logger) {
	level := ParseZapLevel(cfg.Level)
	atomicLevel := zap.NewAtomicLevelAt(level)
	SetApplicationAtomicLevel(&atomicLevel)

	core := buildCores(cfg.Outputs, atomicLevel, false)
	core = &metricsCore{Core: core}
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0)).With(zap.String("type", "app"))
	slogLogger := slog.New(zapslog.NewHandler(zapLogger.Core(), zapslog.WithCaller(true)))

	SetZapApplicationLogger(zapLogger)
	SetApplicationLogger(slogLogger)

	// Keep LevelHandler backward compat for reload tests
	lh := NewLevelHandler(slogLevelFromZap(level), slogLogger.Handler())
	SetApplicationLevelHandler(lh)

	return zapLogger, slogLogger
}

// InitRequestLoggerZap creates a zap-based request logger with multi-output support.
func InitRequestLoggerZap(cfg RequestLoggingConfig) (*zap.Logger, *slog.Logger) {
	level := ParseZapLevel(cfg.Level)
	atomicLevel := zap.NewAtomicLevelAt(level)
	SetRequestAtomicLevel(&atomicLevel)

	core := buildCores(cfg.Outputs, atomicLevel, true)
	core = &metricsCore{Core: core}
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0)).With(zap.String("type", "req"))
	slogLogger := slog.New(zapslog.NewHandler(zapLogger.Core(), zapslog.WithCaller(true)))

	SetZapRequestLogger(zapLogger)
	SetRequestLogger(slogLogger)

	lh := NewLevelHandler(slogLevelFromZap(level), slogLogger.Handler())
	SetRequestLevelHandler(lh)

	return zapLogger, slogLogger
}

// InitSecurityLoggerZap creates a zap-based security logger and its slog bridge.
func InitSecurityLoggerZap(cfg SecurityLoggingConfig) (*zap.Logger, *slog.Logger) {
	level := ParseZapLevel(cfg.Level)
	atomicLevel := zap.NewAtomicLevelAt(level)
	SetSecurityAtomicLevel(&atomicLevel)

	core := buildCores(cfg.Outputs, atomicLevel, false)
	core = &metricsCore{Core: core}
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0)).With(zap.String("type", "sec"))
	slogLogger := slog.New(zapslog.NewHandler(zapLogger.Core(), zapslog.WithCaller(true)))

	SetZapSecurityLogger(zapLogger)
	SetSecurityLogger(slogLogger)

	lh := NewLevelHandler(slogLevelFromZap(level), slogLogger.Handler())
	SetSecurityLevelHandler(lh)

	return zapLogger, slogLogger
}

// --- legacy slog initialization (kept for backward compat) ---

// InitApplicationLoggerWithStderr initializes the application logger with stderr handler.
// Deprecated: Use InitApplicationLoggerZap instead.
func InitApplicationLoggerWithStderr(logLevel slog.Level) *slog.Logger {
	cfg := ApplicationLoggingConfig{
		Level:   zapLevelString(logLevel),
		Outputs: []OutputConfig{{Type: "stderr"}},
	}
	_, slogLogger := InitApplicationLoggerZap(cfg)
	return slogLogger
}

// InitRequestLoggerWithStderr initializes the request logger with stderr handler.
// Deprecated: Use InitRequestLoggerZap instead.
func InitRequestLoggerWithStderr(logLevel slog.Level) *slog.Logger {
	cfg := RequestLoggingConfig{
		Enabled: true,
		Level:   zapLevelString(logLevel),
		Outputs: []OutputConfig{{Type: "stderr"}},
		Fields:  DefaultRequestLoggingConfig().Fields,
	}
	_, slogLogger := InitRequestLoggerZap(cfg)
	return slogLogger
}

// InitSecurityLoggerWithStderr initializes the security logger with stderr handler.
// Deprecated: Use InitSecurityLoggerZap instead.
func InitSecurityLoggerWithStderr(logLevel slog.Level) *slog.Logger {
	cfg := SecurityLoggingConfig{
		Level:   zapLevelString(logLevel),
		Outputs: []OutputConfig{{Type: "stderr"}},
	}
	_, slogLogger := InitSecurityLoggerZap(cfg)
	return slogLogger
}

// WrapLoggerWithMetrics is a no-op in the zap architecture.
// Metrics are handled by the metricsCore wrapper in the zap Core chain.
// Kept for backward compatibility.
func WrapLoggerWithMetrics(logger *slog.Logger) *slog.Logger {
	return logger
}

// InitRequestLogger initializes the request logger with consistent field names.
// Deprecated: Use InitRequestLoggerZap instead.
func InitRequestLogger(baseLogger *slog.Logger) *slog.Logger {
	logger := baseLogger.With(slog.String("type", "req"))
	SetRequestLogger(logger)
	return GetRequestLogger()
}

// InitSecurityLogger initializes the security logger with consistent field names.
// Deprecated: Use InitSecurityLoggerZap instead.
func InitSecurityLogger(baseLogger *slog.Logger) *slog.Logger {
	logger := baseLogger.With(slog.String("type", "sec"))
	SetSecurityLogger(logger)
	return GetSecurityLogger()
}

// --- core building ---

// buildCores creates a zapcore.Core from output configs using zapcore.NewTee.
func buildCores(outputs []OutputConfig, level zap.AtomicLevel, flatMode bool) zapcore.Core {
	var cores []zapcore.Core

	for _, output := range outputs {
		switch output.Type {
		case "stderr":
			encoder := buildEncoder(flatMode)
			cores = append(cores, zapcore.NewCore(
				encoder,
				zapcore.Lock(os.Stderr),
				level,
			))
		case "clickhouse":
			if output.ClickHouse == nil {
				continue
			}
			chWriter, err := NewClickHouseHTTPWriter(ClickHouseWriterConfig{
				Host:          output.ClickHouse.Host,
				Database:      output.ClickHouse.Database,
				Table:         output.ClickHouse.Table,
				MaxBatchSize:  output.ClickHouse.BatchSize,
				MaxBatchBytes: output.ClickHouse.MaxBatchBytes,
				FlushInterval: output.ClickHouse.FlushInterval,
				Timeout:       output.ClickHouse.Timeout,
				AsyncInsert:   output.ClickHouse.AsyncInsert,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to init ClickHouse writer: %v\n", err)
				continue
			}
			encoder := buildEncoder(true) // ClickHouse always gets flat JSON
			cores = append(cores, zapcore.NewCore(
				encoder,
				zapcore.AddSync(chWriter),
				level,
			))
			RegisterCloser(chWriter)
		}
	}

	if len(cores) == 0 {
		// Fallback: always have at least stderr
		encoder := buildEncoder(flatMode)
		cores = append(cores, zapcore.NewCore(
			encoder,
			zapcore.Lock(os.Stderr),
			level,
		))
	}

	if len(cores) == 1 {
		return cores[0]
	}
	return zapcore.NewTee(cores...)
}

// buildEncoder creates the appropriate zapcore.Encoder based on mode.
func buildEncoder(flatMode bool) zapcore.Encoder {
	format := viper.GetString("proxy.logging.format")
	if format == "dev" {
		return NewDevColorEncoder(zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.MillisDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		})
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.MessageKey = "message"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.CallerKey = "caller"
	return zapcore.NewJSONEncoder(encoderCfg)
}

// --- helpers ---

// ParseZapLevel converts a string log level to zapcore.Level.
func ParseZapLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func slogLevelFromZap(level zapcore.Level) slog.Level {
	switch level {
	case zapcore.DebugLevel:
		return slog.LevelDebug
	case zapcore.InfoLevel:
		return slog.LevelInfo
	case zapcore.WarnLevel:
		return slog.LevelWarn
	case zapcore.ErrorLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func zapLevelString(level slog.Level) string {
	switch {
	case level <= slog.LevelDebug:
		return "debug"
	case level <= slog.LevelInfo:
		return "info"
	case level <= slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}
