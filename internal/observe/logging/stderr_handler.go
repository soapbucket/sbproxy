// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
)

// devColorEncoder is a zapcore.Encoder that produces human-readable colored output.
// Used when proxy.logging.format = "dev".
type devColorEncoder struct {
	zapcore.EncoderConfig
	pool buffer.Pool
}

// NewDevColorEncoder creates a new dev-mode colored encoder.
func NewDevColorEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	return &devColorEncoder{
		EncoderConfig: cfg,
		pool:          buffer.NewPool(),
	}
}

// Clone performs the clone operation on the devColorEncoder.
func (e *devColorEncoder) Clone() zapcore.Encoder {
	return &devColorEncoder{
		EncoderConfig: e.EncoderConfig,
		pool:          e.pool,
	}
}

// EncodeEntry performs the encode entry operation on the devColorEncoder.
func (e *devColorEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	buf := e.pool.Get()

	// Timestamp
	buf.AppendString(colorGray)
	buf.AppendString(entry.Time.Format("2006-01-02 15:04:05.000"))
	buf.AppendString(colorReset)
	buf.AppendByte(' ')

	// Level with color
	levelColor := colorReset
	switch entry.Level {
	case zapcore.DebugLevel:
		levelColor = colorGray
	case zapcore.InfoLevel:
		levelColor = colorGreen
	case zapcore.WarnLevel:
		levelColor = colorYellow
	case zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		levelColor = colorRed
	}
	buf.AppendString(levelColor)
	buf.AppendString(strings.ToUpper(entry.Level.String()))
	buf.AppendString(colorReset)
	buf.AppendByte(' ')

	// Caller
	if entry.Caller.Defined {
		buf.AppendString(colorCyan)
		buf.AppendString(getRelativeFile(entry.Caller.File))
		buf.AppendByte(':')
		buf.AppendString(strconv.Itoa(entry.Caller.Line))
		buf.AppendString(colorReset)
		buf.AppendByte(' ')
	}

	// Message
	buf.AppendString(entry.Message)

	// Fields
	for _, f := range fields {
		buf.AppendByte(' ')
		buf.AppendString(colorBlue)
		buf.AppendString(f.Key)
		buf.AppendString(colorReset)
		buf.AppendByte('=')
		buf.AppendString(colorMagenta)
		buf.AppendString(fieldValueString(f))
		buf.AppendString(colorReset)
	}

	buf.AppendByte('\n')
	return buf, nil
}

// AddArray implements zapcore.ObjectEncoder (required by interface but not used for dev output).
func (e *devColorEncoder) AddArray(key string, arr zapcore.ArrayMarshaler) error { return nil }

// AddObject implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddObject(key string, obj zapcore.ObjectMarshaler) error { return nil }

// AddBinary implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddBinary(key string, val []byte) {}

// AddByteString implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddByteString(key string, val []byte) {}

// AddBool implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddBool(key string, val bool) {}

// AddComplex128 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddComplex128(key string, val complex128) {}

// AddComplex64 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddComplex64(key string, val complex64) {}

// AddDuration implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddDuration(key string, val time.Duration) {}

// AddFloat64 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddFloat64(key string, val float64) {}

// AddFloat32 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddFloat32(key string, val float32) {}

// AddInt implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddInt(key string, val int) {}

// AddInt64 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddInt64(key string, val int64) {}

// AddInt32 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddInt32(key string, val int32) {}

// AddInt16 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddInt16(key string, val int16) {}

// AddInt8 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddInt8(key string, val int8) {}

// AddString implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddString(key string, val string) {}

// AddTime implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddTime(key string, val time.Time) {}

// AddUint implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddUint(key string, val uint) {}

// AddUint64 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddUint64(key string, val uint64) {}

// AddUint32 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddUint32(key string, val uint32) {}

// AddUint16 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddUint16(key string, val uint16) {}

// AddUint8 implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddUint8(key string, val uint8) {}

// AddUintptr implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddUintptr(key string, val uintptr) {}

// AddReflected implements zapcore.ObjectEncoder.
func (e *devColorEncoder) AddReflected(key string, val interface{}) error { return nil }

// OpenNamespace implements zapcore.ObjectEncoder.
func (e *devColorEncoder) OpenNamespace(key string) {}

// fieldValueString extracts a string representation from a zap field.
func fieldValueString(f zapcore.Field) string {
	switch f.Type {
	case zapcore.StringType:
		return f.String
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		return strconv.FormatInt(f.Integer, 10)
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
		return strconv.FormatUint(uint64(f.Integer), 10)
	case zapcore.Float64Type:
		return strconv.FormatFloat(float64(f.Integer), 'f', -1, 64)
	case zapcore.Float32Type:
		return strconv.FormatFloat(float64(f.Integer), 'f', -1, 32)
	case zapcore.BoolType:
		if f.Integer == 1 {
			return "true"
		}
		return "false"
	case zapcore.ErrorType:
		if f.Interface != nil {
			return f.Interface.(error).Error()
		}
		return "<nil>"
	default:
		if f.Interface != nil {
			return fmt.Sprintf("%v", f.Interface)
		}
		return fmt.Sprintf("%v", f.String)
	}
}

// getRelativeFile returns a relative file path from the project root.
func getRelativeFile(file string) string {
	if idx := strings.Index(file, "/internal/"); idx >= 0 {
		return file[idx+1:]
	}
	if idx := strings.Index(file, "/lib/"); idx >= 0 {
		return file[idx+1:]
	}
	return filepath.Base(file)
}
