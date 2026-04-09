package wasm

import (
	"testing"
)

func TestReadBytes_NilModule(t *testing.T) {
	result := ReadBytes(nil, 0, 10)
	if result != nil {
		t.Errorf("expected nil for nil module, got %v", result)
	}
}

func TestReadBytes_ZeroLength(t *testing.T) {
	// Zero length should return nil regardless of module.
	result := ReadBytes(nil, 0, 0)
	if result != nil {
		t.Errorf("expected nil for zero length, got %v", result)
	}
}

func TestReadString_NilModule(t *testing.T) {
	result := ReadString(nil, 0, 10)
	if result != "" {
		t.Errorf("expected empty string for nil module, got %q", result)
	}
}

func TestReadString_ZeroLength(t *testing.T) {
	result := ReadString(nil, 0, 0)
	if result != "" {
		t.Errorf("expected empty string for zero length, got %q", result)
	}
}

func TestWriteBytes_NilModule(t *testing.T) {
	ptr, length := WriteBytes(nil, nil, []byte("test"))
	if ptr != 0 || length != 0 {
		t.Errorf("expected (0, 0) for nil module, got (%d, %d)", ptr, length)
	}
}

func TestWriteBytes_EmptyData(t *testing.T) {
	ptr, length := WriteBytes(nil, nil, nil)
	if ptr != 0 || length != 0 {
		t.Errorf("expected (0, 0) for empty data, got (%d, %d)", ptr, length)
	}

	ptr, length = WriteBytes(nil, nil, []byte{})
	if ptr != 0 || length != 0 {
		t.Errorf("expected (0, 0) for empty slice, got (%d, %d)", ptr, length)
	}
}

func TestWriteString_NilModule(t *testing.T) {
	ptr, length := WriteString(nil, nil, "test")
	if ptr != 0 || length != 0 {
		t.Errorf("expected (0, 0) for nil module, got (%d, %d)", ptr, length)
	}
}

func TestWriteString_EmptyString(t *testing.T) {
	ptr, length := WriteString(nil, nil, "")
	if ptr != 0 || length != 0 {
		t.Errorf("expected (0, 0) for empty string, got (%d, %d)", ptr, length)
	}
}

func TestValidateMemoryBounds_NilModule(t *testing.T) {
	if ValidateMemoryBounds(nil, 0, 10) {
		t.Error("expected false for nil module")
	}
}
