package wasm

import "context"

// ReadBytes reads raw bytes from module memory at the given pointer and length.
// Returns nil if the pointer/length pair is out of bounds.
func ReadBytes(mod WasmModule, ptr, length uint32) []byte {
	if mod == nil || length == 0 {
		return nil
	}
	data, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return nil
	}
	// Return a copy so callers do not hold references to WASM memory.
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

// ReadString reads a string from module memory at the given pointer and length.
// Returns an empty string if the pointer/length pair is out of bounds.
func ReadString(mod WasmModule, ptr, length uint32) string {
	if mod == nil || length == 0 {
		return ""
	}
	data, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return ""
	}
	return string(data)
}

// WriteBytes writes bytes to guest memory via the sb_malloc export.
// Returns (ptr, len) of the written data, or (0, 0) if allocation fails.
func WriteBytes(ctx context.Context, mod WasmModule, data []byte) (ptr, length uint32) {
	if mod == nil || len(data) == 0 {
		return 0, 0
	}

	malloc := mod.ExportedFunction("sb_malloc")
	if malloc == nil {
		return 0, 0
	}

	results, err := malloc.Call(ctx, uint64(len(data)))
	if err != nil || len(results) == 0 {
		return 0, 0
	}

	p := uint32(results[0])
	if !mod.Memory().Write(p, data) {
		return 0, 0
	}

	return p, uint32(len(data))
}

// WriteString writes a string to guest memory via sb_malloc.
// Returns (ptr, len) of the written data, or (0, 0) if allocation fails.
func WriteString(ctx context.Context, mod WasmModule, s string) (ptr, length uint32) {
	return WriteBytes(ctx, mod, []byte(s))
}

// ValidateMemoryBounds checks that a pointer+length pair is within module memory bounds.
func ValidateMemoryBounds(mod WasmModule, ptr, length uint32) bool {
	if mod == nil {
		return false
	}
	mem := mod.Memory()
	if mem == nil {
		return false
	}
	size := mem.Size()
	// Check for overflow and bounds.
	end := uint64(ptr) + uint64(length)
	return end <= uint64(size)
}
