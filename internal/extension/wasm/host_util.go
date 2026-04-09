package wasm

import (
	"context"
	"strings"
)

// hostSendResponse implements sb_send_response(status, headers_ptr, headers_len, body_ptr, body_len)
// Headers are passed as newline-separated "Key: Value" pairs.
func hostSendResponse(ctx context.Context, mod WasmModule, stack []uint64) {
	status := int(uint32(stack[0]))
	headersPtr := uint32(stack[1])
	headersLen := uint32(stack[2])
	bodyPtr := uint32(stack[3])
	bodyLen := uint32(stack[4])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	// Parse headers
	headers := make(map[string]string)
	if headersLen > 0 {
		raw, ok := readString(mod, headersPtr, headersLen)
		if ok {
			for _, line := range strings.Split(raw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// Read body
	var body []byte
	if bodyLen > 0 {
		data, ok := mod.Memory().Read(bodyPtr, bodyLen)
		if ok {
			body = make([]byte, len(data))
			copy(body, data)
		}
	}

	rc.SetSendResponse(status, headers, body)
}

// hostGetSharedData implements sb_get_shared_data(key_ptr, key_len) -> (value_ptr, value_len)
func hostGetSharedData(ctx context.Context, mod WasmModule, stack []uint64) {
	keyPtr := uint32(stack[0])
	keyLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	key, ok := readString(mod, keyPtr, keyLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetSharedData(key)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, value)
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetSharedData implements sb_set_shared_data(key_ptr, key_len, val_ptr, val_len)
func hostSetSharedData(ctx context.Context, mod WasmModule, stack []uint64) {
	keyPtr := uint32(stack[0])
	keyLen := uint32(stack[1])
	valPtr := uint32(stack[2])
	valLen := uint32(stack[3])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	key, ok := readString(mod, keyPtr, keyLen)
	if !ok {
		return
	}

	data, ok := mod.Memory().Read(valPtr, valLen)
	if !ok {
		return
	}

	// Copy to avoid holding reference to WASM memory
	value := make([]byte, len(data))
	copy(value, data)
	rc.SetSharedData(key, value)
}
