package wasm

import "context"

// hostGetAuth implements sb_get_auth(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named auth field: type, is_authenticated, or any auth data key.
func hostGetAuth(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetAuthInfo(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetAuthJSON implements sb_get_auth_json() -> (ptr, len)
// Returns the full auth object as pre-serialized JSON.
func hostGetAuthJSON(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil || len(rc.GetAuthJSON()) == 0 {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, rc.GetAuthJSON())
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetClientLocation implements sb_get_client_location(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetClientLocation(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetClientLocation(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetClientUserAgent implements sb_get_client_user_agent(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetClientUserAgent(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetClientUserAgent(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetClientFingerprint implements sb_get_client_fingerprint(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetClientFingerprint(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetClientFingerprint(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetOriginMeta implements sb_get_origin_meta(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetOriginMeta(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetOriginMeta(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetCtx implements sb_get_ctx(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetCtx(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetCtxScalar(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetCtxData implements sb_get_ctx_data(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetCtxData(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetCtxData(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetCtxData implements sb_set_ctx_data(name_ptr, name_len, val_ptr, val_len)
func hostSetCtxData(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])
	valPtr := uint32(stack[2])
	valLen := uint32(stack[3])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		return
	}

	value, ok := readString(mod, valPtr, valLen)
	if !ok {
		return
	}

	rc.SetCtxData(name, value)
}
