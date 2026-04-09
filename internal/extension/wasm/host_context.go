package wasm

import "context"

// hostGetVariable implements sb_get_variable(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetVariable(ctx context.Context, mod WasmModule, stack []uint64) {
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

	value, found := rc.GetVariable(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetClientIP implements sb_get_client_ip() -> (ptr, len)
func hostGetClientIP(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ip := rc.GetClientIP()
	if ip == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(ip))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetGeoCountry implements sb_get_geo_country() -> (ptr, len)
func hostGetGeoCountry(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	country := rc.GetGeoCountry()
	if country == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(country))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetSessionID implements sb_get_session_id() -> (ptr, len)
func hostGetSessionID(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	sid := rc.GetSessionID()
	if sid == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(sid))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// --- New context model host functions ---

// hostGetOrigin implements sb_get_origin() -> (ptr, len)
// Returns the origin ID string.
func hostGetOrigin(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil || rc.OriginID == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(rc.OriginID))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetOriginParam implements sb_get_origin_param(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named origin parameter value.
func hostGetOriginParam(ctx context.Context, mod WasmModule, stack []uint64) {
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

	rc.mu.RLock()
	value, found := rc.OriginParams[name]
	rc.mu.RUnlock()
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetSecret implements sb_get_secret(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named origin secret value.
func hostGetSecret(ctx context.Context, mod WasmModule, stack []uint64) {
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

	value, found := rc.GetOriginSecret(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetServer implements sb_get_server(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named server variable (instance_id, version, build_hash, etc.).
func hostGetServer(ctx context.Context, mod WasmModule, stack []uint64) {
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

	rc.mu.RLock()
	value, found := rc.ServerVars[name]
	rc.mu.RUnlock()
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetVar implements sb_get_var(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named config variable.
func hostGetVar(ctx context.Context, mod WasmModule, stack []uint64) {
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

	rc.mu.RLock()
	value, found := rc.Vars[name]
	rc.mu.RUnlock()
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetFeature implements sb_get_feature(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named feature flag value.
func hostGetFeature(ctx context.Context, mod WasmModule, stack []uint64) {
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

	rc.mu.RLock()
	value, found := rc.Features[name]
	rc.mu.RUnlock()
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetSession implements sb_get_session(name_ptr, name_len) -> (value_ptr, value_len)
// Returns a named session data value.
func hostGetSession(ctx context.Context, mod WasmModule, stack []uint64) {
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

	rc.mu.RLock()
	value, found := rc.SessionData[name]
	rc.mu.RUnlock()
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}
