package wasm

import "context"

// hostRemoveRequestHeader implements sb_remove_request_header(name_ptr, name_len)
func hostRemoveRequestHeader(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		return
	}

	rc.RemoveRequestHeader(name)
}

// hostGetRequestPath implements sb_get_request_path() -> (ptr, len)
func hostGetRequestPath(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	path := rc.GetRequestPath()
	if path == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(path))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetRequestPath implements sb_set_request_path(path_ptr, path_len)
func hostSetRequestPath(ctx context.Context, mod WasmModule, stack []uint64) {
	pathPtr := uint32(stack[0])
	pathLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	path, ok := readString(mod, pathPtr, pathLen)
	if !ok {
		return
	}

	rc.SetRequestPath(path)
}

// hostGetRequestMethod implements sb_get_request_method() -> (ptr, len)
func hostGetRequestMethod(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	method := rc.GetRequestMethod()
	if method == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(method))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetQueryParam implements sb_get_query_param(name_ptr, name_len) -> (value_ptr, value_len)
func hostGetQueryParam(ctx context.Context, mod WasmModule, stack []uint64) {
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

	value, found := rc.GetQueryParam(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}
