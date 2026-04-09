package wasm

import "context"

// hostRemoveResponseHeader implements sb_remove_response_header(name_ptr, name_len)
func hostRemoveResponseHeader(ctx context.Context, mod WasmModule, stack []uint64) {
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

	rc.RemoveResponseHeader(name)
}

// hostGetResponseStatus implements sb_get_response_status() -> status_code
func hostGetResponseStatus(ctx context.Context, _ WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		return
	}

	stack[0] = uint64(rc.GetResponseStatus())
}

// hostSetResponseStatus implements sb_set_response_status(code)
func hostSetResponseStatus(ctx context.Context, _ WasmModule, stack []uint64) {
	code := int(uint32(stack[0]))

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	rc.SetResponseStatus(code)
}
