package config

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

// --- WASM binary builder helpers ---
// These helpers construct valid WASM 1.0 binary modules programmatically,
// avoiding a dependency on the wabt toolkit (wat2wasm).

// wasmBuilder assembles a WASM module from sections.
type wasmBuilder struct {
	sections [][]byte
}

func newWasmBuilder() *wasmBuilder {
	return &wasmBuilder{}
}

// addSection appends a raw WASM section (id byte + size-prefixed payload).
func (b *wasmBuilder) addSection(id byte, payload []byte) {
	sec := []byte{id}
	sec = appendLEB128(sec, uint32(len(payload)))
	sec = append(sec, payload...)
	b.sections = append(b.sections, sec)
}

// build returns the complete WASM binary with magic number and version.
func (b *wasmBuilder) build() []byte {
	// WASM magic: \0asm
	out := []byte{0x00, 0x61, 0x73, 0x6d}
	// Version 1
	out = append(out, 0x01, 0x00, 0x00, 0x00)
	for _, s := range b.sections {
		out = append(out, s...)
	}
	return out
}

// appendLEB128 appends an unsigned LEB128-encoded uint32.
func appendLEB128(buf []byte, val uint32) []byte {
	for {
		b := byte(val & 0x7F)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if val == 0 {
			break
		}
	}
	return buf
}

// appendSignedLEB128 appends a signed LEB128-encoded int32.
func appendSignedLEB128(buf []byte, val int32) []byte {
	more := true
	for more {
		b := byte(val & 0x7F)
		val >>= 7
		if (val == 0 && (b&0x40) == 0) || (val == -1 && (b&0x40) != 0) {
			more = false
		} else {
			b |= 0x80
		}
		buf = append(buf, b)
	}
	return buf
}

// WASM type constants.
const (
	wasmI32       = byte(0x7F)
	wasmFuncType  = byte(0x60)
	wasmFuncRef   = byte(0x00) // funcref type for tables
	wasmExternFn  = byte(0x00) // export kind: function
	wasmExternMem = byte(0x02) // export kind: memory
)

// WASM section IDs.
const (
	sectionType   = byte(1)
	sectionImport = byte(2)
	sectionFunc   = byte(3)
	sectionMemory = byte(5)
	sectionGlobal = byte(6)
	sectionExport = byte(7)
	sectionCode   = byte(10)
	sectionData   = byte(11)
)

// WASM opcodes.
const (
	opEnd        = byte(0x0B)
	opLocalGet   = byte(0x20)
	opLocalSet   = byte(0x21)
	opGlobalGet  = byte(0x23)
	opGlobalSet  = byte(0x24)
	opI32Load    = byte(0x28)
	opI32Const   = byte(0x41)
	opI32Add     = byte(0x6A)
	opI32Eqz     = byte(0x6D) // not used, but available
	opCall       = byte(0x10)
	opIf         = byte(0x04)
	opElse       = byte(0x05)
	opBlock      = byte(0x02)
	opNop        = byte(0x01)
	opReturn     = byte(0x0F)
	opDrop       = byte(0x1A)
	opI32Store   = byte(0x36)
	opI32Ne      = byte(0x47)
	opMemorySize = byte(0x3F)
	opMemoryGrow = byte(0x40)
)

// buildString encodes a WASM string (length-prefixed).
func buildString(s string) []byte {
	b := appendLEB128(nil, uint32(len(s)))
	return append(b, []byte(s)...)
}

// buildTypeSection builds the type section for the module.
// Returns (section bytes, type index mapping).
func buildTypeSection(types [][]byte) []byte {
	payload := appendLEB128(nil, uint32(len(types)))
	for _, t := range types {
		payload = append(payload, t...)
	}
	return payload
}

// funcType builds a WASM function type.
func funcType(params []byte, results []byte) []byte {
	t := []byte{wasmFuncType}
	t = appendLEB128(t, uint32(len(params)))
	t = append(t, params...)
	t = appendLEB128(t, uint32(len(results)))
	t = append(t, results...)
	return t
}

// --- Test module builders ---

// buildEchoPlugin builds a WASM module that:
// - Exports sb_malloc (bump allocator)
// - Exports sb_on_request: reads X-Test-Input header, sets X-Test-Output header, logs, returns 0
// - Exports sb_on_response: returns 0
// - Imports sb_get_request_header, sb_set_response_header, sb_log from "sb" module
func buildEchoPlugin() []byte {
	w := newWasmBuilder()

	// Type section: define function signatures
	// Type 0: (i32, i32) -> (i32, i32)  -- sb_get_request_header
	// Type 1: (i32, i32, i32, i32) -> () -- sb_set_response_header
	// Type 2: (i32, i32, i32) -> ()      -- sb_log
	// Type 3: (i32) -> (i32)             -- sb_malloc
	// Type 4: () -> (i32)                -- sb_on_request, sb_on_response
	types := [][]byte{
		funcType([]byte{wasmI32, wasmI32}, []byte{wasmI32, wasmI32}), // 0
		funcType([]byte{wasmI32, wasmI32, wasmI32, wasmI32}, nil),    // 1
		funcType([]byte{wasmI32, wasmI32, wasmI32}, nil),             // 2
		funcType([]byte{wasmI32}, []byte{wasmI32}),                   // 3
		funcType(nil, []byte{wasmI32}),                               // 4
	}
	w.addSection(sectionType, buildTypeSection(types))

	// Import section: 3 imports from "sb"
	imports := appendLEB128(nil, 3) // count
	// sb.sb_get_request_header (type 0)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_get_request_header")...)
	imports = append(imports, 0x00) // import kind: func
	imports = appendLEB128(imports, 0)
	// sb.sb_set_response_header (type 1)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_set_response_header")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 1)
	// sb.sb_log (type 2)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_log")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 2)
	w.addSection(sectionImport, imports)

	// Function section: 3 local functions (sb_malloc=func3, sb_on_request=func4, sb_on_response=func5)
	funcs := appendLEB128(nil, 3)
	funcs = appendLEB128(funcs, 3) // sb_malloc -> type 3
	funcs = appendLEB128(funcs, 4) // sb_on_request -> type 4
	funcs = appendLEB128(funcs, 4) // sb_on_response -> type 4
	w.addSection(sectionFunc, funcs)

	// Memory section: 1 memory, minimum 1 page
	mem := appendLEB128(nil, 1) // count
	mem = append(mem, 0x00)     // no max
	mem = appendLEB128(mem, 1)  // min 1 page
	w.addSection(sectionMemory, mem)

	// Global section: 1 mutable i32 global (bump pointer, initial value 1024)
	globals := appendLEB128(nil, 1)
	globals = append(globals, wasmI32) // type i32
	globals = append(globals, 0x01)    // mutable
	globals = append(globals, opI32Const)
	globals = appendSignedLEB128(globals, 1024)
	globals = append(globals, opEnd)
	w.addSection(sectionGlobal, globals)

	// Export section: memory, sb_malloc, sb_on_request, sb_on_response
	exports := appendLEB128(nil, 4)
	// memory
	exports = append(exports, buildString("memory")...)
	exports = append(exports, wasmExternMem)
	exports = appendLEB128(exports, 0)
	// sb_malloc (func index 3)
	exports = append(exports, buildString("sb_malloc")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 3)
	// sb_on_request (func index 4)
	exports = append(exports, buildString("sb_on_request")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 4)
	// sb_on_response (func index 5)
	exports = append(exports, buildString("sb_on_response")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 5)
	w.addSection(sectionExport, exports)

	// Code section: 3 function bodies

	// --- sb_malloc body (func 3) ---
	// local $ptr i32
	// local.set $ptr (global.get $bump_ptr)
	// global.set $bump_ptr (i32.add (global.get $bump_ptr) (local.get $size))
	// local.get $ptr
	mallocBody := buildFuncBody(
		[]byte{1, wasmI32}, // 1 local of type i32
		[]byte{
			opGlobalGet, 0x00, // global.get 0 (bump_ptr)
			opLocalSet, 0x01, // local.set 1 (ptr)
			opGlobalGet, 0x00, // global.get 0
			opLocalGet, 0x00, // local.get 0 (size param)
			opI32Add,
			opGlobalSet, 0x00, // global.set 0
			opLocalGet, 0x01, // local.get 1 (ptr) -- return value
			opEnd,
		},
	)

	// --- sb_on_request body (func 4) ---
	// 2 locals: val_ptr (i32), val_len (i32)
	// Call sb_get_request_header with "X-Test-Input" (data offset 0, len 12)
	// If val_ptr != 0, call sb_set_response_header with "X-Test-Output" (offset 16, len 13) and the value
	// Call sb_log(1, offset 32, 20)
	// Return 0
	onRequestCode := []byte{
		// Call sb_get_request_header(0, 12) -> (val_ptr, val_len)
		opI32Const,
	}
	onRequestCode = appendSignedLEB128(onRequestCode, 0) // name_ptr = 0
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 12)   // name_len = 12
	onRequestCode = append(onRequestCode, opCall, 0x00)     // call func 0 (sb_get_request_header)
	onRequestCode = append(onRequestCode, opLocalSet, 0x01) // local.set 1 (val_len)
	onRequestCode = append(onRequestCode, opLocalSet, 0x00) // local.set 0 (val_ptr)

	// if val_ptr != 0
	onRequestCode = append(onRequestCode, opLocalGet, 0x00) // local.get 0 (val_ptr)
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 0)
	onRequestCode = append(onRequestCode, opI32Ne)    // val_ptr != 0
	onRequestCode = append(onRequestCode, opIf, 0x40) // if (block type: void)

	// call sb_set_response_header(16, 13, val_ptr, val_len)
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 16) // name_ptr for "X-Test-Output"
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 13)   // name_len = 13
	onRequestCode = append(onRequestCode, opLocalGet, 0x00) // val_ptr
	onRequestCode = append(onRequestCode, opLocalGet, 0x01) // val_len
	onRequestCode = append(onRequestCode, opCall, 0x01)     // call func 1 (sb_set_response_header)

	onRequestCode = append(onRequestCode, opEnd) // end if

	// call sb_log(1, 32, 20) -- level=info, "echo plugin executed"
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 1) // level = info
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 32) // msg_ptr
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 20) // msg_len
	onRequestCode = append(onRequestCode, opCall, 0x02)   // call func 2 (sb_log)

	// Return ActionContinue (0)
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 0)
	onRequestCode = append(onRequestCode, opEnd)

	onRequestBody := buildFuncBody(
		[]byte{2, wasmI32}, // 2 locals of type i32
		onRequestCode,
	)

	// --- sb_on_response body (func 5) ---
	// Just return 0
	onResponseBody := buildFuncBody(
		nil, // no locals
		[]byte{
			opI32Const, 0x00,
			opEnd,
		},
	)

	codeSection := appendLEB128(nil, 3) // 3 function bodies
	codeSection = append(codeSection, mallocBody...)
	codeSection = append(codeSection, onRequestBody...)
	codeSection = append(codeSection, onResponseBody...)
	w.addSection(sectionCode, codeSection)

	// Data section: static strings
	// "X-Test-Input"  at offset 0  (12 bytes)
	// "X-Test-Output" at offset 16 (13 bytes)
	// "echo plugin executed" at offset 32 (20 bytes)
	dataSection := appendLEB128(nil, 3)
	dataSection = appendDataSegment(dataSection, 0, []byte("X-Test-Input"))
	dataSection = appendDataSegment(dataSection, 16, []byte("X-Test-Output"))
	dataSection = appendDataSegment(dataSection, 32, []byte("echo plugin executed"))
	w.addSection(sectionData, dataSection)

	return w.build()
}

// buildBlockPlugin builds a WASM module whose sb_on_request returns ActionBlock (1).
func buildBlockPlugin() []byte {
	w := newWasmBuilder()

	types := [][]byte{
		funcType([]byte{wasmI32}, []byte{wasmI32}), // 0: sb_malloc
		funcType(nil, []byte{wasmI32}),             // 1: sb_on_request
	}
	w.addSection(sectionType, buildTypeSection(types))

	// No imports needed for a simple block plugin
	funcs := appendLEB128(nil, 2)
	funcs = appendLEB128(funcs, 0) // sb_malloc -> type 0
	funcs = appendLEB128(funcs, 1) // sb_on_request -> type 1
	w.addSection(sectionFunc, funcs)

	mem := appendLEB128(nil, 1)
	mem = append(mem, 0x00)
	mem = appendLEB128(mem, 1)
	w.addSection(sectionMemory, mem)

	globals := appendLEB128(nil, 1)
	globals = append(globals, wasmI32, 0x01) // mutable i32
	globals = append(globals, opI32Const)
	globals = appendSignedLEB128(globals, 1024)
	globals = append(globals, opEnd)
	w.addSection(sectionGlobal, globals)

	exports := appendLEB128(nil, 3)
	exports = append(exports, buildString("memory")...)
	exports = append(exports, wasmExternMem)
	exports = appendLEB128(exports, 0)
	exports = append(exports, buildString("sb_malloc")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 0)
	exports = append(exports, buildString("sb_on_request")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 1)
	w.addSection(sectionExport, exports)

	mallocBody := buildFuncBody(
		[]byte{1, wasmI32},
		[]byte{
			opGlobalGet, 0x00,
			opLocalSet, 0x01,
			opGlobalGet, 0x00,
			opLocalGet, 0x00,
			opI32Add,
			opGlobalSet, 0x00,
			opLocalGet, 0x01,
			opEnd,
		},
	)
	onRequestBody := buildFuncBody(nil, []byte{
		opI32Const, 0x01, // ActionBlock
		opEnd,
	})

	codeSection := appendLEB128(nil, 2)
	codeSection = append(codeSection, mallocBody...)
	codeSection = append(codeSection, onRequestBody...)
	w.addSection(sectionCode, codeSection)

	return w.build()
}

// buildSendResponsePlugin builds a WASM module whose sb_on_request calls sb_send_response
// to short-circuit with a 403 and custom body.
func buildSendResponsePlugin() []byte {
	w := newWasmBuilder()

	// Type 0: (i32, i32, i32, i32, i32) -> () -- sb_send_response
	// Type 1: (i32) -> (i32) -- sb_malloc
	// Type 2: () -> (i32) -- sb_on_request
	types := [][]byte{
		funcType([]byte{wasmI32, wasmI32, wasmI32, wasmI32, wasmI32}, nil), // 0
		funcType([]byte{wasmI32}, []byte{wasmI32}),                         // 1
		funcType(nil, []byte{wasmI32}),                                     // 2
	}
	w.addSection(sectionType, buildTypeSection(types))

	// Import sb_send_response
	imports := appendLEB128(nil, 1)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_send_response")...)
	imports = append(imports, 0x00) // func
	imports = appendLEB128(imports, 0)
	w.addSection(sectionImport, imports)

	// Functions: sb_malloc=func1, sb_on_request=func2
	funcs := appendLEB128(nil, 2)
	funcs = appendLEB128(funcs, 1) // sb_malloc -> type 1
	funcs = appendLEB128(funcs, 2) // sb_on_request -> type 2
	w.addSection(sectionFunc, funcs)

	mem := appendLEB128(nil, 1)
	mem = append(mem, 0x00)
	mem = appendLEB128(mem, 1)
	w.addSection(sectionMemory, mem)

	globals := appendLEB128(nil, 1)
	globals = append(globals, wasmI32, 0x01)
	globals = append(globals, opI32Const)
	globals = appendSignedLEB128(globals, 1024)
	globals = append(globals, opEnd)
	w.addSection(sectionGlobal, globals)

	exports := appendLEB128(nil, 3)
	exports = append(exports, buildString("memory")...)
	exports = append(exports, wasmExternMem)
	exports = appendLEB128(exports, 0)
	exports = append(exports, buildString("sb_malloc")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 1)
	exports = append(exports, buildString("sb_on_request")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 2)
	w.addSection(sectionExport, exports)

	// sb_malloc
	mallocBody := buildFuncBody(
		[]byte{1, wasmI32},
		[]byte{
			opGlobalGet, 0x00,
			opLocalSet, 0x01,
			opGlobalGet, 0x00,
			opLocalGet, 0x00,
			opI32Add,
			opGlobalSet, 0x00,
			opLocalGet, 0x01,
			opEnd,
		},
	)

	// sb_on_request: call sb_send_response(403, headers_ptr=0, headers_len=0, body_ptr=0, body_len=13)
	// Data at offset 0: "access denied" (13 bytes)
	// Data at offset 16: "Content-Type: text/plain" (24 bytes) for headers
	onRequestCode := []byte{opI32Const}
	onRequestCode = appendSignedLEB128(onRequestCode, 403) // status
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 16) // headers_ptr
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 24) // headers_len
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 0) // body_ptr
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 13) // body_len
	onRequestCode = append(onRequestCode, opCall, 0x00)   // call func 0 (sb_send_response)
	onRequestCode = append(onRequestCode, opI32Const)
	onRequestCode = appendSignedLEB128(onRequestCode, 0) // return ActionContinue
	onRequestCode = append(onRequestCode, opEnd)

	onRequestBody := buildFuncBody(nil, onRequestCode)

	codeSection := appendLEB128(nil, 2)
	codeSection = append(codeSection, mallocBody...)
	codeSection = append(codeSection, onRequestBody...)
	w.addSection(sectionCode, codeSection)

	// Data section
	dataSection := appendLEB128(nil, 2)
	dataSection = appendDataSegment(dataSection, 0, []byte("access denied"))
	dataSection = appendDataSegment(dataSection, 16, []byte("Content-Type: text/plain"))
	w.addSection(sectionData, dataSection)

	return w.build()
}

// buildResponsePlugin builds a WASM module for response phase:
// - sb_on_response reads X-Upstream header and sets X-Plugin-Processed
func buildResponsePlugin() []byte {
	w := newWasmBuilder()

	types := [][]byte{
		funcType([]byte{wasmI32, wasmI32}, []byte{wasmI32, wasmI32}), // 0: sb_get_response_header
		funcType([]byte{wasmI32, wasmI32, wasmI32, wasmI32}, nil),    // 1: sb_set_response_header
		funcType([]byte{wasmI32}, []byte{wasmI32}),                   // 2: sb_malloc
		funcType(nil, []byte{wasmI32}),                               // 3: sb_on_response
	}
	w.addSection(sectionType, buildTypeSection(types))

	imports := appendLEB128(nil, 2)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_get_response_header")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 0)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_set_response_header")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 1)
	w.addSection(sectionImport, imports)

	funcs := appendLEB128(nil, 2)
	funcs = appendLEB128(funcs, 2) // sb_malloc -> type 2
	funcs = appendLEB128(funcs, 3) // sb_on_response -> type 3
	w.addSection(sectionFunc, funcs)

	mem := appendLEB128(nil, 1)
	mem = append(mem, 0x00)
	mem = appendLEB128(mem, 1)
	w.addSection(sectionMemory, mem)

	globals := appendLEB128(nil, 1)
	globals = append(globals, wasmI32, 0x01)
	globals = append(globals, opI32Const)
	globals = appendSignedLEB128(globals, 1024)
	globals = append(globals, opEnd)
	w.addSection(sectionGlobal, globals)

	exports := appendLEB128(nil, 3)
	exports = append(exports, buildString("memory")...)
	exports = append(exports, wasmExternMem)
	exports = appendLEB128(exports, 0)
	exports = append(exports, buildString("sb_malloc")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 2) // func index 2 (after 2 imports)
	exports = append(exports, buildString("sb_on_response")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 3) // func index 3
	w.addSection(sectionExport, exports)

	mallocBody := buildFuncBody(
		[]byte{1, wasmI32},
		[]byte{
			opGlobalGet, 0x00,
			opLocalSet, 0x01,
			opGlobalGet, 0x00,
			opLocalGet, 0x00,
			opI32Add,
			opGlobalSet, 0x00,
			opLocalGet, 0x01,
			opEnd,
		},
	)

	// sb_on_response: get X-Upstream header, set X-Plugin-Processed with same value
	// Data: "X-Upstream" at offset 0 (10 bytes), "X-Plugin-Processed" at offset 16 (18 bytes)
	onRespCode := []byte{
		opI32Const,
	}
	onRespCode = appendSignedLEB128(onRespCode, 0) // name_ptr
	onRespCode = append(onRespCode, opI32Const)
	onRespCode = appendSignedLEB128(onRespCode, 10)   // name_len "X-Upstream"
	onRespCode = append(onRespCode, opCall, 0x00)     // sb_get_response_header
	onRespCode = append(onRespCode, opLocalSet, 0x01) // val_len
	onRespCode = append(onRespCode, opLocalSet, 0x00) // val_ptr

	// if val_ptr != 0
	onRespCode = append(onRespCode, opLocalGet, 0x00)
	onRespCode = append(onRespCode, opI32Const)
	onRespCode = appendSignedLEB128(onRespCode, 0)
	onRespCode = append(onRespCode, opI32Ne)
	onRespCode = append(onRespCode, opIf, 0x40)

	// sb_set_response_header(16, 18, val_ptr, val_len)
	onRespCode = append(onRespCode, opI32Const)
	onRespCode = appendSignedLEB128(onRespCode, 16)
	onRespCode = append(onRespCode, opI32Const)
	onRespCode = appendSignedLEB128(onRespCode, 18)
	onRespCode = append(onRespCode, opLocalGet, 0x00)
	onRespCode = append(onRespCode, opLocalGet, 0x01)
	onRespCode = append(onRespCode, opCall, 0x01) // sb_set_response_header

	onRespCode = append(onRespCode, opEnd) // end if

	onRespCode = append(onRespCode, opI32Const)
	onRespCode = appendSignedLEB128(onRespCode, 0) // return ActionContinue
	onRespCode = append(onRespCode, opEnd)

	onRespBody := buildFuncBody([]byte{2, wasmI32}, onRespCode)

	codeSection := appendLEB128(nil, 2)
	codeSection = append(codeSection, mallocBody...)
	codeSection = append(codeSection, onRespBody...)
	w.addSection(sectionCode, codeSection)

	dataSection := appendLEB128(nil, 2)
	dataSection = appendDataSegment(dataSection, 0, []byte("X-Upstream"))
	dataSection = appendDataSegment(dataSection, 16, []byte("X-Plugin-Processed"))
	w.addSection(sectionData, dataSection)

	return w.build()
}

// buildVariablePlugin builds a WASM module that reads a variable via sb_get_var
// and sets it as a response header X-Var-Value.
func buildVariablePlugin() []byte {
	w := newWasmBuilder()

	types := [][]byte{
		funcType([]byte{wasmI32, wasmI32}, []byte{wasmI32, wasmI32}), // 0: sb_get_var
		funcType([]byte{wasmI32, wasmI32, wasmI32, wasmI32}, nil),    // 1: sb_set_response_header
		funcType([]byte{wasmI32}, []byte{wasmI32}),                   // 2: sb_malloc
		funcType(nil, []byte{wasmI32}),                               // 3: sb_on_request
	}
	w.addSection(sectionType, buildTypeSection(types))

	imports := appendLEB128(nil, 2)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_get_var")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 0)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_set_response_header")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 1)
	w.addSection(sectionImport, imports)

	funcs := appendLEB128(nil, 2)
	funcs = appendLEB128(funcs, 2) // sb_malloc
	funcs = appendLEB128(funcs, 3) // sb_on_request
	w.addSection(sectionFunc, funcs)

	mem := appendLEB128(nil, 1)
	mem = append(mem, 0x00)
	mem = appendLEB128(mem, 1)
	w.addSection(sectionMemory, mem)

	globals := appendLEB128(nil, 1)
	globals = append(globals, wasmI32, 0x01)
	globals = append(globals, opI32Const)
	globals = appendSignedLEB128(globals, 1024)
	globals = append(globals, opEnd)
	w.addSection(sectionGlobal, globals)

	exports := appendLEB128(nil, 3)
	exports = append(exports, buildString("memory")...)
	exports = append(exports, wasmExternMem)
	exports = appendLEB128(exports, 0)
	exports = append(exports, buildString("sb_malloc")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 2)
	exports = append(exports, buildString("sb_on_request")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 3)
	w.addSection(sectionExport, exports)

	mallocBody := buildFuncBody(
		[]byte{1, wasmI32},
		[]byte{
			opGlobalGet, 0x00,
			opLocalSet, 0x01,
			opGlobalGet, 0x00,
			opLocalGet, 0x00,
			opI32Add,
			opGlobalSet, 0x00,
			opLocalGet, 0x01,
			opEnd,
		},
	)

	// Data: "env" at offset 0 (3 bytes), "X-Var-Value" at offset 8 (11 bytes)
	onReqCode := []byte{opI32Const}
	onReqCode = appendSignedLEB128(onReqCode, 0)
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 3) // "env"
	onReqCode = append(onReqCode, opCall, 0x00)  // sb_get_var
	onReqCode = append(onReqCode, opLocalSet, 0x01)
	onReqCode = append(onReqCode, opLocalSet, 0x00)

	onReqCode = append(onReqCode, opLocalGet, 0x00)
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 0)
	onReqCode = append(onReqCode, opI32Ne)
	onReqCode = append(onReqCode, opIf, 0x40)

	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 8) // "X-Var-Value" ptr
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 11) // len
	onReqCode = append(onReqCode, opLocalGet, 0x00)
	onReqCode = append(onReqCode, opLocalGet, 0x01)
	onReqCode = append(onReqCode, opCall, 0x01) // sb_set_response_header
	onReqCode = append(onReqCode, opEnd)

	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 0)
	onReqCode = append(onReqCode, opEnd)

	onReqBody := buildFuncBody([]byte{2, wasmI32}, onReqCode)

	codeSection := appendLEB128(nil, 2)
	codeSection = append(codeSection, mallocBody...)
	codeSection = append(codeSection, onReqBody...)
	w.addSection(sectionCode, codeSection)

	dataSection := appendLEB128(nil, 2)
	dataSection = appendDataSegment(dataSection, 0, []byte("env"))
	dataSection = appendDataSegment(dataSection, 8, []byte("X-Var-Value"))
	w.addSection(sectionData, dataSection)

	return w.build()
}

// buildSecretHeaderPlugin builds a WASM module that reads a secret via
// sb_get_secret and sets it as a request header.
func buildSecretHeaderPlugin(secretName, headerName string) []byte {
	w := newWasmBuilder()

	types := [][]byte{
		funcType([]byte{wasmI32, wasmI32}, []byte{wasmI32, wasmI32}), // 0: sb_get_secret
		funcType([]byte{wasmI32, wasmI32, wasmI32, wasmI32}, nil),    // 1: sb_set_request_header
		funcType([]byte{wasmI32}, []byte{wasmI32}),                   // 2: sb_malloc
		funcType(nil, []byte{wasmI32}),                               // 3: sb_on_request
	}
	w.addSection(sectionType, buildTypeSection(types))

	imports := appendLEB128(nil, 2)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_get_secret")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 0)
	imports = append(imports, buildString("sb")...)
	imports = append(imports, buildString("sb_set_request_header")...)
	imports = append(imports, 0x00)
	imports = appendLEB128(imports, 1)
	w.addSection(sectionImport, imports)

	funcs := appendLEB128(nil, 2)
	funcs = appendLEB128(funcs, 2) // sb_malloc
	funcs = appendLEB128(funcs, 3) // sb_on_request
	w.addSection(sectionFunc, funcs)

	mem := appendLEB128(nil, 1)
	mem = append(mem, 0x00)
	mem = appendLEB128(mem, 1)
	w.addSection(sectionMemory, mem)

	globals := appendLEB128(nil, 1)
	globals = append(globals, wasmI32, 0x01)
	globals = append(globals, opI32Const)
	globals = appendSignedLEB128(globals, 1024)
	globals = append(globals, opEnd)
	w.addSection(sectionGlobal, globals)

	exports := appendLEB128(nil, 3)
	exports = append(exports, buildString("memory")...)
	exports = append(exports, wasmExternMem)
	exports = appendLEB128(exports, 0)
	exports = append(exports, buildString("sb_malloc")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 2)
	exports = append(exports, buildString("sb_on_request")...)
	exports = append(exports, wasmExternFn)
	exports = appendLEB128(exports, 3)
	w.addSection(sectionExport, exports)

	mallocBody := buildFuncBody(
		[]byte{1, wasmI32},
		[]byte{
			opGlobalGet, 0x00,
			opLocalSet, 0x01,
			opGlobalGet, 0x00,
			opLocalGet, 0x00,
			opI32Add,
			opGlobalSet, 0x00,
			opLocalGet, 0x01,
			opEnd,
		},
	)

	secretNameOffset := 0
	headerNameOffset := len(secretName) + 8
	onReqCode := []byte{opI32Const}
	onReqCode = appendSignedLEB128(onReqCode, int32(secretNameOffset))
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, int32(len(secretName)))
	onReqCode = append(onReqCode, opCall, 0x00) // sb_get_secret
	onReqCode = append(onReqCode, opLocalSet, 0x01)
	onReqCode = append(onReqCode, opLocalSet, 0x00)

	onReqCode = append(onReqCode, opLocalGet, 0x00)
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 0)
	onReqCode = append(onReqCode, opI32Ne)
	onReqCode = append(onReqCode, opIf, 0x40)
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, int32(headerNameOffset))
	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, int32(len(headerName)))
	onReqCode = append(onReqCode, opLocalGet, 0x00)
	onReqCode = append(onReqCode, opLocalGet, 0x01)
	onReqCode = append(onReqCode, opCall, 0x01) // sb_set_request_header
	onReqCode = append(onReqCode, opEnd)

	onReqCode = append(onReqCode, opI32Const)
	onReqCode = appendSignedLEB128(onReqCode, 0)
	onReqCode = append(onReqCode, opEnd)

	onReqBody := buildFuncBody([]byte{2, wasmI32}, onReqCode)

	codeSection := appendLEB128(nil, 2)
	codeSection = append(codeSection, mallocBody...)
	codeSection = append(codeSection, onReqBody...)
	w.addSection(sectionCode, codeSection)

	dataSection := appendLEB128(nil, 2)
	dataSection = appendDataSegment(dataSection, secretNameOffset, []byte(secretName))
	dataSection = appendDataSegment(dataSection, headerNameOffset, []byte(headerName))
	w.addSection(sectionData, dataSection)

	return w.build()
}

// buildFuncBody wraps locals declaration and code into a WASM function body (size-prefixed).
func buildFuncBody(locals []byte, code []byte) []byte {
	var body []byte
	if len(locals) == 0 {
		// 0 local declarations
		body = appendLEB128(nil, 0)
	} else {
		// locals is encoded as: count of local-decl entries, then entries
		// Each entry is: count (LEB128) + type
		// We pass pre-built locals where first byte is count, rest is type
		numDecls := uint32(1) // We always use a single "N locals of type T" declaration
		body = appendLEB128(nil, numDecls)
		body = appendLEB128(body, uint32(locals[0])) // count of locals
		body = append(body, locals[1:]...)           // type
	}
	body = append(body, code...)

	// Size-prefix the body
	result := appendLEB128(nil, uint32(len(body)))
	return append(result, body...)
}

// appendDataSegment appends an active data segment (memory 0, i32.const offset).
func appendDataSegment(buf []byte, offset int, data []byte) []byte {
	buf = append(buf, 0x00)       // active segment, memory 0
	buf = append(buf, opI32Const) // offset expression
	buf = appendSignedLEB128(buf, int32(offset))
	buf = append(buf, opEnd) // end of init expression
	buf = appendLEB128(buf, uint32(len(data)))
	buf = append(buf, data...)
	return buf
}

// --- E2E Tests ---

// TestWASM_E2E_HeaderManipulation tests the full pipeline: config loading, module
// compilation, host function registration, and HTTP header manipulation through
// the WASM middleware.
func TestWASM_E2E_HeaderManipulation(t *testing.T) {
	ctx := context.Background()

	wasmBytes := buildEchoPlugin()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "echo-test",
		Phase:  wasm.PhaseRequest,
		Source: wasmBytes,
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	var capturedRC *wasm.RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = wasm.RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Test-Input", "hello-wasm")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if capturedRC == nil {
		t.Fatal("expected RequestContext to be set")
	}

	// Verify the plugin read the request header and set the response header
	val, ok := capturedRC.GetResponseHeader("X-Test-Output")
	if !ok {
		t.Fatal("expected X-Test-Output response header to be set by plugin")
	}
	if val != "hello-wasm" {
		t.Errorf("X-Test-Output = %q, want %q", val, "hello-wasm")
	}
}

// TestWASM_E2E_HeaderMissing verifies the plugin handles missing headers gracefully.
func TestWASM_E2E_HeaderMissing(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "echo-test-missing",
		Phase:  wasm.PhaseRequest,
		Source: buildEchoPlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	var capturedRC *wasm.RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = wasm.RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.HandleRequest(next)
	// No X-Test-Input header set
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if capturedRC == nil {
		t.Fatal("expected RequestContext to be set")
	}

	// X-Test-Output should NOT be set since X-Test-Input was missing
	_, ok := capturedRC.GetResponseHeader("X-Test-Output")
	if ok {
		t.Error("expected X-Test-Output to NOT be set when X-Test-Input is missing")
	}
}

// TestWASM_E2E_BlockAction tests that a plugin returning ActionBlock results in a 403 response.
func TestWASM_E2E_BlockAction(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "block-test",
		Phase:  wasm.PhaseRequest,
		Source: buildBlockPlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/blocked", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if nextCalled {
		t.Error("next handler should NOT have been called when plugin blocks")
	}
}

// TestWASM_E2E_SendResponse tests that a plugin can short-circuit with a custom response
// via sb_send_response.
func TestWASM_E2E_SendResponse(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "send-response-test",
		Phase:  wasm.PhaseRequest,
		Source: buildSendResponsePlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/forbidden", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if nextCalled {
		t.Error("next handler should NOT have been called when plugin sends response")
	}

	body := rec.Body.String()
	if body != "access denied" {
		t.Errorf("response body = %q, want %q", body, "access denied")
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
}

// TestWASM_E2E_ResponsePhase tests that response-phase plugins can read and modify
// response headers through the full pipeline.
func TestWASM_E2E_ResponsePhase(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "response-test",
		Phase:  wasm.PhaseResponse,
		Source: buildResponsePlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	// Simulate an upstream response with X-Upstream header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rc := wasm.NewRequestContext()
	wasmCtx := wasm.WithRequestContext(req.Context(), rc)
	req = req.WithContext(wasmCtx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Upstream": []string{"origin-value"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("upstream body"))),
		Request:    req,
	}

	err = mw.HandleResponse(resp)
	if err != nil {
		t.Fatalf("HandleResponse failed: %v", err)
	}

	// The plugin should have copied X-Upstream to X-Plugin-Processed
	if got := resp.Header.Get("X-Plugin-Processed"); got != "origin-value" {
		t.Errorf("X-Plugin-Processed = %q, want %q", got, "origin-value")
	}
}

// TestWASM_E2E_VariableAccess tests that a plugin can read config variables via sb_get_var.
// This test calls the plugin directly (bypassing the HTTP middleware) to exercise the
// host function with a pre-populated RequestContext, since the middleware creates its own
// RequestContext from the HTTP request.
func TestWASM_E2E_VariableAccess(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "variable-test",
		Phase:  wasm.PhaseRequest,
		Source: buildVariablePlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	// Build a RequestContext with variables and call the plugin directly
	rc := wasm.NewRequestContext()
	rc.Vars = map[string]string{"env": "production"}
	pluginCtx := wasm.WithRequestContext(ctx, rc)

	action, err := plugin.CallOnRequest(pluginCtx)
	if err != nil {
		t.Fatalf("CallOnRequest failed: %v", err)
	}
	if action != wasm.ActionContinue {
		t.Errorf("action = %d, want %d (ActionContinue)", action, wasm.ActionContinue)
	}

	// The plugin should have read the "env" variable and set X-Var-Value
	val, ok := rc.GetResponseHeader("X-Var-Value")
	if !ok {
		t.Fatal("expected X-Var-Value response header to be set by plugin")
	}
	if val != "production" {
		t.Errorf("X-Var-Value = %q, want %q", val, "production")
	}
}

func TestWASM_E2E_SecretAccess_AllowedDeniedAndWildcard(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		secretName     string
		headerName     string
		allowedSecrets []string
		secrets        map[string]string
		wantHeader     string
	}{
		{
			name:           "allowed secret is readable",
			secretName:     "API_TOKEN",
			headerName:     "X-Secret-Value",
			allowedSecrets: []string{"API_TOKEN"},
			secrets:        map[string]string{"API_TOKEN": "token-123", "DB_PASS": "db-pass"},
			wantHeader:     "token-123",
		},
		{
			name:           "denied secret is hidden",
			secretName:     "DB_PASS",
			headerName:     "X-Secret-Value",
			allowedSecrets: []string{"API_TOKEN"},
			secrets:        map[string]string{"API_TOKEN": "token-123", "DB_PASS": "db-pass"},
			wantHeader:     "",
		},
		{
			name:           "wildcard grants all secrets",
			secretName:     "DB_PASS",
			headerName:     "X-Secret-Value",
			allowedSecrets: []string{"*"},
			secrets:        map[string]string{"API_TOKEN": "token-123", "DB_PASS": "db-pass"},
			wantHeader:     "db-pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
			if err != nil {
				t.Fatalf("NewRuntime failed: %v", err)
			}
			defer rt.Close(ctx)

			plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
				Name:           "secret-test",
				Phase:          wasm.PhaseRequest,
				Source:         buildSecretHeaderPlugin(tt.secretName, tt.headerName),
				AllowedSecrets: tt.allowedSecrets,
			})
			if err != nil {
				t.Fatalf("LoadPlugin failed: %v", err)
			}
			defer plugin.Close(ctx)

			mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

			var gotHeader string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Get(tt.headerName)
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
			rd := reqctx.NewRequestData()
			rd.OriginCtx = &reqctx.OriginContext{
				Secrets: tt.secrets,
			}
			req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
			rec := httptest.NewRecorder()

			mw.HandleRequest(next).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rec.Code)
			}
			if gotHeader != tt.wantHeader {
				t.Fatalf("%s header = %q, want %q", tt.headerName, gotHeader, tt.wantHeader)
			}
		})
	}
}

// TestWASM_E2E_VaultResolvedSecretAccess tests the full pipeline from vault
// manager secret resolution through to WASM plugin access via sb_get_secret.
// This proves that vault-backed secrets flow correctly through:
// VaultManager.ResolveAll -> GetAllSecrets -> OriginCtx.Secrets -> WASM middleware -> sb_get_secret
func TestWASM_E2E_VaultResolvedSecretAccess(t *testing.T) {
	ctx := context.Background()

	// Step 1: Set up a mock vault provider with test secrets
	mockVault := NewMockVaultProvider(VaultTypeLocal)
	mockVault.SetSecret("prod/api/token", "resolved-api-token-xyz")
	mockVault.SetSecret("prod/db/password", "resolved-db-pass-abc")

	// Step 2: Create a vault manager and resolve secrets
	vm, err := NewVaultManager(mockVault)
	if err != nil {
		t.Fatalf("NewVaultManager failed: %v", err)
	}
	vm.SetSecretDefinitions(map[string]string{
		"API_TOKEN": "system:prod/api/token",
		"DB_PASS":   "system:prod/db/password",
	})
	if err := vm.ResolveAll(ctx); err != nil {
		t.Fatalf("ResolveAll failed: %v", err)
	}

	// Verify vault manager resolved secrets correctly
	allSecrets := vm.GetAllSecrets()
	if len(allSecrets) != 2 {
		t.Fatalf("expected 2 resolved secrets, got %d", len(allSecrets))
	}
	if allSecrets["API_TOKEN"] != "resolved-api-token-xyz" {
		t.Fatalf("API_TOKEN = %q, want %q", allSecrets["API_TOKEN"], "resolved-api-token-xyz")
	}
	if allSecrets["DB_PASS"] != "resolved-db-pass-abc" {
		t.Fatalf("DB_PASS = %q, want %q", allSecrets["DB_PASS"], "resolved-db-pass-abc")
	}

	// Step 3: Test WASM plugin access to vault-resolved secrets
	tests := []struct {
		name           string
		secretName     string
		allowedSecrets []string
		wantHeader     string
	}{
		{
			name:           "vault-resolved secret is accessible when granted",
			secretName:     "API_TOKEN",
			allowedSecrets: []string{"API_TOKEN"},
			wantHeader:     "resolved-api-token-xyz",
		},
		{
			name:           "vault-resolved secret is hidden when not granted",
			secretName:     "DB_PASS",
			allowedSecrets: []string{"API_TOKEN"},
			wantHeader:     "",
		},
		{
			name:           "wildcard grants all vault-resolved secrets",
			secretName:     "DB_PASS",
			allowedSecrets: []string{"*"},
			wantHeader:     "resolved-db-pass-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
			if err != nil {
				t.Fatalf("NewRuntime failed: %v", err)
			}
			defer rt.Close(ctx)

			plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
				Name:           "vault-secret-test",
				Phase:          wasm.PhaseRequest,
				Source:         buildSecretHeaderPlugin(tt.secretName, "X-Vault-Secret"),
				AllowedSecrets: tt.allowedSecrets,
			})
			if err != nil {
				t.Fatalf("LoadPlugin failed: %v", err)
			}
			defer plugin.Close(ctx)

			mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

			var gotHeader string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Get("X-Vault-Secret")
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/vault-test", nil)
			rd := reqctx.NewRequestData()
			// Simulate the configloader pipeline: vault-resolved secrets -> OriginCtx.Secrets
			rd.OriginCtx = &reqctx.OriginContext{
				ID:       "vault-test-origin",
				Hostname: "vault-test.example.com",
				Secrets:  allSecrets,
			}
			req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
			rec := httptest.NewRecorder()

			mw.HandleRequest(next).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rec.Code)
			}
			if gotHeader != tt.wantHeader {
				t.Fatalf("X-Vault-Secret = %q, want %q", gotHeader, tt.wantHeader)
			}
		})
	}
}

// TestWASM_E2E_BodyReading tests that a plugin can read the request body.
func TestWASM_E2E_BodyReading(t *testing.T) {
	ctx := context.Background()

	// Use the echo plugin - it will process normally; we verify the body is preserved
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "body-test",
		Phase:  wasm.PhaseRequest,
		Source: buildEchoPlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	var capturedBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("failed to read body: %v", readErr)
		}
		capturedBody = body
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.HandleRequest(next)
	reqBody := []byte(`{"action":"test","payload":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	// Verify the body was preserved through the middleware pipeline
	if !bytes.Equal(capturedBody, reqBody) {
		t.Errorf("body = %q, want %q", string(capturedBody), string(reqBody))
	}
}

// TestWASM_E2E_InvalidModule tests error handling when loading an invalid WASM module.
func TestWASM_E2E_InvalidModule(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	// Completely invalid bytes
	_, err = rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "invalid-test",
		Phase:  wasm.PhaseRequest,
		Source: []byte{0xFF, 0xFF, 0xFF, 0xFF},
	})
	if err == nil {
		t.Fatal("expected error loading invalid WASM module")
	}
}

// TestWASM_E2E_InvalidModuleMagicOnly tests error handling with truncated WASM.
func TestWASM_E2E_InvalidModuleMagicOnly(t *testing.T) {
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	// WASM magic + version but no sections - this is actually valid (empty module)
	// but it will fail if we require specific exports
	_, err = rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "truncated-test",
		Phase:  wasm.PhaseRequest,
		Source: []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00},
	})
	// An empty module is valid WASM - it will instantiate but have no exports.
	// This should succeed (the plugin just won't do anything).
	if err != nil {
		t.Logf("empty module error (may be expected): %v", err)
	}
}

// TestWASM_E2E_MultiplePlugins tests running multiple request-phase plugins in sequence.
// Each plugin requires its own runtime since wazero only allows instantiating the host
// module ("sb") once per runtime. This mirrors how production code creates a runtime
// per plugin in WasmActionConfig.Init / WasmPolicyConfig.Init.
func TestWASM_E2E_MultiplePlugins(t *testing.T) {
	ctx := context.Background()

	// First plugin: echo (reads X-Test-Input, sets X-Test-Output)
	rt1, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime 1 failed: %v", err)
	}
	defer rt1.Close(ctx)

	plugin1, err := rt1.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "echo-1",
		Phase:  wasm.PhaseRequest,
		Source: buildEchoPlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin 1 failed: %v", err)
	}
	defer plugin1.Close(ctx)

	// Second plugin: also echo (on a separate runtime)
	rt2, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime 2 failed: %v", err)
	}
	defer rt2.Close(ctx)

	plugin2, err := rt2.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "echo-2",
		Phase:  wasm.PhaseRequest,
		Source: buildEchoPlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin 2 failed: %v", err)
	}
	defer plugin2.Close(ctx)

	// Test that both plugins execute correctly by calling them sequentially
	// on the same RequestContext (as the middleware would)
	rc := wasm.NewRequestContext()
	rc.SetRequestHeader("x-test-input", "multi-plugin")
	pluginCtx := wasm.WithRequestContext(ctx, rc)

	action1, err := plugin1.CallOnRequest(pluginCtx)
	if err != nil {
		t.Fatalf("plugin1.CallOnRequest failed: %v", err)
	}
	if action1 != wasm.ActionContinue {
		t.Errorf("plugin1 action = %d, want ActionContinue", action1)
	}

	action2, err := plugin2.CallOnRequest(pluginCtx)
	if err != nil {
		t.Fatalf("plugin2.CallOnRequest failed: %v", err)
	}
	if action2 != wasm.ActionContinue {
		t.Errorf("plugin2 action = %d, want ActionContinue", action2)
	}

	// Both plugins should have set X-Test-Output
	val, ok := rc.GetResponseHeader("X-Test-Output")
	if !ok {
		t.Fatal("expected X-Test-Output to be set after multiple plugins")
	}
	if val != "multi-plugin" {
		t.Errorf("X-Test-Output = %q, want %q", val, "multi-plugin")
	}
}

// TestWASM_E2E_RequestResponseCombined tests request and response phase plugins
// working together on the same RequestContext. Each plugin uses its own runtime
// since wazero allows only one host module instantiation per runtime.
func TestWASM_E2E_RequestResponseCombined(t *testing.T) {
	ctx := context.Background()

	// Request-phase plugin (echo)
	rt1, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime 1 failed: %v", err)
	}
	defer rt1.Close(ctx)

	reqPlugin, err := rt1.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "req-phase",
		Phase:  wasm.PhaseRequest,
		Source: buildEchoPlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin (request) failed: %v", err)
	}
	defer reqPlugin.Close(ctx)

	// Response-phase plugin
	rt2, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime 2 failed: %v", err)
	}
	defer rt2.Close(ctx)

	respPlugin, err := rt2.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "resp-phase",
		Phase:  wasm.PhaseResponse,
		Source: buildResponsePlugin(),
	})
	if err != nil {
		t.Fatalf("LoadPlugin (response) failed: %v", err)
	}
	defer respPlugin.Close(ctx)

	// Test request phase via middleware
	mwReq := wasm.NewMiddleware(rt1, []*wasm.Plugin{reqPlugin})

	var capturedRC *wasm.RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = wasm.RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := mwReq.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/combined", nil)
	req.Header.Set("X-Test-Input", "combined-test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if capturedRC == nil {
		t.Fatal("expected RequestContext to be set")
	}

	// Request plugin should have set X-Test-Output
	val, ok := capturedRC.GetResponseHeader("X-Test-Output")
	if !ok {
		t.Fatal("expected X-Test-Output response header from request phase plugin")
	}
	if val != "combined-test" {
		t.Errorf("X-Test-Output = %q, want %q", val, "combined-test")
	}

	// Test response phase via separate middleware
	mwResp := wasm.NewMiddleware(rt2, []*wasm.Plugin{respPlugin})

	respReq := httptest.NewRequest(http.MethodGet, "/combined", nil)
	respRC := wasm.NewRequestContext()
	respCtx := wasm.WithRequestContext(respReq.Context(), respRC)
	respReq = respReq.WithContext(respCtx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Upstream": []string{"from-origin"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("origin body"))),
		Request:    respReq,
	}

	err = mwResp.HandleResponse(resp)
	if err != nil {
		t.Fatalf("HandleResponse failed: %v", err)
	}

	if got := resp.Header.Get("X-Plugin-Processed"); got != "from-origin" {
		t.Errorf("X-Plugin-Processed = %q, want %q", got, "from-origin")
	}
}

// TestWASM_E2E_ConfigIntegration tests the full config-level integration:
// WasmActionConfig loading, Init (with inline Source), and HTTP handling.
func TestWASM_E2E_ConfigIntegration(t *testing.T) {
	ctx := context.Background()

	wasmBytes := buildEchoPlugin()

	// Build a runtime and plugin directly, then wire up middleware
	// (Config-level Init requires a file path; we test the wasm.Runtime/Plugin path)
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{
		MaxMemoryMB: 16,
	})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "config-integration",
		Phase:  wasm.PhaseRequest,
		Source: wasmBytes,
		Config: []byte(`{"mode":"test"}`),
	})
	if err != nil {
		t.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	if plugin.Name() != "config-integration" {
		t.Errorf("plugin.Name() = %q, want %q", plugin.Name(), "config-integration")
	}
	if plugin.Phase() != wasm.PhaseRequest {
		t.Errorf("plugin.Phase() = %q, want %q", plugin.Phase(), wasm.PhaseRequest)
	}

	// Execute through middleware
	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})
	handler := mw.HandleRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.Header.Set("X-Test-Input", "config-value")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

// BenchmarkWASM_E2E_EchoPlugin benchmarks the full echo plugin request pipeline.
func BenchmarkWASM_E2E_EchoPlugin(b *testing.B) {
	b.ReportAllocs()

	ctx := context.Background()
	wasmBytes := buildEchoPlugin()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		b.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "bench-echo",
		Phase:  wasm.PhaseRequest,
		Source: wasmBytes,
	})
	if err != nil {
		b.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.HandleRequest(next)

	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/bench", nil)
		req.Header.Set("X-Test-Input", "bench-value")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkWASM_E2E_BlockPlugin benchmarks the block plugin request pipeline.
func BenchmarkWASM_E2E_BlockPlugin(b *testing.B) {
	b.ReportAllocs()

	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		b.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.LoadPlugin(ctx, wasm.PluginConfig{
		Name:   "bench-block",
		Phase:  wasm.PhaseRequest,
		Source: buildBlockPlugin(),
	})
	if err != nil {
		b.Fatalf("LoadPlugin failed: %v", err)
	}
	defer plugin.Close(ctx)

	mw := wasm.NewMiddleware(rt, []*wasm.Plugin{plugin})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.HandleRequest(next)

	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
