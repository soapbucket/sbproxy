(module
  (import "env" "proxy_add_header_map_value"
    (func $add-header (param i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (data (i32.const 100) "x-extension-filter")
  (data (i32.const 120) "proxy-wasm")

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $result i32)
    global.get $next
    local.tee $result
    local.get $size
    i32.add
    global.set $next
    local.get $result)

  (func (export "proxy_on_context_create") (param i32 i32))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_configure") (param i32 i32) (result i32)
    i32.const 1)

  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    i32.const 0)
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32)
    i32.const 0)
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
    i32.const 2
    i32.const 100
    i32.const 18
    i32.const 120
    i32.const 10
    call $add-header
    drop
    i32.const 0)

  (func (export "proxy_on_done") (param i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_delete") (param i32)))
