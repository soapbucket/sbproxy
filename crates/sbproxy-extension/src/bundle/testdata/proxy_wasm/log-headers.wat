(module
  (import "env" "proxy_get_header_map_value"
    (func $get-header (param i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (data (i32.const 100) "x-request")
  (data (i32.const 112) "x-response")

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
  (func (export "proxy_on_done") (param i32) (result i32)
    i32.const 1)

  ;; Request and response maps remain readable until the HTTP context logs.
  (func (export "proxy_on_log") (param $context-id i32)
    local.get $context-id
    i32.const 2
    i32.eq
    if
      i32.const 0
      i32.const 100
      i32.const 9
      i32.const 0
      i32.const 4
      call $get-header
      if
        unreachable
      end

      i32.const 2
      i32.const 112
      i32.const 10
      i32.const 0
      i32.const 4
      call $get-header
      if
        unreachable
      end
    end)
  (func (export "proxy_on_delete") (param i32)))
