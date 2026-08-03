(module
  (import "env" "proxy_log" (func $log (param i32 i32 i32) (result i32)))

  (memory (export "memory") 1)
  (data (i32.const 100) "message")

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024)
  (func (export "proxy_on_context_create") (param i32 i32))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_configure") (param i32 i32) (result i32)
    i32.const 1)

  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    i32.const 0 i32.const 100 i32.const 7 call $log drop
    i32.const 1 i32.const 100 i32.const 7 call $log drop
    i32.const 2 i32.const 100 i32.const 7 call $log drop
    i32.const 3 i32.const 100 i32.const 7 call $log drop
    i32.const 4 i32.const 100 i32.const 7 call $log drop
    i32.const 5 i32.const 100 i32.const 7 call $log drop
    i32.const 0))
