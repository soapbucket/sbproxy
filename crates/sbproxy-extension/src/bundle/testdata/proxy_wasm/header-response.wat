(module
  (import "env" "proxy_send_local_response"
    (func $local-response
      (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 32) "local")

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    i32.const 1024)

  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
    i32.const 403
    i32.const 0
    i32.const 0
    i32.const 32
    i32.const 5
    i32.const 0
    i32.const 0
    i32.const -1
    call $local-response
    drop
    i32.const 1))
