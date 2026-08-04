(module
  (import "env" "proxy_set_buffer_bytes"
    (func $set_buffer (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "123456789")
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32) i32.const 1024)
  (func (export "proxy_on_configure") (param i32 i32) (result i32) i32.const 1)
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32)
    i32.const 0 i32.const 0 i32.const 0 i32.const 100 i32.const 9
    call $set_buffer drop
    i32.const 0))
