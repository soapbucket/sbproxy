(module
  (memory (export "memory") 1)
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024)
  (func $recurse
    call $recurse)
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    call $recurse
    i32.const 0))
