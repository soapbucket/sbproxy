(module
  (memory (export "memory") 1)
  (table 1 funcref)
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024)
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    ref.null func
    i32.const 10000
    table.grow
    drop
    i32.const 0))
