(module
  (memory (export "memory") 1)
  (table 10001 funcref)
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024))
