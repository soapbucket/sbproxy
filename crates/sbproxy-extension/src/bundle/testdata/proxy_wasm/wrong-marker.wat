(module
  (memory (export "memory") 1)
  (func (export "proxy_abi_version_0_2_1") (param i32))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024))
