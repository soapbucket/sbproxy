(module
  (import "env" "proxy_http_call"
    (func $proxy_http_call
      (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    i32.const 1024))
