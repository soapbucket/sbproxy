(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\22version\22:\22sbproxy-envelope/v1\22,\22outcome\22:\22response\22,\22status\22:202,\22headers\22:[[\22content-type\22,\22text/plain\22]],\22body_base64\22:\22cXVldWVk\22}")
  (func (export "_start")
    i32.const 0 i32.const 1024 i32.store
    i32.const 4 i32.const 134 i32.store
    i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $fd_write drop))
