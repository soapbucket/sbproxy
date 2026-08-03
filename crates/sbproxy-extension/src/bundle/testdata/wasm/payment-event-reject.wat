(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\22version\22:\22sbproxy-envelope/v1\22,\22decision\22:\22reject\22}")
  (func (export "_start")
    i32.const 16
    i32.const 1024
    i32.store
    i32.const 20
    i32.const 53
    i32.store
    i32.const 1
    i32.const 16
    i32.const 1
    i32.const 24
    call $fd_write
    drop))
