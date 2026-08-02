(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $calls (mut i32) (i32.const 0))
  (data (i32.const 1024) "{\22version\22:\22sbproxy-envelope/v1\22,\22decision\22:\22allow\22}")
  (func (export "_start")
    global.get $calls
    i32.eqz
    (if
      (then
        i32.const 1 global.set $calls
        i32.const 0 i32.const 1024 i32.store
        i32.const 4 i32.const 52 i32.store
        i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $fd_write drop))))
