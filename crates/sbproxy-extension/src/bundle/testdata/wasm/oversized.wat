(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 1024 i32.const 120 i32.const 257 memory.fill
    i32.const 0 i32.const 1024 i32.store
    i32.const 4 i32.const 257 i32.store
    i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $fd_write drop))
