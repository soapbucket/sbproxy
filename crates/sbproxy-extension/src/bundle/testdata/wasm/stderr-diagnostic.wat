;; Envelope policy hook that writes two diagnostic lines to stderr
;; before releasing the request. Fixture for WOR-2364 §1: the bundle
;; path used to hand the guest a sink, so a hook could not tell the
;; operator anything about the decision it had just made.
;;
;; Rebuild with:
;;     wat2wasm stderr-diagnostic.wat -o stderr-diagnostic.wasm
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "checking the allow list\0amatched rule 7\0a")
  (data (i32.const 2048) "{\22version\22:\22sbproxy-envelope/v1\22,\22decision\22:\22release\22}")
  (func (export "_start")
    ;; iovec for stderr: 39 bytes at offset 1024
    i32.const 0 i32.const 1024 i32.store
    i32.const 4 i32.const 39 i32.store
    i32.const 2 i32.const 0 i32.const 1 i32.const 16 call $fd_write drop
    ;; iovec for stdout: 54 bytes at offset 2048
    i32.const 0 i32.const 2048 i32.store
    i32.const 4 i32.const 54 i32.store
    i32.const 1 i32.const 0 i32.const 1 i32.const 16 call $fd_write drop))
