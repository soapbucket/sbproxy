;; Envelope policy that declares the ABI it was built against, for a major this host does not serve.
;;
;; The major version is in the export NAME, so a host can read it with
;; `wasm-objdump -x` before instantiating. See `module_abi_declaration`
;; for why this is not an i32 global the way OPA does it.
;;
;;     wat2wasm abi-v1.wat -o abi-v1.wasm
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global (export "sbproxy_envelope_abi_v9") i32 (i32.const 1))
  (data (i32.const 1024) "{\22version\22:\22sbproxy-envelope/v1\22,\22decision\22:\22release\22}")
  (func (export "_start")
    i32.const 0 i32.const 1024 i32.store
    i32.const 4 i32.const 54 i32.store
    i32.const 1 i32.const 0 i32.const 1 i32.const 16 call $fd_write drop))
