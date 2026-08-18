;; env_echo.wat - minimal WASI module that ignores stdin and writes the
;; first WASI environment variable's raw "KEY=VALUE" bytes to stdout.
;;
;; Test fixture for the opt-in per-request context channel on the wasm
;; transform (WOR-2493 item 5): it proves the environment variable the
;; host sets with `request_context: true` actually reaches the guest,
;; without needing a wasm32-wasi toolchain. Hand-written WAT, same
;; spirit as sbproxy-extension's echo.wat. Assumes at most one
;; environment variable is set (true for every caller in this
;; codebase); with exactly one var, WASI's environ_buf_size is the
;; length of "KEY=VALUE\0", so buf_size - 1 is the string length with
;; no NUL-scanning loop needed. To regenerate the .wasm after editing:
;;
;;     wat2wasm env_echo.wat -o env_echo.wasm
;;
;; Writes nothing to stdout when no environment variable is set.

(module
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $environ_sizes_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_get"
    (func $environ_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 4)

  ;; Memory layout (offsets):
  ;;    0 : environ_count (i32), from environ_sizes_get
  ;;    4 : environ_buf_size (i32), from environ_sizes_get
  ;;   32 : write iov { buf_ptr, buf_len }
  ;;   48 : nwritten out
  ;; 1024 : environ pointer array (environ_get fills this in)
  ;; 8192 : environ_buf, the raw "KEY=VALUE\0" bytes environ_get fills in
  (func (export "_start")
    (local $count i32)
    (local $buf_size i32)
    (local $first_ptr i32)

    (drop (call $environ_sizes_get (i32.const 0) (i32.const 4)))

    (local.set $count (i32.load (i32.const 0)))
    (if (i32.eqz (local.get $count)) (then (return)))

    (drop (call $environ_get (i32.const 1024) (i32.const 8192)))

    (local.set $buf_size (i32.load (i32.const 4)))
    (local.set $first_ptr (i32.load (i32.const 1024)))

    ;; With exactly one env var, buf_size counts "KEY=VALUE\0", so
    ;; buf_size - 1 is the string length without the trailing NUL.
    (i32.store (i32.const 32) (local.get $first_ptr))
    (i32.store (i32.const 36) (i32.sub (local.get $buf_size) (i32.const 1)))

    (drop (call $fd_write (i32.const 1) (i32.const 32) (i32.const 1) (i32.const 48)))
  )
)
