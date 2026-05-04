;; echo.wat — minimal WASI module that copies stdin to stdout.
;;
;; This is the test fixture for the `WasmRuntime` unit tests in
;; sbproxy-extension/src/wasm/mod.rs. It is hand-written WAT so the
;; build pipeline does not need a wasm32-wasi toolchain. To regenerate
;; the .wasm after editing this file:
;;
;;     wat2wasm echo.wat -o echo.wasm
;;
;; A "real" example WASM module that ships in `examples/wasm/echo-rust/`
;; (Rust source, build via cargo + wasm32-wasi target) is the same
;; behaviour written more idiomatically; this WAT version is purely a
;; build-system convenience for the unit tests.

(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Memory layout (offsets):
  ;;   0  : read iov  { buf_ptr=64, buf_len=4096 }
  ;;   16 : nread out
  ;;   32 : write iov { buf_ptr=64, buf_len=<nread> }
  ;;   48 : nwritten out
  ;;   64+: data buffer (4 KiB)
  (func (export "_start")
    (local $n i32)

    ;; Initialise the read iov once. buf_ptr=64, buf_len=4096.
    (i32.store (i32.const 0) (i32.const 64))
    (i32.store (i32.const 4) (i32.const 4096))

    (block $done
      (loop $read_loop
        ;; Read from stdin (fd 0).
        (drop
          (call $fd_read
            (i32.const 0)    ;; fd: stdin
            (i32.const 0)    ;; iovs_ptr
            (i32.const 1)    ;; iovs_len
            (i32.const 16)   ;; nread_ptr
          ))

        ;; n = bytes read
        (local.set $n (i32.load (i32.const 16)))

        ;; EOF -> done
        (br_if $done (i32.eqz (local.get $n)))

        ;; Set up the write iov to point at the same buffer with
        ;; length n (the bytes we just read).
        (i32.store (i32.const 32) (i32.const 64))
        (i32.store (i32.const 36) (local.get $n))

        ;; Write to stdout (fd 1).
        (drop
          (call $fd_write
            (i32.const 1)    ;; fd: stdout
            (i32.const 32)   ;; iovs_ptr
            (i32.const 1)    ;; iovs_len
            (i32.const 48)   ;; nwritten_ptr
          ))

        (br $read_loop)
      )
    )
  )
)
