;; echo_plugin.wat - SoapBucket WASM test plugin
;;
;; This plugin reads the X-Test-Input request header and copies its value
;; to an X-Test-Output response header. It also logs a message via sb_log.
;;
;; To compile (requires wabt toolkit):
;;   wat2wasm echo_plugin.wat -o echo_plugin.wasm
;;
;; Since wat2wasm may not be available, the e2e test builds equivalent
;; modules programmatically using raw WASM binary encoding.

(module
  ;; Import host functions from the "sb" module
  (import "sb" "sb_get_request_header" (func $sb_get_request_header (param i32 i32) (result i32 i32)))
  (import "sb" "sb_set_response_header" (func $sb_set_response_header (param i32 i32 i32 i32)))
  (import "sb" "sb_log" (func $sb_log (param i32 i32 i32)))

  ;; Memory: 1 page (64KB)
  (memory (export "memory") 1)

  ;; Bump allocator pointer (starts at 1024 to leave room for static data)
  (global $bump_ptr (mut i32) (i32.const 1024))

  ;; Static data
  ;; "X-Test-Input" at offset 0 (12 bytes)
  (data (i32.const 0) "X-Test-Input")
  ;; "X-Test-Output" at offset 16 (13 bytes)
  (data (i32.const 16) "X-Test-Output")
  ;; "echo plugin executed" at offset 32 (20 bytes)
  (data (i32.const 32) "echo plugin executed")

  ;; sb_malloc: bump allocator for host-to-guest memory transfers
  ;; param: size (i32)
  ;; result: pointer (i32)
  (func $sb_malloc (export "sb_malloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump_ptr))
    (global.set $bump_ptr (i32.add (global.get $bump_ptr) (local.get $size)))
    (local.get $ptr)
  )

  ;; sb_on_request: reads X-Test-Input, sets X-Test-Output, logs a message
  ;; result: 0 (ActionContinue)
  (func $sb_on_request (export "sb_on_request") (result i32)
    (local $val_ptr i32)
    (local $val_len i32)

    ;; Get X-Test-Input header (name at offset 0, length 12)
    (call $sb_get_request_header (i32.const 0) (i32.const 12))
    (local.set $val_len)
    (local.set $val_ptr)

    ;; If header was found (ptr != 0), set X-Test-Output with same value
    (if (local.get $val_ptr)
      (then
        ;; Set X-Test-Output (name at offset 16, length 13) with the header value
        (call $sb_set_response_header
          (i32.const 16) (i32.const 13)
          (local.get $val_ptr) (local.get $val_len)
        )
      )
    )

    ;; Log: level=1 (info), message at offset 32, length 20
    (call $sb_log (i32.const 1) (i32.const 32) (i32.const 20))

    ;; Return ActionContinue (0)
    (i32.const 0)
  )

  ;; sb_on_response: no-op, returns ActionContinue
  (func $sb_on_response (export "sb_on_response") (result i32)
    (i32.const 0)
  )
)
