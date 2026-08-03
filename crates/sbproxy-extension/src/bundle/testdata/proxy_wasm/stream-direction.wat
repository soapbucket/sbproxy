(module
  (import "env" "proxy_continue_stream" (func $continue (param i32) (result i32)))
  (import "env" "proxy_close_stream" (func $close (param i32) (result i32)))

  (memory (export "memory") 1)

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024)
  (func (export "proxy_on_context_create") (param i32 i32))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_configure") (param i32 i32) (result i32)
    i32.const 1)

  ;; Continuing the response must not override this request pause.
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    i32.const 1
    call $continue
    if
      unreachable
    end
    i32.const 1)

  ;; The response consumes the continue requested by request headers.
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
    i32.const 1)

  ;; Closing the response must not close the current request callback.
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32)
    i32.const 1
    call $close
    if
      unreachable
    end
    i32.const 0)

  ;; The response consumes the close requested by request body.
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32)
    i32.const 0))
