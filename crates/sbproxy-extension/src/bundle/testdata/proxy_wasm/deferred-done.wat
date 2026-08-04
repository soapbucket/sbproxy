(module
  (import "env" "proxy_done" (func $done (result i32)))

  (memory (export "memory") 1)

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024)

  (func (export "proxy_on_context_create") (param i32 i32))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_configure") (param i32 i32) (result i32)
    i32.const 1)

  ;; The HTTP context defers teardown. The root context completes immediately.
  (func (export "proxy_on_done") (param $context-id i32) (result i32)
    local.get $context-id
    i32.const 2
    i32.ne)
  (func (export "proxy_on_log") (param i32))
  (func (export "proxy_on_delete") (param i32))

  ;; Model an SDK callback that completes deferred work and calls proxy_done.
  (func (export "complete_pending")
    call $done
    if
      unreachable
    end))
