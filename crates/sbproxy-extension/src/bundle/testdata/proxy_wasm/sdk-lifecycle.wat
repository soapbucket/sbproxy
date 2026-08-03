(module
  (memory (export "memory") 1)
  (global $factory-ready (mut i32) (i32.const 0))
  (global $root-context-id (mut i32) (i32.const 0))

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    i32.const 1024)

  ;; The Rust SDK installs its root-context factory during `_initialize`.
  (func (export "_initialize")
    i32.const 1
    global.set $factory-ready)

  ;; Mirror the SDK dispatcher: a root context becomes addressable only after
  ;; `proxy_on_context_create(root_id, 0)` has inserted it into the root map.
  (func (export "proxy_on_context_create") (param $context-id i32) (param $parent-id i32)
    local.get $parent-id
    i32.eqz
    if
      global.get $factory-ready
      i32.eqz
      if
        unreachable
      end
      local.get $context-id
      global.set $root-context-id
    else
      local.get $parent-id
      global.get $root-context-id
      i32.ne
      if
        unreachable
      end
    end)

  ;; The SDK's `proxy_on_vm_start` traps when the supplied root context has
  ;; not already been created.
  (func (export "proxy_on_vm_start") (param $context-id i32) (param i32) (result i32)
    local.get $context-id
    i32.eqz
    if
      unreachable
    end
    local.get $context-id
    global.get $root-context-id
    i32.ne
    if
      unreachable
    end
    i32.const 1)

  (func (export "proxy_on_configure") (param $context-id i32) (param i32) (result i32)
    local.get $context-id
    global.get $root-context-id
    i32.ne
    if
      unreachable
    end
    i32.const 1))
