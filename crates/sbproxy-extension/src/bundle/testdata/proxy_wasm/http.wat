(module
  (import "env" "proxy_get_buffer_bytes"
    (func $get_buffer (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_set_buffer_bytes"
    (func $set_buffer (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_get_header_map_value"
    (func $get_header (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_add_header_map_value"
    (func $add_header (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_replace_header_map_value"
    (func $replace_header (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_continue_stream" (func $continue (param i32) (result i32)))
  (import "env" "proxy_close_stream" (func $close (param i32) (result i32)))
  (import "env" "proxy_send_local_response"
    (func $local_response
      (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_log" (func $log (param i32 i32 i32) (result i32)))

  (memory (export "memory") 2)
  (global $next (mut i32) (i32.const 4096))
  (data (i32.const 100) "x-input")
  (data (i32.const 110) "x-seen")
  (data (i32.const 120) "x-block")
  (data (i32.const 130) "x-pause")
  (data (i32.const 140) "x-continue")
  (data (i32.const 152) "x-close")
  (data (i32.const 160) "x-response")
  (data (i32.const 172) "filtered")
  (data (i32.const 180) "blocked")
  (data (i32.const 200)
    "\01\00\00\00\0c\00\00\00\0a\00\00\00content-type\00text/plain\00")
  (data (i32.const 240) "done")

  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $result i32)
    global.get $next
    local.tee $result
    local.get $size
    i32.add
    global.set $next
    local.get $result)

  (func (export "proxy_on_context_create") (param i32 i32))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_configure") (param i32 i32) (result i32)
    i32.const 7
    i32.const 0
    i32.const -1
    i32.const 0
    i32.const 4
    call $get_buffer
    drop
    i32.const 4
    i32.load
    i32.const 0
    i32.gt_u)

  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    i32.const 0 i32.const 152 i32.const 7 i32.const 0 i32.const 4
    call $get_header
    i32.eqz
    if
      i32.const 0 call $close drop
      i32.const 1 return
    end
    i32.const 0 i32.const 140 i32.const 10 i32.const 0 i32.const 4
    call $get_header
    i32.eqz
    if
      i32.const 0 call $continue drop
      i32.const 1 return
    end
    i32.const 0 i32.const 130 i32.const 7 i32.const 0 i32.const 4
    call $get_header
    i32.eqz
    if
      i32.const 1 return
    end
    i32.const 0 i32.const 120 i32.const 7 i32.const 0 i32.const 4
    call $get_header
    i32.eqz
    if
      i32.const 403 i32.const 0 i32.const 0 i32.const 180 i32.const 7
      i32.const 200 i32.const 36 i32.const -1
      call $local_response drop
      i32.const 1 return
    end
    i32.const 0 i32.const 100 i32.const 7 i32.const 0 i32.const 4
    call $get_header
    i32.eqz
    if
      i32.const 0 i32.const 110 i32.const 6
      i32.const 0 i32.load
      i32.const 4 i32.load
      call $replace_header drop
    end
    i32.const 0)

  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32)
    i32.const 0 i32.const 0 i32.const -1 i32.const 0 i32.const 4
    call $get_buffer
    i32.eqz
    if
      i32.const 0 i32.const 0 i32.const -1
      i32.const 0 i32.load
      i32.const 4 i32.load
      call $set_buffer drop
    end
    i32.const 0)

  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
    i32.const 2 i32.const 160 i32.const 10 i32.const 172 i32.const 8
    call $add_header drop
    i32.const 0)

  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32)
    i32.const 1 i32.const 0 i32.const -1 i32.const 172 i32.const 8
    call $set_buffer drop
    i32.const 0)

  (func (export "proxy_on_done") (param i32) (result i32)
    i32.const 1)
  (func (export "proxy_on_log") (param i32)
    i32.const 2 i32.const 240 i32.const 4 call $log drop)
  (func (export "proxy_on_delete") (param i32)))
