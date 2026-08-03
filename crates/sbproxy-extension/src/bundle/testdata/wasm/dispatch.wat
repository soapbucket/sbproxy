(module
  (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8192) "{\22version\22:\22sbproxy-envelope/v1\22,\22decision\22:\22deny\22,\22status\22:403,\22message\22:\22upgrade required\22}")
  (data (i32.const 12288) "{\22version\22:\22sbproxy-envelope/v1\22,\22body_base64\22:\22cmVwbGFjZWQ=\22}")
  (func $write (param $ptr i32) (param $len i32)
    i32.const 16
    local.get $ptr
    i32.store
    i32.const 20
    local.get $len
    i32.store
    i32.const 1
    i32.const 16
    i32.const 1
    i32.const 24
    call $fd_write
    drop)
  (func $is_transform (param $length i32) (result i32)
    (local $i i32)
    (block $not_found
      (loop $scan
        local.get $i
        local.get $length
        i32.const 9
        i32.sub
        i32.ge_u
        br_if $not_found
        local.get $i
        i32.const 1024
        i32.add
        i32.load8_u
        i32.const 116
        i32.eq
        (if
          (then
            local.get $i
            i32.const 1025
            i32.add
            i32.load8_u
            i32.const 114
            i32.eq
            local.get $i
            i32.const 1026
            i32.add
            i32.load8_u
            i32.const 97
            i32.eq
            i32.and
            local.get $i
            i32.const 1027
            i32.add
            i32.load8_u
            i32.const 110
            i32.eq
            i32.and
            local.get $i
            i32.const 1028
            i32.add
            i32.load8_u
            i32.const 115
            i32.eq
            i32.and
            (if
              (then i32.const 1 return))))
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $scan))
    i32.const 0)
  (func (export "_start")
    i32.const 0
    i32.const 1024
    i32.store
    i32.const 4
    i32.const 4096
    i32.store
    i32.const 0
    i32.const 0
    i32.const 1
    i32.const 8
    call $fd_read
    drop
    i32.const 8
    i32.load
    call $is_transform
    (if
      (then i32.const 12288 i32.const 62 call $write)
      (else i32.const 8192 i32.const 93 call $write))))
