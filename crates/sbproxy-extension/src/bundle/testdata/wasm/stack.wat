(module
  (memory (export "memory") 1)
  (func $recurse
    call $recurse)
  (func (export "_start")
    call $recurse))
