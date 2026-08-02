(module
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 32
    memory.grow
    drop))
