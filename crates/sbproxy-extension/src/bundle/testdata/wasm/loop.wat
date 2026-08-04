(module
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $forever br $forever)))
