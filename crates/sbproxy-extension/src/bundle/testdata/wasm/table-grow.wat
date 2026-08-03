(module
  (table 1 20000 funcref)

  (func (export "_start")
    ref.null func
    i32.const 10000
    table.grow
    drop))
