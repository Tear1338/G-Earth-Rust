(module
  (type $void (func))
  (type $key (func (param i32 i32 i32 i32)))
  (type $byte (func (param i32 i32 i32) (result i32)))
  (type $out (func (param i32 i32 i32)))
  (type $in (func (param i32 i32 i32 i32 i32)))
  (import "env" "original_noop" (func $noop (type $void)))
  (memory (export "memory") 1)
  (table 1 funcref)
  (elem (i32.const 0) $outgoing)
  (global (export "function_ref") funcref (ref.func $outgoing))
  (func $consume (param i32 i32 i32 i32 i32 i32) call $noop)
  (func $keyfn (export "key") (type $key)
    local.get 0 if nop end
    local.get 0 i32.const 0 local.get 1 i32.load align=4
    i32.const 0 i32.const 0 i32.const 0 call $consume)
  (func $returnbyte (export "byte") (type $byte) (local i32)
    i32.const 0 local.set 3 i32.const 0 drop i32.const 0 drop nop
    block (result i32) i32.const 1 i32.const 2 i32.xor end drop
    nop nop nop nop nop nop nop nop nop nop nop local.get 1)
  (func $outgoing (export "out") (type $out)
    local.get 0 i32.load8_u offset=30 align=1 if nop end)
  (func $incoming (export "in") (type $in) (local i32 i32 i32 i32 i32)
    i32.const 0 i32.load8_u i32.eqz if call $noop call $noop call $noop end
    i32.const 0 i32.load align=4 local.set 5
    block (result i32) i32.const 0 end local.set 6
    local.get 0 local.get 1 local.get 2 local.get 3 local.get 4 i32.load
    drop drop drop drop drop)
  (func (export "indirect") i32.const 0 i32.const 0 i32.const 0 i32.const 0 call_indirect (type $out))
  (func $start call $noop)
  (start $start)
)
