import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
const directory=process.argv[2];
for(const filename of process.argv.slice(3).length?process.argv.slice(3):['rust-patched.wasm']){
  const bytes=fs.readFileSync(path.join(directory,filename));
  assert.equal(WebAssembly.validate(bytes),true);
  const calls=[];
  const imports={env:{original_noop:()=>calls.push('original'),g_chacha_setkey:()=>calls.push('key'),g_chacha_returnbyte:(_state,value)=>{calls.push('byte');return value+1;},g_outgoing_packet:()=>calls.push('out'),g_incoming_packet:()=>calls.push('in')}};
  const {instance}=await WebAssembly.instantiate(bytes,imports);
  const e=instance.exports;
  assert.deepEqual(calls,['original']);calls.length=0;
  e.key(0,0,0,0);assert.deepEqual(calls,['key','original']);calls.length=0;
  assert.equal(e.byte(0,41,0),42);assert.deepEqual(calls,['byte']);calls.length=0;
  assert.equal(e._gearth_returnbyte_copy(0,41,0),41);assert.deepEqual(calls,[]);
  e.out(0,0,0);e.in(0,0,0,0,0);e.indirect();
  if(e.function_ref)e.function_ref.value(0,0,0);
  assert.deepEqual(calls,e.function_ref?['out','in','out','out']:['out','in','out']);calls.length=0;
  e._gearth_outgoing_copy(0,0,0);assert.deepEqual(calls,[]);
  e._gearth_incoming_copy(0,0,0,0,0);assert.deepEqual(calls,['original','original','original']);
  console.log(`${filename}: validated hooks, original bodies, import/export/table/global/start indices`);
}
