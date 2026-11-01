import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {setTimeout as pause} from 'node:timers/promises';

const directory=process.argv[2];
const wasm=new WebAssembly.Module(fs.readFileSync(path.join(directory,'client.wasm')));
const outgoing=[],incoming=[],allocated=new Set();
let exports,heap,next=8192,socket;
const nativeCopies={
  out(a,p,c){const size=new DataView(heap.buffer).getUint32(p+12,true);outgoing.push(Buffer.from(heap.slice(p+16,p+16+size)));return exports._gearth_outgoing_copy(a,p,c);},
  in(a,p,start,size,c){incoming.push(Buffer.from(heap.slice(p+16+start,p+16+start+size)));return exports._gearth_incoming_copy(a,p,start,size,c);}
};
class BrowserSocket extends WebSocket {constructor(url){super(url);socket=this;}}
const context=vm.createContext({WebSocket:BrowserSocket,TextEncoder,TextDecoder,console,Uint8Array,unityFramework:{},
  fixtureNoop(){},fixtureInstantiate(imports){exports=new WebAssembly.Instance(wasm,{env:imports}).exports;heap=new Uint8Array(exports.memory.buffer);return {...exports,_gearth_outgoing_copy:nativeCopies.out,_gearth_incoming_copy:nativeCopies.in};},
  fixtureMalloc(size){const p=next;next+=size+8;assert.ok(next<heap.length);allocated.add(p);return p;},
  fixtureFree(p){assert.equal(allocated.delete(p),true);}
});
vm.runInContext(fs.readFileSync(path.join(directory,'framework.js'),'utf8'),context,{timeout:5000});
async function wait(predicate,label){const deadline=Date.now()+7000;while(!predicate()){assert.ok(Date.now()<deadline,label);await pause(5);}}
await wait(()=>socket.readyState===WebSocket.OPEN,'communicator did not open');
function p(header,value){const bytes=Buffer.alloc(10);bytes.writeInt32BE(6);bytes.writeUInt16BE(header,4);bytes.writeInt32BE(value,6);return bytes;}
function nativeOut(bytes){const pointer=1024;heap.fill(0,pointer,pointer+16+bytes.length);new DataView(heap.buffer).setUint32(pointer+12,bytes.length,true);heap.set(bytes,pointer+16);exports.out(0,pointer,0);}
function nativeIn(bytes){const pointer=2048;heap.fill(0,pointer,pointer+16+bytes.length);heap.set(bytes,pointer+16);exports.in(0,pointer,0,bytes.length,0);}
function find(list,header){return list.find(bytes=>bytes.length>=6&&bytes.readUInt16BE(4)===header);}
const first=Buffer.from('ignored'),id=Buffer.from('UNITY-FIXTURE');const hello=Buffer.alloc(10+first.length+id.length);hello.writeInt32BE(hello.length-4);hello.writeUInt16BE(4000,4);hello.writeUInt16BE(first.length,6);first.copy(hello,8);hello.writeUInt16BE(id.length,8+first.length);id.copy(hello,10+first.length);
nativeOut(hello);await wait(()=>find(outgoing,4000),'hello was not reinjected');assert.deepEqual(find(outgoing,4000),hello);
nativeOut(p(77,13));nativeOut(p(78,41));await wait(()=>find(outgoing,78),'replacement was not reinjected');assert.equal(find(outgoing,78).readInt32BE(6),42);assert.equal(find(outgoing,77),undefined);
nativeIn(p(88,17));await wait(()=>find(incoming,88),'incoming packet was not reinjected');assert.deepEqual(find(incoming,88),p(88,17));
nativeOut(p(90,1));await wait(()=>find(outgoing,79)&&find(incoming,89),'server injections were not reinjected');assert.deepEqual(find(outgoing,79),p(79,99));assert.deepEqual(find(incoming,89),p(89,33));assert.equal(allocated.size,0);
socket.close();await wait(()=>socket.readyState===WebSocket.CLOSED,'communicator did not close');await pause(10);
nativeOut(p(99,7));assert.deepEqual(find(outgoing,99),p(99,7));assert.equal(allocated.size,0);
console.log('Unity WASM + browser hooks + authenticated WSS + Rust rules + bidirectional injection + disconnect fallback passed');
