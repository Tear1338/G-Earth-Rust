var Module=typeof unityFramework!="undefined"?unityFramework:{};
var wasmImports={original_noop:fixtureNoop};
function createWasm(){Module.asm=fixtureInstantiate(wasmImports);Module.HEAPU8=new Uint8Array(Module.asm.memory.buffer);return Module.asm;}
var asm=createWasm();
var _malloc=fixtureMalloc;
var _free=fixtureFree;
