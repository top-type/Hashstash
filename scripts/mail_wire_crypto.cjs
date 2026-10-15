'use strict';
// Test-only bridge: exercises the browser bundle with published fixture keys.
// No browser storage, networking, user wallet files or signing are involved.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..'),request=JSON.parse(fs.readFileSync(0,'utf8'));
const fixture=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/mail-v2.json'),'utf8'));
const c=vm.createContext({Uint8Array,TextEncoder,TextDecoder,isSecureContext:true,crypto:webcrypto,fetch(){throw Error('Network forbidden in crypto fixture');}});
for(const file of ['ui/vendor/noble.js','ui/mail-crypto.js'])vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),c);
async function run(){
  if(request.mode==='encrypt')return {data_hex:await c.HashstashMailCrypto.encrypt(request.plaintext,request.identity)};
  if(request.mode==='decrypt'){
    if(!Object.values(fixture.private_keys).includes(request.private_key))throw Error('Only published test fixture scalars are accepted');
    return await c.HashstashMailCrypto.decrypt(request.data_hex,request.identity,request.private_key);
  }
  throw Error('Unsupported fixture mode');
}
run().then(result=>process.stdout.write(JSON.stringify(result)+'\n')).catch(error=>{console.error(error.message);process.exitCode=1;});
