'use strict';
// Published, deterministic fixture keys only. This suite never makes network calls.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {webcrypto}=require('node:crypto');const root=path.resolve(__dirname,'..');let checks=0;
const eq=(a,b)=>{assert.deepEqual(a,b);checks++;},ok=a=>{assert.ok(a);checks++;};
const fail=async(f,p=/./)=>{await assert.rejects(f,p);checks++;};
const c=vm.createContext({Uint8Array,TextEncoder,TextDecoder,crypto:webcrypto,isSecureContext:true,console,fetch(){throw Error('No network allowed');}});
for(const file of ['ui/vendor/noble.js','ui/mail-crypto.js'])vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),c);
const api=c.HashstashMailCrypto,noble=c.HashstashNoble;
const key=n=>BigInt(n).toString(16).padStart(64,'0'),bytes=s=>Uint8Array.from(Buffer.from(s,'hex')),pub=s=>Buffer.from(noble.schnorr.getPublicKey(bytes(s))).toString('hex');
const order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const a=key(1),b=key(6),other=key(3),chain='27'.repeat(32),identity={chain_id:chain,sender:pub(a),recipient:pub(b),nonce:'18446744073709551615'};
const publicContext={chain_id:chain,sender:pub(a),nonce:identity.nonce};
const plain={subject:'A public fixture',body:'Local encrypted content.\nUnicode: café ☀'};
const expected={recipient:identity.recipient,...plain};
const encode=e=>Buffer.from(api.PREFIX+JSON.stringify(e)).toString('hex');
const obj=x=>JSON.parse(JSON.stringify(x));
async function run(){
  const envelope=await api.encrypt(plain,identity),e=api.parse(envelope);
  eq(obj(await api.decrypt(envelope,publicContext,b)),expected);eq(obj(await api.decrypt(envelope,publicContext,a)),expected);
  // A key in 32 bytes opens it too, so a wallet need not make a hex string;
  // the caller's bytes are its own to wipe.
  {
    const raw=bytes(b);eq(obj(await api.decrypt(envelope,publicContext,raw)),expected);eq(Buffer.from(raw).toString('hex'),b);
    for(const bad of [bytes(b).subarray(1),new Uint16Array(32),[...bytes(b)],null])await fail(()=>api.decrypt(envelope,publicContext,bad),/Invalid private key/);
  }
  // The alternate representative n-d has the same BIP340 x-only identity.
  eq(obj(await api.decrypt(envelope,publicContext,key(order-6n))),expected);eq(obj(await api.decrypt(envelope,publicContext,key(order-1n))),expected);
  for(const i of [1n,2n,3n,4n,5n,6n,7n,8n,17n,31n]){
    const secret=bytes(key(i)),peer=bytes(pub(b)),copy=Buffer.from(secret);
    const shared=noble.ecdhXOnly(secret,peer),reverse=noble.ecdhXOnly(bytes(b),bytes(pub(key(i))));
    eq(Buffer.from(shared).toString('hex'),Buffer.from(reverse).toString('hex'));eq(Buffer.from(secret),copy);
  }
  ok(!envelope.includes(Buffer.from(plain.subject).toString('hex')));ok(envelope.length/2<=api.MAX_DATA_BYTES);
  ok(!Buffer.from(envelope,'hex').toString().includes(identity.recipient));eq(Buffer.from(e.ciphertext,'hex').length,1168);
  eq(Object.keys(e),['ephemeral_key','iv','ciphertext','recipient_iv','recipient_key','sender_iv','sender_key']);
  ok((await api.encrypt(plain,identity))!==envelope);
  const self={...identity,recipient:identity.sender};eq(obj(await api.decrypt(await api.encrypt(plain,self),publicContext,a)),{recipient:identity.sender,...plain});
  await fail(()=>api.decrypt(envelope,publicContext,other),/authentication/);
  for(const context of [{...publicContext,chain_id:'28'.repeat(32)},{...publicContext,nonce:'1'},{...publicContext,sender:pub(other)}])await fail(()=>api.decrypt(envelope,context,b),/authentication/);
  // No public recipient hint is accepted or required to select the private key.
  eq(obj(await api.decrypt(envelope,{...publicContext,recipient:pub(other)},b)),expected);
  for(const field of ['ephemeral_key','iv','ciphertext','recipient_iv','recipient_key']){
    const mutated={...e};mutated[field]=field==='ephemeral_key'?pub(other):(e[field][0]==='0'?'1':'0')+e[field].slice(1);
    await fail(()=>api.decrypt(encode(mutated),publicContext,b));
  }
  for(const field of ['sender_iv','sender_key']){const mutated={...e};mutated[field]=(e[field][0]==='0'?'1':'0')+e[field].slice(1);await fail(()=>api.decrypt(encode(mutated),publicContext,a));}
  const swapped={...e,recipient_iv:e.sender_iv,recipient_key:e.sender_key,sender_iv:e.recipient_iv,sender_key:e.recipient_key};
  for(const secret of [a,b])await fail(()=>api.decrypt(encode(swapped),publicContext,secret),/authentication/);
  const shuffled=Object.fromEntries(Object.entries(e).reverse());
  for(const bad of ['',envelope.slice(0,-2),envelope.toUpperCase(),encode({...e,extra:'x'}),encode(shuffled),encode({...e,ciphertext:'00'}),encode({...e,ciphertext:e.ciphertext.slice(2)}),encode({...e,ciphertext:e.ciphertext+'00'}),encode({...e,ephemeral_key:'ff'.repeat(32)}),Buffer.from(api.PREFIX+JSON.stringify(e,null,1)).toString('hex'),Buffer.from('hashstash.mail/1\n'+JSON.stringify(e)).toString('hex'),'ff'.repeat(3073)])await fail(()=>api.decrypt(bad,publicContext,b));
  for(const content of [{subject:'',body:'x'},{subject:'x',body:''},{subject:'é'.repeat(49),body:'x'},{subject:'x',body:'é'.repeat(385)},{subject:'x',body:'\ud800'},{subject:'x',body:'bad\u0000'},{subject:'x',body:'x',secret:'x'},{subject:'"'.repeat(96),body:'"'.repeat(768)}])await fail(()=>api.encrypt(content,identity));
  const boundary={subject:'é'.repeat(48),body:'é'.repeat(384)};const boundaryEnvelope=await api.encrypt(boundary,identity);eq(obj(await api.decrypt(boundaryEnvelope,publicContext,b)),{recipient:identity.recipient,...boundary});
  for(const content of [{subject:'x',body:'y'},boundary,{subject:'many lines',body:'x\n'.repeat(200)}]){
    const data=await api.encrypt(content,identity);eq(data.length,boundaryEnvelope.length);eq(Buffer.from(api.parse(data).ciphertext,'hex').length,1168);
  }
  for(const nonce of ['01','-1','18446744073709551616','1.2',1,9007199254740993])await fail(()=>api.encrypt(plain,{...identity,nonce}));
  for(const field of ['sender','recipient','chain_id'])await fail(()=>api.encrypt(plain,{...identity,[field]:'00'}));
  c.isSecureContext=false;await fail(()=>api.encrypt(plain,identity),/HTTPS/);c.isSecureContext=true;
  // A receiver cannot change the signed sender/context to make an old ciphertext a new message.
  await fail(()=>api.decrypt(envelope,{...publicContext,nonce:'2'},b),/authentication/);
  console.log(`${checks} encrypted-mail cryptography checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});
