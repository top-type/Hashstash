'use strict';
// Independent Node/OpenSSL oracle for browser mail. All keys below are public
// test vectors. This script never reads wallet files or makes network calls.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const crypto=require('node:crypto'),root=path.resolve(__dirname,'..');
const fixturePath=path.join(root,'tests','fixtures','mail-v2.json');
const order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const secret=n=>BigInt(n).toString(16).padStart(64,'0');
let checks=0;
const eq=(a,b)=>{assert.deepEqual(a,b);checks++;};
const ok=a=>{assert.ok(a);checks++;};
function ecdh(privateHex){const key=crypto.createECDH('secp256k1');key.setPrivateKey(Buffer.from(privateHex,'hex'));return key;}
function publicX(privateHex){return ecdh(privateHex).getPublicKey(undefined,'compressed').subarray(1).toString('hex');}
function sharedX(privateHex,peer){return ecdh(privateHex).computeSecret(Buffer.from('02'+peer,'hex'));}
function browser(random){
  let calls=0,loaded=false;
  const c=vm.createContext({Uint8Array,TextEncoder,TextDecoder,isSecureContext:true,
    crypto:{subtle:crypto.webcrypto.subtle,getRandomValues(bytes){
      // Noble probes its RNG while loading and uses 16-byte scalar blinding.
      // Keep those calls genuinely random; fix only the mail protocol inputs.
      if(!random||!loaded||bytes.length===16)return crypto.webcrypto.getRandomValues(bytes);
      const value=Buffer.from(random[calls++],'hex');assert.equal(bytes.length,value.length);bytes.set(value);return bytes;
    }},fetch(){throw Error('Network forbidden in cryptography tests');}});
  for(const file of ['ui/vendor/noble.js','ui/mail-crypto.js'])vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),c);
  loaded=true;
  return {api:c.HashstashMailCrypto,noble:c.HashstashNoble,calls:()=>calls};
}
// Reconstruct the wire context independently using Node byte encoders, without
// calling any browser helper or copying a browser-generated AAD/key.
function context(identity,ephemeral){
  const nonce=Buffer.alloc(8);nonce.writeBigUInt64LE(BigInt(identity.nonce));
  return Buffer.concat([Buffer.from('Hashstash/Mail/v2\0'),...['chain_id','sender'].map(k=>Buffer.from(identity[k],'hex')),nonce,Buffer.from(ephemeral,'hex')]);
}
function wrapping(privateHex,peer,identity,ephemeral,role,candidate){
  return Buffer.from(crypto.hkdfSync('sha256',sharedX(privateHex,peer),Buffer.from(identity.chain_id,'hex'),Buffer.concat([Buffer.from('Hashstash/Mail/v2/'+role+'\0'),context(identity,ephemeral),Buffer.from(candidate,'hex')]),32));
}
function seal(key,iv,plain,aad){
  const cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plain),cipher.final(),cipher.getAuthTag()]);
}
function open(key,iv,ciphertext,aad){
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,iv);decipher.setAAD(aad);decipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([decipher.update(ciphertext.subarray(0,-16)),decipher.final()]);
}
function paddedText(text){const payload=Buffer.from(text),out=Buffer.alloc(1152);assert.ok(payload.length+2<=out.length);out.writeUInt16BE(payload.length);payload.copy(out,2);return out;}
function referenceEnvelope(v,plaintext=paddedText(JSON.stringify({recipient:v.identity.recipient,...v.plaintext}))){
  const [content,ephemeral,iv,recipientIv,senderIv]=v.random.map(s=>Buffer.from(s,'hex'));
  const ephemeralKey=publicX(ephemeral.toString('hex')),aad=context(v.identity,ephemeralKey);
  const wrapped=role=>seal(wrapping(ephemeral.toString('hex'),v.identity[role],v.identity,ephemeralKey,role,v.identity[role]),role==='recipient'?recipientIv:senderIv,content,Buffer.concat([aad,Buffer.from('/'+role)]));
  const e={ephemeral_key:ephemeralKey,iv:iv.toString('hex'),ciphertext:seal(content,iv,plaintext,aad).toString('hex'),recipient_iv:recipientIv.toString('hex'),recipient_key:wrapped('recipient').toString('hex'),sender_iv:senderIv.toString('hex'),sender_key:wrapped('sender').toString('hex')};
  return Buffer.from('hashstash.mail/2\n'+JSON.stringify(e)).toString('hex');
}
function referenceDecrypt(dataHex,identity,privateHex,role){
  const text=Buffer.from(dataHex,'hex').toString('utf8');assert.ok(text.startsWith('hashstash.mail/2\n'));
  const e=JSON.parse(text.slice('hashstash.mail/2\n'.length)),aad=context(identity,e.ephemeral_key);
  const content=open(wrapping(privateHex,e.ephemeral_key,identity,e.ephemeral_key,role,publicX(privateHex)),Buffer.from(e[role+'_iv'],'hex'),Buffer.from(e[role+'_key'],'hex'),Buffer.concat([aad,Buffer.from('/'+role)]));
  const padded=open(content,Buffer.from(e.iv,'hex'),Buffer.from(e.ciphertext,'hex'),aad);assert.equal(padded.length,1152);
  const length=padded.readUInt16BE();assert.ok(length>0&&length+2<=padded.length);assert.ok(padded.subarray(length+2).every(b=>b===0));
  const value=JSON.parse(padded.subarray(2,length+2).toString('utf8'));assert.deepEqual(Object.keys(value),['recipient','subject','body']);
  if(role==='recipient')assert.equal(value.recipient,publicX(privateHex));return value;
}
function fixture(){
  const v={format:'hashstash-mail-interop-v2',notice:'PUBLIC TEST KEYS ONLY. Never use these keys for funds.',
    identity:{chain_id:'27'.repeat(32),sender:publicX(secret(1)),recipient:publicX(secret(6)),nonce:'18446744073709551615'},
    private_keys:{sender:secret(1),recipient:secret(6)},plaintext:{subject:'Interoperability: ☀',body:'Flow becomes structure.\nUnicode: café 冰'},
    random:['31'.repeat(32),secret(7),'01'.repeat(12),'02'.repeat(12),'03'.repeat(12)]};
  v.data_hex=referenceEnvelope(v);return v;
}
async function run(){
  const expected=fixture();
  if(process.argv.includes('--write-fixture')){fs.mkdirSync(path.dirname(fixturePath),{recursive:true});fs.writeFileSync(fixturePath,JSON.stringify(expected,null,2)+'\n');}
  const v=JSON.parse(fs.readFileSync(fixturePath,'utf8'));eq(v,expected);
  const deterministic=browser(v.random),data=await deterministic.api.encrypt(v.plaintext,v.identity);
  eq(data,v.data_hex);eq(deterministic.calls(),5);ok(Buffer.byteLength(Buffer.from(data,'hex'))<=3072);
  const publicContext={chain_id:v.identity.chain_id,sender:v.identity.sender,nonce:v.identity.nonce},expectedPlain={recipient:v.identity.recipient,...v.plaintext};
  ok(!Buffer.from(data,'hex').toString('utf8').includes(v.identity.recipient));
  for(const role of ['recipient','sender']){
    eq(referenceDecrypt(data,publicContext,v.private_keys[role],role),expectedPlain);
    eq(JSON.parse(JSON.stringify(await deterministic.api.decrypt(v.data_hex,publicContext,v.private_keys[role]))),expectedPlain);
    // The opposite secret scalar has the same x-only wallet identity.
    eq(referenceDecrypt(data,publicContext,secret(order-BigInt('0x'+v.private_keys[role])),role),expectedPlain);
  }
  const runtime=browser();let even=0,odd=0;
  for(const n of [1n,2n,3n,4n,5n,6n,7n,8n,17n,31n,order-1n,order-6n]){
    const privateHex=secret(n),key=ecdh(privateHex);key.getPublicKey(undefined,'compressed')[0]===2?even++:odd++;
    for(const peer of [secret(1),secret(6),secret(17)]){
      const input=Uint8Array.from(Buffer.from(privateHex,'hex')),before=Buffer.from(input);
      eq(Buffer.from(runtime.noble.ecdhXOnly(input,Uint8Array.from(Buffer.from(publicX(peer),'hex')))),sharedX(privateHex,publicX(peer)));
      eq(Buffer.from(input),before);
    }
  }
  ok(even>0&&odd>0);
  const same={...v.identity,recipient:v.identity.sender};
  const sameEph=publicX(v.random[1]);
  ok(!wrapping(v.random[1],same.sender,same,sameEph,'sender',same.sender).equals(wrapping(v.random[1],same.recipient,same,sameEph,'recipient',same.recipient)));
  ok(!wrapping(v.random[1],same.sender,same,sameEph,'sender',same.sender).equals(wrapping(v.random[1],same.sender,same,sameEph,'sender',v.identity.recipient)));
  const selfData=await runtime.api.encrypt(v.plaintext,same);
  for(const role of ['recipient','sender'])eq(referenceDecrypt(selfData,publicContext,v.private_keys.sender,role),{recipient:same.recipient,...v.plaintext});
  const fresh=await runtime.api.encrypt(v.plaintext,v.identity);
  for(const role of ['recipient','sender'])eq(referenceDecrypt(fresh,publicContext,v.private_keys[role],role),expectedPlain);
  // The independent decryptor rejects each transaction-bound identity change.
  for(const identity of [{...publicContext,chain_id:'28'.repeat(32)},{...publicContext,nonce:'18446744073709551614'},{...publicContext,sender:publicX(secret(17))}]){
    assert.throws(()=>referenceDecrypt(data,identity,v.private_keys.recipient,'recipient'));checks++;
  }
  assert.throws(()=>referenceDecrypt(data,publicContext,secret(17),'recipient'));checks++;
  // Authenticated but malformed plaintext must also fail closed. These cases
  // are produced solely by the independent oracle, not the browser encoder.
  const good=paddedText(JSON.stringify(expectedPlain)),zero=Buffer.from(good),oversize=Buffer.from(good),badPadding=Buffer.from(good);
  zero.writeUInt16BE(0);oversize.writeUInt16BE(1151);badPadding[1151]=1;
  const invalidUtf8=Buffer.from(good);invalidUtf8[2]=0xff;
  const invalid=[zero,oversize,badPadding,invalidUtf8,
    paddedText(JSON.stringify({...v.plaintext,recipient:v.identity.recipient})),
    paddedText(JSON.stringify({...expectedPlain,extra:1})),
    paddedText(JSON.stringify({...expectedPlain,recipient:publicX(secret(17))})),
    paddedText(JSON.stringify(expectedPlain,null,1)),
    paddedText(JSON.stringify({...expectedPlain,recipient:'ff'.repeat(32)}))];
  for(const bad of invalid){await assert.rejects(()=>runtime.api.decrypt(referenceEnvelope(v,bad),publicContext,v.private_keys.recipient),/authentication/);checks++;}
  console.log(`${checks} independent encrypted-mail interoperability checks passed`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
