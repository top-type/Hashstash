'use strict';
// Property and cross-implementation checks of the browser's mail envelope
// parser (ui/mail-crypto.js `parse`), which reads attacker-chosen transaction
// data. Every vector in fuzz/mail-envelope-vectors.json carries the node's
// verdict (src/mail.rs, checked by tests/fuzz_parsers.rs); the browser must
// agree, or a record would be mail in one and not the other. Seeded random
// mutations then check that the parser only accepts canonical envelopes and
// fails only with its own messages. Public fixture data only; no network.
//   node fuzz/js/mail_envelope.cjs [iterations] [seed]
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..','..');
const iterations=Number(process.argv[2]||20000),seed=BigInt(process.argv[3]||'0x6861736873746173');
const context=vm.createContext({Uint8Array,TextEncoder,TextDecoder,crypto:webcrypto,isSecureContext:true,console,fetch(){throw Error('No network allowed');}});
for(const file of ['ui/vendor/noble.js','ui/mail-crypto.js'])vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),context,{filename:file});
const api=context.HashstashMailCrypto;
const fields=['ephemeral_key','iv','ciphertext','recipient_iv','recipient_key','sender_iv','sender_key'];
const lengths={ephemeral_key:32,iv:12,ciphertext:api.MAX_PLAIN_BYTES+16,recipient_iv:12,recipient_key:48,sender_iv:12,sender_key:48};
const messages=new Set(['Encrypted message is too large.','Invalid encrypted message.','Invalid encrypted message encoding.','Unsupported encrypted message version.','Noncanonical encrypted message.','Invalid messaging public key.']);
let checks=0;

/** The parser's verdict; anything but its own Error, or a noncanonical acceptance, fails. */
function verdict(dataHex,label){
  let envelope;
  try{envelope=api.parse(dataHex);}
  catch(error){
    assert.ok(error&&error.constructor&&error.constructor.name==='Error'&&messages.has(error.message),`${label}: unexpected failure ${error&&error.stack||error}`);
    checks++;return false;
  }
  assert.deepEqual(Object.keys(envelope),fields,label);
  for(const field of fields)assert.match(envelope[field],new RegExp(`^[0-9a-f]{${lengths[field]*2}}$`),`${label}: ${field}`);
  assert.equal(Buffer.from(api.PREFIX+JSON.stringify(envelope)).toString('hex'),dataHex,`${label}: one encoding per envelope`);
  checks++;return true;
}

const fixture=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/mail-v2.json'),'utf8'));
const base=Buffer.from(fixture.data_hex,'hex');
const edited=edits=>edits.reduce((bytes,[at,remove,inserted])=>Buffer.concat([bytes.subarray(0,at),Buffer.from(inserted,'hex'),bytes.subarray(at+remove)]),base);
const vectors=JSON.parse(fs.readFileSync(path.join(root,'fuzz/mail-envelope-vectors.json'),'utf8'));
assert.equal(vectors.format,'hashstash-mail-envelope-vectors-v1');
for(const vector of vectors.vectors){
  assert.equal(verdict(edited(vector.edits).toString('hex'),vector.name),vector.accepted,`${vector.name}: the browser and the node disagree`);
}

// splitmix64, as in tests/fuzz_parsers.rs.
let state=seed;const mask=(1n<<64n)-1n;
function next(){state=(state+0x9e3779b97f4a7c15n)&mask;let z=state;z=((z^(z>>30n))*0xbf58476d1ce4e5b9n)&mask;z=((z^(z>>27n))*0x94d049bb133111ebn)&mask;return z^(z>>31n);}
const below=n=>n<=0?0:Number(next()%BigInt(n));
const tokens=['{','}','"',',',':','\\','\\u0030','\u00a0','\ufeff','\n',' ','null','0','f','F','hashstash.mail/2\n','"iv":"','"ciphertext":"'].map(t=>Buffer.from(t));
const special=[0x00,0x22,0x2c,0x3a,0x5c,0x7b,0x7d,0x7f,0x80,0xbf,0xc0,0xef,0xf4,0xff];
function mutate(input){
  let bytes=Buffer.from(input);
  for(let round=0,rounds=1<<below(4);round<rounds;round++){
    const at=below(bytes.length+1);
    switch(below(7)){
      case 0:if(bytes.length){bytes[Math.min(at,bytes.length-1)]^=1<<below(8);}break;
      case 1:if(bytes.length){bytes[Math.min(at,bytes.length-1)]=special[below(special.length)];}break;
      case 2:{const value=Buffer.from('0123456789abcdef'[below(16)]);bytes=Buffer.concat([bytes.subarray(0,at),value,bytes.subarray(Math.min(at+1,bytes.length))]);break;}
      case 3:bytes=Buffer.concat([bytes.subarray(0,at),tokens[below(tokens.length)],bytes.subarray(at)]);break;
      case 4:bytes=Buffer.concat([bytes.subarray(0,at),bytes.subarray(Math.min(bytes.length,at+1+below(32)))]);break;
      case 5:{const from=below(bytes.length),count=1+below(64);bytes=Buffer.concat([bytes.subarray(0,at),bytes.subarray(from,from+count),bytes.subarray(at)]);break;}
      default:bytes=bytes.subarray(0,at);
    }
  }
  return bytes;
}
let accepted=0;
for(let i=0;i<iterations;i++){
  const bytes=mutate(base),label=`mutation ${i} (seed ${seed})`;
  accepted+=verdict(bytes.toString('hex'),label)?1:0;
  // The parser also receives arbitrary strings, not only hexadecimal bytes.
  if(i%16===0){const text=bytes.toString('latin1');verdict(text.slice(0,below(text.length+1)),`${label}, as text`);verdict(bytes.toString('hex').toUpperCase(),`${label}, uppercase`);}
}
assert.ok(accepted>0&&accepted<iterations,`mutations should reach both verdicts (${accepted} accepted)`);
for(const value of [undefined,null,0,{},[],'0'.repeat(api.MAX_DATA_BYTES*2+2)])verdict(value,`non-hex input ${typeof value}`);
console.log(`Mail envelope parser: ${vectors.vectors.length} shared node vectors, ${iterations} mutated envelopes (${accepted} canonical), ${checks} checks passed.`);
