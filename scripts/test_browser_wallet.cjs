'use strict';
// Real browser module in isolated profiles; every key here is public test data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto,createHash} = require('node:crypto');
const root = path.resolve(__dirname,'..');
const source = ['ui/vendor/noble.js','ui/address.js','ui/mail-crypto.js','ui/browser-wallet.js'].map(p=>fs.readFileSync(path.join(root,p),'utf8'));
let checks=0;
const ok = value=>{assert.ok(value);checks++;};
const equal=(a,b)=>{assert.equal(a,b);checks++;};
const throws=(f,pattern)=>{assert.throws(f,pattern);checks++;};
const rejects=async(f,pattern)=>{await assert.rejects(f,pattern);checks++;};
function profile() {
  const values=new Map(),listeners=new Set(),queues=new Map();
  return {
    values,listeners,
    storage:{getItem:k=>values.has(k)?values.get(k):null,setItem:(k,v)=>values.set(k,v)},
    locks:{request(name,fn){const previous=queues.get(name)||Promise.resolve();const result=previous.catch(()=>{}).then(fn);queues.set(name,result);return result;}},
    event(key){for(const f of listeners)f({key});}
  };
}
function browser(p=profile(),hostname='wallet.example',protocol='https:') {
  const logs=[],quiet={},metrics={publicKeyDerivations:0};for(const method of ['log','warn','error','info','debug'])quiet[method]=(...args)=>logs.push(args);
  const context=vm.createContext({Uint8Array,DataView,TextEncoder,TextDecoder,console:quiet,JSON,BigInt,crypto:webcrypto,
    location:{hostname,protocol},isSecureContext:protocol==='https:'||hostname==='localhost',
    localStorage:p.storage,navigator:{locks:p.locks},
    addEventListener:(event,f)=>{if(event==='storage')p.listeners.add(f);},removeEventListener:(event,f)=>p.listeners.delete(f),
    fetch(){throw new Error('Wallet must never contact the network');}});
  for(const [index,s] of source.entries()) {
    vm.runInContext(s,context);
    if(index===0){const actual=context.HashstashNoble;context.HashstashNoble={...actual,schnorr:{...actual.schnorr,getPublicKey(...args){metrics.publicKeyDerivations++;return actual.schnorr.getPublicKey(...args);}}};}
  }
  return {api:context.HashstashBrowserWallet,noble:context.HashstashNoble,address:context.HashstashAddress,context,profile:p,logs,metrics};
}
const LE=(n,size)=>{n=BigInt(n);const b=Buffer.alloc(size);for(let i=0;i<size;i++){b[i]=Number(n&255n);n>>=8n;}return b;};
const compact=n=>{n=BigInt(n);return n<251n?LE(n,1):n<=0xffffn?Buffer.concat([LE(251,1),LE(n,2)]):n<=0xffffffffn?Buffer.concat([LE(252,1),LE(n,4)]):Buffer.concat([LE(253,1),LE(n,8)]);};
const vector=b=>Buffer.concat([compact(b.length),b]);
const amt=n=>{n=BigInt(n);if(n===0n)return vector(Buffer.alloc(0));let h=n.toString(16);if(h.length%2)h='0'+h;return vector(Buffer.from(h,'hex').reverse());};
function transferFixture(api,changes={}) {
  const secret='13'.repeat(32),sender=api.publicKey(secret),recipient=api.publicKey('14'.repeat(32));
  const expected={chain_id:'27'.repeat(32),sender,nonce:'18446744073709551614',expiry_height:'18446744073709551615',protocol_version:28,fee:'1200',data_hex:'000180ff3c7363726970743e',operation:{TransferExact:{recipient,amount:'100'}},...changes};
  const t=expected.operation.TransferExact;
  const inner=Buffer.concat([compact(0),Buffer.from(t.recipient,'hex'),amt(t.amount)]);
  const data=Buffer.from(expected.data_hex,'hex');
  const op=Buffer.concat([inner,vector(data)]);
  const body=Buffer.concat([Buffer.from(expected.chain_id,'hex'),Buffer.from(expected.sender,'hex'),compact(expected.nonce),amt(expected.fee),compact(expected.expiry_height),op]).toString('hex');
  return {secret,expected,envelope:{format:'hashstash-unsigned-v1',body}};
}
async function runRustVectors() {
  const rows=JSON.parse(fs.readFileSync(0,'utf8')),b=browser(),results=[];
  for(const row of rows) {
    const store=b.api.createStore(row.expected.chain_id),snapshot=await store.importPrivate(row.secret);
    const expected={...row.expected,wallet_id:snapshot.wallet_id,wallet_revision:snapshot.wallet_revision};
    b.api.verifyUnsigned(row.envelope,expected);
    const signed=store.signUnsigned(row.envelope,expected);
    b.api.verifySigned(signed.raw,{...row.expected,txid:signed.transaction_id});
    results.push(signed);
    store.destroy();
  }
  process.stdout.write(JSON.stringify(results));
}
async function run() {
  const b=browser();
  // Every published BIP340 verify case and every signing case, including odd keys,
  // invalid points, non-liftable r, altered messages and variable message lengths.
  for(const line of fs.readFileSync(path.join(root,'tests/data/bip340.csv'),'utf8').trim().split(/\r?\n/).slice(1)) {
    const [index,secret,publicKey,aux,msg,sig,valid]=line.split(',');
    const bytes=x=>Uint8Array.from(Buffer.from(x,'hex'));
    equal(b.noble.schnorr.verify(bytes(sig),bytes(msg),bytes(publicKey)),valid==='TRUE');
    if(secret) {equal(Buffer.from(b.noble.schnorr.getPublicKey(bytes(secret))).toString('hex').toUpperCase(),publicKey);equal(Buffer.from(b.noble.schnorr.sign(bytes(msg),bytes(secret),bytes(aux))).toString('hex').toUpperCase(),sig);}
    ok(index!==undefined);
  }
  for(const row of JSON.parse(fs.readFileSync(path.join(root,'tests/data/addresses.json'),'utf8'))) {
    equal(b.address.encode(row.public_key,'hsh'+row.chain_id.slice(0,16)),row.address);
    const watch=b.api.createStore(row.chain_id);await watch.watch(row.address);equal(watch.snapshot().public_key,row.public_key);equal(watch.snapshot().wallet_enabled,false);watch.destroy();
  }
  for(const row of JSON.parse(fs.readFileSync(path.join(root,'tests/data/passphrase-v1.json'),'utf8')).vectors) {equal(b.api.derivePrivate(row.passphrase),row.secret);equal(b.api.publicKey(row.secret),row.public_key);}
  throws(()=>b.api.derivePrivate(''),/passphrase/i);throws(()=>b.api.derivePrivate('\ud800'),/Unicode/);throws(()=>b.api.derivePrivate('é'.repeat(2049)),/long/);equal(b.api.derivePrivate('é'.repeat(2048)).length,64);
  throws(()=>b.api.publicKey('00'.repeat(32)),/private/i);throws(()=>b.api.publicKey('ff'.repeat(32)),/private/i);
  throws(()=>browser(profile(),'public.example','http:').api.createStore('27'.repeat(32)),/HTTPS/);
  throws(()=>browser(profile(),'public.example','http:').api.publicKey('13'.repeat(32)),/HTTPS/);
  throws(()=>browser(profile(),'public.example','http:').api.derivePrivate('example'),/HTTPS/);
  ok(browser(profile(),'localhost','http:').api.createStore('27'.repeat(32)));
  const f=transferFixture(b.api),store=b.api.createStore(f.expected.chain_id);
  // Polling unchanged storage needs no repeated curve work. The cache contains
  // only independent public views; direct/cross-tab edits cannot hide behind an
  // unchanged revision, and signing still fully revalidates persisted keys.
  {
    const cached=browser(),cs=cached.api.createStore(f.expected.chain_id),name='hashstash.browser-wallet.v1.'+f.expected.chain_id;
    const initial=await cs.importPrivate(f.secret);cs.snapshot();const warm=cached.metrics.publicKeyDerivations;
    const first=cs.snapshot(),second=cs.snapshot();equal(cached.metrics.publicKeyDerivations,warm);
    first.wallets[0].public_key='bad';first.wallets.length=0;second.wallet_revision='bad';equal(cs.snapshot().public_key,initial.public_key);equal(cs.snapshot().wallets.length,1);equal(cs.snapshot().wallet_revision,initial.wallet_revision);
    cached.profile.event('unrelated');cs.snapshot();equal(cached.metrics.publicKeyDerivations,warm);
    cached.profile.event(name);cs.snapshot();ok(cached.metrics.publicKeyDerivations>warm);
    const beforeSign=cached.metrics.publicKeyDerivations;cs.signUnsigned(f.envelope,{...f.expected,wallet_id:initial.wallet_id,wallet_revision:initial.wallet_revision});ok(cached.metrics.publicKeyDerivations>=beforeSign+2);
    const saved=cached.profile.values.get(name),changed=JSON.parse(saved);changed.wallets[0].private_key='14'.repeat(32);cached.profile.values.set(name,JSON.stringify(changed));throws(()=>cs.snapshot(),/does not match/);
    cached.profile.values.set(name,saved);equal(cs.snapshot().public_key,initial.public_key);
    const edited=JSON.parse(saved);edited.wallets[0].backed_up=true;cached.profile.values.set(name,JSON.stringify(edited));equal(cs.snapshot().wallets[0].backed_up,true);
    const rawRevision=unit=>JSON.stringify({...JSON.parse(saved),revision:unit}).replace(/\\ud80[01]/,unit);
    cached.profile.values.set(name,rawRevision('\ud800'));equal(cs.snapshot().wallet_revision,'\ud800');
    cached.profile.values.set(name,rawRevision('\ud801'));equal(cs.snapshot().wallet_revision,'\ud801','distinct raw UTF-16 storage cannot share cached metadata');
    // A storage event is optional for detection, but an event clearing storage
    // must immediately invalidate metadata used by subscriptions.
    let notified;cs.subscribe(value=>{notified=value;});cached.profile.values.delete(name);cached.profile.event(null);equal(notified.wallets.length,0);equal(cs.snapshot().wallet_enabled,false);
    cached.profile.values.set(name,saved);equal(cs.snapshot().wallets.length,1);
    const beforeMutation=cached.metrics.publicKeyDerivations;await cs.acknowledgeBackup(initial.wallet_id,{wallet_revision:initial.wallet_revision});ok(cached.metrics.publicKeyDerivations>beforeMutation);equal(cs.snapshot().wallets[0].backed_up,true);
    cs.destroy();
  }
  let snap=await store.importPrivate(f.secret),expected={...f.expected,wallet_id:snap.wallet_id,wallet_revision:snap.wallet_revision};
  equal(b.api.decodeUnsigned(f.envelope).operation.TransferExact.amount,'100');
  b.api.verifyUnsigned(f.envelope,expected);checks++;
  for (const version of [2,12,14,16,17,18,expected.protocol_version-1,expected.protocol_version+1]) throws(()=>b.api.verifyUnsigned(f.envelope,{...expected,protocol_version:version}),/Unsupported protocol/);
  for(const parameter of ['AccountCharge','StaleTargetBps','UncleFinderPercent','UncleIncluderPercent','DifficultyFloor']) {
    const intent={...expected,operation:{Propose:{round:'0',description:'44'.repeat(32),proposal:{Parameter:{parameter,old:'25',new:'30'}},support:'1'}}};
    throws(()=>b.api.verifyUnsigned(f.envelope,intent),/Unknown parameter/);
  }
  for (const percent of [0,1,49,50,51,99,100]) {
    const intent={...expected,protocol_version:28,data_hex:'',operation:{Propose:{round:'0',description:'44'.repeat(32),proposal:{Parameter:{parameter:'MinerFeePercent',old:'50',new:String(percent)}},support:'1'}}};
    const inner=Buffer.concat([compact(3),compact(0),Buffer.from('44'.repeat(32),'hex'),compact(1),compact(5),compact(50),compact(percent),amt(1)]);
    const outer=Buffer.concat([inner,vector(Buffer.alloc(0))]);
    const body=Buffer.concat([Buffer.from(intent.chain_id,'hex'),Buffer.from(intent.sender,'hex'),compact(intent.nonce),amt(intent.fee),compact(intent.expiry_height),outer]);
    const envelope={format:'hashstash-unsigned-v1',body:body.toString('hex')};
    b.api.verifyUnsigned(envelope,intent);checks++;
    equal(b.api.decodeUnsigned(envelope).operation.Propose.proposal.Parameter.new,String(percent));
    const signed=store.signUnsigned(envelope,intent);ok(signed.raw.length>0);
    equal(b.api.verifySigned(signed.raw,{...intent,txid:signed.transaction_id}).operation.Propose.proposal.Parameter.new,String(percent));
    const bad=JSON.parse(JSON.stringify(intent));bad.operation.Propose.proposal.Parameter.new='101';throws(()=>b.api.verifyUnsigned(envelope,bad),/0 to 100/);
  }
  const parameterCases={BlockBytes:[[1024n,1537n],[33554432n,33554433n],[1024n,(1n<<64n)-1n]],Interval:[[15n,61n],[61n,(1n<<64n)-1n]],Lead:[[0n,17n],[17n,0n],[0n,(1n<<64n)-1n]],Rest:[[0n,19n],[19n,0n],[0n,(1n<<64n)-1n]],Duration:[[60n,1n],[1n,(1n<<64n)-1n]],PassMarginBps:[[0n,15001n],[15001n,0n],[0n,(1n<<64n)-1n]],MinimumFeeRate:[[0n,1n],[1n,0n],[3n,1n],[2n,3n],[(1n<<64n)-1n,0n],[0n,(1n<<64n)-1n]]};
  const parameterNames=['BlockBytes','Interval','Lead','Rest','Duration','MinerFeePercent','PassMarginBps','MinimumFeeRate'];
  for(const [parameter,pairs] of Object.entries(parameterCases)) for(const [oldValue,newValue] of pairs) {
    const intent={...expected,data_hex:'',operation:{Propose:{round:'0',description:'44'.repeat(32),proposal:{Parameter:{parameter,old:String(oldValue),new:String(newValue)}},support:'1'}}};
    const inner=Buffer.concat([compact(3),compact(0),Buffer.from('44'.repeat(32),'hex'),compact(1),compact(parameterNames.indexOf(parameter)),compact(oldValue),compact(newValue),amt(1)]);
    const envelope={format:'hashstash-unsigned-v1',body:Buffer.concat([Buffer.from(intent.chain_id,'hex'),Buffer.from(intent.sender,'hex'),compact(intent.nonce),amt(intent.fee),compact(intent.expiry_height),inner,vector(Buffer.alloc(0))]).toString('hex')};
    b.api.verifyUnsigned(envelope,intent);checks++;equal(JSON.stringify(b.api.decodeUnsigned(envelope).operation.Propose.proposal.Parameter),JSON.stringify({parameter,old:String(oldValue),new:String(newValue)}));
    const signed=store.signUnsigned(envelope,intent);equal(b.api.verifySigned(signed.raw,{...intent,txid:signed.transaction_id}).operation.Propose.proposal.Parameter.new,String(newValue));
    for(const invalid of ['18446744073709551616','-1','1.5',9007199254740992]) {
      const bad={...intent,operation:{Propose:{...intent.operation.Propose,proposal:{Parameter:{parameter,old:String(oldValue),new:invalid}}}}};throws(()=>b.api.verifyUnsigned(envelope,bad),/integer|too large/i);
    }
    if(['BlockBytes','Interval','Duration'].includes(parameter)) {
      const bad={...intent,operation:{Propose:{...intent.operation.Propose,proposal:{Parameter:{parameter,old:String(oldValue),new:'0'}}}}};throws(()=>b.api.verifyUnsigned(envelope,bad),/positive/i);
    }
    if(parameter==='BlockBytes') {
      const bad={...intent,operation:{Propose:{...intent.operation.Propose,proposal:{Parameter:{parameter,old:String(oldValue),new:'1023'}}}}};throws(()=>b.api.verifyUnsigned(envelope,bad),/1,024 weight/i);
    }
  }
  // Exercise every operation layout using a separately authored byte oracle.
  const hash=value=>Buffer.from(value,'hex'), decision='55'.repeat(32), proposal='66'.repeat(32);
  const optional=value=>value==null?Buffer.from([0]):Buffer.concat([Buffer.from([1]),value]);
  const sides=(d,o)=>Buffer.concat([optional(d==null?null:hash(d)),optional(o==null?null:compact(o==='Pass'?0:1))]);
  const operationVectors=[
    [{Deposit:{amount:'256',min_shares:'0',decision:null,outcome:null}},Buffer.concat([compact(1),amt(256),amt(0),sides(null,null)])],
    [{Deposit:{amount:'251',min_shares:'65536',decision,outcome:'Pass'}},Buffer.concat([compact(1),amt(251),amt(65536),sides(decision,'Pass')])],
    [{Redeem:{shares:'65536',min_received:'0',decision,outcome:'Fail'}},Buffer.concat([compact(2),amt(65536),amt(0),sides(decision,'Fail')])],
    [{Propose:{round:'251',description:proposal,proposal:{Grant:{payments:[{recipient:expected.operation.TransferExact.recipient,amount:'65536'}]}},support:'1'}},Buffer.concat([compact(3),compact(251),hash(proposal),compact(0),compact(1),hash(expected.operation.TransferExact.recipient),amt(65536),amt(1)])],
    [{Support:{round:'65536',proposal,amount:'1'}},Buffer.concat([compact(4),compact(65536),hash(proposal),amt(1)])],
    [{Refund:{round:'18446744073709551615',proposal}},Buffer.concat([compact(5),compact((1n<<64n)-1n),hash(proposal)])]
  ];
  function oracleEnvelope(inner,data=Buffer.alloc(0)) {
    const outer=Buffer.concat([inner,vector(data)]);
    return {format:'hashstash-unsigned-v1',body:Buffer.concat([hash(expected.chain_id),hash(expected.sender),compact(expected.nonce),amt(expected.fee),compact(expected.expiry_height),outer]).toString('hex')};
  }
  for(const [operation,inner] of operationVectors)for(const length of [0,1,250,251]) {
    const data=Buffer.alloc(length,0xa5),intent={...expected,operation,data_hex:data.toString('hex')},envelope=oracleEnvelope(inner,data);
    b.api.verifyUnsigned(envelope,intent);checks++;
    equal(JSON.stringify(b.api.decodeUnsigned(envelope).operation),JSON.stringify(operation));
    const signed=store.signUnsigned(envelope,intent);equal(signed.raw.length/2,envelope.body.length/2+64);
    const verified=b.api.verifySigned(signed.raw,{...intent,txid:signed.transaction_id});
    equal(JSON.stringify(verified.operation),JSON.stringify(operation));equal(verified.data_hex,intent.data_hex);
  }
  {
    const [operation,inner]=operationVectors[0],data=Buffer.alloc(256*1024,0xa5),envelope=oracleEnvelope(inner,data),intent={...expected,operation,data_hex:data.toString('hex')};
    b.api.verifyUnsigned(envelope,intent);checks++;
    equal(b.api.decodeUnsigned(envelope).data_hex,intent.data_hex,'larger blocks can carry data beyond the former wallet ceiling');
    const signed=store.signUnsigned(envelope,intent),raw=Buffer.from(signed.raw,'hex'),body=raw.subarray(0,-64),tag=createHash('sha256').update('Hashstash/Transaction/v26').digest();
    ok(b.noble.schnorr.verify(raw.subarray(-64),createHash('sha256').update(Buffer.concat([tag,tag,body])).digest(),Buffer.from(expected.sender,'hex')),'large payload has a valid signature over every byte');
    equal(raw.length,envelope.body.length/2+64);
    equal(b.api.verifySigned(signed.raw,{...intent,txid:signed.transaction_id}).data_hex,intent.data_hex);
  }
  for(const removed of [6,7,8,9,10,11])throws(()=>b.api.decodeUnsigned(oracleEnvelope(compact(removed))),/Unsupported operation/);
  {
    const keys=Array.from({length:100},(_,i)=>b.api.publicKey(BigInt(i+1).toString(16).padStart(64,'0'))).sort(),payments=keys.map((recipient,i)=>({recipient,amount:String(i+1)}));
    const inner=values=>Buffer.concat([compact(3),compact(0),hash(proposal),compact(0),compact(values.length),...values.flatMap(p=>[hash(p.recipient),amt(p.amount)]),amt(1)]);
    const intent=values=>({...expected,data_hex:'',operation:{Propose:{round:'0',description:proposal,proposal:{Grant:{payments:values}},support:'1'}}});
    for(const count of [1,2,16,17,32,100]){const list=payments.slice(0,count),envelope=oracleEnvelope(inner(list));b.api.verifyUnsigned(envelope,intent(list));checks++;equal(JSON.stringify(b.api.decodeUnsigned(envelope).operation.Propose.proposal.Grant.payments),JSON.stringify(list));const signed=store.signUnsigned(envelope,intent(list));equal(signed.raw.length/2,envelope.body.length/2+64);equal(JSON.stringify(b.api.verifySigned(signed.raw,{...intent(list),txid:signed.transaction_id}).operation.Propose.proposal.Grant.payments),JSON.stringify(list));}
    const max=((1n<<512n)-1n).toString();
    for(const list of [[],[payments[0],payments[0]],[payments[1],payments[0]],[{...payments[0],amount:'0'}],[{...payments[0],amount:max},{...payments[1],amount:'1'}]]){throws(()=>b.api.verifyUnsigned(oracleEnvelope(inner(list)),intent(list)));throws(()=>b.api.decodeUnsigned(oracleEnvelope(inner(list))));}
    for(const count of [101n,1n<<32n,(1n<<64n)-1n]){
      const truncated=oracleEnvelope(Buffer.concat([compact(3),compact(0),hash(proposal),compact(0),compact(count)]));
      throws(()=>b.api.decodeUnsigned(truncated),/Truncated grant payments/);
    }
    const impossible=Array.from({length:Math.floor(32*1024*1024/1058)+1},()=>payments[0]);
    throws(()=>b.api.verifyUnsigned(oracleEnvelope(inner(payments.slice(0,1))),intent(impossible)),/unique and sorted/);
    const valid=oracleEnvelope(inner(payments.slice(0,2)));throws(()=>b.api.verifyUnsigned(valid,intent([{...payments[0],amount:'9'},payments[1]])),/does not match/);
    const legacy={...intent(payments.slice(0,1)),operation:{Propose:{round:'0',description:proposal,proposal:{Grant:{recipient:payments[0].recipient,amount:'1'}},support:'1'}}};throws(()=>b.api.verifyUnsigned(valid,legacy),/unsupported fields/);
  }
  throws(()=>b.api.decodeUnsigned(oracleEnvelope(Buffer.concat([compact(1),amt(1),amt(0),Buffer.from([2,0])]))),/Invalid optional/);
  throws(()=>b.api.decodeUnsigned(oracleEnvelope(Buffer.concat([compact(1),amt(1),amt(0),optional(hash(decision)),Buffer.from([0])]))),/appear together/);
  throws(()=>b.api.decodeUnsigned(oracleEnvelope(Buffer.concat([compact(1),amt(1),amt(0),optional(hash(decision)),optional(compact(2))]))),/Invalid outcome/);
  throws(()=>b.api.decodeUnsigned(oracleEnvelope(Buffer.concat([compact(1),compact(65),Buffer.alloc(65,1)]))),/too large/);
  throws(()=>b.api.decodeUnsigned(oracleEnvelope(Buffer.concat([compact(1n<<32n)]))),/too large/);
  const signed=store.signUnsigned(f.envelope,expected),raw=Buffer.from(signed.raw,'hex'),body=Buffer.from(f.envelope.body,'hex');
  equal(raw.length,body.length+64);equal(raw.subarray(0,body.length).toString('hex'),f.envelope.body);equal(raw.subarray(body.length).length,64);
  const tag=createHash('sha256').update('Hashstash/Transaction/v26').digest(),message=createHash('sha256').update(Buffer.concat([tag,tag,body])).digest();
  ok(b.noble.schnorr.verify(raw.subarray(-64),message,Buffer.from(expected.sender,'hex')));
  equal(signed.transaction_id,createHash('sha256').update(createHash('sha256').update(raw).digest()).digest('hex'));
  // Mail authenticates the complete signed transaction locally. Encryption
  // alone cannot establish that the claimed sender authorized a message.
  const verified=b.api.verifySigned(signed.raw,{...expected,txid:signed.transaction_id});
  equal(verified.txid,signed.transaction_id);equal(verified.sender,expected.sender);equal(verified.nonce,expected.nonce);equal(verified.data_hex,expected.data_hex);ok(Object.isFrozen(verified));
  equal(b.api.verifySigned(signed.raw).txid,signed.transaction_id);
  equal(b.api.verifySigned(signed.raw.toUpperCase()).txid,signed.transaction_id);
  for(const [field,value] of Object.entries({chain_id:'28'.repeat(32),sender:b.api.publicKey('15'.repeat(32)),nonce:'1',data_hex:'00',txid:'00'.repeat(32),operation:{TransferExact:{...expected.operation.TransferExact,amount:'101'}}}))throws(()=>b.api.verifySigned(signed.raw,{[field]:value}),/does not match/);
  for(const invalid of [null,[],false])throws(()=>b.api.verifySigned(signed.raw,invalid),/expectations/);
  throws(()=>b.api.verifySigned(signed.raw,{nonce:9007199254740992}),/exact/);
  for(const invalid of [null,{},'', 'a','zz','00'.repeat(64)])throws(()=>b.api.verifySigned(invalid),/invalid/i);
  for(const length of [1,32,64,65,raw.length-1])throws(()=>b.api.verifySigned(raw.subarray(0,length).toString('hex')));
  throws(()=>b.api.verifySigned(signed.raw+'00'));
  const signBody=(bytes,secret=f.secret,domain='Hashstash/Transaction/v26')=>{
    const tag=createHash('sha256').update(domain).digest(),message=createHash('sha256').update(Buffer.concat([tag,tag,bytes])).digest();
    const signature=b.noble.schnorr.sign(message,Buffer.from(secret,'hex'),Buffer.alloc(32));
    return Buffer.concat([bytes,signature]).toString('hex');
  };
  const forgedSender=Buffer.from(body);Buffer.from(b.api.publicKey('15'.repeat(32)),'hex').copy(forgedSender,32);
  throws(()=>b.api.verifySigned(signBody(forgedSender)),/signature/);
  throws(()=>b.api.verifySigned(signBody(body,f.secret,'Hashstash/Transaction/v25')),/signature/);
  throws(()=>b.api.verifySigned(signBody(Buffer.concat([body,Buffer.from([0])]))),/bytes/);
  for(let i=0;i<raw.length;i++){const changed=Buffer.from(raw);changed[i]^=1;throws(()=>b.api.verifySigned(changed.toString('hex')));}
  // Tamper each byte: no field, opaque suffix or discriminator can escape review.
  for(let i=0;i<body.length;i++) {const changed=Buffer.from(body);changed[i]^=1;throws(()=>store.signUnsigned({...f.envelope,body:changed.toString('hex')},expected));}
  for(const [k,v] of Object.entries({chain_id:'28'.repeat(32),sender:b.api.publicKey('15'.repeat(32)),nonce:'1',expiry_height:'100',fee:'1201',data_hex:'00',protocol_version:expected.protocol_version+1})) throws(()=>b.api.verifyUnsigned(f.envelope,{...expected,[k]:v}));
  const altered=JSON.parse(JSON.stringify(expected));altered.operation.TransferExact.amount='101';throws(()=>b.api.verifyUnsigned(f.envelope,altered));
  throws(()=>b.api.verifyUnsigned(f.envelope,{...expected,expiry_height:9007199254740992}),/exact/);
  const wrapped={...expected,nonce:JSON.rawJSON(expected.nonce),expiry_height:JSON.rawJSON(expected.expiry_height)};b.api.verifyUnsigned(f.envelope,wrapped);checks++;
  throws(()=>b.api.verifyUnsigned({...f.envelope,body:f.envelope.body+'00'},expected),/bytes/);
  throws(()=>b.api.verifyUnsigned({...f.envelope,body:f.envelope.body+'a'},expected),/invalid/);
  {
    const [operation,inner]=operationVectors[0],data=Buffer.alloc(32*1024*1024+1,0xa5),envelope=oracleEnvelope(inner,data);
    equal(b.api.decodeUnsigned(envelope).data_hex.length,data.length*2,'a complete valid record above32MiB is decoded');
  }
  throws(()=>b.api.verifyUnsigned(f.envelope,{...expected,current_height:expected.expiry_height}),/expired/);
  // Minimal amounts use an empty vector for zero. Compact integer boundaries
  // are independently constructed here, rather than using the wallet encoder.
  for(const nonce of [0n,1n,250n,251n,65535n,65536n,0xffffffffn,0x100000000n,(1n<<64n)-2n]) {
    const sample=transferFixture(b.api,{nonce:String(nonce)});
    b.api.verifyUnsigned(sample.envelope,sample.expected);checks++;
    equal(b.api.decodeUnsigned(sample.envelope).nonce,String(nonce));
  }
  for(const value of [0n,1n,255n,256n,(1n<<512n)-1n]) {
    const sample=transferFixture(b.api,{fee:String(value)});
    b.api.verifyUnsigned(sample.envelope,sample.expected);checks++;
    equal(b.api.decodeUnsigned(sample.envelope).fee,String(value));
  }
  const feeOffset=64+compact(expected.nonce).length, afterFee=feeOffset+amt(expected.fee).length;
  const extraLimb=Buffer.concat([body.subarray(0,feeOffset),compact(3),LE(expected.fee,2),Buffer.from([0]),body.subarray(afterFee)]);
  throws(()=>b.api.decodeUnsigned({...f.envelope,body:extraLimb.toString('hex')}),/Noncanonical amount/);
  throws(()=>b.api.verifySigned(signBody(extraLimb)),/Noncanonical amount/);
  const zero=transferFixture(b.api,{fee:'0',extra_fee:'0'}),zeroBody=Buffer.from(zero.envelope.body,'hex');
  const paddedZero=Buffer.concat([zeroBody.subarray(0,feeOffset),Buffer.from([1,0]),zeroBody.subarray(feeOffset+1)]);
  throws(()=>b.api.decodeUnsigned({...zero.envelope,body:paddedZero.toString('hex')}),/Noncanonical amount/);
  throws(()=>b.api.verifySigned(signBody(paddedZero)),/Noncanonical amount/);
  for(const malformed of [Buffer.concat([LE(251,1),LE(250,2)]),Buffer.concat([LE(252,1),LE(65535,4)]),Buffer.concat([LE(253,1),LE(0xffffffffn,8)]),Buffer.concat([LE(254,1),LE(1,16)]),LE(255,1)]) {
    const changed=Buffer.concat([body.subarray(0,64),malformed,body.subarray(feeOffset)]);
    throws(()=>b.api.decodeUnsigned({...f.envelope,body:changed.toString('hex')}),/Noncanonical integer|Invalid integer/);
    throws(()=>b.api.verifySigned(signBody(changed)),/Noncanonical integer|Invalid integer/);
  }
  for(const malformed of [LE(251,1),Buffer.from([252,1,2]),Buffer.from([253,1,2,3])]) {
    throws(()=>b.api.decodeUnsigned({...f.envelope,body:Buffer.concat([body.subarray(0,64),malformed]).toString('hex')}),/Truncated/);
  }
  const plain=transferFixture(b.api,{data_hex:''}),plainBody=Buffer.from(plain.envelope.body,'hex'),outerOffset=afterFee+compact(expected.expiry_height).length;
  throws(()=>b.api.decodeUnsigned({...plain.envelope,body:plainBody.subarray(0,-1).toString('hex')}),/Truncated/);
  const overlongEnum=Buffer.concat([plainBody.subarray(0,outerOffset),Buffer.from([251,0,0]),plainBody.subarray(outerOffset+1)]);
  throws(()=>b.api.decodeUnsigned({...f.envelope,body:overlongEnum.toString('hex')}),/Noncanonical integer/);
  throws(()=>b.api.verifySigned(signBody(overlongEnum)),/Noncanonical integer/);
  const vectorOffset=outerOffset+1+32+amt(100).length;
  const overlongLength=Buffer.concat([plainBody.subarray(0,vectorOffset),Buffer.from([251,plainBody[vectorOffset],0]),plainBody.subarray(vectorOffset+1)]);
  throws(()=>b.api.decodeUnsigned({...f.envelope,body:overlongLength.toString('hex')}),/Noncanonical integer/);
  throws(()=>b.api.verifySigned(signBody(overlongLength)),/Noncanonical integer/);
  const hugeLength=Buffer.concat([plainBody.subarray(0,vectorOffset),compact(32*1024*1024+1)]);
  throws(()=>b.api.decodeUnsigned({...f.envelope,body:hugeLength.toString('hex')}),/too large/);
  const obsoleteField={...expected,operation:{TransferExact:{...expected.operation.TransferExact,max_account_charge:'0'}}};
  throws(()=>b.api.verifyUnsigned(f.envelope,obsoleteField),/unsupported fields/i);
  const view=store.snapshot();equal(JSON.stringify(view).includes(f.secret),false);equal('private_key' in view.wallets[0],false);
  equal(await store.exportPrivate(view.wallet_id,{wallet_revision:view.wallet_revision}),f.secret);
  equal(b.logs.length,0);
  await store.acknowledgeBackup(view.wallet_id,{wallet_revision:view.wallet_revision});equal(store.snapshot().wallets.find(w=>w.id===view.wallet_id).backed_up,true);
  throws(()=>store.signUnsigned(f.envelope,expected),/changed/);
  // Independent browser profiles cannot see, select or export one another's keys.
  const other=browser().api.createStore(f.expected.chain_id);equal(other.snapshot().wallets.length,0);await rejects(()=>other.select(view.wallet_id),/not found/);await rejects(()=>other.exportPrivate(view.wallet_id),/no private/);
  const otherChain=b.api.createStore('99'.repeat(32));equal(otherChain.snapshot().wallets.length,0);
  // Two tabs share one origin/profile. Serialized writes retain both new wallets.
  const p=profile(),tab1=browser(p),tab2=browser(p),a=tab1.api.createStore(f.expected.chain_id),c=tab2.api.createStore(f.expected.chain_id);
  await Promise.all([a.importPrivate('21'.repeat(32)),c.importPrivate('22'.repeat(32))]);equal(a.snapshot().wallets.length,2);equal(c.snapshot().wallets.length,2);
  const before=a.snapshot();await c.select(before.wallets[0].id);await rejects(()=>a.create({wallet_revision:before.wallet_revision}),/changed/);equal(a.snapshot().wallets.length,2);
  let updates=0;const unsubscribe=a.subscribe(()=>updates++);p.event([...p.values.keys()][0]);equal(updates,1);unsubscribe();p.event(null);equal(updates,1);
  const saved=p.values.values().next().value;await a.watch(before.wallets[0].public_key);equal(a.snapshot().wallets.find(w=>w.id===before.wallets[0].id).can_sign,true);ok(p.values.values().next().value.includes('21'.repeat(32)));ok(saved.includes('22'.repeat(32)));
  const watchOnly=await a.watch(b.api.publicKey('23'.repeat(32)));equal(watchOnly.wallet_enabled,false);await rejects(()=>a.exportPrivate(watchOnly.wallet_id),/no private/);
  // Importing a secret into a watch entry upgrades that entry without duplicates.
  await a.importPrivate('23'.repeat(32));equal(a.snapshot().wallets.length,3);equal(a.snapshot().wallet_enabled,true);
  const beforeFailure=[...p.values.entries()];p.storage.setItem=()=>{throw new Error('quota');};await rejects(()=>a.create(),/saved/);assert.deepEqual([...p.values.entries()],beforeFailure);checks++;
  const corrupt=profile(),bad=browser(corrupt).api.createStore(f.expected.chain_id),storageKey='hashstash.browser-wallet.v1.'+f.expected.chain_id;corrupt.values.set(storageKey,'broken');throws(()=>bad.snapshot(),/preserved/);await rejects(()=>bad.create(),/preserved/);equal(corrupt.values.get(storageKey),'broken');
  // Generated keys use native randomness, remain available on reload and are not
  // replaced by miner accounts, server sessions, chain changes or watch imports.
  const fresh=browser(),created=fresh.api.createStore(f.expected.chain_id),createdMeta=await created.create();equal(createdMeta.wallets.length,1);equal(createdMeta.wallet_enabled,true);equal(createdMeta.wallets[0].backed_up,false);
  equal(browser(fresh.profile).api.createStore(f.expected.chain_id).snapshot().public_key,createdMeta.public_key);
  // Another tab can write while synchronous cryptography runs. Recheck persisted
  // revision before returning the signature, not only before starting to sign.
  const race=browser(),raceStore=race.api.createStore(f.expected.chain_id),raceMeta=await raceStore.importPrivate(f.secret);
  const raceIntent={...f.expected,wallet_id:raceMeta.wallet_id,wallet_revision:raceMeta.wallet_revision};
  race.context.crypto={getRandomValues(target){const name='hashstash.browser-wallet.v1.'+f.expected.chain_id;const data=JSON.parse(race.profile.values.get(name));data.revision='changed-in-another-tab';race.profile.values.set(name,JSON.stringify(data));return webcrypto.getRandomValues(target);}};
  throws(()=>raceStore.signUnsigned(f.envelope,raceIntent),/changed/);
  equal(race.logs.length,0);equal(fresh.logs.length,0);
  const mb=browser(),ms=mb.api.createStore(f.expected.chain_id),meta=await ms.importPrivate(f.secret);
  const mailIdentity={chain_id:f.expected.chain_id,sender:mb.api.publicKey(f.secret),recipient:mb.api.publicKey('14'.repeat(32)),nonce:'0'};
  const mailBytes=await mb.context.HashstashMailCrypto.encrypt({subject:'Public test fixture',body:'Local decryption only'},mailIdentity);
  const expectedMail={chain_id:f.expected.chain_id,wallet_id:meta.wallet_id,wallet_revision:meta.wallet_revision};
  ms.snapshot();const beforeDecrypt=mb.metrics.publicKeyDerivations;
  equal((await ms.decryptMail(mailBytes,mailIdentity,expectedMail)).body,'Local decryption only');
  ok(mb.metrics.publicKeyDerivations>=beforeDecrypt+2,'mail decryption revalidates persisted keys before and after decrypting');
  await rejects(()=>ms.decryptMail(mailBytes,mailIdentity,{...expectedMail,wallet_revision:undefined}),/changed/);
  await rejects(()=>ms.decryptMail(mailBytes,{...mailIdentity,chain_id:'28'.repeat(32)},expectedMail),/changed/);
  let resolveMail;const actualMailCrypto=mb.context.HashstashMailCrypto;
  mb.context.HashstashMailCrypto={decrypt:()=>new Promise(resolve=>{resolveMail=resolve;})};
  const pendingMail=ms.decryptMail(mailBytes,mailIdentity,expectedMail),rejectedMail=rejects(()=>pendingMail,/changed/);
  await ms.watch(mailIdentity.recipient);resolveMail({subject:'old',body:'not returned'});await rejectedMail;
  mb.context.HashstashMailCrypto=actualMailCrypto;const watchedMail=ms.snapshot();
  await rejects(()=>ms.decryptMail(mailBytes,mailIdentity,{chain_id:f.expected.chain_id,wallet_id:watchedMail.wallet_id,wallet_revision:watchedMail.wallet_revision}),/private key locally/);
  equal(mb.logs.length,0);
  process.stdout.write(JSON.stringify({ok:true,checks})+'\n');
}
(process.argv.includes('--rust-vectors')?runRustVectors():run()).catch(error=>{console.error(error.stack);process.exitCode=1;});
