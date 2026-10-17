'use strict';

// Full UI with the real local wallet/crypto modules in independent VM browsers.
// Only DOM and public RPC transport are doubled; no node wallet endpoint exists.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {harness,response,settle,addr,deferred} = require('./test_wallet_ui.cjs');
const sha = bytes => createHash('sha256').update(bytes).digest();
const integer = (value,size) => { let n=BigInt(value); const b=Buffer.alloc(size); for(let i=0;i<size;i++){b[i]=Number(n&255n);n>>=8n;} return b; };
const compact = value => { const n=BigInt(value);return n<251n?integer(n,1):n<=0xffffn?Buffer.concat([integer(251,1),integer(n,2)]):n<=0xffffffffn?Buffer.concat([integer(252,1),integer(n,4)]):Buffer.concat([integer(253,1),integer(n,8)]); };
const vector = bytes => Buffer.concat([compact(bytes.length),bytes]);
const amount = value => {let n=BigInt(value),out=[];while(n){out.push(Number(n&255n));n>>=8n;}return vector(Buffer.from(out));};
const bytes = value => typeof value==='string'?Buffer.from(value,'hex'):Buffer.from(value);

// Independent Rust bincode layout for a current exact transfer, including opaque data.
function prepare(chain, p) {
  const tx=p.operation.TransferExact;
  const inner=Buffer.concat([compact(0),bytes(tx.recipient),amount(tx.amount)]);
  const data=Buffer.from(p.data_hex||'','hex');
  const envelope=Buffer.concat([inner,vector(data)]);
  return {format:'hashstash-unsigned-anchor',chain_id:chain,body:Buffer.concat([bytes(p.sender),compact(p.nonce),amount(p.fee),bytes(p.anchor),compact(p.expiry_blocks),envelope]).toString('hex')};
}
function fee(h,p) {
  const {chain_id,tip,state_root,height}=h.currentSnapshot.status, priority=p.extra_fee||'0';
  const paid=1n+BigInt(priority),miner=paid/2n,nonce=p.nonce??0,expiry=p.expiry_blocks??2;
  // Like the node, weigh the exact body this quote describes plus its 64-byte signature.
  const weight=Buffer.from(prepare(chain_id,{...p,fee:String(paid),nonce,anchor:p.anchor??tip,expiry_blocks:expiry}).body,'hex').length+64;
  return {miner_fee_percent:50,miner_fee:String(miner),revenue_fee:String(paid-miner),chain_id,tip,state_root,height,sender:addr(p.sender),sender_public_key:p.sender,fee:String(1n+BigInt(priority)),minimum_fee:'1',account_creation_fee:'0',grant_recipient_fee:'0',record_fee:'0',extra_fee:priority,weight:String(weight),minimum_fee_rate:'1',pending:false,nonce,anchor:tip,anchor_height:height,expiry_blocks:expiry,expiry_height:String(BigInt(height)+BigInt(expiry)),operation:p.operation,data_hex:p.data_hex||'',data_bytes:(p.data_hex||'').length/2};
}
async function setup(options={}) {
  const h=await harness({realWallet:true,publicWeb:true,...options});
  h.currentSnapshot.status.settings.pass_margin_bps=0;



  h.currentSnapshot.status.fee_policy={minimum_fee_rate:'1',fee_scale:1024,account_weight:1024};

  h.handlers.fee_quote=p=>response({result:fee(h,p)});
  h.handlers.transfer_quote=p=>{const f=fee(h,{...p,operation:{TransferExact:{recipient:p.recipient,amount:p.amount}}});return response({result:{...f,recipient:addr(p.recipient),public_key:p.recipient,amount:p.amount,recipient_receives:p.amount,total_debit:String(BigInt(p.amount)+BigInt(f.fee))}});};
  h.handlers.preparetransaction=p=>response({result:{...prepare(h.currentSnapshot.status.chain_id,p),fee_quote:fee(h,p)}});
  h.handlers.broadcasttransaction=p=>response({result:{transaction_id:sha(sha(Buffer.from(p.raw,'hex'))).toString('hex')}});
  await h.refresh(); return h;
}
async function fill(h,recipient,data='00ff80') {
  const f=h.get('send-form');
  f.elements.data_format.value='hex';await f.fire('change');
  f.elements.recipient.value=addr(recipient);f.elements.amount.value='0.1';f.elements.extra_fee.value='0.003';f.elements.data_hex.value=data;
  await f.fire('input');await h.timersDue();
  assert.equal(h.get('send-submit').disabled,false,h.get('send-cost').textContent);
  return f;
}
const broadcasts=h=>h.calls.filter(c=>c.body.method==='broadcasttransaction');
async function run() {
  let checks=0;
  const a=await setup(),b=await setup();
  assert.equal(a.location.hash,'#overview');checks++;
  assert.equal(a.browserStore.snapshot().wallets.length,0,'server wallet fixture is never imported into browser');checks++;
  assert.equal(b.browserStore.snapshot().wallets.length,0);checks++;
  assert.equal(a.hasElement('test-mining'),false);checks++;
  assert.equal(a.hasElement('guide-test-mining'),false);checks++;
  for(const button of a.mineButtons){assert.equal(button.disabled,true);await button.click();checks++;}
  assert.equal(a.calls.some(c=>c.body.method==='mine'),false);checks++;
  await a.get('wallet-create').click();
  const original=a.browserStore.snapshot(), alice=original.public_key;
  assert.equal(original.wallets.length,1,a.get('wallet-feedback').textContent);checks++;
  assert.equal(b.browserStore.snapshot().wallets.length,0);checks++;
  await a.get('export-private').click();const aliceSecret=a.get('backup-private').value;
  assert.match(aliceSecret,/^[0-9a-f]{64}$/);checks++;
  assert.equal(a.browserApi.publicKey(aliceSecret),alice);checks++;
  const bobSecret='0'.repeat(63)+'3'; // Published BIP340 test key, never a real wallet.
  b.get('import-private-key').value=bobSecret;await b.get('wallet-import-form').requestSubmit();
  const bob=b.browserStore.snapshot().public_key;
  assert.equal(bob,b.browserApi.publicKey(bobSecret),b.get('wallet-feedback').textContent);checks++;
  assert.equal(b.get('import-private-key').value,'');checks++;
  assert.equal(a.browserStore.snapshot().public_key,alice);checks++;
  a.get('watch-key').value=addr(bob);await a.get('watch-form').requestSubmit();
  assert.equal(a.browserStore.snapshot().wallet_enabled,false);checks++;
  assert.equal(a.browserStore.snapshot().wallets.length,2);checks++;
  assert.equal(b.browserStore.snapshot().wallets.length,1);checks++;
  await (await fill(a,alice)).requestSubmit();
  assert.equal(a.get('unsigned-dialog').open,true,a.get('send-form').querySelector().textContent);checks++;
  const watchEnvelope=JSON.parse(a.get('unsigned-output').value);
  assert.equal(a.browserApi.decodeUnsigned(watchEnvelope).sender,bob);checks++;
  assert.equal(broadcasts(a).length,0);checks++;
  await a.chooseWallet(alice);
  assert.equal(a.browserStore.snapshot().wallet_enabled,true);checks++;
  await (await fill(a,bob)).requestSubmit();
  assert.equal(broadcasts(a).length,1,a.get('send-form').querySelector().textContent);checks++;
  const raw=Buffer.from(broadcasts(a)[0].body.params.raw,'hex'),body=raw.subarray(0,-64),signature=raw.subarray(-64);
  assert.equal(raw.length,body.length+64);checks++;
  const tag=sha(Buffer.from('Hashstash/chain-bound-transaction')),message=sha(Buffer.concat([tag,tag,Buffer.from(a.currentSnapshot.status.chain_id,'hex'),body]));
  assert.equal(a.noble.schnorr.verify(Uint8Array.from(signature),Uint8Array.from(message),Uint8Array.from(Buffer.from(alice,'hex'))),true);checks++;
  const decoded=a.browserApi.decodeUnsigned({format:'hashstash-unsigned-anchor',chain_id:a.currentSnapshot.status.chain_id,body:body.toString('hex')});
  assert.equal(decoded.sender,alice);checks++;
  assert.equal(Object.hasOwn(decoded,'chain_id'),false);checks++;
  assert.equal(watchEnvelope.chain_id,a.currentSnapshot.status.chain_id,'offline export retains unsigned network context');checks++;
  assert.deepEqual(Object.keys(watchEnvelope).sort(),['body','chain_id','format'],'RPC-only fee quote is excluded from the strict offline export');checks++;
  assert.equal(decoded.operation.TransferExact.recipient,bob);checks++;
  assert.equal(decoded.operation.TransferExact.amount,'100');checks++;
  assert.equal(decoded.fee,'4');checks++;
  assert.equal(Object.hasOwn(decoded,'extra_fee'),false);checks++;
  assert.equal(decoded.data_hex,'00ff80');checks++;
  assert.equal(decoded.nonce,'0');checks++;
  assert.equal(decoded.anchor,a.currentSnapshot.status.tip);checks++;
  assert.equal(decoded.expiry_blocks,'2');checks++;
  a.handlers.preparetransaction=p=>response({result:prepare(a.currentSnapshot.status.chain_id,{...p,fee:'500'})});
  await (await fill(a,bob)).requestSubmit();
  assert.equal(broadcasts(a).length,1,'malicious prepared fee cannot be signed or broadcast');checks++;
  assert.match(a.get('send-form').querySelector().textContent,/does not match/);checks++;
  for(const change of [{anchor:'35'.repeat(32)},{expiry_blocks:3}]) {
    a.handlers.preparetransaction=p=>response({result:prepare(a.currentSnapshot.status.chain_id,{...p,...change})});
    await (await fill(a,bob)).requestSubmit();
    assert.equal(broadcasts(a).length,1,'changed signed lifetime or block reference cannot be broadcast');checks++;
    assert.match(a.get('send-form').querySelector().textContent,/does not match/);checks++;
  }
  a.handlers.preparetransaction=p=>response({result:prepare('ff'.repeat(32),p)});
  await (await fill(a,bob)).requestSubmit();assert.equal(broadcasts(a).length,1,'unsigned network metadata mismatch cannot be signed');checks++;
  assert.match(a.get('send-form').querySelector().textContent,/network context/);checks++;
  const pending=deferred();a.handlers.preparetransaction=()=>pending.promise;
  const form=await fill(a,bob),sending=form.requestSubmit();await settle();
  const req=a.calls.filter(c=>c.body.method==='preparetransaction').at(-1).body.params;
  await a.browserStore.select(bob,{wallet_revision:a.browserStore.snapshot().wallet_revision});a.storageChanged();
  pending.resolve(response({result:prepare(a.currentSnapshot.status.chain_id,req)}));await sending;
  assert.equal(broadcasts(a).length,1,'selection change cancels pending signing');checks++;
  assert.equal(b.browserStore.snapshot().public_key,bob);checks++;
  const reloaded=await setup({savedStorage:a.savedStorage});
  assert.equal(reloaded.browserStore.snapshot().public_key,bob);checks++;
  assert.equal(reloaded.browserStore.snapshot().wallets.length,2);checks++;
  assert.equal(reloaded.browserStore.snapshot().wallet_enabled,false);checks++;
  // A watch export can be signed in the other independent browser holding its key.
  const local=b.browserStore.snapshot(),signed=b.browserStore.signUnsigned(watchEnvelope,{chain_id:b.currentSnapshot.status.chain_id,sender:bob,nonce:'0',anchor:b.currentSnapshot.status.tip,expiry_blocks:'2',operation:{TransferExact:{recipient:alice,amount:'100'}},fee:'4',data_hex:'00ff80',wallet_id:local.wallet_id,wallet_revision:local.wallet_revision});
  reloaded.get('broadcast-raw').value=signed.raw;await reloaded.get('broadcast-form').requestSubmit();
  assert.equal(broadcasts(reloaded).length,1);checks++;
  // The watch-only broadcast is followed by sender nonce like the other forms,
  // so a transaction the node drops does not stay pending.
  const broadcastFeedback=()=>reloaded.get('broadcast-form').querySelector().textContent;
  assert.match(broadcastFeedback(),/^Pending · /);checks++;
  reloaded.currentSnapshot.mempool=[];reloaded.currentSnapshot.status.mempool=0;await reloaded.refresh();await reloaded.refresh();
  assert.match(broadcastFeedback(),/^No longer pending · .*Prepare it again\.$/);checks++;
  for(const h of [a,b,reloaded]) {
    const requests=JSON.stringify(h.calls);
    assert.equal(requests.includes(aliceSecret),false,'generated private key never leaves browser');checks++;
    assert.equal(requests.includes(bobSecret),false,'imported private key never leaves browser');checks++;
    assert.equal(h.calls.some(c=>c.url.startsWith('/api/wallet')),false);checks++;
    for(const c of h.calls.filter(c=>['fee_quote','transfer_quote','preparetransaction'].includes(c.body.method))) {assert.ok(c.body.params.sender);checks++;}
  }
  b.handlers.snapshot=params=>response({result:{...b.snapshotResult(params),status:{...b.currentSnapshot.status,chain_id:'a'.repeat(63)+'b'}}});
  await b.refresh();
  assert.equal(b.get('connection-label').textContent,'Offline','full chain mismatch fails even when its address fingerprint matches');checks++;
  assert.equal(b.get('send-submit').disabled,true);checks++;
  // Public text uses an ordinary Send transaction and the real browser signer.
  {
    const c=await setup({chat:true});
    c.handlers.explorer_chat=()=>response({result:{chain_id:c.currentSnapshot.status.chain_id,tip:c.currentSnapshot.status.tip,height:20,ready:true,items:[],pending:[],next_cursor:null}});
    c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();await c.navigate('#send');
    const f=c.get('send-form');f.elements.recipient.value=addr(alice);f.elements.amount.value='0.001';f.elements.data_text.value='Public test message 🌱';await f.fire('input');await c.timersDue();
    assert.equal(c.get('send-submit').disabled,false,c.get('send-cost').textContent);checks++;
    assert.equal(c.hasElement('chat-form'),false,'feed has no separate transaction composer');checks++;
    assert.equal(broadcasts(c).length,0);checks++;
    await f.requestSubmit();assert.equal(broadcasts(c).length,1,f.querySelector().textContent);checks++;
    const raw=Buffer.from(broadcasts(c)[0].body.params.raw,'hex'),body=raw.subarray(0,-64),envelope={format:'hashstash-unsigned-anchor',chain_id:c.currentSnapshot.status.chain_id,body:body.toString('hex')},decoded=c.browserApi.decodeUnsigned(envelope);
    assert.equal(decoded.operation.TransferExact.recipient,alice);checks++;
    assert.equal(decoded.operation.TransferExact.amount,'1','public text has no special payment threshold');checks++;
    assert.equal(decoded.fee,'1');checks++;
    assert.equal(Buffer.from(decoded.data_hex,'hex').toString(),'Public test message 🌱');checks++;
    const tag=sha(Buffer.from('Hashstash/chain-bound-transaction')),message=sha(Buffer.concat([tag,tag,Buffer.from(c.currentSnapshot.status.chain_id,'hex'),body]));
    assert.equal(c.noble.schnorr.verify(Uint8Array.from(raw.subarray(-64)),Uint8Array.from(message),Uint8Array.from(Buffer.from(bob,'hex'))),true);checks++;
    const intent={chain_id:c.currentSnapshot.status.chain_id,sender:bob,nonce:'0',anchor:c.currentSnapshot.status.tip,expiry_blocks:'2',operation:{Donate:{amount:'1',decision:null,outcome:null}},fee:'1',data_hex:''};
    assert.throws(()=>c.browserApi.verifyUnsigned(envelope,intent),/unsupported fields/i);checks++;
    assert.throws(()=>c.browserApi.verifyUnsigned(envelope,{...decoded,chain_id:'not-a-chain'}),/Invalid|hex/i);checks++;
    c.handlers.preparetransaction=p=>response({result:prepare(c.currentSnapshot.status.chain_id,{...p,operation:{TransferExact:{...p.operation.TransferExact,recipient:bob}}})});
    f.elements.data_text.value='Do not redirect';await f.fire('input');await c.timersDue();await f.requestSubmit();
    assert.equal(broadcasts(c).length,1,'redirected ordinary transfer is never signed');checks++;
    assert.match(f.querySelector().textContent,/does not match/);checks++;
  }
  // Periodic refresh reads only the selected wallet, keeping other saved
  // addresses local until they are explicitly selected.
  {
    const c=await setup();c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();const before=c.browserStore.snapshot();
    const others=[];for(const n of [8,9,10]){const created=await c.browserStore.importPrivate(BigInt(n).toString(16).padStart(64,'0'));others.push(created.public_key);}
    await c.refresh();await c.chooseWallet(before.wallet_id);await settle();assert.equal(c.browserStore.snapshot().wallet_id,before.wallet_id);checks++;const start=c.calls.length;await c.refresh();await settle();
    const requests=JSON.stringify(c.calls.slice(start));for(const key of others){assert.equal(requests.includes(key),false,'unselected key never enters RPC');checks++;assert.equal(requests.includes(addr(key)),false,'unselected address never enters RPC');checks++;}
    const snapshots=c.calls.slice(start).filter(call=>call.body.method==='snapshot');assert.ok(snapshots.length>0);checks++;for(const request of snapshots){assert.deepEqual(request.body.params.keys,[before.public_key],'snapshot queries selected wallet only');checks++;}
    const next=c.calls.length;await c.chooseWallet(others[0]);await c.refresh();const selectedRequests=JSON.stringify(c.calls.slice(next));assert.ok(selectedRequests.includes(others[0]),'explicit selection permits reading that account');checks++;for(const key of others.slice(1)){assert.equal(selectedRequests.includes(key),false,'selecting one wallet does not reveal the others');checks++;}
  }
  // A submission the node drops (expiry, reorganized anchor or decision) does
  // not keep a stale pending indicator; a used nonce ends it without an error.
  {
    const c=await setup();c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    const f=await fill(c,alice);await f.requestSubmit();
    assert.equal(broadcasts(c).length,1,f.querySelector().textContent);checks++;
    assert.match(f.querySelector().textContent,/^Pending · /);checks++;
    c.currentSnapshot.mempool=[{body:{sender:bob,nonce:0,operation:{TransferExact:{recipient:alice,amount:'100'}}}}];c.currentSnapshot.status.mempool=1;
    await c.refresh();await c.refresh();
    assert.match(f.querySelector().textContent,/^Pending · /,'a pooled submission stays pending');checks++;
    c.currentSnapshot.mempool=[];c.currentSnapshot.status.mempool=0;await c.refresh();
    assert.match(f.querySelector().textContent,/^Pending · /,'one empty pool view is not conclusive');checks++;
    await c.refresh();
    assert.match(f.querySelector().textContent,/^No longer pending · .*Prepare it again\.$/);checks++;
    await (await fill(c,alice)).requestSubmit();
    assert.equal(broadcasts(c).length,2,f.querySelector().textContent);checks++;
    c.currentSnapshot.account.account.nonce=1;await c.refresh();
    assert.match(f.querySelector().textContent,/^Mined or replaced · /);checks++;
    c.currentSnapshot.account.account.nonce=0;await c.refresh();await c.refresh();
    assert.match(f.querySelector().textContent,/^Mined or replaced · /,'a settled submission is no longer followed');checks++;
  }
  // A busy pool truncates the global page; the sender's own complete page
  // still shows whether its submission is pending.
  {
    const c=await setup();c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    const f=await fill(c,alice);await f.requestSubmit();
    assert.equal(broadcasts(c).length,1,f.querySelector().textContent);checks++;
    const own={body:{sender:bob,nonce:0,operation:{TransferExact:{recipient:alice,amount:'100'}}}};
    c.currentSnapshot.mempool=[];c.currentSnapshot.status.mempool=500;c.currentSnapshot.sender_mempool=[own];c.currentSnapshot.account={...c.currentSnapshot.account,pending_nonce:1};
    await c.refresh();await c.refresh();
    assert.match(f.querySelector().textContent,/^Pending · /,'the sender page shows the submission pending');checks++;
    c.currentSnapshot.sender_mempool=[];c.currentSnapshot.account={...c.currentSnapshot.account,pending_nonce:0};await c.refresh();await c.refresh();
    assert.match(f.querySelector().textContent,/^No longer pending · /,'a complete sender page detects a dropped submission');checks++;
  }
  console.log(`Browser wallet UI: ${checks} integration assertions passed.`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
