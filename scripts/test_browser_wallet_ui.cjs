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
  const local=b.browserStore.snapshot(),signed=await b.browserStore.signUnsigned(watchEnvelope,{chain_id:b.currentSnapshot.status.chain_id,sender:bob,nonce:'0',anchor:b.currentSnapshot.status.tip,expiry_blocks:'2',operation:{TransferExact:{recipient:alice,amount:'100'}},fee:'4',data_hex:'00ff80',wallet_id:local.wallet_id,wallet_revision:local.wallet_revision});
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
  // A broadcast answered by anything but a 429/503 refusal may have run. The
  // form keeps the signed transaction and follows it instead of showing the
  // node's text as a plain error, and it does not sign a second transaction
  // (at the next nonce) until the first is known to be pending, used or gone.
  {
    const c=await setup();c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    const own={body:{sender:bob,nonce:0,operation:{TransferExact:{recipient:alice,amount:'100'}}}},prepared=()=>c.calls.filter(x=>x.body.method==='preparetransaction');
    const pool=(rows,nonce)=>{c.currentSnapshot.sender_mempool=rows;c.currentSnapshot.account={...c.currentSnapshot.account,pending_nonce:nonce};};
    const txid=raw=>sha(sha(Buffer.from(raw,'hex'))).toString('hex');
    // The exact case: the broadcast ran and was pooled, but the public reply
    // budget replaced its answer with a 200 JSON-RPC error saying "try again".
    c.handlers.broadcasttransaction=()=>{pool([own],1);return response({jsonrpc:'2.0',id:1,error:{code:-32000,message:'public response byte budget exhausted; try again'}});};
    const f=await fill(c,alice);await f.requestSubmit();
    const first=broadcasts(c)[0].body.params.raw;
    assert.equal(broadcasts(c).length,1);checks++;
    assert.match(f.querySelector().textContent,new RegExp(`^Pending · ${txid(first).slice(0,7)}`),'the pooled transaction is reported pending, not failed');checks++;
    assert.doesNotMatch(f.querySelector().textContent,/try again/,'the node text never tells the user to send it again');checks++;
    // A lost answer whose transaction the snapshots do not show yet.
    c.handlers.broadcasttransaction=()=>{throw new TypeError('Failed to fetch');};pool([],0);c.currentSnapshot.account.account.nonce=1;
    await c.refresh();let g=await fill(c,alice);await g.requestSubmit();
    const lost=broadcasts(c).at(-1).body.params.raw,shown=()=>g.querySelector().textContent;
    assert.equal(c.browserApi.verifySigned(lost,{chain_id:c.currentSnapshot.status.chain_id}).nonce,'1');checks++;
    assert.match(shown(),new RegExp(`^Result unknown · ${txid(lost).slice(0,7)}.*Do not submit it again\\.`),shown());checks++;
    assert.match(shown(),/Send the same transaction again$/,'the identical bytes can be sent again');checks++;
    assert.doesNotMatch(shown(),/Failed to fetch|reply was/,'a lost connection has no reply to show');checks++;
    assert.equal(c.get('send-submit').disabled,true,'the form cannot sign another transaction meanwhile');checks++;
    const signedBefore=prepared().length,sentBefore=broadcasts(c).length;
    await c.timersDue();await g.requestSubmit();
    assert.equal(prepared().length,signedBefore,'nothing new is prepared while the result is unknown');checks++;assert.equal(broadcasts(c).length,sentBefore);checks++;
    assert.match(shown(),/^Result unknown · /,'and the form keeps saying so');checks++;
    // Sending the same bytes again is idempotent: the node answers with the same ID.
    c.handlers.broadcasttransaction=p=>{pool([{body:{...own.body,nonce:1}}],2);return response({result:{transaction_id:txid(p.raw)}});};
    const resend=g.querySelector().children.at(-1);await resend.click();await settle();
    assert.equal(broadcasts(c).at(-1).body.params.raw,lost,'the resend carries the identical signed bytes');checks++;
    assert.match(shown(),new RegExp(`^Pending · ${txid(lost).slice(0,7)}`),shown());checks++;
    assert.equal(prepared().length,signedBefore,'and is not prepared or signed again');checks++;
    // Once the snapshots show it pending, the form is free again: another
    // submission is a deliberate second transaction at the next nonce.
    await c.timersDue();assert.equal(c.get('send-submit').disabled,false);checks++;
    // An unknown result whose transaction never appears is released after two
    // complete snapshots requested after the failure, with its transaction
    // number still unused. One requested before cannot show it: it does not
    // count.
    c.handlers.broadcasttransaction=()=>response({jsonrpc:'2.0',id:1,error:{code:-32000,message:'RPC response exceeds the local response limit'}});
    pool([],1);c.currentSnapshot.account.account.nonce=1;await c.refresh();await c.refresh();g=await fill(c,alice);
    let early;const held=deferred();c.handlers.snapshot=p=>{early=p;return held.promise;};const polling=c.poll();await settle();
    await g.requestSubmit();assert.match(shown(),/^Result unknown · /);checks++;
    assert.doesNotMatch(shown(),/local response limit/,'the node text is not shown while the result is unknown');checks++;
    delete c.handlers.snapshot;held.resolve(response({result:c.snapshotResult(early)}));await polling;
    assert.match(shown(),/^Result unknown · /,'a snapshot requested before the failure does not count');checks++;
    await c.refresh();assert.match(shown(),/^Result unknown · /,'one empty pool view is not conclusive');checks++;
    await c.refresh();assert.match(shown(),/^Not pending · .*unused.*Submit it again\.$/,shown());checks++;
    assert.match(shown(),/ Its reply was: RPC response exceeds the local response limit\. Submit it again\.$/,'once it is known not to be pending, the node reply is shown');checks++;
    g=await fill(c,alice);c.handlers.broadcasttransaction=p=>response({result:{transaction_id:txid(p.raw)}});await g.requestSubmit();
    assert.equal(prepared().at(-1).body.params.nonce,1,'a released form signs at the same unused nonce');checks++;
    assert.match(shown(),/^Pending · /);checks++;
    // A refusal promises that nothing ran: it says so and keeps nothing.
    pool([],1);await c.refresh();await c.refresh();
    c.handlers.broadcasttransaction=()=>({ok:false,status:429,headers:{get:name=>name==='Retry-After'?'2':null},text:async()=>JSON.stringify({jsonrpc:'2.0',id:1,error:{code:-32000,message:'transaction admission is busy'}})});
    g=await fill(c,alice);await g.requestSubmit();
    assert.equal(shown(),'Not sent: transaction admission is busy (try again in 2 s)');checks++;
    c.handlers.broadcasttransaction=p=>response({result:{transaction_id:txid(p.raw)}});
    g=await fill(c,alice);await g.requestSubmit();assert.match(shown(),/^Pending · /,'after a refusal the same details can be sent');checks++;
    assert.equal(prepared().at(-1).body.params.nonce,1);checks++;
  }
  // Switching accounts does not forget a broadcast of unknown outcome.
  {
    const c=await setup();c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    c.handlers.broadcasttransaction=()=>{throw new TypeError('Failed to fetch');};
    const f=await fill(c,alice);await f.requestSubmit();assert.match(f.querySelector().textContent,/^Result unknown · /);checks++;
    c.get('import-private-key').value='0'.repeat(63)+'5';await c.get('wallet-import-form').requestSubmit();
    assert.notEqual(c.browserStore.snapshot().public_key,bob);checks++;
    c.currentSnapshot.sender_mempool=[{body:{sender:bob,nonce:0,operation:{TransferExact:{recipient:alice,amount:'100'}}}}];c.currentSnapshot.account={...c.currentSnapshot.account,pending_nonce:1};
    await c.chooseWallet(bob);await c.refresh();
    assert.match(f.querySelector().textContent,/^Pending · /,'back on its account, the broadcast is found pending');checks++;
  }
  // Advanced → Broadcast sends signed bytes from the cold signer: its
  // outcomes are read the same way.
  {
    const c=await setup();c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    const txid=raw=>sha(sha(Buffer.from(raw,'hex'))).toString('hex'),refusal=status=>({ok:false,status,headers:{get:name=>name==='Retry-After'?'1':null},text:async()=>JSON.stringify({jsonrpc:'2.0',id:1,error:{code:-32000,message:'HTTP sessions busy'}})});
    // A refused page broadcast leaves signed bytes that were never sent.
    let signed;c.handlers.broadcasttransaction=p=>{signed=p.raw;return refusal(503);};
    const f=await fill(c,alice);await f.requestSubmit();assert.match(f.querySelector().textContent,/^Not sent: HTTP sessions busy/);checks++;
    const form=c.get('broadcast-form'),shown=()=>form.querySelector().textContent;
    c.get('broadcast-raw').value=signed;c.handlers.broadcasttransaction=()=>refusal(429);await form.requestSubmit();
    assert.equal(shown(),'Not sent: HTTP sessions busy (try again in 1 s)','a refusal promises nothing ran');checks++;
    c.handlers.broadcasttransaction=()=>response({jsonrpc:'2.0',id:1,error:{code:-32000,message:'public response byte budget exhausted; try again'}});await form.requestSubmit();
    assert.match(shown(),new RegExp(`^Result unknown · ${txid(signed).slice(0,7)}.*Do not submit it again\\..*Send the same transaction again$`),shown());checks++;
    assert.doesNotMatch(shown(),/try again/);checks++;
    c.handlers.broadcasttransaction=p=>{c.currentSnapshot.sender_mempool=[{body:{sender:bob,nonce:0,operation:{TransferExact:{recipient:alice,amount:'100'}}}}];c.currentSnapshot.account={...c.currentSnapshot.account,pending_nonce:1};return response({result:{transaction_id:txid(p.raw)}});};
    const sent=broadcasts(c).length;await form.querySelector().children.at(-1).click();await settle();
    assert.equal(broadcasts(c).length,sent+1);checks++;assert.equal(broadcasts(c).at(-1).body.params.raw,signed,'the same bytes are sent again');checks++;
    assert.match(shown(),new RegExp(`^Pending · ${txid(signed).slice(0,7)}`),shown());checks++;
    // Bytes of an account this page does not follow get the same warning
    // in place of the node's text.
    c.get('import-private-key').value='0'.repeat(63)+'5';await c.get('wallet-import-form').requestSubmit();
    c.handlers.broadcasttransaction=()=>{throw new TypeError('Failed to fetch');};c.get('broadcast-raw').value=signed;await form.requestSubmit();
    assert.match(shown(),new RegExp(`^Result unknown · ${txid(signed).slice(0,7)}…${txid(signed).slice(-5)}: .*Broadcasting these same bytes again is safe; do not sign a new transaction`),shown());checks++;
  }
  // Optional passphrase encryption of browser keys, through the page itself.
  {
    const c=await setup(),phrase='correct horse battery staple',saved=()=>[...c.savedStorage.values()].join('\n');
    c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    assert.equal(c.get('wallet-security').hidden,false,'a hot wallet shows its key protection');checks++;
    assert.equal(c.get('wallet-lock-state').textContent,'Not encrypted');checks++;
    assert.match(c.get('wallet-security-status').textContent,/saved unencrypted/);checks++;
    await c.get('wallet-passphrase-open').click();const form=c.get('wallet-passphrase-form');assert.equal(form.hidden,false);checks++;
    form.elements.passphrase.value=phrase;form.elements.confirm.value=phrase+'!';await form.requestSubmit();
    assert.match(form.querySelector().textContent,/differ/);checks++;assert.equal(form.elements.passphrase.value,'','passphrase fields are cleared after every attempt');checks++;
    assert.ok(saved().includes(bobSecret));checks++;
    form.elements.passphrase.value=form.elements.confirm.value=phrase;await form.requestSubmit();
    assert.equal(c.get('wallet-lock-state').textContent,'Unlocked',form.querySelector().textContent);checks++;
    assert.equal(form.hidden,true);checks++;assert.match(c.get('wallet-feedback').textContent,/cannot be recovered/);checks++;
    assert.equal(saved().includes(bobSecret),false,'the saved key is encrypted');checks++;
    let f=await fill(c,alice);await f.requestSubmit();assert.equal(broadcasts(c).length,1,f.querySelector().textContent);checks++;
    // A reload starts locked; signing asks for the passphrase first.
    const r=await setup({savedStorage:c.savedStorage}),unlock=r.get('unlock-form');
    assert.equal(r.get('wallet-lock-state').textContent,'Locked');checks++;
    assert.equal(r.get('wallet-kind').textContent,'Hot wallet · locked');checks++;
    f=await fill(r,alice);await f.requestSubmit();
    assert.equal(r.get('unlock-dialog').open,true,'signing asks for the passphrase');checks++;
    assert.match(f.querySelector().textContent,/Unlock/);checks++;
    assert.equal(r.calls.some(call=>call.body.method==='preparetransaction'),false,'nothing is prepared while locked');checks++;
    unlock.elements.passphrase.value='wrong horse battery staple';await unlock.requestSubmit();
    assert.match(unlock.querySelector().textContent,/Wrong passphrase/);checks++;assert.equal(r.get('unlock-dialog').open,true);checks++;
    unlock.elements.passphrase.value=phrase;await unlock.requestSubmit();
    assert.equal(r.get('unlock-dialog').open,false,unlock.querySelector().textContent);checks++;
    assert.equal(r.get('wallet-lock-state').textContent,'Unlocked');checks++;assert.equal(unlock.elements.passphrase.value,'');checks++;
    f=await fill(r,alice);await f.requestSubmit();assert.equal(broadcasts(r).length,1,f.querySelector().textContent);checks++;
    // The idle lock can expire after the last session snapshot, as in a
    // background tab whose refresh is late: Send still asks to unlock.
    r.wallClock+=5*60*1000;assert.equal(r.get('wallet-lock-state').textContent,'Unlocked','the last snapshot predates the lock');checks++;
    const prepares=()=>r.calls.filter(call=>call.body.method==='preparetransaction').length,before=prepares();
    f=await fill(r,alice);await f.requestSubmit();
    assert.equal(r.get('unlock-dialog').open,true,'a lock that expired since the last snapshot opens the dialog');checks++;
    assert.equal(prepares(),before,'and nothing is prepared');checks++;assert.equal(r.get('wallet-lock-state').textContent,'Locked');checks++;
    unlock.elements.passphrase.value=phrase;await unlock.requestSubmit();assert.equal(r.get('unlock-dialog').open,false);checks++;
    // So does a lock that expires while the transaction is being prepared.
    const preparing=r.handlers.preparetransaction;r.handlers.preparetransaction=p=>{r.wallClock+=5*60*1000;return preparing(p);};
    f=await fill(r,alice);await f.requestSubmit();r.handlers.preparetransaction=preparing;
    assert.equal(r.get('unlock-dialog').open,true,'a lock reported by signing opens the dialog');checks++;
    assert.match(f.querySelector().textContent,/Unlock/);checks++;assert.equal(broadcasts(r).length,1,'nothing is signed');checks++;
    unlock.elements.passphrase.value=phrase;await unlock.requestSubmit();
    f=await fill(r,alice);await f.requestSubmit();assert.equal(broadcasts(r).length,2,f.querySelector().textContent);checks++;
    // A copied key leaves the clipboard after 30 seconds.
    await r.get('export-private').click();assert.equal(r.get('backup-private').value,bobSecret);checks++;
    await r.get('backup-copy').click();assert.equal(r.clipboard.at(-1),bobSecret);checks++;
    await r.timersDue(29999);assert.equal(r.clipboard.at(-1),bobSecret);checks++;
    await r.timersDue(30000);assert.equal(r.clipboard.at(-1),'','a copied key is cleared');checks++;
    r.navigator.permissions={query:async()=>({state:'granted'})};r.navigator.clipboard.readText=async()=>'copied later';
    await r.get('backup-copy').click();await r.timersDue(30000);assert.equal(r.clipboard.at(-1),bobSecret,'newer clipboard content the page can read is left alone');checks++;
    r.navigator.clipboard.readText=async()=>bobSecret;await r.get('backup-copy').click();await r.timersDue(30000);assert.equal(r.clipboard.at(-1),'');checks++;
    delete r.navigator.permissions;delete r.navigator.clipboard.readText;
    await r.get('backup-copy').click();await r.get('copy-key').click();await r.timersDue(30000);assert.equal(r.clipboard.at(-1),addr(bob),'a later copy from this page replaces the key and is kept');checks++;
    // Firefox and Safari write the clipboard only during a user action: while
    // the page kept focus, the next click or key press in it clears the key.
    const write=r.navigator.clipboard.writeText;
    for(const action of ['pointerdown','keydown']) {
      await r.get('backup-copy').click();r.navigator.clipboard.writeText=async value=>{if(value==='')throw new Error('Clipboard write was blocked due to lack of user activation.');return write(value);};
      assert.equal(r.get('clipboard-notice').hidden,true);checks++;
      await r.timersDue(30000);assert.equal(r.clipboard.at(-1),bobSecret);checks++;
      assert.equal(r.get('clipboard-notice').hidden,false,'a refused clear says the key is still on the clipboard');checks++;assert.match(r.get('clipboard-notice-text').textContent,/is still on the clipboard/);checks++;
      r.navigator.clipboard.writeText=write;await r.windowEvents.get(action)();await settle();
      assert.equal(r.clipboard.at(-1),'',`the next ${action} clears the key`);checks++;assert.equal(r.get('clipboard-notice').hidden,true);checks++;
      assert.equal(r.windowEvents.has('pointerdown'),false,'and stops retrying');checks++;
    }
    // Once the page has lost focus, another application may have copied
    // something since: neither the timer, a return nor a click erases it
    // unasked. The page asks instead.
    await r.get('backup-copy').click();await r.windowEvents.get('blur')();r.clipboard.push('hsh1copiedelsewhere');
    await r.timersDue(30000);assert.equal(r.clipboard.at(-1),'hsh1copiedelsewhere','content copied elsewhere is left alone');checks++;
    assert.equal(r.get('clipboard-notice').hidden,false);checks++;assert.match(r.get('clipboard-notice-text').textContent,/may still be on the clipboard/);checks++;
    assert.equal(['focus','pointerdown','pointerup','keydown'].some(name=>r.windowEvents.has(name)),false,'no return, click or key press clears it');checks++;
    await r.get('clipboard-keep').click();assert.equal(r.get('clipboard-notice').hidden,true);checks++;assert.equal(r.clipboard.at(-1),'hsh1copiedelsewhere');checks++;
    await r.get('backup-copy').click();await r.windowEvents.get('blur')();await r.timersDue(30000);
    await r.get('clipboard-clear').click();await settle();assert.equal(r.clipboard.at(-1),'','an explicit request clears it');checks++;assert.equal(r.get('clipboard-notice').hidden,true);checks++;
    // A copy or cut in this page replaces the key and is kept; copying the
    // key itself from the backup is cleared like Copy.
    await r.get('backup-copy').click();r.clipboard.push('selected page text');r.documentEvents.get('copy')({target:r.get('wallet-public')});
    await r.timersDue(30000);assert.equal(r.clipboard.at(-1),'selected page text','a later copy in this page is kept');checks++;
    r.clipboard.push(bobSecret);r.documentEvents.get('copy')({target:r.get('backup-private')});await r.timersDue(30000);assert.equal(r.clipboard.at(-1),'','the key copied by hand from the backup is cleared too');checks++;
    // Leaving before the clear asks first; staying shows how to clear it.
    await r.get('backup-copy').click();const leaving={prevented:false,preventDefault(){this.prevented=true;}};r.windowEvents.get('beforeunload')(leaving);
    assert.equal(leaving.prevented,true,'closing or reloading before the clear asks first');checks++;assert.equal(r.get('clipboard-notice').hidden,false);checks++;
    r.windowEvents.get('pagehide')();await settle();assert.equal(r.clipboard.at(-1),'','a page that is left tries to clear it');checks++;
    assert.equal(r.windowEvents.has('beforeunload')||r.windowEvents.has('pagehide'),false,'with nothing to clear the page leaves without asking');checks++;
    await r.get('backup-download').click();assert.deepEqual(JSON.parse(r.downloads.at(-1)),{format:'hashstash-private-v1',private_key:bobSecret,public_key:bob});checks++;
    assert.ok(r.blobParts.at(-1).every(part=>part instanceof Uint8Array&&part.every(byte=>byte===0)),'the backup bytes are wiped once the file holds its copy');checks++;
    await r.get('backup-close').click();
    // An idle page locks itself; a backup then asks for the passphrase too.
    r.wallClock+=5*60*1000;await r.timersDue(5*60*1000);await r.refresh();
    assert.equal(r.get('wallet-lock-state').textContent,'Locked','an idle page locks itself');checks++;
    await r.get('export-private').click();assert.equal(r.get('unlock-dialog').open,true,'a backup asks for the passphrase');checks++;assert.equal(r.get('backup-dialog').open,false);checks++;
    unlock.elements.passphrase.value=phrase;await unlock.requestSubmit();assert.equal(r.get('wallet-lock-state').textContent,'Unlocked');checks++;
    await r.get('wallet-lock').click();assert.equal(r.get('wallet-lock-state').textContent,'Locked','Lock now');checks++;
    unlock.elements.passphrase.value=phrase;await unlock.requestSubmit();
    // Removing the passphrase asks for it again, not only an unlocked page.
    await r.get('wallet-passphrase-remove').click();const removal=r.get('wallet-remove-form');assert.equal(removal.hidden,false);checks++;
    await removal.requestSubmit();assert.equal(removal.nativeBlocked,true,'the current passphrase is required');checks++;
    removal.elements.current.value='wrong horse battery staple';await removal.requestSubmit();
    assert.match(removal.querySelector().textContent,/Wrong current passphrase/);checks++;assert.equal(removal.elements.current.value,'');checks++;
    assert.equal(r.get('wallet-lock-state').textContent,'Unlocked','a wrong passphrase removes nothing');checks++;assert.equal(saved().includes(bobSecret),false);checks++;
    removal.elements.current.value=phrase;await removal.requestSubmit();assert.equal(r.get('wallet-lock-state').textContent,'Not encrypted',r.get('wallet-feedback').textContent);checks++;
    assert.equal(removal.hidden,true);checks++;
    assert.ok(saved().includes(bobSecret),'removing the passphrase saves the key unencrypted again');checks++;
    for(const h of [c,r]){assert.equal(JSON.stringify(h.calls).includes(phrase),false,'the passphrase never leaves the page');checks++;}
  }
  // Changing the passphrase asks for the current one; a first one does not.
  {
    const c=await setup(),phrase='correct horse battery staple',next='another battery staple',form=c.get('wallet-passphrase-form');
    c.get('import-private-key').value=bobSecret;await c.get('wallet-import-form').requestSubmit();
    await c.get('wallet-passphrase-open').click();assert.equal(c.get('wallet-current-field').hidden,true,'a first passphrase needs no current one');checks++;
    form.elements.passphrase.value=form.elements.confirm.value=phrase;await form.requestSubmit();assert.equal(c.get('wallet-lock-state').textContent,'Unlocked',form.querySelector().textContent);checks++;
    const salt=()=>JSON.parse([...c.savedStorage.entries()].find(([name])=>name.startsWith('hashstash.browser-wallet.v1.'))[1]).lock.salt,before=salt();
    await c.get('wallet-passphrase-open').click();assert.equal(c.get('wallet-current-field').hidden,false,'changing it asks for the current one');checks++;
    form.elements.passphrase.value=form.elements.confirm.value=next;await form.requestSubmit();assert.equal(form.nativeBlocked,true);checks++;
    form.elements.passphrase.value=form.elements.confirm.value=next;form.elements.current.value='wrong horse battery staple';await form.requestSubmit();
    assert.match(form.querySelector().textContent,/Wrong current passphrase/);checks++;assert.equal(salt(),before,'a wrong current passphrase changes nothing');checks++;
    assert.equal(form.elements.current.value,'','the current passphrase field is cleared after every attempt');checks++;
    form.elements.passphrase.value=form.elements.confirm.value=next;form.elements.current.value=phrase;await form.requestSubmit();
    assert.equal(c.get('wallet-feedback').textContent,'Passphrase changed.',form.querySelector().textContent);checks++;assert.notEqual(salt(),before);checks++;
    assert.equal(JSON.stringify(c.calls).includes(phrase)||JSON.stringify(c.calls).includes(next),false,'no passphrase leaves the page');checks++;
  }
  // A passphrase covers this network's keys only. Keys the site keeps
  // unencrypted for another network, as after a network reset, are counted.
  {
    const other='5c'.repeat(32),saved=new Map(),key=a.browserApi.publicKey(bobSecret);
    saved.set(`hashstash.browser-wallet.v1.${other}`,JSON.stringify({version:1,chain_id:other,revision:'0',selected:key,wallets:[{id:key,public_key:key,private_key:bobSecret,backed_up:false}]}));
    const c=await setup({savedStorage:saved}),status=()=>c.get('wallet-security-status').textContent;
    assert.equal(c.get('wallet-security').hidden,false,'the panel shows the other network’s keys');checks++;
    assert.match(status(),/also keeps 1 private key unencrypted for another network/);checks++;
    c.get('import-private-key').value='0'.repeat(63)+'5';await c.get('wallet-import-form').requestSubmit();
    await c.get('wallet-passphrase-open').click();const form=c.get('wallet-passphrase-form');form.elements.passphrase.value=form.elements.confirm.value='correct horse battery staple';await form.requestSubmit();
    assert.match(c.get('wallet-feedback').textContent,/for this network are now encrypted/);checks++;
    assert.match(c.get('wallet-feedback').textContent,/create a new key now and move your funds/,'migrated keys are not promised full protection');checks++;
    assert.match(status(),/which this network's passphrase does not cover/);checks++;
    assert.ok(saved.get(`hashstash.browser-wallet.v1.${other}`).includes(bobSecret),'the other network’s store is left unchanged');checks++;
  }
  console.log(`Browser wallet UI: ${checks} integration assertions passed.`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
