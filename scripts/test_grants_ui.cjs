'use strict';
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {harness,response,addr,deferred,settle}=require('./test_wallet_ui.cjs');
const {exactInput}=require('../ui/amounts.js');
let checks=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(v,m)=>{assert.ok(v,m);checks++;};
const sha=b=>createHash('sha256').update(b).digest(),bytes=v=>typeof v==='string'?Buffer.from(v,'hex'):Buffer.from(v);
function compact(value){let n=BigInt(value),length=n<251n?1:n<=65535n?2:n<=4294967295n?4:8,out=[];for(let i=0;i<length;i++){out.push(Number(n&255n));n>>=8n;}return Buffer.from(length===1?out:[length===2?251:length===4?252:253,...out]);}
function amount(value){let n=BigInt(value),out=[];while(n){out.push(Number(n&255n));n>>=8n;}return Buffer.concat([compact(out.length),Buffer.from(out)]);}
function prepare(chain,p){const g=p.operation.Propose,data=bytes(p.data_hex||'');return {format:'hashstash-unsigned-anchor',chain_id:chain,body:Buffer.concat([bytes(p.sender),compact(p.nonce),amount(p.fee),bytes(p.anchor),compact(p.expiry_blocks),compact(3),compact(g.round),bytes(g.description),compact(0),compact(g.proposal.Grant.payments.length),...g.proposal.Grant.payments.flatMap(payment=>[bytes(payment.recipient),amount(payment.amount)]),amount(g.support),compact(data.length),data]).toString('hex')};}
const broadcasts=h=>h.calls.filter(c=>c.body.method==='broadcasttransaction');
async function setup(){
 const h=await harness({realWallet:true,publicWeb:true});h.handlers.preparetransaction=p=>response({result:prepare(h.currentSnapshot.status.chain_id,p)});h.handlers.broadcasttransaction=p=>response({result:{transaction_id:sha(sha(bytes(p.raw))).toString('hex')}});
 // Quote the weight of the exact body the node would prepare, as the wallet re-derives it.
 h.nominalFee=h.fee;h.fee=(p={})=>{let fee=1n;for(let i=0;i<8;i++){const size=bytes(prepare(h.currentSnapshot.status.chain_id,{...p,fee:String(fee),nonce:p.nonce??0,expiry_blocks:p.expiry_blocks??2}).body).length+64,quote=h.nominalFee(p,size);if(BigInt(quote.fee)===fee)return quote;fee=BigInt(quote.fee);}throw Error('fixture fee did not converge');};
 h.get('import-private-key').value='01'.padStart(64,'0');await h.get('wallet-import-form').requestSubmit();
 h.keys=[2,3,4].map(n=>h.browserApi.publicKey(n.toString(16).padStart(64,'0'))).sort();h.form=h.get('propose-form');h.form.elements.type.value='grant';h.form.elements.support.value=exactInput('1');
 h.fill=async payments=>{while(h.get('grant-payments').children.length<payments.length)await h.get('grant-add').click();for(let i=0;i<payments.length;i++){const row=h.grantRow(i);row.recipient.value=addr(payments[i][0]);row.amount.value=exactInput(payments[i][1]);await row.amount.fire('input');}await h.form.fire('input');await h.timersDue();await h.timersDue();for(let i=0;i<100&&h.get('propose-fee-quote').textContent==='—'&&!h.get('propose-fee-error').textContent;i++)await new Promise(resolve=>setTimeout(resolve,5));};return h;
}
async function run(){
 {
  const h=await setup();await h.fill([[h.keys[0],'20']]);h.grantRow().recipient.value='@Alice';
  await h.form.fire('input');await h.timersDue();await h.form.requestSubmit();
  eq(broadcasts(h).length,0,'grant recipients require a checksummed address');
  ok(!h.calls.some(call=>/^explorer_names?$/.test(call.body.method)),'grant validation does not resolve aliases');
 }
 {
  const h=await setup();await h.fill([[h.keys[1],'10'],[h.keys[0],'20'],[h.keys[1],'30']]);eq(h.get('grant-total').textContent,'0.06 hash');
  const latest=h.calls.filter(c=>c.body.method==='fee_quote').at(-1);assert.ok(latest,h.get('propose-fee-error').textContent||h.get('wallet-feedback').textContent);const quote=latest.body.params;eq(quote.operation.Propose.proposal.Grant.payments.map(p=>[bytes(p.recipient).toString('hex'),p.amount]),[[h.keys[0],'20'],[h.keys[1],'40']],'duplicate destinations combine and sort before the fee quote');eq(h.calls.filter(c=>c.body.method==='grant_quote').at(-1).body.params,{amount:'60'});eq(h.get('propose-fee-quote').textContent,'0.004 hash','two payouts and the proposal record each add 1,024 weight');
  await h.form.requestSubmit();eq(broadcasts(h).length,1,h.form.feedback.textContent);const raw=bytes(broadcasts(h)[0].body.params.raw),body=raw.subarray(0,-64),decoded=h.browserApi.decodeUnsigned({format:'hashstash-unsigned-anchor',chain_id:h.currentSnapshot.status.chain_id,body:body.toString('hex')});eq(JSON.parse(JSON.stringify(decoded.operation.Propose.proposal.Grant.payments)),[{recipient:h.keys[0],amount:'20'},{recipient:h.keys[1],amount:'40'}]);eq(decoded.fee,'4','grant payments do not include the proposal fee');
  const tag=sha(Buffer.from('Hashstash/anchor-only-transaction')),digest=sha(Buffer.concat([tag,tag,body]));ok(h.noble.schnorr.verify(raw.subarray(-64),digest,bytes(decoded.sender)),'the real browser signs all payouts with the current domain');
 }
 for(const advance of [0,2]){
  const h=await setup();await h.fill([[h.keys[0],'20']]);const held=deferred();let request;
  h.handlers.preparetransaction=p=>{request=p;return held.promise;};const sending=h.form.requestSubmit();for(let i=0;i<100&&!request;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.ok(request);
  h.currentSnapshot.status.height+=advance;h.currentSnapshot.status.tip='72'.repeat(32);h.currentSnapshot.status.state_root='73'.repeat(32);await h.refresh();
  held.resolve(response({result:prepare(h.currentSnapshot.status.chain_id,request)}));await sending;
  eq(broadcasts(h).length,0,'delayed preparation cannot sign after a height advance or same-height reorganization');ok(h.form.feedback.textContent.includes('changed'));
 }
 for(const mutation of ['amount','recipient','order']){
  const h=await setup();await h.fill([[h.keys[0],'20'],[h.keys[1],'40']]);h.handlers.preparetransaction=p=>{p=JSON.parse(JSON.stringify(p));const list=p.operation.Propose.proposal.Grant.payments;if(mutation==='amount')list[1].amount='41';if(mutation==='recipient')list[1].recipient=h.keys[2];if(mutation==='order')list.reverse();return response({result:prepare(h.currentSnapshot.status.chain_id,p)});};await h.form.requestSubmit();eq(broadcasts(h).length,0,mutation+' substitution must not sign');ok(!!h.form.feedback.textContent);
 }
 {
  const h=await setup();await h.fill([[h.keys[0],'20'],[h.keys[1],'40']]);const held=deferred();let p;h.handlers.preparetransaction=request=>{p=request;return held.promise;};const sending=h.form.requestSubmit();for(let i=0;i<100&&!p;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.ok(p,'preparation reached the held RPC');h.grantRow(1).amount.value=exactInput('50');held.resolve(response({result:prepare(h.currentSnapshot.status.chain_id,p)}));await sending;eq(broadcasts(h).length,0,'editing any row while preparing cancels signing');
 }
 {
  const h=await setup();await h.fill([[h.keys[0],'20'],[h.keys[1],'40']]);await h.grantRow(0).remove.click();eq(h.get('grant-payments').children.length,1);eq(h.get('grant-total').textContent,exactInput('40')+' hash');eq(h.grantRow(0).remove.disabled,true);await h.grantRow(0).remove.click();eq(h.get('grant-payments').children.length,1,'the last recipient cannot be removed');for(let i=1;i<32;i++)await h.get('grant-add').click();eq(h.get('grant-payments').children.length,32);eq(h.get('grant-add').disabled,false,'no independent recipient-count cutoff');
 }
 {
  const h=await setup(),keys=Array.from({length:32},(_,i)=>h.browserApi.publicKey(BigInt(i+10).toString(16).padStart(64,'0'))).sort();await h.fill(keys.map(key=>[key,'1']));await h.form.requestSubmit();eq(broadcasts(h).length,1,h.form.feedback.textContent);const raw=bytes(broadcasts(h)[0].body.params.raw),decoded=h.browserApi.decodeUnsigned({format:'hashstash-unsigned-anchor',chain_id:h.currentSnapshot.status.chain_id,body:raw.subarray(0,-64).toString('hex')});eq(decoded.operation.Propose.proposal.Grant.payments.length,32);eq(decoded.fee,String(Math.ceil((raw.length+33*1024)/1024)),'upfront recipient weight scales beyond sixteen, plus the proposal record');ok(Number(decoded.fee)>=33);
 }
 {
  const h=await setup();h.currentSnapshot.status.settings.block_bytes=2048;await h.refresh();await h.fill([[h.keys[0],'1'],[h.keys[1],'1']]);await h.form.requestSubmit();eq(broadcasts(h).length,0,'a smaller block weight can reject even two recipients');ok(h.get('propose-fee-error').textContent.includes('block capacity'));
 }
 {
  // The understated quote still counts the payout and proposal record weight.
  const h=await setup();h.fee=p=>h.nominalFee(p,0n);h.currentSnapshot.status.settings.block_bytes=2048;await h.refresh();h.form.elements.description.value='a'.repeat(2000);await h.fill([[h.keys[0],'1']]);await h.form.requestSubmit();eq(broadcasts(h).length,0,'signed bytes must fit the block capacity even when the node understates quote weight');ok(h.form.feedback.textContent.includes('block capacity'));
 }
 for(const invalid of ['0','-1','1.0000000000000000001','9'.repeat(160)]){
  const h=await setup();await h.fill([[h.keys[0],'1']]);h.grantRow().amount.value=invalid;await h.grantRow().amount.fire('input');await h.timersDue();await h.form.requestSubmit();eq(broadcasts(h).length,0,'invalid exact amount cannot sign');
 }
 for(const fee of [undefined,'0','1','3','1.5']){
  const h=await setup(),original=h.fee;h.fee=p=>({...original(p),grant_recipient_fee:fee});await h.fill([[h.keys[0],'20'],[h.keys[1],'40']]);await h.form.requestSubmit();eq(broadcasts(h).length,0,'incorrect or missing grant recipient charge cannot sign');ok(h.get('propose-fee-error').textContent.includes('fee'));
 }
 // Audit F046: every proposal pays 1,024 weight for its permanent records.
 for(const fee of [undefined,'0','2']){
  const h=await setup(),original=h.fee;h.fee=p=>({...original(p),record_fee:fee});await h.fill([[h.keys[0],'20'],[h.keys[1],'40']]);await h.form.requestSubmit();eq(broadcasts(h).length,0,'incorrect or missing proposal record charge cannot sign');ok(h.get('propose-fee-error').textContent.includes('fee'));
 }
 {
  const h=await setup();h.handlers.grant_quote=()=>response({result:{feasible:false}});await h.fill([[h.keys[0],'20'],[h.keys[1],'40']]);await h.form.requestSubmit();eq(broadcasts(h).length,0,'an infeasible aggregate cannot be proposed');ok(h.form.feedback.textContent.includes('available revenue'));
 }
 console.log(`Multi-recipient grant UI: ${checks} wire, signing and interaction checks passed.`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
