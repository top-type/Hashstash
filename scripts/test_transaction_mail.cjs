'use strict';

// Exercise encrypted attachments through the same public DOM events as users.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {create} = require('../ui/transaction-mail.js');
const {harness, response, addr} = require('./test_wallet_ui.cjs');
const amounts = require('../ui/amounts.js');
const shares = require('../ui/shares.js');
let checks = 0;
const eq = (a,b,message) => { assert.deepEqual(a,b,message); checks++; };
const ok = (value,message) => { assert.ok(value,message); checks++; };
const rejected = async (promise,pattern) => { await assert.rejects(promise,pattern); checks++; };
const deferred = () => { let resolve; const promise = new Promise(done => {resolve=done;}); return {promise,resolve}; };
async function until(predicate,message) {
  for(let i=0;i<100&&!predicate();i++) await new Promise(resolve=>setTimeout(resolve,5));
  ok(predicate(),message);
}
async function setup() {
  const h = await harness({mail:true});
  const sender = Buffer.from(h.noble.schnorr.getPublicKey(Uint8Array.from(Buffer.from('01'.padStart(64,'0'),'hex')))).toString('hex');
  const recipient = Buffer.from(h.noble.schnorr.getPublicKey(Uint8Array.from(Buffer.from('02'.padStart(64,'0'),'hex')))).toString('hex');
  h.selectSession({id:'hot:'+sender,public_key:sender,mode:'hot'});
  await h.refresh();
  Object.assign(h,{sender,recipient});
  return h;
}
function attach(h,form,body='Private attachment text') {
  form.elements.data_format.value='private';
  form.elements.mail_recipient.value=addr(h.recipient);
  form.elements.mail_subject.value='Private attachment subject';
  form.elements.mail_body.value=body;
}
async function quote(h,form) {
  await form.fire('change');
  await form.fire('input');
  if(form.id==='trade-form') await h.get('trade-amount').fire('input');
  for(let i=0;i<5;i++) {await h.timersDue(); await new Promise(resolve=>setTimeout(resolve,5));}
  const field=h.get(form.id.replace('-form','-fee-quote'));
  await until(()=>field.textContent!=='—',`${form.id}: encrypted data receives a fee quote: ${h.get(form.id.replace('-form','-fee-error')).textContent}`);
}
async function expectEncrypted(h,form,kind) {
  await quote(h,form);
  await form.requestSubmit();
  eq(h.wallet.length,1,`${form.id}: signs exactly once: ${form.feedback.textContent}`);
  const tx=h.wallet[0];
  ok(tx.operation[kind],`${form.id}: keeps its public operation`);
  eq(tx.data_hex.length/2,2793,'fixed-size mail envelope');
  const value=await h.mailCrypto.decrypt(tx.data_hex,{chain_id:h.currentSnapshot.status.chain_id,sender:h.sender,nonce:'0'},'02'.padStart(64,'0'));
  eq(value.subject,'Private attachment subject');
  eq(value.body,'Private attachment text');
  eq(value.recipient,h.recipient);
  const rpc=JSON.stringify(h.calls);
  ok(!rpc.includes(value.subject)&&!rpc.includes(value.body),'plaintext is absent from quote/preparation/broadcast RPCs');
  ok(!rpc.includes(h.recipient),'private message target is absent from RPCs');
  return tx;
}
async function run() {
  {
    let identity={chain_id:'chain',sender:'sender',nonce:'0',wallet_id:'one',wallet_revision:1},count=0;
    const form={id:'send-form',elements:{data_format:{value:'private'},mail_recipient:{value:'target'},mail_subject:{value:'subject'},mail_body:{value:'body'}}};
    const gate=deferred(),api=create({getIdentity:()=>identity,decodeAddress:v=>v,encrypt:async()=>{count++;return gate.promise;}});
    const first=api.prepare(form),same=api.prepare(form);eq(count,1,'concurrent preparations share one encryption');
    identity={...identity,nonce:'1'};gate.resolve('cipher');
    await rejected(first,/changed/);await rejected(same,/changed/);
    assert.throws(()=>api.data(form),/Wait/);checks++;
    await api.prepare(form);eq(count,2,'nonce change requires fresh ciphertext');eq(api.data(form),'cipher');
    form.elements.mail_body.value='changed';assert.throws(()=>api.data(form),/Wait/);checks++;
    await api.prepare(form);identity={...identity,wallet_id:'two',wallet_revision:2};assert.throws(()=>api.data(form),/Wait/);checks++;
    await api.prepare(form);api.clear();assert.throws(()=>api.data(form),/Wait/);checks++;
    form.elements.data_format.value='text';eq(api.enabled(form),false);eq(await api.prepare(form),undefined);
  }
  {
    const h=await setup(),form=h.get('send-form');attach(h,form);
    form.elements.recipient.value=addr('34'.repeat(32));form.elements.amount.value=amounts.exactInput('25');
    const tx=await expectEncrypted(h,form,'TransferExact');
    eq(tx.operation.TransferExact.amount,'25');eq(tx.operation.TransferExact.recipient,Array(32).fill(0x34),'public payment is independent of encrypted target');
  }
  for(const mode of ['deposit','redeem']) {
    const h=await setup(),form=h.get('trade-form');await h.tradeTab(mode);attach(h,form);
    form.elements.amount.value=mode==='deposit'?amounts.exactInput('25'):shares.exactInput('1000000000000000');
    await expectEncrypted(h,form,mode==='deposit'?'Deposit':'Redeem');
  }
  for(const action of ['support','refund','propose']) {
    const h=await setup(),form=h.get(action+'-form');attach(h,form);
    if(action==='support') {form.elements.proposal.value='77'.repeat(32);form.elements.amount.value=amounts.exactInput('10');}
    if(action==='refund') {form.elements.proposal.value='77'.repeat(32);form.elements.round.value='0';}
    if(action==='propose') {h.grantRow().recipient.value=addr('34'.repeat(32));h.grantRow().amount.value=amounts.exactInput('10');form.elements.support.value=amounts.exactInput('1');form.elements.description.value='Unrelated stale public draft';}
    const kind={support:'Support',refund:'Refund',propose:'Propose'}[action],tx=await expectEncrypted(h,form,kind);
    if(action==='propose') {eq(tx.operation.Propose.description,Array.from(createHash('sha256').update(Buffer.from(tx.data_hex,'hex')).digest()),'proposal commits to ciphertext, never stale plaintext');ok(!JSON.stringify(h.calls).includes('Unrelated stale public draft'));}
  }
  {
    const h=await setup(),form=h.get('send-form');attach(h,form);form.elements.recipient.value=addr('34'.repeat(32));form.elements.amount.value=amounts.exactInput('25');
    await quote(h,form);const gate=deferred();let preparing=false;
    h.handlers.preparetransaction=()=>{preparing=true;return gate.promise;};
    const submitting=form.requestSubmit();await until(()=>preparing,'preparation is in flight');
    form.elements.mail_body.value='Changed while preparing';gate.resolve(response({result:{format:'hashstash-unsigned-v1',body:'abcdef'}}));await submitting;
    eq(h.wallet.length,0,'changed message never signs the old ciphertext');ok(/changed/i.test(form.feedback.textContent));
  }
  for(const mode of ['text','hex']) {
    const h=await setup(),form=h.get('send-form');form.elements.recipient.value=addr('34'.repeat(32));form.elements.amount.value=amounts.exactInput('25');form.elements.data_format.value=mode;
    form.elements.data_text.value='public text';form.elements.data_hex.value='00FF';await quote(h,form);await form.requestSubmit();
    eq(h.wallet.at(-1).data_hex,mode==='text'?Buffer.from('public text').toString('hex'):'00ff','ordinary raw/public data remains unchanged');
  }
  console.log(`Transaction Mail attachments: ${checks} checks passed`);
}
if(require.main===module)run().catch(error=>{console.error(error);process.exitCode=1;});
