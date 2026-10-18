'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),{harness,response,settle,deferred,addr}=require('./test_wallet_ui.cjs');let checks=0;
const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(a,m)=>{assert.ok(a,m);checks++;};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const wait=async f=>{for(let i=0;i<100&&!f();i++)await new Promise(r=>setTimeout(r,5));assert.ok(f());};
async function run(){
 const h=await harness({rationale:true}),api=h.proposalData;
 eq(Buffer.from(api.encode('  Full proposal\nSecond line.  '),'hex').toString(),'Full proposal\nSecond line.');
 eq(api.encode('   '),'');eq(api.verifiedText('Published text',sha('Published text')),'Published text');eq(api.verifiedText('Different text',sha('Published text')),'');eq(api.verifiedText(' Published text',sha(' Published text')),'');
 for(const text of ['é'.repeat(1025),'\ud800','\udc00','"'.repeat(2049)]){assert.throws(()=>api.encode(text));checks++;}
 for(const code of [0,8,11,12,14,31,127,128,133,159]){const text=`Before${String.fromCharCode(code)}after`;assert.throws(()=>api.encode(text),/unsupported control/);checks++;eq(api.verifiedText(text,sha(text)),'');}
 const readable='First line\nSecond line\r\n\tIndented.';eq(Buffer.from(api.encode(readable),'hex').toString(),readable);eq(api.verifiedText(readable,sha(readable)),readable);
 api.encode('é'.repeat(1024));checks++;
 eq(Buffer.from(api.encode('"'.repeat(2048)),'hex').toString(),'"'.repeat(2048),'plain text does not incur JSON escaping overhead');
 const s=h.currentSnapshot; s.status.settings.block_bytes=16384;

 s.status.fee_policy={minimum_fee_rate:'1',fee_scale:1024,account_weight:1024};
 h.handlers.fee_quote=params=>{const {chain_id,tip,state_root,height}=s.status,data=params.data_hex||'';return response({result:{miner_fee_percent:50,miner_fee:'0',revenue_fee:'1',chain_id,tip,state_root,height,anchor:tip,anchor_height:height,expiry_blocks:params.expiry_blocks??2,expiry_height:String(BigInt(height)+BigInt(params.expiry_blocks??2)),sender:require('./test_wallet_ui.cjs').addr(params.sender),sender_public_key:params.sender,fee:'1',minimum_fee:'1',account_creation_fee:'0',grant_recipient_fee:'0',extra_fee:'0',weight:'512',minimum_fee_rate:'1',data_hex:data,data_bytes:data.length/2,...(params.operation?.Propose?{miner_fee:'1',fee:'2',minimum_fee:'2',weight:'1536',record_fee:'1'}:{record_fee:'0'})}});};
 await h.refresh();const f=h.get('propose-form');f.elements.type.value='parameter';f.elements.parameter.value='Interval';f.elements.parameter_value.value='5';f.elements.support.value='0.001';f.elements.description.value='Fund careful experiments, with public results.';
 await f.fire('input');await h.timersDue();await wait(()=>h.get('propose-fee-quote').textContent!=='—');await f.requestSubmit();
 eq(h.wallet.length,1);const signed=h.wallet[0];eq(signed.data_hex,api.encode(f.elements.description.value));eq(Buffer.from(signed.operation.Propose.description).toString('hex'),sha(f.elements.description.value));
 const id='ab'.repeat(32),text='<script>Literal public explanation</script>\nShared between visitors.';
 s.proposals=[{id,proposal:{round:s.governance.phase.Auction.round,support:'10',description:sha(text),action:{Parameter:{parameter:'Interval',old:15,new:5}},refund_height:null}}];
 h.handlers.explorer_governance=()=>response({result:{chain_id:s.status.chain_id,proposals:[{id,description:sha(text),description_text:text}]}});
 await h.refresh();await h.navigate('#governance');await settle();ok(h.get('proposal-list').textContent.includes(text),'a fresh browser can read a signed explanation without localStorage');
 s.proposals=[{...s.proposals[0],id:'bc'.repeat(32)}];h.handlers.explorer_governance=()=>response({result:{chain_id:s.status.chain_id,proposals:[{id:'bc'.repeat(32),description:sha(text),description_text:'Altered rationale'}]}});await h.refresh();await settle();
 ok(!h.get('proposal-list').textContent.includes('Altered rationale'));ok(!h.get('proposal-list').textContent.includes('No verified explanation published.'));
 const action={Grant:{payments:[{recipient:'12'.repeat(32),amount:'1000'},{recipient:'34'.repeat(32),amount:'2000'}]}};
 const decision={id:'de'.repeat(32),proposal_id:id,round:0,started:240,blocks:16,started_height:16,leading_blocks:0,proposal:action};
 s.governance.phase={Governance:decision};s.governance.pass={...s.governance.world,grant_escrow:'3000'};
 s.proposals=[{id,proposal:{round:0,support:'10',description:sha(text),action,refund_height:null}}];await h.refresh();await settle();
 const payouts=h.get('gov-grant-payments').children;
 eq(payouts.length,2,'the current decision shows every recipient, not just a total or first destination');
 for(let i=0;i<2;i++){eq(payouts[i].children[0].textContent,addr(action.Grant.payments[i].recipient));eq(payouts[i].children[1].textContent,`${i+1} hash`);}
 eq(h.get('gov-decision-message').textContent,text,'verified signed public text appears directly with the current decision');
 eq(h.get('gov-decision-message').hidden,false);eq(h.get('gov-decision-message').children.length,0,'markup in a public message is only text, never executable HTML');
 ok(!h.get('proposal-list').textContent.includes('Grant '),'recipient rows replace a redundant grant category in proposal cards');
 ok(!/awarded|paid|provisional/i.test(h.get('gov-result-status').textContent),'a leading outcome is not presented as a paid award');
 h.handlers.snapshot=()=>response({error:{message:'offline'}});await h.refresh();eq(h.get('gov-decision-message').hidden,true,'disconnected state does not retain current-decision text');
 delete h.handlers.snapshot;await h.refresh();eq(h.get('gov-decision-message').textContent,text);
 const unpublished='cb'.repeat(32);decision.proposal_id=unpublished;s.proposals=[{...s.proposals[0],id:unpublished}];h.handlers.explorer_governance=()=>response({result:{chain_id:s.status.chain_id,proposals:[{id:unpublished,description:sha(text),description_text:null}]}});await h.refresh();await settle();
 eq(h.get('gov-decision-message').hidden,true,'an opaque commitment or encrypted attachment is not a public message');eq(h.get('gov-decision-message').textContent,'');
 const late=deferred(),lateId='db'.repeat(32);decision.proposal_id=lateId;s.proposals=[{...s.proposals[0],id:lateId}];h.handlers.explorer_governance=()=>late.promise;await h.refresh();await settle();
 s.governance.phase={Rest:{until:780,pending:null}};s.governance.pass=null;await h.refresh();late.resolve(response({result:{chain_id:s.status.chain_id,proposals:[{id:lateId,description:sha(text),description_text:text}]}}));await settle();
 eq(h.get('gov-decision-message').hidden,true,'a late public-data response cannot revive a completed decision');
 const missingId='fc'.repeat(32);decision.proposal_id=missingId;decision.proposal={Parameter:{parameter:'Interval',old:15,new:5}};s.governance.phase={Governance:decision};s.governance.pass={...s.governance.world};s.proposals=[];
 h.handlers.explorer_governance=()=>response({result:{chain_id:s.status.chain_id,proposals:[{id:missingId,description:sha(text),description_text:text}]}});await h.refresh();await settle();
 eq(h.get('gov-title').textContent,'Set target block interval to 5s','setting changes keep their concrete action title');eq(h.get('gov-grant-payments').hidden,true);
 eq(h.get('gov-decision-message').textContent,text,'the current decision gets its own canonical-data query even outside the proposal page');
 {
  // Drafts typed into the description are never written to browser storage;
  // the retired per-draft cache is removed, and other settings are kept.
  const entries=new Map([['hashstash-description-'+'ab'.repeat(32),'old abandoned draft'],['hashstash-description-'+'cd'.repeat(32),'another'],['hashstash-chat-muted:x','[]']]);
  const store={get length(){return entries.size;},key:i=>[...entries.keys()][i]??null,getItem:k=>entries.get(k)??null,setItem:(k,v)=>entries.set(k,String(v)),removeItem:k=>entries.delete(k)};
  const d=await harness({rationale:true,localStorage:store}),ds=d.currentSnapshot;ds.status.settings.block_bytes=16384;ds.status.fee_policy=s.status.fee_policy;
  d.handlers.fee_quote=params=>{const {chain_id,tip,state_root,height}=ds.status,data=params.data_hex||'';return response({result:{miner_fee_percent:50,miner_fee:'0',revenue_fee:'1',chain_id,tip,state_root,height,anchor:tip,anchor_height:height,expiry_blocks:params.expiry_blocks??2,expiry_height:String(BigInt(height)+BigInt(params.expiry_blocks??2)),sender:addr(params.sender),sender_public_key:params.sender,fee:'1',minimum_fee:'1',account_creation_fee:'0',grant_recipient_fee:'0',extra_fee:'0',weight:'512',minimum_fee_rate:'1',data_hex:data,data_bytes:data.length/2,...(params.operation?.Propose?{miner_fee:'1',fee:'2',minimum_fee:'2',weight:'1536',record_fee:'1'}:{record_fee:'0'})}});};
  eq([...entries.keys()],['hashstash-chat-muted:x'],'legacy description drafts are removed at startup');
  await d.refresh();const form=d.get('propose-form');form.elements.type.value='parameter';form.elements.parameter.value='Interval';form.elements.parameter_value.value='5';form.elements.support.value='0.001';
  for(const draft of ['Secret first wording','Second wording','Final public explanation']){form.elements.description.value=draft;await form.fire('input');await d.timersDue();await wait(()=>d.get('propose-fee-quote').textContent!=='—');}
  eq([...entries.keys()],['hashstash-chat-muted:x'],'fee quotes for intermediate drafts write nothing');
  await form.requestSubmit();eq(d.wallet.length,1,form.feedback.textContent);eq([...entries.keys()],['hashstash-chat-muted:x'],'a successful submission writes nothing either');
  const mine='ef'.repeat(32);ds.proposals=[{id:mine,proposal:{round:ds.governance.phase.Auction.round,support:'1',description:sha('Final public explanation'),action:{Parameter:{parameter:'Interval',old:15,new:5}},refund_height:null}}];
  d.handlers.explorer_governance=()=>response({result:{chain_id:ds.status.chain_id,proposals:[{id:mine,description:sha('Final public explanation'),description_text:null}]}});
  await d.refresh();await d.navigate('#governance');await settle();ok(d.get('proposal-list').textContent.includes('Final public explanation'),'this session still shows its own submitted explanation before the explorer has it');
  ok(!d.get('proposal-list').textContent.includes('Secret first wording'),'abandoned drafts are not shown');
 }
 {
  // Anyone can register proposals whose text is never published. Their
  // lookups back off instead of repeating on every block, and each refresh
  // starts only a few, the active decision first.
  const g=await harness({rationale:true}),gs=g.currentSnapshot,round=gs.governance.phase.Auction.round;
  const ids=Array.from({length:12},(_,i)=>(0x40+i).toString(16).repeat(32)),published=ids[11],text='Published once, cached after';
  gs.proposals=ids.map(id=>({id,proposal:{round,support:'1',description:sha(id===published?text:id),action:{Parameter:{parameter:'Interval',old:15,new:5}},refund_height:null}}));
  g.handlers.explorer_governance=p=>response({result:{chain_id:gs.status.chain_id,proposals:[{id:p.proposal,description:sha(p.proposal===published?text:p.proposal),description_text:p.proposal===published?text:null}]}});
  const lookups=id=>g.calls.filter(c=>c.body.method==='explorer_governance'&&(!id||c.body.params.proposal===id)).length;
  const block=async()=>{gs.status.height++;gs.status.tip=gs.status.height.toString(16).padStart(64,'0');await g.refresh();await settle();};
  await g.refresh();await g.navigate('#governance');await settle();
  eq(lookups(),4,'one refresh starts at most four explanation lookups');
  for(let i=0;i<8;i++)await block();
  eq(ids.map(id=>lookups(id)),ids.map(()=>1),'every proposal is looked up once across many new blocks');
  ok(g.get('proposal-list').textContent.includes(text),'a published explanation is verified and shown');
  g.wallClock+=31e3;for(let i=0;i<4;i++)await block();
  eq(lookups(published),1,'a verified explanation stays cached');
  eq(ids.slice(0,11).map(id=>lookups(id)),ids.slice(0,11).map(()=>2),'unpublished ones are retried once after the back-off');
  g.wallClock+=31e3;for(let i=0;i<4;i++)await block();
  eq(lookups(),23,'the next retry waits twice as long');
  // The active decision is looked up first, and its description hash, once
  // known, is a new commitment to check.
  const active='4c'.repeat(32);gs.governance.phase={Governance:{id:'de'.repeat(32),proposal_id:active,round,started:240,blocks:16,started_height:16,leading_blocks:0,proposal:{Parameter:{parameter:'Interval',old:15,new:5}}}};gs.governance.pass={...gs.governance.world};
  const before=g.calls.length;await block();
  eq(g.calls.slice(before).filter(c=>c.body.method==='explorer_governance')[0]?.body.params.proposal,active,'the active decision is looked up first');
  await block();eq(lookups(active),1);
  gs.proposals=[{id:active,proposal:{round,support:'1',description:sha(active),action:{Parameter:{parameter:'Interval',old:15,new:5}},refund_height:null}},...gs.proposals];await block();
  eq(lookups(active),2,'a newly known description hash is checked without waiting for the back-off');
 }
 console.log(`${checks} shared-proposal explanation checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});
