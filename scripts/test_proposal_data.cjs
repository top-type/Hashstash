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
 h.handlers.fee_quote=params=>{const {chain_id,tip,state_root,height}=s.status,data=params.data_hex||'';return response({result:{miner_fee_percent:50,miner_fee:'0',revenue_fee:'1',chain_id,tip,state_root,height,anchor:tip,anchor_height:height,expiry_blocks:params.expiry_blocks??2,expiry_height:String(BigInt(height)+BigInt(params.expiry_blocks??2)),sender:require('./test_wallet_ui.cjs').addr(params.sender),sender_public_key:params.sender,fee:'1',minimum_fee:'1',account_creation_fee:'0',grant_recipient_fee:'0',extra_fee:'0',weight:'512',minimum_fee_rate:'1',data_hex:data,data_bytes:data.length/2}});};
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
 console.log(`${checks} shared-proposal explanation checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});
