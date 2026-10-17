'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {setup:outcomeSetup}=require('./test_outcome_wallet.cjs'),{deferred,settle,response}=require('./test_wallet_ui.cjs');
const amounts=require('../ui/amounts.js');let checks=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(v,m)=>{assert.ok(v,m);checks++;};
async function setup(percent=50){const h=await outcomeSetup('1000000','1000000'),s=h.currentSnapshot; s.status.settings.miner_fee_percent=percent;const previous=h.fee;
 h.fee=p=>{const r=previous(p),n=BigInt(s.status.settings.miner_fee_percent),miner=BigInt(r.fee)*n/100n;return {...r,miner_fee_percent:s.status.settings.miner_fee_percent,miner_fee:String(miner),revenue_fee:String(BigInt(r.fee)-miner)};};await h.refresh();return h;}
async function run(){
 const html=fs.readFileSync(path.join(__dirname,'../ui/index.html'),'utf8');ok(!html.includes('Miner priority'));ok(html.includes('Optional extra'));
 for(const percent of [0,50,100]){
  const h=await setup(percent),f=h.get('send-form');f.elements.extra_fee.value=amounts.exactInput('4');await h.send('10');
  const r=h.fee({sender:h.currentSession.public_key,extra_fee:'4'}),split=h.get('send-fee-allocation');eq(split.hidden,false);ok(split.textContent.includes(`Fee ${amounts.formatExactHash('5')}`));ok(split.textContent.includes(`Miner ${amounts.formatExactHash(r.miner_fee)} (${percent}%)`));ok(split.textContent.includes(`Revenue ${amounts.formatExactHash(r.revenue_fee)} (${100-percent}%)`));eq(h.get('send-fee-quote').textContent,amounts.formatExactHash('5'),'exact fee is the minimum plus requested extra');
  ok(h.get('guide-fees').textContent.includes('entire fee'));ok(h.get('guide-fees').textContent.includes(`${percent}% to the miner`));ok(f.elements.extra_fee.title.includes('entire fee'));
  await f.requestSubmit();eq(h.wallet.at(-1).fee,'5');eq(Object.hasOwn(h.wallet.at(-1),'extra_fee'),false);
 }
 for(const value of [0,1,49,51,99,100]){
  const h=await setup(),s=h.currentSnapshot;s.governance.phase={Auction:{round:0,opened:0,leader:null,lead_since:0}};s.governance.pass=null;s.pass=s.fail=null;await h.refresh();
  const option=h.get('proposal-parameter').options.find(o=>o.value==='MinerFeePercent');eq(Boolean(option.hidden),false);eq(Boolean(option.disabled),false);
  const f=h.get('propose-form');f.elements.type.value='parameter';f.elements.parameter.value='MinerFeePercent';f.elements.parameter_value.value=String(value);f.elements.support.value=amounts.exactInput('1');await h.get('proposal-parameter').fire('change');await f.fire('input');await h.timersDue();
  ok(!html.includes('proposal-direction'),'fee share uses the common direct-value field');eq(h.get('proposal-value').step,'1');ok(h.get('parameter-preview').textContent.includes(`→ ${value}%`));ok(h.get('parameter-preview').title.includes('after rest'));
  await f.requestSubmit();eq(h.wallet.at(-1).operation.Propose.proposal.Parameter,{parameter:'MinerFeePercent',old:50,new:value});
 }
 for(const invalid of ['-1','100.1','101','1.5','NaN']){
  const h=await setup(),s=h.currentSnapshot;s.governance.phase={Auction:{round:0,opened:0,leader:null,lead_since:0}};s.governance.pass=null;s.pass=s.fail=null;await h.refresh();const f=h.get('propose-form');f.elements.type.value='parameter';f.elements.parameter.value='MinerFeePercent';f.elements.parameter_value.value=invalid;f.elements.support.value=amounts.exactInput('1');await f.fire('input');await h.timersDue();await f.fire('submit');eq(h.wallet.length,0,'invalid percent cannot sign');
 }
 for(const mutation of [{fee:'6'},{minimum_fee:'2'},{extra_fee:'5'},{weight:'1025'},{account_creation_fee:'1'},{minimum_fee_rate:'2'},{minimum_fee_rate:'0'},{minimum_fee_rate:'18446744073709551616'},{miner_fee:'3',revenue_fee:'2'},{miner_fee:'2',revenue_fee:'4'},{miner_fee:'2.0'},{miner_fee_percent:51},{miner_fee_percent:101},{miner_fee_percent:'50.0'},{miner_fee:null},{revenue_fee:3}]){
  const h=await setup(),original=h.fee;h.fee=p=>({...original(p),...mutation});const f=h.get('send-form');f.elements.extra_fee.value=amounts.exactInput('4');await h.send('10');eq(h.get('send-submit').disabled,true,JSON.stringify(mutation));eq(h.get('send-fee-allocation').hidden,true);await f.fire('submit');eq(h.wallet.length,0);
 }
 {
  const h=await setup(),f=h.get('send-form');f.elements.extra_fee.value=amounts.exactInput('4');await h.send('10');const original=h.handlers.transfer_quote,pending=deferred();let old;h.handlers.transfer_quote=p=>{old=original(p);return pending.promise;};
  f.elements.amount.value=amounts.exactInput('11');await f.fire('input');await h.timersDue();eq(h.get('send-fee-allocation').hidden,true,'edited amounts clear old allocation');
  h.currentSnapshot.status.settings.miner_fee_percent=100;await h.refresh();pending.resolve(old);await settle();eq(h.get('send-submit').disabled,true,'an otherwise valid old-ratio quote cannot authorize spending');eq(h.get('send-fee-allocation').hidden,true);
  h.handlers.transfer_quote=original;await h.send('11');eq(h.get('send-submit').disabled,false,'fresh quote under the new split can authorize spending');ok(h.get('send-fee-allocation').textContent.includes('(100%)'));
 }
 {
  const h=await setup(),s=h.currentSnapshot;s.governance.pending={MinerFeePercent:100};s.governance.phase={Rest:{until:100}};s.governance.pass=null;s.pass=s.fail=null;await h.refresh();const f=h.get('send-form');f.elements.extra_fee.value=amounts.exactInput('4');await h.send('10');ok(h.get('send-fee-allocation').textContent.includes('(50%)'),'approved-but-pending change does not alter effective split during rest');
  s.status.settings.miner_fee_percent=100;s.status.tip='e'.repeat(64);s.governance.phase={Auction:{round:1,opened:100,leader:null,lead_since:100}};await h.refresh();await h.timersDue();ok(h.get('send-fee-allocation').textContent.includes('(100%)'),'new effective split appears only from current settings');
 }

 {
  const h=await setup(),s=h.currentSnapshot;s.status.settings.minimum_fee_rate=2;s.status.fee_policy.minimum_fee_rate='2';s.governance.phase={Auction:{round:0,opened:0,leader:null,lead_since:0}};s.governance.pass=null;s.pass=s.fail=null;await h.refresh();
  for(const value of ['0','3','1']) {
   const f=h.get('propose-form');f.elements.type.value='parameter';f.elements.parameter.value='MinimumFeeRate';f.elements.parameter_value.value=value;f.elements.support.value=amounts.exactInput('1');await h.get('proposal-parameter').fire('change');await f.fire('input');await h.timersDue();await f.requestSubmit();eq(h.wallet.at(-1).operation.Propose.proposal.Parameter,{parameter:'MinimumFeeRate',old:2,new:Number(value)});
  }
 }
 {
  const h=await setup(),s=h.currentSnapshot;await h.send('10');const pending=deferred();let old;h.handlers.transfer_quote=p=>{old=h.transferQuote(p);return pending.promise;};
  h.get('send-form').elements.amount.value=amounts.exactInput('11');await h.get('send-form').fire('input');await h.timersDue();s.status.settings.minimum_fee_rate=4;s.status.fee_policy.minimum_fee_rate='4';await h.refresh();pending.resolve(response({result:old}));await settle();eq(h.get('send-submit').disabled,true,'fee rate change invalidates an in-flight payment quote');
  delete h.handlers.transfer_quote;await h.send('11');eq(h.get('send-submit').disabled,false);eq(h.get('send-fee-quote').textContent,amounts.formatExactHash('2'),'fresh quote uses governed rate with ceiling division');
 }
 {
  // Audit F157: a fee-rate increase due within the lifetime is shown without
  // blocking a fee that is valid now.
  const h=await setup(),original=h.fee,f=h.get('send-form');
  h.fee=p=>({...original(p),scheduled_change:{parameter:'MinimumFeeRate',value:'2',activation_height:21,effective_height:22,minimum_fee:'9',valid_after:false}});
  await h.send('10');ok(h.get('send-fee-error').textContent.includes('from block 22'),h.get('send-fee-error').textContent);eq(h.get('send-fee-error').hidden,false);eq(h.get('send-submit').disabled,false,'the warning does not block a fee that is valid now');
  h.fee=p=>({...original(p),scheduled_change:{parameter:'MinimumFeeRate',value:'2',activation_height:21,effective_height:22,minimum_fee:'1',valid_after:true}});
  f.elements.amount.value=amounts.exactInput('11');await f.fire('input');await h.timersDue();await settle();eq(h.get('send-fee-error').hidden,true,'a fee that stays valid needs no warning');
 }
 console.log(`Whole fee split UI: ${checks} checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});
