'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {harness,response,addr}=require('./test_wallet_ui.cjs');
const amounts=require('../ui/amounts.js');
const shares=require('../ui/shares.js'),stash=v=>`${shares.formatAmount(v)} stash`;
let checks=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(x,m)=>{assert.ok(x,m);checks++;};
const walk=n=>[n,...(n.children||[]).flatMap(walk)],cash=n=>walk(n).find(x=>x.className==='wallet-balance-hash')?.['aria-label'];
const balanceRows=n=>n.children.filter(row=>row.className==='wallet-balance-row');
const selectorValues=h=>walk(h.get('account-summary')).filter(n=>['account-summary-cash','account-summary-stash'].includes(n.className));
const recipient='34'.repeat(32),exact=amounts.exactInput;
async function setup(pass='1000',fail='400',version=27,options={}){
 const h=await harness(options),s=h.currentSnapshot;
 if(options.mail){const sender=Buffer.from(h.noble.schnorr.getPublicKey(Uint8Array.from(Buffer.from('01'.padStart(64,'0'),'hex')))).toString('hex');h.selectSession({id:'hot:'+sender,public_key:sender,mode:'hot'});}
 h.handlers.explorer_mail=()=>response({result:{chain_id:s.status.chain_id,ready:true,tip:s.status.tip,anchor:s.status.tip,indexed_height:s.status.height,messages:[],next_cursor:null,scan_cursor:`${s.status.height}:9223372036854775807`}});
 h.handlers.explorer_chat=()=>response({result:{chain_id:s.status.chain_id,ready:true,items:[],pending:[],next_cursor:null}});
 s.config.protocol_version=s.status.protocol_version=version;
 Object.assign(s.status.settings,{pass_margin_bps:0,miner_fee_percent:50});
 s.status.fee_policy={minimum_fee_rate:'1',fee_scale:1024,account_weight:1024};
 s.governance.pass={...s.governance.world};
 s.governance.phase={Governance:{id:'d'.repeat(64),round:0,started:240,duration:240,start_integral:'0',proposal:{Parameter:{parameter:'Lead',old:60,new:120}}}};
 s.pass={...s.account,account:{...s.account.account,ordinary:pass}};
 s.fail={...s.account,account:{...s.account.account,ordinary:fail}};s.account=s.fail;
 h.handlers.fee_quote=p=>response({result:h.fee(p)});
 h.handlers.transfer_quote=p=>{const f=h.fee(p);return response({result:{...f,recipient:addr(p.recipient),public_key:p.recipient,amount:p.amount,recipient_receives:p.amount,total_debit:String(BigInt(p.amount)+BigInt(f.fee)),pending:false}});};
 await h.refresh();
 h.trade=async(amount,outcome='Pass')=>{const f=h.get('trade-form');f.elements.outcome.value=outcome;await h.get('trade-outcome').fire('change');f.elements.amount.value=exact(amount);await h.get('trade-amount').fire('input');await h.timersDue();await h.timersDue();return f;};
 h.send=async amount=>{const f=h.get('send-form');f.elements.recipient.value=addr(recipient);f.elements.amount.value=exact(amount);await f.fire('input');await h.timersDue();return f;};
 return h;
}
async function run(){
 const html=fs.readFileSync(path.join(__dirname,'../ui/index.html'),'utf8'),source=fs.readFileSync(path.join(__dirname,'../ui/app.js'),'utf8');
 for(const action of ['commit','merge']){ok(!html.includes(`id="${action}-form"`));ok(!source.includes(`bindForm('${action}-form'`));}
 {
  const h=await setup('1','1');
  h.currentSnapshot.pass.account.shares='1';h.currentSnapshot.fail.account.shares='999999999999999999999999999999';await h.refresh();
  eq(selectorValues(h).map(n=>n.textContent),['<0.000001','<0.000001','<0.000001'],'tiny nonzero selector balances show an honest bound, not truncated zeros');
  eq(selectorValues(h).map(n=>n['aria-label']),[amounts.formatHash('1'),stash('1'),stash('999999999999999999999999999999')],'tiny values keep complete accessible amounts');
  ok(selectorValues(h)[1].title.includes('0.000000000000000000000000000000000001 stash'),'one-atom tooltip stays exact');
  h.currentSnapshot.pass.account.ordinary=h.currentSnapshot.fail.account.ordinary='1000000000000';
  h.currentSnapshot.pass.account.shares=h.currentSnapshot.fail.account.shares='1000000000000000000000000000000';await h.refresh();
  eq(selectorValues(h).map(n=>n.textContent),['0.000001','0.000001','0.000001'],'threshold equality displays its amount without a less-than sign');
  h.currentSnapshot.pass.account.ordinary=h.currentSnapshot.fail.account.ordinary='0';
  h.currentSnapshot.pass.account.shares=h.currentSnapshot.fail.account.shares='0';await h.refresh();
  eq(selectorValues(h).map(n=>n.textContent),['0','0','0'],'true zeros remain zero');
 }
 {
  const h=await setup();eq(h.get('send-available').textContent,amounts.formatHash('400'),'payment ceiling is smaller outcome, not default FAIL by assumption');
  eq(h.get('pass-cash').textContent,amounts.formatHash('1000'));eq(h.get('fail-cash').textContent,amounts.formatHash('400'));
  eq(cash(balanceRows(h.get('account-balances'))[0]),amounts.formatHash('400'));eq(cash(balanceRows(h.get('account-balances'))[1]),amounts.formatHash('1000'));eq(cash(balanceRows(h.get('account-balances'))[2]),amounts.formatHash('400'));
  const grid=h.get('account-balances'),rows=balanceRows(grid),heading=grid.children[0];
  eq(selectorValues(h).map(n=>n['aria-label']),[amounts.formatHash('400'),stash('100000000000000000'),stash('100000000000000000')],'top selector shows shared cash and distinct conditional Stash holdings');
  eq(walk(h.get('account-summary')).filter(n=>n.className==='account-summary-outcome').map(n=>n.textContent),['PASS','FAIL']);
  ok(h.get('account-summary').textContent.includes('Available before fees'),'conditional common cash has an accessible scope label');
  h.currentSnapshot.pass.account.shares='300000000000000000';h.currentSnapshot.fail.account.shares='700000000000000000';await h.refresh();
  eq(selectorValues(h).map(n=>n['aria-label']),[amounts.formatHash('400'),stash('300000000000000000'),stash('700000000000000000')],'outcome Stash is never summed or replaced by default FAIL');
  eq(heading.children.map(n=>n.textContent),['','hash','stash'],'asset labels appear once above their balance columns');
  eq(rows.map(row=>row.children[0].textContent),['Available','PASS','FAIL']);
  ok(rows.every(row=>!row.textContent.includes('hash')&&!row.textContent.includes('stash')),'amounts do not repeat their column units');
  eq(h.get('overview-total-pass')['aria-label'],amounts.formatHash('1500'),'compact Home balances retain accessible units');
  eq(h.get('overview-total').hidden,true);eq(h.get('overview-total-pass').textContent,amounts.formatHash('1500').replace(/ hash$/,''),'PASS total includes its own cash once');eq(h.get('overview-total-fail').textContent,amounts.formatHash('900').replace(/ hash$/,''),'FAIL total includes its own cash once');ok(h.get('governance-outcome-help').textContent.includes('balances continue from the winning side'));
  h.currentSnapshot.pass.account.ordinary='100';await h.refresh();eq(h.get('send-available').textContent,amounts.formatHash('100'),'smaller PASS replaces default FAIL as payment ceiling');
  h.currentSnapshot.pass.account.ordinary='9007199254740993';h.currentSnapshot.fail.account.ordinary='9007199254740994';await h.refresh();ok(h.get('send-available').title.startsWith('0.009007199254740993 hash'),'ceiling remains exact beyond JS safe integers');
 }
 {
  const h=await setup('1000','400'),f=await h.send('399');eq(h.get('send-submit').disabled,false,'amount plus exact fee exactly fits both');await f.requestSubmit();eq(h.wallet.at(-1).operation.TransferExact.amount,'399');
  await h.send('400');eq(h.get('send-submit').disabled,true,'amount plus exact fee exceeds the smaller balance');await f.fire('submit');eq(h.wallet.length,1);ok(h.get('send-cost').textContent.includes('FAIL balance'));
 }
 {
  const h=await setup('1000','400'),f=await h.trade('999');eq(h.get('trade-balance').textContent,amounts.formatHash('1000'),'selected outcome uses full automatic cash');eq(h.get('trade-submit').disabled,false);await f.requestSubmit();eq(h.wallet.at(-1).operation.Deposit.outcome,'Pass');eq(h.wallet.at(-1).operation.Deposit.amount,'999');
  await h.trade('1000');eq(h.get('trade-submit').disabled,true,'deposit leaves selected-side exact fee');
 }
 {
  const h=await setup('1000','0'),f=await h.trade('100');eq(h.get('trade-submit').disabled,true,'other side must fund fee even though selected side is rich');ok(h.get('trade-fee-error').textContent.includes('FAIL balance'));await f.fire('submit');eq(h.wallet.length,0);
  await h.get('trade-max').click();ok(f.feedback.textContent.includes('other outcome'),'max explains insufficient opposite fee balance');
 }
 {
  const h=await setup('1000','400'),f=h.get('trade-form');await h.get('trade-max').click();await h.timersDue();await h.timersDue();eq(amounts.parseAmount(f.elements.amount.value),'999','PASS max reserves exact fee');eq(h.calls.filter(c=>c.body.method==='fee_quote').at(-1).body.params.operation.Deposit.outcome,'Pass');
  f.elements.outcome.value='Fail';await h.get('trade-outcome').fire('change');await h.get('trade-max').click();await h.timersDue();await h.timersDue();eq(amounts.parseAmount(f.elements.amount.value),'399','FAIL max uses own smaller balance');
 }
 {
  const h=await setup('0','2'),f=h.get('trade-form');await h.tradeTab('redeem');await h.get('trade-max').click();await h.timersDue();await h.timersDue();eq(h.get('trade-submit').disabled,false,'withdrawal proceeds can fund selected-side fee');await f.requestSubmit();eq(h.wallet.at(-1).operation.Redeem.outcome,'Pass');
  h.currentSnapshot.fail.account.ordinary='0';h.currentSnapshot.status.tip='e'.repeat(64);await h.refresh();await h.timersDue();await h.timersDue();eq(h.get('trade-submit').disabled,true,'withdrawal cannot fund fee in opposite outcome');
 }
 {
  const h=await setup();
  h.currentSnapshot.account=h.currentSnapshot.pass=h.currentSnapshot.fail=null;
  await h.refresh();
  eq(h.get('overview-cash').textContent,'0','a successfully queried unfunded address has zero available');
  eq(h.get('overview-nonce').textContent,'','an unfunded address does not add an explanatory account-state label');
  ok(!source.includes('Account not present on this chain.'),'the empty-account banner is removed');
  for(const id of ['send-available','governance-common-cash','pass-cash','fail-cash','trade-balance'])eq(h.get(id).textContent,'0 hash',`${id} shows an empty known balance as zero`);
  eq(balanceRows(h.get('account-balances')).map(cash),['0 hash','0 hash','0 hash'],'unfunded wallet balance matrix agrees with the selected account views');
  eq(selectorValues(h).map(n=>n['aria-label']),['0 hash','0 stash','0 stash'],'known empty conditional account shows zeros in the selector');
  await h.tradeTab('redeem');eq(h.get('trade-balance').textContent,'0 stash');
  const form=await h.send('1');eq(h.get('send-submit').disabled,true,'displaying zero never enables spending');await form.fire('submit');eq(h.wallet.length,0);
  h.handlers.snapshot=()=>response({error:{message:'offline'}});await h.refresh();
  for(const id of ['overview-cash','send-available','governance-common-cash','pass-cash','fail-cash','trade-balance'])eq(h.get(id).textContent,'—',`${id} distinguishes an unavailable refresh from a known zero`);
  eq(h.get('overview-cash')['aria-label'],undefined,'offline Home does not retain an accessible zero balance');
  eq(cash(balanceRows(h.get('account-balances'))[0]),'— hash');
  eq(selectorValues(h).map(n=>n['aria-label']),['— hash','— stash'],'failed refresh clears all top selector balances');
  ok(selectorValues(h).every(n=>n.title==='Unavailable'),'failed refresh does not retain exact numeric titles');
  delete h.handlers.snapshot;await h.refresh();eq(h.get('governance-common-cash').textContent,'0 hash','successful recovery restores the confirmed zero');
 }
 {
  const h=await setup();h.currentSnapshot.pass=null;await h.refresh();
  eq(h.get('send-available').textContent,'0 hash','an address absent from one outcome has no shared spendable balance');
  eq(cash(balanceRows(h.get('account-balances'))[0]),'0 hash');eq(h.get('pass-cash').textContent,'0 hash');eq(h.get('fail-cash').textContent,amounts.formatHash('400'));
  delete h.currentSnapshot.pass;await h.refresh();eq(h.get('send-available').textContent,'—','an omitted outcome response is unknown, not an absent on-chain address');
  eq(selectorValues(h).map(n=>n['aria-label']),['— hash','— stash',stash('100000000000000000')],'missing outcome prevents fabricated shared cash or Stash');
 }
 {
  const h=await setup();h.currentSnapshot.governance.phase={Rest:{until:64}};h.currentSnapshot.governance.pass=null;h.currentSnapshot.account=h.currentSnapshot.pass=h.currentSnapshot.fail=null;await h.refresh();
  eq(h.get('overview-cash').textContent,'0');eq(h.get('send-available').textContent,'0 hash');eq(h.get('trade-balance').textContent,'0 hash');eq(cash(balanceRows(h.get('account-balances'))[0]),'0 hash');
  eq(selectorValues(h).map(n=>n['aria-label']),['0 hash','0 stash'],'known empty ordinary account shows zeros');
  delete h.currentSnapshot.account;await h.refresh();eq(h.get('send-available').textContent,'—','an omitted ordinary account response remains unknown');eq(h.get('send-available').title,'Unavailable','unknown ordinary balances do not keep a previous numeric tooltip');
  eq(selectorValues(h).map(n=>n['aria-label']),['— hash','— stash']);
  h.currentSnapshot.account={account:{}};await h.refresh();
  eq(selectorValues(h).map(n=>n['aria-label']),['— hash','— stash'],'missing amount fields inside a response are not zero');
 }
 {
  const h=await setup();delete h.currentSnapshot.pass;await h.refresh();eq(h.get('send-available').textContent,'—','missing outcome does not imply known shared funds');eq(cash(balanceRows(h.get('account-balances'))[0]),'— hash');const f=await h.send('1');eq(h.get('send-submit').disabled,true);await f.fire('submit');eq(h.wallet.length,0);
 }
 {
  const h=await setup();h.selectSession({id:'watch:other',public_key:recipient,mode:'watch'});h.currentSnapshot.balances={[recipient]:{}};await h.refresh();eq(cash(balanceRows(h.get('account-balances'))[0]),'— hash','missing alternate wallet data cannot fall back to selected account snapshot');
  eq(selectorValues(h).map(n=>n['aria-label']),['— hash','— stash','— stash'],'top selector never falls back to another wallet balances');
  ok(h.calls.filter(c=>c.body?.method==='snapshot').every(c=>c.body.params.keys.length===1),'only the selected key is queried');
 }
 {
  const h=await setup();h.currentSession.wallet_enabled=false;await h.refresh();const f=await h.send('398');await f.requestSubmit();eq(h.get('unsigned-dialog').open,true,'watch-only can prepare affordable transfer');eq(h.wallet.length,0);
 }

 {
  const h=await setup();await h.trade('50');h.currentSnapshot.governance.phase={Rest:{until:64}};h.currentSnapshot.governance.pass=null;h.currentSnapshot.pass=null;h.currentSnapshot.fail=null;h.currentSnapshot.account.account.ordinary='123';await h.refresh();eq(h.get('trade-outcome').value,'');eq(h.get('send-available').textContent,amounts.formatHash('123'));eq(h.get('overview-total').hidden,false);eq(h.get('overview-total-outcomes').hidden,true);eq(balanceRows(h.get('account-balances')).length,1,'resolution restores a single surviving balance');
  eq(selectorValues(h).map(n=>n['aria-label']),[amounts.formatHash('123'),stash('100000000000000000')],'resolution returns the top selector to the surviving ordinary balances');
 }
 for(const channel of ['send','mail']){
  const h=await setup('1000000000010',channel==='mail'?'1':'1000000000000',27,channel==='mail'?{mail:true}:{}),s=h.currentSnapshot,f=h.get(`${channel}-form`);
  if(channel==='send'){f.elements.data_text.value='Public test fixture message';f.elements.recipient.value=addr(recipient);}else{f.elements.message.value='Private test fixture message';}
  if(channel==='send')f.elements.amount.value='0.000001';
  if(channel==='mail'){f.elements.subject.value='Published fixture';f.elements.recipient.value=addr('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');}
  const preview=async()=>{await f.fire('input');await h.timersDue();for(let i=0;i<100&&h.get(`${channel}-fee-quote`).textContent==='—'&&!h.get(`${channel}-fee-error`).textContent;i++)await new Promise(r=>setTimeout(r,5));};
  await preview();eq(h.get(`${channel}-submit`).disabled,true,`${channel} cannot bypass min-both payment limit`);ok(h.get(channel==='send'?'send-cost':`${channel}-fee-error`).textContent.includes('FAIL balance'),`${channel} explains insufficient other-outcome exact fee`);await f.fire('submit');eq(h.wallet.length,0);
  s.fail.account.ordinary=channel==='mail'?'2':'1000000000001';s.status.tip='f'.repeat(64);await h.refresh();await preview();eq(h.get(`${channel}-submit`).disabled,false,`${channel} payment plus exact fee fits both`);await f.requestSubmit();eq(h.wallet.at(-1).operation.TransferExact.amount,channel==='mail'?'1':'1000000000000');ok(h.wallet.at(-1).data_hex.length>0);
 }
 console.log(`Automatic outcome wallet: ${checks} checks passed`);
}
if(require.main===module)run().catch(error=>{console.error(error);process.exitCode=1;});
module.exports={setup};

