'use strict';
const assert=require('node:assert/strict'),{harness,response,settle,addr,deferred}=require('./test_wallet_ui.cjs');
const fs=require('node:fs'),path=require('node:path');let checks=0;
const {signMailRow}=require('./mail_fixture.cjs');
const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(v,m)=>{assert.ok(v,m);checks++;};
const key=n=>BigInt(n).toString(16).padStart(64,'0'),a=key(1),b=key(6),c=key(9),walk=n=>[n,...(n.children||[]).flatMap(walk)];
const wait=async(predicate,h)=>{for(let i=0;i<400&&!predicate();i++){if(h)await h.timersDue(0);await new Promise(r=>setTimeout(r,5));}assert.ok(predicate(),'asynchronous local work completed');};
async function setup(options={}){
 const h=await harness({mail:true,...options}),s=h.currentSnapshot;h.pub=k=>Buffer.from(h.noble.schnorr.getPublicKey(Uint8Array.from(Buffer.from(k,'hex')))).toString('hex');
 h.sender=h.pub(a);h.recipient=h.pub(b);h.other=h.pub(c);h.selectSession({id:'hot:'+h.sender,public_key:h.sender,mode:'hot'});
 s.status.settings.block_bytes=16384;s.status.settings.pass_margin_bps=0;
 s.status.fee_policy={minimum_fee_rate:'1',fee_scale:1024,account_weight:1024};
 s.account.account.ordinary='1000000000000000000';
 h.history=options.history||[];h.canonicalAnchors=new Set([s.status.tip]);h.invalidAnchor=!!options.invalidAnchor;
 h.feed=(params={})=>{const after=params.after?.split(':').map(BigInt),all=h.history.filter(e=>!after||BigInt(e.height)>after[0]||(BigInt(e.height)===after[0]&&BigInt(e.position)>after[1])),messages=all.slice(0,params.limit||50),next_cursor=all.length>messages.length?`${messages.at(-1).height}:${messages.at(-1).position}`:null;
   return {ready:true,chain_id:s.status.chain_id,tip:s.status.tip,anchor:s.status.tip,indexed_height:s.status.height,height:s.status.height,messages,next_cursor,scan_cursor:next_cursor||`${s.status.height}:9223372036854775807`};};
 h.handlers.explorer_mail=params=>h.invalidAnchor&&params.anchor?response({error:{message:'Mail scan anchor is no longer canonical'}}):response({result:h.feed(params)});
 h.handlers.fee_quote=params=>{const {chain_id,tip,state_root,height}=s.status,priority=params.extra_fee||'0',data=params.data_hex||'',paid=1n+BigInt(priority),miner=paid/2n;
 return response({result:{miner_fee_percent:50,miner_fee:String(miner),revenue_fee:String(paid-miner),chain_id,tip,state_root,height,anchor:tip,anchor_height:height,expiry_blocks:params.expiry_blocks??2,expiry_height:String(BigInt(height)+BigInt(params.expiry_blocks??2)),sender:addr(params.sender),sender_public_key:params.sender,fee:String(paid),minimum_fee:'1',account_creation_fee:'0',grant_recipient_fee:'0',extra_fee:priority,weight:'512',minimum_fee_rate:'1',data_hex:data,data_bytes:data.length/2}});};
 h.decryptMail=(data,identity)=>h.mailCrypto.decrypt(data,identity,a);
 h.drain=()=>wait(()=>!h.get('mail-scan-status').textContent.startsWith('Scanning'),h);
 await h.refresh();await h.navigate('#mail');await h.drain();
 h.compose=async()=>{const f=h.get('mail-form');f.elements.recipient.value=addr(h.recipient);f.elements.subject.value='Fixture subject';f.elements.message.value='Secret fixture body';await f.fire('input');await h.timersDue();await wait(()=>h.get('mail-fee-quote').textContent!=='—'||!!h.get('mail-fee-error').textContent,h);assert.equal(h.get('mail-fee-error').textContent,'');return f;};
 let serial=1000;
 h.sign=(row,secret=a,fee=1)=>signMailRow(h.noble,s.status.chain_id,secret,row,fee);
 h.message=async(overrides={},recipient=h.recipient,sender=h.sender)=>{const identity={chain_id:s.status.chain_id,sender,recipient,nonce:'0'},data=await h.mailCrypto.encrypt({subject:'Visible after authentication',body:'<script>text only</script>'},identity);
 return h.sign({sender:addr(sender),sender_public_key:sender,nonce:'0',data_hex:data,height:s.status.height+1,position:0,confirmations:1,...overrides},sender===h.sender?a:sender===h.recipient?b:c,++serial);};
 h.publish=async(messages)=>{h.history.push(...messages);s.status.height=Math.max(s.status.height+1,...messages.map(x=>x.height));s.status.tip=key(++serial);h.canonicalAnchors.add(s.status.tip);await h.refresh();await h.drain();};
 h.reload=async()=>{await h.get('mail-refresh').click();await settle();await h.drain();};return h;
}
async function run(){
 {
  const h=await setup(),f=await h.compose();f.elements.recipient.value='@Alice';
  await f.fire('input');await h.timersDue();await f.requestSubmit();
  eq(h.wallet.length,0,'Mail requires a checksummed recipient address');
  ok(!h.calls.some(call=>/^explorer_names?$/.test(call.body.method)),'Mail does not download or query an alias directory');
 }
 const source=fs.readFileSync(path.join(__dirname,'../ui/app.js'),'utf8'),html=fs.readFileSync(path.join(__dirname,'../ui/index.html'),'utf8'),mailSource=fs.readFileSync(path.join(__dirname,'../ui/mail.js'),'utf8');
 ok(!source.includes("rpc('mine'"));ok(!html.includes('data-mine='));ok(!html.includes('id="automine-toggle"'));ok(!html.includes('id="copy-stratum"'));
 const section=html.slice(html.indexOf('id="view-mail"'),html.indexOf('id="view-guide"'));ok(!section.includes('name="amount"'),'mail does not offer a recipient payment');ok(section.includes('name="message" rows="5" maxlength="768"'));ok(section.includes('title="Up to 768 UTF-8 bytes"'));ok(!mailSource.includes('slice(0,200)'),'historical scanning has no arbitrary cutoff');
 for(const [label,change] of [
  ['unsigned RPC row',m=>({...m,raw:undefined})],
  ['changed signature',m=>({...m,raw:m.raw.slice(0,-2)+(m.raw.endsWith('00')?'01':'00')})],
  ['claimed sender', (m,h)=>({...m,sender_public_key:h.other,sender:addr(h.other)})],
  ['changed nonce',m=>({...m,nonce:'1'})],
  ['changed ciphertext',m=>({...m,data_hex:m.data_hex.slice(0,-2)+(m.data_hex.endsWith('00')?'01':'00')})],
  ['wrong txid',m=>({...m,txid:key(555)})],
  ['changed operation',(m,h)=>({...m,operation:{TransferExact:{recipient:h.other,amount:'1'}}})],
 ]){
  const h=await setup(),m=await h.message({},h.sender,h.recipient),before=[...h.savedMail.values()][0];let attempts=0;const real=h.decryptMail;h.decryptMail=(...args)=>{attempts++;return real(...args);};
  await h.publish([change(m,h)]);
  eq(attempts,0,`${label}: reject before decryption`);eq(h.get('mail-list').children.length,0,`${label}: never display`);ok(h.get('mail-error').textContent.includes('could not be verified'),`${label}: report verification failure`);eq([...h.savedMail.values()][0],before,`${label}: never advance persisted checkpoint`);
  h.history=[m];await h.publish([]);eq(h.get('mail-list').children.length,1,`${label}: the valid signed message remains discoverable`);
 }
 {
  const h=await setup(),foreign={chain_id:'fe'.repeat(32),sender:h.recipient,recipient:h.sender,nonce:'0'};
  const data=await h.mailCrypto.encrypt({subject:'Foreign network',body:'Cannot authenticate in this network'},foreign);
  const row=await h.message({data_hex:data},h.sender,h.recipient);
  let attempts=0;const decrypt=h.decryptMail;h.decryptMail=(...args)=>{attempts++;return decrypt(...args);};
  await h.publish([row]);eq(attempts,1,'transaction signature does not authenticate network metadata');eq(h.get('mail-list').children.length,0,'mail encryption still binds the selected network');eq(h.get('mail-error').textContent,'','unrelated encrypted context stays private');
 }
 {
  const h=await setup();let attempts=0;h.decryptMail=async()=>{attempts++;throw Error('not mine');};
  const m=await h.message({},h.other,h.recipient);delete m.raw;await h.publish([m]);eq(attempts,0,'unrelated mail also requires a sender signature');ok(h.get('mail-error').textContent.includes('could not be verified'));
 }
 {
  const h=await setup(),f=await h.compose();eq(h.wallet.length,0,'typing encrypts and quotes without signing');
  const quote=h.calls.filter(x=>x.body.method==='fee_quote').at(-1).body.params;ok(!JSON.stringify(quote).includes('Secret fixture body'));ok(!JSON.stringify(quote).includes('Fixture subject'));
  eq(quote.operation.TransferExact.amount,'1','mail carrier is one raw atom');eq(Buffer.from(quote.operation.TransferExact.recipient).toString('hex'),h.sender,'mail carrier returns to its sender');
  const identity={chain_id:h.currentSnapshot.status.chain_id,sender:h.sender,nonce:String(h.currentSnapshot.account.account.nonce)};
  eq(JSON.parse(JSON.stringify(await h.mailCrypto.decrypt(quote.data_hex,identity,b))),{recipient:h.recipient,subject:'Fixture subject',body:'Secret fixture body'});
  ok(!JSON.stringify(quote).includes(h.recipient),'recipient key is not exposed in fee RPC');
  await f.requestSubmit();eq(h.wallet.length,1);eq(h.wallet[0].data_hex,quote.data_hex,'submitted bytes match reviewed fee');eq(f.elements.message.value,'');eq(f.elements.subject.value,'');
  ok(h.calls.every(call=>!JSON.stringify(call.body).includes('Secret fixture body')),'no plaintext enters RPC');
 }
 {
  const h=await setup(),f=await h.compose(),quoted=h.calls.filter(x=>x.body.method==='fee_quote').at(-1).body.params.data_hex;
  h.currentSnapshot.mempool.push({body:{sender:h.sender,nonce:0,operation:{TransferExact:{recipient:h.sender,amount:'1'}}}});await h.refresh();await f.requestSubmit();
  eq(h.wallet.length,0,'changed nonce invalidates encryption and fee context');ok(!f.feedback.textContent.startsWith('Pending'));
  await h.timersDue();await wait(()=>h.calls.filter(x=>x.body.method==='fee_quote').at(-1).body.params.data_hex!==quoted,h);
 }
 {
  const h=await setup(),incoming=await h.message({position:0},h.sender,h.recipient),unrelated=await h.message({position:1},h.other,h.recipient);
  await h.publish([incoming,unrelated]);eq(h.get('mail-list').children.length,1,'only authenticated own mail creates a row');ok(h.get('mail-list').textContent.includes('Received'));ok(h.get('mail-list').textContent.includes('<script>text only</script>'),'plaintext remains text');ok(!walk(h.get('mail-list')).some(n=>n.textContent==='Open message'),'decryption is automatic');
  eq(h.get('mail-error').textContent,'','wrong key is normal and silent');ok(h.get('mail-scan-status').textContent.includes('2 checked · 1 found'));
  const row=h.get('mail-list').children[0];await h.refresh();await h.reload();eq(h.get('mail-list').children[0],row,'unchanged incremental poll preserves rows');await h.navigate('#wallet');await h.refresh();await h.navigate('#mail');eq(h.get('mail-list').children[0],row,'unchanged navigation preserves rows');
  const requests=h.calls.filter(x=>x.body.method==='explorer_mail');ok(requests.every(x=>Object.keys(x.body.params).every(k=>['limit','after','anchor'].includes(k))),'shared mail requests contain no recipient or account');ok(requests.at(-1).body.params.after,'later polls use committed scan cursor');eq(requests.at(-1).body.params.anchor,h.currentSnapshot.status.tip);
 }
 {
  const h=await setup(),outgoing=await h.message();await h.publish([outgoing]);eq(h.get('mail-list').children.length,1);ok(h.get('mail-list').textContent.includes('Sent'));ok(h.get('mail-list').textContent.includes(addr(h.recipient)),'recipient displayed only after authenticated decryption');
  const rawCalls=JSON.stringify(h.calls.filter(x=>x.body.method==='explorer_mail'));ok(!rawCalls.includes(h.recipient));ok(!h.calls.some(x=>x.body.method==='explorer_account'&&JSON.stringify(x.body.params).includes(h.recipient)),'rendering mail never reverse-queries a recipient');
 }
 {
  const h=await setup(),template=await h.message();let tried=0;
  h.decryptMail=async()=>{tried++;if(tried<251)throw Error('Authentication failed');return {recipient:h.recipient,subject:'After 250 unrelated envelopes',body:'Found without a cutoff'};};
  const batch=Array.from({length:251},(_,i)=>h.sign({...template,position:i},a,5000+i));
  await h.publish(batch);eq(tried,100,'automatic history discovery stops after its bounded budget');ok(h.get('mail-scan-status').textContent.includes('Paused'));await h.get('mail-more').click();await h.drain();eq(tried,200,'each explicit continuation has a fresh bounded budget');await h.get('mail-more').click();await h.drain();eq(tried,251,'explicit continuation reaches all history without a cutoff');eq(h.get('mail-list').children.length,1);ok(h.get('mail-list').textContent.includes('After 250'));ok(h.get('mail-scan-status').textContent.includes('251 checked'));
  eq(h.calls.filter(x=>x.body.method==='explorer_mail').length,7,'initial empty scan plus six bounded pages');
 }
 {
  const h=await setup(),m=await h.message({},h.sender,h.recipient);let decryptionCalls=0;h.decryptMail=async()=>{decryptionCalls++;return {recipient:h.other,subject:'MALFORMED',body:'Wrong audience'};};
  await h.publish([m]);eq(h.get('mail-list').children.length,0,'unexpected plaintext audience is rejected');eq(decryptionCalls,1);
  const bad=await h.message({data_hex:'00'});await h.publish([bad]);eq(decryptionCalls,1,'invalid envelope is skipped before decryption');eq(h.get('mail-error').textContent,'');
 }
 {
  const h=await setup(),held=deferred(),m=await h.message();h.decryptMail=()=>held.promise;
  const publishing=h.publish([m]);await wait(()=>h.get('mail-scan-status').textContent.startsWith('Scanning'),h);await settle();
  h.selectSession({id:'watch:'+h.recipient,public_key:h.recipient,mode:'watch'});await h.refresh();held.resolve({recipient:h.recipient,subject:'OLD SECRET',body:'hidden'});await publishing;
  eq(h.get('mail-list').children.length,0,'late decryption cannot cross wallets');ok(h.get('mail-empty').textContent.includes('Watch-only'));const count=h.calls.filter(x=>x.body.method==='explorer_mail').length;await h.reload();eq(h.calls.filter(x=>x.body.method==='explorer_mail').length,count,'watch-only performs no inbox discovery');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);ok(h.get('mail-list').textContent.includes('Visible after authentication'));
  h.history=[];h.invalidAnchor=true;h.currentSnapshot.status.tip='dd'.repeat(32);await h.refresh();await h.drain();
  eq(h.get('mail-list').children.length,0,'reorg anchor rejection clears all obsolete plaintext');eq(h.get('mail-error').textContent,'');const req=h.calls.filter(x=>x.body.method==='explorer_mail').at(-1).body.params;ok(!Object.hasOwn(req,'after'),'reorg restarts shared scan from canonical history');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);const good=h.handlers.explorer_mail;
  h.handlers.explorer_mail=()=>response({error:{message:'Temporarily unavailable'}});h.currentSnapshot.status.tip='dc'.repeat(32);h.currentSnapshot.status.height++;await h.refresh();await h.drain();
  eq(h.get('mail-list').children.length,0,'unverified new tip hides previously decrypted messages');ok(h.get('mail-scan-status').textContent.includes('Verification pending'));ok(h.get('mail-error').textContent.includes('Temporarily unavailable'));
  h.handlers.explorer_mail=good;await h.reload();eq(h.get('mail-list').children.length,1,'validated unchanged anchor restores retained messages without rescanning');
  h.handlers.explorer_mail=p=>response({result:{...h.feed(p),tip:'ad'.repeat(32),anchor:'ad'.repeat(32)}});await h.reload();eq(h.get('mail-list').children.length,0,'response from another tip cannot mark the current tip verified');ok(h.get('mail-error').textContent.includes('index changed'));
 }
 {
  const h=await setup(),held=deferred(),m=await h.message(),real=h.decryptMail;h.decryptMail=()=>held.promise;h.history=[m];h.currentSnapshot.status.height=m.height;h.currentSnapshot.status.tip='ac'.repeat(32);await h.refresh();await settle();
  await h.navigate('#wallet');held.resolve({recipient:h.recipient,subject:'HIDDEN ROUTE',body:'not committed'});await settle();eq(h.get('mail-list').children.length,0,'leaving Mail cancels an in-flight page');
  h.decryptMail=real;await h.navigate('#mail');await h.drain();eq(h.get('mail-list').children.length,1,'returning to Mail retries uncommitted messages');ok(!h.get('mail-list').textContent.includes('HIDDEN ROUTE'));
 }
 {
  const h=await setup(),template=await h.message();h.decryptMail=async()=>({recipient:h.recipient,subject:'My mail',body:'Authenticated fixture'});await h.publish(Array.from({length:53},(_,i)=>h.sign({...template,position:i},a,9000+i)));
  eq(h.get('mail-list').children.length,50,'initial rendering is bounded even for a large inbox');ok(!h.get('mail-show-more').hidden);await h.get('mail-show-more').click();eq(h.get('mail-list').children.length,53,'all discovered messages remain reachable');ok(h.get('mail-show-more').hidden);
 }
 {
  const h=await setup(),held=deferred(),oldResponse=h.feed();h.handlers.explorer_mail=()=>held.promise;await h.get('mail-refresh').click();await settle();
  h.currentSnapshot.status.tip='ee'.repeat(32);h.currentSnapshot.status.height++;h.handlers.explorer_mail=p=>response({result:h.feed(p)});await h.refresh();await h.drain();held.resolve(response({result:oldResponse}));await settle();
  eq(h.get('mail-list').children.length,0,'late prior-tip response does not restore old state');eq(h.get('mail-error').textContent,'');
  const valid=h.handlers.explorer_mail;h.handlers.explorer_mail=p=>response({result:{...h.feed(p),chain_id:'bb'.repeat(32)}});await h.reload();ok(h.get('mail-error').textContent.includes('different network'));h.handlers.explorer_mail=valid;
 }
 {
  const h=await setup(),held=deferred(),m=await h.message();let calls=0;const real=h.decryptMail;h.decryptMail=(...args)=>++calls===1?held.promise:real(...args);
  h.history=[m];h.currentSnapshot.status.height=m.height;h.currentSnapshot.status.tip='fc'.repeat(32);await h.refresh();await settle();
  await h.get('mail-more').click();ok(h.get('mail-scan-status').textContent.includes('Paused'),'history scanning can be paused');held.resolve({recipient:h.recipient,subject:'CANCELLED',body:'late'});await settle();eq(h.get('mail-list').children.length,0,'cancelled page does not publish plaintext or cursor');
  await h.get('mail-more').click();await h.drain();eq(h.get('mail-list').children.length,1,'resume retries the uncommitted page');ok(!h.get('mail-list').textContent.includes('CANCELLED'));
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);
  const saved=[...h.savedMail.entries()].filter(([k])=>k.startsWith('hashstash-mail-scan-3:'));eq(saved.length,1,'one atomic checkpoint stores an account scan');
  ok(!saved[0][1].includes('Visible after authentication'),'plaintext subject is never persisted');ok(!saved[0][1].includes('text only'),'plaintext body is never persisted');ok(!saved[0][1].includes(h.recipient),'encrypted private recipient is not cached in clear');
  const cached=JSON.parse(saved[0][1]);eq(cached.entries.length,1);ok(!Object.hasOwn(cached.entries[0],'clear'));eq(cached.cursor,`${h.currentSnapshot.status.height}:9223372036854775807`);
  const restored=await setup({savedMail:h.savedMail,initialSnapshot:h.currentSnapshot,history:h.history});
  eq(restored.get('mail-list').children.length,1,'new browser instance reauthenticates persisted ciphertext and restores old mail');ok(restored.get('mail-list').textContent.includes('Visible after authentication'));
  const requests=restored.calls.filter(x=>x.body.method==='explorer_mail');eq(requests.length,1,'restoration fetches only history after saved checkpoint');eq(requests[0].body.params.after,cached.cursor);eq(requests[0].body.params.anchor,cached.anchor);
  const priorRequests=restored.calls.filter(x=>x.body.method==='explorer_mail').length;await restored.navigate('#wallet');await restored.refresh();eq(restored.calls.filter(x=>x.body.method==='explorer_mail').length,priorRequests,'visiting other pages downloads no mail');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);
  const saved=[...h.savedMail.entries()].find(([k])=>k.startsWith('hashstash-mail-scan-3:')),record=JSON.parse(saved[1]);record.entries[0].raw=record.entries[0].raw.slice(0,-2)+(record.entries[0].raw.endsWith('00')?'01':'00');h.savedMail.set(saved[0],JSON.stringify(record));
  const restored=await setup({savedMail:h.savedMail,initialSnapshot:h.currentSnapshot,history:h.history});eq(restored.get('mail-list').children.length,1,'tampered cached ciphertext triggers full scan, restoring the authentic canonical message');eq(restored.calls.filter(x=>x.body.method==='explorer_mail').length,2,'failed cached authentication never silently skips history');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);
  const restored=await setup({savedMail:h.savedMail,initialSnapshot:h.currentSnapshot,history:[],invalidAnchor:true});eq(restored.get('mail-list').children.length,0,'persisted reorged history is cleared before any cached plaintext is rendered');eq(restored.calls.filter(x=>x.body.method==='explorer_mail').length,2,'stale persisted anchor triggers canonical full scan');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);const count=h.calls.filter(x=>x.body.method==='explorer_mail').length;await h.get('mail-clear-cache').click();eq(h.get('mail-list').children.length,0,'clear cache immediately removes plaintext');eq([...h.savedMail.keys()].filter(k=>k.startsWith('hashstash-mail-scan-3:')).length,0);eq(h.calls.filter(x=>x.body.method==='explorer_mail').length,count,'clearing cache does not silently download history again');ok(h.get('mail-scan-status').textContent.includes('cache cleared'));await h.get('mail-more').click();await h.drain();eq(h.get('mail-list').children.length,1,'explicit continue rediscovers cleared history');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);
  const saved=[...h.savedMail.entries()].find(([k])=>k.startsWith('hashstash-mail-scan-3:'));h.savedMail.set(saved[0],'{broken');
  const restored=await setup({savedMail:h.savedMail,initialSnapshot:h.currentSnapshot,history:h.history});eq(restored.get('mail-list').children.length,1,'invalid checkpoint rescans history instead of skipping it');ok(!restored.calls.find(x=>x.body.method==='explorer_mail').body.params.after);
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);const before=JSON.parse([...h.savedMail.values()][0]);
  const held=deferred(),fresh=await h.message(),real=h.decryptMail;h.decryptMail=()=>held.promise;const publishing=h.publish([fresh]);await wait(()=>h.get('mail-scan-status').textContent.startsWith('Scanning'),h);await settle();await h.navigate('#wallet');held.resolve({recipient:h.recipient,subject:'LATE',body:'not cached'});await publishing;
  eq(JSON.parse([...h.savedMail.values()][0]).cursor,before.cursor,'cancelled page never commits persisted cursor');h.decryptMail=real;await h.navigate('#mail');await h.drain();eq(h.get('mail-list').children.length,2,'cancelled messages are retried on return');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);const saved=[...h.savedMail.entries()].find(([k])=>k.startsWith('hashstash-mail-scan-3:')),prior=JSON.parse(saved[1]);h.savedMail.set=()=>{throw Error('QuotaExceededError');};
  const fresh=await h.message();await h.publish([fresh]);eq(h.get('mail-list').children.length,2,'storage failure preserves a working in-memory inbox');ok(h.get('mail-scan-status').textContent.includes('only for this visit'),'storage failure is visible');eq(JSON.parse(h.savedMail.get(saved[0])).cursor,prior.cursor,'quota failure retains earlier complete cursor');
 }
 {
  const h=await harness({mail:true,empty:true});await h.refresh();await h.navigate('#mail');eq(h.calls.filter(c=>c.body.method==='explorer_mail').length,0);ok(h.get('mail-empty').textContent.includes('Select a wallet'));
 }
 console.log(`${checks} recipient-hidden mail UI checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});

