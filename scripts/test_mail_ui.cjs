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
 return response({result:{miner_fee_percent:50,miner_fee:String(miner),revenue_fee:String(paid-miner),chain_id,tip,state_root,height,anchor:tip,anchor_height:height,expiry_blocks:params.expiry_blocks??2,expiry_height:String(BigInt(height)+BigInt(params.expiry_blocks??2)),sender:addr(params.sender),sender_public_key:params.sender,fee:String(paid),minimum_fee:'1',account_creation_fee:'0',grant_recipient_fee:'0',record_fee:'0',extra_fee:priority,weight:'512',minimum_fee_rate:'1',data_hex:data,data_bytes:data.length/2}});};
 h.decryptMail=(data,identity)=>h.mailCrypto.decrypt(data,identity,a);
 h.drain=()=>wait(()=>!h.get('mail-scan-status').textContent.startsWith('Scanning'),h);
 await h.refresh();await h.navigate('#mail');await h.drain();
 h.compose=async()=>{const f=h.get('mail-form');f.elements.recipient.value=addr(h.recipient);f.elements.subject.value='Fixture subject';f.elements.message.value='Secret fixture body';await f.fire('input');await h.timersDue();await wait(()=>h.get('mail-fee-quote').textContent!=='—'||!!h.get('mail-fee-error').textContent,h);assert.equal(h.get('mail-fee-error').textContent,'');return f;};
 let serial=1000;
 h.sign=(row,secret=a,fee=1)=>signMailRow(h.noble,s.status.chain_id,secret,row,fee);
 h.signFor=(chain,row,secret=a,fee=1)=>signMailRow(h.noble,chain,secret,row,fee);
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
 // A row is unwrapped under its stated context first. An envelope that opens
 // must then match its signed record before it is shown or checkpointed; one
 // that does not open is treated as another account's mail.
 for(const [label,change,decrypted,detected] of [
  ['unsigned RPC row',m=>({...m,raw:undefined}),0,true],
  ['changed signature',m=>({...m,raw:m.raw.slice(0,-2)+(m.raw.endsWith('00')?'01':'00')}),1,true],
  // Signed by the envelope's real sender, so only the network differs.
  ['signed for another network',(m,h)=>h.signFor('fe'.repeat(32),m,b),1,true],
  ['claimed sender', (m,h)=>({...m,sender_public_key:h.other,sender:addr(h.other)}),1,false],
  ['changed nonce',m=>({...m,nonce:'1'}),1,false],
  ['changed ciphertext',m=>({...m,data_hex:m.data_hex.slice(0,-2)+(m.data_hex.endsWith('00')?'01':'00')}),0,false],
  ['wrong txid',m=>({...m,txid:key(555)}),1,true],
  ['changed operation',(m,h)=>({...m,operation:{TransferExact:{recipient:h.other,amount:'1'}}}),1,true],
 ]){
  const h=await setup(),m=await h.message({},h.sender,h.recipient),before=[...h.savedMail.values()][0];let attempts=0;const real=h.decryptMail;h.decryptMail=(...args)=>{attempts++;return real(...args);};
  await h.publish([change(m,h)]);
  eq(attempts,decrypted,`${label}: decryption attempts`);eq(h.get('mail-list').children.length,0,`${label}: never display`);
  if(detected){
   ok(h.get('mail-error').textContent.includes('could not be verified'),`${label}: report verification failure`);eq([...h.savedMail.values()][0],before,`${label}: never advance persisted checkpoint`);
   h.history=[m];await h.publish([]);eq(h.get('mail-list').children.length,1,`${label}: the valid signed message remains discoverable`);
  }else eq(h.get('mail-error').textContent,'',`${label}: an envelope that does not open under the stated context is not ours`);
 }
 {
  // A feed cannot attribute mail to a key that did not sign it: an envelope
  // encrypted under a claimed sender's context opens, then fails the signed
  // record check before display.
  const h=await setup(),s=h.currentSnapshot,data=await h.mailCrypto.encrypt({subject:'Forged',body:'Not from the claimed sender'},{chain_id:s.status.chain_id,sender:h.recipient,recipient:h.sender,nonce:'0'});
  const signed=h.sign({sender:addr(h.other),nonce:'0',data_hex:data,height:s.status.height+1,position:0,confirmations:1},c,4242);
  await h.publish([{...signed,sender:addr(h.recipient),sender_public_key:h.recipient}]);
  eq(h.get('mail-list').children.length,0,'forged sender: never display');ok(h.get('mail-error').textContent.includes('could not be verified'),'forged sender: an opened envelope must match its signed sender');
  h.history=[signed];await h.publish([]);eq(h.get('mail-list').children.length,0,'under its real signer the envelope does not open');eq(h.get('mail-error').textContent,'');
 }
 {
  // Another account's envelope costs no signature check: a broken signature
  // on it neither stops the scan nor hides later mail.
  const h=await setup(),unrelated=await h.message({position:0},h.recipient,h.other),mine=await h.message({position:1},h.sender,h.recipient);
  await h.publish([{...unrelated,raw:unrelated.raw.slice(0,-2)+(unrelated.raw.endsWith('00')?'01':'00')},mine]);
  eq(h.get('mail-error').textContent,'','an unopened envelope is not signature-checked');eq(h.get('mail-list').children.length,1,'later own mail is found');ok(h.get('mail-scan-status').textContent.includes('2 checked · 1 found'));
 }
 {
  const h=await setup(),foreign={chain_id:'fe'.repeat(32),sender:h.recipient,recipient:h.sender,nonce:'0'};
  const data=await h.mailCrypto.encrypt({subject:'Foreign network',body:'Cannot authenticate in this network'},foreign);
  const row=await h.message({data_hex:data},h.sender,h.recipient);
  let attempts=0;const decrypt=h.decryptMail;h.decryptMail=(...args)=>{attempts++;return decrypt(...args);};
  await h.publish([row]);eq(attempts,1,'a signature for this network reaches decryption whatever context the ciphertext names');eq(h.get('mail-list').children.length,0,'mail encryption still binds the selected network');eq(h.get('mail-error').textContent,'','unrelated encrypted context stays private');
 }
 {
  const h=await setup();let attempts=0;h.decryptMail=async()=>{attempts++;throw Error('not mine');};
  const m=await h.message({},h.other,h.recipient);delete m.raw;await h.publish([m]);eq(attempts,0,'unrelated rows still need their signed record');ok(h.get('mail-error').textContent.includes('could not be verified'));
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
  const h=await setup(),incoming=await h.message({},h.sender,h.recipient);h.decryptMail=async()=>({recipient:h.sender,subject:'Invoice \u202efdp.exe',body:'Pay \u2067reversed\u2069 now'});
  await h.publish([incoming]);const node=name=>walk(h.get('mail-list')).find(n=>n.className===name);
  eq(node('mail-subject').textContent,'Invoice \\u202efdp.exe','bidi overrides in a subject are visible escapes');eq(node('mail-body').textContent,'Pay \\u2067reversed\\u2069 now','bidi isolates in a body are visible escapes');
 }
 {
  const h=await setup(),outgoing=await h.message();await h.publish([outgoing]);eq(h.get('mail-list').children.length,1);ok(h.get('mail-list').textContent.includes('Sent'));ok(h.get('mail-list').textContent.includes(addr(h.recipient)),'recipient displayed only after authenticated decryption');
  const rawCalls=JSON.stringify(h.calls.filter(x=>x.body.method==='explorer_mail'));ok(!rawCalls.includes(h.recipient));ok(!h.calls.some(x=>x.body.method==='explorer_account'&&JSON.stringify(x.body.params).includes(h.recipient)),'rendering mail never reverse-queries a recipient');
 }
 {
  const h=await setup(),template=await h.message();let tried=0;
  h.decryptMail=async()=>{tried++;if(tried<251)throw Error('Authentication failed');return {recipient:h.recipient,subject:'After 250 unrelated envelopes',body:'Found without a cutoff'};};
  const batch=Array.from({length:251},(_,i)=>h.sign({...template,position:i},a,5000+i)),s=h.currentSnapshot;
  // Publish without draining: the scan rests on a real timer between budgets.
  h.history.push(...batch);s.status.height=Math.max(...batch.map(x=>x.height));s.status.tip=key(7777);await h.refresh();
  const resting=()=>[...h.timers.values()].some(timer=>timer.delay===250);
  await wait(()=>tried===100&&resting(),h);await settle();
  eq(tried,100,'each slice of history discovery is bounded');ok(h.get('mail-scan-status').textContent.startsWith('Scanning'),'the scan rests instead of stopping');eq(h.get('mail-more').textContent,'Pause scan');eq(h.get('mail-more').hidden,false);
  await h.timersDue(250);await wait(()=>tried===200&&resting(),h);await settle();eq(tried,200,'it continues on its own with a fresh bounded budget');
  await h.get('mail-more').click();ok(h.get('mail-scan-status').textContent.includes('Paused'),'the user can still pause');await h.timersDue(250);await settle();eq(tried,200,'a paused scan does not resume when its rest ends');
  await h.get('mail-more').click();await h.drain();eq(tried,251,'continuing reaches all history without a cutoff');eq(h.get('mail-list').children.length,1);ok(h.get('mail-list').textContent.includes('After 250'));ok(h.get('mail-scan-status').textContent.includes('251 checked'));
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
  // A reorganization above part of a completed scan keeps the mail at or
  // below the fork and continues from there instead of rescanning.
  const h=await setup(),early=await h.message();await h.publish([early]);const fork=early.height,resume=`${fork}:9223372036854775807`;
  const late=await h.message({height:fork+1});await h.publish([late]);eq(h.get('mail-list').children.length,2,'both messages are shown before the reorganization');
  const oldAnchor=h.currentSnapshot.status.tip,good=h.handlers.explorer_mail,before=h.calls.length;
  h.history=h.history.filter(entry=>entry.height<=fork);h.currentSnapshot.status.tip='de'.repeat(32);
  h.handlers.explorer_mail=p=>p.anchor===oldAnchor&&p.after!==resume?response({error:{message:`Mail scan anchor is no longer canonical; blocks above height ${fork} were replaced`}}):good(p);
  await h.refresh();await h.drain();
  eq(h.get('mail-list').children.length,1,'mail above the fork height is discarded');eq(h.get('mail-error').textContent,'');
  const requests=h.calls.slice(before).filter(x=>x.body.method==='explorer_mail').map(x=>x.body.params);
  eq(requests.at(-1).after,resume,'the scan continues from the fork height');eq(requests.at(-1).anchor,oldAnchor,'with the same anchor');
  ok(requests.every(p=>Object.hasOwn(p,'after')),'mail at or below the fork is not rescanned');
 }
 {
  // A wallet locked by its passphrase cannot open mail. It says so, and a
  // lock racing a scan stops the page without advancing or clearing the cache.
  const h=await setup(),m=await h.message();await h.publish([m]);eq(h.get('mail-list').children.length,1);
  const before=[...h.savedMail.entries()].find(([name])=>name.startsWith('hashstash-mail-scan-3:'))[1],real=h.decryptMail;
  h.currentSession={...h.currentSession,wallet_locked:true,wallet_encrypted:true};await h.refresh();
  eq(h.get('mail-list').children.length,0,'locking hides opened mail');ok(h.get('mail-empty').textContent.startsWith('Locked'),h.get('mail-empty').textContent);
  const locked=()=>{const error=new Error('Unlock this browser wallet with its passphrase first.');error.walletLocked=true;throw error;};
  h.decryptMail=locked;h.currentSession={...h.currentSession,wallet_locked:false};const later=await h.message({height:m.height+1});await h.publish([later]);
  eq(h.get('mail-list').children.length,0,'nothing is shown while the key cannot open');ok(h.get('mail-error').textContent.includes('Unlock'),h.get('mail-error').textContent);
  eq([...h.savedMail.entries()].find(([name])=>name.startsWith('hashstash-mail-scan-3:'))[1],before,'the checkpoint and cached mail are kept');
  h.decryptMail=real;await h.reload();eq(h.get('mail-list').children.length,2,'once open, the cache restores and the scan continues');
 }
 {
  // A second reorganization reported during the same scan rewinds again,
  // rather than discarding the saved scan and starting from genesis.
  const h=await setup(),first=await h.message();await h.publish([first]);
  const second=await h.message({height:first.height+1});await h.publish([second]);
  const third=await h.message({height:second.height+1});await h.publish([third]);eq(h.get('mail-list').children.length,3);
  const end=height=>`${height}:9223372036854775807`,oldAnchor=h.currentSnapshot.status.tip,good=h.handlers.explorer_mail,before=h.calls.length;
  h.history=h.history.filter(entry=>entry.height<=first.height);h.currentSnapshot.status.tip='df'.repeat(32);
  h.handlers.explorer_mail=p=>p.anchor!==oldAnchor||p.after===end(first.height)?good(p):response({error:{message:`Mail scan anchor is no longer canonical; blocks above height ${p.after===end(second.height)?first.height:second.height} were replaced`}});
  await h.refresh();await h.drain();
  eq(h.get('mail-list').children.length,1,'both rewinds drop the mail above their fork heights');eq(h.get('mail-error').textContent,'');
  const requests=h.calls.slice(before).filter(x=>x.body.method==='explorer_mail').map(x=>x.body.params);
  eq(requests.map(p=>p.after),[end(third.height),end(second.height),end(first.height)],'each fork height rewinds the cursor further');
  ok(requests.every(p=>p.anchor===oldAnchor),'every rewind keeps the anchor the node relates to its fork');
 }
 {
  // An anchor error without a fork height resumes from the newest earlier
  // checkpoint, keeping the messages at or below it.
  const h=await setup(),early=await h.message();await h.publish([early]);const kept=h.currentSnapshot.status.tip,keptCursor=`${early.height}:9223372036854775807`;
  const late=await h.message({height:early.height+1});await h.publish([late]);eq(h.get('mail-list').children.length,2);
  const saved=()=>JSON.parse([...h.savedMail.entries()].find(([name])=>name.startsWith('hashstash-mail-scan-3:'))[1]);
  eq(saved().checkpoints[0],{cursor:keptCursor,anchor:kept},'the checkpoint before the latest anchor is saved');
  const unknown=h.currentSnapshot.status.tip,good=h.handlers.explorer_mail,before=h.calls.length;let attempts=0;const real=h.decryptMail;h.decryptMail=(...args)=>{attempts++;return real(...args);};
  h.handlers.explorer_mail=p=>p.anchor===unknown?response({error:{message:'Mail scan anchor is no longer canonical'}}):good(p);
  h.currentSnapshot.status.tip='d0'.repeat(32);await h.refresh();await h.drain();
  eq(h.get('mail-list').children.length,2,'the earlier message is kept and the later one found again');eq(h.get('mail-error').textContent,'');
  const requests=h.calls.slice(before).filter(x=>x.body.method==='explorer_mail').map(x=>x.body.params);
  eq(requests.map(p=>[p.after,p.anchor]),[[`${late.height}:9223372036854775807`,unknown],[keptCursor,kept]],'the scan resumes from the earlier checkpoint');
  eq(attempts,1,'only the mail above that checkpoint is opened again');
  eq(saved().cursor,`${late.height}:9223372036854775807`);eq(saved().entries.length,2);
  // When no earlier checkpoint is accepted either, the scan still restarts.
  h.handlers.explorer_mail=p=>p.anchor?response({error:{message:'Mail scan anchor is no longer canonical'}}):good(p);
  h.currentSnapshot.status.tip='d1'.repeat(32);const restart=h.calls.length;await h.refresh();await h.drain();
  const retried=h.calls.slice(restart).filter(x=>x.body.method==='explorer_mail').map(x=>x.body.params);
  ok(!Object.hasOwn(retried.at(-1),'after'),'with every checkpoint refused the scan starts from genesis');eq(retried.length,retried.filter(p=>p.anchor).length+1);
  eq(h.get('mail-list').children.length,2,'and rediscovers the canonical mail');
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
  const restored=await setup({savedMail:h.savedMail,initialSnapshot:h.currentSnapshot,history:[],invalidAnchor:true});eq(restored.get('mail-list').children.length,0,'persisted reorged history is cleared before any cached plaintext is rendered');eq(restored.calls.filter(x=>x.body.method==='explorer_mail').length,3,'a stale persisted anchor, then its saved earlier checkpoint, are refused before a canonical full scan');
 }
 {
  const h=await setup(),m=await h.message();await h.publish([m]);
  const saved=[...h.savedMail.entries()].find(([k])=>k.startsWith('hashstash-mail-scan-3:'));h.savedMail.set(saved[0],JSON.stringify({...JSON.parse(saved[1]),omitted:2}));
  const restored=await setup({savedMail:h.savedMail,initialSnapshot:h.currentSnapshot,history:h.history});
  eq(restored.get('mail-list').children.length,1,'cached messages still restore');ok(restored.get('mail-scan-status').textContent.includes('2 earlier messages are not kept in this browser'),'messages evicted from a full cache are reported');
  eq(JSON.parse(restored.savedMail.get(saved[0])).omitted,2,'the count survives later checkpoints');
  await restored.get('mail-clear-cache').click();await restored.get('mail-more').click();await restored.drain();ok(!restored.get('mail-scan-status').textContent.includes('not kept'),'a rescan from the beginning shows them again');
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
  // A key this browser creates can have no earlier mail: its first scan
  // starts above the tip it was created at instead of at genesis.
  const h=await setup({realWallet:true,publicWeb:true}),s=h.currentSnapshot;h.history.push(await h.message({height:s.status.height},h.recipient,h.other));
  const birth={height:s.status.height,tip:s.status.tip};await h.navigate('#wallet');await h.get('wallet-create').click();await settle();
  const created=h.browserStore.snapshot().public_key,startKey=`hashstash-mail-start-1:${s.status.chain_id}:${created}`;
  eq(JSON.parse(h.savedStorage.get(startKey)),{version:1,height:birth.height,anchor:birth.tip,origin:'created'},'creating a wallet records the tip as its mail scan start');
  const incoming=await h.message({height:birth.height+1},created,h.other),before=h.calls.length;await h.navigate('#mail');await h.publish([incoming]);
  const requests=h.calls.slice(before).filter(x=>x.body.method==='explorer_mail').map(x=>x.body.params);
  eq(requests[0].after,`${birth.height}:9223372036854775807`,'the first scan starts above the creation tip');eq(requests[0].anchor,birth.tip,'anchored at that block');
  ok(requests.every(p=>Object.hasOwn(p,'after')),'history at or below the start is never requested');
  eq(h.get('mail-list').children.length,1,'mail sent after creation is found');ok(h.get('mail-list').textContent.includes('Received'));
  ok(h.get('mail-start-note').textContent.includes(`created in this browser at block ${birth.height}`));ok(h.get('mail-scan-status').textContent.includes(`from block ${birth.height+1}`));eq(h.get('mail-scan-genesis').hidden,false,'a genesis scan is offered');
  const cleared=h.calls.length;await h.get('mail-clear-cache').click();await h.get('mail-more').click();await h.drain();
  eq(h.calls.slice(cleared).find(x=>x.body.method==='explorer_mail').body.params.after,`${birth.height}:9223372036854775807`,'clearing the saved scan returns to the start, not to genesis');
  const genesis=h.calls.length;await h.get('mail-scan-genesis').click();await h.drain();
  ok(!Object.hasOwn(h.calls.slice(genesis).find(x=>x.body.method==='explorer_mail').body.params,'after'),'Scan from genesis rescans all history');ok(!h.savedStorage.has(startKey),'and forgets the start');
  eq(h.get('mail-list').children.length,1);eq(h.get('mail-scan-genesis').hidden,true);ok(h.get('mail-start-note').textContent.includes('from genesis'));
  h.get('import-private-key').value='0'.repeat(63)+'3';await h.get('wallet-import-form').requestSubmit();await settle();
  ok(![...h.savedStorage.keys()].some(k=>k.startsWith('hashstash-mail-start-1:')&&!k.endsWith(created)),'an imported key gets no guessed start');
 }
 {
  // An imported wallet can choose where its scan begins.
  const h=await setup(),s=h.currentSnapshot,early=await h.message({},h.sender,h.recipient);await h.publish([early]);
  const late=await h.message({height:early.height+3},h.sender,h.recipient);await h.publish([late]);eq(h.get('mail-list').children.length,2);
  const form=h.get('mail-start-form'),startKey=`hashstash-mail-start-1:${s.status.chain_id}:${h.sender}`,tip=s.status.tip;
  form.elements.height.value=String(s.status.height+1);await form.requestSubmit();await settle();
  ok(h.get('mail-start-feedback').textContent.includes(`from 0 to ${s.status.height}`),'a start above the tip is refused');eq(h.get('mail-list').children.length,2,'and changes nothing');
  const before=h.calls.length;form.elements.height.value=String(late.height);await form.requestSubmit();await h.drain();
  const first=h.calls.slice(before).find(x=>x.body.method==='explorer_mail').body.params;
  eq(first.after,`${late.height-1}:9223372036854775807`,'a chosen start rescans from that block');eq(first.anchor,tip,'anchored at the current tip');
  eq(h.get('mail-list').children.length,1,'mail below the chosen block is not scanned');ok(h.get('mail-scan-status').textContent.includes(`from block ${late.height}`));
  eq(JSON.parse(h.savedMail.get(startKey)),{version:1,height:late.height-1,anchor:tip,origin:'chosen'});ok(h.get('mail-start-note').textContent.includes(`scanned from block ${late.height}`));
  form.elements.height.value='0';await form.requestSubmit();await h.drain();
  ok(!h.savedMail.has(startKey),'block 0 scans from genesis');eq(h.get('mail-list').children.length,2,'and finds the earlier mail again');
 }
 {
  // A start whose anchor the node does not know is dropped for a genesis scan.
  const h=await setup(),m=await h.message();await h.publish([m]);
  const startKey=`hashstash-mail-start-1:${h.currentSnapshot.status.chain_id}:${h.sender}`,saved=new Map([[startKey,JSON.stringify({version:1,height:m.height,anchor:'ab'.repeat(32),origin:'created'})]]);
  const restored=await setup({savedMail:saved,initialSnapshot:h.currentSnapshot,history:h.history,invalidAnchor:true}),requests=restored.calls.filter(x=>x.body.method==='explorer_mail').map(x=>x.body.params);
  eq(requests[0].after,`${m.height}:9223372036854775807`);ok(!Object.hasOwn(requests[1],'after'),'an unknown start anchor falls back to genesis');
  eq(restored.get('mail-list').children.length,1,'so no mail is missed');ok(!saved.has(startKey),'and the start is dropped');
 }
 {
  const h=await harness({mail:true,empty:true});await h.refresh();await h.navigate('#mail');eq(h.calls.filter(c=>c.body.method==='explorer_mail').length,0);ok(h.get('mail-empty').textContent.includes('Select a wallet'));
 }
 console.log(`${checks} recipient-hidden mail UI checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});

