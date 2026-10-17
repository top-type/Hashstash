'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { harness, response, settle, addr, deferred } = require('./test_wallet_ui.cjs');
const sender = '12'.repeat(32), other = '34'.repeat(32), id = 'ab'.repeat(32);
let checks = 0;
const equal = (a,b,m) => { assert.deepEqual(a,b,m); checks++; };
const ok = (value,m) => { assert.ok(value,m); checks++; };
const walk = node => [node,...(node.children||[]).flatMap(walk)];
const hash = value => BigInt(value).toString(16).padStart(64,'0');
async function setup(options = {}) {
  const h = await harness({chat:true,...options}), s=h.currentSnapshot;
  s.status.settings.block_bytes=16384;

  s.status.fee_policy={minimum_fee_rate:'1',fee_scale:1024,account_weight:1024};
  h.feed={chain_id:s.status.chain_id,tip:s.status.tip,height:s.status.height,ready:true,items:[],pending:[],next_cursor:null,message_bytes:16384};
  h.handlers.explorer_chat=()=>response({result:h.feed});
  h.message=(overrides={})=>({txid:id,sender:addr(sender),height:19,position:0,text:'Hello',kind:'transfer',amount:'1',asset:'hash',recipient:addr(other),status:'confirmed',confirmations:2,...overrides});
  await h.refresh(); await h.navigate('#chat');
  h.feedRefresh=async()=>{h.wallClock+=7000;await h.refresh();await settle();};
  return h;
}
async function run() {
  const html=fs.readFileSync(path.join(__dirname,'../ui/index.html'),'utf8'),view=html.slice(html.indexOf('<section id="view-chat"'),html.indexOf('<section id="view-mail"'));
  ok(!view.includes('<form'),'Chat is only a feed');
  for(const removed of ['chat-form','chat-submit','chat-amount','chat-text','chat-reply-cancel'])ok(!html.includes(`id="${removed}"`));
  ok(view.indexOf('id="chat-more"')<view.indexOf('id="chat-messages"'),'load older is above chronological messages');
  ok(view.indexOf('id="chat-pending-section"')>view.indexOf('id="chat-messages"'),'pending is separate from confirmed ordering');
  equal(Object.keys(require('../ui/chat.js')),['create','isBlank'],'no message wrapper encoder or posting minimum remains in the feed');
  {
    // The browser's blank-text rule is a literal copy of the node's table.
    const rust=fs.readFileSync(path.join(__dirname,'../src/chat.rs'),'utf8'),start=rust.indexOf('pub const BLANK'),table=rust.slice(start,rust.indexOf('];',start));
    const ranges=[...table.matchAll(/\(0x([0-9A-F]+),\s*0x([0-9A-F]+)\)/g)].map(match=>[parseInt(match[1],16),parseInt(match[2],16)]);
    ok(ranges.length>20,'the Rust blank table was found');
    const {isBlank}=require('../ui/chat.js');let mismatches=0;
    for(let point=0;point<=0x10ffff;point++){if(point>=0xd800&&point<=0xdfff)continue;if(isBlank(String.fromCodePoint(point))!==ranges.some(([low,high])=>point>=low&&point<=high))mismatches++;}
    equal(mismatches,0,'every code point is blank in the browser exactly when it is blank in src/chat.rs');
    for(const text of ['﻿',' ﻿\n','​','⁠️','\u{e0020}','ㅤ'])ok(isBlank(text),JSON.stringify(text));
    for(const text of ['a﻿b','⠀','👨‍👩'])ok(!isBlank(text),JSON.stringify(text));
  }
  {
    const h=await setup({empty:true});
    equal(h.get('chat-nav').hidden,false);equal(h.get('chat-enabled').hidden,false);
    h.feed.items=[
      h.message({txid:hash(5),height:21,position:4,kind:'refund',amount:null,asset:null,recipient:null,text:'Refund explanation'}),
      h.message({txid:hash(4),height:21,position:3,kind:'propose',amount:'0',text:'Proposal rationale'}),
      h.message({txid:hash(3),height:21,position:2,kind:'redeem',amount:'1000',asset:'stash',text:'Selling some stash'}),
      h.message({txid:hash(2),height:21,position:1,kind:'deposit',amount:'1',text:'Buying stash'}),
      h.message({txid:hash(1),height:20,position:8,text:'One atom transfer'})
    ];
    await h.feedRefresh();
    equal(h.get('chat-messages').children.map(row=>row.dataset.txid),[1,2,3,4,5].map(hash),'canonical messages use ascending block and transaction position');
    for(const label of ['One atom transfer','Stash purchase','Stash sale','Proposal','Refund'])ok(h.get('chat-messages').textContent.includes(label));
    ok(h.get('chat-messages').children[2].textContent.includes('1 stash'),'redemptions show their share amount in stash');
    ok(!h.get('chat-messages').children[4].textContent.includes('hash'),'an operation without an amount does not invent one');
    equal(h.wallet.length,0);equal(h.calls.filter(call=>['preparetransaction','broadcasttransaction','fee_quote'].includes(call.body.method)).length,0,'reading messages cannot prepare, quote or broadcast a contribution');
    equal(h.storage.filter(entry=>entry.key.startsWith('hashstash-chat-draft:')).length,0,'feed creates no composer drafts');
  }
  {
    const h=await setup();h.feed.items=[h.message({txid:hash(1),height:'9007199254740993',position:'9007199254740993'}),h.message({txid:hash(2),height:'9007199254740993',position:'9007199254740992'}),h.message({txid:hash(3),height:'9007199254740992',position:0})];await h.feedRefresh();
    equal(h.get('chat-messages').children.map(row=>row.dataset.txid),[3,2,1].map(hash),'chronological ordering preserves full integer precision');
  }
  {
    const h=await setup({empty:true});h.feed.items=[h.message({text:'<img src=x onerror=alert(1)>\r\n\tPublic text'})];
    const pending=h.message({txid:'cd'.repeat(32),height:null,position:null,status:'pending',confirmations:0,text:'waiting'});
    h.feed.pending=[pending,pending,{...h.feed.items[0],height:null,position:null,status:'pending',confirmations:0}];await h.feedRefresh();
    const list=h.get('chat-messages'),first=list.children[0];
    ok(first.textContent.includes('<img src=x onerror=alert(1)>'));equal(walk(first).filter(node=>['IMG','SCRIPT'].includes(node.tagName)).length,0,'public text is never HTML');
    equal(walk(first).filter(node=>node.tagName==='BUTTON'&&node.textContent==='Reply').length,0,'feed has no reply composer');
    equal(h.get('chat-pending-section').hidden,false);equal(h.get('chat-pending').children.length,1,'pending duplicates and already confirmed IDs are excluded');
    ok(h.get('chat-pending').textContent.includes('Pending'));ok(!h.get('chat-pending').textContent.includes('Block'),'pending messages have no invented height or time');
    await h.feedRefresh();equal(list.children[0],first,'unchanged polling preserves DOM and text selection');
    await walk(first).find(node=>node.tagName==='BUTTON'&&node.textContent==='Mute').click();equal(list.children.length,0);equal(h.get('chat-muted').hidden,false);equal(h.get('chat-pending-section').hidden,true);
    ok(h.storage.some(entry=>entry.key==='hashstash-chat-muted:'+'a'.repeat(64)));
    await walk(h.get('chat-muted-list')).find(node=>node.tagName==='BUTTON').click();equal(list.children.length,1);
    h.wallClock+=130000;await h.refresh();ok(h.get('chat-status').textContent.includes('No recent block'));
    h.feed.items=[];h.feed.pending=[];h.currentSnapshot.status.tip='ef'.repeat(32);h.feed.tip=h.currentSnapshot.status.tip;await h.feedRefresh();equal(list.children.length,0,'a reorganization removes disappeared canonical messages');equal(h.get('chat-pending').children.length,0);
  }
  {
    const h=await setup({empty:true});
    const original='Automated Demo · Mara — Bought stash.\nSame exact body.';
    const untrusted='Automated Demo · <img src=x onerror=alert(1)> — <script>alert(2)</script>';
    const ordinary=[
      'Mara — Ordinary message',
      'automated Demo · Mara — Different capitalization',
      'Automated Demo - Mara — Different separator',
      'Automated Demo · Mara— Missing separator spaces',
      'Quoted: Automated Demo · Mara — Not a leading label',
      'Automated Demo · Mara\nQuinn — Multiline name',
      'Automated Demo ·   — Empty name'
    ];
    h.feed.items=[original,untrusted,...ordinary].map((text,index)=>h.message({txid:hash(index+1),position:index,text}));
    const pendingText='Automated Demo · Quinn — Waiting for inclusion.';
    h.feed.pending=[h.message({txid:hash(20),height:null,position:null,status:'pending',confirmations:0,text:pendingText})];
    await h.feedRefresh();
    const rows=h.get('chat-messages').children;
    const body=row=>walk(row).find(node=>node.className==='chat-message-text');
    const badge=row=>walk(row).find(node=>node.className==='chat-automated');
    const account=row=>walk(row).find(node=>node.href?.startsWith('#explorer?account='));
    const transaction=row=>walk(row).find(node=>node.href?.startsWith('#explorer?tx='));
    equal(body(rows[0]).textContent,'Mara — Bought stash.\nSame exact body.','a demo label is shortened without changing the persona or message body');
    equal(badge(rows[0]).textContent,'Automated','automation remains visible in the message header');
    equal(badge(rows[0])['aria-label'],'Automated, self-described');
    ok(badge(rows[0]).title.includes('not a verified sender identity'),'the label is a self-description, not an authenticated identity');
    equal(account(rows[0]).href,`#explorer?account=${encodeURIComponent(addr(sender))}`,'the sender still links to the signed account');
    equal(account(rows[0]).title,addr(sender));
    ok(!account(rows[0]).textContent.includes('Mara'),'the claimed persona does not replace the account identity');
    equal(transaction(rows[0]).href,`#explorer?tx=${hash(1)}`);
    equal(transaction(rows[0]).title,`Transaction 1 in this block\nOriginal signed message:\n${original}`,'the existing transaction link exposes the unchanged signed message');
    equal(h.feed.items[0].text,original,'display normalization never rewrites the source record');
    equal(body(rows[1]).textContent,'<img src=x onerror=alert(1)> — <script>alert(2)</script>');
    equal(walk(rows[1]).filter(node=>['IMG','SCRIPT'].includes(node.tagName)).length,0,'untrusted persona and body stay plain text');
    equal(account(rows[1]).href,`#explorer?account=${encodeURIComponent(addr(sender))}`,'a claimed HTML persona cannot change the sender identity');
    ok(transaction(rows[1]).title.endsWith(untrusted),'the untrusted original is retained as text');
    for(let index=0;index<ordinary.length;index++){
      const row=rows[index+2];
      equal(body(row).textContent,ordinary[index],'ordinary and lookalike labels remain unchanged');
      equal(badge(row),undefined,'only the exact leading demo label gets an automation badge');
      ok(!transaction(row).title.includes('Original signed message:'),'ordinary transaction labels remain unchanged');
    }
    const pending=h.get('chat-pending').children[0];
    equal(body(pending).textContent,'Quinn — Waiting for inclusion.');
    equal(badge(pending).textContent,'Automated');
    equal(transaction(pending).textContent,'Pending','automation formatting does not imply confirmation');
    equal(transaction(pending).title,`Original signed message:\n${pendingText}`);
  }
  {
    const h=await setup({empty:true});
    const original='Mara · Automated — Bought stash.\nThe body also mentions Rook · Automated — unchanged.';
    const untrusted='<img src=x onerror=alert(1)> · Automated — <script>alert(2)</script>';
    const ordinary=[
      'Mara · automated — Different capitalization',
      'Mara - Automated — Different separator',
      'Mara· Automated — Missing separator space',
      'Mara · Automated— Missing separator spaces',
      'Mara · Automated - Different body separator',
      'Mara\nQuinn · Automated — Multiline name',
      '  · Automated — Empty name',
      'Mara — A body mentions Rook · Automated — without changing its author'
    ];
    h.feed.items=[original,untrusted,...ordinary].map((text,index)=>h.message({txid:hash(index+1),position:index,text}));
    const pendingText='Quinn · Automated — Waiting for inclusion.';
    h.feed.pending=[h.message({txid:hash(20),height:null,position:null,status:'pending',confirmations:0,text:pendingText})];
    await h.feedRefresh();
    const rows=h.get('chat-messages').children;
    const body=row=>walk(row).find(node=>node.className==='chat-message-text');
    const badge=row=>walk(row).find(node=>node.className==='chat-automated');
    const account=row=>walk(row).find(node=>node.href?.startsWith('#explorer?account='));
    const transaction=row=>walk(row).find(node=>node.href?.startsWith('#explorer?tx='));
    equal(body(rows[0]).textContent,'Mara — Bought stash.\nThe body also mentions Rook · Automated — unchanged.','the native label is shortened only at the start and the complete body is preserved');
    equal(badge(rows[0]).textContent,'Automated');
    equal(badge(rows[0])['aria-label'],'Automated, self-described');
    ok(badge(rows[0]).title.includes('not a verified sender identity'));
    equal(account(rows[0]).href,`#explorer?account=${encodeURIComponent(addr(sender))}`,'native persona labels do not change the signed sender');
    equal(account(rows[0]).title,addr(sender));
    ok(!account(rows[0]).textContent.includes('Mara'));
    equal(transaction(rows[0]).href,`#explorer?tx=${hash(1)}`);
    equal(transaction(rows[0]).title,`Transaction 1 in this block\nOriginal signed message:\n${original}`);
    equal(h.feed.items[0].text,original,'the native signed record remains unchanged');
    equal(body(rows[1]).textContent,'<img src=x onerror=alert(1)> — <script>alert(2)</script>');
    equal(walk(rows[1]).filter(node=>['IMG','SCRIPT'].includes(node.tagName)).length,0,'native persona and original message remain plain text');
    equal(account(rows[1]).href,`#explorer?account=${encodeURIComponent(addr(sender))}`);
    ok(transaction(rows[1]).title.endsWith(untrusted));
    for(let index=0;index<ordinary.length;index++){
      const row=rows[index+2];
      equal(body(row).textContent,ordinary[index],'native lookalikes and labels inside ordinary bodies remain unchanged');
      equal(badge(row),undefined);
      ok(!transaction(row).title.includes('Original signed message:'));
    }
    const pending=h.get('chat-pending').children[0];
    equal(body(pending).textContent,'Quinn — Waiting for inclusion.');
    equal(badge(pending).textContent,'Automated');
    equal(transaction(pending).textContent,'Pending');
    equal(transaction(pending).title,`Original signed message:\n${pendingText}`);
  }
  {
    const h=await setup();h.feed.items=[h.message({txid:hash(3),height:21}),h.message({txid:hash(2),height:20})];h.feed.next_cursor='older';
    h.handlers.explorer_chat=p=>response({result:p.cursor?{...h.feed,items:[h.message({txid:hash(1),height:18})],next_cursor:null}:h.feed});
    await h.feedRefresh();await h.get('chat-more').click();await settle();equal(h.get('chat-messages').children.map(row=>row.dataset.txid),[1,2,3].map(hash),'older pages prepend in chronological order');
    const first=h.get('chat-messages').children[0];await h.feedRefresh();equal(h.get('chat-messages').children.length,3,'polling retains opened history');equal(h.get('chat-messages').children[0],first);
    h.feed.items=[h.message({txid:hash(9),height:21})];h.feed.next_cursor=null;await h.feedRefresh();equal(h.get('chat-messages').children.map(row=>row.dataset.txid),[hash(9)],'refresh replaces removed history rather than appending stale rows');
  }
  {
    const h=await setup();h.handlers.explorer_chat=p=>{const page=Number(p.cursor||0);return response({result:{...h.feed,items:Array.from({length:20},(_,offset)=>h.message({txid:hash(1000-page*20-offset),height:1000-page*20-offset})),next_cursor:String(page+1)}});};
    await h.feedRefresh();for(let page=1;page<10;page++){await h.get('chat-more').click();await settle();}
    equal(h.get('chat-messages').children.length,200);equal(h.get('chat-more').hidden,true);equal(h.get('chat-history-note').hidden,false);
    const before=h.calls.filter(call=>call.body.method==='explorer_chat').length;await h.get('chat-more').click();await settle();equal(h.calls.filter(call=>call.body.method==='explorer_chat').length,before,'loading history cannot exceed the visible page bound');
    await h.feedRefresh();equal(h.calls.filter(call=>call.body.method==='explorer_chat').length-before,10,'refresh work is bounded by retained pages');
  }
  {
    const h=await setup();h.feed.items=[h.message({text:'é'.repeat(16384)})];await h.feedRefresh();equal(h.get('chat-messages').children.length,1,'historical plaintext remains readable even above the current governed block capacity');
    h.feed.items=[h.message({text:'a'.repeat(32*1024*1024+1)})];await h.feedRefresh();equal(h.get('chat-messages').children.length,1,'historical messages above32MiB remain readable');
    for(const invalid of [{text:' '},{text:'﻿'},{text:' ﻿\n'},{text:'​'},{text:'a\u0000b'},{text:'a\u0085b'},{text:'\ud800'},{sender:'<script>'},{amount:'-1'},{amount:'0',asset:'bitcoin'},{amount:null,asset:'hash'},{position:null},{position:'18446744073709551616'}, {kind:'<script>'}, {txid:'<script>'}]){
      h.feed.items=[h.message({txid:hash(1),height:18,text:'Before'}),h.message({txid:hash(2),...invalid}),h.message({txid:hash(3),height:20,text:'After'})];await h.feedRefresh();
      equal(h.get('chat-messages').children.map(row=>row.dataset.txid),[hash(1),hash(3)],`a malformed record is skipped without hiding its page: ${JSON.stringify(invalid)}`);
      ok(h.get('chat-status').textContent.includes('1 message could not be displayed.'),'malformed message metadata is reported, not rendered');
    }
    h.feed.items=[h.message({txid:hash(1)})];h.feed.pending=[h.message({txid:hash(2),height:null,position:null,status:'pending',confirmations:0,text:'﻿'}),h.message({txid:hash(3),height:null,position:null,status:'pending',confirmations:0,text:'Waiting'})];await h.feedRefresh();
    equal(h.get('chat-pending').children.map(row=>row.dataset.txid),[hash(3)],'a blank pending record does not hide other pending messages');equal(h.get('chat-messages').children.length,1);
    ok(h.get('chat-status').textContent.includes('1 message could not be displayed.'));
    h.feed.pending=[];await h.feedRefresh();ok(!h.get('chat-status').textContent.includes('could not be displayed'),'a clean refresh clears the skipped-record note');
    h.feed.items=Array.from({length:21},(_,n)=>h.message({txid:hash(n)}));await h.feedRefresh();ok(h.get('chat-status').textContent.includes('Messages unavailable'),'oversized pages are rejected');
    h.feed.items=[];h.feed.next_cursor='x'.repeat(257);await h.feedRefresh();ok(h.get('chat-status').textContent.includes('Messages unavailable'),'oversized cursors are rejected');
  }
  {
    const h=await setup(),held=deferred();h.handlers.explorer_chat=()=>held.promise;h.wallClock+=7000;await h.refresh();
    await h.navigate('#wallet');held.resolve(response({result:{...h.feed,items:[h.message()]}}));await settle();equal(h.get('chat-messages').children.length,0,'late results after navigation are ignored');
  }
  {
    const h=await setup(),held=deferred(),old={...h.feed,items:[h.message()]};h.handlers.explorer_chat=()=>held.promise;h.wallClock+=7000;await h.refresh();
    h.currentSnapshot.status.tip=hash(99);h.feed.tip=hash(99);h.handlers.explorer_chat=()=>response({result:h.feed});await h.refresh();held.resolve(response({result:old}));await settle();equal(h.get('chat-messages').children.length,0,'a late old-tip response cannot restore removed messages');
  }
  {
    const h=await setup();h.feed.items=Array.from({length:21},(_,n)=>h.message({txid:hash(n)}));await h.feedRefresh();equal(h.get('chat-messages').children.length,0);ok(h.get('chat-status').textContent.includes('Messages unavailable'));
    const error=h.get('chat-status').textContent;await h.refresh();equal(h.get('chat-status').textContent,error,'ordinary refresh preserves the feed error until recovery');
    h.feed.items=[];h.feed.ready=false;await h.feedRefresh();equal(h.get('chat-status').textContent,'Indexing messages…');await h.refresh();equal(h.get('chat-status').textContent,'Indexing messages…');
    h.feed.ready=true;await h.feedRefresh();equal(h.get('chat-status').hidden,true,'successful reindexing clears the status');
  }
  {
    const h=await setup({empty:true}),full=addr(sender),start=full.lastIndexOf('1')+1;
    h.feed.items=[h.message({txid:hash(1),text:'Pay 01‮987‬ now'}),h.message({txid:hash(2),text:'Automated Demo · Mara — ⁧reversed⁩'})];await h.feedRefresh();
    const rows=h.get('chat-messages').children,account=row=>walk(row).find(node=>node.href?.startsWith('#explorer?account='));
    const label=`hsh…${full.slice(start,start+10)}…${full.slice(-6)}`;
    equal(account(rows[0]).textContent,label,'the sender label shows key data and the checksum, not the network prefix');
    ok(!account(rows[0]).textContent.startsWith(full.slice(0,8)),'the constant network prefix is not spent on the label');
    equal(walk(rows[0]).find(node=>node.className==='chat-message-text').textContent,'Pay 01\\u202e987\\u202c now','bidi overrides are shown as visible escapes');
    equal(walk(rows[1]).find(node=>node.className==='chat-message-text').textContent,'Mara — \\u2067reversed\\u2069','isolates are shown as visible escapes');
    ok(walk(rows[1]).find(node=>node.href?.startsWith('#explorer?tx=')).title.endsWith('\\u2067reversed\\u2069'),'the original-message tooltip is escaped too');
    equal(h.feed.items[0].text,'Pay 01‮987‬ now','display escaping never rewrites the source record');
    await walk(rows[0]).find(node=>node.tagName==='BUTTON'&&node.textContent==='Mute').click();
    const muted=walk(h.get('chat-muted-list')).find(node=>node.href?.startsWith('#explorer?account='));
    equal(muted.textContent,label,'muted senders use the same distinguishing label');equal(muted.title,full);
  }
  console.log(`Chat UI: ${checks} behavior assertions passed.`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
