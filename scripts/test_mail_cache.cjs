'use strict';
const assert=require('node:assert/strict'),{createCache}=require('../ui/mail.js');
let checks=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(v,m)=>{assert.ok(v,m);checks++;};
const id=n=>BigInt(n).toString(16).padStart(64,'0'),chain=id(1),wallet=id(2),other=id(3),anchor=id(4),values=new Map();
let denied=false;const storage={getItem:k=>values.get(k)??null,setItem:(k,v)=>{if(denied)throw Error('QuotaExceededError');values.set(k,v);},removeItem:k=>values.delete(k)},cache=createCache({storage});
const row=(n=0)=>({txid:id(100+n),sender_public_key:wallet,nonce:'0',height:1,position:n,raw:'ab'.repeat(3000),clear:{subject:'DO NOT STORE',body:'PRIVATE BODY'},private_key:'NEVER STORE',recipient_public_key:other});
const state=(n=1)=>({cursor:'1:9223372036854775807',anchor,scanned:n,entries:Array.from({length:n},(_,i)=>row(i))});
eq(cache.read(chain,wallet),{value:null},'new account starts with no checkpoint');
values.set(`hashstash-mail-scan-2:${chain}:${wallet}`,JSON.stringify({...state(),version:2}));
eq(cache.read(chain,wallet),{value:null},'old unsigned checkpoints cannot skip history');values.clear();
eq(cache.write(chain,wallet,state()),{saved:true});
const original=[...values.values()][0];ok(!original.includes('DO NOT STORE'));ok(!original.includes('PRIVATE BODY'));ok(!original.includes('NEVER STORE'));ok(!original.includes('recipient_public_key'),'persistent rows whitelist only public ciphertext metadata');
const result=cache.read(chain,wallet);eq(result.value.cursor,state().cursor);eq(result.value.entries.length,1);eq(Object.keys(result.value.entries[0]).sort(),['height','position','raw','txid']);
eq(cache.read(chain,other),{value:null},'wallets have separate scan checkpoints');eq(cache.read(other,wallet),{value:null},'chains have separate scan checkpoints');
eq(cache.write(chain,other,state()),{saved:true});eq(values.size,2);
eq(cache.write(chain,wallet,state(256)),{saved:true},'bounded ciphertext inbox persists');eq(cache.read(chain,wallet).value.omitted,0);
// More opened mail than the cache holds must not freeze the checkpoint: anyone
// can send an address 257 messages. The oldest are left out and counted.
eq(cache.write(chain,wallet,{...state(257),cursor:'2:0',scanned:900}),{saved:true},'a full cache still advances its checkpoint');
{const saved=cache.read(chain,wallet).value;eq(saved.cursor,'2:0');eq(saved.scanned,900);eq(saved.entries.length,256);eq(saved.omitted,1,'the evicted message is counted');eq(saved.entries.some(e=>e.position===0),false,'the oldest message is the one left out');ok(saved.entries.some(e=>e.position===256),'the newest message is kept');}
eq(cache.write(chain,wallet,{...state(257),omitted:3}),{saved:true});eq(cache.read(chain,wallet).value.omitted,4,'earlier omissions accumulate');
{const big=n=>({...row(n),height:1+n,raw:'cd'.repeat(5000)}),entries=Array.from({length:250},(_,n)=>big(n));
 eq(cache.write(chain,wallet,{cursor:'999:0',anchor,scanned:250,entries}),{saved:true},'the byte bound also evicts instead of failing');
 const text=values.get([...values.keys()][0]),saved=cache.read(chain,wallet).value;ok(text.length<=2*1024*1024);ok(saved.entries.length<250&&saved.entries.length>150);eq(saved.omitted+saved.entries.length,250);eq(Math.min(...saved.entries.map(e=>e.height)),251-saved.entries.length,'only the newest rows are kept');}
eq(cache.write(chain,wallet,{...state(),entries:[{...row(),raw:'ff'.repeat(1024*1024+1)}]}),{saved:true},'one carrier too large to cache does not freeze the checkpoint');eq(cache.read(chain,wallet).value.entries.length,0);eq(cache.read(chain,wallet).value.omitted,1);
eq(cache.write(chain,wallet,state(256)),{saved:true});const full=values.get([...values.keys()][0]);
denied=true;eq(cache.write(chain,wallet,{...state(),cursor:'2:1'}).saved,false);eq(values.get([...values.keys()][0]),full,'storage failure never writes cursor separately');denied=false;
values.set([...values.keys()][0],JSON.stringify({...JSON.parse(full),omitted:-1}));eq(cache.read(chain,wallet).value,null,'a negative omission count is invalid');values.set([...values.keys()][0],full);
eq(cache.write(chain,wallet,{...state(),cursor:'0:1'}).saved,false,'entries beyond checkpoint are invalid');eq(cache.write(chain,wallet,{...state(),entries:[row(),row()]}).saved,false,'duplicate rows are invalid');
eq(cache.write(chain,wallet,{...state(),entries:[{...row(),height:-1}]}).saved,false);eq(cache.write(chain,wallet,{...state(),anchor:'bad'}).saved,false);
eq(cache.write(chain,wallet,{...state(),entries:[{...row(),raw:undefined}]}).saved,false,'unsigned records cannot enter the signed cache');
// Earlier checkpoints, newest first and strictly below the current cursor,
// let a scan resume when its latest anchor is unknown to the node.
{const points=[{cursor:'1:5',anchor:id(5)},{cursor:'0:9223372036854775807',anchor:id(6)}];
 eq(cache.read(chain,other).value.checkpoints,[],'a checkpoint saved without earlier ones reads as none');
 eq(cache.write(chain,wallet,{...state(),checkpoints:points}),{saved:true});eq(cache.read(chain,wallet).value.checkpoints,points);
 for(const bad of [[points[1],points[0]],[{cursor:'1:9223372036854775807',anchor:id(5)}],[points[0],points[0]],[{cursor:'1:5',anchor:'bad'}],[{cursor:'x',anchor:id(5)}],Array.from({length:5},(_,i)=>({cursor:`0:${10-i}`,anchor:id(5)})),'not a list'])
  eq(cache.write(chain,wallet,{...state(),checkpoints:bad}).saved,false,'checkpoints must be valid and strictly below the cursor');
 eq(cache.read(chain,wallet).value.checkpoints,points,'a refused write keeps the saved checkpoints');}
eq(cache.clear(chain,wallet),{cleared:true});eq(cache.read(chain,wallet),{value:null});eq(cache.read(chain,other).value.entries.length,1,'clearing one cache preserves another wallet');
const brokenKey=[...values.keys()][0];values.set(brokenKey,'{bad json');ok(cache.read(chain,other).error.includes('beginning'),'malformed local data starts full history scan');
values.set(brokenKey,JSON.stringify({...state(),version:999}));eq(cache.read(chain,other).value,null,'unknown schema is never reused');
// A scan start is kept beside the checkpoint, so clearing one keeps the other.
{const start={version:1,height:40,anchor,origin:'created'};values.clear();
 eq(cache.readStart(chain,wallet),null,'accounts start at genesis by default');eq(cache.writeStart(chain,wallet,start),{saved:true});eq(cache.readStart(chain,wallet),start);
 eq(cache.readStart(chain,other),null,'starts are per account');eq(cache.readStart(other,wallet),null,'and per chain');
 eq(cache.write(chain,wallet,state()),{saved:true});eq(cache.clear(chain,wallet),{cleared:true});eq(cache.readStart(chain,wallet),start,'clearing the saved scan keeps its start');
 for(const bad of [{...start,version:2},{...start,height:-1},{...start,height:2**32},{...start,height:1.5},{...start,anchor:'bad'},{...start,origin:'guessed'}])eq(cache.writeStart(chain,other,bad).saved,false,'invalid starts are refused');
 values.set([...values.keys()].find(k=>k.startsWith('hashstash-mail-start-1:')),'{bad json');eq(cache.readStart(chain,wallet),null,'an unreadable start falls back to genesis');
 eq(cache.writeStart(chain,wallet,start).saved,true);eq(cache.clearStart(chain,wallet),{cleared:true});eq(cache.readStart(chain,wallet),null);eq(cache.read(chain,wallet),{value:null});}
const disabled=createCache({storage:null});eq(disabled.readStart(chain,wallet),null);eq(disabled.writeStart(chain,wallet,{version:1,height:0,anchor,origin:'chosen'}).saved,false);ok(disabled.read(chain,wallet).error.includes('visit'));eq(disabled.write(chain,wallet,state()).saved,false);eq(disabled.clear(chain,wallet).cleared,false);
const fault=createCache({storage:{getItem(){throw Error('SecurityError');},setItem(){throw Error('SecurityError');},removeItem(){throw Error('SecurityError');}}});eq(fault.read(chain,wallet).value,null);eq(fault.write(chain,wallet,state()).saved,false);eq(fault.clear(chain,wallet).cleared,false);
console.log(`${checks} private mail cache checks passed`);
