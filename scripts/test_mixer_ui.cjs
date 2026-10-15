'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{webcrypto,createHash}=require('node:crypto');
const Address=require('../ui/address.js');let checks=0;
const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(v,m)=>{assert.ok(v,m);checks++;},bad=(f,re=/./)=>{assert.throws(f,re);checks++;},reject=async(f,re=/./)=>{await assert.rejects(f,re);checks++;};
const context=vm.createContext({crypto:webcrypto,TextEncoder,Uint8Array,console,fetch(){throw Error('Pure planning must never fetch');}});vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/vendor/noble.js'),'utf8'),context);
const chain='17'.repeat(32),key=n=>Buffer.from(context.HashstashNoble.schnorr.getPublicKey(Uint8Array.from(Buffer.from(BigInt(n).toString(16).padStart(64,'0'),'hex')))).toString('hex'),mixerKey=key(2),sender=key(3),hrp='hsh'+chain.slice(0,16),encode=k=>Address.encode(k,hrp),decode=a=>Address.decode(a,hrp),receivers=Array.from({length:8},(_,n)=>encode(key(20+n)));
const canonical=t=>JSON.stringify(Object.fromEntries(Object.keys(t).sort().map(k=>[k,t[k]]))),descriptor=updates=>{const terms={version:1,chain_id:chain,public_key:mixerKey,denomination_atoms:'1000',service_fee_bps:100,payout_fee_cap_atoms:'20',minimum_deposits:2,confirmations:2,timeout_seconds:3600,max_addresses:8,...updates};return {terms,terms_id:createHash('sha256').update(canonical(terms)).digest('hex'),address:encode(terms.public_key)};};
vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/mixer.js'),'utf8'),context);const api=context.HashstashMixer;
const simple=o=>JSON.parse(JSON.stringify(o));
class Element{constructor(){this.events={};this.textContent='';this.children=[];this.disabled=false;this.classList={toggle(){}};}appendChild(child){this.children.push(child);return child;}replaceChildren(...children){this.children=children;this.textContent='';}addEventListener(name,fn){this.events[name]=fn;}fire(name,event={preventDefault(){}}){return this.events[name]?.(event);}}
async function interfaceHarness(){
 const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};const form=get('mixer-form');form.elements={count:{value:'2'},addresses:{value:receivers.slice(0,3).join('\n')},amount:{value:'3110'},trust:{checked:true}};
 const h={get,form,requests:[],prepared:[],c:{ready:true,chain_id:chain,key:sender,wallet:'wallet1'},current:descriptor(),generated:0};
 h.fetch=async(url,options)=>{h.requests.push({url,options});return {ok:true,text:async()=>JSON.stringify(h.current)};};
 h.ui=api.create({getContext:()=>h.c,encodeAddress:encode,decodeAddress:decode,parseAmount:x=>x,formatAmount:x=>x,prepareDeposit:v=>h.prepared.push(v),createAddresses:async count=>{h.generated+=count;return receivers.slice(0,count);},document:{getElementById:get,createElement:()=>new Element()},fetch:(...args)=>h.fetch(...args)});
 h.load=()=>get('mixer-reload').fire('click');return h;
}
async function run(){
 const html=fs.readFileSync(path.join(__dirname,'../ui/index.html'),'utf8');
 const send=/<section id="view-send"[\s\S]*?<\/section>/.exec(html)[0],page=/<section id="view-mixer"[\s\S]*?<\/section>/.exec(html)[0];
 ok(!send.includes('mixer-panel'));ok(page.includes('mixer-form'));ok(page.includes('mixer-terms'));ok(page.includes('mixer-prepare'));ok(html.includes('data-route="mixer"'));ok(html.includes('href="#mixer">Mixer'));
 {const h=await interfaceHarness();h.ui.update();eq(h.requests.length,0);await h.ui.open(true);eq(h.requests.length,1);await h.ui.open(true);eq(h.requests.length,1);await h.ui.open(false);h.c.key=key(5);h.ui.update();eq(h.requests.length,1,'background wallet changes do not fetch descriptors');await h.ui.open(true);eq(h.requests.length,2,'returning to Mixer refreshes terms');}
 const d=descriptor(),valid=await api.validate(d,{chain_id:chain,encodeAddress:encode});eq(valid.terms_id,d.terms_id,'terms hash agrees with independent SHA-256 canonical JSON');ok(Object.isFrozen(valid));ok(Object.isFrozen(valid.terms));
 const reordered={...d,terms:Object.fromEntries(Object.entries(d.terms).reverse())};eq((await api.validate(reordered,{chain_id:chain,encodeAddress:encode})).terms_id,d.terms_id,'key order does not affect terms identifier');
 await reject(()=>api.validate({...d,terms:{...d.terms,service_fee_bps:101}},{chain_id:chain,encodeAddress:encode}),/identifier/);await reject(()=>api.validate(d,{chain_id:'18'.repeat(32),encodeAddress:encode}),/network/);await reject(()=>api.validate({...d,address:receivers[0]},{chain_id:chain,encodeAddress:encode}),/address/);await reject(()=>api.validate(descriptor({unknown:true}),{chain_id:chain,encodeAddress:encode}),/invalid/);
 for(const changes of [{service_fee_bps:1001},{minimum_deposits:1},{minimum_deposits:101},{confirmations:1},{confirmations:101},{timeout_seconds:59},{timeout_seconds:2592001},{max_addresses:0},{max_addresses:9},{denomination_atoms:'0'},{payout_fee_cap_atoms:'0'},{service_fee_bps:0.5},{denomination_atoms:((1n<<512n)).toString()},{public_key:'ff'.repeat(32)}])await reject(()=>api.validate(descriptor(changes),{chain_id:chain,encodeAddress:encode}),/Invalid/);
 const options={decodeAddress:decode,sender},p=api.plan(valid,'3110',receivers.slice(0,3),options);eq(simple(p),{count:3,payout:'3000',service:'30',network_cap:'80',body:JSON.stringify({terms:d.terms_id,addresses:receivers.slice(0,3)}),subject:'hashstash.mix/1'});
 eq(api.plan(valid,'3109',receivers.slice(0,3),options).count,2,'integer budget reserves refund fee before counting slots');eq(api.plan(valid,'1050',receivers,options).count,1);bad(()=>api.plan(valid,'1049',receivers,options),/cannot cover/);eq(api.plan(valid,'999999',receivers.slice(0,2),options).count,2,'address list caps payout count');
 const rounded=await api.validate(descriptor({denomination_atoms:'3',service_fee_bps:1,payout_fee_cap_atoms:'1'}),{chain_id:chain,encodeAddress:encode});eq(api.plan(rounded,'6',receivers,options).service,'1','fractional service atom rounds up using integers');
 for(const amount of ['0','-1',' 1050','1050 ','1.5','1e6',1050,((1n<<512n)).toString()])bad(()=>api.plan(valid,amount,receivers,options),/amount/);
 for(const addresses of [[],receivers.concat(receivers[0]),[receivers[0],receivers[0].toUpperCase()],[encode(sender)],[encode(mixerKey)],[encode('ff'.repeat(32))],['@name'],[Address.encode(key(20),'hsh'+'18'.repeat(8))]])bad(()=>api.plan(valid,'5000',addresses,options));
 const upper=api.plan(valid,'1050',[receivers[0].toUpperCase()],options);eq(JSON.parse(upper.body).addresses,[receivers[0]],'case-insensitive address entry emits canonical instructions accepted by the custodian');eq(Object.keys(JSON.parse(upper.body)),['terms','addresses'],'deposit amount remains authoritative; instructions contain only terms and destinations');
 for(let deposit=1;deposit<9000;deposit+=97){try{const value=api.plan(valid,String(deposit),receivers,options);ok(BigInt(value.payout)+BigInt(value.service)+BigInt(value.network_cap)<=BigInt(deposit),'quoted allocations never exceed deposited budget');}catch(e){ok(deposit<1050);}}
 {
  const h=await interfaceHarness();eq(h.requests.length,0,'unopened Mixer page does not fetch descriptors');await h.load();eq(h.requests.length,1);eq(h.requests[0].url,'/mixer-config.json');eq(h.requests[0].options.credentials,'omit');await h.form.fire('submit');eq(h.prepared.length,1);eq(h.prepared[0].recipient,d.address);eq(h.prepared[0].amount,'3110');eq(JSON.parse(h.prepared[0].body).addresses,receivers.slice(0,3));ok(h.requests.every(r=>r.url==='/mixer-config.json'),'destination resolution never calls recipient-specific RPC');ok(h.requests.every(r=>!JSON.stringify(r).includes(receivers[0])),'receiving addresses are never sent to the descriptor endpoint');
  await h.get('mixer-generate').fire('click');eq(h.generated,2);eq(h.form.elements.addresses.value,receivers.slice(0,2).join('\n'));ok(h.get('mixer-feedback').textContent.includes('Back up'));
  h.c.ready=false;await h.form.fire('submit');eq(h.prepared.length,1,'disconnection blocks preparation');h.c.ready=true;h.form.elements.trust.checked=false;await h.form.fire('submit');eq(h.prepared.length,1,'custodian trust acknowledgment is required');
 }
 {
  const h=await interfaceHarness();await h.load();let release;h.fetch=()=>new Promise(resolve=>{release=()=>resolve({ok:true,text:async()=>JSON.stringify(h.current)});});const pending=h.form.fire('submit');h.form.elements.amount.value='9999';release();await pending;eq(h.prepared.length,0,'editing the deposit during descriptor refresh cancels preparation');
 }
 {
  const h=await interfaceHarness();await h.load();h.current=descriptor({service_fee_bps:101});await h.form.fire('submit');eq(h.prepared.length,0,'changed service terms require another review');ok(h.get('mixer-feedback').textContent.includes('changed'));
 }
 console.log(`${checks} mixer UI planning and privacy checks passed`);
}
run().catch(e=>{console.error(e);process.exitCode=1;});
