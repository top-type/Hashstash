'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const shares = require('../ui/shares.js');
const amounts = require('../ui/amounts.js');
const html = fs.readFileSync(path.join(__dirname,'../cold-ui/index.html'),'utf8');
const source = fs.readFileSync(path.join(__dirname,'../cold-ui/app.js'),'utf8');
const publicKey = 'ab'.repeat(32), privateKey = 'cd'.repeat(32), sessionToken = 'ef'.repeat(32);
const tabStorage = () => { const values = new Map(); return {getItem:name=>values.has(name)?values.get(name):null,setItem(name,value){values.set(name,String(value));}}; };
const chainA = '09'.repeat(32), chainB = '10'.repeat(32);
const addressFor = chain => 'hsh' + chain.slice(0,16) + '1' + 'q'.repeat(58);
const settle = async () => { for(let index=0;index<50;index++) await Promise.resolve(); };
class Element {
  constructor() { Object.assign(this,{value:'',textContent:'',hidden:false,disabled:false,required:false,files:[],children:[],listeners:new Map()}); this.classList={toggle(){}}; }
  get textContent() { return (this._text || '') + (this.children || []).map(child => child.textContent).join(''); }
  set textContent(value) { this._text=String(value); this.children=[]; }
  set innerHTML(_) { throw new Error('Review must render text, never HTML'); }
  addEventListener(event,handler) { if(!this.listeners.has(event)) this.listeners.set(event,[]);this.listeners.get(event).push(handler); }
  async fire(event) { for(const handler of this.listeners.get(event)||[]) await handler({preventDefault(){}}); await settle(); }
  replaceChildren(...children) { this.children = [...children]; }
  append(...children) { this.children.push(...children); }
  scrollIntoView() {}
}
async function harness(initialChain = null, maxReview = undefined, server = {}) {
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],new Element()]));
  const get = id => { assert.ok(elements.has(id),`Missing DOM element ${id}`);return elements.get(id); };
  get('import-method').value='passphrase';
  const calls = [], copied = [], downloads = [], blobs = new Map();
  const review = {fields:null,error:null,body:'abcdef',confirmLifetime:false,maxReview};
  // Mirrors the signer: v2 keys need and belong to the selected network, and
  // reviews never adopt the export's unsigned network context.
  let serverPublic = server.public ?? null, serverChain = initialChain, derivedFor = null, backupPending = !!server.backupPending, idleLocked = false;
  const backup = {format:'hashstash-private-v1',private_key:privateKey,public_key:publicKey};
  const status = () => ({public_key:serverPublic,chain_id:serverChain,address:serverPublic && serverChain ? addressFor(serverChain) : null,backup_pending:backupPending,idle_locked:idleLocked,
    watch:!serverPublic ? null : serverChain ? {format:'hashstash-watch-v2',public_key:serverPublic,chain_id:serverChain,address:addressFor(serverChain)} : {format:'hashstash-watch-v1',public_key:serverPublic}});
  const refuse = error => ({ok:false,json:async()=>({error})});
  // The session token arrives only in the launch URL fragment.
  const location = {hash:server.launch ?? `#token=${sessionToken}`,pathname:'/',search:''}, replaced = [], storage = server.storage || tabStorage();
  const context = {
    HashstashShares:shares,
    HashstashAmounts:amounts,
    TextDecoder,
    location,
    history:{replaceState(state,title,url){replaced.push(url);location.hash='';}},
    sessionStorage:storage,
    document:{getElementById:get,querySelectorAll:()=>[...elements.values()],createDocumentFragment:()=>new Element(),createElement:()=>Object.assign(new Element(),{click(){downloads.push({name:this.download,blob:blobs.get(this.href)});}})},
    navigator:{clipboard:{writeText:async text=>copied.push(text)}},setTimeout(){},Blob,
    URL:{createObjectURL(blob){const id='blob:'+blobs.size;blobs.set(id,blob);return id;},revokeObjectURL(){}},
    async fetch(url,options={}) {
      const body = options.body ? JSON.parse(options.body) : null;
      calls.push({url,body,options});
      if(url!=='/api/session' && options.headers?.['X-Hashstash-Cold-Token']!==sessionToken) return {ok:false,status:403,json:async()=>({error:'Local session required'})};
      if(['/api/unlock','/api/import','/api/generate','/api/lock'].includes(url)) idleLocked=false;
      if(url==='/api/review' && idleLocked) return refuse('Wallet locked after a period without use; open it again');
      if(url==='/api/review' && review.error) return refuse(review.error);
      if(url==='/api/unlock') {
        if(body.scheme==='hashstash-passphrase-v2') { if(!serverChain) return refuse('Select the network first'); derivedFor=serverChain; }
        else if(body.scheme==='hashstash-passphrase-v1') derivedFor=null;
        else return refuse('Choose a passphrase scheme');
      }
      if(url==='/api/unlock'||url==='/api/import'||url==='/api/generate') serverPublic=publicKey;
      if(url==='/api/import'||url==='/api/generate') derivedFor=null;
      if(['/api/unlock','/api/import','/api/lock','/api/generate'].includes(url)) backupPending=url==='/api/generate';
      if(url==='/api/lock') serverPublic=null;
      if(url==='/api/backup') {
        if(!backupPending) return refuse('No unsaved generated key');
        if(body.saved) backupPending=false; else return {ok:true,json:async()=>({backup})};
      }
      if(url==='/api/network') { if(derivedFor&&derivedFor!==body.chain_id) serverPublic=derivedFor=null; serverChain=body.chain_id; }
      if(url==='/api/review') {
        if (!serverChain) return refuse('Select this signer’s network before reviewing; export network context is unsigned');
        if (body?.format!=='hashstash-unsigned-anchor'||!/^[0-9a-f]{64}$/.test(body.chain_id||'')||serverChain!==body.chain_id)return refuse('Unsigned network context does not match the selected network');
      }
      if(url==='/api/sign' && review.confirmLifetime && body.confirm_lifetime!==true) return refuse('Confirm the long transaction lifetime before signing');
      const data = url === '/api/session' ? {format:'hashstash-cold-v1',max_review_bytes:review.maxReview,idle_lock_seconds:300,...status()} :
        ['/api/unlock','/api/import','/api/network','/api/lock','/api/backup'].includes(url) ? status() :
        url === '/api/generate' ? {...status(),backup} :
        url === '/api/review' ? {...status(),review_token:'review-token',body:review.body,confirm_lifetime:review.confirmLifetime,fields:review.fields || [{label:'Sender',value:addressFor(serverChain)}]} :
        url === '/api/sign' ? {raw:'abcdef',txid:'12'.repeat(32)} : {};
      return {ok:true,json:async()=>data};
    }
  };
  vm.runInNewContext(source,context); await settle();
  // The signer locks a wallet left unused for its idle period.
  const idle = () => { if (serverPublic) { serverPublic = null; derivedFor = null; idleLocked = true; } };
  return {get,calls,copied,downloads,review,location,replaced,storage,idle};
}
async function run() {
  let checks=0;
  {
    // The token is taken from the launch fragment, which then leaves the
    // address bar; the session endpoint never carries it.
    const h=await harness(chainA);
    assert.equal(h.location.hash,'');checks++;
    assert.deepEqual(h.replaced,['/']);checks++;
    assert.equal(h.get('idle-lock-hint').textContent,' An open wallet locks after 5 minutes without use.');checks++;
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    assert.equal(h.calls.find(call=>call.url==='/api/unlock').options.headers['X-Hashstash-Cold-Token'],sessionToken);checks++;
    assert.equal(h.get('wallet').hidden,false);checks++;
    // A reload of the same tab keeps its session without a fragment.
    const reloaded=await harness(chainA,undefined,{launch:'',storage:h.storage});
    reloaded.get('passphrase').value='test';await reloaded.get('unlock-form').fire('submit');
    assert.equal(reloaded.get('wallet').hidden,false,'a reloaded tab reuses its launch session');checks++;
    // A page opened without its launch URL explains where the session comes from.
    const orphan=await harness(chainA,undefined,{launch:'#token=bad'});
    assert.match(orphan.get('message').textContent,/Open the address the signer printed/);checks++;
    orphan.get('passphrase').value='test';await orphan.get('unlock-form').fire('submit');
    assert.match(orphan.get('message').textContent,/no signer session/);checks++;
    assert.equal(orphan.get('wallet').hidden,true);checks++;
  }
  {
    // A wallet the signer locked for inactivity stops being shown.
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.idle();
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.match(h.get('message').textContent,/locked after a period without use/);checks++;
    assert.equal(h.get('wallet').hidden,true);checks++;
    assert.equal(h.get('unlock-panel').hidden,false);checks++;
    // Selecting a network after the idle lock names the right reason.
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.idle();
    await h.get('network-change').fire('click');
    h.get('network-chain').value=chainB;await h.get('network-form').fire('submit');
    assert.match(h.get('message').textContent,/locked after a period without use/);checks++;
    assert.equal(h.get('wallet').hidden,true);checks++;
  }
  {
    const h=await harness();
    assert.equal(h.get('copy-address').disabled,true);checks++;
    assert.equal(h.get('export-public').disabled,true);checks++;
    h.get('passphrase').value=' Exact 雪 passphrase ';
    await h.get('unlock-form').fire('submit');
    assert.equal(h.calls.some(call=>call.url==='/api/unlock'),false,'a v2 passphrase needs the network that salts it');checks++;
    assert.match(h.get('message').textContent,/Set the network first/);checks++;
    h.get('network-chain').value=chainA;await h.get('network-form').fire('submit');
    h.get('passphrase').value=' Exact 雪 passphrase ';
    await h.get('unlock-form').fire('submit');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/unlock').body,{passphrase:' Exact 雪 passphrase ',scheme:'hashstash-passphrase-v2'});checks++;
    assert.equal(h.get('passphrase').value,'');checks++;
    assert.equal(h.get('public-key').textContent,publicKey);checks++;
    assert.equal(h.get('export-public').disabled,false);checks++;
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,false);checks++;
    assert.equal(h.get('network-current').textContent,chainA);checks++;
    assert.equal(h.get('address').textContent,addressFor(chainA));checks++;
    await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token'});checks++;
    assert.equal(h.get('raw').value,'abcdef');checks++;
    // Another network locks the v2 account instead of showing it with a foreign address.
    await h.get('network-change').fire('click');
    h.get('network-chain').value=chainB;await h.get('network-form').fire('submit');
    assert.equal(h.get('wallet').hidden,true);checks++;
    assert.equal(h.get('unlock-panel').hidden,false);checks++;
    assert.match(h.get('message').textContent,/belongs to the network/);checks++;
    assert.equal(h.get('network-current').textContent,chainB);checks++;
  }
  {
    // Without a selected network the signer refuses review; export context is never adopted.
    const h=await harness();
    h.get('import-method').value='private';await h.get('import-method').fire('change');
    h.get('private-key').value=privateKey;await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,true);checks++;
    assert.match(h.get('message').textContent,/Select this signer’s network/);checks++;
    assert.equal(h.get('network-current').textContent,'Not set');checks++;
    await h.get('sign').fire('click');assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,0);checks++;
  }
  {
    // Legacy v1 restores only after an explicit acknowledgement.
    const h=await harness();
    h.get('import-method').value='legacy';await h.get('import-method').fire('change');
    assert.equal(h.get('legacy-fields').hidden,false);checks++;
    assert.equal(h.get('v2-hint').hidden,true);checks++;
    assert.equal(h.get('passphrase').required,true);checks++;
    h.get('passphrase').value='old phrase';await h.get('unlock-form').fire('submit');
    assert.equal(h.calls.some(call=>call.url==='/api/unlock'),false);checks++;
    assert.match(h.get('message').textContent,/existing v1 account/);checks++;
    h.get('legacy-confirm').checked=true;await h.get('unlock-form').fire('submit');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/unlock').body,{passphrase:'old phrase',scheme:'hashstash-passphrase-v1'});checks++;
    assert.equal(h.get('public-key').textContent,publicKey);checks++;
    assert.equal(h.get('legacy-confirm').checked,false,'acknowledgement is per restore');checks++;
    for(const [method,visible] of [['passphrase','v2-hint'],['generate','generate-fields'],['private','private-fields']]) {
      await h.get('lock').fire('click');
      h.get('import-method').value=method;await h.get('import-method').fire('change');
      assert.equal(h.get(visible).hidden,false);checks++;
      assert.equal(h.get('legacy-fields').hidden,true);checks++;
    }
  }
  {
    // A generated key is withheld from funding until its only backup is saved.
    const h=await harness(chainA);
    h.get('import-method').value='generate';await h.get('import-method').fire('change');
    assert.equal(h.get('passphrase').required,false);checks++;
    assert.equal(h.get('private-key').required,false);checks++;
    await h.get('unlock-form').fire('submit');
    assert.ok(h.calls.some(call=>call.url==='/api/generate'));checks++;
    assert.equal(h.get('public-key').textContent,publicKey);checks++;
    assert.equal(h.get('backup-panel').hidden,false);checks++;
    assert.equal(h.get('copy-address').disabled,true);checks++;
    assert.equal(h.get('export-public').disabled,true);checks++;
    await h.get('download-backup').fire('click');
    assert.deepEqual(JSON.parse(await h.downloads[0].blob.text()),{format:'hashstash-private-v1',private_key:privateKey,public_key:publicKey});checks++;
    assert.equal(h.downloads[0].name,'hashstash-private-key.json');checks++;
    await h.get('backup-done').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/backup').body,{saved:true},'the signer records the saved backup');checks++;
    assert.equal(h.get('backup-panel').hidden,true);checks++;
    assert.equal(h.get('export-public').disabled,false);checks++;
    assert.equal(h.get('copy-address').disabled,false);checks++;
    await h.get('lock').fire('click');
    h.get('import-method').value='generate';await h.get('import-method').fire('change');await h.get('unlock-form').fire('submit');
    assert.equal(h.get('backup-panel').hidden,false);checks++;
    await h.get('lock').fire('click');
    assert.equal(h.get('backup-panel').hidden,true,'locking discards the unsaved backup view');checks++;
    await h.get('download-backup').fire('click');assert.equal(h.downloads.length,1);checks++;
  }
  {
    // Reloading the page keeps an unsaved generated key behind its backup gate.
    const h=await harness(chainA,undefined,{public:publicKey,backupPending:true});
    assert.deepEqual(h.calls.find(call=>call.url==='/api/backup').body,{},'the reloaded page refetches the pending backup');checks++;
    assert.equal(h.get('backup-panel').hidden,false);checks++;
    assert.equal(h.get('export-public').disabled,true);checks++;
    await h.get('download-backup').fire('click');
    assert.equal(JSON.parse(await h.downloads[0].blob.text()).private_key,privateKey);checks++;
    const saved=await harness(chainA,undefined,{public:publicKey});
    assert.equal(saved.calls.some(call=>call.url==='/api/backup'),false);checks++;
    assert.equal(saved.get('backup-panel').hidden,true);checks++;
    assert.equal(saved.get('export-public').disabled,false);checks++;
  }
  {
    // Imported keys are network-independent and survive a network change.
    const h=await harness(chainA);
    h.get('import-method').value='private';await h.get('import-method').fire('change');
    h.get('private-key').value=privateKey;await h.get('unlock-form').fire('submit');
    assert.equal(h.get('network-form').hidden,true);checks++;
    assert.equal(h.get('address').textContent,addressFor(chainA));checks++;
    assert.equal(h.get('copy-address').disabled,false);checks++;
    await h.get('copy-address').fire('click');assert.equal(h.copied[0],addressFor(chainA));checks++;
    await h.get('export-public').fire('click');
    const watch=JSON.parse(await h.downloads[0].blob.text());
    assert.deepEqual(watch,{format:'hashstash-watch-v2',address:addressFor(chainA),public_key:publicKey,chain_id:chainA});checks++;
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    await h.get('network-change').fire('click');
    assert.equal(h.get('review-panel').hidden,true);checks++;
    assert.equal(h.get('network-form').hidden,false);checks++;
    assert.ok(h.calls.some(call=>call.url==='/api/cancel'));checks++;
    h.get('network-chain').value=chainB;await h.get('network-form').fire('submit');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/network').body,{chain_id:chainB});checks++;
    assert.equal(h.get('address').textContent,addressFor(chainB));checks++;
    assert.equal(h.get('public-key').textContent,publicKey);checks++;
    await h.get('lock').fire('click');
    assert.equal(h.get('network-current').textContent,chainB);checks++;
    assert.equal(h.get('copy-address').disabled,true);checks++;
  }
  for(const networkContext of [chainB,null,undefined]) {
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:networkContext,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('network-current').textContent,chainA,'unsigned metadata cannot silently switch a selected network');checks++;
    assert.equal(h.get('review-panel').hidden,true);checks++;
    await h.get('sign').fire('click');assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,0,'bad or mismatched network context never yields a signing token');checks++;
  }
  {
    const h=await harness();
    const descriptor=JSON.stringify({format:'hashstash-network-v1',chain_id:chainB});
    h.get('network-file').files=[{size:descriptor.length,text:async()=>descriptor}];
    await h.get('network-file').fire('change');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/network').body,{chain_id:chainB});checks++;
    assert.equal(h.get('network-current').textContent,chainB);checks++;
    assert.equal(h.get('network-file').value,'');checks++;
    const bad=JSON.stringify({format:'hashstash-network-v1',chain_id:chainA,secret:'no'});
    h.get('network-file').files=[{size:bad.length,text:async()=>bad}];
    await h.get('network-file').fire('change');
    assert.equal(h.calls.filter(call=>call.url==='/api/network').length,1);checks++;
    assert.match(h.get('message').textContent,/network file/);checks++;
    h.get('network-chain').value='123';await h.get('network-form').fire('submit');
    assert.equal(h.calls.filter(call=>call.url==='/api/network').length,1);checks++;
  }
  for(const backup of [
    {format:'hashstash-private-v1',private_key:privateKey,public_key:publicKey},
    {secret:privateKey,public:publicKey},
    privateKey
  ]) {
    const h=await harness();
    h.get('import-method').value='private';await h.get('import-method').fire('change');
    assert.equal(h.get('passphrase').required,false);checks++;
    assert.equal(h.get('private-key').required,true);checks++;
    const text=typeof backup==='string' ? backup : JSON.stringify(backup);
    h.get('private-file').files=[{size:text.length,text:async()=>text}];
    await h.get('private-file').fire('change');
    assert.equal(h.get('private-key').value,privateKey);checks++;
    assert.equal(h.calls.filter(call=>call.url==='/api/import').length,0);checks++;
    await h.get('unlock-form').fire('submit');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/import').body,{private_key:privateKey});checks++;
    assert.equal(h.get('private-key').value,'');checks++;
    assert.equal(h.get('public-key').textContent,publicKey);checks++;
  }
  {
    const h=await harness();
    h.get('import-method').value='private';await h.get('import-method').fire('change');
    const text=JSON.stringify({format:'hashstash-private-v1',private_key:privateKey,public_key:'ef'.repeat(32)});
    h.get('private-file').files=[{size:text.length,text:async()=>text}];
    await h.get('private-file').fire('change');await h.get('unlock-form').fire('submit');
    assert.ok(h.calls.some(call=>call.url==='/api/lock'),'mismatched backup locks imported key');checks++;
    assert.equal(h.get('wallet').hidden,true);checks++;
    assert.match(h.get('message').textContent,/does not match/);checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.review.fields = [
      {label:'Action',value:'Redeem'},
      {label:'Shares',value:'95000'},
      {label:'Fee · HASH',value:'1234567890000000000'},
      {label:'Outcome',value:'PASS'},
    ];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    const fields=h.get('review-fields').children[0].children, technical=h.get('review-technical-fields').children[0].children;
    assert.equal(fields[1].textContent,'Withdraw','withdraw terminology does not alter signed Redeem operation');checks++;
    assert.equal(fields[2].textContent,'Amount · stash','withdrawn ownership quantity is visible in primary review');checks++;
    assert.equal(fields[3].textContent,'95','raw signed shares display exactly in stash');checks++;
    assert.equal(fields[3].title,'95000 stash atoms');checks++;
    assert.equal(fields[3].className,'stash-amount');checks++;
    assert.match(fields[5].textContent,/ hash$/,'exact signed fee uses the same monetary unit');checks++;
    assert.equal(amounts.parseAmount(fields[5].textContent),'1234567890000000000','fee display never rounds away signed digits');checks++;
    assert.equal(fields[7].textContent,'PASS');checks++;
    assert.equal(fields.some(field=>/minimum received|minimum shares/i.test(field.textContent)),false,'amount-only orders authorize no minimum output');checks++;
    assert.equal(technical[1].textContent,'95000','technical details retain signed raw STASH atom count');checks++;
    assert.equal(technical[0].textContent,'stash atoms');checks++;
    assert.equal(technical[1].className,'stash-amount');checks++;
    assert.equal(h.get('review-details').hidden,false);checks++;
    assert.equal(h.get('review-details').open,false,'technical share details start collapsed');checks++;
    assert.equal(h.get('review-panel').hidden,false);checks++;
    await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token'},'normalization only changes presentation, not signing token');checks++;
    assert.equal(h.get('review-technical-fields').children.length,0,'signing clears obsolete technical review');checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,false);checks++;
    h.review.fields=[{label:'Shares',value:'95E'}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,true,'malformed raw share field cannot expose signable review');checks++;
    assert.equal(h.get('review-technical-fields').children.length,0);checks++;
    assert.equal(h.get('review-details').hidden,true);checks++;
    await h.get('sign').fire('click');
    assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,0,'failed normalization clears even a prior successful review token');checks++;
    assert.match(h.get('message').textContent,/Review the transaction first/);checks++;
  }
  for(const edit of ['input','file','network-input','network-change','lock','rejected','bad-json','bad-hash']) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Action',value:'Deposit'},{label:'Amount · HASH',value:'1234000'},{label:'Data bytes',value:'2'},{label:'Data hex',value:'00ff'}];
    await h.get('review-form').fire('submit');
    const fields=h.get('review-fields').children[0].children;
    assert.equal(fields[1].textContent,'Deposit');checks++;
    assert.equal(fields[3].textContent,'1234 hash','deposit amount retains every signed hash');checks++;
    assert.ok(!fields.some(field=>/Minimum/.test(field.textContent)),'deposit review has no minimum-output field');checks++;
    h.get('review-details').open=true;
    h.get('review-data').open=true; h.get('review-bytes').open=true;
    if(edit==='input') await h.get('unsigned').fire('input');
    if(edit==='file') await h.get('unsigned-file').fire('change');
    if(edit==='network-input') await h.get('network-chain').fire('input');
    if(edit==='network-change') await h.get('network-change').fire('click');
    if(edit==='lock') await h.get('lock').fire('click');
    if(edit==='rejected') {h.review.error='Transaction expired';await h.get('review-form').fire('submit');}
    if(edit==='bad-json') {h.get('unsigned').value='{';await h.get('review-form').fire('submit');}
    if(edit==='bad-hash') {h.review.fields=[{label:'Amount · HASH',value:'not an integer'}];await h.get('review-form').fire('submit');}
    assert.equal(h.get('review-panel').hidden,true,`${edit} clears review`);checks++;
    assert.equal(h.get('review-details').hidden,true,`${edit} hides technical review`);checks++;
    assert.equal(h.get('review-details').open,false,`${edit} collapses details`);checks++;
    assert.equal(h.get('review-technical-fields').children.length,0,`${edit} clears all prior share fields`);checks++;
    assert.equal(h.get('review-fields').children.length,0,`${edit} clears prior primary fields`);checks++;
    for (const section of ['review-data','review-bytes']) {
      assert.equal(h.get(section).hidden,true,`${edit} hides signed bytes`);checks++;
      assert.equal(h.get(section).open,false,`${edit} collapses signed bytes`);checks++;
    }
    assert.equal(h.get('review-data-hex').textContent,'');checks++;
    assert.equal(h.get('review-message').hidden,true);checks++;
    assert.equal(h.get('review-message-text').textContent,'');checks++;
    assert.equal(h.get('review-body-hex').textContent,'');checks++;
    await h.get('sign').fire('click');
    assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,0,`${edit} invalidates the signing token`);checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Shares',value:'95000'}];
    await h.get('review-form').fire('submit');h.get('review-details').open=true;
    h.review.fields=[{label:'Action',value:'Transfer'},{label:'Amount · HASH',value:'20'}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-details').hidden,true,'a new ordinary transfer has no stale technical details');checks++;
    assert.equal(h.get('review-details').open,false);checks++;
    assert.equal(h.get('review-technical-fields').children[0].children.length,0);checks++;
    assert.equal(h.get('review-fields').children[0].children[3].textContent,'0.02 hash');checks++;
    await h.get('sign').fire('click');
    assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,1,'fresh non-Stash review remains signable');checks++;
  }
  for (const percent of [0, 75, 100]) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.review.fields=[
      {label:'Action',value:'Propose'},
      {label:'Proposal',value:'Parameter'},
      {label:'Parameter',value:'Miner fee share'},
      {label:'Expected miner share',value:'50%'},
      {label:'Proposed miner share',value:`${percent}%`},
      {label:'Expected Revenue share',value:'50%'},
      {label:'Proposed Revenue share',value:`${100-percent}%`},
    ];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    const fields=h.get('review-fields').children[0].children;
    assert.equal(fields[5].textContent,'Miner fee share');checks++;
    assert.equal(fields[7].textContent,'50%');checks++;
    assert.equal(fields[9].textContent,`${percent}%`,'direct percentage is shown exactly, including zero');checks++;
    assert.equal(fields[13].textContent,`${100-percent}%`);checks++;
    assert.equal(h.get('review-details').hidden,true,'fee shares are not confused with STASH ownership');checks++;
    await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token'});checks++;
  }
  for (const exactFee of ['1','2234567890000000000']) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.review.fields=[
      {label:'Action',value:'TransferExact'},
      {label:'Recipient receives · HASH',value:'100'},
      {label:'Fee · HASH',value:exactFee},
      {label:'Total debit · HASH',value:String(100n+BigInt(exactFee))},
    ];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    const fields=h.get('review-fields').children[0].children;
    assert.equal(fields[2].textContent,'Recipient receives'); checks++;
    assert.equal(fields[3].textContent,'0.1 hash'); checks++;
    assert.equal(fields[4].textContent,'Fee'); checks++;
    assert.equal(amounts.parseAmount(fields[5].textContent),exactFee,'offline exact fee preserves every signed digit'); checks++;
    assert.equal(h.get('review-fee-help').hidden,false);checks++;
    assert.match(html,/<p[^>]+id="review-fee-help"[^>]*>[^<]*exact amount[^<]*cannot check the current minimum fee/);checks++;
    assert.equal(fields[6].textContent,'Total debit'); checks++;
    assert.equal(amounts.parseAmount(fields[7].textContent),String(100n+BigInt(exactFee)),'amount plus exact fee is never rounded'); checks++;
    assert.equal(h.get('review-details').hidden,true); checks++;
    await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token'}); checks++;
  }
  for (const bytes of [Buffer.from([0]), Buffer.from(Array.from({length:256},(_,i)=>i)), Buffer.from('<script>alert("data")</script>\0\r\n'), Buffer.alloc(4096,255)]) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.review.fields=[{label:'Action',value:'Transfer'},{label:'Recipient receives · HASH',value:'100'},{label:'Data bytes',value:String(bytes.length)},{label:'Data hex',value:bytes.toString('hex')}];
    h.review.body='aabb00ff'+bytes.toString('hex');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:h.review.body});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,false);checks++;
    assert.equal(h.get('review-data').hidden,false);checks++;
    assert.equal(h.get('review-data').open,false);checks++;
    assert.equal(h.get('review-data-summary').textContent,`Data · ${bytes.length} ${bytes.length===1?'byte':'bytes'} · hex`);checks++;
    assert.equal(h.get('review-data-hex').textContent,bytes.toString('hex'),'every byte is rendered as hex without UTF-8 interpretation');checks++;
    assert.equal(h.get('review-message').hidden,true,'binary or control-containing bytes have no public-message preview');checks++;
    assert.equal(h.get('review-bytes').hidden,false);checks++;
    assert.equal(h.get('review-body-hex').textContent,h.review.body,'complete canonical signing bytes remain available');checks++;
    assert.equal(h.get('review-data-hex').children.length,0);checks++;
    assert.equal(h.get('review-fields').children[0].children.length,4,'data stays separate from decoded action fields');checks++;
    await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token'});checks++;
    assert.equal(h.get('review-data-hex').textContent,'');checks++;
    assert.equal(h.get('review-body-hex').textContent,'');checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    const message='<script>alert("literal")</script>\r\n\t雪 🌞', bytes=Buffer.from(message);
    h.review.fields=[{label:'Data bytes',value:String(bytes.length)},{label:'Data hex',value:bytes.toString('hex')}];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-message').hidden,false);checks++;
    assert.equal(h.get('review-message-text').textContent,message,'public UTF-8 is displayed exactly as literal text');checks++;
    assert.equal(h.get('review-message-text').children.length,0,'message text is never parsed as HTML');checks++;
    assert.equal(h.get('review-data-hex').textContent,bytes.toString('hex'),'exact raw bytes remain available beside readable text');checks++;
    h.review.fields=[{label:'Action',value:'Transfer'}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-message').hidden,true,'a replacement transaction clears the public message');checks++;
    assert.equal(h.get('review-message-text').textContent,'');checks++;
    h.review.fields=[{label:'Data bytes',value:String(bytes.length)},{label:'Data hex',value:bytes.toString('hex')}];
    await h.get('review-form').fire('submit');
    await h.get('sign').fire('click');
    assert.equal(h.get('review-message').hidden,true,'signing clears the message with the approval');checks++;
    assert.equal(h.get('review-message-text').textContent,'');checks++;
  }
  for(const bytes of [Buffer.from([0xc0,0xaf]),Buffer.from('  \r\n\t'),Buffer.from('text\u0085hidden')]) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.review.fields=[{label:'Data bytes',value:String(bytes.length)},{label:'Data hex',value:bytes.toString('hex')}];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-message').hidden,true,'invalid UTF-8, blank data and control characters remain hex-only');checks++;
    assert.equal(h.get('review-data-hex').textContent,bytes.toString('hex'));checks++;
  }
  for (const malformed of [
    {count:'2',hex:'00'}, {count:'1',hex:'0'}, {count:'0',hex:'00'},
    {count:'1',hex:'<img src=x onerror=alert(1)>'}, {count:'1',hex:'zz'},
    {count:'01',hex:'00'}, {count:'1',hex:''}, {count:'',hex:'00'},
    {count:'1',hex:'00',body:'<script>bad()</script>'},
  ]) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    h.review.fields=[{label:'Data bytes',value:malformed.count},{label:'Data hex',value:malformed.hex}];
    h.review.body=malformed.body||'abcdef';
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,true,'invalid byte previews cannot expose signable approval');checks++;
    await h.get('sign').fire('click');
    assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,0,'invalid data invalidates any previous approval');checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Data bytes',value:'1'},{label:'Data hex',value:'ff'}];
    await h.get('review-form').fire('submit');
    h.review.fields=[{label:'Action',value:'Transfer'},{label:'Recipient',value:'<img src=x onerror=alert(1)>'}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-data').hidden,true,'a transaction without data removes the previous preview');checks++;
    assert.equal(h.get('review-data-hex').textContent,'');checks++;
    assert.equal(h.get('review-fields').children[0].children[3].textContent,'<img src=x onerror=alert(1)>','untrusted review strings remain literal text');checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Parameter',value:'Minimum difficulty'},{label:'Change',value:'Double'},
      {label:'Expected minimum work · hashes',value:'4295032833'},
      {label:'Expected compact target',value:'1d00ffff'},
      {label:'Proposed minimum work · hashes',value:'8590065666'},
      {label:'Proposed compact target',value:'1c7fff80'}];
    await h.get('review-form').fire('submit');
    const fields=h.get('review-fields').children[0].children, technical=h.get('review-technical-fields').children[0].children;
    assert.equal(fields[1].textContent,'Minimum difficulty');checks++;
    assert.equal(fields[3].textContent,'Double');checks++;
    assert.equal(fields[5].textContent,'0.000000004295032833 EH','physical work retains every hash in an exact EH amount');checks++;
    assert.equal(fields[7].textContent,'0.000000008590065666 EH');checks++;
    assert.equal(technical[1].textContent,'1d00ffff');checks++;
    assert.equal(technical[3].textContent,'1c7fff80');checks++;
    assert.equal(h.get('review-details').hidden,false);checks++;
    await h.get('sign').fire('click');assert.equal(h.calls.filter(c=>c.url==='/api/sign').length,1);checks++;
  }
  {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Amount · HASH',value:'1000000'},{label:'Shares',value:'1000'}];
    await h.get('review-form').fire('submit');
    const fields=h.get('review-fields').children[0].children;
    assert.equal(fields[0].textContent,'Amount');checks++;
    assert.equal(fields[1].textContent,'1000 hash');checks++;
    assert.equal(fields[2].textContent,'Amount · stash');checks++;
    assert.equal(fields[3].textContent,'1','cold review converts the signed quantity exactly to stash');checks++;
    assert.equal(shares.parseAmount(fields[3].textContent),h.review.fields[1].value);checks++;
  }
  {
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Recipient 1',value:'first-full-address'},{label:'Payment 1 · HASH',value:'1000000000000000001'},{label:'Recipient 2',value:'second-full-address'},{label:'Payment 2 · HASH',value:'2'},{label:'Total grant · HASH',value:'1000000000000000003'},{label:'Fee · HASH',value:'7'}];
    await h.get('review-form').fire('submit');const fields=h.get('review-fields').children[0].children;
    for(const [index,value] of [[1,'first-full-address'],[3,'1000000000000000.001 hash'],[5,'second-full-address'],[7,'0.002 hash'],[9,'1000000000000000.003 hash'],[11,'0.007 hash']]){assert.equal(fields[index].textContent,value);checks++;}
  }
  for (const raw of ['0', '1', '1000000000000000001', '123456789123456789123456789', ((1n << 512n) - 1n).toString()]) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=['Amount', 'Recipient receives', 'Fee', 'Total debit', 'Payment', 'Support', 'Grant'].map(label => ({label:label+' · HASH',value:raw}));
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,false);checks++;
    const fields=h.get('review-fields').children[0].children;
    for (let index=1;index<fields.length;index+=2) {
      assert.match(fields[index].textContent,/^\d+(?:\.\d{1,18})? hash$/,'every approval amount is a plain exact hash decimal');checks++;
      assert.equal(amounts.parseAmount(fields[index].textContent),raw,'approval cannot round amounts or fees');checks++;
      assert.equal(fields[index].title,fields[index].textContent);checks++;
    }
    assert.equal(h.get('review-body-hex').textContent,'abcdef','changing display units leaves signing bytes intact');checks++;
    await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token'});checks++;
    assert.equal(h.calls.every(call=>call.url.startsWith('/api/')),true,'exact conversion adds no network dependency');checks++;
  }
  for (const raw of ['-1', '1000000000000000 hash', '1.1', '1e18']) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Amount · HASH',value:raw}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,true,'review API still requires nonnegative integer hash atoms');checks++;
    await h.get('sign').fire('click');
    assert.equal(h.calls.some(call=>call.url==='/api/sign'),false);checks++;
  }
  {
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Parameter',value:'Rest period'},{label:'Expected value',value:'18446744073709551615'},{label:'Proposed value',value:'9007199254740993'}];
    await h.get('review-form').fire('submit');
    assert.ok(h.get('review-fields').textContent.includes('18446744073709551615'));checks++;
    assert.ok(h.get('review-fields').textContent.includes('9007199254740993'));checks++;
  }
  for(const margin of ['0.00%','150.01%','184467440737095516.15%']) {
    const h=await harness(chainA);
    h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    h.review.fields=[{label:'Parameter',value:'PASS margin'},{label:'Expected margin',value:'2.50%'},{label:'Proposed margin',value:margin}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-fields').children[0].children[5].textContent,margin);checks++;
    assert.equal(h.get('review-details').hidden,true);checks++;
  }
  {
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    const data=Buffer.from('hashstash.mail/2\n{}').toString('hex');
    h.review.fields=[{label:'Action',value:'Transfer'},{label:'Recipient',value:addressFor(chainA)},{label:'Amount · HASH',value:'1000000000000'},{label:'Data bytes',value:String(data.length/2)},{label:'Data hex',value:data}];
    await h.get('review-form').fire('submit');
    assert.match(h.get('review-fields').textContent,/cannot verify their plaintext/);checks++;
    assert.ok(h.get('review-fields').textContent.includes(addressFor(chainA)));checks++;
    assert.equal(h.get('review-data-hex').textContent,data);checks++;
    assert.equal(h.get('review-message').hidden,true,'encrypted mail envelope never becomes a public-message preview');checks++;
  }
  for (const limit of [undefined, 96*1024*1024]) {
    // Unsigned imports may exceed the 128 KiB control limit, up to the signer's
    // finite (configurable) review limit; larger files are never read.
    const h=await harness(chainA,limit),maximum=limit||64*1024*1024,source=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'ab'.repeat(256*1024)});
    h.get('unsigned-file').files=[{size:source.length,text:async()=>source}];
    await h.get('unsigned-file').fire('change');
    assert.equal(h.get('unsigned').value,source,'unsigned imports may exceed the former 128KiB file ceiling');checks++;
    assert.equal(h.get('unsigned-file').value,'');checks++;
    let read=false;h.get('unsigned').value='';h.get('unsigned-file').files=[{size:maximum,text:async()=>{read=true;return source;}}];
    await h.get('unsigned-file').fire('change');
    assert.equal(read,true,'a file at the limit is accepted');checks++;
    read=false;h.get('unsigned').value='';h.get('unsigned-file').files=[{size:maximum+1,text:async()=>{read=true;return source;}}];
    await h.get('unsigned-file').fire('change');
    assert.equal(read,false,'a file over the review limit is never read');checks++;
    assert.equal(h.get('unsigned').value,'');checks++;
    assert.match(h.get('message').textContent,new RegExp(`${maximum}-byte review limit`));checks++;
  }
  {
    // Long lifetimes need an explicit acknowledgement before the sign request.
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    h.review.confirmLifetime=true;
    h.review.fields=[{label:'Valid for · blocks',value:'18446744073709551615'},{label:'Lifetime warning',value:'Valid for 18446744073709551615 blocks'}];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-lifetime').hidden,false);checks++;
    assert.equal(h.get('lifetime-confirm-text').textContent,'I accept that this signature stays valid for 18446744073709551615 blocks');checks++;
    await h.get('sign').fire('click');
    assert.equal(h.calls.filter(call=>call.url==='/api/sign').length,0,'unconfirmed long lifetime sends no sign request');checks++;
    assert.match(h.get('message').textContent,/Confirm the long transaction lifetime/);checks++;
    assert.equal(h.get('review-panel').hidden,false,'the review stays available for confirmation');checks++;
    h.get('lifetime-confirm').checked=true;await h.get('sign').fire('click');
    assert.deepEqual(h.calls.find(call=>call.url==='/api/sign').body,{review_token:'review-token',confirm_lifetime:true});checks++;
    assert.equal(h.get('raw').value,'abcdef');checks++;
    assert.equal(h.get('review-lifetime').hidden,true);checks++;
    assert.equal(h.get('lifetime-confirm').checked,false);checks++;
    h.review.fields=[{label:'Valid for · blocks',value:'bad'}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-panel').hidden,true,'a malformed lifetime cannot be acknowledged');checks++;
    h.review.confirmLifetime=false;h.review.fields=[{label:'Valid for · blocks',value:'2'}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-lifetime').hidden,true);checks++;
  }
  for (const [rationale,title,warning] of [
    ['Matches the description hash','Proposal rationale',true],
    ['Does not match the description hash','Attached text · not the committed rationale',false],
    ['Matches the hash but is not publishable plain text','Attached text · not the committed rationale',false],
  ]) {
    // Proposal text counts as the rationale only when its hash is the signed commitment.
    const h=await harness(chainA);h.get('passphrase').value='test';await h.get('unlock-form').fire('submit');
    const bytes=Buffer.from('Fund the shared explorer');
    h.review.fields=[{label:'Action',value:'Propose'},{label:'Description hash',value:'00'.repeat(32)},{label:'Rationale',value:rationale},{label:'Data bytes',value:String(bytes.length)},{label:'Data hex',value:bytes.toString('hex')}];
    h.get('unsigned').value=JSON.stringify({format:'hashstash-unsigned-anchor',chain_id:chainA,body:'abcdef'});
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-message').hidden,false);checks++;
    assert.equal(h.get('review-message-title').textContent,title);checks++;
    assert.equal(h.get('review-rationale-warning').hidden,warning);checks++;
    assert.ok(h.get('review-fields').textContent.includes(rationale));checks++;
    h.review.fields=[{label:'Action',value:'Transfer'},{label:'Data bytes',value:String(bytes.length)},{label:'Data hex',value:bytes.toString('hex')}];
    await h.get('review-form').fire('submit');
    assert.equal(h.get('review-message-title').textContent,'Public message','ordinary data keeps the public-message label');checks++;
    assert.equal(h.get('review-rationale-warning').hidden,true);checks++;
  }
  assert.ok(html.includes('Anchor ancestry and expiry are checked by the receiving node.'));checks++;
  assert.ok(html.includes('Network context is not signed.'));checks++;
  assert.ok(html.includes('use a separate key there'));checks++;
  assert.match(html, /id="import-method"><option value="private">Private key/);checks++;
  assert.match(html, /<option value="legacy">Legacy v1 passphrase · restore only<\/option>/);checks++;
  assert.ok(html.includes('unsalted brain-wallet derivation'));checks++;
  assert.ok(html.includes('entering it here derives a different account'));checks++;
  console.log(`Cold UI: ${checks} behavior assertions passed.`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
