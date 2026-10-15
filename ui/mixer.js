(function(root,factory){'use strict';const api=factory(root);if(typeof module==='object'&&module.exports)module.exports=api;else root.HashstashMixer=api;})(globalThis,function(root){
  'use strict';
  const FIELDS=['version','chain_id','public_key','denomination_atoms','service_fee_bps','payout_fee_cap_atoms','minimum_deposits','confirmations','timeout_seconds','max_addresses'];
  const amount=v=>{if(typeof v!=='string'||!/^[1-9][0-9]{0,153}$/.test(v))throw Error('Invalid mixer amount.');const n=BigInt(v);if(n>((1n<<512n)-1n))throw Error('Mixer amount exceeds the protocol limit.');return n;};
  const id=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
  const validPublic=v=>id(v)&&root.HashstashNoble?.validPublic(Uint8Array.from(v.match(/../g),pair=>parseInt(pair,16)))===true;
  async function validate(descriptor,{chain_id,encodeAddress}){
    const t=descriptor?.terms;
    if(!t||Object.keys(t).length!==FIELDS.length||FIELDS.some(k=>!Object.hasOwn(t,k))||t.version!==1||t.chain_id!==chain_id||!id(t.public_key)||!id(descriptor.terms_id))throw Error('Mixer terms belong to another network or are invalid.');
    if(!validPublic(t.public_key))throw Error('Invalid mixer public key.');
    amount(t.denomination_atoms);amount(t.payout_fee_cap_atoms);
    for(const [k,min,max] of [['service_fee_bps',0,1000],['minimum_deposits',2,100],['confirmations',2,100],['timeout_seconds',60,2592000],['max_addresses',1,8]])if(!Number.isSafeInteger(t[k])||t[k]<min||t[k]>max)throw Error('Invalid mixer limits.');
    const canonical=JSON.stringify(Object.fromEntries(Object.keys(t).sort().map(k=>[k,t[k]])));
    const digest=Array.from(new Uint8Array(await root.crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical))),b=>b.toString(16).padStart(2,'0')).join('');
    if(digest!==descriptor.terms_id||descriptor.address!==encodeAddress(t.public_key))throw Error('Mixer terms do not match its address or identifier.');
    return Object.freeze({terms:Object.freeze({...t}),terms_id:digest,address:descriptor.address});
  }
  function plan(descriptor,deposit,addresses,{decodeAddress,sender}){
    const t=descriptor.terms,A=amount(deposit),D=amount(t.denomination_atoms),cap=amount(t.payout_fee_cap_atoms),service=(D*BigInt(t.service_fee_bps)+9999n)/10000n;
    if(!Array.isArray(addresses)||!addresses.length||addresses.length>t.max_addresses)throw Error(`Enter one to ${t.max_addresses} receiving addresses.`);
    addresses=addresses.map(a=>String(a).toLowerCase());
    const keys=addresses.map(a=>decodeAddress(a));
    if(keys.some(k=>!validPublic(k)))throw Error('Invalid receiving public key.');
    if(new Set(keys).size!==keys.length||keys.some(k=>k===sender||k===t.public_key))throw Error('Use different receiving addresses, separate from the depositing account and mixer.');
    const slots=A>cap?(A-cap)/(D+service+cap):0n;
    const count=Number(slots<BigInt(addresses.length)?slots:BigInt(addresses.length));
    if(count<1)throw Error('Deposit cannot cover one payout, its service fee and the network-fee allowance.');
    const body=JSON.stringify({terms:descriptor.terms_id,addresses});
    if(new TextEncoder().encode(body).length>768)throw Error('Address list exceeds the encrypted message limit.');
    return {count,payout:String(BigInt(count)*D),service:String(BigInt(count)*service),network_cap:String(BigInt(count+1)*cap),body,subject:'hashstash.mix/1'};
  }
  function create({getContext,encodeAddress,decodeAddress,parseAmount,formatAmount,prepareDeposit,createAddresses,document=root.document,fetch=root.fetch}){
    const $=id=>document.getElementById(id),form=$('mixer-form');let descriptor=null,sequence=0,scope='',visible=false;
    const say=(text,bad=false)=>{$('mixer-feedback').textContent=text;$('mixer-feedback').classList.toggle('error',bad);};
    const context=()=>getContext(),stamp=()=>JSON.stringify([context().chain_id,context().key,context().wallet]);
    function render(){
      const c=context();$('mixer-prepare').disabled=!c.ready||!c.key||!descriptor;
      $('mixer-generate').disabled=!c.ready||!c.key||!createAddresses;
      $('mixer-state').textContent=!c.ready?'Node disconnected.':descriptor?'Custodian selected':'No mixer selected.';
      $('mixer-address').textContent=descriptor?.address||'';
      const terms=$('mixer-terms');terms.replaceChildren();
      if(descriptor){const t=descriptor.terms;for(const [label,value] of [
        ['Payout per address',formatAmount(t.denomination_atoms)],['Service fee per payout',`${t.service_fee_bps/100}%`],
        ['Maximum network fee per transaction',formatAmount(t.payout_fee_cap_atoms)],['Minimum depositing accounts',String(t.minimum_deposits)],
        ['Confirmations',String(t.confirmations)],['Refund timeout after acceptance',`${t.timeout_seconds} scheduled seconds`]
      ]){const row=document.createElement('div'),term=document.createElement('dt'),detail=document.createElement('dd');term.textContent=label;detail.textContent=value;row.appendChild(term);row.appendChild(detail);terms.appendChild(row);}}
    }
    async function load(){
      const token=++sequence,chain=context().chain_id;descriptor=null;render();
      if(!context().ready)return;
      try{
        const response=await fetch('/mixer-config.json',{cache:'no-store',credentials:'omit',redirect:'error'});
        if(!response.ok)throw Error('No mixer advertised by this node.');
        const raw=await response.text();if(raw.length>8192)throw Error('Invalid mixer configuration.');
        const value=await validate(JSON.parse(raw),{chain_id:chain,encodeAddress});
        if(token!==sequence||context().chain_id!==chain)return;descriptor=value;say('');render();
      }catch(e){if(token===sequence){say(e.message,true);render();}}
    }
    $('mixer-reload').addEventListener('click',load);
    $('mixer-generate').addEventListener('click',async()=>{
      try{const n=Number(form.elements.count.value);if(!Number.isInteger(n)||n<1||n>8)throw Error('Choose one to eight receiving wallets.');const chain=context().chain_id;const list=await createAddresses(n);if(context().chain_id!==chain)throw Error('Network changed. Your saved wallets remain available in Wallet.');form.elements.addresses.value=list.join('\n');say('Receiving wallets saved. Back up their keys in Wallet before depositing.');}
      catch(e){say(e.message,true);}
    });
    form.addEventListener('submit',async event=>{
      event.preventDefault();const start=stamp();try{
        if(!context().ready||!context().key)throw Error('Select a wallet and connect to a node before mixing.');
        if(!descriptor)throw Error('Load the mixer terms first.');
        if(!form.elements.trust.checked)throw Error('Confirm that you trust this custodian with the funds and destination list.');
        const draft=JSON.stringify([form.elements.amount.value,form.elements.addresses.value,form.elements.trust.checked]);
        const inputAmount=form.elements.amount.value,terms=descriptor,addresses=form.elements.addresses.value.trim().split(/\s+/u),deposit=parseAmount(inputAmount);
        const p=plan(terms,deposit,addresses,{decodeAddress,sender:context().key});
        // Reload public terms before preparing, without sending destination addresses.
        await load();if(start!==stamp()||descriptor?.terms_id!==terms.terms_id||draft!==JSON.stringify([form.elements.amount.value,form.elements.addresses.value,form.elements.trust.checked]))throw Error('Wallet or mixer terms changed. Review again.');
        prepareDeposit({recipient:terms.address,amount:inputAmount,subject:p.subject,body:p.body});
        say(`Prepared ${p.count} payouts · ${formatAmount(p.payout)} total. Review the deposit in Send & receive.`);
      }catch(e){say(e.message,true);}
    });
    return Object.freeze({open(value){const entering=value&&!visible;visible=value;if(entering)return load();},update(){const next=JSON.stringify([context().chain_id,context().key]);if(next!==scope){scope=next;sequence++;descriptor=null;form.elements.addresses.value='';form.elements.trust.checked=false;say('');if(visible)load();}render();}});
  }
  return Object.freeze({validate,plan,create});
});
