(function(root,factory){'use strict';const api=factory(root);if(typeof module==='object'&&module.exports)module.exports=api;else root.HashstashMail=api;})(globalThis,function(root){
  'use strict';const validId=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v),validCursor=v=>typeof v==='string'&&/^\d{1,20}:\d{1,20}$/.test(v);
  const compareCursor=(a,b)=>{const x=a.split(':').map(BigInt),y=b.split(':').map(BigInt);return x[0]===y[0]?(x[1]>y[1]?1:x[1]<y[1]?-1:0):x[0]>y[0]?1:-1;};
  // One localStorage write commits the ciphertext rows and their scan cursor
  // together. Persist no decrypted content or secret keys. A full cache keeps
  // its previous complete checkpoint rather than discarding older messages.
  const CACHE_PREFIX='hashstash-mail-scan-3:',CACHE_LIMIT=256,CACHE_BYTES=2*1024*1024,SCAN_BUDGET=100;
  function cacheEntry(entry){
    const position=entry.position??entry.tx_position??0;
    if(!validId(entry.txid)||!Number.isSafeInteger(entry.height)||entry.height<0||!Number.isSafeInteger(position)||position<0||typeof entry.raw!=='string'||entry.raw.length>CACHE_BYTES||!/^(?:[0-9a-f]{2})+$/.test(entry.raw))throw Error('Invalid cached mail.');
    // Recover sender, nonce and ciphertext from the verified signed record on
    // restore. Do not persist a second, independently editable copy of them.
    return {txid:entry.txid,raw:entry.raw,height:entry.height,position};
  }
  function createCache(options={}){
    let storage;try{storage=Object.hasOwn(options,'storage')?options.storage:root.localStorage;}catch(_){}
    const cacheKey=(chain,key)=>{if(!validId(chain)||!validId(key))throw Error('Invalid mail cache identity.');return CACHE_PREFIX+chain+':'+key;};
    const validate=value=>{
      if(!value||value.version!==3||!validCursor(value.cursor)||!validId(value.anchor)||!Number.isSafeInteger(value.scanned)||value.scanned<0||!Array.isArray(value.entries)||value.entries.length>CACHE_LIMIT)throw Error('Invalid cached mail.');
      const entries=value.entries.map(cacheEntry);if(new Set(entries.map(e=>e.txid)).size!==entries.length||entries.some(e=>compareCursor(`${e.height}:${e.position}`,value.cursor)>0))throw Error('Invalid cached mail.');
      return {version:3,cursor:value.cursor,anchor:value.anchor,scanned:value.scanned,entries};
    };
    return Object.freeze({
      read(chain,key){
        try{if(!storage)throw Error();const text=storage.getItem(cacheKey(chain,key));if(text==null)return {value:null};if(text.length>CACHE_BYTES)throw Error();return {value:validate(JSON.parse(text))};}
        catch(_){return {value:null,error:'Local mail cache is unavailable or invalid; scanning from the beginning for this visit.'};}
      },
      write(chain,key,value){
        try{if(!storage)throw Error();const encoded=JSON.stringify(validate({...value,version:3}));if(encoded.length>CACHE_BYTES)throw Error();storage.setItem(cacheKey(chain,key),encoded);return {saved:true};}
        catch(_){return {saved:false,error:'Local mail storage is full or unavailable. Later progress is kept only for this visit; the last complete checkpoint is preserved.'};}
      },
      clear(chain,key){try{if(!storage||typeof storage.removeItem!=='function')throw Error();storage.removeItem(cacheKey(chain,key));return {cleared:true};}catch(_){return {cleared:false,error:'This browser could not clear its local mail cache.'};}}
    });
  }
  function create({rpc,getIdentity,recipientKey,decrypt,verifySigned,encodeAddress,onDraftChange=()=>{},document=root.document,location=root.location,cache=createCache()}){
    const $=id=>document.getElementById(id),form=$('mail-form');let context={},sequence=0,prepared=null,preparing=null,checkedTip='',verifiedTip='',cursor=null,anchor=null,opened=new Map(),lastWallet='',loading=false,paused=false,scanned=0,visibleCount=50,rendered='',cacheLoaded=false,restoreEntries=[],storageNote='';
    const active=()=>location.hash.split('?')[0]==='#mail',eligible=()=>active()&&context.ready&&context.available&&context.key&&context.can_decrypt;
    const add=(p,t,c,text)=>{const n=document.createElement(t);n.className=c;if(text!==undefined)n.textContent=text;p.appendChild(n);return n;};
    const identity=()=>getIdentity(),yieldTask=()=>new Promise(resolve=>root.setTimeout(resolve,0));
    const draftId=()=>JSON.stringify([identity(),form.elements.recipient.value,recipientKey(form.elements.recipient.value),form.elements.subject.value,form.elements.message.value]);
    function invalidate(){prepared=null;preparing=null;}
    function error(message){$('mail-error').textContent=message;$('mail-error').hidden=!message;}
    function resetScan(){opened.clear();cursor=null;anchor=null;checkedTip='';verifiedTip='';scanned=0;visibleCount=50;rendered='';$('mail-list').replaceChildren();error('');}
    function blank(){invalidate();resetScan();paused=false;cacheLoaded=false;restoreEntries=[];storageNote='';}
    function render(){
      const verified=verifiedTip===context.tip;
      $('mail-empty').hidden=verified&&opened.size>0;
      $('mail-empty').textContent=!context.key?'Select a wallet.':!context.can_decrypt?'Watch-only · import the private key to read mail.':!context.available?'Mail unavailable.':loading?'Checking messages…':paused?'Scan paused.':!verified&&checkedTip?'Verifying latest blocks…':'No messages found.';
      $('mail-scan-status').textContent=context.key&&context.can_decrypt?(loading?`Scanning · ${scanned} checked · ${opened.size} found`:paused?`Paused · ${scanned} checked`:!verified&&checkedTip?'Verification pending':verified?`${scanned} checked · ${opened.size} found`:''):'';
      if(context.key&&context.can_decrypt&&storageNote)$('mail-scan-status').textContent+=' · '+storageNote;
      $('mail-more').hidden=!context.can_decrypt||!context.key||(!loading&&!paused);$('mail-more').textContent=paused?'Continue scan':'Pause scan';
      $('mail-show-more').hidden=!verified||opened.size<=visibleCount;
      if($('mail-clear-cache'))$('mail-clear-cache').disabled=!context.key||!context.can_decrypt;
      if(!active())return;
      const entries=verified?[...opened.values()].sort((a,b)=>b.entry.height-a.entry.height||(b.entry.position??b.entry.tx_position??0)-(a.entry.position??a.entry.tx_position??0)):[];
      const signature=JSON.stringify([lastWallet,context.height,visibleCount,entries.map(({entry,clear})=>[entry.txid,entry.height,entry.position,clear])]);if(signature===rendered)return;
      rendered=signature;const list=$('mail-list');list.replaceChildren();
      for(const {entry,clear} of entries.slice(0,visibleCount)){
        const row=add(list,'article','panel mail-message'),sender=entry.sender_public_key||entry.sender,outgoing=sender===context.key;
        const peer=encodeAddress(outgoing?clear.recipient:sender),heading=add(row,'div','section-heading');
        add(heading,'strong','',outgoing?'Sent':'Received');const link=add(heading,'a','small-link',`Block ${entry.height}`);link.href='#explorer?tx='+entry.txid;
        const peerLine=add(row,'p','mail-peer');add(peerLine,'span','',outgoing?'To: ':'From: ');add(peerLine,'span','',peer);
        const confirmations=Number.isSafeInteger(context.height)?Math.max(0,context.height-entry.height+1):entry.confirmations??0;add(row,'p','field-help',`${confirmations} confirmations`);
        const copy=add(row,'div','mail-content');add(copy,'h3','mail-subject',clear.subject);add(copy,'p','mail-body',clear.body);
      }
    }
    async function load(){
      if(!eligible()||loading||paused)return;
      loading=true;const version=++sequence,stamp=lastWallet;let restarted=false,checkedThisPass=0;
      if(!cacheLoaded){cacheLoaded=true;const saved=cache.read(context.chain_id,context.key);storageNote=saved.error||'';if(saved.value){cursor=saved.value.cursor;anchor=saved.value.anchor;scanned=saved.value.scanned;restoreEntries=saved.value.entries;}}
      const current=()=>version===sequence&&stamp===lastWallet&&eligible()&&!paused;render();
      try{
        do{
          let result;
          try{result=await rpc('explorer_mail',{limit:50,...(cursor?{after:cursor,anchor}:{})});}
          catch(e){
            if(!current())return;
            if(String(e.message).includes('Mail scan anchor is no longer canonical')&&!restarted){resetScan();restoreEntries=[];const cleared=cache.clear(context.chain_id,context.key);storageNote=cleared.error||'';restarted=true;render();continue;}
            throw e;
          }
          if(!current())return;
          if(result.chain_id!==context.chain_id)throw Error('Mail belongs to a different network.');
          if(result.ready!==true||!validId(result.tip)||!validId(result.anchor)||result.anchor!==result.tip||!Number.isSafeInteger(result.indexed_height)||result.indexed_height<0||!Array.isArray(result.messages)||result.messages.length>50||!validCursor(result.scan_cursor))throw Error('Invalid shared mail response.');
          if(result.tip!==context.tip||(Number.isSafeInteger(context.height)&&result.indexed_height!==context.height))throw Error('Mail index changed. Refreshing again shortly.');
          if(result.next_cursor!=null&&(!validCursor(result.next_cursor)||result.next_cursor!==result.scan_cursor))throw Error('Invalid mail cursor.');
          if(cursor&&(compareCursor(result.scan_cursor,cursor)<0||(result.next_cursor&&compareCursor(result.scan_cursor,cursor)===0)))throw Error('Mail scan did not advance.');
          if(result.next_cursor&&result.messages.length===0)throw Error('Mail scan did not advance.');
          const found=[],restoreCount=restoreEntries.length,entries=[...restoreEntries,...result.messages];let restoreFailed=false;
          for(let index=0;index<entries.length;index++){
            const source=entries[index],restoring=index<restoreCount,position=source.position??source.tx_position??0;
            if(!validId(source.txid)||!Number.isSafeInteger(source.height)||source.height<0||source.height>result.indexed_height||!Number.isSafeInteger(position)||position<0||compareCursor(`${source.height}:${position}`,result.scan_cursor)>0)throw Error('Invalid shared mail response.');
            if(!current())return;
            let signed;
            try{
              const expected={chain_id:context.chain_id,txid:source.txid};
              if(!restoring){
                const sender=source.sender_public_key||source.sender;
                if(!validId(sender)||!/^\d{1,20}$/.test(String(source.nonce))||typeof source.data_hex!=='string')throw Error();
                Object.assign(expected,{sender,nonce:String(source.nonce),data_hex:source.data_hex});
                if(source.operation!==undefined)expected.operation=source.operation;
              }
              signed=verifySigned(source.raw,expected);
            }catch(_){
              if(restoring){restoreFailed=true;break;}
              throw Error('Mail transaction signature or details could not be verified.');
            }
            const sender=signed.sender,entry={txid:signed.txid,raw:source.raw,sender_public_key:sender,nonce:signed.nonce,data_hex:signed.data_hex,height:source.height,position};
            // Sender authentication is mandatory even for another user's mail.
            // Decryption failure alone is normal: most envelopes are not ours.
            try{
              root.HashstashMailCrypto.parse(entry.data_hex);
              const clear=await decrypt(entry.data_hex,{chain_id:context.chain_id,sender,nonce:String(entry.nonce)},identity());
              if(!current())return;
              if(validId(clear?.recipient)&&typeof clear.subject==='string'&&typeof clear.body==='string'&&(sender===context.key||clear.recipient===context.key))found.push({entry,clear});else if(index<restoreCount)throw Error('Cached mail authentication failed.');
            }catch(_){if(!current())return;if(index<restoreCount){restoreFailed=true;break;}}
            if((index+1)%4===0){await yieldTask();if(!current())return;}
          }
          if(!current())return;
          if(restoreFailed){resetScan();restoreEntries=[];const cleared=cache.clear(context.chain_id,context.key);storageNote=cleared.error||'';render();continue;}
          // Commit the cursor and authenticated messages together. A cancelled
          // page is retried rather than silently skipping its remaining mail.
          for(const value of found)opened.set(value.entry.txid,value);
          restoreEntries=[];verifiedTip=result.tip;scanned+=result.messages.length;checkedThisPass+=result.messages.length;cursor=result.scan_cursor;anchor=result.anchor;error('');
          const saved=cache.write(context.chain_id,context.key,{cursor,anchor,scanned,entries:[...opened.values()].map(v=>v.entry)});storageNote=saved.error||'';
          if(result.next_cursor==null){checkedTip=context.tip;break;}
          if(checkedThisPass>=SCAN_BUDGET){paused=true;render();break;}
          render();await yieldTask();
        }while(current());
      }catch(e){if(current()){checkedTip=context.tip;verifiedTip='';error(e.message);}}
      finally{if(version===sequence){loading=false;render();}}
    }
    form.addEventListener('input',()=>{invalidate();onDraftChange();});
    $('mail-refresh').addEventListener('click',()=>{sequence++;loading=false;paused=false;checkedTip='';load();});
    $('mail-more').addEventListener('click',()=>{paused=!paused;if(paused){sequence++;loading=false;render();}else load();});
    $('mail-show-more').addEventListener('click',()=>{visibleCount+=50;render();});
    function clearCache(){
      if(!context.key)return;sequence++;loading=false;const result=cache.clear(context.chain_id,context.key);blank();cacheLoaded=true;paused=true;storageNote=result.error||'Local mail cache cleared. Continue to scan again.';render();
    }
    $('mail-clear-cache')?.addEventListener('click',clearCache);
    return Object.freeze({
      async prepare(){
        const id=draftId();if(prepared?.id===id)return prepared.data;if(preparing?.id===id)return preparing.promise;
        const own={...identity(),recipient:recipientKey(form.elements.recipient.value)};const value={subject:form.elements.subject.value,body:form.elements.message.value};
        const promise=root.HashstashMailCrypto.encrypt(value,own).then(data=>{if(id!==draftId())throw Error('Message or wallet changed. Review again.');prepared={id,data};return data;});
        preparing={id,promise};try{return await promise;}finally{if(preparing?.id===id)preparing=null;}
      },
      data(){if(!prepared||prepared.id!==draftId())throw Error('Wait for the encrypted message and fee quote.');return prepared.data;},
      sent(){invalidate();form.elements.subject.value='';form.elements.message.value='';checkedTip='';load();},
      update(value){
        const stamp=JSON.stringify([value.chain_id,value.key,value.wallet_id,value.wallet_revision,value.can_decrypt,value.node_id]);
        if(stamp!==lastWallet){sequence++;loading=false;blank();if(lastWallet){form.elements.subject.value='';form.elements.message.value='';}lastWallet=stamp;}
        else if(context.tip!==value.tip){sequence++;loading=false;}
        context=value;if(!value.ready||!value.available){sequence++;loading=false;blank();}
        render();if(eligible()&&checkedTip!==value.tip)load();
      },
      route(){if(!active()){sequence++;loading=false;render();return;}render();if(checkedTip!==context.tip)load();},
      clear(){sequence++;loading=false;blank();render();},
      clearCache,
    });
  }
  return Object.freeze({create,createCache});
});
