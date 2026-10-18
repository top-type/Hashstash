(function(root,factory){'use strict';const api=factory(root);if(typeof module==='object'&&module.exports)module.exports=api;else root.HashstashMail=api;})(globalThis,function(root){
  'use strict';const validId=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v),validCursor=v=>typeof v==='string'&&/^\d{1,20}:\d{1,20}$/.test(v);
  const compareCursor=(a,b)=>{const x=a.split(':').map(BigInt),y=b.split(':').map(BigInt);return x[0]===y[0]?(x[1]>y[1]?1:x[1]<y[1]?-1:0):x[0]>y[0]?1:-1;};
  const visibleControls=text=>text.replace(/[\u202a-\u202e\u2066-\u2069]/g,c=>`\\u${c.charCodeAt(0).toString(16)}`);
  // One localStorage write commits the ciphertext rows and their scan cursor
  // together. Persist no decrypted content or secret keys. When the opened
  // messages exceed the cache bounds, the oldest are left out of the saved
  // copy and counted, so the checkpoint still advances; anyone can send an
  // address enough mail to fill it. A rescan from the beginning shows them.
  // Discovery rests briefly after each budget of candidates, then continues.
  // A scan start (the tip when this browser created the wallet, or a block
  // chosen in Mail settings) is kept apart from the checkpoint, so clearing
  // the saved scan returns to it rather than to genesis.
  const CACHE_PREFIX='hashstash-mail-scan-3:',START_PREFIX='hashstash-mail-start-1:',CACHE_LIMIT=256,CACHE_BYTES=2*1024*1024,SCAN_BUDGET=100,SCAN_REST_MS=250,END='9223372036854775807';
  // A scan keeps this many earlier checkpoints, and rewinds at most this
  // many times in one pass before it restarts from the beginning.
  const CHECKPOINTS=4,MAX_REWINDS=4;
  const entryCursor=entry=>`${entry.height}:${entry.position??entry.tx_position??0}`;
  function cacheEntry(entry){
    const position=entry.position??entry.tx_position??0;
    if(!validId(entry.txid)||!Number.isSafeInteger(entry.height)||entry.height<0||!Number.isSafeInteger(position)||position<0||typeof entry.raw!=='string'||entry.raw.length>CACHE_BYTES||!/^(?:[0-9a-f]{2})+$/.test(entry.raw))throw Error('Invalid cached mail.');
    // Recover sender, nonce and ciphertext from the verified signed record on
    // restore. Do not persist a second, independently editable copy of them.
    return {txid:entry.txid,raw:entry.raw,height:entry.height,position};
  }
  function createCache(options={}){
    let storage;try{storage=Object.hasOwn(options,'storage')?options.storage:root.localStorage;}catch(_){}
    const cacheKey=(chain,key,prefix=CACHE_PREFIX)=>{if(!validId(chain)||!validId(key))throw Error('Invalid mail cache identity.');return prefix+chain+':'+key;};
    // Scan only blocks above height; anchor is a canonical block at or above
    // it, checked by the node like a checkpoint's.
    const validStart=value=>{
      if(!value||value.version!==1||!Number.isSafeInteger(value.height)||value.height<0||value.height>0xffffffff||!validId(value.anchor)||!['created','chosen'].includes(value.origin))throw Error('Invalid mail scan start.');
      return {version:1,height:value.height,anchor:value.anchor,origin:value.origin};
    };
    const validate=value=>{
      const omitted=value?.omitted??0,points=value?.checkpoints??[];
      if(!value||value.version!==3||!validCursor(value.cursor)||!validId(value.anchor)||!Number.isSafeInteger(value.scanned)||value.scanned<0||!Number.isSafeInteger(omitted)||omitted<0||!Array.isArray(value.entries)||value.entries.length>CACHE_LIMIT||!Array.isArray(points)||points.length>CHECKPOINTS)throw Error('Invalid cached mail.');
      const entries=value.entries.map(cacheEntry);if(new Set(entries.map(e=>e.txid)).size!==entries.length||entries.some(e=>compareCursor(`${e.height}:${e.position}`,value.cursor)>0))throw Error('Invalid cached mail.');
      // Earlier checkpoints lie strictly below the current one, newest first.
      const checkpoints=points.map(point=>{if(!validCursor(point?.cursor)||!validId(point.anchor))throw Error('Invalid cached mail.');return {cursor:point.cursor,anchor:point.anchor};});
      if(checkpoints.some((point,i)=>compareCursor(point.cursor,i?checkpoints[i-1].cursor:value.cursor)>=0))throw Error('Invalid cached mail.');
      return {version:3,cursor:value.cursor,anchor:value.anchor,scanned:value.scanned,omitted,entries,checkpoints};
    };
    // Keep the newest entries that fit the count and byte bounds. A signed
    // carrier too large to cache on its own is left out, not a reason to stop.
    const bounded=value=>{
      const all=Array.isArray(value?.entries)?value.entries:[],entries=all.filter(e=>!(typeof e?.raw==='string'&&e.raw.length>CACHE_BYTES)).map(cacheEntry);
      entries.sort((a,b)=>compareCursor(`${b.height}:${b.position}`,`${a.height}:${a.position}`));
      let bytes=JSON.stringify({...value,version:3,omitted:Number.MAX_SAFE_INTEGER,entries:[]}).length;const kept=[];
      for(const entry of entries){if(kept.length>=CACHE_LIMIT)break;const size=JSON.stringify(entry).length+1;if(bytes+size>CACHE_BYTES)continue;bytes+=size;kept.push(entry);}
      return {...value,version:3,omitted:(value?.omitted??0)+all.length-kept.length,entries:kept.reverse()};
    };
    return Object.freeze({
      read(chain,key){
        try{if(!storage)throw Error();const text=storage.getItem(cacheKey(chain,key));if(text==null)return {value:null};if(text.length>CACHE_BYTES)throw Error();return {value:validate(JSON.parse(text))};}
        catch(_){return {value:null,error:'Local mail cache is unavailable or invalid; scanning from the beginning for this visit.'};}
      },
      write(chain,key,value){
        try{if(!storage)throw Error();const checked=validate(bounded(value)),encoded=JSON.stringify(checked);if(encoded.length>CACHE_BYTES)throw Error();storage.setItem(cacheKey(chain,key),encoded);return {saved:true};}
        catch(_){return {saved:false,error:'Local mail storage is full or unavailable. Later progress is kept only for this visit; the last complete checkpoint is preserved.'};}
      },
      clear(chain,key){try{if(!storage||typeof storage.removeItem!=='function')throw Error();storage.removeItem(cacheKey(chain,key));return {cleared:true};}catch(_){return {cleared:false,error:'This browser could not clear its local mail cache.'};}},
      // An unreadable start is ignored: the scan then begins at genesis.
      readStart(chain,key){try{if(!storage)return null;const text=storage.getItem(cacheKey(chain,key,START_PREFIX));return text==null||text.length>1024?null:validStart(JSON.parse(text));}catch(_){return null;}},
      writeStart(chain,key,value){try{if(!storage)throw Error();storage.setItem(cacheKey(chain,key,START_PREFIX),JSON.stringify(validStart(value)));return {saved:true};}catch(_){return {saved:false,error:'This browser could not save the mail scan start; it applies only for this visit.'};}},
      clearStart(chain,key){try{if(!storage||typeof storage.removeItem!=='function')throw Error();storage.removeItem(cacheKey(chain,key,START_PREFIX));return {cleared:true};}catch(_){return {cleared:false,error:'This browser could not clear its mail scan start.'};}}
    });
  }
  function create({rpc,getIdentity,recipientKey,decrypt,verifySigned,encodeAddress,onDraftChange=()=>{},document=root.document,location=root.location,cache=createCache()}){
    const $=id=>document.getElementById(id),form=$('mail-form');let context={},sequence=0,prepared=null,preparing=null,checkedTip='',verifiedTip='',cursor=null,anchor=null,checkpoints=[],opened=new Map(),lastWallet='',loading=false,paused=false,scanned=0,visibleCount=50,rendered='',cacheLoaded=false,restoreEntries=[],storageNote='',omitted=0,start=null;
    const active=()=>location.hash.split('?')[0]==='#mail',eligible=()=>active()&&context.ready&&context.available&&context.key&&context.can_decrypt;
    const add=(p,t,c,text)=>{const n=document.createElement(t);n.className=c;if(text!==undefined)n.textContent=text;p.appendChild(n);return n;};
    const identity=()=>getIdentity(),yieldTask=()=>new Promise(resolve=>root.setTimeout(resolve,0));
    const draftId=()=>JSON.stringify([identity(),form.elements.recipient.value,recipientKey(form.elements.recipient.value),form.elements.subject.value,form.elements.message.value]);
    function invalidate(){prepared=null;preparing=null;}
    function error(message){$('mail-error').textContent=message;$('mail-error').hidden=!message;}
    function resetScan(){opened.clear();cursor=null;anchor=null;checkpoints=[];checkedTip='';verifiedTip='';scanned=0;omitted=0;visibleCount=50;rendered='';$('mail-list').replaceChildren();error('');}
    // Continue from an earlier position: drop what was found above it, and
    // the checkpoints there, whose history may have been replaced.
    function rewindTo(target,base){
      for(const [txid,value] of opened)if(compareCursor(entryCursor(value.entry),target)>0)opened.delete(txid);
      restoreEntries=restoreEntries.filter(entry=>compareCursor(entryCursor(entry),target)<=0);
      checkpoints=checkpoints.filter(point=>compareCursor(point.cursor,target)<0);
      cursor=target;anchor=base;verifiedTip='';render();
    }
    function blank(){invalidate();resetScan();paused=false;cacheLoaded=false;restoreEntries=[];storageNote='';start=null;}
    // Begin a scan without a checkpoint at this account's start, if it has one.
    function fromStart(){if(start){cursor=`${start.height}:${END}`;anchor=start.anchor;}}
    function startNote(text,failed=false){const node=$('mail-start-feedback');if(node){node.textContent=text;node.classList.toggle('error',failed);}}
    function render(){
      const verified=verifiedTip===context.tip;
      $('mail-empty').hidden=verified&&opened.size>0;
      $('mail-empty').textContent=!context.key?'Select a wallet.':!context.can_decrypt?(context.locked?'Locked · unlock this browser wallet to read mail.':'Watch-only · import the private key to read mail.'):!context.available?'Mail unavailable.':loading?'Checking messages…':paused?'Scan paused.':!verified&&checkedTip?'Verifying latest blocks…':'No messages found.';
      $('mail-scan-status').textContent=context.key&&context.can_decrypt?(loading?`Scanning · ${scanned} checked · ${opened.size} found`:paused?`Paused · ${scanned} checked`:!verified&&checkedTip?'Verification pending':verified?`${scanned} checked · ${opened.size} found`:''):'';
      if(context.key&&context.can_decrypt&&storageNote)$('mail-scan-status').textContent+=' · '+storageNote;
      if(context.key&&context.can_decrypt&&omitted)$('mail-scan-status').textContent+=` · ${omitted} earlier message${omitted===1?' is':'s are'} not kept in this browser; clear the saved scan to show ${omitted===1?'it':'them'} again`;
      if(context.key&&context.can_decrypt&&start)$('mail-scan-status').textContent+=` · from block ${start.height+1}`;
      $('mail-more').hidden=!context.can_decrypt||!context.key||(!loading&&!paused);$('mail-more').textContent=paused?'Continue scan':'Pause scan';
      $('mail-show-more').hidden=!verified||opened.size<=visibleCount;
      if($('mail-clear-cache'))$('mail-clear-cache').disabled=!context.key||!context.can_decrypt;
      if($('mail-start-note'))$('mail-start-note').textContent=!context.key||!context.can_decrypt?'':!start?'Mail is scanned from genesis.':start.origin==='created'?`This wallet was created in this browser at block ${start.height}, so mail is scanned from block ${start.height+1}.`:`Mail is scanned from block ${start.height+1}.`;
      if($('mail-scan-genesis'))$('mail-scan-genesis').hidden=!start||!context.key||!context.can_decrypt;
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
        // Explicit bidi embeddings, overrides and isolates are shown as escapes
        // so decrypted text cannot display in a different order from its bytes.
        const copy=add(row,'div','mail-content');add(copy,'h3','mail-subject',visibleControls(clear.subject));add(copy,'p','mail-body',visibleControls(clear.body));
      }
    }
    async function load(){
      if(!eligible()||loading||paused)return;
      loading=true;const version=++sequence,stamp=lastWallet;let restarted=false,rewinds=0,checkedThisPass=0;
      if(!cacheLoaded){cacheLoaded=true;const saved=cache.read(context.chain_id,context.key);storageNote=saved.error||'';start=cache.readStart(context.chain_id,context.key);if(saved.value){cursor=saved.value.cursor;anchor=saved.value.anchor;checkpoints=saved.value.checkpoints;scanned=saved.value.scanned;omitted=saved.value.omitted;restoreEntries=saved.value.entries;}else fromStart();}
      const current=()=>version===sequence&&stamp===lastWallet&&eligible()&&!paused;render();
      try{
        do{
          let result;
          try{result=await rpc('explorer_mail',{limit:50,...(cursor?{after:cursor,anchor}:{})});}
          catch(e){
            if(!current())return;
            // A reorganization above part of the scan keeps what was found at
            // or below the reported fork height and continues from there with
            // the same anchor. Each rewind moves the cursor strictly down, and a
            // pass allows only a few, so a second fork during a scan rewinds too.
            const message=String(e.message),fork=/blocks above height (\d{1,16}) were replaced/.exec(message),forkCursor=fork&&`${fork[1]}:${END}`;
            if(forkCursor&&rewinds<MAX_REWINDS&&cursor&&compareCursor(forkCursor,cursor)<0){rewinds++;rewindTo(forkCursor,anchor);continue;}
            if(message.includes('Mail scan anchor is no longer canonical')){
              // Without a fork height (an anchor the node does not know, or one
              // replaced too deeply), resume from the newest earlier checkpoint
              // below the cursor. The node checks its anchor in turn.
              const earlier=cursor&&checkpoints.find(point=>compareCursor(point.cursor,cursor)<0);
              if(earlier&&rewinds<MAX_REWINDS){rewinds++;rewindTo(earlier.cursor,earlier.anchor);continue;}
              // With none left, rescan from genesis. The start's anchor may be
              // the unknown one, so the start is dropped as well.
              if(!restarted){resetScan();restoreEntries=[];const cleared=cache.clear(context.chain_id,context.key);storageNote=cleared.error||'';if(start){cache.clearStart(context.chain_id,context.key);start=null;}restarted=true;render();continue;}
            }
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
            // A restored row is this account's own mail: derive its sender,
            // nonce and ciphertext from the verified signed record. A new row
            // is first unwrapped under the feed's stated context, and only an
            // envelope that opens is verified against its signed record, still
            // before it is shown or checkpointed. Most envelopes are not ours,
            // so they cost no signature check. A feed that alters an
            // envelope's sender, nonce or ciphertext can hide it, as it can by
            // leaving the row out, but cannot attribute it to another sender.
            let claimed;
            try{
              if(restoring){const signed=verifySigned(source.raw,{chain_id:context.chain_id,txid:source.txid});claimed={sender:signed.sender,nonce:signed.nonce,data_hex:signed.data_hex,signed};}
              else{
                const sender=source.sender_public_key||source.sender;
                if(!validId(sender)||!/^\d{1,20}$/.test(String(source.nonce))||typeof source.data_hex!=='string'||typeof source.raw!=='string')throw Error();
                claimed={sender,nonce:String(source.nonce),data_hex:source.data_hex};
              }
            }catch(_){
              if(restoring){restoreFailed=true;break;}
              throw Error('Mail transaction signature or details could not be verified.');
            }
            // Decryption failure alone is normal: most envelopes are not ours.
            // A wallet locked by its passphrase opened nothing, so the page
            // stops without advancing the checkpoint or dropping the cache.
            let clear=null;
            try{root.HashstashMailCrypto.parse(claimed.data_hex);clear=await decrypt(claimed.data_hex,{chain_id:context.chain_id,sender:claimed.sender,nonce:claimed.nonce},identity());}catch(e){if(e?.walletLocked)throw e;}
            if(!current())return;
            if(validId(clear?.recipient)&&typeof clear.subject==='string'&&typeof clear.body==='string'&&(claimed.sender===context.key||clear.recipient===context.key)){
              let signed=claimed.signed;
              if(!signed){
                try{
                  const expected={chain_id:context.chain_id,txid:source.txid,sender:claimed.sender,nonce:claimed.nonce,data_hex:claimed.data_hex};
                  if(source.operation!==undefined)expected.operation=source.operation;
                  signed=verifySigned(source.raw,expected);
                }catch(_){throw Error('Mail transaction signature or details could not be verified.');}
              }
              found.push({entry:{txid:signed.txid,raw:source.raw,sender_public_key:signed.sender,nonce:signed.nonce,data_hex:signed.data_hex,height:source.height,position},clear});
            }else if(restoring){restoreFailed=true;break;}
            if((index+1)%4===0){await yieldTask();if(!current())return;}
          }
          if(!current())return;
          if(restoreFailed){resetScan();fromStart();restoreEntries=[];const cleared=cache.clear(context.chain_id,context.key);storageNote=cleared.error||'';render();continue;}
          // Commit the cursor and authenticated messages together. A cancelled
          // page is retried rather than silently skipping its remaining mail.
          for(const value of found)opened.set(value.entry.txid,value);
          // The node just accepted the previous position and anchor. Keep it as
          // an earlier checkpoint when the anchor moves on, for an anchor error
          // that later arrives without a fork height.
          if(cursor&&anchor&&anchor!==result.anchor&&compareCursor(cursor,result.scan_cursor)<0)checkpoints=[{cursor,anchor},...checkpoints.filter(point=>compareCursor(point.cursor,cursor)<0)].slice(0,CHECKPOINTS);
          restoreEntries=[];verifiedTip=result.tip;scanned+=result.messages.length;checkedThisPass+=result.messages.length;cursor=result.scan_cursor;anchor=result.anchor;error('');
          const saved=cache.write(context.chain_id,context.key,{cursor,anchor,checkpoints,scanned,omitted,entries:[...opened.values()].map(v=>v.entry)});storageNote=saved.error||'';
          if(result.next_cursor==null){checkedTip=context.tip;break;}
          // Rest after each budget instead of waiting for a click, so a long
          // history (or envelope spam) costs time, not repeated user action.
          if(checkedThisPass>=SCAN_BUDGET){render();await new Promise(resolve=>root.setTimeout(resolve,SCAN_REST_MS));if(!current())return;checkedThisPass=0;continue;}
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
      if(!context.key)return;sequence++;loading=false;const result=cache.clear(context.chain_id,context.key);blank();cacheLoaded=true;start=cache.readStart(context.chain_id,context.key);fromStart();paused=true;storageNote=result.error||'Local mail cache cleared. Continue to scan again.';render();
    }
    // Rescan this account from a chosen first block (0 is genesis). The
    // current tip anchors a chosen start, as it would a checkpoint.
    function rescanFrom(first){
      if(!eligible())return;
      sequence++;loading=false;const cleared=cache.clear(context.chain_id,context.key);blank();cacheLoaded=true;
      const result=first>0?cache.writeStart(context.chain_id,context.key,start={version:1,height:first-1,anchor:context.tip,origin:'chosen'}):cache.clearStart(context.chain_id,context.key);
      storageNote=result.error||cleared.error||'';fromStart();render();load();
    }
    $('mail-clear-cache')?.addEventListener('click',clearCache);
    $('mail-start-form')?.addEventListener('submit',event=>{
      event.preventDefault();const text=String($('mail-start-form').elements.height.value).trim();
      if(!eligible()||!Number.isSafeInteger(context.height)){startNote('Select a wallet with its private key and wait for the node.',true);return;}
      if(!/^\d{1,10}$/.test(text)||Number(text)>context.height){startNote(`Enter a block height from 0 to ${context.height}.`,true);return;}
      startNote('');rescanFrom(Number(text));
    });
    $('mail-scan-genesis')?.addEventListener('click',()=>{startNote('');rescanFrom(0);});
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
      // A key this browser just generated can have no mail at or below the
      // tip it was created at, so its first scan starts above that block.
      recordStart({chain_id,key,height,tip}){
        if(cache.read(chain_id,key).value||cache.readStart(chain_id,key))return false;
        return cache.writeStart(chain_id,key,{version:1,height,anchor:tip,origin:'created'}).saved;
      },
    });
  }
  return Object.freeze({create,createCache});
});
