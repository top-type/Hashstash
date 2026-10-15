// Hashstash mail v2: recipient-hidden, fixed-size envelopes in transaction data.
(function(root,factory){'use strict';const api=factory(root);if(typeof module==='object'&&module.exports)module.exports=api;else root.HashstashMailCrypto=api;})(globalThis,function(root){
  'use strict';
  const PREFIX='hashstash.mail/2\n', MAX_DATA_BYTES=3072, MAX_PLAIN_BYTES=1152;
  const fields=['ephemeral_key','iv','ciphertext','recipient_iv','recipient_key','sender_iv','sender_key'];
  const utf8=new TextEncoder(), decoder=new TextDecoder('utf-8',{fatal:true});
  const hex=b=>Array.from(b,v=>v.toString(16).padStart(2,'0')).join('');
  const concat=(...parts)=>{const b=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let offset=0;for(const p of parts){b.set(p,offset);offset+=p.length;}return b;};
  function bytes(s,length){if(typeof s!=='string'||!/^[0-9a-f]*$/.test(s)||s.length%2||(length!==undefined&&s.length!==length*2))throw Error('Invalid encrypted message.');return Uint8Array.from(s.match(/../g)||[],v=>parseInt(v,16));}
  function secure(){if(!root.isSecureContext||!root.crypto?.subtle||!root.crypto?.getRandomValues||!root.HashstashNoble?.ecdhXOnly)throw Error('Secure messaging is unavailable. Use HTTPS or localhost.');}
  function random(n){const b=new Uint8Array(n);root.crypto.getRandomValues(b);return b;}
  function context(c,eph){
    const chain=bytes(c.chain_id,32),sender=bytes(c.sender,32),ephemeral=bytes(eph,32);
    if(!root.HashstashNoble.validPublic(sender)||!root.HashstashNoble.validPublic(ephemeral))throw Error('Invalid messaging public key.');
    if(typeof c.nonce!=='string'||!/^(0|[1-9][0-9]*)$/.test(c.nonce))throw Error('Invalid message nonce.');
    let n=BigInt(c.nonce);if(n>0xffffffffffffffffn)throw Error('Invalid message nonce.');
    const nonce=new Uint8Array(8);for(let i=0;i<8;i++){nonce[i]=Number(n&255n);n>>=8n;}
    return {chain,aad:concat(utf8.encode('Hashstash/Mail/v2\0'),chain,sender,nonce,ephemeral)};
  }
  function plain(value){
    if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['subject','body'].includes(k)))throw Error('Invalid message content.');
    const {subject,body}=value;
    for(const s of [subject,body])if(typeof s!=='string'||/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(s)||/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/u.test(s))throw Error('Message contains unsupported characters.');
    if(!subject.trim()||!body.trim()||utf8.encode(subject).length>96||utf8.encode(body).length>768)throw Error('Use a subject up to 96 UTF-8 bytes and a message up to 768 bytes.');
    // Reserve the fixed recipient field and the two-byte content length here,
    // so composition validation agrees with encryption even with JSON escapes.
    const result=utf8.encode(JSON.stringify({subject,body}));if(result.length+79+2>MAX_PLAIN_BYTES){result.fill(0);throw Error('Encoded message is too long.');}return result;
  }
  function padded(value,recipient){
    const checked=plain(value);checked.fill(0);
    if(!root.HashstashNoble.validPublic(bytes(recipient,32)))throw Error('Invalid messaging public key.');
    const content=utf8.encode(JSON.stringify({recipient,subject:value.subject,body:value.body}));
    try{
      if(content.length+2>MAX_PLAIN_BYTES)throw Error('Encoded message is too long.');
      const result=new Uint8Array(MAX_PLAIN_BYTES);result[0]=content.length>>>8;result[1]=content.length&255;result.set(content,2);return result;
    }finally{content.fill(0);}
  }
  function parse(dataHex){
    if(typeof dataHex!=='string'||dataHex.length>MAX_DATA_BYTES*2)throw Error('Encrypted message is too large.');
    const data=bytes(dataHex);if(data.length>MAX_DATA_BYTES)throw Error('Encrypted message is too large.');
    let text;try{text=decoder.decode(data);}catch{throw Error('Invalid encrypted message encoding.');}
    if(!text.startsWith(PREFIX))throw Error('Unsupported encrypted message version.');
    let e;try{e=JSON.parse(text.slice(PREFIX.length));}catch{throw Error('Invalid encrypted message.');}
    if(!e||typeof e!=='object'||Array.isArray(e)||Object.keys(e).length!==fields.length||fields.some((f,i)=>Object.keys(e)[i]!==f))throw Error('Noncanonical encrypted message.');
    if(!root.HashstashNoble?.validPublic(bytes(e.ephemeral_key,32)))throw Error('Invalid messaging public key.');for(const f of ['iv','recipient_iv','sender_iv'])bytes(e[f],12);
    for(const f of ['recipient_key','sender_key'])bytes(e[f],48);
    const cipher=bytes(e.ciphertext);if(cipher.length!==MAX_PLAIN_BYTES+16||PREFIX+JSON.stringify(e)!==text)throw Error('Noncanonical encrypted message.');
    return e;
  }
  async function aesKey(raw){return root.crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);}
  async function crypt(mode,key,iv,data,aad){return new Uint8Array(await root.crypto.subtle[mode]({name:'AES-GCM',iv,additionalData:aad,tagLength:128},key,data));}
  async function wrappingKey(secret,peer,c,role,candidate){
    const shared=root.HashstashNoble.ecdhXOnly(secret,bytes(peer,32));
    try{const base=await root.crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);return await root.crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:c.chain,info:concat(utf8.encode('Hashstash/Mail/v2/'+role+'\0'),c.aad,bytes(candidate,32))},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
    finally{shared.fill(0);}
  }
  async function encrypt(value,identity){
    secure();let plaintext,contentSecret,ephemeral;
    try{
      plaintext=padded(value,identity.recipient);contentSecret=random(32);
      do{ephemeral?.fill(0);ephemeral=random(32);}while(!root.HashstashNoble.validSecret(ephemeral));
      const eph=hex(root.HashstashNoble.schnorr.getPublicKey(ephemeral)),c=context(identity,eph),iv=random(12),recipientIv=random(12),senderIv=random(12);
      const contentKey=await aesKey(contentSecret),recipientKey=await wrappingKey(ephemeral,identity.recipient,c,'recipient',identity.recipient),senderKey=await wrappingKey(ephemeral,identity.sender,c,'sender',identity.sender);
      const e={ephemeral_key:eph,iv:hex(iv),ciphertext:hex(await crypt('encrypt',contentKey,iv,plaintext,c.aad)),recipient_iv:hex(recipientIv),recipient_key:hex(await crypt('encrypt',recipientKey,recipientIv,contentSecret,concat(c.aad,utf8.encode('/recipient')))),sender_iv:hex(senderIv),sender_key:hex(await crypt('encrypt',senderKey,senderIv,contentSecret,concat(c.aad,utf8.encode('/sender'))))};
      const result=hex(utf8.encode(PREFIX+JSON.stringify(e)));parse(result);return result;
    }finally{ephemeral?.fill(0);contentSecret?.fill(0);plaintext?.fill(0);}
  }
  async function decrypt(dataHex,identity,privateHex){
    secure();const e=parse(dataHex),c=context(identity,e.ephemeral_key),secret=bytes(privateHex,32);let contentSecret,decoded;
    try{
      const own=hex(root.HashstashNoble.schnorr.getPublicKey(secret));
      const role=own===identity.sender?'sender':'recipient';
      const key=await wrappingKey(secret,e.ephemeral_key,c,role,own);
      contentSecret=await crypt('decrypt',key,bytes(e[role+'_iv'],12),bytes(e[role+'_key'],48),concat(c.aad,utf8.encode('/'+role)));
      if(contentSecret.length!==32)throw Error('Invalid content key.');
      decoded=await crypt('decrypt',await aesKey(contentSecret),bytes(e.iv,12),bytes(e.ciphertext),c.aad);
      if(decoded.length!==MAX_PLAIN_BYTES)throw Error('Invalid message size.');
      const length=(decoded[0]<<8)|decoded[1];if(length===0||length+2>decoded.length||decoded.subarray(length+2).some(v=>v!==0))throw Error('Invalid message padding.');
      const text=decoder.decode(decoded.subarray(2,length+2)),value=JSON.parse(text);
      if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).join(',')!=='recipient,subject,body'||(role==='recipient'&&value.recipient!==own))throw Error('Invalid private recipient.');
      const canonical=padded({subject:value.subject,body:value.body},value.recipient);
      try{if(canonical.some((v,i)=>v!==decoded[i]))throw Error('Noncanonical message content.');}finally{canonical.fill(0);}
      return {recipient:value.recipient,subject:value.subject,body:value.body};
    }catch{throw Error('Message authentication failed. Its content or transaction identity does not match.');}
    finally{secret.fill(0);contentSecret?.fill(0);decoded?.fill(0);}
  }
  return Object.freeze({PREFIX,MAX_DATA_BYTES,MAX_PLAIN_BYTES,parse,encrypt,decrypt,validatePlain:plain});
});
