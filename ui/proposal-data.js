(function(root,factory){'use strict';const api=factory(root);if(typeof module==='object'&&module.exports)module.exports=api;else root.HashstashProposalData=api;})(globalThis,function(root){
  'use strict';const MAX_TEXT_BYTES=2048,encoder=new TextEncoder();
  function encode(value){
    if(typeof value!=='string'||/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value))throw Error('Proposal explanation contains invalid Unicode.');
    if(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/u.test(value))throw Error('Proposal explanation contains unsupported control characters.');
    const text=value.trim();if(encoder.encode(text).length>MAX_TEXT_BYTES)throw Error('Explain the proposal in up to 2,048 UTF-8 bytes.');
    if(!text)return '';
    const bytes=encoder.encode(text);
    return Array.from(bytes,v=>v.toString(16).padStart(2,'0')).join('');
  }
  function verifiedText(value,commitment){
    if(typeof value!=='string'||!value.trim()||value!==value.trim()||!root.HashstashNoble)return '';
    try{encode(value);const digest=Array.from(root.HashstashNoble.sha256(encoder.encode(value)),v=>v.toString(16).padStart(2,'0')).join('');
      const expected=Array.isArray(commitment)?commitment.map(v=>Number(v).toString(16).padStart(2,'0')).join(''):commitment;
      return digest===expected?value:'';
    }catch{return '';}
  }
  return Object.freeze({MAX_TEXT_BYTES,encode,verifiedText});
});
