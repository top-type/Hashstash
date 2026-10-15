(function(root,factory){'use strict';const api=factory(root);if(typeof module==='object'&&module.exports)module.exports=api;else root.HashstashTransactionMail=api;})(globalThis,function(root){
  'use strict';
  function create({getIdentity,decodeAddress,encrypt=(value,identity)=>root.HashstashMailCrypto.encrypt(value,identity)}){
    const drafts=new Map();
    const enabled=form=>form.elements.data_format?.value==='private';
    const fields=form=>[form.elements.mail_recipient?.value||'',form.elements.mail_subject?.value||'',form.elements.mail_body?.value||''];
    const stamp=form=>JSON.stringify([getIdentity(),fields(form)]);
    return Object.freeze({
      enabled,
      identity(form){return enabled(form)?stamp(form):'';},
      async prepare(form){
        if(!enabled(form))return;
        const identity=getIdentity(),[recipient,subject,body]=fields(form),id=stamp(form);
        const prior=drafts.get(form.id);if(prior?.id===id)return prior.promise;
        if(!recipient.trim())throw Error('Enter the encrypted message recipient address.');
        const target=decodeAddress(recipient.trim());
        const draft={id,promise:null,data:null};
        draft.promise=encrypt({subject,body},{...identity,recipient:target}).then(data=>{
          if(!enabled(form)||id!==stamp(form)||drafts.get(form.id)!==draft)throw Error('Message or wallet changed. Review again.');
          draft.data=data;return data;
        });
        drafts.set(form.id,draft);
        try{return await draft.promise;}catch(error){if(drafts.get(form.id)===draft)drafts.delete(form.id);throw error;}
      },
      data(form){const draft=drafts.get(form.id);if(!enabled(form)||!draft?.data||draft.id!==stamp(form))throw Error('Wait for the encrypted message and its fee quote.');return draft.data;},
      clear(){drafts.clear();}
    });
  }
  return Object.freeze({create});
});
