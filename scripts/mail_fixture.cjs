'use strict';
// Independent wire encoder for public, deterministic Mail test keys only.
const {createHash}=require('node:crypto');
const digest=data=>createHash('sha256').update(data).digest();
const le=(n,size)=>{let v=BigInt(n);const out=Buffer.alloc(size);for(let i=0;i<size;i++){out[i]=Number(v&255n);v>>=8n;}return out;};
const uint=n=>{n=BigInt(n);return n<251n?le(n,1):n<=65535n?Buffer.concat([le(251,1),le(n,2)]):n<=0xffffffffn?Buffer.concat([le(252,1),le(n,4)]):Buffer.concat([le(253,1),le(n,8)]);};
const vector=b=>Buffer.concat([uint(b.length),b]);
const amount=n=>{n=BigInt(n);const out=[];while(n){out.push(Number(n&255n));n>>=8n;}return vector(Buffer.from(out));};
function signMailRow(noble,chain,secret,row,fee=1){
  const key=Uint8Array.from(Buffer.from(secret,'hex')),sender=Buffer.from(noble.schnorr.getPublicKey(key)).toString('hex');
  const body=Buffer.concat([Buffer.from(chain,'hex'),Buffer.from(sender,'hex'),uint(row.nonce??0),amount(fee),uint(1000000),uint(0),Buffer.from(sender,'hex'),amount(1),vector(Buffer.from(row.data_hex,'hex'))]);
  const tag=digest('Hashstash/Transaction'),message=digest(Buffer.concat([tag,tag,body]));
  const signature=noble.schnorr.sign(Uint8Array.from(message),key,new Uint8Array(32));
  const raw=Buffer.concat([body,Buffer.from(signature)]);
  return {...row,sender_public_key:sender,nonce:String(row.nonce??0),raw:raw.toString('hex'),txid:digest(digest(raw)).toString('hex')};
}
module.exports={signMailRow};
