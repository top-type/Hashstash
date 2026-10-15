// Browser-local Hashstash wallet. No network calls; private keys never enter RPC.
(function (root, factory) {
  'use strict';
  const api = factory(root, root.HashstashNoble, root.HashstashAddress);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.HashstashBrowserWallet = api;
})(globalThis, function (root, noble, addresses) {
  'use strict';
  if (!noble || !addresses) throw new Error('Wallet cryptography is unavailable.');
  const MAX_U64 = (1n << 64n) - 1n, MAX_AMOUNT = (1n << 512n) - 1n;
  const operations = ['TransferExact','Deposit','Redeem','Propose','Support','Refund'];
  const parameters = ['BlockBytes','Interval','Lead','Rest','Duration','MinerFeePercent','PassMarginBps','MinimumFeeRate'];
  const utf8 = new TextEncoder();
  const fail = message => { throw new Error(message); };
  const hex = bytes => {
    const parts = [];
    for (let start = 0; start < bytes.length; start += 32768) parts.push(Array.from(bytes.subarray(start, start + 32768), b => b.toString(16).padStart(2, '0')).join(''));
    return parts.join('');
  };
  function fromHex(value, size, label = 'Hexadecimal value') {
    if (typeof value !== 'string' || value.length % 2 || (size !== undefined && value.length !== size * 2) || !/^[0-9a-f]*$/i.test(value)) fail(`${label} is invalid.`);
    const bytes = new Uint8Array(value.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  function bytes32(value, label = 'Hash') {
    if (typeof value === 'string') return fromHex(value, 32, label);
    if (!(Array.isArray(value) || value instanceof Uint8Array) || value.length !== 32 || Array.from(value).some(v => !Number.isInteger(v) || v < 0 || v > 255)) fail(`${label} must contain 32 bytes.`);
    return Uint8Array.from(value);
  }
  function publicBytes(value) {
    const bytes = bytes32(value, 'Public key');
    if (!noble.validPublic(bytes)) fail('Invalid BIP340 public key.');
    return bytes;
  }
  function integer(value, maximum, label) {
    if (typeof JSON.isRawJSON === 'function' && JSON.isRawJSON(value)) value = value.rawJSON;
    if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) fail(`${label} must be an exact unsigned integer.`);
    if (!['string','number','bigint'].includes(typeof value) || !/^(0|[1-9][0-9]*)$/.test(String(value))) fail(`${label} must be an exact unsigned integer.`);
    // Bound before BigInt conversion to keep hostile inputs cheap.
    if (String(value).length > 155) fail(`${label} is too large.`);
    const n = BigInt(value);
    if (n > maximum) fail(`${label} is too large.`);
    return n;
  }
  const u64 = (v, label = 'Integer') => integer(v, MAX_U64, label);
  const amount = v => integer(v, MAX_AMOUNT, 'Amount');
  function fields(value, allowed, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k))) fail(`${label} has unsupported fields.`);
  }
  function tagged(tag, data) {
    const digest = noble.sha256(utf8.encode(tag));
    return noble.sha256(concat(digest, digest, data));
  }
  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0; for (const p of parts) { out.set(p, offset); offset += p.length; } return out;
  }
  class Writer {
    constructor() { this.parts = []; this.length = 0; }
    raw(v) { if (!Number.isSafeInteger(this.length + v.length)) fail('Transaction exceeds browser representation.'); this.parts.push(v instanceof Uint8Array ? v : Uint8Array.from(v)); this.length += v.length; }
    int(v, size) { v = BigInt(v); const bytes = new Uint8Array(size); for (let i = 0; i < size; i++) { bytes[i] = Number(v & 255n); v >>= 8n; } this.raw(bytes); }
    uint(v) {
      v = u64(v);
      if (v < 251n) this.int(v, 1);
      else if (v <= 0xffffn) { this.int(251, 1); this.int(v, 2); }
      else if (v <= 0xffffffffn) { this.int(252, 1); this.int(v, 4); }
      else { this.int(253, 1); this.int(v, 8); }
    }
    vector(v) { this.uint(v.length); this.raw(v); }
    amount(v) { v = amount(v); const b = []; while (v) { b.push(Number(v & 255n)); v >>= 8n; } this.vector(b); }
    hash(v, key = false) { this.raw(key ? publicBytes(v) : bytes32(v)); }
    option(v, put) { this.int(v == null ? 0 : 1, 1); if (v != null) put(v); }
    finish() { const bytes = new Uint8Array(this.length); let offset = 0; for (const part of this.parts) { bytes.set(part, offset); offset += part.length; } return bytes; }
  }
  class Reader {
    constructor(data) { this.data = data; this.offset = 0; }
    raw(n) { if (!Number.isSafeInteger(n) || n < 0 || n > this.data.length - this.offset) fail('Truncated transaction.'); const out = this.data.slice(this.offset, this.offset + n); this.offset += n; return out; }
    int(n) { const b = this.raw(n); let value = 0n; for (let i = b.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(b[i]); return value; }
    uint(max = MAX_U64) {
      const tag = this.int(1);
      if (tag < 251n) { if (tag > max) fail('Integer is too large.'); return tag; }
      const size = tag === 251n ? 2 : tag === 252n ? 4 : tag === 253n ? 8 : 0;
      if (!size) fail('Invalid integer encoding.');
      const value = this.int(size), minimum = tag === 251n ? 251n : tag === 252n ? 0x10000n : 0x100000000n;
      if (value < minimum) fail('Noncanonical integer.');
      if (value > max) fail('Integer is too large.');
      return value;
    }
    vector(max = this.data.length - this.offset) { const n = this.uint(); if (n > BigInt(max)) fail('Transaction field is too large.'); return this.raw(Number(n)); }
    amount() { const b = this.vector(64); if (b.length && b[b.length - 1] === 0) fail('Noncanonical amount.'); let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return String(v); }
    hash(key = false) { const b = this.raw(32); if (key) publicBytes(b); return hex(b); }
    option(read) { const tag = this.int(1); if (tag === 0n) return null; if (tag !== 1n) fail('Invalid optional field.'); return read(); }
    done() { if (this.offset !== this.data.length) fail('Unexpected transaction bytes.'); }
  }
  function sides(w, v) {
    if ((v.decision == null) !== (v.outcome == null)) fail('Decision and outcome must appear together.');
    w.option(v.decision, d => w.hash(d));
    w.option(v.outcome, o => { if (o !== 'Pass' && o !== 'Fail') fail('Invalid outcome.'); w.uint(o === 'Pass' ? 0 : 1); });
  }
  function readSides(r) {
    const decision = r.option(() => r.hash());
    const outcome = r.option(() => { const n = r.uint(0xffffffffn); if (n > 1n) fail('Invalid outcome.'); return n === 0n ? 'Pass' : 'Fail'; });
    if ((decision == null) !== (outcome == null)) fail('Decision and outcome must appear together.');
    return {decision, outcome};
  }
  function writeProposal(w, proposal) {
    fields(proposal, ['Grant','Parameter'], 'Proposal');
    const names = Object.keys(proposal); if (names.length !== 1) fail('Invalid proposal.');
    const name = names[0], p = proposal[name];
    if (name === 'Grant') {
      fields(p, ['payments'], 'Grant'); validatePayments(p.payments); w.uint(0); w.uint(p.payments.length);
      for (const payment of p.payments) { w.hash(payment.recipient, true); w.amount(payment.amount); }
    }
    else { fields(p, ['parameter','old','new'], 'Parameter'); const n = parameters.indexOf(p.parameter); if (n < 0) fail('Unknown parameter.'); w.uint(1); w.uint(n); w.uint(p.old); w.uint(p.new); }
  }
  function readProposal(r) {
    const tag = r.uint(0xffffffffn);
    if (tag === 0n) {
      const count = r.uint();
      if (!count) fail('Grant needs at least one payment.');
      // Even an invalid zero amount needs its length byte after the 32-byte key.
      // Bound the allocation by the actual input before decoding any recipients.
      if (count > BigInt(Math.floor((r.data.length - r.offset) / 33))) fail('Truncated grant payments.');
      const payments = Array.from({length:Number(count)},()=>({recipient:r.hash(true),amount:r.amount()}));
      validatePayments(payments); return {Grant:{payments}};
    }
    if (tag !== 1n) fail('Unknown proposal.');
    const p = Number(r.uint(0xffffffffn)); if (!parameters[p]) fail('Unknown parameter.');
    return {Parameter:{parameter:parameters[p], old:String(r.uint()), new:String(r.uint())}};
  }
  function validatePayments(payments) {
    if (!Array.isArray(payments) || payments.length < 1) fail('Grant needs at least one payment.');
    let previous = '', total = 0n;
    for (const payment of payments) {
      fields(payment, ['recipient','amount'], 'Grant payment'); const recipient = hex(publicBytes(payment.recipient)), value = amount(payment.amount);
      if (recipient <= previous) fail('Grant recipients must be unique and sorted.');
      if (!value) fail('Grant payment must be positive.');
      total += value; if (total > MAX_AMOUNT) fail('Grant total is too large.'); previous = recipient;
    }
  }
  function encodeOperation(operation) {
    fields(operation, operations, 'Operation'); const names = Object.keys(operation);
    if (names.length !== 1) fail('Exactly one operation is required.');
    const name = names[0], v = operation[name], w = new Writer();
    w.uint(operations.indexOf(name));
    const layout = {
      TransferExact:['recipient','amount'],
      Deposit:['amount','min_shares','decision','outcome'], Redeem:['shares','min_received','decision','outcome'],
      Propose:['round','description','proposal','support'], Support:['round','proposal','amount'], Refund:['round','proposal']
    };
    fields(v, layout[name], 'Operation');
    switch (name) {
      case 'TransferExact': w.hash(v.recipient, true); w.amount(v.amount); break;
      case 'Deposit': w.amount(v.amount); w.amount(v.min_shares); sides(w,v); break;
      case 'Redeem': w.amount(v.shares); w.amount(v.min_received); sides(w,v); break;
      case 'Propose': w.uint(v.round); w.hash(v.description); writeProposal(w,v.proposal); w.amount(v.support); break;
      case 'Support': case 'Refund': w.uint(v.round); w.hash(v.proposal); if (name === 'Support') w.amount(v.amount); break;
      default: fail('Unknown operation.');
    }
    return w.finish();
  }
  function readOperation(r) {
    const tag = Number(r.uint(0xffffffffn)), name = operations[tag]; if (!name) fail('Unsupported operation.');
    let v;
    switch(name) {
      case 'TransferExact': v={recipient:r.hash(true),amount:r.amount()}; break;
      case 'Deposit': v={amount:r.amount(),min_shares:r.amount(),...readSides(r)}; break;
      case 'Redeem': v={shares:r.amount(),min_received:r.amount(),...readSides(r)}; break;
      case 'Propose': v={round:String(r.uint()),description:r.hash(),proposal:readProposal(r),support:r.amount()}; break;
      case 'Support': v={round:String(r.uint()),proposal:r.hash(),amount:r.amount()}; break;
      case 'Refund': v={round:String(r.uint()),proposal:r.hash()}; break;
    }
    return {[name]:v};
  }
  function decodeBody(bytes) {
    const r = new Reader(bytes);
    const decoded = {chain_id:r.hash(),sender:r.hash(true),nonce:String(r.uint()),fee:r.amount(),expiry_height:String(r.uint()),operation:readOperation(r),data_hex:hex(r.vector())};
    r.done(); if (BigInt(decoded.nonce) === MAX_U64) fail('Nonce exhausted.'); if (decoded.expiry_height === '0') fail('Expiry height must be positive.');
    return decoded;
  }
  function decodeUnsigned(envelope) {
    if (!envelope || envelope.format !== 'hashstash-unsigned-v1' || typeof envelope.body !== 'string' || !envelope.body.length) fail('Invalid unsigned transaction.');
    return decodeBody(fromHex(envelope.body));
  }
  function expectedBytes(expected) {
    if (!expected || typeof expected !== 'object') fail('Transaction intent is required.');
    const version = Number(u64(expected.protocol_version, 'Protocol version'));
    if (version !== 28) fail('Unsupported protocol version.');
    const nonce = u64(expected.nonce, 'Nonce'), expiry = u64(expected.expiry_height, 'Expiry height');
    if (nonce === MAX_U64 || !expiry) fail('Invalid nonce or expiry height.');
    if (expected.current_height !== undefined && expiry <= u64(expected.current_height)) fail('Transaction has expired.');
    const parameter = expected.operation?.Propose?.proposal?.Parameter;
    if (parameter?.parameter === 'MinerFeePercent' && (u64(parameter.old) > 100n || u64(parameter.new) > 100n)) fail('Miner fee share must be from 0 to 100 percent.');
    if (parameter && ['Interval','Duration','BlockBytes'].includes(parameter.parameter) && (!u64(parameter.old) || !u64(parameter.new))) fail('This setting must be positive.');
    if (parameter?.parameter === 'BlockBytes' && (u64(parameter.old) < 1024n || u64(parameter.new) < 1024n)) fail('Block capacity must cover the miner account’s 1,024 weight.');
    const op = encodeOperation(expected.operation), data = fromHex(expected.data_hex ?? '', undefined, 'Transaction data');
    const fee = amount(expected.fee);
    const w = new Writer(); w.hash(expected.chain_id); w.hash(expected.sender,true); w.uint(nonce); w.amount(fee); w.uint(expiry); w.raw(op); w.vector(data);
    return w.finish();
  }
  function verifyUnsigned(envelope, expected) {
    const decoded = decodeUnsigned(envelope), bytes = expectedBytes(expected);
    // Compare every canonical byte, including opaque data and all optional fields.
    if (hex(bytes) !== envelope.body.toLowerCase()) fail('Prepared transaction does not match the requested details.');
    return Object.freeze(decoded);
  }
  function verifySigned(raw, expected = {}) {
    if (!expected || typeof expected !== 'object' || Array.isArray(expected)) fail('Invalid transaction expectations.');
    const bytes = fromHex(raw, undefined, 'Signed transaction');
    if (bytes.length <= 64) fail('Invalid signed transaction.');
    const body = bytes.subarray(0, -64), decoded = decodeBody(body);
    if (!noble.schnorr.verify(bytes.subarray(-64), tagged('Hashstash/Transaction/v26', body), bytes32(decoded.sender))) fail('Invalid transaction signature.');
    const txid = hex(noble.sha256(noble.sha256(bytes)));
    for (const field of ['chain_id','sender','data_hex']) {
      if (expected[field] !== undefined && expected[field] !== decoded[field]) fail('Signed transaction does not match the message.');
    }
    if (expected.nonce !== undefined && String(u64(expected.nonce, 'Nonce')) !== decoded.nonce) fail('Signed transaction does not match the message.');
    if (expected.txid !== undefined && expected.txid !== txid) fail('Signed transaction ID does not match the message.');
    if (expected.operation !== undefined && hex(encodeOperation(expected.operation)) !== hex(encodeOperation(decoded.operation))) fail('Signed transaction operation does not match the message.');
    // Authentication of these bytes does not establish canonical-chain inclusion.
    return Object.freeze({...decoded,txid});
  }
  function secretBytes(privateHex) { const bytes = fromHex(privateHex,32,'Private key'); if (!noble.validSecret(bytes)) fail('Invalid private key.'); return bytes; }
  function publicKey(privateHex) { requireSecure(); const secret = secretBytes(privateHex); try { return hex(noble.schnorr.getPublicKey(secret)); } finally { secret.fill(0); } }
  function derivePrivate(passphrase) {
    requireSecure();
    if (typeof passphrase !== 'string' || !passphrase.length) fail('Enter a passphrase.');
    // Rust strings cannot contain lone UTF-16 surrogates; reject rather than silently replacing.
    if (typeof passphrase.isWellFormed === 'function' ? !passphrase.isWellFormed() : /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(passphrase)) fail('Passphrase contains invalid Unicode.');
    const phrase = utf8.encode(passphrase); if (phrase.length > 4096) fail('Passphrase is too long.');
    const input = concat(phrase,new Uint8Array(4)); phrase.fill(0);
    try { for (let counter=0;counter<=0xffffffff;counter++) { new DataView(input.buffer).setUint32(input.length-4,counter,true); const secret=tagged('Hashstash/Passphrase/v1',input); if (noble.validSecret(secret)) { const out=hex(secret); secret.fill(0); return out; } secret.fill(0); } } finally { input.fill(0); }
    fail('Could not derive private key.');
  }
  function requireSecure() {
    const l = root.location, local = l && ['localhost','127.0.0.1','[::1]','::1'].includes(l.hostname);
    if (!root.isSecureContext || !l || (l.protocol !== 'https:' && !(l.protocol === 'http:' && local))) fail('Use HTTPS for this wallet, or localhost.');
    if (!root.crypto?.getRandomValues) fail('Secure randomness is unavailable.');
  }
  function random(size) { requireSecure(); return root.crypto.getRandomValues(new Uint8Array(size)); }
  function createStore(chainId) {
    requireSecure(); chainId = hex(bytes32(chainId,'Chain ID'));
    const storageKey = `hashstash.browser-wallet.v1.${chainId}`, hrp = 'hsh' + chainId.slice(0,16), callbacks = new Set();
    let cachedFingerprint, cachedMetadata;
    const empty = () => ({version:1,chain_id:chainId,revision:'0',selected:null,wallets:[]});
    const invalidateMetadata = () => { cachedFingerprint = cachedMetadata = undefined; };
    function storedText() {
      let text; try { text = root.localStorage.getItem(storageKey); } catch { fail('Browser wallet storage is unavailable.'); }
      if (text != null && text.length > 1024*1024) fail('Browser wallet data is too large. Export existing keys before changing storage.');
      return text;
    }
    function read(text = storedText()) {
      if (text == null) return empty();
      let data; try { data=JSON.parse(text); } catch { fail('Browser wallet data cannot be read. Existing data was preserved.'); }
      fields(data,['version','chain_id','revision','selected','wallets'],'Wallet data');
      if (data.version !== 1 || data.chain_id !== chainId || typeof data.revision !== 'string' || !Array.isArray(data.wallets) || data.wallets.length > 1000) fail('Invalid browser wallet data. Existing data was preserved.');
      const seen=new Set();
      for(const w of data.wallets) {
        fields(w,['id','public_key','private_key','backed_up'],'Wallet');
        if(w.id !== w.public_key || seen.has(w.id) || hex(publicBytes(w.public_key)) !== w.public_key || typeof w.backed_up !== 'boolean') fail('Invalid saved wallet. Existing data was preserved.');
        seen.add(w.id);
        if(w.private_key != null && publicKey(w.private_key) !== w.public_key) fail('Saved private key does not match its address. Existing data was preserved.');
      }
      if(data.selected !== null && !seen.has(data.selected)) fail('Selected wallet is unavailable. Existing data was preserved.');
      return data;
    }
    function metadata(data) {
      const wallets=data.wallets.map(w=>({id:w.id,public_key:w.public_key,address:addresses.encode(w.public_key,hrp),mode:w.private_key?'hot':'watch',can_sign:!!w.private_key,backed_up:w.backed_up}));
      const selected=wallets.find(w=>w.id===data.selected);
      return {wallets,wallet_id:selected?.id??null,wallet_revision:data.revision,public_key:selected?.public_key??null,address:selected?.address??null,wallet_enabled:!!selected?.can_sign,wallet_mode:selected?.mode??'none',chain_id:chainId};
    }
    function snapshot() {
      requireSecure();
      const text = storedText(), bytes = text == null ? null : new Uint8Array(text.length * 2);
      // Hash the exact UTF-16 code units, including malformed surrogate input,
      // rather than letting a UTF-8 encoder normalize distinct stored strings.
      if(bytes)for(let i=0;i<text.length;i++){const unit=text.charCodeAt(i);bytes[2*i]=unit;bytes[2*i+1]=unit>>>8;}
      let fingerprint;
      // Cache only public metadata and a content digest, never another copy of
      // the persisted secrets. Revision alone cannot detect edited storage.
      try { fingerprint = bytes == null ? null : hex(noble.sha256(bytes)); }
      finally { bytes?.fill(0); }
      if (!cachedMetadata || fingerprint !== cachedFingerprint) {
        invalidateMetadata();
        cachedMetadata = metadata(read(text)); cachedFingerprint = fingerprint;
      }
      // Callers must not be able to mutate the cached view.
      return {...cachedMetadata,wallets:cachedMetadata.wallets.map(wallet=>({...wallet}))};
    }
    function guard(data, expected) { if(expected?.wallet_revision !== undefined && expected.wallet_revision !== data.revision) fail('Wallet selection changed. Try again.'); }
    function notify() { for(const callback of callbacks) { try { callback(snapshot()); } catch { /* callbacks cannot interrupt persistence */ } } }
    async function locked(fn) { requireSecure(); if(!root.navigator?.locks?.request) fail('This browser does not support safe wallet storage. Use a current browser.'); return root.navigator.locks.request(storageKey,fn); }
    async function change(fn,expected) {
      return locked(()=>{ const data=read(); guard(data,expected); fn(data); data.revision=hex(random(16));
        try { root.localStorage.setItem(storageKey,JSON.stringify(data)); } catch { fail('Wallet could not be saved. Existing wallets were preserved.'); }
        invalidateMetadata();
        notify(); return metadata(data);
      });
    }
    async function add(public_key,private_key,expected) {
      return change(data=>{let existing=data.wallets.find(w=>w.id===public_key);
        if(existing) { if(private_key && !existing.private_key) { existing.private_key=private_key; existing.backed_up=false; } }
        else { if(data.wallets.length >= 1000) fail('Too many saved wallets.'); data.wallets.push({id:public_key,public_key,private_key:private_key??null,backed_up:false}); }
        data.selected=public_key;
      },expected);
    }
    const onStorage=e=>{if(e.key===storageKey || e.key===null) { invalidateMetadata(); notify(); }}; root.addEventListener?.('storage',onStorage);
    return Object.freeze({
      snapshot,
      subscribe(callback) { if(typeof callback!=='function') fail('Invalid wallet subscriber.'); callbacks.add(callback); return ()=>callbacks.delete(callback); },
      destroy() { root.removeEventListener?.('storage',onStorage); callbacks.clear(); invalidateMetadata(); },
      async create(expected) { let secret; do { secret=random(32); } while(!noble.validSecret(secret)); try { return await add(hex(noble.schnorr.getPublicKey(secret)),hex(secret),expected); } finally { secret.fill(0); } },
      importPrivate(privateHex,expected) { const key=publicKey(privateHex); return add(key,privateHex.toLowerCase(),expected); },
      importPassphrase(passphrase,expected) { const secret=derivePrivate(passphrase); return add(publicKey(secret),secret,expected); },
      watch(value,expected) { const key=typeof value==='string' && value.length===78 ? addresses.decode(value,hrp) : hex(publicBytes(value)); publicBytes(key); return add(key,null,expected); },
      select(id,expected) { return change(data=>{if(!data.wallets.some(w=>w.id===id)) fail('Wallet not found.'); data.selected=id;},expected); },
      exportPrivate(id,expected) { return locked(()=>{const data=read();guard(data,expected);const w=data.wallets.find(w=>w.id===id);if(!w?.private_key)fail('This wallet has no private key.');return w.private_key;}); },
      acknowledgeBackup(id,expected) { return change(data=>{const w=data.wallets.find(w=>w.id===id);if(!w)fail('Wallet not found.');w.backed_up=true;},expected); },
      async decryptMail(dataHex,identity,expected) {
        requireSecure(); const data=read(); guard(data,expected);
        if(!expected || expected.wallet_revision===undefined || expected.wallet_id!==data.selected || expected.chain_id!==chainId || identity.chain_id!==chainId) fail('Wallet context changed. Try again.');
        const w=data.wallets.find(w=>w.id===data.selected);
        if(!w?.private_key) fail('Import this account’s private key locally to open encrypted mail.');
        if(!root.HashstashMailCrypto) fail('Encrypted mail is unavailable.');
        const result=await root.HashstashMailCrypto.decrypt(dataHex,identity,w.private_key);
        guard(read(),expected);
        return result;
      },
      signUnsigned(envelope,expected) {
        requireSecure(); const data=read(); guard(data,expected);
        if(!expected || expected.wallet_revision===undefined || expected.wallet_id!==data.selected || hex(bytes32(expected.chain_id))!==chainId) fail('Wallet context changed. Try again.');
        const w=data.wallets.find(w=>w.id===data.selected);
        if(!w?.private_key) fail('Use the offline signer for this watch-only wallet.');
        if(hex(publicBytes(expected.sender))!==w.public_key) fail('Selected wallet does not authorize this sender.');
        verifyUnsigned(envelope,expected);
        const secret=secretBytes(w.private_key), aux=random(32);
        try {
          const body=fromHex(envelope.body), signature=noble.schnorr.sign(tagged('Hashstash/Transaction/v26',body),secret,aux);
          const raw=concat(body,signature);
          guard(read(),expected);
          return {raw:hex(raw),transaction_id:hex(noble.sha256(noble.sha256(raw)))};
        } finally {secret.fill(0);aux.fill(0);}
      }
    });
  }
  return Object.freeze({createStore,publicKey,derivePrivate,decodeUnsigned,verifyUnsigned,verifySigned});
});
