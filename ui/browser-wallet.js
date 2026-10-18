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
  const parameters = ['BlockBytes','Interval','Lead','Rest','DecisionBlocks','MinerFeePercent','PassMarginBps','MinimumFeeRate','MaxPriceChangeBps'];
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
  // The signed chain ID is not transmitted: a signature verifies on one network only.
  const signingMessage = (chain, body) => tagged('Hashstash/chain-bound-transaction', concat(chain, body));
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
      Deposit:['amount','decision','outcome'], Redeem:['shares','decision','outcome'],
      Propose:['round','description','proposal','support'], Support:['round','proposal','amount'], Refund:['round','proposal']
    };
    fields(v, layout[name], 'Operation');
    switch (name) {
      case 'TransferExact': w.hash(v.recipient, true); w.amount(v.amount); break;
      case 'Deposit': w.amount(v.amount); sides(w,v); break;
      case 'Redeem': w.amount(v.shares); sides(w,v); break;
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
      case 'Deposit': v={amount:r.amount(),...readSides(r)}; break;
      case 'Redeem': v={shares:r.amount(),...readSides(r)}; break;
      case 'Propose': v={round:String(r.uint()),description:r.hash(),proposal:readProposal(r),support:r.amount()}; break;
      case 'Support': v={round:String(r.uint()),proposal:r.hash(),amount:r.amount()}; break;
      case 'Refund': v={round:String(r.uint()),proposal:r.hash()}; break;
    }
    return {[name]:v};
  }
  function decodeBody(bytes) {
    const r = new Reader(bytes);
    const decoded = {sender:r.hash(true),nonce:String(r.uint()),fee:r.amount(),anchor:r.hash(),expiry_blocks:String(r.uint()),operation:readOperation(r),data_hex:hex(r.vector())};
    r.done(); if (BigInt(decoded.nonce) === MAX_U64) fail('Nonce exhausted.'); if (decoded.expiry_blocks === '0') fail('Transaction lifetime must be positive.');
    return decoded;
  }
  function decodeUnsigned(envelope) {
    if (!envelope || envelope.format !== 'hashstash-unsigned-anchor' || typeof envelope.body !== 'string' || !envelope.body.length) fail('Invalid unsigned transaction.');
    fields(envelope, ['format','chain_id','body'], 'Unsigned transaction');
    if (typeof envelope.chain_id !== 'string' || !/^[0-9a-f]{64}$/.test(envelope.chain_id)) fail('Invalid network context.');
    return decodeBody(fromHex(envelope.body));
  }
  function expectedBytes(expected) {
    if (!expected || typeof expected !== 'object') fail('Transaction intent is required.');
    const nonce = u64(expected.nonce, 'Nonce'), lifetime = u64(expected.expiry_blocks, 'Transaction lifetime');
    if (nonce === MAX_U64 || !lifetime) fail('Invalid nonce or transaction lifetime.');
    if (expected.expiry_height !== undefined) fail('Use a block reference and lifetime, not an absolute expiry.');
    if (expected.anchor_height !== undefined) {
      const height = u64(expected.anchor_height, 'Anchor height'), expiry = height + lifetime;
      if (expiry > MAX_U64) fail('Transaction expiry exceeds the height limit.');
      if (expected.current_height !== undefined) {
        const current = u64(expected.current_height, 'Current height');
        if (current < height) fail('Anchor is ahead of the current block.');
        if (current >= expiry) fail('Transaction has expired.');
      }
    } else if (expected.current_height !== undefined) fail('Anchor height is required to check expiry.');
    const parameter = expected.operation?.Propose?.proposal?.Parameter;
    if (parameter?.parameter === 'MinerFeePercent' && (u64(parameter.old) > 100n || u64(parameter.new) > 100n)) fail('Miner fee share must be from 0 to 100 percent.');
    if (parameter && ['Interval','DecisionBlocks','BlockBytes'].includes(parameter.parameter) && (!u64(parameter.old) || !u64(parameter.new))) fail('This setting must be positive.');
    if (parameter?.parameter === 'BlockBytes' && (u64(parameter.old) < 1024n || u64(parameter.new) < 1024n)) fail('Block capacity must cover the miner account’s 1,024 weight.');
    const op = encodeOperation(expected.operation), data = fromHex(expected.data_hex ?? '', undefined, 'Transaction data');
    const fee = amount(expected.fee);
    const w = new Writer(); w.hash(expected.sender,true); w.uint(nonce); w.amount(fee); w.hash(expected.anchor); w.uint(lifetime); w.raw(op); w.vector(data);
    return w.finish();
  }
  function verifyUnsigned(envelope, expected) {
    const decoded = decodeUnsigned(envelope);
    // The signature binds the selected network; the export's context must agree with it.
    if (hex(bytes32(expected?.chain_id, 'Network context')) !== envelope.chain_id) fail('Prepared transaction network context does not match the selected network.');
    const bytes = expectedBytes(expected);
    // Compare every canonical byte, including opaque data and all optional fields.
    if (hex(bytes) !== envelope.body.toLowerCase()) fail('Prepared transaction does not match the requested details.');
    return Object.freeze(decoded);
  }
  // `expected.chain_id` names the network the signature must have been made for.
  function verifySigned(raw, expected) {
    if (!expected || typeof expected !== 'object' || Array.isArray(expected)) fail('Invalid transaction expectations.');
    const chain = bytes32(expected.chain_id, 'Chain ID');
    const bytes = fromHex(raw, undefined, 'Signed transaction');
    if (bytes.length <= 64) fail('Invalid signed transaction.');
    const body = bytes.subarray(0, -64), decoded = decodeBody(body);
    if (!noble.schnorr.verify(bytes.subarray(-64), signingMessage(chain, body), bytes32(decoded.sender))) fail('Invalid transaction signature for this network.');
    const txid = hex(noble.sha256(noble.sha256(bytes)));
    for (const field of ['sender','anchor','data_hex']) {
      if (expected[field] !== undefined && expected[field] !== decoded[field]) fail('Signed transaction does not match the message.');
    }
    if (expected.nonce !== undefined && String(u64(expected.nonce, 'Nonce')) !== decoded.nonce) fail('Signed transaction does not match the message.');
    if (expected.expiry_blocks !== undefined && String(u64(expected.expiry_blocks, 'Transaction lifetime')) !== decoded.expiry_blocks) fail('Signed transaction does not match the message.');
    if (expected.txid !== undefined && expected.txid !== txid) fail('Signed transaction ID does not match the message.');
    if (expected.operation !== undefined && hex(encodeOperation(expected.operation)) !== hex(encodeOperation(decoded.operation))) fail('Signed transaction operation does not match the message.');
    // Authentication of these bytes does not establish canonical-chain inclusion.
    return Object.freeze({...decoded,txid});
  }
  function secretBytes(privateHex) { const bytes = fromHex(privateHex,32,'Private key'); if (!noble.validSecret(bytes)) fail('Invalid private key.'); return bytes; }
  function publicKey(privateHex) { requireSecure(); const secret = secretBytes(privateHex); try { return hex(noble.schnorr.getPublicKey(secret)); } finally { secret.fill(0); } }
  function passphraseBytes(passphrase) {
    if (typeof passphrase !== 'string' || !passphrase.length) fail('Enter a passphrase.');
    // Rust strings cannot contain lone UTF-16 surrogates; reject rather than silently replacing.
    if (typeof passphrase.isWellFormed === 'function' ? !passphrase.isWellFormed() : /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(passphrase)) fail('Passphrase contains invalid Unicode.');
    const phrase = utf8.encode(passphrase); if (phrase.length > 4096) { phrase.fill(0); fail('Passphrase is too long.'); }
    return phrase;
  }
  // First valid secp256k1 secret of tagged(tag, seed || counter_le32), as in Rust.
  function firstSecret(tag, seed) {
    const input = concat(seed,new Uint8Array(4));
    try { for (let counter=0;counter<=0xffffffff;counter++) { new DataView(input.buffer).setUint32(input.length-4,counter,true); const secret=tagged(tag,input); if (noble.validSecret(secret)) { const out=hex(secret); secret.fill(0); return out; } secret.fill(0); } } finally { input.fill(0); }
    fail('Could not derive private key.');
  }
  // Legacy hashstash-passphrase-v1: one unsalted SHA256 per guess. Restore only.
  function derivePrivate(passphrase) {
    requireSecure();
    const phrase = passphraseBytes(passphrase);
    try { return firstSecret('Hashstash/Passphrase/v1',phrase); } finally { phrase.fill(0); }
  }
  // HMAC-SHA256 and one-iteration PBKDF2-HMAC-SHA256, the only form scrypt uses.
  function hmac(key, ...parts) {
    const block = new Uint8Array(64), pad = new Uint8Array(64);
    block.set(key.length > 64 ? noble.sha256(key) : key);
    let inner;
    try {
      for (let i = 0; i < 64; i++) pad[i] = block[i] ^ 0x36;
      inner = noble.sha256(concat(pad, ...parts));
      for (let i = 0; i < 64; i++) pad[i] = block[i] ^ 0x5c;
      return noble.sha256(concat(pad, inner));
    } finally { block.fill(0); pad.fill(0); inner?.fill(0); }
  }
  function pbkdf2(password, salt, length) {
    const out = new Uint8Array(length), index = new Uint8Array(4);
    for (let block = 1, offset = 0; offset < length; block++, offset += 32) {
      new DataView(index.buffer).setUint32(0, block, false);
      const t = hmac(password, salt, index); out.set(t.subarray(0, Math.min(32, length - offset)), offset); t.fill(0);
    }
    return out;
  }
  // RFC 7914 Salsa20/8 core on 16 little-endian words, in place.
  function salsa8(b) {
    let x0=b[0],x1=b[1],x2=b[2],x3=b[3],x4=b[4],x5=b[5],x6=b[6],x7=b[7],x8=b[8],x9=b[9],x10=b[10],x11=b[11],x12=b[12],x13=b[13],x14=b[14],x15=b[15],u;
    for (let i = 0; i < 8; i += 2) {
      u=(x0+x12)|0;x4^=(u<<7)|(u>>>25);u=(x4+x0)|0;x8^=(u<<9)|(u>>>23);u=(x8+x4)|0;x12^=(u<<13)|(u>>>19);u=(x12+x8)|0;x0^=(u<<18)|(u>>>14);
      u=(x5+x1)|0;x9^=(u<<7)|(u>>>25);u=(x9+x5)|0;x13^=(u<<9)|(u>>>23);u=(x13+x9)|0;x1^=(u<<13)|(u>>>19);u=(x1+x13)|0;x5^=(u<<18)|(u>>>14);
      u=(x10+x6)|0;x14^=(u<<7)|(u>>>25);u=(x14+x10)|0;x2^=(u<<9)|(u>>>23);u=(x2+x14)|0;x6^=(u<<13)|(u>>>19);u=(x6+x2)|0;x10^=(u<<18)|(u>>>14);
      u=(x15+x11)|0;x3^=(u<<7)|(u>>>25);u=(x3+x15)|0;x7^=(u<<9)|(u>>>23);u=(x7+x3)|0;x11^=(u<<13)|(u>>>19);u=(x11+x7)|0;x15^=(u<<18)|(u>>>14);
      u=(x0+x3)|0;x1^=(u<<7)|(u>>>25);u=(x1+x0)|0;x2^=(u<<9)|(u>>>23);u=(x2+x1)|0;x3^=(u<<13)|(u>>>19);u=(x3+x2)|0;x0^=(u<<18)|(u>>>14);
      u=(x5+x4)|0;x6^=(u<<7)|(u>>>25);u=(x6+x5)|0;x7^=(u<<9)|(u>>>23);u=(x7+x6)|0;x4^=(u<<13)|(u>>>19);u=(x4+x7)|0;x5^=(u<<18)|(u>>>14);
      u=(x10+x9)|0;x11^=(u<<7)|(u>>>25);u=(x11+x10)|0;x8^=(u<<9)|(u>>>23);u=(x8+x11)|0;x9^=(u<<13)|(u>>>19);u=(x9+x8)|0;x10^=(u<<18)|(u>>>14);
      u=(x15+x14)|0;x12^=(u<<7)|(u>>>25);u=(x12+x15)|0;x13^=(u<<9)|(u>>>23);u=(x13+x12)|0;x14^=(u<<13)|(u>>>19);u=(x14+x13)|0;x15^=(u<<18)|(u>>>14);
    }
    b[0]+=x0;b[1]+=x1;b[2]+=x2;b[3]+=x3;b[4]+=x4;b[5]+=x5;b[6]+=x6;b[7]+=x7;b[8]+=x8;b[9]+=x9;b[10]+=x10;b[11]+=x11;b[12]+=x12;b[13]+=x13;b[14]+=x14;b[15]+=x15;
  }
  function blockMix(input, output, r, t) {
    t.set(input.subarray((2 * r - 1) * 16, 2 * r * 16));
    for (let i = 0; i < 2 * r; i++) {
      for (let k = 0; k < 16; k++) t[k] ^= input[i * 16 + k];
      salsa8(t); output.set(t, (i & 1 ? r + (i >> 1) : i >> 1) * 16);
    }
  }
  // scrypt (RFC 7914); N is a power of two. Words convert from bytes explicitly,
  // so the result does not depend on platform endianness.
  function scrypt(password, salt, N, r, p, length) {
    const words = 32 * r, B = pbkdf2(password, salt, p * 128 * r);
    const X = new Uint32Array(words), Y = new Uint32Array(words), V = new Uint32Array(words * N), t = new Uint32Array(16);
    try {
      for (let block = 0; block < p; block++) {
        const base = block * 128 * r;
        for (let k = 0; k < words; k++) { const o = base + 4 * k; X[k] = B[o] | (B[o + 1] << 8) | (B[o + 2] << 16) | (B[o + 3] << 24); }
        for (let i = 0; i < N; i += 2) { V.set(X, i * words); blockMix(X, Y, r, t); V.set(Y, (i + 1) * words); blockMix(Y, X, r, t); }
        for (let i = 0; i < N; i += 2) {
          let j = (X[(2 * r - 1) * 16] & (N - 1)) * words;
          for (let k = 0; k < words; k++) X[k] ^= V[j + k];
          blockMix(X, Y, r, t);
          j = (Y[(2 * r - 1) * 16] & (N - 1)) * words;
          for (let k = 0; k < words; k++) Y[k] ^= V[j + k];
          blockMix(Y, X, r, t);
        }
        for (let k = 0; k < words; k++) { const o = base + 4 * k, w = X[k]; B[o] = w; B[o + 1] = w >>> 8; B[o + 2] = w >>> 16; B[o + 3] = w >>> 24; }
      }
      return pbkdf2(password, B, length);
    } finally { B.fill(0); X.fill(0); Y.fill(0); V.fill(0); t.fill(0); }
  }
  // hashstash-passphrase-v2: printable ASCII, scrypt (N=2^17, r=8, p=1) salted with
  // the tag and chain ID, then the first valid tagged secret. Each network gets its
  // own account. Other text is refused: one visible Unicode phrase has several encodings.
  function derivePrivateV2(passphrase, chainId) {
    requireSecure();
    const chain = bytes32(chainId, 'Chain ID'), phrase = passphraseBytes(passphrase);
    let stretched;
    try {
      if (phrase.some(b => b < 0x20 || b > 0x7e)) fail('Version 2 passphrases use printable ASCII only: letters, digits, punctuation and spaces.');
      if (phrase.length < 16) fail('Passphrase must contain at least 16 characters.');
      stretched = scrypt(phrase, concat(utf8.encode('Hashstash/Passphrase/v2'), chain), 1 << 17, 8, 1, 32);
      return firstSecret('Hashstash/Passphrase/v2', stretched);
    } finally { phrase.fill(0); stretched?.fill(0); }
  }
  function requireSecure() {
    const l = root.location, local = l && ['localhost','127.0.0.1','[::1]','::1'].includes(l.hostname);
    if (!root.isSecureContext || !l || (l.protocol !== 'https:' && !(l.protocol === 'http:' && local))) fail('Use HTTPS for this wallet, or localhost.');
    if (!root.crypto?.getRandomValues) fail('Secure randomness is unavailable.');
  }
  function random(size) { requireSecure(); return root.crypto.getRandomValues(new Uint8Array(size)); }
  // Optional passphrase lock for saved private keys, hashstash-browser-lock-v1.
  // PBKDF2-HMAC-SHA256 over the NFC-normalized passphrase and a random 16-byte
  // salt derives a non-extractable AES-256-GCM key. Each sealed key is bound to
  // the network and its public key as authenticated data. A sealed empty check
  // value, bound to the network and salt, identifies the passphrase.
  const LOCK_FORMAT = 'hashstash-browser-lock-v1', LOCK_KDF = 'PBKDF2-HMAC-SHA256', LOCK_ITERATIONS = 600000;
  const IDLE_LOCK_MS = 5 * 60 * 1000, MIN_LOCK_PASSPHRASE = 8;
  function subtle() { requireSecure(); if (!root.crypto?.subtle) fail('Browser encryption is unavailable. Use a current browser.'); return root.crypto.subtle; }
  function canonicalHex(value, size) { return typeof value === 'string' && value.length === size * 2 && /^[0-9a-f]*$/.test(value); }
  function sealedShape(value, size, label) {
    fields(value, ['iv','data'], label);
    if (!canonicalHex(value.iv, 12) || !canonicalHex(value.data, size)) fail(`${label} is invalid. Existing data was preserved.`);
  }
  function lockShape(lock) {
    fields(lock, ['format','kdf','iterations','salt','check'], 'Wallet passphrase');
    if (lock.format !== LOCK_FORMAT || lock.kdf !== LOCK_KDF || lock.iterations !== LOCK_ITERATIONS || !canonicalHex(lock.salt, 16)) fail('Unsupported wallet passphrase. Existing data was preserved.');
    sealedShape(lock.check, 16, 'Wallet passphrase');
  }
  // The thrown error says the lock, not the data, stopped the operation.
  function lockedFail(message) { const error = new Error(message); error.walletLocked = true; throw error; }
  async function lockKey(passphrase, salt) {
    if (typeof passphrase !== 'string') fail('Enter the wallet passphrase.');
    const phrase = passphraseBytes(passphrase.normalize('NFC'));
    try {
      const base = await subtle().importKey('raw', phrase, 'PBKDF2', false, ['deriveKey']);
      return await subtle().deriveKey({name:'PBKDF2', hash:'SHA-256', salt, iterations:LOCK_ITERATIONS}, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
    } finally { phrase.fill(0); }
  }
  async function seal(key, plain, additionalData) {
    const iv = random(12);
    return {iv:hex(iv), data:hex(new Uint8Array(await subtle().encrypt({name:'AES-GCM', iv, additionalData, tagLength:128}, key, plain)))};
  }
  // The plaintext, or null when the key or authenticated data does not match.
  async function unseal(key, sealed, additionalData) {
    try { return new Uint8Array(await subtle().decrypt({name:'AES-GCM', iv:fromHex(sealed.iv, 12), additionalData, tagLength:128}, key, fromHex(sealed.data))); }
    catch { return null; }
  }
  function createStore(chainId, options = {}) {
    requireSecure(); chainId = hex(bytes32(chainId,'Chain ID'));
    const idleLock = options.idleLockMs ?? IDLE_LOCK_MS;
    if (!Number.isSafeInteger(idleLock) || idleLock <= 0) fail('Invalid idle lock.');
    const storageKey = `hashstash.browser-wallet.v1.${chainId}`, hrp = 'hsh' + chainId.slice(0,16), callbacks = new Set(), lockCallbacks = new Set();
    let cachedFingerprint, cachedMetadata, cachedLock, unlocked = null, idleTimer;
    const empty = () => ({version:1,chain_id:chainId,revision:'0',selected:null,wallets:[]});
    const invalidateMetadata = () => { cachedFingerprint = cachedMetadata = cachedLock = undefined; };
    const keyData = publicKey => concat(utf8.encode('Hashstash/browser-wallet-key/v1\0'), fromHex(chainId, 32), fromHex(publicKey, 32));
    const checkData = salt => concat(utf8.encode('Hashstash/browser-wallet-lock/v1\0'), fromHex(chainId, 32), salt);
    const lockId = lock => lock ? `${lock.salt}:${lock.check.data}` : null;
    // The passphrase key lives only in this page's memory. It opens only the
    // lock it was derived for, so a passphrase changed in another tab locks
    // this one, and it is dropped after a period without explicit use even
    // when a background tab's timer is late.
    function relock() { unlocked = null; root.clearTimeout?.(idleTimer); idleTimer = undefined; }
    function session(lock) {
      if (unlocked && Date.now() - unlocked.used >= idleLock) relock();
      return unlocked && unlocked.lock === lockId(lock) ? unlocked.key : null;
    }
    function lockChanged() { for (const callback of lockCallbacks) { try { callback(snapshot()); } catch { /* listeners cannot interrupt locking */ } } }
    function expire() {
      if (!unlocked) return;
      const left = idleLock - (Date.now() - unlocked.used);
      if (left > 0) { idleTimer = root.setTimeout?.(expire, left); return; }
      relock(); lockChanged();
    }
    function touch() {
      if (!unlocked) return;
      unlocked.used = Date.now(); root.clearTimeout?.(idleTimer); idleTimer = root.setTimeout?.(expire, idleLock);
    }
    // A saved key's secret bytes, checked against its address. Callers wipe them.
    async function secretOf(data, w) {
      if (w.private_key) return secretBytes(w.private_key);
      if (!w.sealed_key) fail('This wallet has no private key.');
      const key = session(data.lock);
      if (!key) lockedFail('Unlock this browser wallet with its passphrase first.');
      const secret = await unseal(key, w.sealed_key, keyData(w.public_key));
      if (!secret || secret.length !== 32 || !noble.validSecret(secret) || hex(noble.schnorr.getPublicKey(secret)) !== w.public_key) { secret?.fill(0); fail('Saved private key does not match its address. Existing data was preserved.'); }
      return secret;
    }
    function storedText() {
      let text; try { text = root.localStorage.getItem(storageKey); } catch { fail('Browser wallet storage is unavailable.'); }
      if (text != null && text.length > 1024*1024) fail('Browser wallet data is too large. Export existing keys before changing storage.');
      return text;
    }
    function read(text = storedText()) {
      if (text == null) return empty();
      let data; try { data=JSON.parse(text); } catch { fail('Browser wallet data cannot be read. Existing data was preserved.'); }
      // An optional `lock` and per-wallet `sealed_key` hold passphrase-encrypted
      // keys. Data without them keeps the original unencrypted layout.
      fields(data,['version','chain_id','revision','selected','wallets','lock'],'Wallet data');
      if (data.version !== 1 || data.chain_id !== chainId || typeof data.revision !== 'string' || !Array.isArray(data.wallets) || data.wallets.length > 1000) fail('Invalid browser wallet data. Existing data was preserved.');
      if (data.lock !== undefined) lockShape(data.lock);
      const seen=new Set();
      for(const w of data.wallets) {
        fields(w,['id','public_key','private_key','backed_up','sealed_key'],'Wallet');
        if(w.id !== w.public_key || seen.has(w.id) || hex(publicBytes(w.public_key)) !== w.public_key || typeof w.backed_up !== 'boolean') fail('Invalid saved wallet. Existing data was preserved.');
        seen.add(w.id);
        if(w.sealed_key !== undefined) { if (!data.lock || w.private_key != null) fail('Invalid saved wallet. Existing data was preserved.'); sealedShape(w.sealed_key, 48, 'Saved private key'); }
        if(w.private_key != null && publicKey(w.private_key) !== w.public_key) fail('Saved private key does not match its address. Existing data was preserved.');
      }
      if(data.selected !== null && !seen.has(data.selected)) fail('Selected wallet is unavailable. Existing data was preserved.');
      return data;
    }
    function metadata(data) {
      const wallets=data.wallets.map(w=>{const hot=!!(w.private_key||w.sealed_key);return {id:w.id,public_key:w.public_key,address:addresses.encode(w.public_key,hrp),mode:hot?'hot':'watch',can_sign:hot,encrypted:!!w.sealed_key,backed_up:w.backed_up};});
      const selected=wallets.find(w=>w.id===data.selected);
      return {wallets,wallet_id:selected?.id??null,wallet_revision:data.revision,public_key:selected?.public_key??null,address:selected?.address??null,wallet_enabled:!!selected?.can_sign,wallet_mode:selected?.mode??'none',chain_id:chainId,
        wallet_encrypted:!!data.lock,wallet_plaintext_keys:data.wallets.filter(w=>w.private_key).length,wallet_idle_lock_seconds:Math.ceil(idleLock/1000)};
    }
    // Lock state lives in memory, so it joins the cached public view here.
    function view(meta, lock) {
      return {...meta,wallet_locked:meta.wallet_encrypted&&!session(lock),wallets:meta.wallets.map(wallet=>({...wallet}))};
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
        const data = read(text);
        cachedMetadata = metadata(data); cachedLock = data.lock; cachedFingerprint = fingerprint;
      }
      // Callers must not be able to mutate the cached view.
      return view(cachedMetadata, cachedLock);
    }
    function guard(data, expected) { if(expected?.wallet_revision !== undefined && expected.wallet_revision !== data.revision) fail('Wallet selection changed. Try again.'); }
    function notify() { for(const callback of callbacks) { try { callback(snapshot()); } catch { /* callbacks cannot interrupt persistence */ } } }
    async function locked(fn) { requireSecure(); if(!root.navigator?.locks?.request) fail('This browser does not support safe wallet storage. Use a current browser.'); return root.navigator.locks.request(storageKey,fn); }
    // The storage lock is held across any encryption the change awaits.
    async function change(fn,expected) {
      return locked(async()=>{ const data=read(); guard(data,expected); await fn(data); data.revision=hex(random(16));
        try { root.localStorage.setItem(storageKey,JSON.stringify(data)); } catch { fail('Wallet could not be saved. Existing wallets were preserved.'); }
        invalidateMetadata();
        notify(); return view(metadata(data), data.lock);
      });
    }
    // With a passphrase, a new private key is saved only sealed, so adding one
    // needs the unlocked passphrase key.
    async function add(public_key,private_key,expected) {
      let keyAdded = false;
      const result = await change(async data=>{let existing=data.wallets.find(w=>w.id===public_key);
        const needsKey=!!private_key && !(existing?.private_key || existing?.sealed_key);
        let sealed=null;
        if(needsKey && data.lock) {
          const key=session(data.lock);
          if(!key) lockedFail('Unlock this browser wallet with its passphrase to add a private key.');
          const secret=secretBytes(private_key);
          try { sealed=await seal(key,secret,keyData(public_key)); } finally { secret.fill(0); }
        }
        if(existing) { if(needsKey) { if(sealed) existing.sealed_key=sealed; else existing.private_key=private_key; existing.backed_up=false; } }
        else { if(data.wallets.length >= 1000) fail('Too many saved wallets.'); const entry={id:public_key,public_key,private_key:sealed?null:private_key??null,backed_up:false}; if(sealed) entry.sealed_key=sealed; data.wallets.push(entry); }
        data.selected=public_key; keyAdded=!!sealed;
      },expected);
      keyAdded && touch();
      return result;
    }
    // Every saved key, opened for resealing. Callers wipe the secrets.
    async function openAll(data) {
      const opened=[];
      try { for(const w of data.wallets) if(w.private_key || w.sealed_key) opened.push([w,await secretOf(data,w)]); return opened; }
      catch(error) { for(const [,secret] of opened) secret.fill(0); throw error; }
    }
    // Stores this origin keeps for other chain IDs, for example after a
    // network reset, lie outside this store's passphrase. Count the ones that
    // still hold unencrypted keys, without keeping any of their contents.
    function otherNetworks() {
      let networks=0,keys=0;
      try {
        const storage=root.localStorage,count=storage.length;
        for(let i=0;i<count;i++) {
          const name=storage.key(i);
          if(typeof name!=='string' || !name.startsWith('hashstash.browser-wallet.v1.') || name===storageKey) continue;
          const text=storage.getItem(name);
          if(typeof text!=='string' || text.length>1024*1024) continue;
          let data; try { data=JSON.parse(text); } catch { continue; }
          const found=Array.isArray(data?.wallets) ? data.wallets.filter(w=>typeof w?.private_key==='string' && w.private_key.length>0).length : 0;
          if(found) { networks++; keys+=found; }
        }
      } catch { /* storage that cannot be listed reports none */ }
      return {networks,keys};
    }
    const onStorage=e=>{if(e.key===storageKey || e.key===null) { invalidateMetadata(); notify(); }}; root.addEventListener?.('storage',onStorage);
    return Object.freeze({
      snapshot,
      otherNetworks,
      subscribe(callback) { if(typeof callback!=='function') fail('Invalid wallet subscriber.'); callbacks.add(callback); return ()=>callbacks.delete(callback); },
      // Locking and unlocking change no saved data, so they notify separately.
      onLockChange(callback) { if(typeof callback!=='function') fail('Invalid wallet subscriber.'); lockCallbacks.add(callback); return ()=>lockCallbacks.delete(callback); },
      destroy() { root.removeEventListener?.('storage',onStorage); callbacks.clear(); lockCallbacks.clear(); relock(); invalidateMetadata(); },
      async create(expected) { let secret; do { secret=random(32); } while(!noble.validSecret(secret)); try { return await add(hex(noble.schnorr.getPublicKey(secret)),hex(secret),expected); } finally { secret.fill(0); } },
      importPrivate(privateHex,expected) { const key=publicKey(privateHex); return add(key,privateHex.toLowerCase(),expected); },
      // The scheme is explicit: v2 for passphrase accounts, v1 only to restore legacy ones.
      importPassphrase(passphrase,scheme,expected) {
        const secret=scheme==='hashstash-passphrase-v2' ? derivePrivateV2(passphrase,chainId) : scheme==='hashstash-passphrase-v1' ? derivePrivate(passphrase) : fail('Choose a passphrase scheme.');
        return add(publicKey(secret),secret,expected);
      },
      watch(value,expected) { const key=typeof value==='string' && value.length===78 ? addresses.decode(value,hrp) : hex(publicBytes(value)); publicBytes(key); return add(key,null,expected); },
      select(id,expected) { return change(data=>{if(!data.wallets.some(w=>w.id===id)) fail('Wallet not found.'); data.selected=id;},expected); },
      exportPrivate(id,expected) {
        return locked(async()=>{const data=read();guard(data,expected);const w=data.wallets.find(w=>w.id===id);if(!w?.private_key && !w?.sealed_key)fail('This wallet has no private key.');
          if(w.private_key)return w.private_key;
          const secret=await secretOf(data,w);try{touch();return hex(secret);}finally{secret.fill(0);}});
      },
      acknowledgeBackup(id,expected) { return change(data=>{const w=data.wallets.find(w=>w.id===id);if(!w)fail('Wallet not found.');w.backed_up=true;},expected); },
      // Seal every saved key under a new passphrase: the migration from
      // unencrypted storage, or a passphrase change, which needs the current
      // lock open. Derivation runs before the storage lock is taken.
      async setPassphrase(passphrase,expected) {
        requireSecure();
        if(typeof passphrase!=='string' || [...passphrase.normalize('NFC')].length < MIN_LOCK_PASSPHRASE) fail(`Choose a wallet passphrase of at least ${MIN_LOCK_PASSPHRASE} characters.`);
        const salt=random(16), key=await lockKey(passphrase,salt);
        let lock;
        const result=await change(async data=>{
          if(data.lock && !session(data.lock)) lockedFail('Unlock this browser wallet before changing its passphrase.');
          const opened=await openAll(data);
          try {
            lock={format:LOCK_FORMAT,kdf:LOCK_KDF,iterations:LOCK_ITERATIONS,salt:hex(salt),check:await seal(key,new Uint8Array(0),checkData(salt))};
            const sealed=[];for(const [w,secret] of opened) sealed.push([w,await seal(key,secret,keyData(w.public_key))]);
            for(const [w,value] of sealed) { w.private_key=null; w.sealed_key=value; }
            data.lock=lock;
          } finally { for(const [,secret] of opened) secret.fill(0); }
        },expected);
        unlocked={lock:lockId(lock),key,used:Date.now()};touch();lockChanged();
        return {...result,wallet_locked:false};
      },
      // Return every key to unencrypted storage; the lock must be open.
      async removePassphrase(expected) {
        const result=await change(async data=>{
          if(!data.lock) fail('This browser wallet has no passphrase.');
          if(!session(data.lock)) lockedFail('Unlock this browser wallet before removing its passphrase.');
          const opened=await openAll(data);
          try { for(const [w,secret] of opened) { w.private_key=hex(secret); delete w.sealed_key; } delete data.lock; }
          finally { for(const [,secret] of opened) secret.fill(0); }
        },expected);
        relock();lockChanged();
        return result;
      },
      // Opens the lock for this page only. A key saved unencrypted beside the
      // lock, by older software for example, is sealed at the first unlock.
      async unlock(passphrase) {
        requireSecure();
        const data=read();if(!data.lock) fail('This browser wallet has no passphrase.');
        const salt=fromHex(data.lock.salt,16),key=await lockKey(passphrase,salt);
        if(await unseal(key,data.lock.check,checkData(salt))===null) fail('Wrong passphrase.');
        const id=lockId(data.lock);
        unlocked={lock:id,key,used:Date.now()};touch();
        if(data.wallets.some(w=>w.private_key)) {
          await change(async current=>{
            if(lockId(current.lock)!==id) lockedFail('The wallet passphrase changed in another tab. Unlock again.');
            for(const w of current.wallets) if(w.private_key) { const secret=secretBytes(w.private_key); try { w.sealed_key=await seal(key,secret,keyData(w.public_key)); w.private_key=null; } finally { secret.fill(0); } }
          });
        }
        lockChanged();
        return snapshot();
      },
      lock() { relock(); lockChanged(); return snapshot(); },
      async decryptMail(dataHex,identity,expected) {
        requireSecure(); const data=read(); guard(data,expected);
        if(!expected || expected.wallet_revision===undefined || expected.wallet_id!==data.selected || expected.chain_id!==chainId || identity.chain_id!==chainId) fail('Wallet context changed. Try again.');
        const w=data.wallets.find(w=>w.id===data.selected);
        if(!w?.private_key && !w?.sealed_key) fail('Import this account’s private key locally to open encrypted mail.');
        if(!root.HashstashMailCrypto) fail('Encrypted mail is unavailable.');
        // Background mail scanning does not count as use for the idle lock.
        // A sealed key opens into bytes wiped after each envelope, never into
        // another string.
        const secret=w.sealed_key ? await secretOf(data,w) : null;
        try {
          const result=await root.HashstashMailCrypto.decrypt(dataHex,identity,secret ?? w.private_key);
          guard(read(),expected);
          return result;
        } finally { secret?.fill(0); }
      },
      async signUnsigned(envelope,expected) {
        requireSecure(); const data=read(); guard(data,expected);
        if(!expected || expected.wallet_revision===undefined || expected.wallet_id!==data.selected || hex(bytes32(expected.chain_id))!==chainId) fail('Wallet context changed. Try again.');
        const w=data.wallets.find(w=>w.id===data.selected);
        if(!w?.private_key && !w?.sealed_key) fail('Use the offline signer for this watch-only wallet.');
        if(hex(publicBytes(expected.sender))!==w.public_key) fail('Selected wallet does not authorize this sender.');
        verifyUnsigned(envelope,expected);
        const secret=await secretOf(data,w);let aux;
        try {
          aux=random(32);
          const body=fromHex(envelope.body), signature=noble.schnorr.sign(signingMessage(fromHex(chainId,32),body),secret,aux);
          const raw=concat(body,signature);
          guard(read(),expected);
          touch();
          return {raw:hex(raw),transaction_id:hex(noble.sha256(noble.sha256(raw)))};
        } finally {secret.fill(0);aux?.fill(0);}
      }
    });
  }
  return Object.freeze({createStore,publicKey,derivePrivate,derivePrivateV2,decodeUnsigned,verifyUnsigned,verifySigned});
});
