'use strict';

// Exercise the unmodified browser script through its public DOM events. The

// small DOM/fetch doubles make response ordering deterministic without a browser.

const assert = require('node:assert/strict');

const fs = require('node:fs');

const path = require('node:path');

const vm = require('node:vm');

const { webcrypto } = require('node:crypto');

const parseExact = source => JSON.parse(source, (_key, value, context) => typeof value === 'number' && !Number.isSafeInteger(value) && /^\d+$/.test(context?.source || '') ? context.source : value);

const amounts = require('../ui/amounts.js');

const shares = require('../ui/shares.js');

const addresses = require('../ui/address.js');

const addressHrp = 'hsh' + 'a'.repeat(16);

const addr = (publicKey, hrp = addressHrp) => addresses.encode(publicKey,hrp);

const shortAddr = (publicKey, hrp = addressHrp) => {

  const full = addr(publicKey, hrp), start = full.lastIndexOf('1') + 1;

  return `hsh…${full.slice(start,start+10)}…${full.slice(-6)}`;

};

const byClass = (element, name) => element.children.find(child => (child.className || '').split(' ').includes(name));

const walletEntry = (h, id) => h.get('wallet-switcher-list').children.find(entry => entry.dataset.walletId === id);

const entryBalances = (h, id) => byClass(byClass(walletEntry(h,id), 'wallet-entry-copy'), 'wallet-balances');

const balanceRows = element => element.children.map(row => {

  assert.equal(row.className, 'wallet-balance-row');

  return {

    outcome: byClass(row, 'wallet-balance-outcome')?.textContent || '',

    hash: byClass(row, 'wallet-balance-hash').textContent,

    stash: byClass(row, 'wallet-balance-stash').textContent,

  };

});



const html = fs.readFileSync(path.join(__dirname, '../ui/index.html'), 'utf8');

const source = fs.readFileSync(path.join(__dirname, '../ui/app.js'), 'utf8');

const publicKey = '12'.repeat(32), recipient = '34'.repeat(32);

function deferred() {

  let resolve;

  const promise = new Promise(done => { resolve = done; });

  return { promise, resolve };

}

const settle = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };

const response = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(data) });

const attr = (text, name) => new RegExp(`\\b${name}="([^"]*)"`).exec(text)?.[1];



class Element {

  constructor(id = '') {

    Object.assign(this, { id, value: '', defaultValue: '', textContent: '', hidden: false, disabled: false, required: false, title: '', dataset: {}, elements: {}, options: [], children: [], listeners: new Map(), parentElement: { clientWidth: 0 }, open: false });

    this.classList = { add() {}, remove() {}, toggle() {}, contains() { return false; } };

  }

  addEventListener(type, fn) { if (!this.listeners.has(type)) this.listeners.set(type, []); this.listeners.get(type).push(fn); }
  get textContent() { return (this._text || '') + (this.children || []).map(child=>child.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }

  fire(type, event = {}) { return Promise.all((this.listeners.get(type) || []).map(fn => fn({ preventDefault() {}, target: this, ...event }))); }

  appendChild(child) {
    if (child.parentElement?.children) child.parentElement.children = child.parentElement.children.filter(entry => entry !== child);
    child.parentElement = this; this.children.push(child); this.appendCount = (this.appendCount || 0) + 1; return child;
  }

  append(...children) { for (const child of children) this.appendChild(child); }
  remove() { if(this.parentElement?.children)this.parentElement.children=this.parentElement.children.filter(child=>child!==this); }

  replaceChildren(...children) { this._text = ''; this.children = [...children]; }

  setAttribute(name, value) { if (name === 'required') this.required = true; this[name] = value; }

  removeAttribute(name) { if (name === 'required') this.required = false; else delete this[name]; }

  toggleAttribute(name, value) { this[name] = value; }

  closest() { return this.parentElement; }

  querySelector(selector) { if (selector === '.form-feedback' && this.hasFeedback === false) return null; this.feedback ||= new Element(); return this.feedback; }

  querySelectorAll() { return Object.values(this.elements); }

  reset() { for (const input of Object.values(this.elements)) input.value = input.defaultValue; }

  focus() {}

  showModal() { this.open = true; }

  close() { this.open = false; }

  click() { return this.fire('click'); }

  scrollIntoView() {}

  requestSubmit() {

    this.nativeBlocked = Object.values(this.elements).some(input => input.required && !input.disabled && (input.type==='checkbox'?!input.checked:input.value === ''));

    return this.nativeBlocked ? Promise.resolve() : this.fire('submit');

  }

}



function snapshot(chain = 'a'.repeat(64)) {

  const settings = { block_bytes: 1048576, interval: 15, lead: 60, rest: 480, duration: 240, miner_fee_percent:50, pass_margin_bps:0, minimum_fee_rate:1 };

  const config = { protocol_version:27, network: 'hashstash-ui-test', auction_timeout: 480, quote_scale: '1000000', share_scale: '1000000000000000000' };



  const world = { reserve: '1000', curve_mass: '5000', shares: '1000000000000000000', revenue: '0', grant_escrow: '0', price_integral: '0' };

  return {

    config,

    status: { protocol_version:27, fee_policy:{minimum_fee_rate:'1',fee_scale:1024,account_weight:1024}, chain_id: chain, tip: 'b'.repeat(64), state_root: 'c'.repeat(64), height: 20, clock: 300, time_unit:'seconds', clock_basis:'target_interval', issued: '2000', settings, mempool: 0, reserve: world.reserve, curve_mass: world.curve_mass, shares: world.shares, revenue: '0' },

    governance: { phase: { Auction: { round: 0, opened: 0, leader: null, lead_since: 0 } }, clock: 300, time_unit:'seconds', clock_basis:'target_interval', frozen: settings, settings, world, pass: null },

    account: { account: { ordinary: '1000', shares: '100000000000000000', nonce: 0 }, stash_withdrawal_hash:'409', stash_value_hash: { numerator: '500', denominator: '1' }, price_hash_per_share: { numerator: '5000', denominator: world.shares } },

    pass: null, fail: null, mempool: [], proposals: [],

  };

}



function initialSnapshot() {
  const result = snapshot();
  result.status.height = result.status.clock = result.governance.clock = 0;
  result.status.phase = 'rest';
  result.governance.phase = { Rest: { until: result.status.settings.rest, pending: null } };
  Object.assign(result.governance.world, { reserve: '0', shares: '0', curve_mass: '0' });
  Object.assign(result.status, { reserve: '0', shares: '0', curve_mass: '0' });
  result.account.account.shares = '0';
  result.account.stash_value_hash = { numerator: '0', denominator: '1' };
  result.account.stash_withdrawal_hash = '0';
  return result;
}

async function harness(options = {}) {

  const elements = new Map();

  const get = id => { if (!elements.has(id)) elements.set(id, new Element(id)); return elements.get(id); };

  for (const match of html.matchAll(/\bid="([^"]+)"/g)) get(match[1]);

  for (const match of html.matchAll(/<[a-z][a-z0-9]*\b([^>]*\bid="([^"]+)"[^>]*)>/g)) get(match[2]).hidden = /(?:^|\s)hidden(?:\s|$|=)/.test(match[1]);

  for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*\bid="([^"]+)"[^>]*)>([^<]*)<\/\1>/g)) get(match[3]).textContent = match[4];

  const mineButtons = [...html.matchAll(/<button\b([^>]*)>/g)].filter(match => attr(match[1], 'data-mine')).map(match => {

    const button = new Element(); button.dataset.mine = attr(match[1], 'data-mine'); return button;

  });

  const tradeButtons = [...html.matchAll(/<button\b([^>]*)>/g)].filter(match => attr(match[1], 'data-trade-tab')).map(match => {

    const button = new Element(); button.dataset.tradeTab = attr(match[1], 'data-trade-tab'); return button;

  });

  get('wallet-expiry').value = '100';

  const navLinks = [...html.matchAll(/<a\b([^>]*data-route="[^"]+"[^>]*)>/g)].map(match => {
    const link = new Element(); link.dataset.route = attr(match[1], 'data-route'); return link;
  });
  const forms = [], walletButtons = [], numericInputs = [];

  for (const match of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/g)) {

    const form = get(attr(match[1], 'id')); forms.push(form);
    form.hasFeedback = /class="form-feedback"/.test(match[2]);

    for (const field of match[2].matchAll(/<(input|select|textarea)\b([^>]*)(?:>([\s\S]*?)<\/\1>|>)/g)) {

      const name = attr(field[2], 'name'); if (!name) continue;

      const input = attr(field[2], 'id') ? get(attr(field[2], 'id')) : new Element();

      input.name = name; input.type=attr(field[2], 'type') || ''; input.required = /\brequired\b/.test(field[2]);

      if (field[1] === 'input' && attr(field[2], 'data-exa') === 'true') numericInputs.push(input);

      input.value = attr(field[2], 'value') || (input.type==='checkbox'?'on':'');

      for (const data of field[2].matchAll(/data-([a-z-]+)="([^"]*)"/g)) input.dataset[data[1].replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = data[2];

      if (field[1] === 'select') {

        input.options = [...(field[3] || '').matchAll(/<option\b([^>]*)>/g)].map(option => ({ value: attr(option[1], 'value') || '', disabled: false }));

        input.value = input.options[0]?.value || '';

      }

      input.defaultValue = input.value; form.elements[name] = input;

    }

    for (const buttonMatch of match[2].matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)) {

      const classes = (attr(buttonMatch[1], 'class') || '').split(' ');

      if (!classes.includes('wallet-action')) continue;

      const button = attr(buttonMatch[1], 'id') ? get(attr(buttonMatch[1], 'id')) : new Element();

      button.parentElement = form;

      button.textContent = buttonMatch[2].replace(/<[^>]+>/g, '');

      button.classList.contains = value => classes.includes(value);

      walletButtons.push(button);

    }

  }

  // Model the real shared trading region so moves use browser appendChild semantics.
  const nest = (parent, ...children) => children.forEach(id => get(parent).appendChild(get(id)));
  nest('network-status', 'network-status-line', 'network-phase-progress', 'network-phase-time');
  nest('network-status-line', 'network-phase', 'sidebar-height');
  nest('view-stash', 'curve-panel', 'stash-live', 'stash-revenue-mount');
  nest('stash-live', 'stash-decision-notice', 'stash-trade-mount');
  nest('stash-trade-mount', 'stash-trading');
  nest('stash-trading', 'trade-form');
  nest('curve-panel', 'curve-stage'); nest('curve-stage', 'curve-svg');
  get('curve-stage').clientWidth = 0;

  nest('view-governance', 'governance-live'); nest('governance-live', 'outcome-section');
  nest('outcome-section', 'governance-trading'); nest('governance-trading', 'governance-trade-mount');

  const timers = new Map(); let nextTimer = 0;

  const calls = [], wallet = [], managers = [], storage = [], clipboard = [], downloads = [];

  const h = { get, forms, timers, calls, wallet, managers, storage, clipboard, currentSnapshot: options.initialSnapshot || snapshot(), currentSession: { address_hrp:addressHrp, wallet_enabled: true, wallet_mode:'hot', wallet_id:`hot:${publicKey}`, wallet_revision:0, wallets:[{id:`hot:${publicKey}`,name:'First wallet',public_key:publicKey,mode:'hot'}], public_key: publicKey, miner: publicKey, token: 'old-token' }, handlers: {} };

  h.hasElement = id => elements.has(id);

  h.mineButtons = mineButtons;

  h.tradeButtons = tradeButtons;

  h.walletButtons = walletButtons;
  h.navLinks = navLinks;
  h.grantRow = (index=0) => { const row=get('grant-payments').children[index];return {recipient:row.children[0].children[0],amount:row.children[1].children[0],remove:row.children[2],review:row.children[3]}; };

  h.downloads = downloads;
  h.publicWeb = !!options.publicWeb;
  h.faucetCalls = [];
  h.faucetTransport = options.faucetTransport;

  if (options.empty) {

    h.currentSession = {...h.currentSession,wallet_id:null,public_key:null,wallet_mode:'none',wallet_enabled:false,wallets:[]};

    h.currentSnapshot.account = h.currentSnapshot.pass = h.currentSnapshot.fail = null;

  }

  h.selectSession = (selected, revision = h.currentSession.wallet_revision + 1) => {

    const wallets = [...h.currentSession.wallets];

    if (!wallets.some(wallet => wallet.id === selected.id)) wallets.push(selected);

    h.currentSession = {...h.currentSession,wallets,wallet_id:selected.id,wallet_revision:revision,public_key:selected.public_key,wallet_mode:selected.mode,wallet_enabled:selected.mode === 'hot'};

  };

  h.defaultManage = body => {

    if (body.revision !== h.currentSession.wallet_revision) return response({error:'Wallet changed'},409);

    if (body.action === 'export') return response({format:'hashstash-private-v1',private_key:'56'.repeat(32),public_key:h.currentSession.public_key});

    let selected;

    if (body.action === 'select') selected = h.currentSession.wallets.find(wallet => wallet.id === body.id);

    else {

      const mode = body.action === 'watch' ? 'watch' : 'hot';

      const key = mode === 'watch' ? body.public_key : body.action === 'create' ? '78'.repeat(32) : '9a'.repeat(32);

      if (body.action === 'import' && body.public_key && body.public_key !== key) return response({error:'Backup public key does not match'},400);

      selected = h.currentSession.wallets.find(wallet => wallet.id === `${mode}:${key}`) || {id:`${mode}:${key}`,name:body.name || `${mode === 'watch' ? 'Watch' : 'Wallet'} ${key.slice(0,8)}`,public_key:key,mode};

    }

    if (!selected) return response({error:'Unknown wallet'},400);

    if (selected.id !== h.currentSession.wallet_id) h.selectSession(selected);

    const {token,miner,...selection} = h.currentSession;

    return response(selection);

  };

  h.snapshotResult = (params = {}) => {

    if (Object.hasOwn(h.currentSnapshot, 'balances')) return h.currentSnapshot;

    const balances = {};

    for (const requested of params.keys || []) {

      const active = requested === (h.browserStore?.snapshot() || h.currentSession).public_key?.toLowerCase();

      balances[requested] = Object.fromEntries(['account','pass','fail'].map(outcome => {

        const data = h.currentSnapshot[outcome];
        const account = active ? data === null ? null : data?.account : null;

        return [outcome, account ? {ordinary:account.ordinary, shares:account.shares} : account];

      }));

    }

    return {...h.currentSnapshot, balances};

  };

  h.stashQuote = (params = {}, overrides = {}) => {

    const account = params.outcome === 'Pass' ? h.currentSnapshot.pass : params.outcome === 'Fail' ? h.currentSnapshot.fail : h.currentSnapshot.account;

    const before = BigInt(account?.stash_withdrawal_hash || '0');

    const owned = BigInt(account?.account.shares || '0');

    const kind = params.kind || 'deposit', isRedeem = kind === 'redeem';

    const amount = params.all ? (isRedeem ? owned : before) : BigInt(params.amount || '0');

    const quotedShares = isRedeem ? amount : params.all ? owned : amount * 100n;

    let output = amount, after = kind === 'withdraw' ? (before > amount ? before - amount : 0n) : before + amount;

    if (isRedeem) {

      if (amount > owned) throw new Error('Insufficient stash');

      const world = params.outcome === 'Pass' ? h.currentSnapshot.governance.pass : h.currentSnapshot.governance.world;

      const reserve = BigInt(world.reserve), supply = BigInt(world.shares);

      const redeem = (r, s, burn) => s ? r - (r * (s - burn) ** 5n + s ** 5n - 1n) / s ** 5n : 0n;

      output = redeem(reserve, supply, amount);

      after = redeem(reserve - output, supply - amount, owned - amount);

    }

    const shareAfter = kind === 'deposit' ? owned + quotedShares : owned - quotedShares;

    return {

      kind, amount:String(amount), shares:String(quotedShares), share_before:String(owned), share_after:String(shareAfter),

      output_hash:String(output), stash_before_hash:String(before), stash_after_hash:String(after),

      decision:h.currentSnapshot.governance.phase.Governance?.id || null, height:h.currentSnapshot.status.height,

      tip:h.currentSnapshot.status.tip, state_root:h.currentSnapshot.status.state_root, transaction_fee_included:false, ...overrides,

    };

  };

  h.fee = (params={}) => {
    const {chain_id,tip,state_root,height,settings}=h.currentSnapshot.status;
    const rate=BigInt(settings.minimum_fee_rate),recipients=BigInt(params.operation?.Propose?.proposal?.Grant?.payments?.length||0),weight=512n+1024n*recipients,base=(rate*weight+1023n)/1024n,paid=params.fee===undefined?base+BigInt(params.extra_fee||'0'):BigInt(params.fee),priority=String(paid-base),data=params.data_hex||'',percent=settings.miner_fee_percent,miner=paid*BigInt(percent)/100n;
    return {chain_id,tip,state_root,height,sender:addr(params.sender),sender_public_key:params.sender,fee:String(paid),minimum_fee:String(base),account_creation_fee:'0',grant_recipient_fee:String(rate*recipients),extra_fee:priority,weight:String(weight),minimum_fee_rate:String(rate),miner_fee_percent:percent,miner_fee:String(miner),revenue_fee:String(paid-miner),data_hex:data,data_bytes:data.length/2};
  };
  h.transferQuote = (params={},overrides={}) => {
    const f=h.fee(params);return {...f,recipient:addr(params.recipient),public_key:params.recipient,amount:params.amount,recipient_receives:params.amount,total_debit:String(BigInt(params.amount)+BigInt(f.fee)),pending:false,...overrides};
  };
  const windowEvents = new Map();

  h.wallClock = 1791500000000;

  const context = {

    console, HashstashAmounts: amounts, HashstashShares:shares, HashstashAddress:addresses, TextEncoder, TextDecoder, Uint8Array, crypto: webcrypto,
    HashstashBrowserWallet: {
      publicKey() { return '9a'.repeat(32); },
      verifyUnsigned(envelope) {
        if (envelope?.format !== 'hashstash-unsigned-v1' || !/^[a-f0-9]+$/i.test(envelope.body || '') || envelope.body.length % 2) throw new Error('The node returned an invalid unsigned transaction.');
      },
      createStore() {
        const manage = async (action, values, guard) => {
          const body = {action, ...values, revision:guard.wallet_revision}; managers.push(body);
          const reply = await (h.handlers.manage ? h.handlers.manage(body) : h.defaultManage(body));
          const data = JSON.parse(await reply.text());
          if (!reply.ok || data.error) throw new Error(data.error || 'Wallet action failed');
          return action === 'export' ? data.private_key : data;
        };
        return {
          snapshot: () => { const {wallets,wallet_id,wallet_revision,public_key,wallet_enabled,wallet_mode} = h.currentSession; return {wallets,wallet_id,wallet_revision,public_key,wallet_enabled,wallet_mode}; },
          subscribe(callback) { h.emitStoreChange = callback; return () => {}; },
          create: guard => manage('create', {}, guard),
          importPrivate: (private_key, guard) => manage('import', {private_key}, guard),
          watch: (public_key, guard) => manage('watch', {public_key}, guard),
          select: (id, guard) => manage('select', {id}, guard),
          exportPrivate: (id, guard) => manage('export', {id}, guard),
          async acknowledgeBackup() {},
          decryptMail: (...args) => h.decryptMail(...args),
          async signUnsigned(envelope, expected) {
            const { operation, fee, data_hex, expiry_blocks, sender, wallet_revision } = expected;
            const body = parseExact(JSON.stringify({operation, fee, ...(data_hex ? {data_hex} : {}), expiry_blocks, expected_sender:sender, wallet_revision}));
            wallet.push(body);
            const reply = h.handlers.wallet ? await h.handlers.wallet(body) : response({transaction_id:'d'.repeat(64)});
            const data = JSON.parse(await reply.text());
            if (!reply.ok || data.error) throw new Error(data.error || 'Local signing failed');
            return {raw:'ab'.repeat(96),transaction_id:data.transaction_id};
          },
        };
      },
    },

    Date: class extends Date {

      constructor(...args) { super(...(args.length ? args : [h.wallClock])); }

      static now() { return h.wallClock; }

    },

    Blob: class {constructor(parts) {this.content=parts.join('');}},

    URL: {createObjectURL(blob) {downloads.push(blob.content);return 'blob:local-test';},revokeObjectURL(){}},

    location: { hash: options.hash || '#overview' }, navigator: { clipboard: { writeText: async value => { clipboard.push(value); } } },

    localStorage: { getItem() { return null; }, setItem(key,value) { storage.push({key,value}); } },

    document: {

      getElementById: get,

      querySelectorAll(selector) {

        if (selector === 'form') return forms;

        if (selector === '[data-mine]') return mineButtons;

        if (selector === '[data-trade-tab]') return tradeButtons;
        if (selector === '[data-route]') return navLinks;

        if (selector === 'input[data-exa]') return numericInputs;

        if (selector === '.wallet-action') return walletButtons;

        if (selector === '.view') return [...elements.values()].filter(element => element.id.startsWith('view-'));

        return [];

      },

      createElement: tag => Object.assign(new Element(), {tagName:tag.toUpperCase()}), createElementNS: () => new Element(),
      createTextNode: text => ({textContent:String(text),nodeType:3}),

    },

    window: { addEventListener(name,fn) {windowEvents.set(name,fn);}, scrollTo() {} },

    FormData: class { constructor(form) { this.form = form; } *[Symbol.iterator]() { for (const [name, input] of Object.entries(this.form.elements)) yield [name, input.value]; } },

    setTimeout(fn, delay) { timers.set(++nextTimer, { fn, delay }); return nextTimer; },

    clearTimeout(id) { timers.delete(id); }, setInterval() { return 0; },

    async fetch(url, options = {}) {

      if (url === '/api/session') return response({...h.currentSession,chain_id:h.currentSnapshot.status.chain_id,public_web:h.publicWeb,browser_wallet:true});
      if (url === '/faucet-config.json' || url.startsWith('https://')) {
        h.faucetCalls.push({url,options});
        return h.faucetTransport ? h.faucetTransport(url,options) : response({},404);
      }

      const body = parseExact(options.body); calls.push({ url, body, options });

      if (url === '/api/wallet' || url === '/api/wallet/manage') throw new Error('Browser wallets must not call server key endpoints');

      const method = body.method;

      if (h.handlers[method]) return h.handlers[method](body.params, body);

      if (method === 'snapshot') return response({ result: h.snapshotResult(body.params) });

      if (method === 'stash_quote') return response({result:h.stashQuote(body.params)});

      if (method === 'transfer_quote') return response({result:h.transferQuote(body.params)});
      if (method === 'fee_quote') return response({result:h.fee(body.params)});

      if (method === 'account') return response({ result: { account: { ordinary: '1' } } });

      if (method === 'grant_quote') return response({ result: { feasible: true } });

      if (method === 'mine') return response({ result: {} });

      if (method === 'preparetransaction') return response({result:{format:'hashstash-unsigned-v1',body:'abcdef'}});
      if (method === 'broadcasttransaction') return response({result:{transaction_id:'d'.repeat(64)}});

      throw new Error(`Unexpected RPC ${method}`);

    },

  };

  if(options.mail&&!options.realWallet){
    const saved=options.savedMail||new Map();h.savedMail=saved;
    context.localStorage={getItem:key=>saved.get(key)??null,setItem:(key,value)=>saved.set(key,value),removeItem:key=>saved.delete(key)};
  }
  if (options.realWallet) {
    const saved = options.savedStorage || new Map(); h.savedStorage = saved;
    context.localStorage = {getItem:key=>saved.get(key) ?? null,setItem:(key,value)=>saved.set(key,value),removeItem:key=>saved.delete(key)};
    context.isSecureContext = true;
    Object.assign(context.location, {hostname:'wallet.example',protocol:'https:'});
    context.navigator.locks = {request:async (_name,callback)=>callback()};
    context.addEventListener = (name,callback)=>windowEvents.set(name,callback);
    context.removeEventListener = (name,callback)=>{if(windowEvents.get(name)===callback)windowEvents.delete(name);};
  }
  vm.createContext(context);
  if (options.realWallet) {
    for (const name of ['vendor/noble.js','browser-wallet.js']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui',name),'utf8'),context,{filename:name});
    h.browserApi=context.HashstashBrowserWallet; h.noble=context.HashstashNoble;
    h.browserStore=h.browserApi.createStore(h.currentSnapshot.status.chain_id);
    h.storageChanged=()=>windowEvents.get('storage')?.({key:null});
  }
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/proposal-data.js'),'utf8'),context,{filename:'proposal-data.js'});
  if (options.chat) vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/chat.js'),'utf8'),context,{filename:'chat.js'});
  if (options.mail || options.rationale) {
    context.isSecureContext=true;
    for(const name of ['vendor/noble.js','mail-crypto.js','proposal-data.js']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui',name),'utf8'),context,{filename:name});
    h.noble=context.HashstashNoble;h.mailCrypto=context.HashstashMailCrypto;h.proposalData=context.HashstashProposalData;
    if(options.mail) {
      const walletDouble=context.HashstashBrowserWallet;
      vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/browser-wallet.js'),'utf8'),context,{filename:'browser-wallet.js'});
      h.mailWalletApi=context.HashstashBrowserWallet;
      if(!options.realWallet)context.HashstashBrowserWallet={...walletDouble,verifySigned:h.mailWalletApi.verifySigned};
      vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/mail.js'),'utf8'),context,{filename:'mail.js'});
    }
  }
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui/transaction-mail.js'),'utf8'),context,{filename:'transaction-mail.js'});
  vm.runInContext(source, context, { filename: 'app.js' });

  await settle();

  assert.equal(get('connection-label').textContent, 'Connected', get('global-alert').textContent);

  h.timersDue = async (maximum = 500) => {

    const due = [...timers.entries()].filter(([, timer]) => timer.delay <= maximum);

    for (const [id, timer] of due) { timers.delete(id); timer.fn(); }

    await settle();

  };

  h.refresh = async () => { await get('refresh-now').fire('click'); await settle(); };

  h.location = context.location;

  h.navigate = async hash => { context.location.hash = hash; windowEvents.get('hashchange')?.(); await settle(); };

  h.chooseWallet = async id => {

    await get('account-select').click();

    const button = get('wallet-switcher-list').children.find(item => item.dataset.walletId === id);

    assert.ok(button, `wallet switcher contains ${id}`);

    await button.click(); await settle();

  };

  h.tradeTab = async kind => {

    const button = tradeButtons.find(item => item.dataset.tradeTab === kind);

    assert.ok(button, `Stash action ${kind} exists`);

    await button.click(); await settle();

  };

  return h;

}



async function run() {
 let checks=0;const eq=(a,b,m)=>{assert.deepEqual(a,b,m);checks++;},ok=(v,m)=>{assert.ok(v,m);checks++;};
 {
  const direct=await harness(),form=direct.get('send-form');
  await direct.navigate('#names');eq(direct.get('view-overview').hidden,false,'retired routes fall back to Home');
  ok(!direct.navLinks.some(link=>link.dataset.route==='names'),'no retired application navigation');
  form.elements.recipient.value='@Alice';form.elements.amount.value=amounts.exactInput('10');
  await form.fire('input');await direct.timersDue();await form.requestSubmit();
  eq(direct.wallet.length,0,'a recipient alias cannot be signed');
  ok(!direct.calls.some(call=>/^explorer_names?$/.test(call.body.method)),'invalid recipients never trigger remote alias lookup');
  form.elements.recipient.value=addr(recipient);form.elements.data_format.value='text';form.elements.data_text.value='name:Alice';
  await form.fire('input');await direct.timersDue();await direct.timersDue();await form.requestSubmit();
  eq(direct.wallet.length,1,form.feedback.textContent);
  eq(direct.wallet[0].data_hex,Buffer.from('name:Alice').toString('hex'),'former registration syntax remains ordinary signed data');
  eq(Buffer.from(direct.wallet[0].operation.TransferExact.recipient).toString('hex'),recipient,'the entered address determines the recipient');
 }
 const h=await harness(), s=h.currentSnapshot;
 eq(h.get('connection-label').textContent,'Connected');
 eq(h.get('proposal-parameter').options.map(o=>o.value),['BlockBytes','Interval','Lead','Rest','Duration','MinerFeePercent','PassMarginBps','MinimumFeeRate']);
 ok(!/legacy-fee|guide-clockfree-mining|UncleFinder|DifficultyFloor/.test(html));
 eq(h.get('network-phase-label').textContent,'Auction');
 eq(h.get('sidebar-height-value').textContent,'20');
 eq(h.get('sidebar-height').href,'#explorer?block=20');
 ok(h.get('guide-difficulty').textContent.includes('Only blocks on the accepted chain create new hashes'));
 ok(h.get('guide-fees').textContent.includes('entire fee'));
 await h.navigate('#guide');eq(h.get('guide-overview-panel').hidden,false);eq(h.get('guide-technical-panel').hidden,true);
 await h.get('guide-technical-tab').click();eq(h.get('guide-overview-panel').hidden,true);eq(h.get('guide-technical-panel').hidden,false);eq(h.get('guide-technical-tab')['aria-selected'],'true');eq(h.get('guide-overview-tab').tabIndex,-1);
 await h.get('guide-technical-tab').fire('keydown',{key:'Home'});eq(h.get('guide-overview-panel').hidden,false);eq(h.get('guide-technical-panel').hidden,true);eq(h.get('guide-overview-tab').tabIndex,0);
 await h.navigate('#governance');
 const values = {
  BlockBytes:['1024','1537','33554433','18446744073709551615'],
  Interval:['1','61','9007199254740993','18446744073709551615'],
  Lead:['0','17','18446744073709551615'], Rest:['0','19','18446744073709551615'],
  Duration:['1','73','18446744073709551615'], MinerFeePercent:['0','37','100'],
  PassMarginBps:['0.01','150.01','184467440737095516.15'], MinimumFeeRate:['0','3','18446744073709551615']
 };
 const settingNames={BlockBytes:'block_bytes',Interval:'interval',Lead:'lead',Rest:'rest',Duration:'duration',MinerFeePercent:'miner_fee_percent',PassMarginBps:'pass_margin_bps',MinimumFeeRate:'minimum_fee_rate'};
 for(const [parameter,inputs] of Object.entries(values)) for(const value of inputs) {
  const form=h.get('propose-form'),before=h.wallet.length;form.elements.type.value='parameter';form.elements.parameter.value=parameter;form.elements.parameter_value.value=value;form.elements.support.value=amounts.exactInput('1');
  await h.get('proposal-parameter').fire('change');await form.fire('input');await h.timersDue();await form.requestSubmit();
  eq(h.wallet.length,before+1,`${parameter}=${value}: ${form.feedback.textContent}`);
  const [whole,fraction='']=value.split('.'),next=parameter==='PassMarginBps'?BigInt(whole)*100n+BigInt(fraction.padEnd(2,'0')):BigInt(value);
  eq(h.wallet.at(-1)?.operation.Propose.proposal.Parameter,{parameter,old:s.status.settings[settingNames[parameter]],new:next>BigInt(Number.MAX_SAFE_INTEGER)?String(next):Number(next)});
 }
 ok(!/proposal-direction|proposal-miner-fee|halve|double|1–60/.test(html),'all settings use one direct value field');
 for(const [parameter,value] of [['BlockBytes','1023'],['BlockBytes','0'],['Interval','0'],['Duration','0'],['MinerFeePercent','101'],['Lead','-1'],['Rest','1.5'],['MinimumFeeRate','18446744073709551616'],['PassMarginBps','184467440737095516.16'],['PassMarginBps','0.001'],['Interval','15']]) {
  const count=h.wallet.length,form=h.get('propose-form');form.elements.parameter.value=parameter;form.elements.parameter_value.value=value;
  await form.fire('input');await h.timersDue();await form.requestSubmit();eq(h.wallet.length,count,`${parameter}=${value} cannot sign`);
 }
 {
  const zero=await harness(),form=zero.get('send-form');zero.currentSnapshot.status.settings.minimum_fee_rate=0;await zero.refresh();
  form.elements.recipient.value=addr(recipient);form.elements.amount.value=amounts.exactInput('10');
  await form.fire('input');await zero.timersDue();await form.requestSubmit();
  eq(zero.wallet.length,1,form.feedback.textContent);eq(zero.wallet[0].fee,'0','zero rate permits a zero fee');
 }
 {
  const large=await harness(),form=large.get('propose-form');large.currentSnapshot.status.settings.rest='18446744073709551615';large.currentSnapshot.status.settings.block_bytes='18446744073709551615';await large.refresh();
  form.elements.type.value='parameter';form.elements.parameter.value='Rest';form.elements.parameter_value.value='9007199254740993';form.elements.support.value=amounts.exactInput('1');
  await form.fire('input');await large.timersDue();await form.requestSubmit();
  eq(large.wallet.at(-1)?.operation.Propose.proposal.Parameter,{parameter:'Rest',old:'18446744073709551615',new:'9007199254740993'},'both old and new retain exact u64 digits');
  ok(large.get('network-settings').textContent.includes('18,446,744,073,709,551,615'),'network setting display retains every digit');
 }
 const count=h.wallet.length, form=h.get('propose-form');form.elements.parameter.value='UncleFinderPercent';await form.fire('submit');eq(h.wallet.length,count);
 const initial=initialSnapshot();h.currentSnapshot=initial;await h.refresh();
 eq(h.get('network-phase-label').textContent,'Rest');ok(h.get('network-phase-time').textContent.includes('32 blocks'));
 eq(h.get('overview-price').textContent,'1');eq(h.get('curve-price').textContent,'1');eq(h.get('reserve-ratio').textContent,'100% reserve ratio');
 eq(h.get('stash-live').hidden,false);eq(h.get('governance-live').hidden,false);
 const trade=h.get('trade-form');await h.tradeTab('deposit');trade.elements.amount.value=amounts.exactInput('10');await h.get('trade-amount').fire('input');await h.timersDue();await h.timersDue();
 eq(h.get('trade-submit').disabled,false,'initial rest permits a funded account to deposit');
 await trade.requestSubmit();eq(h.wallet.at(-1)?.operation.Deposit.amount,'10');
 eq(initial.account.account.ordinary,'1000','refresh and preparation never convert account hashes');
 eq(h.walletButtons.find(button=>button.closest('form')?.id==='propose-form').disabled,true,'initial rest still delays proposal submission');
 const visitor=await harness({empty:true});visitor.currentSnapshot=initialSnapshot();visitor.currentSnapshot.account=null;await visitor.refresh();await visitor.navigate('#stash');
 eq(visitor.get('view-stash').hidden,false,'the initial Stash page is visible without a wallet');
 eq(visitor.get('stash-live').hidden,false);eq(visitor.get('curve-price').textContent,'1');
 eq(visitor.get('trade-submit').disabled,true,'a visitor must select and fund a wallet before signing a deposit');
 h.currentSnapshot=s;await h.refresh();
 h.handlers.snapshot=()=>response({error:{message:'offline'}});await h.refresh();eq(h.get('sidebar-height-value').textContent,'—');eq(h.get('network-status').dataset.ready,'false');
 delete h.handlers.snapshot;s.status.height=1234;await h.refresh();eq(h.get('sidebar-height-value').textContent,'1,234');eq(h.get('sidebar-height').href,'#explorer?block=1234');
 s.status.height=1229;s.status.tip='e'.repeat(64);await h.refresh();eq(h.get('sidebar-height-value').textContent,'1,229');
 s.config.protocol_version=18;await h.refresh();eq(h.get('connection-label').textContent,'Offline');ok(h.get('global-alert').textContent.includes('Unsupported protocol'));
 {
  const personal=await harness(),state=personal.currentSnapshot;
  const pending=(sender,amount,nonce=0)=>({body:{sender,nonce,operation:{TransferExact:{recipient:publicKey,amount}}}});
  state.mempool=[pending(recipient,'700')];state.status.mempool=1;await personal.refresh();
  eq(personal.get('activity-panel').hidden,true,'another account’s pending transfer does not appear on Home');
  ok(!personal.get('activity-list').textContent.includes(amounts.formatHash('700')));
  personal.selectSession({id:`watch:${recipient}`,public_key:recipient,mode:'watch'});await personal.refresh();
  eq(personal.get('activity-panel').hidden,false,'switching to its sender reveals that account’s pending transfer');
  eq(personal.get('activity-list').children.length,1);
  ok(personal.get('activity-list').textContent.includes(amounts.formatHash('700')));
  state.mempool.push(pending(publicKey,'200',1));state.status.mempool=2;
  personal.selectSession({id:`hot:${publicKey}`,public_key:publicKey,mode:'hot'});await personal.refresh();
  eq(personal.get('activity-list').children.length,1,'each account sees only its own pending sends');
  ok(personal.get('activity-list').textContent.includes(amounts.formatHash('200')));
  ok(!personal.get('activity-list').textContent.includes(amounts.formatHash('700')));
  eq(personal.get('metric-pending').textContent,'2','network pending totals remain global');
  personal.selectSession({id:'watch:third',public_key:'56'.repeat(32),mode:'watch'});await personal.refresh();
  eq(personal.get('activity-panel').hidden,true,'a third account with no pending sends gets no global fallback');
  eq(personal.wallet.length,0,'reading and switching personal activity cannot sign or submit');
 }
 console.log(`Wallet UI: ${checks} current-protocol assertions passed.`);
}

if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = {harness,response,settle,addr,deferred};

