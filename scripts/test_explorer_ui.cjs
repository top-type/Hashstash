'use strict';
const assert = require('node:assert/strict');
global.HashstashAmounts = require('../ui/amounts.js');
global.HashstashShares = require('../ui/shares.js');
global.HashstashAddress = require('../ui/address.js');
const { create } = require('../ui/explorer.js');
const chain = 'a'.repeat(64), blockHash = 'b'.repeat(64), txid = 'd'.repeat(64), publicKey = '12'.repeat(32), proposal = 'e'.repeat(64);
const address = HashstashAddress.encode(publicKey, 'hsh' + chain.slice(0, 16));
const settle = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = {}; this.dataset = {}; this.hidden = false; this.attributes = {}; this.classes = new Set(); this.value = ''; this.classList = { toggle: (c, on) => on ? this.classes.add(c) : this.classes.delete(c) }; }
  set textContent(value) { this.valueText = String(value); this.children = []; }
  get textContent() { return (this.valueText || '') + this.children.map(c => c.textContent).join(''); }
  set innerHTML(_) { throw new Error('Explorer must not parse HTML'); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; this.valueText = ''; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  fire(name) { return this.listeners[name]?.({ preventDefault() {} }); }
  querySelectorAll(tag) { return this.children.flatMap(walk).filter(node => node.tagName === tag); }
  querySelector(tag) { return this.querySelectorAll(tag)[0] || null; }
}
const walk = element => [element, ...element.children.flatMap(walk)];
const links = h => walk(h.content).filter(n => n.tagName === 'a');
const ctx = { chain_id: chain, tip: blockHash, height: 12, state_root: 'c'.repeat(64) };
const block = { height: 12, hash: blockHash, previous: 'c'.repeat(64), state_root: 'f'.repeat(64), miner: address, expected_hashes: '1000000000000', subsidy: '1000000000000', difficulty: 232.83, body_bytes: 500, transaction_count: 1, phase: 'auction', status: 'confirmed', header: { nonce: 42 }, rewards: { subsidy: '1000000000000', extra_fees: '6', minimum_fees: '3', miner_total: '1000000000006' } };
const tx = { txid, kind: 'transfer', status: 'confirmed', height: 12, block_hash: blockHash, confirmations: 1, sender: address, recipient: address, amount: '1000', asset: 'hash', nonce: 0, fee: '9', minimum_fee: '3', extra_fee: '6', expiry_height: 30, operation: { TransferExact: { recipient: Array(32).fill(18), amount: '1000' } }, data_hex: '', data_bytes: 0, size_bytes: 200 };
function harness() {
  const elements = new Map(), get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const tabs = ['blocks', 'transactions', 'governance'].map(value => { const node = new Element('a'); node.dataset.explorerTab = value; return node; });
  const document = { getElementById: get, createElement: tag => new Element(tag), querySelectorAll: () => tabs };
  const location = { hash: '#explorer' }, calls = [];
  const replies = {
    explorer_blocks: { ...ctx, blocks: [block], next_before_height: 12 },
    explorer_block: { ...ctx, block, transactions: [tx], next_tx_offset: null },
    explorer_transaction: { ...ctx, transaction: tx },
    explorer_transactions: { ...ctx, transactions: [tx], pending: [], next_cursor: '12:0' },
    explorer_account: { ...ctx, address, public_key: publicKey, account: { ordinary: '1000', shares: '2000000000000000000', nonce: 1 }, stash_value_hash: { numerator: '3000', denominator: '1' }, stash_withdrawal_hash: '2000', history: [{ height: 12, block_hash: blockHash, kind: 'mining_reward', amount: '1000000000000', asset: 'hash' }], pending: [], next_cursor: null },
    explorer_governance: { ...ctx, phase: 'rest', proposals: [{ id: proposal, round: 0, description: 'f'.repeat(64), action: { Grant: { payments: [{recipient:Array(32).fill(18),amount:'1000'}] } }, support: '100', created_height: 5 }], decisions: [{ id: 'f'.repeat(64), proposal, started: 105, started_height: 7, ended_height: 10, outcome: 'pass', blocks:3, observed_blocks:3, leading_blocks:2, blocks_remaining:0, pass_margin_bps: 0 }], contributions: [{ txid, height: 5, sender: address, amount: '100' }], next_cursor: null, next_before_height: null },
  };
  const api = create({ document, location, amountText: (n, value) => { n.textContent = value; }, rpc: async (method, params) => { calls.push({ method, params }); const value = replies[method]; if (typeof value === 'function') return value(params); if (value instanceof Error) throw value; return value; } });
  return { get, location, calls, replies, api, tabs, content: get('explorer-content'), navigate: async hash => { location.hash = hash; api.route(); await settle(); } };
}
async function run() {
  let checks = 0;
  const h = harness();
  h.api.route(); assert.match(h.get('explorer-message').textContent, /Waiting/); checks++;
  h.api.update({ ready: true, ...ctx }); await settle();
  assert.match(h.content.textContent, /Latest blocks/); checks++;
  assert.match(h.content.textContent, /0\.000001 EH/); checks++;
  assert.ok(walk(h.content).some(n => n.textContent === '0.000001 EH' && n.title === '0.000001 EH'), 'work uses fixed EH units with an exact EH tooltip'); checks++;
  assert.equal(h.calls[0].method, 'explorer_blocks'); checks++;
  assert.equal(h.calls.some(c => c.params.key || c.params.sender), false, 'Explorer does not require a selected wallet'); checks++;
  assert.ok(links(h).some(n => n.href === '#explorer?block=12')); checks++;
  assert.ok(links(h).some(n => n.href === '#explorer?before_height=12')); checks++;

  await h.navigate('#explorer?block=12');
  assert.match(h.content.textContent, /Confirmed/); checks++;
  assert.match(h.content.textContent, /Rewards and fees/); checks++;
  assert.match(h.content.textContent, /Above minimum0\.000000000000000006 hash/); checks++;
  assert.ok(walk(h.content).some(n => n.textContent === '0.000001 hash' && n.title === '0.000001000000000006 hash'), 'rounded reward retains every paid hash in its tooltip'); checks++;
  for (const percent of [0, 50, 100]) {
    const miner = 9n * BigInt(percent) / 100n, revenue = 9n - miner;
    h.replies.explorer_block = { ...ctx, block: { ...block, rewards: { ...block.rewards, miner_fees: String(miner), revenue_fees: String(revenue), miner_total: String(1000000000000n + miner) } }, transactions: [tx] };
    await h.navigate('#explorer?block=12');
    assert.ok(h.content.textContent.includes('Miner fee allocation' + HashstashAmounts.formatExactHash(String(miner)))); checks++;
    assert.ok(h.content.textContent.includes('Revenue fee allocation' + HashstashAmounts.formatExactHash(String(revenue)))); checks++;
    assert.match(h.content.textContent, /Above minimum0\.000000000000000006 hashMinimum fees0\.000000000000000003 hash/); checks++;
    assert.equal(h.content.textContent.includes('Miner priority'), false); checks++;
  }
  h.replies.explorer_block = { ...ctx, block: { ...block, status: 'orphaned' }, transactions: [{ ...tx, status: 'orphaned' }] };
  await h.navigate('#explorer?block=' + blockHash);
  assert.match(h.content.textContent, /Orphaned/); checks++;
  assert.match(h.content.textContent, /Recorded rewards/); checks++;
  assert.equal(h.content.textContent.includes('Rewards and fees'), false); checks++;
  const hostile = '<script>alert("x")</script><img src=x onerror=alert(1)>', raw = Buffer.from(hostile).toString('hex');
  h.replies.explorer_transaction = { ...ctx, transaction: { ...tx, status: 'pending', height: null, block_hash: null, confirmations: 0, fee_estimated: true, data_hex: raw } };
  await h.navigate('#explorer?tx=' + txid);
  assert.match(h.content.textContent, /Pending/); checks++;
  assert.match(h.content.textContent, /Signed fee/); checks++;
  assert.equal(links(h).some(n => n.href === '#explorer?block=null'), false); checks++;
  assert.ok(walk(h.content).some(n => n.tagName === 'pre' && n.textContent === hostile)); checks++;
  assert.equal(walk(h.content).some(n => ['script', 'img', 'iframe'].includes(n.tagName)), false); checks++;
  for (const status of ['pending','confirmed']) {
    const message='name:<img src=x onerror=alert(1)>';
    h.replies.explorer_transaction={...ctx,transaction:{...tx,status,data_hex:Buffer.from(message).toString('hex')}};
    await h.navigate('#explorer?tx='+txid);
    assert.ok(walk(h.content).some(n=>n.tagName==='pre'&&n.textContent===message),'former registration data is ordinary public text');checks++;
    assert.equal(h.content.textContent.includes('registration'),false,'no registration result is invented from the data prefix');checks++;
    assert.equal(walk(h.content).some(n=>n.tagName==='img'),false,'ordinary data is text escaped');checks++;
  }
  h.replies.explorer_transaction = { ...ctx, transaction: { ...tx, status: 'orphaned', confirmations: 0 } };
  await h.navigate('#explorer?tx=' + txid);
  assert.match(h.content.textContent, /Recorded fee0\.000000000000000009 hash/); checks++;
  assert.equal(h.content.textContent.includes('Fee paid'), false); checks++;

  for (const kind of ['deposit','redeem']) for (const fill of ['full','partial','unfilled']) {
    const input=fill==='full'?'1000':fill==='partial'?'400':'0',output=String(BigInt(input)*2n),asset=kind==='deposit'?'hash':'stash';
    h.replies.explorer_transaction={...ctx,transaction:{...tx,kind,amount:input,asset,input_requested:'1000',input_filled:input,input_unfilled:String(1000n-BigInt(input)),output,output_asset:kind==='deposit'?'shares':'hash',fill_status:fill,operation:{[kind==='deposit'?'Deposit':'Redeem']:{[kind==='deposit'?'amount':'shares']:'1000'}}}};
    await h.navigate('#explorer?tx='+txid);
    assert.match(h.content.textContent,/Filled input/);checks++;
    assert.match(h.content.textContent,/Requested input/);checks++;
    assert.match(h.content.textContent,/Unfilled input returned/);checks++;
    assert.match(h.content.textContent,kind==='deposit'?/Received[^A-Za-z]*stash/:/Received[^A-Za-z]*hash/,'received output uses its actual asset denomination');checks++;
    assert.ok(h.content.textContent.includes({full:'FillFilled',partial:'FillPartial fill',unfilled:'FillUnfilled'}[fill]));checks++;
  }
  h.replies.explorer_transaction={...ctx,transaction:{...tx,kind:'deposit',status:'pending',operation:{Deposit:{amount:'1000'}}}};
  await h.navigate('#explorer?tx='+txid);
  assert.match(h.content.textContent,/Requested input/);checks++;
  assert.doesNotMatch(h.content.textContent,/Filled input|Unfilled input returned/);checks++;

  h.replies.explorer_transactions.pending = [{ ...tx, status: 'pending', height: null }];
  await h.navigate('#explorer?view=transactions');
  assert.match(h.content.textContent, /Pending transactions/); checks++;
  assert.ok(links(h).some(n => n.href === '#explorer?view=transactions&before=12%3A0')); checks++;
  await h.navigate('#explorer?view=transactions&before=12%3A0');
  assert.equal(h.calls.at(-1).params.before, '12:0'); checks++;
  assert.equal(h.content.textContent.includes('Pending transactions'), false); checks++;

  await h.navigate('#explorer?account=' + address);
  assert.match(h.content.textContent, /0\.000000000000000002 stash/); checks++;
  assert.match(h.content.textContent, /Mining reward/); checks++;
  assert.match(h.content.textContent, /Estimated stash value0\.000000000000003 hash/); checks++;
  h.replies.explorer_account.pass_account = { ordinary: '2000', shares: '2000000000000000000', nonce: 1 };
  h.replies.explorer_account.account={ordinary:'7000',shares:'1000000000000000000',nonce:2};
  h.replies.explorer_account.pass_account={ordinary:'2000',shares:'2000000000000000000',nonce:2};
  h.replies.explorer_account.payment_available_hash='2000';
  await h.navigate('#explorer?account=' + address);
  assert.match(h.content.textContent,/Available for payments0\.000000000000002 hash/,'payments show common spendable cash, not the larger FAIL balance or a sum');checks++;
  assert.match(h.content.textContent,/PASShashes0\.000000000000002 hash/);checks++;
  assert.match(h.content.textContent,/FAILhashes0\.000000000000007 hash/);checks++;
  assert.doesNotMatch(h.content.textContent,/Conditional hashes/,'automatic outcomes use each world’s ordinary cash');checks++;
  await h.navigate('#explorer?governance=' + proposal);
  assert.match(h.content.textContent, /Description commitment/); checks++;
  assert.match(h.content.textContent, /OutcomePASS/); checks++;
  assert.match(h.content.textContent, /PASS leading blocks2/); checks++;
  assert.ok(links(h).some(n => n.href === '#explorer?account=' + address)); checks++;
  assert.equal(links(h).some(n => n.href.includes('18%2C18')), false, 'proposal recipients are encoded addresses'); checks++;

  h.replies.explorer_transaction = { ...ctx, transaction: { ...tx, kind: 'deposit', outcome: 'fail', decision: proposal, settlement: { resolved_outcome: 'pass', effect: 'discarded' }, operation: { Deposit: { amount: '1000', outcome: 'Fail', decision: proposal } } } };
  await h.navigate('#explorer?tx=' + txid);
  assert.match(h.content.textContent, /Confirmed/); checks++;
  assert.match(h.content.textContent, /SettlementDiscarded/); checks++;
  assert.match(h.content.textContent, /Resolved outcomePASS/); checks++;
  assert.ok(links(h).some(n => n.href === '#explorer?governance=' + proposal)); checks++;
  h.replies.explorer_account.history.push({ height: 10, block_hash: blockHash, kind: 'governance_grant', amount: '1000', asset: 'hash', outcome: 'pass', decision: proposal, proposal, settlement: { resolved_outcome: 'pass', effect: 'survived' } });
  await h.navigate('#explorer?account=' + address);
  assert.match(h.content.textContent, /Governance grant/); checks++;
  assert.match(h.content.textContent, /PASS · Applied/); checks++;
  h.replies.explorer_governance.proposal_next_cursor = '5:1'; h.replies.explorer_governance.next_before_height = 10; h.replies.explorer_governance.next_cursor = '5:3';
  await h.navigate('#explorer?view=governance&proposal_before=8%3A2&before_height=15&before=8%3A4');
  assert.equal(h.calls.at(-1).params.proposal_before, '8:2'); checks++;
  const proposalPage = links(h).find(n => n.textContent === 'Older proposals →'), decisionPage = links(h).find(n => n.textContent === 'Older decisions →'), backingPage = links(h).find(n => n.textContent === 'Older backing →');
  assert.ok(proposalPage && decisionPage && backingPage); checks++;
  assert.match(proposalPage.href, /proposal_before=5%3A1/); checks++;
  assert.match(proposalPage.href, /before_height=15/); checks++;
  assert.match(decisionPage.href, /proposal_before=8%3A2/); checks++;
  assert.match(decisionPage.href, /before_height=10/); checks++;
  assert.match(backingPage.href, /before=5%3A3/); checks++;

  const old = deferred(); h.replies.explorer_block = () => old.promise;
  h.location.hash = '#explorer?block=11'; h.api.route(); await settle();
  await h.navigate('#explorer?account=' + address);
  old.resolve({ ...ctx, block, transactions: [] }); await settle();
  assert.match(h.content.textContent, /Account/); checks++;
  assert.equal(h.content.textContent.includes('Block 12'), false, 'late block response cannot overwrite account route'); checks++;

  h.api.update({ ready: false, chain_id: chain });
  assert.match(h.get('explorer-message').textContent, /Waiting/); checks++;
  h.api.update({ ready: true, ...ctx }); await settle();
  assert.equal(h.get('explorer-message').hidden, true); checks++;
  h.replies.explorer_account = { ...h.replies.explorer_account, chain_id: 'f'.repeat(64) };
  await h.navigate('#explorer?account=' + address);
  assert.match(h.get('explorer-message').textContent, /Network changed/); checks++;

  await h.navigate('#explorer?q=12');
  assert.equal(h.location.hash, '#explorer?block=12'); checks++;
  await h.navigate('#explorer?q=' + address);
  assert.equal(h.location.hash, '#explorer?account=' + address); checks++;
  await h.navigate('#explorer?q=%3Cscript%3E');
  assert.match(h.get('explorer-message').textContent, /Enter an address/); checks++;
  h.replies.explorer_block = new Error('unknown block'); h.replies.explorer_transaction = { ...ctx, transaction: tx };
  await h.navigate('#explorer?q=' + txid);
  assert.equal(h.location.hash, '#explorer?tx=' + txid); checks++;
  h.replies.explorer_blocks = { ...ctx, blocks: [{ ...block, height: 0, miner: null }], next_before_height: null };
  await h.navigate('#explorer');
  assert.match(h.content.textContent, /Genesis/); checks++;
  assert.equal(links(h).some(n => n.href.includes('account=null')), false); checks++;
  h.replies.explorer_transaction = { ...ctx, transaction: { ...tx, amount: '1234567891234567891', fee: '1000000000000000002', minimum_fee: '1000000000000000001',extra_fee:'1' } };
  await h.navigate('#explorer?tx=' + txid);
  assert.ok(walk(h.content).some(n => n.textContent === '1.23457 hash' && n.title === '1.234567891234567891 hash'), 'transaction amount has an exact hash tooltip'); checks++;
  assert.ok(walk(h.content).some(n => n.textContent === '0.000000000000000001 hash'), 'one-atom extra never displays as zero'); checks++;
  assert.ok(walk(h.content).some(n => n.title === '1.000000000000000001 hash'), 'minimum-fee tooltip retains its last atom'); checks++;
  const operation = walk(h.content).find(n => n.tagName === 'pre');
  assert.equal(operation.textContent,JSON.stringify(tx.operation,null,2),'raw protocol details retain integer hash values'); checks++;
  h.replies.explorer_account = { ...ctx, address, account: { ordinary: '1', shares: '2000000000000000000', nonce: 1 }, stash_value_hash: { numerator: '1', denominator: '3' }, stash_withdrawal_hash: '1', history: [], pending: [] };
  await h.navigate('#explorer?account=' + address);
  assert.ok(walk(h.content).some(n => n.textContent === '0.000000000000000000333333 hash' && n.title === '1 / 3000000000000000000 hash'), 'nonterminating price ratio has an exact rational hash tooltip'); checks++;
  assert.ok(walk(h.content).some(n => n.textContent === '0.000000000000000002 stash' && n.title === '0.000000000000000002 stash'), 'share atoms convert exactly to stash'); checks++;
  h.replies.explorer_account.account.shares = '1000000000000000000000000000000000001';
  await h.navigate('#explorer?account=' + address);
  assert.ok(walk(h.content).some(n => n.textContent === '1 stash' && n.title === '1.000000000000000000000000000000000001 stash'), 'large ownership has a compact display and an exact atom-preserving tooltip'); checks++;
  assert.ok(!h.content.textContent.includes('× 10'), 'ordinary Stash balances do not use scientific notation'); checks++;
  h.replies.explorer_block = { ...ctx, block: { ...block }, transactions: [] };
  await h.navigate('#explorer?block=12');
  const panelBefore = h.content.children[1];
  const expanded = h.content.querySelectorAll('details').find(n => n.querySelector('summary')?.textContent === 'Block details');
  expanded.open = true;
  await h.navigate('#explorer?block=12');
  assert.equal(h.content.children[1], panelBefore, 'unchanged background data keeps rendered DOM stable'); checks++;
  assert.equal(expanded.open, true, 'unchanged refresh preserves open details'); checks++;
  h.replies.explorer_block.block = { ...h.replies.explorer_block.block, body_bytes: 501 };
  await h.navigate('#explorer?block=12');
  assert.match(h.content.textContent, /501 bytes/, 'changed data still updates'); checks++;
  assert.equal(h.content.querySelectorAll('details').find(n => n.querySelector('summary')?.textContent === 'Block details').open, true, 'open details survive an updated response'); checks++;
  h.replies.explorer_governance={...ctx,proposals:[],decisions:[{id:proposal,proposal,started:180,started_height:12,pass_margin_bps:'18446744073709551615'}]};
  await h.navigate('#explorer?governance='+proposal);
  assert.ok(h.content.textContent.includes('184467440737095516.15%'),'large u64 margin remains exact without Number rounding');checks++;
  assert.ok(links(h).some(n=>n.href==='#explorer?block=12'),'decision start links to its height');checks++;
  assert.equal(links(h).some(n=>n.href==='#explorer?block=180'),false,'scheduled seconds never masquerade as a block height');checks++;
  await h.navigate('#explorer?view=governance');
  assert.ok(links(h).some(n=>n.href==='#explorer?block=12'),'decision list also links to actual height');checks++;
  h.replies.explorer_governance.decisions[0].started_height=null;
  await h.navigate('#explorer?governance='+proposal);
  assert.equal(links(h).some(n=>n.href.startsWith('#explorer?block=')),false,'unknown start height has no fabricated link');checks++;
  h.replies.explorer_governance.proposals=[{id:proposal,round:0,action:{Parameter:{parameter:'DecisionBlocks',old:600,new:1200}},support:'1'}];
  await h.navigate('#explorer?governance='+proposal);
  assert.ok(h.content.textContent.includes('600 blocks → 1,200 blocks'),'decision length proposals label their consensus unit');checks++;
  console.log(`Explorer UI: ${checks} behavior assertions passed.`);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
