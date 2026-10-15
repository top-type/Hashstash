'use strict';
const assert = require('node:assert/strict');
const { harness } = require('./test_wallet_ui.cjs');

async function run() {
  let checks = 0;
  const h = await harness({ empty: true }), s = h.currentSnapshot;
  const proposal = 'ab'.repeat(32), other = 'cd'.repeat(32), key = '12'.repeat(32);
  s.config.quote_scale = '1000000000000000000000000000000000000';
  Object.assign(s.status.settings, { pass_margin_bps: 0, });
  const decision = { id: 'ef'.repeat(32), proposal_id: proposal, round: 0, started: 240, duration: 240,
    start_integral: '0', proposal: { Grant: { payments: [{recipient:key,amount:'10'}] } } };
  s.governance.phase = { Governance: decision };
  Object.assign(s.governance.world, { reserve: '1000000000000000000', shares: '1000000000000000000000000000000000000', curve_mass: '5000000000000000000', price_integral: '800000000000000000' });
  s.governance.pass = { ...s.governance.world, reserve: '2000000000000000000', curve_mass: '10000000000000000000', grant_escrow: '10', price_integral: '800000000000000001' };
  const record = id => ({ id, proposal: { round: 0, action: decision.proposal, description: '00'.repeat(32), support: '10', refund_height: null } });
  s.proposals = [record(proposal), record(other)];
  await h.refresh(); await h.navigate('#governance');
  for (const [id, expected] of [['pass-price','10'], ['fail-price','5']]) {
    assert.equal(h.get(id).textContent, expected, 'public market prices survive accountView on navigation'); checks++;
  }
  for (const side of ['pass','fail']) for (const suffix of ['cash','stash','stash-marked']) {
    assert.equal(h.get(`${side}-${suffix}`).textContent, '—', 'no selected wallet is not a zero balance'); checks++;
  }
  assert.equal(h.get('governance-wallet-help').hidden, false); checks++;
  assert.equal(h.get('pass-holdings').hidden, true); checks++;
  assert.equal(h.get('fail-holdings').hidden, true); checks++;
  assert.equal(h.get('governance-common').hidden, true); checks++;
  assert.equal(h.get('governance-trading').hidden, true, 'visitors are not shown a disabled trade form'); checks++;
  assert.equal(h.get('governance-actions').hidden, true); checks++;
  assert.equal(h.get('pass-twap').textContent, h.get('fail-twap').textContent, 'rounded price display can hide the decisive difference'); checks++;
  assert.equal(h.get('gov-result-status').textContent, 'PASS leads', 'one integral unit above equality passes exactly'); checks++;
  s.governance.pass.grant_escrow = '9'; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'an underfunded grant cannot pass even with a higher average'); checks++;
  assert.match(h.get('gov-result-detail').textContent, /funding is incomplete/i); checks++;
  s.governance.pass.grant_escrow = '10'; await h.refresh();
  assert.match(h.get('gov-result-detail').textContent, /<0\.01% above FAIL/); checks++;
  assert.equal(h.get('gov-proposal-link').href, `#explorer?governance=${proposal}`); checks++;
  assert.match(h.get('gov-grant-payments').children[0].children[0].href, /^#explorer\?account=hsh/); checks++;
  assert.equal(h.get('gov-title').textContent, 'Recipients', 'grant category is replaced by the payout itself'); checks++;
  assert.doesNotMatch(h.get('gov-result-status').textContent, /awarded|paid|provisional/i); checks++;
  assert.match(h.get('gov-result').title, /not final until resolution/); checks++;
  assert.equal(h.get('gov-decision-message').hidden, true, 'a description commitment is not rendered as an attached message'); checks++;
  const rows = h.get('proposal-list').children;
  assert.match(rows.find(r => r.textContent.includes(proposal.slice(0,7))).textContent, /In decision · bid becomes revenue.*Details/); checks++;
  assert.doesNotMatch(rows.find(r => r.textContent.includes(proposal.slice(0,7))).textContent, /refund/i); checks++;
  assert.match(rows.find(r => r.textContent.includes(other.slice(0,7))).textContent, /Check refund/); checks++;
  assert.equal(rows.find(r => r.textContent.includes(other.slice(0,7))).children[1].children[1].disabled, true, 'refund checks require a selected wallet'); checks++;
  await h.refresh(); await h.navigate('#overview'); await h.navigate('#governance');
  assert.equal(h.get('pass-price').textContent, '10'); checks++;

  // Watching a real account exposes its holdings but cannot alter the market price.
  h.selectSession({ id: `watch:${key}`, name: 'Read only', public_key: key, mode: 'watch' });
  const account = { account: { ordinary: '100', shares: '10', nonce: 0 },
    price_hash_per_share: { numerator: '999', denominator: '1' }, stash_value_hash: { numerator: '10', denominator: '1' } };
  s.account = s.pass = s.fail = account;
  await h.refresh(); await h.navigate('#governance');
  assert.equal(h.get('governance-wallet-help').hidden, true); checks++;
  assert.equal(h.get('pass-holdings').hidden, false); checks++;
  assert.equal(h.get('fail-holdings').hidden, false); checks++;
  assert.equal(h.get('governance-trading').hidden, false); checks++;
  assert.equal(h.get('governance-actions').hidden, false); checks++;
  assert.equal(h.get('pass-cash').textContent, '0.0000000000000001 hash'); checks++;
  assert.equal(h.get('pass-price').textContent, '10', 'account prices never overwrite the same snapshot market'); checks++;
  assert.equal(h.get('proposal-list').children.find(r => r.textContent.includes(other.slice(0,7))).children[1].children[1].disabled, false, 'watch-wallet selection enables read-only refund check'); checks++;

  s.governance.pass.price_integral = '799999999999999999'; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'higher current PASS spot price does not override the decision average'); checks++;
  s.governance.pass.price_integral = s.governance.world.price_integral; await h.refresh();
  assert.match(h.get('gov-result-detail').textContent, /exactly equal/); checks++;
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'equal decision averages fail'); checks++;
  s.governance.frozen.pass_margin_bps = 500;
  s.governance.pass.price_integral = '1050000000000000000'; s.governance.world.price_integral = '1000000000000000000'; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'equality at a 5% required margin fails'); checks++;
  s.governance.pass.price_integral = '1050000000000000001'; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'PASS leads'); checks++;
  assert.match(h.get('gov-grant-progress').title, /Set aside on PASS/); checks++;
  assert.equal(h.get('pass-ratio').textContent, '20%'); checks++;
  assert.equal(h.get('fail-ratio').textContent, '20%'); checks++;
  decision.started = s.governance.clock; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'Pending'); checks++;
  assert.equal(h.get('pass-twap').textContent, '—'); checks++;

  // A grant changes PASS backing and shape, not its starting spot price.
  s.governance.world.curve_mass = s.governance.world.reserve = '5000000000000000000';
  s.governance.pass.curve_mass = '5000000000000000000';
  s.governance.pass.reserve = '4000000000000000000';
  s.governance.pass.revenue = '12000000000000000000';
  s.governance.pass.grant_capacity = '15000000000000000000';
  await h.refresh();
  assert.equal(h.get('pass-price').textContent, h.get('fail-price').textContent); checks++;
  assert.equal(h.get('pass-ratio').textContent, '80%'); checks++;
  assert.equal(h.get('fail-ratio').textContent, '100%'); checks++;
  assert.equal(h.get('pass-revenue').textContent, '12 hash'); checks++;
  assert.match(h.get('network-grant_capacity').textContent, /PASS 15 hash/); checks++;
  s.governance.pass.reserve = s.governance.pass.curve_mass;
  await h.refresh();
  assert.equal(h.get('pass-ratio').textContent, '100%'); checks++;
  assert.equal(h.get('pass-price').textContent, h.get('fail-price').textContent); checks++;

  Object.assign(s.governance.pass, { reserve:'0',shares:'0',curve_mass:'0' });
  await h.refresh();
  assert.equal(h.get('pass-price').textContent, '0', 'empty outcome has no price contribution to governance'); checks++;
  assert.match(h.get('pass-price').title, /No outstanding stash.*zero to the decision average/); checks++;
  assert.equal(h.get('overview-price-pass').textContent, '1', 'opening conversion rate remains available for the next deposit'); checks++;

  s.governance.phase = { Rest: { until: 780, pending: null } }; s.governance.pass = s.pass = s.fail = null;
  await h.refresh();
  assert.equal(h.get('gov-result').hidden, true); checks++;
  assert.equal(h.get('gov-result-status').textContent, ''); checks++;
  assert.equal(h.get('gov-proposal-link').hidden, true); checks++;
  assert.equal(h.get('gov-grant-payments').hidden, true); checks++;
  assert.equal(h.get('proposal-heading').textContent, 'Proposal history'); checks++;
  assert.doesNotMatch(h.get('proposal-list').textContent, /refund|current leader|In decision/i); checks++;
  s.governance.phase = { Auction: { round: 0, opened: 0, leader: proposal, lead_since: 270 } };
  s.proposals[1].proposal.refund_height = 18; await h.refresh();
  assert.match(h.get('proposal-list').children[0].textContent, /Current auction leader.*Support/); checks++;
  assert.match(h.get('proposal-list').children[1].textContent, /Removed from auction.*Check refund/); checks++;
  assert.doesNotMatch(h.get('proposal-list').children[1].textContent, /Support ↗/); checks++;
  assert.equal(h.wallet.length, 0, 'read-only UI checks never broadcast'); checks++;
  console.log(`governance view: ${checks} checks passed`);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
