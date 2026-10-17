'use strict';
const assert = require('node:assert/strict');
const { harness } = require('./test_wallet_ui.cjs');

async function run() {
  let checks = 0;
  const h = await harness({ empty: true }), s = h.currentSnapshot;
  const proposal = 'ab'.repeat(32), other = 'cd'.repeat(32), key = '12'.repeat(32);
  s.config.quote_scale = '1000000';
  Object.assign(s.status.settings, { pass_margin_bps: 0, });
  const decision = { id: 'ef'.repeat(32), proposal_id: proposal, round: 0, started: 240, blocks:16, started_height:16, leading_blocks:3, proposal: { Grant: { payments: [{recipient:key,amount:'10'}] } } };
  s.governance.phase = { Governance: decision };
  Object.assign(s.governance.world, { reserve: '1000', shares: '1000', curve_mass: '5000' });
  s.governance.pass = { ...s.governance.world, reserve: '2000', curve_mass: '10000', grant_escrow: '10' };
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
  assert.equal(h.get('pass-leading-blocks').textContent, '3', 'counted leading blocks are exact'); checks++;
  assert.equal(h.get('gov-result-status').textContent, 'PASS leads', 'three of four observed blocks puts PASS ahead'); checks++;
  s.governance.pass.grant_escrow = '9'; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'an underfunded grant cannot pass even with a majority'); checks++;
  assert.match(h.get('gov-result-detail').textContent, /funding is incomplete/i); checks++;
  s.governance.pass.grant_escrow = '10'; await h.refresh();
  assert.match(h.get('gov-result-detail').textContent, /3 of 4 blocks counted for PASS/); checks++;
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
  assert.equal(h.get('pass-cash').textContent, '0.1 hash'); checks++;
  assert.equal(h.get('pass-price').textContent, '10', 'account prices never overwrite the same snapshot market'); checks++;
  assert.equal(h.get('proposal-list').children.find(r => r.textContent.includes(other.slice(0,7))).children[1].children[1].disabled, false, 'watch-wallet selection enables read-only refund check'); checks++;

  decision.leading_blocks = 1; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'current spot price does not replace accumulated block counts'); checks++;
  decision.leading_blocks = 2; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'FAIL leads', 'equal observed block counts favor FAIL'); checks++;
  s.governance.frozen.pass_margin_bps = 500;
  assert.match(h.get('gov-subtitle').textContent, /Equal prices/); checks++;
  decision.leading_blocks = 3; await h.refresh();
  assert.match(h.get('gov-subtitle').textContent, /more than 5% above FAIL/); checks++;
  assert.equal(h.get('gov-result-status').textContent, 'PASS leads'); checks++;
  assert.match(h.get('gov-grant-progress').title, /Set aside on PASS/); checks++;
  assert.equal(h.get('pass-ratio').textContent, '20%'); checks++;
  assert.equal(h.get('fail-ratio').textContent, '20%'); checks++;

  // At the last tip the next block adds one observation from these closing
  // prices and resolves before its transactions: the result is already fixed.
  const status = () => h.get('gov-result-status').textContent;
  decision.started_height = s.status.height - 15; decision.leading_blocks = 8; await h.refresh();
  assert.equal(status(), 'PASS decided', 'PASS leads at the closing prices, so it reaches 9 of 16'); checks++;
  assert.match(h.get('gov-result-detail').textContent, /9 of 16 blocks count for PASS.*resolves at the start of the next block/); checks++;
  assert.match(h.get('gov-result').title, /result is fixed/); checks++;
  s.governance.pass.curve_mass = '5000'; await h.refresh();
  assert.equal(status(), 'FAIL decided', 'equal closing prices add no PASS block, so 8 of 16 already means FAIL even though 8 of 15 leads'); checks++;
  decision.blocks = 15; decision.started_height = s.status.height - 14; decision.leading_blocks = 7; s.governance.pass.curve_mass = '10000'; await h.refresh();
  assert.equal(status(), 'PASS decided', 'the mirror case: 7 of 14 trails, but the closing block makes 8 of 15'); checks++;
  s.governance.pass.grant_escrow = '9'; await h.refresh();
  assert.equal(status(), 'FAIL decided', 'an underfunded grant cannot be decided for PASS'); checks++;
  s.governance.pass.grant_escrow = '10';
  {
    // No conditional trade can be included once the next block resolves the decision.
    const { settle } = require('./test_wallet_ui.cjs');
    await h.refresh(); await h.navigate('#stash');
    assert.equal(h.get('stash-context-notice').textContent, 'Trading is closed: the decision resolves at the start of the next block, before its transactions.'); checks++;
    const quotes = () => h.calls.filter(call => call.body.method === 'stash_quote').length, before = quotes();
    h.get('trade-amount').value = '1'; await h.get('trade-amount').fire('input'); await h.timersDue(); await settle();
    assert.equal(quotes(), before, 'no quote is requested for a trade that cannot be included'); checks++;
    assert.equal(h.get('trade-quote').textContent, 'Quote unavailable'); checks++;
    assert.match(h.get('quote-height').textContent, /Trading is closed/); checks++;
    assert.equal(h.get('trade-submit').disabled, true); checks++;
    decision.started_height = s.status.height - 13; await h.refresh(); await h.timersDue(); await settle();
    assert.equal(h.get('stash-context-notice').textContent, 'Fees require hashes in both outcomes.', 'one block earlier, trading is open'); checks++;
    assert.ok(quotes() > before, 'and quotes are requested again'); checks++;
    assert.equal(status(), 'PASS leads', 'before the last tip the running count is shown'); checks++;
    h.get('trade-amount').value = ''; await h.get('trade-amount').fire('input'); await h.timersDue(); await h.navigate('#governance');
  }
  decision.blocks = 16;
  decision.started_height = s.status.height; decision.leading_blocks = 0; await h.refresh();
  assert.equal(h.get('gov-result-status').textContent, 'Pending'); checks++;
  assert.equal(h.get('pass-leading-blocks').textContent, '0'); checks++;

  // A grant changes PASS backing and shape, not its starting spot price.
  s.governance.world.curve_mass = s.governance.world.reserve = '5000';
  s.governance.pass.curve_mass = '5000';
  s.governance.pass.reserve = '4000';
  s.governance.pass.revenue = '12000';
  s.governance.pass.grant_capacity = '15000';
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
  assert.match(h.get('pass-price').title, /No outstanding stash.*price is zero/); checks++;
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
  assert.match(h.get('gov-title').textContent, new RegExp(`Leader ${proposal.slice(0, 10)}…${proposal.slice(-6)}`), 'the hero shows a 64-bit proposal label'); checks++;
  assert.ok(h.get('proposal-list').children[0].textContent.includes(`${proposal.slice(0, 10)}…${proposal.slice(-6)}`), 'cards show a 64-bit proposal label'); checks++;

  // A pasted Support ID is resolved and its action shown before anything is signed.
  {
    const { addr, settle } = require('./test_wallet_ui.cjs');
    const form = h.get('support-form'), preview = h.get('support-proposal-preview'), field = form.elements.proposal;
    const enter = async value => { field.value = value; await field.fire('input'); await settle(); };
    assert.equal(preview.hidden, true, 'no preview before an ID is entered'); checks++;
    await enter('aa'.repeat(32));
    assert.equal(preview.hidden, false); checks++;
    assert.match(preview.textContent, /not an active proposal in the current auction round/, 'an unknown ID is refused'); checks++;
    form.elements.amount.value = '1'; await form.fire('input'); await h.timersDue(); await settle();
    assert.match(h.get('support-fee-error').textContent, /not an active proposal/, 'an unknown ID cannot be quoted or signed'); checks++;
    await enter(other);
    assert.match(preview.textContent, /not an active proposal/, 'a proposal removed from the auction is refused'); checks++;
    await enter(proposal.toUpperCase());
    assert.ok(preview.textContent.includes(addr(key)), 'the full grant recipient address is shown'); checks++;
    assert.ok(preview.textContent.includes('0.01 hash'), 'the exact grant amount is shown'); checks++;
    assert.ok(preview.textContent.includes(`${proposal.slice(0, 10)}…${proposal.slice(-6)}`)); checks++;
    await enter(''); assert.equal(preview.hidden, true); checks++;
    await h.get('proposal-list').children[0].children[1].children[1].click(); await settle();
    assert.equal(field.value, proposal, 'the card button fills the full ID'); checks++;
    assert.ok(preview.textContent.includes(addr(key)), 'and shows the action it backs'); checks++;
    s.proposals[0].proposal.action = { Parameter: { parameter: 'MinimumFeeRate', old: 1, new: 5 } }; await h.refresh();
    assert.match(preview.textContent, /Minimum fee rate: 0\.001 hash \/ 1,024 weight → 0\.005 hash \/ 1,024 weight/, 'parameter changes show old and new values'); checks++;
    s.proposals[0].proposal.action = decision.proposal; await h.refresh();
  }
  assert.equal(h.wallet.length, 0, 'read-only UI checks never broadcast'); checks++;
  console.log(`governance view: ${checks} checks passed`);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
