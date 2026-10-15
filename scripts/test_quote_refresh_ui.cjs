'use strict';
const assert = require('node:assert/strict');
const { setup } = require('./test_outcome_wallet.cjs');
const { deferred, response, settle } = require('./test_wallet_ui.cjs');
const amounts = require('../ui/amounts.js');
const shares = require('../ui/shares.js');

let checks = 0;
const equal = (actual, expected, message) => { assert.equal(actual, expected, message); checks++; };
const ok = (value, message) => { assert.ok(value, message); checks++; };
const stateChange = h => {
  const s = h.currentSnapshot.status;
  s.height++;
  s.tip = BigInt(s.height).toString(16).padStart(64, '0');
  s.state_root = (BigInt(s.height) + 10000n).toString(16).padStart(64, '0');
};
const visible = (h, id) => h.get(id).textContent;
const transferReply = (h, params, overrides = {}) => response({ result: h.transferQuote(params, overrides) });
const noPaymentError = h => {
  ok(!visible(h, 'send-net').includes('Check payment details'), 'chain movement is not a payment-input error');
  equal(h.get('send-fee-error').hidden, true, 'chain movement has no red fee error');
  equal(h.get('send-submit').disabled, true, 'refresh-pending quotes cannot authorize spending');
};

async function paymentDisplaySurvivesOverlappingRefreshes() {
  const h = await setup(); await h.send('10');
  const original = Object.fromEntries(['send-net', 'send-cost', 'send-fee-quote', 'send-fee-allocation'].map(id => [id, visible(h, id)]));
  const pending = deferred(); h.handlers.transfer_quote = () => pending.promise;
  for (let block = 0; block < 3; block++) {
    stateChange(h); await h.refresh(); await h.timersDue();
    for (const [id, value] of Object.entries(original)) equal(visible(h, id), value, `${id} remains visible through overlapping automatic refresh ${block + 1}`);
    equal(h.get('send-fee-allocation').hidden, false, 'previous allocation keeps its layout during automatic refresh');
    equal(h.get('send-submit').disabled, true, 'preserved display is never an executable stale quote');
  }
  const form = h.get('send-form'); form.elements.amount.value = amounts.exactInput('11'); await form.fire('input');
  equal(visible(h, 'send-net'), '—', 'edited payment amount clears the old receive preview');
  equal(visible(h, 'send-cost'), '—', 'edited payment amount clears the old total');
  equal(h.get('send-fee-allocation').hidden, true, 'edited input clears the previous fee allocation');
  equal(h.get('send-submit').disabled, true);
  equal(h.wallet.length, 0, 'preview and refresh never broadcast');
}

async function tradeDisplaySurvivesOverlappingRefreshes() {
  const h = await setup(); await h.trade('10');
  const ids = ['trade-quote', 'quote-remaining', 'trade-fee-quote', 'trade-fee-allocation'];
  const original = Object.fromEntries(ids.map(id => [id, visible(h, id)]));
  const pending = deferred(); h.handlers.stash_quote = () => pending.promise;
  for (let block = 0; block < 3; block++) {
    stateChange(h); await h.refresh(); await h.timersDue();
    for (const [id, value] of Object.entries(original)) equal(visible(h, id), value, `${id} remains visible through overlapping trade refresh ${block + 1}`);
    equal(h.get('quote-remaining').hidden, false);
    equal(h.get('trade-fee-allocation').hidden, false);
    equal(h.get('trade-submit').disabled, true, 'a preserved trade preview cannot authorize signing');
  }
  h.get('trade-form').elements.amount.value = amounts.exactInput('11'); await h.get('trade-amount').fire('input');
  equal(visible(h, 'trade-quote'), '—', 'edited trade amount clears the old result');
  equal(h.get('quote-remaining').hidden, true);
  equal(h.get('trade-fee-allocation').hidden, true);
  equal(h.get('trade-submit').disabled, true);
  equal(h.wallet.length, 0);
}

async function errorsRemainStableWhileRetrying() {
  const h = await setup(); h.handlers.stash_quote = () => response({ error: { message: 'Insufficient deposit balance' } });
  await h.trade('10');
  equal(visible(h, 'trade-quote'), 'Quote unavailable');
  const explanation = visible(h, 'quote-height');
  for (let refresh = 0; refresh < 3; refresh++) {
    await h.refresh();
    equal(visible(h, 'trade-quote'), 'Quote unavailable', 'automatic failed-quote retry never flashes a dash');
    equal(visible(h, 'quote-height'), explanation, 'failure explanation persists before replacement response');
    await h.timersDue();
    equal(visible(h, 'trade-quote'), 'Quote unavailable');
    equal(visible(h, 'quote-height'), explanation);
  }
  h.get('trade-form').elements.amount.value = amounts.exactInput('11'); await h.get('trade-amount').fire('input');
  equal(visible(h, 'trade-quote'), '—', 'new user input clears the previous error');
  equal(visible(h, 'quote-height'), '');

  const j = await setup(); j.handlers.transfer_quote = () => response({ error: { message: 'Insufficient transfer balance' } });
  await j.send('10');
  const net = visible(j, 'send-net'), cost = visible(j, 'send-cost');
  for (let block = 0; block < 2; block++) {
    stateChange(j); await j.refresh();
    equal(visible(j, 'send-net'), net, 'payment errors remain visible while an automatic retry is pending');
    equal(visible(j, 'send-cost'), cost);
    await j.timersDue();
  }
  equal(j.get('send-submit').disabled, true);
}

async function feeErrorsRemainStableWhileRetrying() {
  const h = await setup();
  h.handlers.fee_quote = p => response({ result: { ...h.fee(p), miner_fee: '999' } });
  await h.trade('10');
  const message = visible(h, 'trade-fee-error');
  ok(message.includes('Invalid fee allocation'), 'invalid fee math is visibly rejected');
  equal(h.get('trade-submit').disabled, true);
  for (let block = 0; block < 2; block++) {
    stateChange(h); await h.refresh();
    equal(visible(h, 'trade-fee-error'), message, 'automatic trade requote keeps the existing fee error');
    equal(h.get('trade-fee-error').hidden, false);
    await h.timersDue();
    equal(visible(h, 'trade-fee-error'), message, 'successful Stash leg does not clear an unresolved fee error');
    await h.timersDue();
    equal(visible(h, 'trade-fee-error'), message);
  }
  await h.get('trade-amount').fire('input');
  equal(h.get('trade-fee-error').hidden, true, 'edited input clears the old fee error');
}

async function chainMovementIsPendingRatherThanInvalidInput() {
  for (const drift of ['tip', 'height', 'state_root']) {
    const h = await setup(); await h.send('10');
    const pending = deferred(); let attempt = 0;
    h.handlers.transfer_quote = p => ++attempt === 1 ? transferReply(h, p, {
      [drift]: drift === 'height' ? h.currentSnapshot.status.height + 1 : 'f'.repeat(64)
    }) : pending.promise;
    stateChange(h); await h.refresh(); await h.timersDue();
    noPaymentError(h);
    delete h.handlers.transfer_quote;
    stateChange(h); await h.refresh(); await h.timersDue(); await h.timersDue();
    equal(h.get('send-submit').disabled, false, `fresh payment quote recovers after ${drift} drift`);
    ok(visible(h, 'send-net').includes('hash'));
    equal(h.wallet.length, 0);
  }
  for (const drift of ['tip', 'height', 'state_root', 'decision']) {
    const h = await setup(); await h.trade('10');
    const pending = deferred(); let attempt = 0;
    h.handlers.stash_quote = p => ++attempt === 1 ? response({ result: h.stashQuote(p, {
      [drift]: drift === 'height' ? h.currentSnapshot.status.height + 1 : 'f'.repeat(64)
    }) }) : pending.promise;
    stateChange(h); await h.refresh(); await h.timersDue(); await h.timersDue();
    ok(!visible(h, 'trade-quote').includes('Quote unavailable'), `${drift} drift is not a failed trade quote`);
    equal(h.get('trade-fee-error').hidden, true);
    equal(h.get('trade-submit').disabled, true, 'drifting trade quotes never authorize spending');
    delete h.handlers.stash_quote;
    stateChange(h); await h.refresh(); await h.timersDue(); await h.timersDue();
    equal(h.get('trade-submit').disabled, false, `fresh trade quote recovers after ${drift} drift`);
    equal(h.wallet.length, 0);
  }
}

async function malformedQuotesStillShowErrors() {
  for (const mutation of [{ sender_public_key: 'ab'.repeat(32) }, { data_hex: 'ff', data_bytes: 1 }, { miner_fee: '999' }, { fee: 'invalid' }, { chain_id: 'ab'.repeat(32) }, { tip: 'invalid' }, { height: -1 }]) {
    const h = await setup(); h.handlers.transfer_quote = p => transferReply(h, p, mutation); await h.send('10');
    equal(visible(h, 'send-net'), 'Check payment details', `${Object.keys(mutation)[0]} mismatch remains a real validation error`);
    ok(visible(h, 'send-cost').length > 0);
    equal(h.get('send-submit').disabled, true);
    equal(h.wallet.length, 0);
  }
  const h = await setup(); h.handlers.stash_quote = p => response({ result: h.stashQuote(p, { shares: 'invalid' }) }); await h.trade('10');
  equal(visible(h, 'trade-quote'), 'Quote unavailable', 'malformed trade values are still rejected');
  equal(visible(h, 'quote-height'), 'Invalid Stash quote.');
  equal(h.get('trade-submit').disabled, true);
}

async function amountOnlyPartialFillsRemainEstimates() {
  {
    const h = await setup();
    h.get('trade-form').elements.extra_fee.value = 'invalid';
    await h.get('trade-max').click();
    ok(h.get('trade-form').querySelector('.form-feedback').textContent.includes('Optional extra'), 'Use max identifies an invalid extra fee instead of calling it the expiry value');
    equal(h.wallet.length, 0, 'invalid extra fee never signs');
  }
  for (const kind of ['deposit', 'redeem']) for (const filled of ['0', '4', '10']) {
    const h = await setup(), form = h.get('trade-form');
    await h.tradeTab(kind);
    h.handlers.stash_quote = p => {
      const base = h.stashQuote(p), input = BigInt(filled), output = kind === 'deposit' ? input * 100n : input;
      return response({result: {...base, input_filled: filled, input_unfilled: String(10n-input), output: String(output),
        shares: kind === 'deposit' ? String(output) : '10', output_hash: String(input),
        share_after: String(BigInt(base.share_before) + (kind === 'deposit' ? output : -input))}});
    };
    form.elements.outcome.value='Pass';await h.get('trade-outcome').fire('change');
    form.elements.amount.value = kind === 'deposit' ? amounts.exactInput('10') : shares.exactInput('10');
    await h.get('trade-amount').fire('input');await h.timersDue();await h.timersDue();
    equal(visible(h,'quote-label'),'Estimated receive');
    ok(visible(h,'quote-height').includes(filled === '0' ? 'A fee still applies if included' : 'Final amount may differ'));
    if (filled !== '10') ok(visible(h,'quote-remaining').includes('Estimated unused:'), 'unfilled input is shown without becoming a minimum-output promise');
    equal(h.get('trade-submit').disabled,false,`${kind} ${filled} estimate can authorize the requested order`);
    await form.requestSubmit();
    equal(h.wallet.at(-1).expiry_blocks,2,'trade orders default to two-block expiry');
    equal(h.wallet.at(-1).anchor,h.currentSnapshot.status.tip,'the reviewed block reference is signed');
    const operation=h.wallet.at(-1).operation[kind === 'deposit' ? 'Deposit' : 'Redeem'];
    equal(operation[kind === 'deposit' ? 'amount' : 'shares'],'10','the requested amount is signed, not the preview fill');
    equal(Object.keys(operation).sort().join(','),kind === 'deposit' ? 'amount,decision,outcome' : 'decision,outcome,shares');
  }
  {
    const h=await setup();await h.trade('10');h.get('trade-expiry').value='5';await h.get('trade-expiry').fire('input');await h.timersDue();await h.timersDue();await h.get('trade-form').requestSubmit();
    equal(h.wallet.at(-1).expiry_blocks,5,'explicit trade expiry is retained');
    await h.send('10');await h.get('send-form').requestSubmit();equal(h.wallet.at(-1).expiry_blocks,2,'other transactions also default to two-block expiry');
  }
  {
    const h=await setup();await h.trade('10');h.get('trade-expiry').value='9007199254740993';await h.get('trade-expiry').fire('input');await h.timersDue();await h.timersDue();await h.get('trade-form').requestSubmit();
    equal(h.wallet.at(-1).expiry_blocks,'9007199254740993','an explicit lifetime is preserved exactly beyond the JS number range');
    equal(h.calls.filter(c=>c.body.method==='preparetransaction').at(-1).body.params.expiry_blocks,'9007199254740993','wire JSON carries the exact large integer');
  }
  for (const mutation of [{input_requested:'11'},{input_filled:'11',input_unfilled:'0'}, {input_filled:'4',input_unfilled:'5'}, {output:'999'}, {share_after:'0'}, {kind:'redeem'}, {indicative:false}, {partial_fill_possible:false}, {execution:'immediate'}]) {
    const h=await setup();h.handlers.stash_quote=p=>response({result:h.stashQuote(p,mutation)});await h.trade('10');
    equal(visible(h,'trade-quote'),'Quote unavailable',`${Object.keys(mutation)[0]} cannot change a signed intent`);
    equal(h.get('trade-submit').disabled,true);equal(h.wallet.length,0);
  }
}

async function realFailuresReplacePreservedSuccess() {
  for (const kind of ['send', 'trade']) {
    const h = await setup();
    if (kind === 'send') await h.send('10'); else await h.trade('10');
    equal(h.get(`${kind}-fee-allocation`).hidden, false);
    h.handlers[kind === 'send' ? 'transfer_quote' : 'stash_quote'] = () => response({ error: { message: 'Insufficient balance' } });
    stateChange(h); await h.refresh();
    equal(h.get(`${kind}-fee-allocation`).hidden, false, 'last allocation is preserved while the new request waits');
    await h.timersDue();
    equal(h.get(`${kind}-fee-allocation`).hidden, true, 'a confirmed request failure clears the previous successful allocation');
    equal(visible(h, kind === 'send' ? 'send-net' : 'trade-quote'), kind === 'send' ? 'Check payment details' : 'Quote unavailable');
    equal(h.get(`${kind}-submit`).disabled, true);
  }
}

async function pendingFeeRetriesWithoutAnotherBlock() {
  const h = await setup(); await h.trade('10');
  const original = visible(h, 'trade-fee-allocation');
  h.handlers.fee_quote = p => response({ result: { ...h.fee(p), tip: 'f'.repeat(64) } });
  stateChange(h); await h.refresh(); await h.timersDue(); await h.timersDue();
  equal(visible(h, 'trade-fee-allocation'), original, 'fee-only snapshot drift preserves the last allocation');
  equal(h.get('trade-fee-allocation').hidden, false);
  equal(h.get('trade-fee-error').hidden, true, 'fee-only snapshot drift has no red validation error');
  equal(h.get('trade-submit').disabled, true);
  delete h.handlers.fee_quote;
  await h.refresh(); await h.timersDue();
  equal(h.get('trade-submit').disabled, false, 'pending fee retries and recovers even without another observed block');
  equal(h.wallet.length, 0);
}

async function staleAsyncRepliesCannotOverwriteNewerResults() {
  for (const kind of ['send', 'trade']) for (const stale of ['success', 'error', 'rejection']) {
    const h = await setup(), method = kind === 'send' ? 'transfer_quote' : 'stash_quote';
    const pending = deferred(); let old;
    h.handlers[method] = p => { old = kind === 'send' ? transferReply(h, p) : response({ result: h.stashQuote(p) }); return pending.promise.then(value => { if (stale === 'rejection') throw new Error('Old request failed'); return value; }); };
    if (kind === 'send') await h.send('10'); else await h.trade('10');
    delete h.handlers[method];
    if (kind === 'send') await h.send('11'); else await h.trade('11');
    const ids = kind === 'send' ? ['send-net', 'send-cost', 'send-fee-quote'] : ['trade-quote', 'quote-height', 'trade-fee-quote'];
    const fresh = Object.fromEntries(ids.map(id => [id, visible(h, id)]));
    pending.resolve(stale === 'error' ? response({ error: { message: 'Old request failed' } }) : old); await settle();
    for (const [id, value] of Object.entries(fresh)) equal(visible(h, id), value, `stale ${kind} ${stale} does not overwrite ${id}`);
    equal(h.get(`${kind}-submit`).disabled, false, `stale ${stale} does not disable the current ${kind} quote`);
    equal(h.wallet.length, 0);
  }
}

async function delayedPreparationRechecksTheAnchorSnapshot() {
  for(const advance of [0,2]) {
    const h=await setup();await h.trade('10');const held=deferred();let request;
    h.handlers.preparetransaction=p=>{request=p;return held.promise;};const sending=h.get('trade-form').requestSubmit();await settle();ok(request,'trade preparation reached the held request');
    h.currentSnapshot.status.height+=advance;h.currentSnapshot.status.tip='74'.repeat(32);h.currentSnapshot.status.state_root='75'.repeat(32);await h.refresh();
    held.resolve(response({result:{format:'hashstash-unsigned-v1',body:'abab'}}));await sending;
    equal(h.wallet.length,0,'the signer is never called after the preparation snapshot changes');equal(h.calls.filter(c=>c.body.method==='broadcasttransaction').length,0);
  }
}

async function run() {
  for (const test of [delayedPreparationRechecksTheAnchorSnapshot, paymentDisplaySurvivesOverlappingRefreshes, tradeDisplaySurvivesOverlappingRefreshes, errorsRemainStableWhileRetrying, feeErrorsRemainStableWhileRetrying, chainMovementIsPendingRatherThanInvalidInput, malformedQuotesStillShowErrors, amountOnlyPartialFillsRemainEstimates, realFailuresReplacePreservedSuccess, pendingFeeRetriesWithoutAnotherBlock, staleAsyncRepliesCannotOverwriteNewerResults]) await test();
  console.log(`Quote refresh UI: ${checks} behavior checks passed`);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
