'use strict';

const assert = require('node:assert/strict');
const { harness, response, settle, addr, deferred } = require('./test_wallet_ui.cjs');
const chain = 'a'.repeat(64), origin = 'https://192.0.2.10', first = '12'.repeat(32), second = '34'.repeat(32);
const claim = (status = 'pending') => ({ chain_id: chain, status, txid: 'd'.repeat(64), amount_hashes: '1000000000000', retry_after_seconds: 3600 });
function service() {
  const api = { config: { url: origin, chain_id: chain }, status: { enabled: true, chain_id: chain, amount_hashes: '1000000000000', available: true, mining_active: true, state: 'ready', retry_after_seconds: 0, address: addr(second) }, claims: new Map(), post: null, get: null };
  api.fetch = async (url, options) => {
    if (url === '/faucet-config.json') return response(api.config);
    if (url.includes('/faucet/status?address=')) {
      if (api.get) return api.get(url, options);
      const address = decodeURIComponent(url.split('address=')[1]);
      const receipt = api.claims.get(address);
      return response({ ...api.status, ...(receipt ? { claim: receipt, available: false, state: receipt.status === 'pending' ? 'pending' : 'cooldown', retry_after_seconds: receipt.retry_after_seconds, cooldown_scope: 'address' } : {}) });
    }
    assert.equal(url, origin + '/faucet/claim');
    assert.equal(options.method, 'POST');
    const body = JSON.parse(options.body);
    assert.deepEqual(Object.keys(body), ['address']);
    if (api.post) return api.post(body, options);
    const result = claim(); api.claims.set(body.address, result); return response(result);
  };
  return api;
}
const posts = h => h.faucetCalls.filter(c => c.options.method === 'POST');
async function run() {
  let checks = 0;
  const absent = await harness();
  assert.equal(absent.get('wallet-faucet').hidden, true); checks++;
  assert.equal(absent.faucetCalls.length, 1); checks++;
  await absent.get('faucet-claim').click();
  assert.equal(posts(absent).length, 0); checks++;

  const api = service(), h = await harness({ faucetTransport: api.fetch });
  await settle();
  assert.equal(h.get('wallet-faucet').hidden, false); checks++;
  assert.equal(h.get('faucet-claim').disabled, false); checks++;
  assert.equal(h.get('faucet-claim').textContent, 'Get test hashes'); checks++;
  assert.equal(h.get('faucet-amount').textContent, '0.000001 hash'); checks++;
  assert.equal(h.get('faucet-status').hidden, true); checks++;
  await h.get('faucet-claim').click(); await settle();
  assert.equal(posts(h).length, 1); checks++;
  assert.equal(JSON.parse(posts(h)[0].options.body).address, addr(first)); checks++;
  assert.match(h.get('faucet-status').textContent, /Pending/); checks++;
  assert.equal(h.get('faucet-claim').disabled, true); checks++;
  await h.get('faucet-claim').click();
  assert.equal(posts(h).length, 1, 'repeated click cannot duplicate a claim'); checks++;
  api.claims.set(addr(first), claim('confirmed')); h.wallClock += 11000; await h.refresh(); await settle();
  assert.match(h.get('faucet-status').textContent, /^0\.000001 hash received\. Available in /); checks++;
  assert.equal(h.get('faucet-claim').disabled, true); checks++;
  for (const c of h.faucetCalls) {
    assert.equal(c.options.credentials, 'omit'); checks++;
    assert.equal(c.options.redirect, 'error'); checks++;
    assert.equal(c.options.headers?.['X-Hashstash-Token'], undefined); checks++;
  }

  const paused = service(); paused.status.available = false; paused.status.mining_active = false; paused.status.state = 'waiting_for_mining';
  const p = await harness({ faucetTransport: paused.fetch }); await settle();
  assert.equal(p.get('faucet-claim').disabled, true); checks++;
  assert.equal(p.get('faucet-status').textContent, 'Waiting for mining'); checks++;

  const watchApi = service(), w = await harness({ faucetTransport: watchApi.fetch }); await settle();
  w.currentSession = { ...w.currentSession, wallet_enabled: false, wallet_mode: 'watch', wallet_id: `watch:${first}`, wallets: [{ id: `watch:${first}`, public_key: first, mode: 'watch' }] };
  await w.refresh(); await w.get('faucet-claim').click(); await settle();
  assert.equal(posts(w).length, 1, 'watch-only accounts can receive faucet transfers'); checks++;
  assert.equal(w.calls.some(c => c.body.method === 'preparetransaction' || c.body.method === 'broadcasttransaction'), false); checks++;

  const pendingApi = service(), pending = deferred(); pendingApi.post = () => pending.promise;
  const changing = await harness({ faucetTransport: pendingApi.fetch }); await settle();
  const sending = changing.get('faucet-claim').click(); await settle();
  await changing.get('faucet-claim').click(); assert.equal(posts(changing).length, 1); checks++;
  changing.currentSession = { ...changing.currentSession, public_key: second, wallet_id: `hot:${second}`, wallets: [{ id: `hot:${second}`, public_key: second, mode: 'hot' }] };
  await changing.refresh(); await settle();
  pendingApi.claims.set(addr(first), claim()); pending.resolve(response(claim())); await sending; await settle();
  assert.equal(JSON.parse(posts(changing)[0].options.body).address, addr(first)); checks++;
  assert.equal(changing.get('faucet-status').hidden, true, 'old-wallet completion is not shown on the newly selected wallet'); checks++;
  assert.equal(changing.get('faucet-claim').disabled, false); checks++;

  for (const config of [{ url: origin, chain_id: 'b'.repeat(64) }, { url: 'http://192.0.2.10', chain_id: chain }, { url: 'https://user:password@example.com', chain_id: chain }]) {
    const invalid = service(); invalid.config = config;
    const bad = await harness({ faucetTransport: invalid.fetch }); await settle();
    assert.equal(bad.get('wallet-faucet').hidden, true); checks++;
    assert.equal(bad.faucetCalls.length, 1, 'untrusted or different-network endpoint is not contacted'); checks++;
  }
  const errorApi = service(); errorApi.post = () => { throw new Error('Connection lost'); }; errorApi.get = null;
  const uncertain = await harness({ faucetTransport: errorApi.fetch }); await settle();
  errorApi.get = () => { throw new Error('Connection lost'); };
  await uncertain.get('faucet-claim').click(); await settle();
  assert.equal(uncertain.get('faucet-claim').disabled, true); checks++;
  assert.match(uncertain.get('faucet-status').textContent, /unavailable/); checks++;
  uncertain.wallClock += 11000; await uncertain.refresh(); await settle();
  assert.equal(posts(uncertain).length, 1, 'refresh never retries an uncertain POST'); checks++;

  const limitedApi = service(); limitedApi.post = () => response({ error: 'Too soon', retry_after_seconds: 60 }, 429);
  // A later status read can remain globally ready while this browser is limited.
  limitedApi.get = null;
  const limited = await harness({ faucetTransport: limitedApi.fetch }); await settle();
  limitedApi.get = () => response({ ...limitedApi.status, available: false, state: 'quota_reached' });
  await limited.get('faucet-claim').click(); await settle();
  assert.equal(limited.get('faucet-claim').disabled, true); checks++;
  assert.match(limited.get('faucet-status').textContent, /Limit reached|Available in/); checks++;

  const connectionApi = service(); Object.assign(connectionApi.status, { state: 'cooldown', available: false, retry_after_seconds: 45, cooldown_scope: 'network' });
  const connection = await harness({ faucetTransport: connectionApi.fetch }); await settle();
  assert.equal(connection.get('faucet-claim').disabled, true, 'network cooldown is visible before a failed claim'); checks++;
  assert.equal(connection.get('faucet-status').textContent, 'Retry in 45s'); checks++;
  await connection.get('faucet-claim').click();
  assert.equal(posts(connection).length, 0); checks++;
  Object.assign(connectionApi.status, { state: 'ready', available: true, retry_after_seconds: 0 });
  connection.wallClock += 11000; await connection.refresh(); await settle();
  assert.equal(connection.get('faucet-claim').disabled, false); checks++;
  assert.equal(connection.get('faucet-status').hidden, true); checks++;

  const oldLimitApi = service(), oldLimit = await harness({ faucetTransport: oldLimitApi.fetch }); await settle();
  oldLimitApi.post = () => response({ error: 'Old daily network limit', retry_after_seconds: 86400 }, 429);
  oldLimitApi.get = () => { throw new Error('Transient status outage'); };
  await oldLimit.get('faucet-claim').click(); await settle();
  assert.equal(oldLimit.get('faucet-claim').disabled, true); checks++;
  assert.match(oldLimit.get('faucet-status').textContent, /Available in 1d 0h/); checks++;
  oldLimitApi.get = null; oldLimit.wallClock += 11000; await oldLimit.refresh(); await settle();
  assert.equal(oldLimit.get('faucet-claim').disabled, false, 'eligible server status clears client-only stale 429 lock'); checks++;
  assert.equal(oldLimit.get('faucet-status').hidden, true); checks++;

  // A new advertised payout must not rewrite receipts from earlier claims.
  const raisedApi = service();
  raisedApi.status.amount_hashes = '1000000000000000';
  raisedApi.status.address = addr('56'.repeat(32));
  raisedApi.claims.set(addr(first), claim('confirmed'));
  const raised = await harness({ faucetTransport: raisedApi.fetch }); await settle();
  assert.equal(raised.get('faucet-amount').textContent, '0.001 hash', 'one petahash is advertised in the fixed hash unit'); checks++;
  assert.match(raised.get('faucet-status').textContent, /^0\.000001 hash received\./, 'the old receipt retains its actual payout'); checks++;
  assert.equal(raised.get('faucet-claim').disabled, true, 'a higher payout does not bypass an existing cooldown'); checks++;
  assert.equal(posts(raised).length, 0, 'a changed advertised payout never automatically claims again'); checks++;
  raised.currentSession = { ...raised.currentSession, public_key: second, wallet_id: `watch:${second}`, wallet_enabled: false, wallet_mode: 'watch', wallets: [{ id: `watch:${second}`, public_key: second, mode: 'watch' }] };
  await raised.refresh(); await settle();
  assert.equal(raised.get('faucet-status').hidden, true, 'the old payout receipt stays with its original wallet'); checks++;
  assert.equal(raised.get('faucet-amount').textContent, '0.001 hash'); checks++;
  raisedApi.post = body => {
    const receipt = { ...claim(), txid: 'e'.repeat(64), amount_hashes: raisedApi.status.amount_hashes };
    raisedApi.claims.set(body.address, receipt); return response(receipt);
  };
  await raised.get('faucet-claim').click(); await settle();
  assert.equal(JSON.parse(posts(raised)[0].options.body).address, addr(second)); checks++;
  assert.match(raised.get('faucet-status').textContent, /Pending/); checks++;
  raisedApi.claims.get(addr(second)).status = 'confirmed';
  raised.wallClock += 11000; await raised.refresh(); await settle();
  assert.match(raised.get('faucet-status').textContent, /^0\.001 hash received\./, 'the new receipt reports its own larger payout'); checks++;
  assert.equal(raisedApi.claims.get(addr(first)).amount_hashes, '1000000000000'); checks++;

  const realApi = service(), real = await harness({ realWallet: true, publicWeb: true, faucetTransport: realApi.fetch });
  await real.get('wallet-create').click(); await settle(); const walletA = real.browserStore.snapshot();
  await real.get('faucet-claim').click(); await settle();
  assert.equal(JSON.parse(posts(real)[0].options.body).address, walletA.address); checks++;
  assert.equal(real.get('wallet-public').textContent, walletA.address); checks++;
  await real.get('wallet-create').click(); await settle(); const walletB = real.browserStore.snapshot();
  assert.notEqual(walletB.address, walletA.address); checks++;
  assert.equal(real.get('faucet-status').hidden, true, 'first wallet receipt is not displayed on the new wallet'); checks++;
  await real.get('faucet-claim').click(); await settle();
  assert.equal(JSON.parse(posts(real)[1].options.body).address, walletB.address); checks++;
  assert.equal(real.get('wallet-public').textContent, walletB.address); checks++;
  assert.notEqual(JSON.parse(posts(real)[1].options.body).address, realApi.status.address, 'server funding account is never the recipient'); checks++;
  console.log(`Faucet UI: ${checks} integration assertions passed.`);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
