'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const shares = require('../ui/shares.js');
const hashes = require('../ui/amounts.js');
let checks = 0;
const equal = (actual, expected) => { assert.equal(actual, expected); checks++; };
const reject = action => { assert.throws(action); checks++; };
const SCALE = 10n ** 36n;
const atom = '0.' + '0'.repeat(35) + '1';

equal(shares.DISPLAY_DECIMALS, 36);
equal(shares.DISPLAY_SCALE, SCALE);
assert.ok(Object.isFrozen(shares)); checks++;
// Relabeling the display as stash leaves its 10^36-atom scale unchanged.
equal(shares.parseAmount('1'), '1000000000000000000000000000000000000');
equal(hashes.parseAmount('1'), '1000000000000000000');
equal(shares.exactInput(hashes.parseAmount('1')), '0.000000000000000001');
equal(shares.parseAmount(shares.exactInput(SCALE)), SCALE.toString());

for (const [input, raw] of [
  ['0', '0'], ['000.000', '0'], ['1', SCALE.toString()], ['95', (95n * SCALE).toString()],
  ['  01.2500  ', (125n * SCALE / 100n).toString()], ['.5', (SCALE / 2n).toString()],
  [atom, '1'], ['1.' + '0'.repeat(35) + '1', (SCALE + 1n).toString()],
  ['1000', (1000n * SCALE).toString()],
  ['1000.' + '0'.repeat(35) + '1', (1000n * SCALE + 1n).toString()],
  ['1 stash', SCALE.toString()], ['.5stash', (SCALE / 2n).toString()],
  [' 0.000001 stash ', (10n ** 30n).toString()], [atom + ' stash', '1'],
]) equal(shares.parseAmount(input), raw);

for (const bad of ['', ' ', '1E18', '1e18', '1 HASH', '1 shares', '1 exa stash', '1m', '1 constructor', '1 toString', '1 mega exa',
  '1k', '1M', '1E', '1 h', '1 Ph', '1 kilo', '1 mega', '1 giga', '1 tera', '1 peta', '1 exa', '1 zetta', '1 yotta',
  '1 exastash', '1 exa shares', '1 STASH', '1 stash extra',
  '-1', '+1', '1,000', '1.', '.', '0x10', '1/2', 'NaN', 'Infinity', '1 2', '1\n2',
  '0.' + '0'.repeat(36) + '1', '1.' + '0'.repeat(37), '0.' + '0'.repeat(36) + '1 stash',
  '9'.repeat(140) + ' kilo', '9'.repeat(125), '0'.repeat(191)]) {
  reject(() => shares.parseAmount(bad));
}
for (const bad of [null, undefined, 1, 1n, {}]) reject(() => shares.parseAmount(bad));

const maxRaw = '9'.repeat(160);
equal(shares.parseAmount(shares.exactInput(maxRaw)), maxRaw);
equal(shares.parseAmount(shares.exactInput(maxRaw) + ' stash'), maxRaw);
equal(shares.parseAmount('9'.repeat(124)), '9'.repeat(124) + '0'.repeat(36));
reject(() => shares.exactInput('1' + '0'.repeat(160)));
reject(() => shares.exactInput(-1n));
reject(() => shares.exactInput(1));

for (const [raw, text] of [
  ['0', '0'], ['1', atom], ['10', '0.' + '0'.repeat(34) + '1'],
  [(10n ** 18n).toString(), '0.000000000000000001'],
  [SCALE.toString(), '1'], [(12345n * SCALE / 10000n).toString(), '1.2345'],
  [(SCALE + 1n).toString(), '1.' + '0'.repeat(35) + '1'],
  [(95n * SCALE).toString(), '95'],
]) {
  equal(shares.exactInput(raw), text);
  equal(shares.exactInput(BigInt(raw)), text);
  equal(shares.parseAmount(text), raw);
}

for (const [raw, text] of [
  [0n, '0'], [1n, atom], [1234n, '0.' + '0'.repeat(32) + '1234'],
  [1234567n, '0.' + '0'.repeat(29) + '123457'],
  [SCALE, '1'], [95n * SCALE, '95'], [1234n * SCALE, '1234'],
  [1234567n * SCALE, '1234570'],
  [1234567n * SCALE / 1000000n, '1.23457'], [-1234567n * SCALE / 1000000n, '-1.23457'],
  [9999994n * SCALE / 10000000n, '0.999999'], [9999995n * SCALE / 10000000n, '1'],
  [9999994n * SCALE / 10n, '999999'], [9999995n * SCALE / 10n, '1000000'],
  [10n ** 18n, '0.000000000000000001'], [10n ** 21n, '0.000000000000001'],
  [10n ** 24n, '0.000000000001'], [10n ** 27n, '0.000000001'],
  [10n ** 30n, '0.000001'], [10n ** 33n, '0.001'],
  [10n ** 36n, '1'], [10n ** 39n, '1000'], [10n ** 42n, '1000000'],
  [999n * 10n ** 42n, '999000000'], [10n ** 45n, '1000000000'],
  [10n ** 54n, '1000000000000000000'],
  [BigInt(maxRaw), '1' + '0'.repeat(124)],
]) {
  equal(shares.formatAmount(raw), text);
  equal(shares.formatAmount(raw.toString()), text);
}
equal(shares.formatAmount(SCALE, 3n), '0.333333');
equal(shares.formatAmount(1n, 3n), '0.' + '0'.repeat(36) + '333333');
equal(shares.formatAmount(SCALE.toString(), '8'), '0.125');
equal(shares.formatAmount(3000n * SCALE, 2n), '1500');
equal(shares.formatAmount(10n ** 54n, 3n), '333333000000000000');
equal(shares.formatAmount(-(10n ** 54n), 3n), '-333333000000000000');
reject(() => shares.formatAmount(SCALE, 0n));
reject(() => shares.formatAmount(SCALE, -1n));
reject(() => shares.formatAmount(1));

// Every supported decimal length and power-of-ten boundary keeps all signed
// atoms through editable/Max values, even far beyond Number precision.
for (let exponent = 0; exponent < 160; exponent++) {
  const boundary = 10n ** BigInt(exponent);
  for (const raw of [boundary - 1n, boundary, boundary + 1n]) {
    equal(shares.parseAmount(shares.exactInput(raw)), raw.toString());
    const rendered = shares.formatAmount(raw);
    assert.match(rendered, /^\d+(?:\.\d+)?$/, 'display is always a plain decimal'); checks++;
    if (raw > 0n) { assert.notEqual(rendered, '0'); checks++; }
  }
}
let seed = 1n;
for (let index = 0; index < 256; index++) {
  seed = (seed * 6364136223846793005n + 1442695040888963407n) % (1n << 512n);
  equal(shares.parseAmount(shares.exactInput(seed)), seed.toString());
}

// Browser and CommonJS expose the same independent share API. No monetary
// helper may apply a second 10^18 conversion to share atoms.
const browser = {};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../ui/shares.js'), 'utf8'), browser);
equal(browser.HashstashShares.DISPLAY_SCALE, SCALE);
equal(browser.HashstashShares.exactInput((95n * SCALE).toString()), '95');
equal(browser.HashstashShares.parseAmount('95 stash'), (95n * SCALE).toString());
equal(browser.HashstashShares.formatAmount((1000n * SCALE).toString()), '1000');
equal(browser.HashstashShares.parseAmount('1000'), (1000n * SCALE).toString());
assert.equal(browser.HashstashAmounts, undefined); checks++;
console.log(`Share formatting: ${checks} assertions passed`);
