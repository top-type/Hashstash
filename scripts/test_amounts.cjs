'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { parseAmount, formatAmount, formatHash, formatExactHash, formatWork, formatExactWork, formatHashrate, exactInput } = require('../ui/amounts.js');

let checks = 0;
function equal(actual, expected) { assert.equal(actual, expected); checks += 1; }
function rejects(fn) { assert.throws(fn); checks += 1; }

for (const [input, output] of [
  ['0','0'], ['000001','1000'], ['1.000','1000'], ['.001','1'], ['1.25 hash','1250'],
  ['0.001 hash','1'], ['9007199254740993','9007199254740993000'],
  ['9007199254740.993','9007199254740993'], ['1.001','1001'], ['  2.5 hash  ','2500'],
]) equal(parseAmount(input), output);
for (const input of ['', ' ', '-1', '-0', '+1', '1e3', '1E3', '1m', 'NaN', 'Infinity', '1,000', '1_000', '1.2.3', '1.', '1 hashes', '1 HASH', '1 exa', '1 constructor', '1 toString', '1 hash/s', '1 hash h', '1h', '1 h', '1 kh', '1Mh', '1 Gh', '1 Th', '1 Ph', '1 Eh', '1 Zh', '1 Yh', '1E', '1 peta', '1 mega', '0.0001', '0.0000', '1.0000']) rejects(() => parseAmount(input));
rejects(() => parseAmount(1000));
rejects(() => parseAmount('0'.repeat(191)));
rejects(() => parseAmount('9'.repeat(158)));
equal(parseAmount('9'.repeat(157)), '9'.repeat(157) + '000');
equal(parseAmount('0'.repeat(190)), '0');

for (const [numerator, denominator, output] of [
  [0n, 1n, '0'], [1n, 1n, '1'], [12345n, 1n, '12.3 k'], [12350n, 1n, '12.4 k'],
  [9994n, 10n, '999'], [9995n, 10n, '1 k'], [999499n, 1n, '999 k'], [999500n, 1n, '1 M'],
  [999900n, 1n, '1 M'], [1000n, 1n, '1 k'], [1000000n, 1n, '1 M'],
  [10n ** 9n, 1n, '1 G'], [10n ** 12n, 1n, '1 T'], [10n ** 15n, 1n, '1 P'],
  [10n ** 18n, 1n, '1 E'], [10n ** 21n, 1n, '1 Z'], [10n ** 24n, 1n, '1 Y'],
  [999n * 10n ** 24n, 1n, '999 Y'], [10n ** 27n, 1n, '1e27'],
  [9995n * 10n ** 23n, 1n, '1e27'], [1n, 3n, '0.333'], [2n, 3n, '0.667'],
  [1n, 1000n, '0.001'], [12345n, 10000000n, '0.00123'], [1n, 10000n, '1e-4'],
  [1n, 3000000n, '3.33e-7'], [9999n, 10000000n, '1e-3'],
  [9007199254740993n, 1n, '9.01 P'], [9007199254740993n, 9007199254740992n, '1'],
  [10n ** 159n, 3n, '3.33e158'], [1n, 10n ** 159n, '1e-159'],
  [-12345n, 1n, '-12.3 k'], ['123456789012345678901234567890', '1', '1.23e29'],
]) equal(formatAmount(numerator, denominator), output);
rejects(() => formatAmount(1234));
rejects(() => formatAmount('1.2'));
rejects(() => formatAmount(1n, 0n));
rejects(() => formatAmount(1n, -1n));

for (const [n, d, expected] of [
  ['0','1','0 hash'], ['1','1','0.001 hash'], ['1000','1','1 hash'],
  ['1000000000000','1','1000000000 hash'], ['9999994','10000','0.999999 hash'],
  ['9999995','10000','1 hash'], ['1234567','1000','1.23457 hash'],
  ['9007199254740993','1','9007200000000 hash'], ['1','3','0.000333333 hash'],
  ['-12345','1','-12.345 hash'],
]) equal(formatHash(n,d),expected);
// Mining counts are physical hashes, independent of monetary atom denomination.
for (const [n,d,expected] of [
  ['0','1','0 EH'], ['1','1','0.000000000000000001 EH'],
  ['1000000000000000','1','0.001 EH'], ['1000000000000000000','1','1 EH'],
  ['1234567890000000000','1','1.23457 EH'], ['1','3','0.000000000000000000333333 EH'],
]) equal(formatWork(n,d),expected);
equal(formatHashrate('200000000000000'), '0.0002 EH/s');
equal(formatExactWork('1000000000000000001'), '1.000000000000000001 EH');
equal(formatExactWork('1','3'), '1 / 3000000000000000000 EH');
equal(formatExactHash('1001'),'1.001 hash');
equal(formatExactHash('-1001'),'-1.001 hash');
equal(formatExactHash('1','2'),'0.0005 hash');
equal(formatExactHash('1','3'),'1 / 3000 hash');
equal(formatExactHash('2000','2'),'1 hash');
for (const [raw, expected] of [
  ['1000','1'], ['1500000','1500'], ['1001','1.001'],
  ['9007199254740993','9007199254740.993'], ['0000','0'],
]) equal(exactInput(raw),expected);
rejects(() => exactInput(-1n));
rejects(() => exactInput(10n ** 160n));
rejects(() => exactInput(9007199254740992));
for (const fn of [formatHash, formatExactHash, formatWork, formatExactWork, formatHashrate]) {
  rejects(() => fn('1', '0')); rejects(() => fn('1', '-1')); rejects(() => fn(1));
}
for (const amount of [0n, 1n, 999n, 1000n, 1500n, 1001n, 1234000n, 1500000n, 9007199254740993n, 9007199254740993000n, 10n ** 24n, 10n ** 159n, 10n ** 160n - 1n]) {
  equal(parseAmount(exactInput(amount)), amount.toString());
}

// Deterministic wide-integer coverage: input helpers never round an auto-filled amount.
let state = 0x123456789abcdefn;
for (let i = 0; i < 512; i += 1) {
  state = (state * 6364136223846793005n + 1442695040888963407n) % (10n ** 150n);
  equal(parseAmount(exactInput(state)), state.toString());
}

// Same source also loads directly as a browser script with no CommonJS globals.
const browser = {};
vm.createContext(browser);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../ui/amounts.js'), 'utf8'), browser);
equal(browser.HashstashAmounts.parseAmount('2.5'), '2500');
equal(browser.HashstashAmounts.formatAmount('9007199254740993'), '9.01 P');
equal(browser.HashstashAmounts.formatHash('9007199254740993'), '9007200000000 hash');
equal(browser.HashstashAmounts.parseAmount('2.5 hash'), '2500');
console.log(`Amount utility: ${checks} assertions passed.`);
