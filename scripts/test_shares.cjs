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
const SCALE = 1000n;
const atom = '0.001';
equal(shares.DISPLAY_DECIMALS, 3);
equal(shares.DISPLAY_SCALE, SCALE);
assert.ok(Object.isFrozen(shares)); checks++;
// Both display units use1000atoms; no hidden secondary rescaling.
equal(shares.parseAmount('1'),'1000');
equal(hashes.parseAmount('1'),'1000');
equal(shares.exactInput(hashes.parseAmount('1')),'1');
for (const [input,raw] of [
  ['0','0'], ['000.000','0'], ['1','1000'], ['95','95000'], ['  01.250  ','1250'],
  ['.5','500'], [atom,'1'], ['1.001','1001'], ['1000','1000000'],
  ['1000.001','1000001'], ['1 stash','1000'], ['.5stash','500'], [' 0.001 stash ','1'],
]) equal(shares.parseAmount(input),raw);
for (const bad of ['', ' ', '1E18', '1e18', '1 HASH', '1 shares', '1 exa stash', '1m', '1 constructor', '1 toString', '1 mega exa',
  '1k', '1M', '1E', '1 h', '1 Ph', '1 kilo', '1 mega', '1 giga', '1 tera', '1 peta', '1 exa', '1 zetta', '1 yotta',
  '1 exastash', '1 exa shares', '1 STASH', '1 stash extra', '-1', '+1', '1,000', '1.', '.', '0x10', '1/2', 'NaN', 'Infinity', '1 2', '1\n2',
  '0.0001','1.0000','0.0001 stash','9'.repeat(158),'0'.repeat(191)]) reject(()=>shares.parseAmount(bad));
for (const bad of [null,undefined,1,1n,{}]) reject(()=>shares.parseAmount(bad));
const maxRaw='9'.repeat(160);
equal(shares.parseAmount(shares.exactInput(maxRaw)),maxRaw);
equal(shares.parseAmount(shares.exactInput(maxRaw)+' stash'),maxRaw);
equal(shares.parseAmount('9'.repeat(157)),'9'.repeat(157)+'000');
reject(()=>shares.exactInput('1'+'0'.repeat(160)));
reject(()=>shares.exactInput(-1n));reject(()=>shares.exactInput(1));
for (const [raw,text] of [['0','0'],['1',atom],['10','0.01'],['1000','1'],['1234','1.234'],['1001','1.001'],['95000','95'],['9007199254740993','9007199254740.993']]) {
  equal(shares.exactInput(raw),text);equal(shares.exactInput(BigInt(raw)),text);equal(shares.parseAmount(text),raw);
}
for(const [raw,text] of [[0n,'0'],[1n,atom],[1234n,'1.234'],[1234567n,'1234.57'],[SCALE,'1'],[95n*SCALE,'95'],[1234n*SCALE,'1234'],
  [1234567n*SCALE,'1234570'],[9999994n*SCALE/10n,'999999'],[9999995n*SCALE/10n,'1000000'],[10n**18n,'1000000000000000'],[BigInt(maxRaw),'1'+'0'.repeat(157)]]) {
  equal(shares.formatAmount(raw),text);equal(shares.formatAmount(raw.toString()),text);
}
// Price and valuation ratios can be finer than an indivisible share atom.
equal(shares.formatAmount(1234567n,1000n),'1.23457');
equal(shares.formatAmount(-1234567n,1000n),'-1.23457');
equal(shares.formatAmount(9999994n,10000n),'0.999999');
equal(shares.formatAmount(9999995n,10000n),'1');
equal(shares.formatAmount(SCALE,3n),'0.333333');
equal(shares.formatAmount(1n,3n),'0.000333333');
equal(shares.formatAmount(SCALE.toString(),'8'),'0.125');
equal(shares.formatAmount(3000n*SCALE,2n),'1500');
equal(shares.formatAmount(10n**21n,3n),'333333000000000000');
equal(shares.formatAmount(-(10n**21n),3n),'-333333000000000000');
reject(()=>shares.formatAmount(SCALE,0n));reject(()=>shares.formatAmount(SCALE,-1n));reject(()=>shares.formatAmount(1));

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
// helper may apply a second unit conversion to share atoms.
const browser = {};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../ui/shares.js'), 'utf8'), browser);
equal(browser.HashstashShares.DISPLAY_SCALE, SCALE);
equal(browser.HashstashShares.exactInput((95n * SCALE).toString()), '95');
equal(browser.HashstashShares.parseAmount('95 stash'), (95n * SCALE).toString());
equal(browser.HashstashShares.formatAmount((1000n * SCALE).toString()), '1000');
equal(browser.HashstashShares.parseAmount('1000'), (1000n * SCALE).toString());
assert.equal(browser.HashstashAmounts, undefined); checks++;
console.log(`Share formatting: ${checks} assertions passed`);
