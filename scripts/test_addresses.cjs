'use strict';
const assert = require('node:assert/strict');
const address = require('../ui/address.js');
const fixtures = require('../tests/data/addresses.json');
const alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
let checks = 0;
for (const vector of fixtures) {
  const hrp = 'hsh' + vector.chain_id.slice(0,16);
  assert.equal(address.encode(vector.public_key,hrp),vector.address); checks++;
  assert.equal(address.decode(vector.address,hrp),vector.public_key); checks++;
  assert.equal(address.decode(vector.address.toUpperCase(),hrp),vector.public_key); checks++;
  assert.equal(vector.address.length,78); checks++;
  for(let position=0;position<vector.address.length;position++) {
    for(const replacement of alphabet) {
      if(replacement === vector.address[position]) continue;
      const changed = vector.address.slice(0,position)+replacement+vector.address.slice(position+1);
      assert.throws(()=>address.decode(changed,hrp),`accepted substitution at ${position}`); checks++;
    }
  }
  assert.throws(()=>address.decode('H'+vector.address.slice(1),hrp),/mix/); checks++;
  assert.throws(()=>address.decode(vector.address.slice(1),hrp),/78/); checks++;
  assert.throws(()=>address.decode(vector.address+'q',hrp),/78/); checks++;
  assert.throws(()=>address.decode(vector.address,'hsh1111111111111111'),/network/); checks++;
  assert.throws(()=>address.decode(vector.public_key,hrp),/78/); checks++;
  // Unicode case folding must not create an accepted ASCII address spelling.
  const uppercase = vector.address.toUpperCase();
  if (uppercase.includes('K')) {
    assert.throws(()=>address.decode(uppercase.replace('K','\u212a'),hrp),/characters/); checks++;
  }
  assert.throws(()=>address.decode('\uff48'+vector.address.slice(1),hrp),/characters/); checks++;
}
// Independently encoded with valid Bech32m checksum, but nonzero four-bit padding.
assert.throws(()=>address.decode('hsh000102030405060710xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vp5dvq89','hsh0001020304050607'),/padding/); checks++;
for(const hrp of ['hsh000102030405060','hsh00010203040506070','HSH0001020304050607','hsh000102030405060g','bc']) {
  assert.throws(()=>address.encode(fixtures[0].public_key,hrp)); checks++;
}
for(const key of ['', 'ff'.repeat(31), 'ff'.repeat(33),'gg'.repeat(32)]) {
  assert.throws(()=>address.encode(key,'hsh0001020304050607')); checks++;
}
console.log(`Addresses: ${checks} assertions passed.`);
