// Hashstash addresses: BIP350 Bech32m over a 32-byte x-only public key.
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.HashstashAddress = api;
})(globalThis, function () {
  'use strict';
  const alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const constant = 0x2bc830a3;
  function hrp(value) {
    if (typeof value !== 'string' || !/^hsh[0-9a-f]{16}$/.test(value)) throw new Error('Address network is unavailable.');
    return value;
  }
  function expand(value) {
    return [...value].map(character => character.charCodeAt(0) >>> 5).concat(0, [...value].map(character => character.charCodeAt(0) & 31));
  }
  function polymod(values) {
    let check = 1;
    for (const value of values) {
      const top = check >>> 25;
      check = ((check & 0x1ffffff) << 5) ^ value;
      for (let bit = 0; bit < 5; bit++) if ((top >>> bit) & 1) check ^= generators[bit];
    }
    return check >>> 0;
  }
  function convert(values, from, to, pad) {
    let accumulator = 0, bits = 0;
    const result = [], mask = (1 << to) - 1, maximum = (1 << (from + to - 1)) - 1;
    for (const value of values) {
      if (!Number.isInteger(value) || value < 0 || value >>> from) throw new Error('Invalid address payload.');
      accumulator = ((accumulator << from) | value) & maximum;
      bits += from;
      while (bits >= to) { bits -= to; result.push((accumulator >>> bits) & mask); }
    }
    if (pad) { if (bits) result.push((accumulator << (to - bits)) & mask); }
    else if (bits >= from || ((accumulator << (to - bits)) & mask)) throw new Error('Invalid address padding.');
    return result;
  }
  function encode(publicKey, network) {
    network = hrp(network);
    if (typeof publicKey !== 'string' || !/^[0-9a-f]{64}$/i.test(publicKey)) throw new Error('Public key must contain 32 bytes.');
    const bytes = publicKey.match(/../g).map(pair => parseInt(pair, 16));
    const data = convert(bytes, 8, 5, true);
    const check = polymod(expand(network).concat(data, [0, 0, 0, 0, 0, 0])) ^ constant;
    const checksum = Array.from({length:6}, (_, index) => (check >>> (5 * (5 - index))) & 31);
    return network + '1' + data.concat(checksum).map(value => alphabet[value]).join('');
  }
  function decode(address, expectedHrp) {
    expectedHrp = hrp(expectedHrp);
    if (typeof address !== 'string' || address.length !== 78) throw new Error('Address must contain 78 characters.');
    if (/[^\x21-\x7e]/.test(address)) throw new Error('Invalid address characters.');
    if (address !== address.toLowerCase() && address !== address.toUpperCase()) throw new Error('Address must not mix uppercase and lowercase.');
    address = address.toLowerCase();
    const split = address.lastIndexOf('1'), network = address.slice(0, split);
    if (network !== expectedHrp) throw new Error('Address belongs to a different network.');
    const data = [...address.slice(split + 1)].map(character => alphabet.indexOf(character));
    if (data.length !== 58 || data.some(value => value < 0)) throw new Error('Invalid address characters.');
    if (polymod(expand(network).concat(data)) !== constant) throw new Error('Address checksum does not match.');
    const bytes = convert(data.slice(0, -6), 5, 8, false);
    if (bytes.length !== 32) throw new Error('Address must contain a 32-byte public key.');
    return bytes.map(value => value.toString(16).padStart(2, '0')).join('');
  }
  return Object.freeze({encode, decode});
});
