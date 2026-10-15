(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.HashstashShares = api;
})(globalThis, function () {
  'use strict';

  // Wire quantities stay integer share atoms; the displayed stash denomination
  // is 10^36 atoms.
  const PLACES = 36;
  const SCALE = 10n ** BigInt(PLACES);
  const MAX_INPUT_LENGTH = 190;
  const MAX_AMOUNT_DIGITS = 160;

  function integer(value) {
    if (typeof value === 'bigint') return value;
    if (typeof value !== 'string' || !/^-?\d+$/.test(value)) {
      throw new TypeError('Expected an integer string or BigInt.');
    }
    return BigInt(value);
  }

  function trimDecimal(value) {
    return value.includes('.') ? value.replace(/0+$/, '').replace(/\.$/, '') : value;
  }

  function parseAmount(text) {
    if (typeof text !== 'string') throw new TypeError('Enter the stash amount as text.');
    if (text.length > MAX_INPUT_LENGTH) throw new RangeError('Stash input is too long.');
    const match = /^(\d+(?:\.\d+)?|\.\d+)(?:\s*stash)?$/.exec(text.trim());
    if (!match) throw new Error('Enter a stash amount as a decimal, optionally followed by stash.');
    const [whole, fraction = ''] = match[1].split('.');
    if (fraction.length > PLACES) throw new Error('Stash supports up to 36 decimal places.');
    const digits = (whole + fraction.padEnd(PLACES, '0')).replace(/^0+/, '') || '0';
    if (digits.length > MAX_AMOUNT_DIGITS) throw new RangeError('Stash amount exceeds 160 digits.');
    return digits;
  }

  function exactInput(value) {
    const amount = integer(value);
    if (amount < 0n) throw new RangeError('Stash amount must not be negative.');
    const digits = amount.toString();
    if (digits.length > MAX_AMOUNT_DIGITS) throw new RangeError('Stash amount exceeds 160 digits.');
    const padded = digits.padStart(PLACES + 1, '0');
    return trimDecimal(padded.slice(0, -PLACES) + '.' + padded.slice(-PLACES));
  }

  function power10(exponent) { return 10n ** BigInt(exponent); }

  function decimalExponent(numerator, denominator) {
    let exponent = numerator.toString().length - denominator.toString().length;
    if (exponent >= 0) {
      if (numerator < denominator * power10(exponent)) exponent -= 1;
    } else if (numerator * power10(-exponent) < denominator) exponent -= 1;
    return exponent;
  }

  function decimalText(significand, exponent) {
    const digits = significand.toString();
    const point = digits.length + exponent;
    if (point <= 0) return trimDecimal('0.' + '0'.repeat(-point) + digits);
    if (point >= digits.length) return digits + '0'.repeat(point - digits.length);
    return trimDecimal(digits.slice(0, point) + '.' + digits.slice(point));
  }

  function formatAmount(numerator, denominator = 1n) {
    numerator = integer(numerator);
    denominator = integer(denominator);
    if (denominator <= 0n) throw new RangeError('Denominator must be positive.');
    if (numerator === 0n) return '0';
    const sign = numerator < 0n ? '-' : '';
    if (numerator < 0n) numerator = -numerator;
    denominator *= SCALE;
    const exponent = decimalExponent(numerator, denominator);
    const shift = 5 - exponent;
    if (shift >= 0) numerator *= power10(shift);
    else denominator *= power10(-shift);
    const significand = numerator / denominator + (2n * (numerator % denominator) >= denominator ? 1n : 0n);
    // Six significant digits, including sub-atom rational values, without a
    // floating-point conversion or scientific notation at either extreme.
    return sign + decimalText(significand, exponent - 5);
  }

  return Object.freeze({ parseAmount, formatAmount, exactInput, DISPLAY_DECIMALS: PLACES, DISPLAY_SCALE: SCALE });
});
