(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.HashstashAmounts = api;
})(globalThis, function () {
  'use strict';

  const PREFIXES = ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'];
  const PLACES = 18;
  const SCALE = 10n ** BigInt(PLACES);
  const MAX_INPUT_LENGTH = 190;
  const MAX_AMOUNT_DIGITS = 160;

  function parseAmount(text) {
    if (typeof text !== 'string') throw new TypeError('Enter the amount as text.');
    if (text.length > MAX_INPUT_LENGTH) throw new RangeError('Amount input is too long.');
    const match = /^(\d+(?:\.\d+)?|\.\d+)(?:\s*hash)?$/.exec(text.trim());
    if (!match) throw new Error('Enter a hash amount as a decimal, optionally followed by hash.');
    const parts = match[1].split('.');
    const fraction = parts[1] || '';
    if (fraction.length > PLACES) throw new Error('Hash amounts support up to 18 decimal places.');
    const digits = (parts[0] + fraction.padEnd(PLACES, '0')).replace(/^0+/, '') || '0';
    if (digits.length > MAX_AMOUNT_DIGITS) throw new RangeError('Amount exceeds 160 digits.');
    return digits;
  }

  function integer(value) {
    if (typeof value === 'bigint') return value;
    if (typeof value !== 'string' || !/^-?\d+$/.test(value)) {
      throw new TypeError('Expected an integer string or BigInt.');
    }
    return BigInt(value);
  }

  function power10(exponent) { return 10n ** BigInt(exponent); }

  // Decimal lengths locate the exponent; one exact comparison settles the boundary.
  function decimalExponent(numerator, denominator) {
    let exponent = numerator.toString().length - denominator.toString().length;
    if (exponent >= 0) {
      if (numerator < denominator * power10(exponent)) exponent -= 1;
    } else if (numerator * power10(-exponent) < denominator) {
      exponent -= 1;
    }
    return exponent;
  }

  function roundedSignificand(numerator, denominator, exponent) {
    const scale = 2 - exponent;
    if (scale >= 0) numerator *= power10(scale);
    else denominator *= power10(-scale);
    const quotient = numerator / denominator;
    return quotient + (2n * (numerator % denominator) >= denominator ? 1n : 0n);
  }

  function trimDecimal(value) {
    return value.includes('.') ? value.replace(/0+$/, '').replace(/\.$/, '') : value;
  }

  // A three-digit integer significand represents significand / 100 * 10^exponent.
  function decimalText(significand, exponent) {
    const digits = significand.toString();
    const point = digits.length + exponent - 2;
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
    let exponent = decimalExponent(numerator, denominator);
    const tiny = exponent < -3;
    let significand = roundedSignificand(numerator, denominator, exponent);
    if (significand === 1000n) {
      significand = 100n;
      exponent += 1;
    }
    if (tiny || exponent >= 27) return sign + decimalText(significand, 0) + 'e' + exponent;
    const unit = exponent < 3 ? 0 : Math.floor(exponent / 3);
    return sign + decimalText(significand, exponent - 3 * unit) + (unit ? ' ' + PREFIXES[unit] : '');
  }

  function formatWork(numerator, denominator = 1n) {
    return formatHash(numerator, denominator).replace(/ hash$/, ' EH');
  }

  function formatHashrate(numerator, denominator = 1n) {
    return formatWork(numerator, denominator) + '/s';
  }

  // Monetary displays stay in hash. Significant-digit rounding is performed with
  // integer arithmetic, including values smaller than one atomic unit in price ratios.
  function formatHash(numerator, denominator = 1n) {
    numerator = integer(numerator); denominator = integer(denominator);
    if (denominator <= 0n) throw new RangeError('Denominator must be positive.');
    if (numerator === 0n) return '0 hash';
    const sign = numerator < 0n ? '-' : '';
    if (numerator < 0n) numerator = -numerator;
    denominator *= SCALE;
    const exponent = decimalExponent(numerator, denominator), shift = 5 - exponent;
    if (shift >= 0) numerator *= power10(shift);
    else denominator *= power10(-shift);
    const rounded = numerator / denominator + (2n * (numerator % denominator) >= denominator ? 1n : 0n);
    // decimalText normally takes a three-digit significand; offset for six.
    return sign + decimalText(rounded, exponent - 3) + ' hash';
  }

  function exactInput(value) {
    const amount = integer(value);
    if (amount < 0n) throw new RangeError('Amount must not be negative.');
    const digits = amount.toString();
    if (digits.length > MAX_AMOUNT_DIGITS) throw new RangeError('Amount exceeds 160 digits.');
    const padded = digits.padStart(PLACES + 1, '0');
    return trimDecimal(padded.slice(0, -PLACES) + '.' + padded.slice(-PLACES));
  }

  function formatExactHash(numerator, denominator = 1n) {
    numerator = integer(numerator); denominator = integer(denominator);
    if (denominator <= 0n) throw new RangeError('Denominator must be positive.');
    if (denominator === 1n) return (numerator < 0n ? '-' + exactInput(-numerator) : exactInput(numerator)) + ' hash';
    const sign = numerator < 0n ? '-' : '';
    if (numerator < 0n) numerator = -numerator;
    if (numerator === 0n) return '0 hash';
    denominator *= SCALE;
    let a = numerator, b = denominator;
    while (b) { const remainder = a % b; a = b; b = remainder; }
    numerator /= a; denominator /= a;
    let reduced = denominator, twos = 0, fives = 0;
    while (reduced % 2n === 0n) { reduced /= 2n; twos++; }
    while (reduced % 5n === 0n) { reduced /= 5n; fives++; }
    if (reduced !== 1n) return `${sign}${numerator} / ${denominator} hash`;
    const places = Math.max(twos, fives);
    const digits = (numerator * power10(places) / denominator).toString().padStart(places + 1, '0');
    return sign + (places ? trimDecimal(digits.slice(0, -places) + '.' + digits.slice(-places)) : digits) + ' hash';
  }

  return Object.freeze({ parseAmount, formatAmount, formatHash, formatExactHash, formatWork, formatHashrate, exactInput });
});
