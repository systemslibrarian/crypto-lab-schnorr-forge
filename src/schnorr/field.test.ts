import { describe, it, expect } from 'vitest';
import {
  hexToBytes,
  bytesToHex,
  bytesToBig,
  bigTo32,
  mod,
  invN,
  N,
  normalizeSecretKey,
  liftX,
  P,
} from './field.js';

describe('hexToBytes strict parsing (fail-closed)', () => {
  const bad = ['0g', 'g0', 'ff_', 'fg', '0x1234', '12 34 5', 'zz', 'абв', '11!', ' 0g '];
  for (const s of bad) {
    it(`rejects malformed input ${JSON.stringify(s)} instead of partial-parsing`, () => {
      expect(() => hexToBytes(s)).toThrow();
    });
  }

  it('rejects odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow(/odd-length/);
  });

  it('accepts empty string as zero bytes (empty message)', () => {
    expect(hexToBytes('')).toEqual(new Uint8Array(0));
  });

  it('round-trips upper- and lower-case identically', () => {
    const hex = 'DEADBEEF00FF';
    expect(bytesToHex(hexToBytes(hex))).toBe(hex.toLowerCase());
    expect(hexToBytes(hex)).toEqual(hexToBytes(hex.toLowerCase()));
  });

  it('preserves leading zero bytes', () => {
    expect([...hexToBytes('0001ff')]).toEqual([0, 1, 255]);
  });

  it('tolerates surrounding/interior whitespace the UI permits', () => {
    expect(bytesToHex(hexToBytes('  de ad be ef  '))).toBe('deadbeef');
  });
});

describe('bigint <-> 32-byte encoding boundaries', () => {
  it('encodes 0 and the max 32-byte value', () => {
    expect([...bigTo32(0n)]).toEqual(Array(32).fill(0));
    expect(bytesToBig(bigTo32((1n << 256n) - 1n))).toBe((1n << 256n) - 1n);
  });

  it('throws on values that do not fit in 32 bytes', () => {
    expect(() => bigTo32(-1n)).toThrow();
    expect(() => bigTo32(1n << 256n)).toThrow();
  });

  it('round-trips scalar boundaries 0, 1, n-1', () => {
    for (const v of [0n, 1n, N - 1n]) expect(bytesToBig(bigTo32(v))).toBe(v);
  });
});

describe('scalar helpers', () => {
  it('mod is always the least non-negative residue', () => {
    expect(mod(-1n, N)).toBe(N - 1n);
    expect(mod(N, N)).toBe(0n);
  });

  it('invN inverts across the scalar field', () => {
    for (const a of [1n, 2n, 3n, 12345n, N - 1n]) {
      expect(mod(a * invN(a), N)).toBe(1n);
    }
  });

  it('normalizeSecretKey yields an even-y public key and is idempotent', () => {
    for (const seed of [1n, 2n, 3n, 999n, N - 5n]) {
      const d = normalizeSecretKey(seed);
      expect(normalizeSecretKey(d)).toBe(d);
    }
  });
});

describe('liftX fail-closed domain', () => {
  it('rejects 0, p, and values ≥ p', () => {
    expect(liftX(0n)).toBeNull();
    expect(liftX(P)).toBeNull();
    expect(liftX(P + 1n)).toBeNull();
  });

  it('lifts the generator x to an even-y point', () => {
    const pt = liftX(bytesToBig(hexToBytes('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')));
    expect(pt).not.toBeNull();
    expect(mod(pt!.y, 2n)).toBe(0n);
  });
});
