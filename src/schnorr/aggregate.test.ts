import { describe, it, expect } from 'vitest';
import { aggregateTwo, verifyTextbook } from './aggregate.js';
import { N, G, mod, utf8 } from './field.js';

describe('Linearity: two signers combine into one signature', () => {
  it('the summed response s1+s2 verifies against the combined key', () => {
    const msg = utf8('joint statement');
    const r = aggregateTwo(msg, 111n, 222n, 333n, 444n);
    expect(r.verifies).toBe(true);
    // s is literally s1 + s2 (mod n).
    expect(r.s).toBe(mod(r.signers[0].s + r.signers[1].s, N));
  });

  it('holds across many signer/nonce combinations', () => {
    for (let i = 1; i <= 20; i++) {
      const r = aggregateTwo(utf8(`round ${i}`), BigInt(31 * i + 1), BigInt(97 * i + 5), BigInt(53 * i + 9), BigInt(71 * i + 3));
      expect(r.verifies).toBe(true);
    }
  });

  it('the verifier rejects a wrong combined response and a swapped commitment', () => {
    const msg = utf8('joint statement');
    const r = aggregateTwo(msg, 111n, 222n, 333n, 444n);
    const Pagg = G.multiply(111n).add(G.multiply(222n));
    const Ragg = G.multiply(333n).add(G.multiply(444n));
    // Correct (R, s) accepts.
    expect(verifyTextbook(msg, Pagg, Ragg, r.s)).toBe(true);
    // Wrong s rejects.
    expect(verifyTextbook(msg, Pagg, Ragg, mod(r.s + 1n, N))).toBe(false);
    // Right s but wrong commitment rejects.
    expect(verifyTextbook(msg, Pagg, G.multiply(1n), r.s)).toBe(false);
  });
});
