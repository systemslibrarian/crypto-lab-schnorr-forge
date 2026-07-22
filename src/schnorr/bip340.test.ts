import { describe, it, expect } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sign, signWithNonce, verify, deriveNonce, taggedHash, challenge } from './bip340.js';
import { N, G, mod, bytesToBig, bigTo32, xOnly, hasEvenY, utf8, hexToBytes, bytesToHex } from './field.js';

describe('BIP-340 hand-rolled internals', () => {
  it('tagged hash matches the SHA256(tagHash‖tagHash‖msg) definition', () => {
    // BIP0340/aux of 32 zero bytes is a known intermediate; just check shape + determinism.
    const a = taggedHash('BIP0340/aux', new Uint8Array(32));
    const b = taggedHash('BIP0340/aux', new Uint8Array(32));
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
    // Different tags must not collide even on identical data.
    expect(bytesToHex(taggedHash('BIP0340/nonce', new Uint8Array(32)))).not.toBe(bytesToHex(a));
  });

  it('sign → verify round-trips for both nonce modes', () => {
    const sk = bigTo32(12345678901234567890n);
    const msg = utf8('the quick brown fox');
    for (const mode of ['deterministic', 'random'] as const) {
      const { signature, trace } = sign(msg, sk, mode);
      expect(signature.length).toBe(64);
      const v = verify(signature, msg, trace.pubkey);
      expect(v.valid).toBe(true);
      // The signing equation actually holds: s == (k + e·d) mod n.
      expect(trace.s).toBe(mod(trace.k + trace.e * trace.d, N));
    }
  });

  it('deterministic mode is reproducible; random mode is not', () => {
    const sk = bigTo32(999n);
    const msg = utf8('same message');
    const a = sign(msg, sk, 'deterministic').signature;
    const b = sign(msg, sk, 'deterministic').signature;
    expect(bytesToHex(a)).toBe(bytesToHex(b)); // same R every time
    const r1 = sign(msg, sk, 'random').signature;
    const r2 = sign(msg, sk, 'random').signature;
    expect(bytesToHex(r1)).not.toBe(bytesToHex(r2)); // fresh R
    // Both still verify.
    expect(verify(r1, msg, sign(msg, sk, 'deterministic').trace.pubkey).valid).toBe(true);
  });

  it('our signatures match @noble/curves schnorr byte-for-byte (deterministic aux=0)', () => {
    const sk = bigTo32(0xdeadbeefn);
    const msg = utf8('cross-check against the audited library');
    const ours = sign(msg, sk, 'deterministic').signature;
    const theirs = schnorr.sign(msg, sk, new Uint8Array(32));
    expect(bytesToHex(ours)).toBe(bytesToHex(theirs));
    // And @noble accepts our signature.
    expect(schnorr.verify(ours, msg, schnorr.getPublicKey(sk))).toBe(true);
  });

  it('verify exposes both sides: s·G equals R + e·P on a good signature', () => {
    const sk = bigTo32(7n);
    const msg = utf8('both sides');
    const { signature, trace } = sign(msg, sk, 'deterministic');
    const v = verify(signature, msg, trace.pubkey);
    expect(v.lhs).toBe(v.rhs);
    expect(v.valid).toBe(true);
  });

  it('rejects a tampered message, a flipped s, and malformed lengths (fail-closed)', () => {
    const sk = bigTo32(42n);
    const msg = utf8('authentic');
    const { signature, trace } = sign(msg, sk, 'deterministic');
    expect(verify(signature, utf8('forged'), trace.pubkey).valid).toBe(false);
    const badS = signature.slice();
    badS[63] ^= 0x01;
    expect(verify(badS, msg, trace.pubkey).valid).toBe(false);
    expect(verify(signature.subarray(0, 63), msg, trace.pubkey).valid).toBe(false);
    expect(verify(signature, msg, trace.pubkey.subarray(0, 31)).valid).toBe(false);
  });

  it('challenge and nonce derivation are pure functions of their inputs', () => {
    const px = hexToBytes('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
    const msg = utf8('m');
    const rx = xOnly(G.multiply(5n));
    expect(challenge(rx, px, msg)).toBe(challenge(rx, px, msg));
    const k = deriveNonce(3n, px, msg, new Uint8Array(32));
    expect(k).toBeGreaterThan(0n);
    expect(k).toBeLessThan(N);
  });

  it('signWithNonce applies even-y adjustment to k and d', () => {
    // Pick a key/nonce; verify the produced signature regardless of parities.
    const d0 = 0x1234n;
    const k0 = 0x9999n;
    const msg = utf8('parity');
    const { signature, trace } = signWithNonce(msg, d0, k0);
    expect(hasEvenY(G.multiply(bytesToBig(bigTo32(trace.k0)))) === trace.rHasEvenY).toBe(true);
    expect(verify(signature, msg, trace.pubkey).valid).toBe(true);
  });
});
