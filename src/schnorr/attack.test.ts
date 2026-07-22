import { describe, it, expect } from 'vitest';
import { signReusedNonce, recoverPrivateKey } from './attack.js';
import { sign } from './bip340.js';
import { bigTo32, bytesToBig, utf8, bytesToHex, normalizeSecretKey } from './field.js';

describe('Nonce-reuse key recovery (the break-it attack)', () => {
  it('recovers the exact private key from two signatures sharing a nonce', () => {
    const d0 = 0xa11ce5ec17n; // the victim's secret
    const k0 = 0xbadbadbadbeefn; // a nonce a broken RNG repeats
    const msg1 = utf8('Pay Alice 10 coins');
    const msg2 = utf8('Pay Mallory 10 coins');
    const [a, b] = signReusedNonce(msg1, msg2, d0, k0);

    // Both signatures share R.x — the observable tell.
    expect(bytesToHex(a.result.trace.Rx)).toBe(bytesToHex(b.result.trace.Rx));

    const pubkey = a.result.trace.pubkey;
    const rec = recoverPrivateKey(a.result.signature, msg1, b.result.signature, msg2, pubkey);
    expect(rec.ok).toBe(true);
    // Recovery returns the even-y canonical secret for the x-only public key.
    expect(bytesToHex(rec.trace!.recovered)).toBe(bytesToHex(bigTo32(normalizeSecretKey(d0))));
  });

  it('works across many keys/nonces (algebra, not luck)', () => {
    for (let i = 1; i <= 25; i++) {
      const d0 = BigInt(1000003 * i + 7);
      const k0 = BigInt(7654321 * i + 11);
      const [a, b] = signReusedNonce(utf8(`m1-${i}`), utf8(`m2-${i}`), d0, k0);
      const rec = recoverPrivateKey(
        a.result.signature,
        utf8(`m1-${i}`),
        b.result.signature,
        utf8(`m2-${i}`),
        a.result.trace.pubkey,
      );
      expect(rec.ok).toBe(true);
      expect(bytesToBig(rec.trace!.recovered)).toBe(normalizeSecretKey(d0));
    }
  });

  it('fails closed when the two nonces differ (real BIP-340 signatures)', () => {
    const sk = bigTo32(555n);
    const s1 = sign(utf8('m1'), sk, 'deterministic');
    const s2 = sign(utf8('m2'), sk, 'deterministic');
    // Different messages ⇒ different deterministic nonces ⇒ different R.x.
    expect(bytesToHex(s1.trace.Rx)).not.toBe(bytesToHex(s2.trace.Rx));
    const rec = recoverPrivateKey(s1.signature, utf8('m1'), s2.signature, utf8('m2'), s1.trace.pubkey);
    expect(rec.ok).toBe(false);
  });

  it('fails closed when the messages (hence challenges) are identical', () => {
    const d0 = 12321n;
    const k0 = 45654n;
    const [a, b] = signReusedNonce(utf8('same'), utf8('same'), d0, k0);
    const rec = recoverPrivateKey(a.result.signature, utf8('same'), b.result.signature, utf8('same'), a.result.trace.pubkey);
    expect(rec.ok).toBe(false);
  });
});
