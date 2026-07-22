import { describe, it, expect } from 'vitest';
import { BIP340_VECTORS } from './vectors.js';
import { verify, signWithNonce, deriveNonce } from './bip340.js';
import { bytesToBig, xOnly, hasEvenY, hexToBytes, bytesToHex, G, N } from './field.js';

describe('Official BIP-340 test vectors (KATs)', () => {
  it('covers all 19 official rows', () => {
    expect(BIP340_VECTORS.length).toBe(19);
  });

  for (const v of BIP340_VECTORS) {
    it(`vector ${v.index}: verify ⇒ ${v.expected}${v.comment ? ` (${v.comment})` : ''}`, () => {
      const result = verify(hexToBytes(v.signature), hexToBytes(v.message), hexToBytes(v.publicKey));
      expect(result.valid).toBe(v.expected);
    });
  }

  const signable = BIP340_VECTORS.filter((v) => v.secretKey && v.auxRand !== null);
  for (const v of signable) {
    it(`vector ${v.index}: signing reproduces the exact expected signature`, () => {
      const d0 = bytesToBig(hexToBytes(v.secretKey!));
      const Ppt = G.multiply(d0);
      const d = hasEvenY(Ppt) ? d0 : N - d0;
      const k0 = deriveNonce(d, xOnly(Ppt), hexToBytes(v.message), hexToBytes(v.auxRand!));
      const { signature } = signWithNonce(hexToBytes(v.message), d0, k0, hexToBytes(v.auxRand!));
      expect(bytesToHex(signature).toUpperCase()).toBe(v.signature.toUpperCase());
      // And the derived public key matches the vector.
      expect(bytesToHex(xOnly(Ppt)).toUpperCase()).toBe(v.publicKey.toUpperCase());
    });
  }
});
