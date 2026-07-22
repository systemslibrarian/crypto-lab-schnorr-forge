/**
 * The nonce-reuse key-recovery attack — the whole point of the "break-it" panel.
 *
 * If a signer ever reuses one nonce k for two DIFFERENT messages under the same
 * key, both signatures share R (= k·G), so:
 *     s1 = k + e1·d        s2 = k + e2·d       (mod n)
 *     s1 − s2 = (e1 − e2)·d
 *     d = (s1 − s2) · (e1 − e2)⁻¹              (mod n)
 * The private key falls straight out by algebra — no brute force, two signatures
 * are enough. This is why real BIP-340 derives the nonce deterministically from
 * the message: two different messages force two different nonces. The attack can
 * only fire against a broken RNG that repeats k.
 *
 * `d` recovered here is the BIP-340 EFFECTIVE secret (the one paired with the
 * even-y public key). We undo the even-y negation to hand back the actual sk.
 */
import { N, G, mod, invN, bytesToBig, bigTo32, xOnly, hasEvenY, liftX, Point } from './field.js';
import { challenge, signWithNonce, type SignResult } from './bip340.js';

export interface ReusedSignature {
  msg: Uint8Array;
  result: SignResult;
}

/**
 * Sign two distinct messages with the SAME forced nonce k0 under key d0.
 * This simulates a catastrophically broken RNG. Real BIP-340 never does this;
 * the panel forces it so the recovery below has something to bite on.
 */
export function signReusedNonce(
  msg1: Uint8Array,
  msg2: Uint8Array,
  d0: bigint,
  k0: bigint,
): [ReusedSignature, ReusedSignature] {
  return [
    { msg: msg1, result: signWithNonce(msg1, d0, k0) },
    { msg: msg2, result: signWithNonce(msg2, d0, k0) },
  ];
}

export interface RecoveryTrace {
  sharedRx: string; // the tell-tale: both signatures share this R.x
  e1: bigint;
  e2: bigint;
  s1: bigint;
  s2: bigint;
  sDiff: bigint; // (s1 − s2) mod n
  eDiff: bigint; // (e1 − e2) mod n
  eDiffInv: bigint; // (e1 − e2)⁻¹ mod n
  dEffective: bigint; // (s1 − s2)/(e1 − e2)  = even-y-adjusted secret
  recovered: Uint8Array; // the actual 32-byte private key
}

export interface RecoveryResult {
  ok: boolean;
  reason: string;
  trace: RecoveryTrace | null;
}

/**
 * Recover the private key from two signatures that share a nonce (same R.x),
 * given the x-only public key. Fails closed if the nonces differ or the messages
 * (hence challenges) coincide.
 */
export function recoverPrivateKey(
  sig1: Uint8Array,
  msg1: Uint8Array,
  sig2: Uint8Array,
  msg2: Uint8Array,
  pubkey: Uint8Array,
): RecoveryResult {
  const rx1 = sig1.subarray(0, 32);
  const rx2 = sig2.subarray(0, 32);
  const rx1Hex = bigTo32(bytesToBig(rx1)).reduce((h, b) => h + b.toString(16).padStart(2, '0'), '');

  if (bytesToBig(rx1) !== bytesToBig(rx2)) {
    return { ok: false, reason: 'nonces differ (R.x mismatch) — nothing to exploit', trace: null };
  }

  const e1 = challenge(rx1, pubkey, msg1);
  const e2 = challenge(rx2, pubkey, msg2);
  const eDiff = mod(e1 - e2, N);
  if (eDiff === 0n) {
    return { ok: false, reason: 'challenges are equal (same message) — cannot divide', trace: null };
  }

  const s1 = bytesToBig(sig1.subarray(32, 64));
  const s2 = bytesToBig(sig2.subarray(32, 64));
  const sDiff = mod(s1 - s2, N);
  const eDiffInv = invN(eDiff);
  const dEffective = mod(sDiff * eDiffInv, N);

  // Undo BIP-340's even-y negation: the public key we can see is even-y, so the
  // actual sk is dEffective if x(d0·G) already had even y, else n − dEffective.
  const Ppt = liftX(bytesToBig(pubkey));
  if (!Ppt) return { ok: false, reason: 'public key is not a valid curve point', trace: null };
  const cand = G.multiply(dEffective);
  const actual = hasEvenY(cand) ? dEffective : N - dEffective;
  const recovered = bigTo32(actual);

  // Prove it: does the recovered key regenerate the public key?
  const check = G.multiply(actual);
  const matches =
    bytesToBig(xOnly(check)) === bytesToBig(pubkey) && !check.is0() && Point.ZERO !== check;
  if (!matches) {
    return { ok: false, reason: 'recovered key does not reproduce the public key', trace: null };
  }

  return {
    ok: true,
    reason: 'private key recovered from two signatures — the secret is out',
    trace: {
      sharedRx: rx1Hex,
      e1,
      e2,
      s1,
      s2,
      sDiff,
      eDiff,
      eDiffInv,
      dEffective,
      recovered,
    },
  };
}
