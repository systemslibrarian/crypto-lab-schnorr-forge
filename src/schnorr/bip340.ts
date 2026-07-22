/**
 * BIP-340 Schnorr over secp256k1 — hand-rolled so every intermediate value is
 * inspectable. This is the teaching subject; we build it on @noble/curves group
 * arithmetic (field.ts) and cross-check byte-for-byte against @noble's own
 * schnorr and against the official BIP-340 test vectors.
 *
 * The one clean equation:   s = k + e·x        (mod n)
 *   k  nonce   (secret, per-signature)   R = k·G     the commitment
 *   x  private key                        P = x·G     the public key
 *   e  challenge = tagged-hash(R, P, m)   s           the response
 * Verification recomputes both sides of  s·G = R + e·P  and compares.
 *
 * NOT production crypto — a teaching demo. Real signers must use the constant-
 * time, self-verifying @noble/curves `schnorr.sign`.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import {
  N,
  G,
  P as FIELD_P,
  Point,
  type Pt,
  mod,
  bytesToBig,
  bigTo32,
  concatBytes,
  hasEvenY,
  xOnly,
  liftX,
  randomBytes,
} from './field.js';

/** Multiply that tolerates the scalar 0 (noble's multiply rejects it). */
function mul(pt: Pt, k: bigint): Pt {
  const s = mod(k, N);
  return s === 0n ? Point.ZERO : pt.multiply(s);
}

/**
 * BIP-340 tagged hash:  SHA256( SHA256(tag) ‖ SHA256(tag) ‖ data ).
 * The doubled tag-hash prefix domain-separates every use of SHA-256 in the
 * scheme (aux, nonce, challenge) so a digest from one context can never be
 * replayed in another.
 */
export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, ...data));
}

/** The Fiat–Shamir challenge e = int(tagged-hash("BIP0340/challenge", R.x ‖ P.x ‖ m)) mod n. */
export function challenge(rx: Uint8Array, px: Uint8Array, msg: Uint8Array): bigint {
  return mod(bytesToBig(taggedHash('BIP0340/challenge', rx, px, msg)), N);
}

export type NonceMode = 'deterministic' | 'random';

/** Every intermediate a learner (or an auditor) might want to see. */
export interface SignTrace {
  d0: bigint; // raw private scalar int(sk)
  pubkey: Uint8Array; // x-only public key P.x
  pubHasEvenY: boolean;
  d: bigint; // effective secret: d0 or n-d0 so that P has even y
  auxRand: Uint8Array | null; // 32 aux bytes (null when the nonce was forced)
  k0: bigint; // raw nonce scalar
  Rx: Uint8Array; // commitment R.x
  rHasEvenY: boolean;
  k: bigint; // effective nonce: k0 or n-k0 so that R has even y
  e: bigint; // challenge
  s: bigint; // response = (k + e·d) mod n
}

export interface SignResult {
  signature: Uint8Array; // 64 bytes: R.x ‖ s
  trace: SignTrace;
}

/** Reject scalars outside [1, n-1] — the fail-closed domain for keys and nonces. */
function assertScalar(x: bigint, what: string): void {
  if (x <= 0n || x >= N) throw new Error(`${what} out of range [1, n-1]`);
}

/**
 * Core signer: given the raw private scalar and the raw nonce scalar, produce a
 * BIP-340 signature and the full trace. `auxRand` is carried only for display.
 * The deliberately-vulnerable "reuse a nonce" mode drives THIS directly with a
 * fixed k0 — see attack.ts. Normal signing derives k0 first (see `sign`).
 */
export function signWithNonce(
  msg: Uint8Array,
  d0: bigint,
  k0: bigint,
  auxRand: Uint8Array | null = null,
): SignResult {
  assertScalar(d0, 'private key');
  assertScalar(k0, 'nonce');

  const Ppt = mul(G, d0);
  const pubkey = xOnly(Ppt);
  const pubHasEvenY = hasEvenY(Ppt);
  const d = pubHasEvenY ? d0 : N - d0;

  const Rpt = mul(G, k0);
  const Rx = xOnly(Rpt);
  const rHasEvenY = hasEvenY(Rpt);
  const k = rHasEvenY ? k0 : N - k0;

  const e = challenge(Rx, pubkey, msg);
  const s = mod(k + e * d, N);

  const signature = concatBytes(Rx, bigTo32(s));
  return {
    signature,
    trace: { d0, pubkey, pubHasEvenY, d, auxRand, k0, Rx, rHasEvenY, k, e, s },
  };
}

/**
 * BIP-340 deterministic nonce derivation.
 *   t    = bytes(d) XOR tagged-hash("BIP0340/aux", auxRand)
 *   rand = tagged-hash("BIP0340/nonce", t ‖ P.x ‖ m)
 *   k0   = int(rand) mod n
 * `auxRand` = 32 zero bytes is the fully deterministic variant; fresh random aux
 * is the hedged variant. BOTH are safe — the nonce still binds the message, so
 * two different messages never collide. (Reuse only happens with a broken RNG,
 * which is what the attack panel forces.)
 */
export function deriveNonce(
  d: bigint,
  px: Uint8Array,
  msg: Uint8Array,
  auxRand: Uint8Array,
): bigint {
  const auxHash = taggedHash('BIP0340/aux', auxRand);
  const dBytes = bigTo32(d);
  const t = new Uint8Array(32);
  for (let i = 0; i < 32; i++) t[i] = dBytes[i] ^ auxHash[i];
  const rand = taggedHash('BIP0340/nonce', t, px, msg);
  const k0 = mod(bytesToBig(rand), N);
  if (k0 === 0n) throw new Error('derived nonce is zero (astronomically unlikely)');
  return k0;
}

/**
 * Full BIP-340 sign. `mode = 'deterministic'` uses all-zero aux (reproducible
 * R for a given key+message); `mode = 'random'` hedges with fresh aux (fresh R
 * each call, still safe). Returns the signature and the complete trace.
 */
export function sign(msg: Uint8Array, sk: Uint8Array, mode: NonceMode): SignResult {
  const d0 = bytesToBig(sk);
  assertScalar(d0, 'private key');
  const Ppt = mul(G, d0);
  const pubHasEvenY = hasEvenY(Ppt);
  const d = pubHasEvenY ? d0 : N - d0;
  const auxRand = mode === 'deterministic' ? new Uint8Array(32) : randomBytes(32);
  const k0 = deriveNonce(d, xOnly(Ppt), msg, auxRand);
  return signWithNonce(msg, d0, k0, auxRand);
}

export interface VerifyResult {
  valid: boolean;
  reason: string; // human-readable outcome (pass or the exact fail-closed cause)
  e: bigint | null;
  // "Compute both sides and compare" — the two points of  s·G  vs  R + e·P.
  lhs: string | null; // s·G, x-only hex (or "∞")
  rhs: string | null; // R + e·P, x-only hex (or "∞")
}

function pointX(pt: Pt): string {
  return pt.is0() ? '∞' : bigTo32(pt.x).reduce((h, b) => h + b.toString(16).padStart(2, '0'), '');
}

/**
 * Hand-rolled BIP-340 verification, structured as compute-both-sides:
 * lift R from its x, recompute e, and check  s·G  ==  R + e·P.
 * Every rejection returns the exact fail-closed reason (used by the KAT panel).
 */
export function verify(sig: Uint8Array, msg: Uint8Array, pubkey: Uint8Array): VerifyResult {
  const fail = (reason: string, e: bigint | null = null): VerifyResult => ({
    valid: false,
    reason,
    e,
    lhs: null,
    rhs: null,
  });

  if (sig.length !== 64) return fail(`signature must be 64 bytes (got ${sig.length})`);
  if (pubkey.length !== 32) return fail(`public key must be 32 bytes (got ${pubkey.length})`);

  const px = bytesToBig(pubkey);
  if (px >= FIELD_P) return fail('public key x ≥ field size p — not a coordinate');
  const Ppt = liftX(px);
  if (!Ppt) return fail('public key is not a valid x-coordinate on the curve');

  const r = bytesToBig(sig.subarray(0, 32));
  const s = bytesToBig(sig.subarray(32, 64));
  if (r >= FIELD_P) return fail('signature R.x ≥ field size p');
  if (s >= N) return fail('signature s ≥ group order n');

  const Rpt = liftX(r);
  if (!Rpt) return fail('signature R.x is not a point on the curve');

  const e = challenge(sig.subarray(0, 32), pubkey, msg);
  const lhs = mul(G, s); // s·G
  const rhs = Rpt.add(mul(Ppt, e)); // R + e·P

  const result: VerifyResult = {
    valid: lhs.equals(rhs),
    reason: '',
    e,
    lhs: pointX(lhs),
    rhs: pointX(rhs),
  };
  result.reason = result.valid
    ? 's·G equals R + e·P — signature valid'
    : 's·G ≠ R + e·P — signature rejected';
  return result;
}
