/**
 * secp256k1 group parameters and the small byte/scalar helpers BIP-340 needs.
 *
 * Group arithmetic (point multiply/add, field sqrt, scalar inverse) comes from
 * @noble/curves — audited, constant-time-ish, and NOT the teaching subject. The
 * teaching subject is BIP-340 itself (tagged hashes, the commit/challenge/respond
 * equation, x-only encoding), which we hand-roll in bip340.ts on top of these
 * primitives so every intermediate value is inspectable.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';

/** Projective point constructor for secp256k1 (G, multiply, add, fromAffine, Fp, Fn). */
export const Point = secp256k1.Point;
export type Pt = InstanceType<typeof Point>;

const C = Point.CURVE();

/** Field prime p — coordinates live in F_p.  (2^256 − 2^32 − 977) */
export const P: bigint = C.p;
/** Group order n — scalars (private keys, nonces) live in Z_n. */
export const N: bigint = C.n;
/** Generator / base point G. */
export const G: Pt = Point.BASE;

/** Least non-negative residue of a mod m (JS % keeps the sign of the dividend). */
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/** Modular inverse in Z_n, via the scalar field (throws on 0). */
export function invN(a: bigint): bigint {
  return Point.Fn.inv(mod(a, N));
}

/** `len` cryptographically-random bytes (browser or Node WebCrypto). */
export function randomBytes(len = 32): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

// ---- byte <-> bigint (big-endian, the encoding BIP-340 fixes) ----

export function bytesToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
}

/** Fixed 32-byte big-endian encoding (throws if the value doesn't fit). */
export function bigTo32(x: bigint): Uint8Array {
  if (x < 0n || x >= 1n << 256n) throw new Error('value out of 32-byte range');
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/\s+/g, '');
  // Validate the ENTIRE string up front. parseInt() stops at the first invalid
  // character and silently accepts a valid prefix ("0g" → 0), so a per-pair
  // parse would let malformed input through. Fail closed instead.
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex character');
  if (h.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (const byte of b) s += byte.toString(16).padStart(2, '0');
  return s;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** UTF-8 encode a string to bytes (for human-typed messages). */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ---- BIP-340 point helpers ----

/** BIP-340 has_even_y: a point's affine y is even. */
export function hasEvenY(pt: Pt): boolean {
  return mod(pt.y, 2n) === 0n;
}

/**
 * BIP-340 even-y canonical form of a secret scalar: d0 if d0·G already has an
 * even-y public key, else n − d0. Both scalars yield the SAME x-only public key
 * (they are negatives, x(P) = x(−P)), so this is the unique secret an x-only
 * key can pin down — and the form nonce-reuse recovery returns. Keygen
 * normalizes to it so the key you see is the key that comes back out.
 */
export function normalizeSecretKey(d0: bigint): bigint {
  const d = mod(d0, N);
  if (d === 0n) throw new Error('secret key is zero');
  return hasEvenY(G.multiply(d)) ? d : N - d;
}

/** 32-byte x-only serialization of a point (BIP-340 public keys and R). */
export function xOnly(pt: Pt): Uint8Array {
  return bigTo32(pt.x);
}

/**
 * BIP-340 lift_x: the unique curve point with the given x and EVEN y.
 * Returns null if x ≥ p or x is not an x-coordinate on the curve — exactly the
 * fail-closed cases the spec's malformed-key vectors exercise.
 */
export function liftX(x: bigint): Pt | null {
  if (x <= 0n || x >= P) return null;
  const Fp = Point.Fp;
  // c = x³ + 7  (secp256k1: a = 0, b = 7)
  const c = mod(x * x * x + 7n, P);
  let y: bigint;
  try {
    y = Fp.sqrt(c); // p ≡ 3 (mod 4) ⇒ sqrt is c^((p+1)/4); throws if non-residue
  } catch {
    return null;
  }
  if (mod(y * y, P) !== c) return null; // x is not on the curve
  const evenY = mod(y, 2n) === 0n ? y : P - y;
  try {
    const pt = Point.fromAffine({ x, y: evenY });
    pt.assertValidity();
    return pt;
  } catch {
    return null;
  }
}
