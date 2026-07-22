/**
 * "Why linearity matters" — the payoff teaser.
 *
 * Schnorr's response is LINEAR in the secret and the nonce:  s = k + e·x.
 * That single fact is what lets many signers collapse into one signature. Two
 * signers on a shared message, using a shared challenge e over the summed
 * commitment R = R1+R2 and summed key P = P1+P2, each produce s_i = k_i + e·x_i.
 * Their responses simply ADD:
 *     s = s1 + s2 = (k1 + k2) + e·(x1 + x2)
 *     s·G = (k1+k2)·G + e·(x1+x2)·G = (R1+R2) + e·(P1+P2) = R + e·P
 * so the ordinary verifier accepts (R, s) against the combined key P — one
 * 64-byte signature for two signers. This is the seed of Schnorr multisig,
 * threshold signing, and aggregation.
 *
 * SIMPLIFICATION (labeled honestly): this teaser uses textbook Schnorr over
 * FULL points — it drops BIP-340's x-only/even-y parity bookkeeping, and it does
 * naive nonce addition, which is INSECURE against rogue-key and Wagner-style
 * attacks. Making key aggregation safe is exactly the job of MuSig2 (two-round
 * nonces, key-aggregation coefficients) and FROST. See the linked demos. The
 * linearity shown here is real; the security work is what those protocols add.
 */
import { N, G, Point, type Pt, mod, bytesToBig, bigTo32 } from './field.js';
import { taggedHash } from './bip340.js';

function mul(pt: Pt, k: bigint): Pt {
  const s = mod(k, N);
  return s === 0n ? Point.ZERO : pt.multiply(s);
}

/** Challenge for the illustrative variant. Distinct tag so it can never be
 *  confused with a real BIP-340 challenge. Hashes full compressed points. */
function aggChallenge(R: Pt, Pk: Pt, msg: Uint8Array): bigint {
  return mod(
    bytesToBig(taggedHash('SchnorrForge/textbook', R.toBytes(true), Pk.toBytes(true), msg)),
    N,
  );
}

/** Textbook Schnorr verify over full points: s·G == R + e·P. */
export function verifyTextbook(msg: Uint8Array, Pk: Pt, R: Pt, s: bigint): boolean {
  const e = aggChallenge(R, Pk, msg);
  return mul(G, s).equals(R.add(mul(Pk, e)));
}

export interface SignerView {
  x: bigint; // private key
  Px: string; // public key x-only hex
  k: bigint; // nonce
  Rx: string; // commitment x-only hex
  s: bigint; // response s_i = k_i + e·x_i
}

export interface AggregateResult {
  signers: [SignerView, SignerView];
  e: bigint; // shared challenge
  aggPubX: string; // (P1+P2).x
  aggRx: string; // (R1+R2).x
  s: bigint; // s1 + s2 (mod n) — the single combined response
  sIndividualSum: string; // "s1 + s2" arithmetic, for display
  verifies: boolean; // the ordinary verifier accepts (R, s) for P1+P2
}

const xHex = (pt: Pt): string => bigTo32(pt.x).reduce((h, b) => h + b.toString(16).padStart(2, '0'), '');

/**
 * Combine two signers into one signature and check the plain verifier accepts it.
 * Returns every value needed to SHOW the s-values adding.
 */
export function aggregateTwo(
  msg: Uint8Array,
  x1: bigint,
  x2: bigint,
  k1: bigint,
  k2: bigint,
): AggregateResult {
  const P1 = mul(G, x1);
  const P2 = mul(G, x2);
  const R1 = mul(G, k1);
  const R2 = mul(G, k2);
  const Pagg = P1.add(P2);
  const Ragg = R1.add(R2);

  const e = aggChallenge(Ragg, Pagg, msg); // shared challenge over the aggregates
  const s1 = mod(k1 + e * x1, N);
  const s2 = mod(k2 + e * x2, N);
  const s = mod(s1 + s2, N);

  const verifies = verifyTextbook(msg, Pagg, Ragg, s);

  return {
    signers: [
      { x: x1, Px: xHex(P1), k: k1, Rx: xHex(R1), s: s1 },
      { x: x2, Px: xHex(P2), k: k2, Rx: xHex(R2), s: s2 },
    ],
    e,
    aggPubX: xHex(Pagg),
    aggRx: xHex(Ragg),
    s,
    sIndividualSum: `(${s1} + ${s2}) mod n`,
    verifies,
  };
}
