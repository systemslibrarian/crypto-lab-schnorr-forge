# Schnorr Forge

**Schnorr Signatures · BIP-340 · secp256k1**

An interactive, browser-only lab for BIP-340 Schnorr signatures. Generate a key, sign a message, and verify it with real elliptic-curve arithmetic — then step through the signing equation, reuse a nonce to watch the private key fall out by algebra, and see how two signatures add into one.

> **Not production cryptography — a teaching demo.** Keys are generated per-session in memory and never stored or transmitted. There is no backend. For real signing, use the audited [`@noble/curves`](https://github.com/paulmillr/noble-curves) `schnorr` implementation — which this demo cross-checks against byte-for-byte.

## What It Is

Schnorr is the signature ECDSA wishes it were: one clean, **linear** equation.

```
sign:    s = k + e·x            e = tagged-hash(R.x ‖ P.x ‖ m)
verify:  s·G = R + e·P          R = k·G,  P = x·G
```

- **x** private key · **P = x·G** public key (x-only, 32 bytes in BIP-340)
- **k** one-time secret nonce · **R = k·G** the public commitment
- **e** the Fiat–Shamir challenge · **s** the response

The primitives are **BIP-340 Schnorr over secp256k1** (x-only public keys, tagged hashes, 64-byte signatures) with BIP-340 deterministic nonce derivation. Group arithmetic comes from `@noble/curves`; **the BIP-340 layer itself — tagged hashes, the commit/challenge/respond equation, x-only/even-y encoding, and verification — is hand-rolled** in [`src/schnorr/bip340.ts`](src/schnorr/bip340.ts) so every intermediate value is inspectable. The **security model** is standard EUF-CMA signatures: unforgeable without the private key, provided the nonce is never reused.

That last clause is the whole drama of this lab. Schnorr's linearity is exactly what makes multisig and threshold signing possible — and exactly what turns one reused nonce into total key compromise.

## Exhibits

1. **Sign & Verify** — Pick or randomize a key, supply a message as **UTF-8 text or exact hex bytes**, choose deterministic or randomized (hedged) nonce derivation, and sign. See the three moves (commit `R`, challenge `e`, respond `s`), the 64-byte signature, and a **compute-both-sides** verification that shows `s·G` and `R + e·P` byte-for-byte. A "Break it" button flips one message byte and watches the real verifier reject it, an optional **BIP-340 details** disclosure exposes the even-y/parity normalization on real intermediates, and copy/export/shareable-verify-link actions handle only public artifacts (private key copy is separately marked).
2. **Verify Workbench** — Paste an x-only public key, signature, and message (UTF-8 or hex) from **any** BIP-340 implementation — no private key needed — and watch the explicit five-stage pipeline decide: parse & lengths → range checks → lift points → recompute challenge → compare `s·G` against `R + e·P`. Curated presets cover a valid signature and the malformed rejections (off-curve key, out-of-range scalar, changed message, wrong length).
3. **The Equation** — A user-driven, step-at-a-time walk through commit → challenge → respond → verify, ending in the algebra `s·G = (k + e·x)·G = R + e·P`. Motion is tied to your clicks; nothing loops on its own.
4. **Nonce Reuse → Key Recovery** — The break-it centerpiece. A deliberately faulty signer reuses one nonce across two messages; the panel then runs the actual recovery `x = (s₁ − s₂)·(e₁ − e₂)⁻¹ mod n` and shows the recovered key **equals** the real secret. Isolated and clearly marked broken — never the default path.
5. **BIP-340 Test Vectors** — All 19 official vectors run through the same hand-rolled `verify()`, including the malformed cases that must be **rejected** (point off the curve, out-of-range scalars, negated values). Each row expands to its full artifacts and the exact failing stage, and can be sent to the Verify Workbench. Green means our verdict matched the spec.
6. **Why Linearity Matters** — Two independent signers produce responses `s₁`, `s₂` that literally add into one combined signature the ordinary verifier accepts against the summed key — the seed of Schnorr multisig, pointing to MuSig2 and FROST.

Several exhibits end with an optional **quick check** — a one-question prediction with an immediate explanation — targeting a common misconception. The lab stays fully usable whether or not you answer them.

## When to Use It

- **Use** Schnorr/BIP-340 when you want short, linear, aggregatable signatures — Bitcoin Taproot, multisig, threshold signing.
- **Use** deterministic (or hedged) nonce derivation **always** — never a bare RNG for the nonce.
- **Do NOT** roll your own signer for production from this code. It is optimized for transparency, not constant-time safety. Use `@noble/curves`, `libsecp256k1`, or an equivalent audited library.
- **Do NOT** ever reuse a nonce, derive it from anything an attacker can force to repeat, or truncate its entropy. Exhibit 4 shows exactly why.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-schnorr-forge/**

Sign a message, flip a byte and watch verification fail, force a nonce reuse and recover a key, and combine two signers into one signature — all in the browser, no install.

## What Can Go Wrong

- **Nonce reuse** — two signatures under one key with the same `k` leak the private key by subtraction (Exhibit 4). This sank the Sony PlayStation 3 signing key (2010) and has drained Bitcoin wallets.
- **Predictable / low-entropy nonces** — a nonce an attacker can guess or bias is as fatal as reuse; BIP-340 derives it deterministically from the message and key for this reason.
- **Malleability / malformed inputs** — BIP-340 fixes strict encodings; the verifier rejects non-canonical `R`/`s`, off-curve points, and out-of-range scalars (Exhibit 5).
- **Naive key aggregation** — simply adding public keys and nonces (Exhibit 6's teaser) is insecure against rogue-key and Wagner attacks; MuSig2 and FROST exist to fix that.

## Real-World Usage

BIP-340 Schnorr is deployed in **Bitcoin Taproot** (activated 2021) for single-key and multisig spending, and underpins **MuSig2** key aggregation and **FROST** threshold signing. The same commit-challenge-respond structure is the Schnorr identification protocol behind much of the zero-knowledge and threshold-signature literature.

## Threat Model & Scope

What "not production crypto" concretely means here:

- **Secrets are deliberately on screen.** The lab renders private keys and nonces so you can watch the arithmetic. Browser extensions, injected scripts, and devtools can read anything the page holds.
- **No timing guarantees.** JavaScript cannot promise constant-time execution and cannot reliably zeroize secrets from memory. This code is optimized for transparency, not side-channel resistance.
- **Conformance ≠ audit.** The hand-rolled BIP-340 layer is **specification-conformant and differentially tested** against `@noble/curves` (which is independently audited) and the official vectors — but it has not itself received an independent security audit.
- **Provenance.** Test vectors are the 19 official rows from [`bitcoin/bips` `bip-0340/test-vectors.csv`](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv); the differential oracle is `@noble/curves` v2. Group arithmetic (point mul/add, field sqrt, scalar inverse) is Noble's; tagged hashes, the sign/verify equation, x-only/even-y encoding, nonce-reuse recovery, and the textbook aggregation teaser are hand-rolled. The aggregation panel is intentionally **textbook full-point Schnorr**, not BIP-340.

Bottom line: great for learning exactly what BIP-340 signs and why a signature passes or fails; never for protecting real funds.

## How to Run Locally

```bash
npm install
npm run dev          # http://localhost:5173/crypto-lab-schnorr-forge/
npm run build        # typecheck + production build to dist/
npm test             # unit tests incl. BIP-340 KATs
npm run size-budget  # compressed-bundle budget (build first)
npm run test:a11y    # WCAG 2.1 AA axe gate, both themes (build first)
npm run test:e2e     # functional flows on Chromium + a mobile viewport
npm run test:e2e:all # full matrix: Chromium, Firefox, WebKit, mobile
```

## Related Demos

- [crypto-lab-musig-gate](https://systemslibrarian.github.io/crypto-lab-musig-gate/) — the two-round MuSig2 nonce ceremony that makes key aggregation safe.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — threshold Schnorr (FROST): t-of-n signers, one signature.
- [crypto-lab-blind-sign](https://systemslibrarian.github.io/crypto-lab-blind-sign/) — blind Schnorr, where the signer never sees the message.
- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — ECDSA over the same curve, and why its non-linear response makes all of the above hard.
- [crypto-lab-bitcoin-script](https://systemslibrarian.github.io/crypto-lab-bitcoin-script/) — Taproot script paths and transaction construction on top of these signatures.

## Build & Verify

- **69 unit tests** (Vitest, colocated `src/**/*.test.ts`), run in CI on every push and before every merge.
- **28 BIP-340 spec KAT assertions** — [`src/schnorr/vectors.ts`](src/schnorr/vectors.ts) holds all 19 official test vectors; [`src/schnorr/vectors.test.ts`](src/schnorr/vectors.test.ts) checks verification against every row **and** reproduces the exact expected signature for the 8 signing vectors. Our signatures are additionally cross-checked byte-for-byte against `@noble/curves` schnorr in a **differential sweep across 40 keys/messages/aux/lengths** ([`src/schnorr/bip340.test.ts`](src/schnorr/bip340.test.ts)), and every verifier rejection branch and pipeline stage is named in a test.
- **Strict parsing & boundaries** — [`src/schnorr/field.test.ts`](src/schnorr/field.test.ts) proves malformed hex fails closed (no partial parse) and exercises scalar/coordinate boundaries (`0`, `1`, `n-1`, `p`).
- **Attack correctness** — [`src/schnorr/attack.test.ts`](src/schnorr/attack.test.ts) proves nonce-reuse recovery returns the exact private key across many keys, and fails closed when nonces differ or messages coincide.
- **Accessibility gate** — `@axe-core/playwright` scans the production build for **zero** WCAG 2.1 A/AA violations in **both** themes ([`e2e/a11y.spec.ts`](e2e/a11y.spec.ts)).
- **Functional flows** — role-based end-to-end scenarios ([`e2e/flows.spec.ts`](e2e/flows.spec.ts)) run on **Chromium, Firefox, WebKit, and a mobile viewport**: sign/verify, tamper-rejects, workbench presets, vector hand-off, aggregation, keyboard tab roving, skip navigation, no-overflow geometry, and 44px touch targets.
- **Gated CI** — a pull-request workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs typecheck, unit tests, build, the size budget, the a11y gate, and the cross-browser flows **before merge**, with no Pages write permissions; [`deploy.yml`](.github/workflows/deploy.yml) re-runs the gates and ships to Pages only from `main`.

## Performance

All arithmetic runs in the browser in a few milliseconds per operation. There is no backend and no network I/O after the initial static load. A CI **compressed-size budget** ([`scripts/size-budget.mjs`](scripts/size-budget.mjs)) holds the bundle to ≤ 35 kB gzip JS and ≤ 10 kB gzip CSS (currently ~27 kB / ~3 kB).

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
