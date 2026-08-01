import { h, clear, field, verdict, panelIntro, note, learnerCheck } from './dom.js';
import { signReusedNonce, recoverPrivateKey } from '../schnorr/attack.js';
import { verify } from '../schnorr/bip340.js';
import {
  bigTo32,
  bytesToBig,
  bytesToHex,
  randomBytes,
  normalizeSecretKey,
  N,
  utf8,
} from '../schnorr/field.js';

/**
 * The break-it panel: force a signer to reuse one nonce across two messages and
 * recover the private key by the actual algebra x = (s1 − s2)/(e1 − e2).
 */
export function renderAttackPanel(root: HTMLElement): void {
  clear(root);

  let secret = normalizeSecretKey(bytesToBig(randomBytes(32)));
  let nonce = (bytesToBig(randomBytes(32)) % (N - 1n)) + 1n;

  const msg1 = h('textarea', { id: 'atk-msg1', class: 'msg-input', rows: 1, spellcheck: false }, 'Pay Alice 10 coins') as HTMLTextAreaElement;
  const msg2 = h('textarea', { id: 'atk-msg2', class: 'msg-input', rows: 1, spellcheck: false }, 'Pay Mallory 10000 coins') as HTMLTextAreaElement;
  const output = h('div', { class: 'output', id: 'attack-output' });

  function run(): void {
    clear(output);
    const m1 = utf8(msg1.value);
    const m2 = utf8(msg2.value);

    const [a, b] = signReusedNonce(m1, m2, secret, nonce);
    const pubkey = a.result.trace.pubkey;

    // Both signatures are genuinely valid under the real verifier...
    const ok1 = verify(a.result.signature, m1, pubkey).valid;
    const ok2 = verify(b.result.signature, m2, pubkey).valid;

    const sigsBlock = h('div', { class: 'attack-sigs' },
      h('h3', {}, '1 · Two valid signatures — but the nonce was reused'),
      h('div', { class: 'sig-pair' },
        h('div', { class: 'sig-card' },
          field('message 1', msg1.value, { mono: false }),
          field('R.x (commitment)', bytesToHex(a.result.trace.Rx)),
          field('s₁', `0x${a.result.trace.s.toString(16)}`),
          ok1 ? verdict('pass', 'valid signature') : verdict('fail', 'invalid'),
        ),
        h('div', { class: 'sig-card' },
          field('message 2', msg2.value, { mono: false }),
          field('R.x (commitment)', bytesToHex(b.result.trace.Rx)),
          field('s₂', `0x${b.result.trace.s.toString(16)}`),
          ok2 ? verdict('pass', 'valid signature') : verdict('fail', 'invalid'),
        ),
      ),
      bytesToHex(a.result.trace.Rx) === bytesToHex(b.result.trace.Rx)
        ? note('danger', h('strong', {}, 'The tell: '), 'both commitments share the same R.x. Identical R means identical nonce k — the one thing that must never repeat.')
        : note('info', 'Distinct R.x — no reuse here.'),
    );

    // ...and that reuse is fatal. Recover the key by algebra.
    const rec = recoverPrivateKey(a.result.signature, m1, b.result.signature, m2, pubkey);
    const recBlock = h('div', { class: 'attack-recover' },
      h('h3', {}, '2 · The private key falls out by algebra'),
    );

    if (rec.ok && rec.trace) {
      const tr = rec.trace;
      recBlock.append(
        h('p', { class: 'eq-derivation' }, 's₁ − s₂ = (e₁ − e₂)·x   ⇒   x = (s₁ − s₂) · (e₁ − e₂)⁻¹  (mod n)'),
        field('e₁ = hash(R.x ‖ P.x ‖ m₁)', `0x${tr.e1.toString(16)}`),
        field('e₂ = hash(R.x ‖ P.x ‖ m₂)', `0x${tr.e2.toString(16)}`),
        field('s₁ − s₂ (mod n)', `0x${tr.sDiff.toString(16)}`),
        field('e₁ − e₂ (mod n)', `0x${tr.eDiff.toString(16)}`),
        field('(e₁ − e₂)⁻¹ (mod n)', `0x${tr.eDiffInv.toString(16)}`),
        field('recovered private key x', bytesToHex(tr.recovered)),
        bytesToHex(tr.recovered) === bytesToHex(bigTo32(secret))
          ? verdict('alarm', 'Recovered key EQUALS the real secret — the wallet is emptied')
          : verdict('fail', 'recovered value did not match (unexpected)'),
        note('caveat', 'This is the real derivation on real signatures — no shortcut, no stored key. Two signatures are all it takes.'),
      );
    } else {
      recBlock.append(verdict('fail', `No recovery — ${rec.reason}`));
    }

    output.append(sigsBlock, recBlock);
  }

  root.append(
    panelIntro(
      'Nonce Reuse → Key Recovery',
      'A Schnorr signature hides the private key x behind a one-time secret nonce k in the response s = k + e·x. That mask only works once. If a signer ever reuses the same k for two different messages, subtracting the two responses cancels k and leaves the key exposed to simple division.',
      'This is not a theoretical worry. The 2010 Sony PlayStation 3 breach and multiple Bitcoin wallet thefts were the same root cause — a repeated signing nonce. Both of those were ECDSA rather than Schnorr, so the recovery algebra differs in detail, but the fatal ingredient is identical: one k used twice.',
    ),
    note('danger',
      h('strong', {}, 'Deliberately broken signer. '),
      'Real BIP-340 derives the nonce deterministically from the message, so a collision between two different messages is cryptographically negligible. This tab overrides that and forces one fixed nonce across both messages to simulate a faulty RNG — the failure mode, isolated and clearly marked, never the default.',
    ),
    h('div', { class: 'controls' },
      h('div', { class: 'control' },
        h('label', { for: 'atk-msg1' }, 'Message 1'),
        msg1,
      ),
      h('div', { class: 'control' },
        h('label', { for: 'atk-msg2' }, 'Message 2 (must differ)'),
        msg2,
      ),
      h('div', { class: 'input-row' },
        h('button', { type: 'button', class: 'btn btn-primary', onclick: run }, 'Sign both with the same nonce, then attack'),
        h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => {
          secret = normalizeSecretKey(bytesToBig(randomBytes(32)));
          nonce = (bytesToBig(randomBytes(32)) % (N - 1n)) + 1n;
          run();
        } }, 'New victim key & nonce'),
      ),
    ),
    learnerCheck(
      'Two signatures reuse one nonce k, so s₁ = k + e₁·x and s₂ = k + e₂·x. When you subtract them, which term cancels?',
      [
        { label: 'The nonce k', correct: true },
        { label: 'The private key x', correct: false },
        { label: 'Nothing cancels', correct: false },
      ],
      's₁ − s₂ = (k + e₁·x) − (k + e₂·x) = (e₁ − e₂)·x. The shared k cancels, leaving one linear equation in x — divide by (e₁ − e₂) and the key is out.',
    ),
    output,
  );

  run();
}
