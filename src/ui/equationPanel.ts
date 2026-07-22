import { h, clear, field, verdict, panelIntro } from './dom.js';
import { sign, verify } from '../schnorr/bip340.js';
import { bigTo32, bytesToBig, bytesToHex, randomBytes, normalizeSecretKey, utf8 } from '../schnorr/field.js';

/**
 * A user-driven step-through of  s = k + e·x  and why  s·G = R + e·P.
 * Reveals one move at a time on Next — motion is tied to the action, never idle.
 */
export function renderEquationPanel(root: HTMLElement): void {
  clear(root);

  const message = 'I authorize this transaction.';
  let secret = normalizeSecretKey(bytesToBig(randomBytes(32)));
  let step = 0;
  const LAST = 4;

  const stage = h('div', { class: 'equation-stage', role: 'status', 'aria-live': 'polite' });
  const prevBtn = h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => go(step - 1) }, '‹ Back') as HTMLButtonElement;
  const nextBtn = h('button', { type: 'button', class: 'btn btn-primary', onclick: () => go(step + 1) }, 'Next ›') as HTMLButtonElement;
  const resetBtn = h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => {
    secret = normalizeSecretKey(bytesToBig(randomBytes(32)));
    go(0);
  } }, 'New example');
  const progress = h('span', { class: 'step-progress' }, '');

  function go(next: number): void {
    step = Math.max(0, Math.min(LAST, next));
    render();
  }

  function render(): void {
    const res = sign(utf8(message), bigTo32(secret), 'deterministic');
    const t = res.trace;
    const v = verify(res.signature, utf8(message), t.pubkey);

    clear(stage);
    progress.textContent = `Step ${step} / ${LAST}`;
    prevBtn.disabled = step === 0;
    nextBtn.disabled = step === LAST;

    const rows: HTMLElement[] = [];
    rows.push(h('div', { class: 'eq-line reveal' },
      h('span', { class: 'trace-tag' }, 'KEYS'),
      field('private key  x', `0x${secret.toString(16)}`),
      field('public key   P = x·G  → P.x', bytesToHex(t.pubkey)),
      field('message', message, { mono: false }),
    ));

    if (step >= 1) rows.push(h('div', { class: 'eq-line reveal' },
      h('span', { class: 'trace-tag' }, '① COMMIT'),
      h('p', {}, 'Draw a fresh secret nonce k and publish only its point R = k·G. R commits to k without revealing it.'),
      field('nonce  k', `0x${t.k.toString(16)}`),
      field('R = k·G  → R.x', bytesToHex(t.Rx)),
    ));

    if (step >= 2) rows.push(h('div', { class: 'eq-line reveal' },
      h('span', { class: 'trace-tag' }, '② CHALLENGE'),
      h('p', {}, 'Hash the commitment, the key, and the message into a challenge e. Because e depends on R, the signer cannot choose R after seeing e — that is what makes the proof binding.'),
      field('e = tagged-hash(R.x ‖ P.x ‖ m) mod n', `0x${t.e.toString(16)}`),
    ));

    if (step >= 3) rows.push(h('div', { class: 'eq-line reveal' },
      h('span', { class: 'trace-tag' }, '③ RESPOND'),
      h('p', {}, 'Answer with s = k + e·x. The fresh nonce k masks the private key x, so s reveals nothing about x — unless k is ever reused.'),
      field('s = (k + e·x) mod n', `0x${t.s.toString(16)}`),
    ));

    if (step >= 4) rows.push(h('div', { class: 'eq-line reveal' },
      h('span', { class: 'trace-tag' }, '④ VERIFY'),
      h('p', { class: 'eq-derivation' }, 's·G = (k + e·x)·G = k·G + e·(x·G) = R + e·P'),
      h('p', {}, 'The verifier never learns k or x — it only checks the two points match:'),
      field('left  = s·G', v.lhs ?? '—', { sub: '(x)' }),
      field('right = R + e·P', v.rhs ?? '—', { sub: '(x)' }),
      v.valid ? verdict('pass', 'Both sides equal — the identity holds') : verdict('fail', 'mismatch'),
    ));

    stage.append(...rows);
  }

  root.append(
    panelIntro(
      'The Equation',
      'Every Schnorr signature is three moves: commit, challenge, respond. Walk them one at a time and watch the single equation s = k + e·x fall out — then see why the verifier’s check s·G = R + e·P is just that equation multiplied through by the generator G.',
    ),
    h('div', { class: 'stepper-controls' }, prevBtn, nextBtn, resetBtn, progress),
    stage,
  );

  render();
}
