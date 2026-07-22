import { h, clear, field, verdict, panelIntro, note } from './dom.js';
import { sign, verify, type NonceMode, type SignResult } from '../schnorr/bip340.js';
import {
  G,
  N,
  bytesToBig,
  bigTo32,
  bytesToHex,
  hexToBytes,
  xOnly,
  utf8,
  randomBytes,
  normalizeSecretKey,
} from '../schnorr/field.js';

export function renderSignPanel(root: HTMLElement): void {
  clear(root);

  let mode: NonceMode = 'deterministic';
  let secret: bigint = normalizeSecretKey(bytesToBig(randomBytes(32)));

  const skInput = h('input', {
    type: 'text',
    id: 'sk-input',
    class: 'mono-input',
    spellcheck: false,
    autocomplete: 'off',
    value: bytesToHex(bigTo32(secret)),
    'aria-describedby': 'sk-help',
  }) as HTMLInputElement;

  const pkOut = h('code', { class: 'field-value' }, '');
  const msgInput = h('textarea', {
    id: 'msg-input',
    class: 'msg-input',
    rows: 2,
    spellcheck: false,
  }, 'Schnorr is the signature ECDSA wishes it were.') as HTMLTextAreaElement;

  const output = h('div', { class: 'output', id: 'sign-output' });

  function refreshPubkey(): boolean {
    try {
      const raw = hexToBytes(skInput.value.trim());
      if (raw.length !== 32) throw new Error('need 32 bytes (64 hex chars)');
      const d0 = bytesToBig(raw);
      if (d0 <= 0n || d0 >= N) throw new Error('out of range [1, n-1]');
      secret = normalizeSecretKey(d0);
      pkOut.textContent = bytesToHex(xOnly(G.multiply(secret)));
      skInput.setAttribute('aria-invalid', 'false');
      return true;
    } catch (e) {
      pkOut.textContent = `invalid key — ${(e as Error).message}`;
      skInput.setAttribute('aria-invalid', 'true');
      return false;
    }
  }

  function renderResult(res: SignResult, msg: Uint8Array): void {
    clear(output);
    const t = res.trace;
    const sigHex = bytesToHex(res.signature);

    // The three moves of Schnorr, shown as the values they produced.
    const steps = h(
      'div',
      { class: 'trace' },
      h('div', { class: 'trace-step' },
        h('span', { class: 'trace-tag' }, '① COMMIT'),
        field('nonce k (secret, per-signature)', `0x${t.k.toString(16)}`),
        field('R = k·G  → R.x (32-byte commitment)', bytesToHex(t.Rx)),
      ),
      h('div', { class: 'trace-step' },
        h('span', { class: 'trace-tag' }, '② CHALLENGE'),
        field('e = tagged-hash(R.x ‖ P.x ‖ message) mod n', `0x${t.e.toString(16)}`),
      ),
      h('div', { class: 'trace-step' },
        h('span', { class: 'trace-tag' }, '③ RESPOND'),
        field('s = (k + e·x) mod n', `0x${t.s.toString(16)}`),
      ),
    );

    const sigField = field('signature = R.x ‖ s  (64 bytes)', sigHex);
    sigField.classList.add('signature-out');

    // Compute-both-sides verification (never a mere "valid" assertion).
    const v = verify(res.signature, msg, t.pubkey);
    const both = h(
      'div',
      { class: 'both-sides' },
      h('p', { class: 'both-sides-eq' }, 'Verification recomputes both sides of  s·G = R + e·P  and compares:'),
      field('left  = s·G', v.lhs ?? '—', { sub: '(x)' }),
      field('right = R + e·P', v.rhs ?? '—', { sub: '(x)' }),
      v.valid
        ? verdict('pass', 'Bytes match on both sides — signature VALID')
        : verdict('fail', `Rejected — ${v.reason}`),
    );

    const tamper = h('button', {
      type: 'button',
      class: 'btn btn-ghost',
      onclick: () => {
        const forged = utf8(msgTextForVerify + ' (edited)');
        const fv = verify(res.signature, forged, t.pubkey);
        clear(tamperOut);
        tamperOut.append(
          field('verify same signature against an edited message', new TextDecoder().decode(forged), { mono: false }),
          fv.valid
            ? verdict('alarm', 'Unexpectedly accepted — this should never happen')
            : verdict('fail', `Correctly rejected — ${fv.reason}`),
        );
      },
    }, 'Break it: edit the message, re-verify the same signature');
    const tamperOut = h('div', { class: 'tamper-out', role: 'status', 'aria-live': 'polite' });
    const msgTextForVerify = new TextDecoder().decode(msg);

    output.append(
      field('public key P.x (x-only, 32 bytes)', bytesToHex(t.pubkey)),
      steps,
      sigField,
      both,
      h('div', { class: 'tamper' }, tamper, tamperOut),
    );
  }

  function doSign(): void {
    if (!refreshPubkey()) {
      clear(output);
      output.append(verdict('fail', 'Fix the private key before signing.'));
      return;
    }
    const msg = utf8(msgInput.value);
    const res = sign(msg, bigTo32(secret), mode);
    renderResult(res, msg);
  }

  const modeRadios = (['deterministic', 'random'] as const).map((m) =>
    h('label', { class: 'radio' },
      h('input', {
        type: 'radio', name: 'nonce-mode', value: m, checked: m === mode,
        onchange: () => { mode = m; },
      }),
      h('span', {}, m === 'deterministic' ? 'Deterministic (aux = 0)' : 'Random (hedged aux)'),
    ),
  );

  root.append(
    panelIntro(
      'Sign & Verify',
      'A digital signature proves a specific message came from the holder of a private key, and that nobody altered it in transit — without ever revealing the key. Schnorr does this with one short equation instead of the tangle inside ECDSA.',
      'Pick a key, type a message, and sign. Everything below is computed with real BIP-340 arithmetic over secp256k1 — the same signatures Bitcoin Taproot uses.',
    ),
    h('div', { class: 'controls' },
      h('div', { class: 'control' },
        h('label', { for: 'sk-input' }, 'Private key x (hex, 32 bytes)'),
        h('div', { class: 'input-row' },
          skInput,
          h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => {
            secret = normalizeSecretKey(bytesToBig(randomBytes(32)));
            skInput.value = bytesToHex(bigTo32(secret));
            refreshPubkey();
          } }, 'Randomize'),
        ),
        h('p', { id: 'sk-help', class: 'help' }, 'Normalized to BIP-340 even-y form, so the key you see is the key recovery would return.'),
        h('div', { class: 'field' },
          h('span', { class: 'field-label' }, 'Public key P.x'),
          pkOut,
        ),
      ),
      h('div', { class: 'control' },
        h('label', { for: 'msg-input' }, 'Message'),
        msgInput,
      ),
      h('div', { class: 'control' },
        h('span', { class: 'control-label', id: 'nonce-mode-label' }, 'Nonce derivation'),
        h('div', { class: 'radio-row', role: 'group', 'aria-labelledby': 'nonce-mode-label' }, ...modeRadios),
        h('p', { class: 'help' }, 'Both are safe. Deterministic gives the same R every time; random hedges with fresh entropy. Because the nonce binds the message, reuse across different messages is cryptographically negligible — the deliberate-reuse flaw lives in the attack tab.'),
      ),
      h('button', { type: 'button', class: 'btn btn-primary', onclick: doSign }, 'Sign message'),
    ),
    note('info', h('strong', {}, 'Not production crypto — a teaching demo. '), 'This page deliberately renders private keys and nonces so you can watch the math; browser extensions, injected scripts, and devtools can read them, and JavaScript cannot guarantee constant-time execution or reliably zeroize secrets. The BIP-340 layer here is specification-conformant and differentially tested against ', h('code', {}, '@noble/curves'), ' (which is independently audited) — but it is not itself audited. Never use this to protect real funds.'),
    output,
  );

  refreshPubkey();
  doSign();
}
