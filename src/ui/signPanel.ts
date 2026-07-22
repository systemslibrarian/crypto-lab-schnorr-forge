import { h, clear, field, verdict, panelIntro, note, copyButton, learnerCheck } from './dom.js';
import { sign, verify, type NonceMode, type SignResult } from '../schnorr/bip340.js';
import {
  G,
  N,
  bytesToBig,
  bigTo32,
  bytesToHex,
  hexToBytes,
  xOnly,
  randomBytes,
  normalizeSecretKey,
} from '../schnorr/field.js';
import { createMessageInput } from './messageInput.js';

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
  const msg = createMessageInput({
    id: 'msg-input',
    label: 'Message',
    initialText: 'Schnorr is the signature ECDSA wishes it were.',
    initialMode: 'utf8',
  });
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

  function bip340Details(res: SignResult): HTMLElement {
    const t = res.trace;
    return h(
      'details',
      { class: 'bip-details' },
      h('summary', {}, 'BIP-340 details: why x-only keys need parity normalization'),
      h('div', { class: 'bip-body' },
        h('p', {}, 'Textbook Schnorr uses full points; BIP-340 stores only the x-coordinate (32 bytes). Two points share each x — one with even y, one with odd — so BIP-340 fixes the even-y representative and negates the secret or nonce to match.'),
        field('raw private scalar  d₀ = int(sk)', `0x${t.d0.toString(16)}`),
        field('public key P has even y?', String(t.pubHasEvenY), { mono: false }),
        field('effective secret  d = d₀' + (t.pubHasEvenY ? '' : '  →  n − d₀ (P had odd y)'), `0x${t.d.toString(16)}`),
        t.auxRand ? field('auxiliary randomness (aux)', bytesToHex(t.auxRand)) : field('nonce source', 'forced (attack mode)', { mono: false }),
        field('raw nonce scalar  k₀', `0x${t.k0.toString(16)}`),
        field('commitment R has even y?', String(t.rHasEvenY), { mono: false }),
        field('effective nonce  k = k₀' + (t.rHasEvenY ? '' : '  →  n − k₀ (R had odd y)'), `0x${t.k.toString(16)}`),
        h('p', { class: 'help' }, 'The challenge hashes exactly R.x (32 bytes) ‖ P.x (32 bytes) ‖ message (variable) — fixed 32-byte boundaries, no length prefixes.'),
      ),
    );
  }

  function renderResult(res: SignResult, msgBytes: Uint8Array): void {
    clear(output);
    const t = res.trace;
    const sigHex = bytesToHex(res.signature);
    const pubHex = bytesToHex(t.pubkey);
    const msgHex = bytesToHex(msgBytes);

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

    const v = verify(res.signature, msgBytes, t.pubkey);
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

    const tamperOut = h('div', { class: 'tamper-out', role: 'status', 'aria-live': 'polite' });
    const tamper = h('button', {
      type: 'button',
      class: 'btn btn-ghost',
      onclick: () => {
        const forged = msgBytes.slice();
        if (forged.length === 0) {
          clear(tamperOut);
          tamperOut.append(verdict('fail', 'Empty message — type something to tamper with.'));
          return;
        }
        forged[forged.length - 1] ^= 0x01; // flip one real byte
        const fv = verify(res.signature, forged, t.pubkey);
        clear(tamperOut);
        tamperOut.append(
          field('re-verify the same signature against one flipped message byte', bytesToHex(forged), { sub: '(hex)' }),
          fv.valid
            ? verdict('alarm', 'Unexpectedly accepted — this should never happen')
            : verdict('fail', `Correctly rejected — ${fv.reason}`),
        );
      },
    }, 'Break it: flip one message byte, re-verify the same signature');

    // Public artifacts only — copy, export, and a shareable verify permalink.
    const permalink = () => {
      const base = `${location.origin}${location.pathname}`;
      return `${base}#verify?pk=${pubHex}&sig=${sigHex}&msg=${msgHex}`;
    };
    const exportJson = () =>
      JSON.stringify(
        { version: 1, scheme: 'BIP-340', containsSecrets: false, publicKey: pubHex, messageHex: msgHex, signature: sigHex, valid: v.valid },
        null,
        2,
      );

    const actions = h('div', { class: 'action-row' },
      copyButton(() => sigHex, { label: 'Copy signature' }),
      copyButton(() => permalink(), { label: 'Copy shareable verify link' }),
      h('button', {
        type: 'button', class: 'btn btn-ghost',
        onclick: () => {
          const blob = new Blob([exportJson()], { type: 'application/json' });
          const a = h('a', { href: URL.createObjectURL(blob), download: 'schnorr-signature.json' });
          a.click();
          URL.revokeObjectURL(a.href);
        },
      }, 'Export public JSON'),
    );

    output.append(
      h('div', { class: 'field' },
        h('span', { class: 'field-label' }, 'public key P.x (x-only, 32 bytes)'),
        h('div', { class: 'value-with-copy' },
          h('code', { class: 'field-value' }, pubHex),
          copyButton(() => pubHex, { label: 'Copy public key' }),
        ),
      ),
      steps,
      sigField,
      actions,
      both,
      bip340Details(res),
      h('div', { class: 'tamper' }, tamper, tamperOut),
    );
  }

  function doSign(): void {
    if (!refreshPubkey()) {
      clear(output);
      output.append(verdict('fail', 'Fix the private key before signing.'));
      return;
    }
    const m = msg.read();
    if (!m.ok) {
      clear(output);
      output.append(verdict('fail', `Message: ${m.error}`));
      return;
    }
    renderResult(sign(m.bytes, bigTo32(secret), mode), m.bytes);
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
      'A digital signature proves a specific message came from the holder of a private key, and that nobody altered it — without revealing the key. Schnorr does this with one short equation instead of the tangle inside ECDSA.',
      'Pick a key, supply a message as text or exact bytes, and sign. Everything below is computed with real BIP-340 arithmetic over secp256k1 — the same signatures Bitcoin Taproot uses.',
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
          copyButton(() => skInput.value.trim(), { secret: true, label: 'Copy private key (secret)' }),
        ),
        h('p', { id: 'sk-help', class: 'help' }, 'Normalized to BIP-340 even-y form, so the key you see is the key recovery would return.'),
        h('div', { class: 'field' },
          h('span', { class: 'field-label' }, 'Public key P.x'),
          pkOut,
        ),
      ),
      msg.element,
      h('div', { class: 'control' },
        h('span', { class: 'control-label', id: 'nonce-mode-label' }, 'Nonce derivation'),
        h('div', { class: 'radio-row', role: 'group', 'aria-labelledby': 'nonce-mode-label' }, ...modeRadios),
        h('p', { class: 'help' }, 'Both are safe. Deterministic gives the same R every time; random hedges with fresh entropy. Because the nonce binds the message, reuse across different messages is cryptographically negligible — the deliberate-reuse flaw lives in the attack tab.'),
      ),
      h('button', { type: 'button', class: 'btn btn-primary', onclick: doSign }, 'Sign message'),
    ),
    note('info', h('strong', {}, 'Not production crypto — a teaching demo. '), 'This page deliberately renders private keys and nonces so you can watch the math; browser extensions, injected scripts, and devtools can read them, and JavaScript cannot guarantee constant-time execution or reliably zeroize secrets. The BIP-340 layer here is specification-conformant and differentially tested against ', h('code', {}, '@noble/curves'), ' (which is independently audited) — but it is not itself audited. Never use this to protect real funds.'),
    learnerCheck(
      'You sign a message, then change only the message and re-verify with the same signature. What happens?',
      [
        { label: 'It still verifies', correct: false },
        { label: 'It is rejected', correct: true },
      ],
      'The challenge e = hash(R.x ‖ P.x ‖ message) folds the message in, so changing the message changes e, and s·G no longer equals R + e·P. Try it with the "Break it" button.',
    ),
    output,
  );

  refreshPubkey();
  doSign();
}
