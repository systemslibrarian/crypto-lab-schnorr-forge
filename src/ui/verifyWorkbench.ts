import { h, clear, field, verdict, panelIntro, note } from './dom.js';
import { verify, type VerifyStage } from '../schnorr/bip340.js';
import { hexToBytes } from '../schnorr/field.js';
import { BIP340_VECTORS } from '../schnorr/vectors.js';
import { createMessageInput } from './messageInput.js';
import { setVerifyLoader } from './workbenchBridge.js';

interface Preset {
  name: string;
  expect: 'accept' | 'reject';
  pubkey: string;
  sig: string;
  msgHex: string;
  why: string;
}

function buildPresets(): Preset[] {
  const v = (i: number) => BIP340_VECTORS[i];
  const valid = v(1);
  // Changed-message: valid signature, one message byte flipped.
  const flipped = valid.message.slice(0, -2) + (valid.message.slice(-2) === '89' ? '8a' : '00');
  return [
    { name: 'Valid (vector 1)', expect: 'accept', pubkey: valid.publicKey, sig: valid.signature, msgHex: valid.message, why: 'a well-formed BIP-340 signature' },
    { name: 'Public key off curve (vector 5)', expect: 'reject', pubkey: v(5).publicKey, sig: v(5).signature, msgHex: v(5).message, why: v(5).comment },
    { name: 'R.x not on curve (vector 11)', expect: 'reject', pubkey: v(11).publicKey, sig: v(11).signature, msgHex: v(11).message, why: v(11).comment },
    { name: 'R.x = field size p (vector 12)', expect: 'reject', pubkey: v(12).publicKey, sig: v(12).signature, msgHex: v(12).message, why: v(12).comment },
    { name: 's = curve order n (vector 13)', expect: 'reject', pubkey: v(13).publicKey, sig: v(13).signature, msgHex: v(13).message, why: v(13).comment },
    { name: 'Public key > field size (vector 14)', expect: 'reject', pubkey: v(14).publicKey, sig: v(14).signature, msgHex: v(14).message, why: v(14).comment },
    { name: 'Changed message', expect: 'reject', pubkey: valid.publicKey, sig: valid.signature, msgHex: flipped, why: 'the signature is valid but the message was altered' },
    { name: 'Truncated signature (63 bytes)', expect: 'reject', pubkey: valid.publicKey, sig: valid.signature.slice(0, 126), msgHex: valid.message, why: 'wrong signature length' },
  ];
}

function stageRow(st: VerifyStage): HTMLElement {
  const icon = st.status === 'pass' ? '✓' : st.status === 'fail' ? '✕' : '·';
  return h(
    'li',
    { class: `stage stage-${st.status}`, role: 'listitem' },
    h('span', { class: 'stage-icon', 'aria-hidden': 'true' }, icon),
    h('span', { class: 'stage-label' }, st.label),
    h('span', { class: 'stage-detail' }, st.detail),
  );
}

export function renderVerifyWorkbench(root: HTMLElement): void {
  clear(root);

  const pkInput = h('input', { type: 'text', id: 'wb-pk', class: 'mono-input', spellcheck: false, autocomplete: 'off', placeholder: 'x-only public key — 64 hex chars' }) as HTMLInputElement;
  const sigInput = h('input', { type: 'text', id: 'wb-sig', class: 'mono-input', spellcheck: false, autocomplete: 'off', placeholder: 'signature R.x ‖ s — 128 hex chars' }) as HTMLInputElement;
  const msg = createMessageInput({ id: 'wb-msg', label: 'Message', initialMode: 'hex', initialText: '' });
  const output = h('div', { class: 'output', id: 'wb-output' });

  function run(): void {
    clear(output);
    let sig: Uint8Array, pubkey: Uint8Array;
    try {
      pubkey = hexToBytes(pkInput.value.trim());
    } catch (e) {
      output.append(verdict('fail', `Public key: ${(e as Error).message}`));
      return;
    }
    try {
      sig = hexToBytes(sigInput.value.trim());
    } catch (e) {
      output.append(verdict('fail', `Signature: ${(e as Error).message}`));
      return;
    }
    const m = msg.read();
    if (!m.ok) {
      output.append(verdict('fail', `Message: ${m.error}`));
      return;
    }

    const res = verify(sig, m.bytes, pubkey);
    const children: (Node | null)[] = [
      h('h3', {}, 'Verification pipeline'),
      h('ol', { class: 'stage-list', role: 'list' }, ...res.stages.map(stageRow)),
      res.lhs != null
        ? h('div', { class: 'both-sides' },
            field('left  = s·G', res.lhs, { sub: '(x)' }),
            field('right = R + e·P', res.rhs ?? '—', { sub: '(x)' }),
          )
        : null,
      res.valid
        ? verdict('pass', 'Signature VALID — verified with no private key')
        : verdict('fail', `Rejected — ${res.reason}`),
    ];
    output.append(...children.filter((c): c is Node => c != null));
  }

  function load(pubkeyHex: string, sigHex: string, msgHex: string): void {
    pkInput.value = pubkeyHex;
    sigInput.value = sigHex;
    msg.setValue('hex', msgHex);
    run();
  }

  const presetButtons = buildPresets().map((p) =>
    h('button', {
      type: 'button',
      class: `btn btn-ghost preset-btn preset-${p.expect}`,
      title: p.why,
      onclick: () => load(p.pubkey, p.sig, p.msgHex),
    },
    h('span', { 'aria-hidden': 'true' }, p.expect === 'accept' ? '✓ ' : '✕ '),
    p.name),
  );

  // Allow other panels / the permalink to hand a case over.
  setVerifyLoader((d) => load(d.pubkeyHex, d.sigHex, d.msgHex));

  root.append(
    panelIntro(
      'Verify Workbench',
      'Verification needs only public data — a public key, a signature, and the message. Paste artifacts from any BIP-340 implementation (or load a preset) and watch the exact five-stage pipeline decide: parse and lengths, range checks, lift the points, recompute the challenge, and compare s·G against R + e·P.',
    ),
    note('info', 'No private key is used or required here. Every rejection names the precise stage and cause — the same hand-rolled ', h('code', {}, 'verify()'), ' the other tabs use.'),
    h('div', { class: 'controls' },
      h('div', { class: 'control' },
        h('label', { for: 'wb-pk' }, 'Public key P.x (x-only, hex)'),
        pkInput,
      ),
      h('div', { class: 'control' },
        h('label', { for: 'wb-sig' }, 'Signature R.x ‖ s (hex)'),
        sigInput,
      ),
      msg.element,
      h('button', { type: 'button', class: 'btn btn-primary', onclick: run }, 'Verify'),
    ),
    h('div', { class: 'presets' },
      h('span', { class: 'control-label', id: 'wb-preset-label' }, 'Load a case'),
      h('div', { class: 'preset-row', role: 'group', 'aria-labelledby': 'wb-preset-label' }, ...presetButtons),
    ),
    output,
  );

  // Start on the valid preset so the panel is populated and scannable.
  const first = buildPresets()[0];
  load(first.pubkey, first.sig, first.msgHex);
}
