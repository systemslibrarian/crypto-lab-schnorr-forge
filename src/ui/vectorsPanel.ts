import { h, clear, field, panelIntro, note } from './dom.js';
import { verify } from '../schnorr/bip340.js';
import { hexToBytes } from '../schnorr/field.js';
import { BIP340_VECTORS, type Bip340Vector } from '../schnorr/vectors.js';
import { openVerifyWorkbench } from './workbenchBridge.js';

/**
 * Runs every official BIP-340 vector through our hand-rolled verify(). Each row
 * expands (keyboard- and touch-operable via native <details>) to show the full
 * artifacts, our verdict, the exact failing stage, and a hand-off to the Verify
 * Workbench. "Matched spec" means our verdict equalled the expected column.
 */
export function renderVectorsPanel(root: HTMLElement): void {
  clear(root);

  const summary = h('div', { class: 'kat-summary', role: 'status', 'aria-live': 'polite' });
  const list = h('div', { class: 'kat-list' });

  function row(v: Bip340Vector): HTMLElement {
    const res = verify(hexToBytes(v.signature), hexToBytes(v.message), hexToBytes(v.publicKey));
    const agree = res.valid === v.expected;
    const caseLabel = v.comment || (v.expected ? 'valid signature' : 'must be rejected');

    const loadBtn = h('button', {
      type: 'button',
      class: 'btn btn-ghost',
      onclick: () =>
        openVerifyWorkbench({ pubkeyHex: v.publicKey, sigHex: v.signature, msgHex: v.message }),
    }, 'Load in Verify Workbench');

    return h(
      'details',
      { class: `kat-item ${agree ? 'kat-ok' : 'kat-bad'}` },
      h('summary', {},
        h('span', { class: 'kat-idx' }, `#${v.index}`),
        h('span', { class: 'kat-case' }, caseLabel),
        h('span', { class: `pill pill-${agree ? 'ok' : 'bad'}` },
          h('span', { 'aria-hidden': 'true' }, agree ? '✓ ' : '✕ '),
          agree ? 'matched spec' : 'MISMATCH',
        ),
      ),
      h('div', { class: 'kat-body' },
        field('public key (x-only)', v.publicKey),
        field('message', v.message === '' ? '(empty)' : v.message, { sub: '(hex)' }),
        field('signature R.x ‖ s', v.signature),
        field('spec expects', v.expected ? 'accept' : 'reject', { mono: false }),
        field('our verify()', res.valid ? 'accept' : `reject — ${res.reason}`, { mono: false }),
        h('div', { class: 'input-row' }, loadBtn),
      ),
    );
  }

  function run(): void {
    clear(list);
    let passed = 0;
    for (const v of BIP340_VECTORS) {
      const res = verify(hexToBytes(v.signature), hexToBytes(v.message), hexToBytes(v.publicKey));
      if (res.valid === v.expected) passed++;
      list.append(row(v));
    }
    clear(summary);
    const all = passed === BIP340_VECTORS.length;
    summary.append(
      h('span', { class: `pill pill-${all ? 'ok' : 'bad'}` },
        h('span', { 'aria-hidden': 'true' }, all ? '✓ ' : '✕ '),
        `${passed} / ${BIP340_VECTORS.length} vectors match the BIP-340 spec`,
      ),
    );
  }

  root.append(
    panelIntro(
      'BIP-340 Test Vectors',
      'Known-answer tests separate a real implementation from one that merely looks right. These are the official vectors published with BIP-340 — some valid signatures that must be accepted, some deliberately malformed (a point off the curve, an out-of-range scalar, a negated value) that must be rejected.',
      'Every row is checked by the same hand-rolled verify() the other tabs use. Expand any row for the full artifacts and the exact stage that accepted or rejected it, or send it to the Verify Workbench.',
    ),
    summary,
    list,
    note('info', 'These same vectors run in CI as unit tests (', h('code', {}, 'src/schnorr/vectors.test.ts'), ') — the build fails if any diverges from the spec.'),
  );

  run();
}
