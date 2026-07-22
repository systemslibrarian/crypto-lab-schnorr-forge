import { h, clear, panelIntro, note, short } from './dom.js';
import { verify } from '../schnorr/bip340.js';
import { hexToBytes } from '../schnorr/field.js';
import { BIP340_VECTORS } from '../schnorr/vectors.js';

/**
 * Runs every official BIP-340 vector through our hand-rolled verify() and shows
 * pass/fail per row. "Pass" means our verdict matched the spec's expected result
 * (including the malformed rows that MUST be rejected).
 */
export function renderVectorsPanel(root: HTMLElement): void {
  clear(root);

  const summary = h('div', { class: 'kat-summary', role: 'status', 'aria-live': 'polite' });
  const tbody = h('tbody', {});

  function run(): void {
    clear(tbody);
    let passed = 0;
    for (const v of BIP340_VECTORS) {
      const got = verify(hexToBytes(v.signature), hexToBytes(v.message), hexToBytes(v.publicKey)).valid;
      const agree = got === v.expected;
      if (agree) passed++;
      tbody.append(
        h('tr', { class: agree ? 'kat-ok' : 'kat-bad' },
          h('td', {}, String(v.index)),
          h('td', {}, h('code', { class: 'field-value', title: v.publicKey }, short(v.publicKey))),
          h('td', {}, v.expected ? 'accept' : 'reject'),
          h('td', {},
            h('span', { class: `pill pill-${agree ? 'ok' : 'bad'}` },
              h('span', { 'aria-hidden': 'true' }, agree ? '✓ ' : '✕ '),
              agree ? 'matched spec' : 'MISMATCH',
            ),
          ),
          h('td', { class: 'kat-comment' }, v.comment || (v.expected ? 'valid signature' : '')),
        ),
      );
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
      'Known-answer tests are how you tell a real implementation from one that merely looks right. These are the official vectors published with BIP-340 — some are valid signatures that must be accepted, and some are deliberately malformed (a point off the curve, an out-of-range scalar, a negated value) that must be rejected.',
      'Every row is checked by the same hand-rolled verify() used in the other tabs. A green row means our verdict matched the spec.',
    ),
    summary,
    h('div', { class: 'table-wrap', role: 'region', 'aria-label': 'BIP-340 test vector results', tabindex: '0' },
      h('table', { class: 'kat-table' },
        h('thead', {},
          h('tr', {},
            h('th', { scope: 'col' }, '#'),
            h('th', { scope: 'col' }, 'public key (x-only)'),
            h('th', { scope: 'col' }, 'spec expects'),
            h('th', { scope: 'col' }, 'our verify()'),
            h('th', { scope: 'col' }, 'case'),
          ),
        ),
        tbody,
      ),
    ),
    note('info', 'These same vectors run in CI as unit tests (', h('code', {}, 'src/schnorr/vectors.test.ts'), ') — the build fails if any diverges from the spec.'),
  );

  run();
}
