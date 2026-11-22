import { describe, expect, it } from 'vitest';
import { copyLabels } from './dom';

/**
 * WCAG 2.5.3 Label in Name, as axe enforces it in `label-content-name-mismatch`.
 *
 * The rule became a failure in this lab when @axe-core/playwright moved 4.13 ->
 * 4.14. The secret copy button was named "Copy private key (secret)" over the
 * visible text "Copy secret": every word is present, but not as a contiguous
 * string, so the accessible name did not CONTAIN the visible label and the rule
 * fired. One violation, on one node, `.copy-secret`.
 *
 * `copyLabels` is the pure half of `copyButton`, extracted so the invariant can be
 * asserted without a DOM: this lab's Vitest run has no jsdom and no `environment`,
 * so a test that built an element would fail on `document` being undefined — and
 * adding jsdom to satisfy a test is not a dependency this fix needs.
 *
 * The invariant: the visible text is always a PREFIX of the accessible name. The
 * old signature took the whole name from the caller, so any call site could
 * reintroduce the mismatch; these assertions are why that shape cannot come back.
 */
const norm = (s: string) => s.replace(/\s+/g, ' ').trim().toLowerCase();

describe('copyLabels: the visible text is always part of the accessible name', () => {
  it('a plain button names itself exactly', () => {
    expect(copyLabels()).toEqual({ visible: 'Copy', name: 'Copy' });
  });

  it('a described button starts with its visible text', () => {
    const { visible, name } = copyLabels({ describes: 'signature' });
    expect(visible).toBe('Copy');
    expect(name).toBe('Copy signature');
    expect(norm(name).startsWith(norm(visible))).toBe(true);
  });

  it('the SECRET button starts with its visible text — the case that failed', () => {
    const { visible, name } = copyLabels({ secret: true, describes: 'private key' });
    expect(visible).toBe('Copy secret');
    expect(name).toBe('Copy secret private key');
    expect(norm(name).startsWith(norm(visible))).toBe(true);
  });

  it('NEGATIVE: the name that shipped would fail this assertion', () => {
    /* Keeps the defect legible. "Copy private key (secret)" contains every WORD of
       "Copy secret" and still does not contain the label as a string, which is
       exactly why axe flagged it and why word-presence is not the test. */
    expect(norm('Copy private key (secret)').includes(norm('Copy secret'))).toBe(false);
  });

  it('every shape this builder can produce satisfies the rule', () => {
    for (const secret of [false, true]) {
      for (const describes of [undefined, 'signature', 'shareable verify link', 'public key', 'private key']) {
        const { visible, name } = copyLabels({ secret, describes });
        expect(norm(name).startsWith(norm(visible))).toBe(true);
      }
    }
  });
});
