/* What "audited" covers for the @noble/curves this lab ships.
 *
 * Three places called it audited with no version: the README's banner ("use
 * the audited [`@noble/curves`] `schnorr` implementation"), the "Conformance ≠
 * audit" bullet ("which is independently audited"), and src/schnorr/field.ts
 * ("audited, constant-time-ish"); the sign panel said the same on the page.
 * The library records its latest independent audit as "at version 2.3.0, in
 * Aug 2026, by [Trail of Bits]", scope "everything", and this lab pins ^2.4.0.
 *
 * The banner's claim is the one that matters most: it tells readers what to use
 * for real signing, so the version they should check is worth naming.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const flat = (text: string) => text.replace(/\n\s*\*\s?/g, ' ').replace(/\s+/g, ' ');

const pkg = JSON.parse(read('../../package.json'));
const nobleReadme = read('../../node_modules/@noble/curves/README.md');

describe('the @noble/curves audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
  });

  it('names that version in every place that calls the library audited', () => {
    for (const [name, text] of [
      ['README.md', flat(read('../../README.md'))],
      ['src/schnorr/field.ts', flat(read('./field.ts'))],
      ['src/ui/signPanel.ts', flat(read('../ui/signPanel.ts'))],
    ] as const) {
      expect(text, name).not.toContain('use the audited [`@noble/curves`]');
      expect(text, name).not.toContain('(which is independently audited)');
      expect(text, name).not.toContain('@noble/curves — audited, constant-time-ish');
      expect(text, name).toMatch(/at version 2\.3\.0, in Aug 2026, by \[?Trail of Bits\]?/);
      expect(text, name).toMatch(/\^2\.4\.0/);
    }
  });
});
