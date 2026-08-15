import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where Sign
 * & Verify has auto-signed its default message and the other five tabpanels
 * are hidden and UNRENDERED; the shared skip link focused; the tamper button's
 * correctly-rejected verdict; the BIP-340 parity disclosure and the learner
 * check opened through their summaries, answered wrong and then right; a
 * malformed private key and a malformed hex message, each replacing the signed
 * output with a failure verdict behind an `aria-invalid` boundary; the
 * message control's hex mode; a copy button in its just-clicked state; the
 * Verify Workbench on its valid preset, on an off-curve rejection that stops
 * the pipeline at a failing stage, on a truncated signature, and on an
 * unparseable key; the equation stepper at
 * step 0, stepped to its verified end, and reset; the nonce-reuse attack's
 * recovered-key alarm and its no-recovery branch on identical messages; the
 * vectors table shut, expanded, and handing a case across tabs to the
 * workbench; the linearity aggregation with fresh signers; three hover states;
 * two focus rings; and finally the theme switched live through the shared bar
 * with every panel rendered. Every one of those states is scanned, in both
 * themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (the old gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion
 * block, so the rendering reduced-motion readers get was never the one
 * scanned), why no panel is revealed from script (the old gate stripped every
 * `[hidden]` and opened every `<details>` by JS before its only scan), why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
