import { expect, test } from '@playwright/test';
import { boot } from './gate';

/**
 * The claims suite: what this lab's interface SAYS, as opposed to what it is
 * shaped like. §4.1b of audits/_MASTER-TEMPLATE.md.
 *
 * These three assertions used to live in `boot()` in gate.ts, the shared setup
 * every a11y test imports. That meant a one-word copy edit failed every test in
 * the accessibility gate at once, and the step that went red was named
 * "Accessibility gate" — a report naming the wrong subject. crypto-lab-mceliece-
 * gate lost three days of corrected security claims to exactly that on
 * 2026-09-26. Here, a failure says "claims", which is what actually changed.
 *
 * Each test below was mutation-checked on 2026-10-02: the source string was
 * changed, the build confirmed to still succeed, and THIS test confirmed to be
 * the one that fails. The kills are recorded in the pull request.
 */

test.describe('displayed claims', () => {
  test('the arrival verdict says the signature is VALID', async ({ page }) => {
    await boot(page, 'dark');
    // signPanel.ts signs its default message at mount, so first paint carries a
    // real pass verdict rather than a placeholder.
    await expect(page.locator('#panel-sign .verdict-pass')).toContainText('VALID');
  });

  test('the message box arrives holding this lab\'s own example sentence', async ({ page }) => {
    await boot(page, 'dark');
    await expect(page.locator('#msg-input')).toHaveValue(
      'Schnorr is the signature ECDSA wishes it were.'
    );
  });

  test('the pressed input-mode segment is labelled UTF-8 text', async ({ page }) => {
    await boot(page, 'dark');
    // messageInput.ts ships two segments and presses the UTF-8 one. That the
    // page arrives in text mode rather than hex is a claim about behaviour; the
    // label is the claim a reader actually sees.
    await expect(
      page.locator('#panel-sign .seg-btn[aria-pressed="true"]')
    ).toHaveText('UTF-8 text');
  });
});
