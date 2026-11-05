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

  test('signing canonicalizes the visible key and input edits retire its evidence', async ({ page }) => {
    await boot(page, 'dark');
    const panel = page.locator('#panel-sign');
    await expect(panel.locator('.verdict-pass')).toContainText('VALID');

    await page.locator('#msg-input').fill('a changed message');
    await expect(panel.locator('.evidence-retired')).toContainText('Inputs changed');
    await expect(panel.locator('.verdict-pass')).toHaveCount(0);

    // 6·G has odd y, so the canonical BIP-340 secret is n - 6. The visible
    // and copyable input must change with the scalar the signer actually uses.
    await page.locator('#sk-input').fill('0000000000000000000000000000000000000000000000000000000000000006');
    await expect(panel.getByText('key changed — sign to recompute')).toBeVisible();
    await page.getByRole('button', { name: 'Sign message' }).click();
    await expect(panel.getByText('key changed — sign to recompute')).toHaveCount(0);
    await expect(page.locator('#sk-input')).toHaveValue(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413b',
    );
    await expect(panel.locator('.verdict-pass')).toContainText('VALID');
  });

  test('the Verify Workbench retires a verdict as soon as an artifact changes', async ({ page }) => {
    await boot(page, 'dark');
    await page.getByRole('tab', { name: 'Verify Workbench' }).click();
    const panel = page.locator('#panel-verify');
    await expect(panel.locator('.verdict-pass')).toContainText('VALID');
    const current = await page.locator('#wb-sig').inputValue();
    await page.locator('#wb-sig').fill(`${current.slice(0, -1)}0`);
    await expect(panel.locator('.evidence-retired')).toContainText('inputs changed');
    await expect(panel.locator('.verdict-pass, .verdict-fail')).toHaveCount(0);
  });

  test('nonce-reuse and aggregation evidence retires with its message', async ({ page }) => {
    await boot(page, 'dark');

    await page.getByRole('tab', { name: 'Nonce Reuse' }).click();
    const attack = page.locator('#panel-attack');
    await expect(attack.locator('.verdict-alarm')).toContainText('EQUALS');
    await page.locator('#atk-msg2').fill('a different transfer');
    await expect(attack.locator('.evidence-retired')).toContainText('Messages changed');
    await expect(attack.locator('.verdict-alarm')).toHaveCount(0);

    await page.getByRole('tab', { name: 'Why Linearity Matters' }).click();
    const linearity = page.locator('#panel-linearity');
    await expect(linearity.locator('.verdict-pass')).toContainText('accepts');
    await page.locator('#lin-msg').fill('a different joint statement');
    await expect(linearity.locator('.evidence-retired')).toContainText('message changed');
    await expect(linearity.locator('.verdict-pass')).toHaveCount(0);
  });
});
