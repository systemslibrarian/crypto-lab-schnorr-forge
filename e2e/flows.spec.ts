import { expect, test, type Page } from '@playwright/test';

/**
 * Explicit, role-based end-to-end scenarios. Unlike the axe gate, these assert
 * real outcomes (a VALID verdict, a rejection, a tab switch) and never swallow a
 * failed interaction — a missing result fails the test immediately. Runs across
 * Chromium/Firefox/WebKit and a mobile viewport (see playwright.config.ts).
 */

const selectedTab = (page: Page) =>
  page.locator('.tab-btn[aria-selected="true"]').textContent();

test('sign then verify shows a VALID both-sides verdict', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('button', { name: 'Sign message' }).click();
  const panel = page.locator('#panel-sign');
  await expect(panel.locator('.verdict-pass')).toContainText(/VALID/);
});

test('tampering with the message makes the real verifier reject', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('button', { name: 'Sign message' }).click();
  await page.getByRole('button', { name: /Break it/ }).click();
  await expect(page.locator('#panel-sign .tamper-out .verdict-fail')).toContainText(/rejected/i);
});

test('Verify Workbench accepts a valid preset and rejects an off-curve key', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('tab', { name: 'Verify Workbench' }).click();
  const panel = page.locator('#panel-verify');
  // Valid preset → the full five-stage pipeline, all passing.
  await expect(panel.locator('.verdict-pass')).toContainText(/VALID/);
  await expect(panel.locator('.stage')).toHaveCount(5);
  // Off-curve key → rejected, and the pipeline stops at the failing stage.
  await panel.getByRole('button', { name: /off curve/ }).click();
  await expect(panel.locator('.verdict-fail')).toContainText(/not a valid x-coordinate/);
  await expect(panel.locator('.stage-fail')).toHaveCount(1);
});

test('all 19 official vectors match spec and a row loads into the workbench', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('tab', { name: 'BIP-340 Test Vectors' }).click();
  await expect(page.locator('#panel-vectors .kat-summary')).toContainText('19 / 19');
  const first = page.locator('#panel-vectors .kat-item').first();
  await first.locator('summary').click();
  await first.getByRole('button', { name: /Load in Verify Workbench/ }).click();
  await expect.poll(() => selectedTab(page)).toContain('Verify Workbench');
  await expect(page.locator('#wb-pk')).not.toHaveValue('');
});

test('two signers aggregate into one signature the verifier accepts', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('tab', { name: 'Why Linearity Matters' }).click();
  await page.getByRole('button', { name: /Sign separately, then combine/ }).click();
  await expect(page.locator('#panel-linearity .verdict-pass')).toContainText(/accepts/);
});

test('tablist supports roving arrow-key navigation', async ({ page }) => {
  await page.goto('.');
  const tabs = page.getByRole('tab');
  await tabs.first().focus();
  await page.keyboard.press('End');
  expect(await selectedTab(page)).toBe(await tabs.last().textContent());
  await page.keyboard.press('Home');
  expect(await selectedTab(page)).toBe(await tabs.first().textContent());
  await page.keyboard.press('ArrowRight');
  expect(await selectedTab(page)).toBe(await tabs.nth(1).textContent());
});

test('skip link is the first focusable element and jumps to content', async ({ page, browserName }) => {
  // WebKit emulates macOS, where Tab skips links unless "Full Keyboard Access"
  // is enabled — so tabbing to a link is not testable there. The skip link still
  // works via click/Enter in WebKit; we assert Tab focus on the other engines.
  test.skip(browserName === 'webkit', 'macOS Tab order skips links by default');
  await page.goto('.');
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toHaveClass(/cl-skip-link/);
  await page.keyboard.press('Enter');
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#app');
});

test('no horizontal overflow at the tested viewport', async ({ page }) => {
  await page.goto('.');
  const { sw, cw } = await page.evaluate(() => ({
    sw: document.documentElement.scrollWidth,
    cw: document.documentElement.clientWidth,
  }));
  expect(sw).toBeLessThanOrEqual(cw);
});

test('primary controls meet the 44px touch target on coarse pointers', async ({ page }) => {
  await page.goto('.');
  const coarse = await page.evaluate(() => matchMedia('(pointer: coarse)').matches);
  test.skip(!coarse, 'touch-target rule only applies to coarse pointers');
  const box = await page.getByRole('button', { name: 'Sign message' }).boundingBox();
  expect(box).not.toBeNull();
  expect(box!.height).toBeGreaterThanOrEqual(44);
});
