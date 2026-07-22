import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Put EVERY panel into its post-interaction state before scanning. Axe only
 * checks what's in the DOM, and this lab renders each tab lazily on first
 * activation and fills dynamic result regions on button clicks — so we open
 * every tab and drive each exhibit's core actions. An unscanned state is an
 * ungated state.
 */
async function driveDemos(page: Page): Promise<void> {
  const tabs = page.locator('.tab-btn');
  const count = await tabs.count();
  for (let i = 0; i < count; i++) {
    await tabs.nth(i).click();
    await page.waitForTimeout(120);
    const panelId = await tabs.nth(i).getAttribute('aria-controls');
    const panel = page.locator(`#${panelId}`);

    // Fire the primary actions in this panel (sign, attack, combine, tamper…).
    const buttons = panel.locator('button');
    const n = await buttons.count();
    for (let b = 0; b < n; b++) {
      const label = ((await buttons.nth(b).textContent()) || '').toLowerCase();
      if (/(sign|attack|combine|break it|next|randomize|new )/.test(label)) {
        await buttons.nth(b).click().catch(() => {});
        await page.waitForTimeout(60);
      }
    }
  }
  // Reveal every panel so all of them are scanned in one pass.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
    document.querySelectorAll<HTMLElement>('[hidden]').forEach((el) => el.removeAttribute('hidden'));
  });
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.waitForTimeout(200);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await scan(page);
});
