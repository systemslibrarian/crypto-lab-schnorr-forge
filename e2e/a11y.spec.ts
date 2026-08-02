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

    // Fire the primary actions in this panel (sign, verify, attack, combine…).
    // Every exploratory click is time-bounded so a non-actionable target can
    // never hang the scan.
    const buttons = panel.locator('button');
    const n = await buttons.count();
    for (let b = 0; b < n; b++) {
      const label = ((await buttons.nth(b).textContent()) || '').toLowerCase();
      if (/(sign|verify|attack|combine|break it|next|randomize|new )/.test(label)) {
        await buttons.nth(b).click({ timeout: 2000 }).catch(() => {});
      }
    }
  }
  // Reveal every panel and open every disclosure so all states are in the DOM.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
    document.querySelectorAll<HTMLElement>('[hidden]').forEach((el) => el.removeAttribute('hidden'));
  });
  // Now that everything is visible, drive rejection + learner-check states too.
  for (const sel of ['.preset-reject', '.check-opt']) {
    for (const el of await page.locator(sel).all()) {
      await el.click({ timeout: 1500, force: true }).catch(() => {});
    }
  }
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

async function minimumInputBoundaryContrast(page: Page): Promise<number> {
  return page.locator('.mono-input, .msg-input').evaluateAll((elements) => {
    const luminance = (color: string): number => {
      const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045
          ? normalized / 12.92
          : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    };
    return Math.min(...elements.map((element) => {
      const style = getComputedStyle(element);
      const border = luminance(style.borderTopColor);
      const background = luminance(style.backgroundColor);
      return (Math.max(border, background) + 0.05) / (Math.min(border, background) + 0.05);
    }));
  });
}

test('input boundaries clear WCAG non-text contrast in both themes', async ({ page }) => {
  await page.goto('.');
  expect(await minimumInputBoundaryContrast(page)).toBeGreaterThanOrEqual(3);

  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await minimumInputBoundaryContrast(page)).toBeGreaterThanOrEqual(3);
});

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
