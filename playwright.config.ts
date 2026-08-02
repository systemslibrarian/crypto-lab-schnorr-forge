import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what passes
 * here is what ships. Two kinds of tests:
 *   - a11y.spec.ts  — the axe WCAG gate, Chromium only (deterministic gate).
 *   - flows.spec.ts — role-based functional scenarios across Chromium, Firefox,
 *     WebKit, and a mobile viewport.
 *
 * Port 4357 is unique to this lab across the fleet (never the Vite default 4173).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 90_000, // the axe driver walks every panel + disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4357/crypto-lab-schnorr-forge/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      // Scan the real dark default; the toggle deterministically reaches light.
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    { name: 'flows-chromium', testMatch: /flows\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'flows-firefox', testMatch: /flows\.spec\.ts/, use: { ...devices['Desktop Firefox'] } },
    { name: 'flows-webkit', testMatch: /flows\.spec\.ts/, use: { ...devices['Desktop Safari'] } },
    { name: 'flows-mobile', testMatch: /flows\.spec\.ts/, use: { ...devices['Pixel 5'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4357 --strictPort',
    url: 'http://localhost:4357/crypto-lab-schnorr-forge/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
