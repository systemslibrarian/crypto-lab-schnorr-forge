import { defineConfig, devices } from '@playwright/test';

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 *
 * Port 4357 is unique to this lab across the fleet (never the Vite default 4173:
 * with 100+ labs checked out side by side a shared port would silently scan a
 * different lab's preview via reuseExistingServer).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4357/crypto-lab-schnorr-forge/',
    // Dark is the default theme; pin the emulated scheme to dark so the default
    // scan is dark and the toggle deterministically moves to light.
    colorScheme: 'dark',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run preview -- --port 4357 --strictPort',
    url: 'http://localhost:4357/crypto-lab-schnorr-forge/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
