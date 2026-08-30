import { defineConfig, devices } from "@playwright/test";

const port = 13081;
const image = process.env.WEB_WALLET_IMAGE || "mercury-bip448-web-wallet:e2e";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? "github" : "line",
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
  },
  webServer: {
    command: `docker rm -f mercury-bip448-web-wallet-e2e >/dev/null 2>&1 || true; exec docker run --rm --name mercury-bip448-web-wallet-e2e -p 127.0.0.1:${port}:8080 ${image}`,
    url: `http://127.0.0.1:${port}`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
