import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  STORAGE_KEY,
  STORAGE_PREFIX,
  installWalletHarness,
  loadSnapshot,
  storedSnapshot,
} from "./support/wallet-harness.js";

const fixturePath = fileURLToPath(new URL("../fixtures/recovery-ready.json", import.meta.url));
const recoveryFixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const generatorPublicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function blankFixture() {
  const snapshot = clone(recoveryFixture);
  snapshot.wallet.coins = [];
  snapshot.wallet.activities = [];
  snapshot.statechains = [];
  snapshot.state_histories = {};
  snapshot.funding_bindings = [];
  snapshot.withdrawal_attempts = [];
  snapshot.recovery_attempts = [];
  snapshot.pending_deposits = [];
  snapshot.pending_outgoing_transfer = null;
  snapshot.pending_incoming_transfer = null;
  snapshot.enclave_verification = null;
  snapshot.enclave_runtime_proof = null;
  return snapshot;
}

function confirmedUtxo(txid, vout, value) {
  return { txid, vout, value, status: { confirmed: true, block_height: 100 } };
}

test("launch wallet clears obsolete namespaces before starting fresh", async ({ page }) => {
  const obsoleteSnapshot = clone(recoveryFixture);
  const obsoleteKeys = [
    `${STORAGE_PREFIX}prelaunch-a`,
    `${STORAGE_PREFIX}prelaunch-b`,
  ];
  await installWalletHarness(page, { snapshot: obsoleteSnapshot });
  await page.addInitScript(({ keys, snapshot }) => {
    for (const key of keys) localStorage.setItem(key, JSON.stringify(snapshot));
  }, { keys: obsoleteKeys, snapshot: obsoleteSnapshot });

  await page.goto("/");
  await expect(page.locator("#status")).toHaveText("Ready.");
  const stored = await page.evaluate(({ currentKey, staleKeys }) => ({
    current: localStorage.getItem(currentKey),
    obsolete: staleKeys.map((key) => localStorage.getItem(key)),
  }), { currentKey: STORAGE_KEY, staleKeys: obsoleteKeys });

  expect(stored.obsolete).toEqual(obsoleteKeys.map(() => null));
  expect(stored.current).not.toBeNull();
  const freshSnapshot = JSON.parse(stored.current);
  expect(freshSnapshot.wallet.coins).toEqual([]);
  expect(freshSnapshot.statechains).toEqual([]);
  expect(freshSnapshot.wallet.mnemonic).not.toBe(obsoleteSnapshot.wallet.mnemonic);
});

test("wallet chrome stays focused on the core lifecycle", async ({ page }) => {
  const snapshot = blankFixture();
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  await expect(page).toHaveTitle("BIP448 Mercury Layer wallet");
  await expect(page.locator('meta[name="viewport"]')).toHaveAttribute(
    "content",
    "width=device-width, initial-scale=1, minimum-scale=1",
  );
  await expect(page.locator("#sync-wallet")).toHaveCount(0);
  await expect(page.locator('meta[name="description"]')).toHaveAttribute(
    "content",
    "Bitcoin layer 2 prototype for private, instant off-chain payments using Mercury Layer statechains and BIP448.",
  );
  const documentResponse = await page.request.get("/");
  expect(documentResponse.headers()["strict-transport-security"]).toBe("max-age=31536000");
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "./favicon.svg");
  const favicon = await page.evaluate(async () => {
    const response = await fetch(document.querySelector('link[rel="icon"]').href);
    return { ok: response.ok, svg: await response.text() };
  });
  expect(favicon.ok).toBe(true);
  expect(favicon.svg).toContain("🥖");
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveAttribute(
    "content",
    /wss:\/\/11b69774-3ba1-4911-8897-ab2380488cdb\.enclaves\.beta\.enclavia\.io/,
  );
  await expect(page.getByRole("heading", { level: 1, name: "BIP448 Mercury Layer wallet" })).toBeVisible();
  await expect(page.getByText("bip448.cash", { exact: true })).toBeVisible();
  await expect(page.getByText("Mutinynet signet", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "View source on GitHub" })).toHaveAttribute(
    "href",
    "https://github.com/stutxo/mercurylayer/tree/feature/bip448-web-wallet-mutinynet",
  );
  await expect(page.getByRole("link", { name: "View source on GitHub" }).locator("svg")).toBeVisible();
  const footer = page.locator(".status-bar");
  await expect(footer).toContainText("Made with love by stutxo at lx.dev");
  await expect(footer.getByRole("link", { name: "stutxo", exact: true })).toHaveAttribute(
    "href",
    "https://x.com/stutxo",
  );
  await expect(footer.getByRole("link", { name: "lx.dev", exact: true })).toHaveAttribute(
    "href",
    "https://lx.dev",
  );
  const about = page.getByRole("dialog", { name: "About this wallet" });
  await expect(about).toBeHidden();
  await page.getByRole("button", { name: "About", exact: true }).click();
  await expect(about).toBeVisible();
  await expect(about).toContainText(
    "Mercury Layer is a Bitcoin layer 2 for private, instant off-chain payments",
  );
  await expect(about.getByRole("link", { name: "Mercury Layer", exact: true })).toHaveAttribute(
    "href",
    "https://mercurylayer.com/",
  );
  await expect(about).toContainText("pre-signed update and settlement path");
  await expect(about.getByRole("link", { name: "BIP448", exact: true })).toHaveAttribute(
    "href",
    "https://github.com/bitcoin/bips/blob/master/bip-0448.md",
  );
  await expect(about).toContainText(
    "BIP448 is a soft-fork proposal and is not currently active on Bitcoin mainnet",
  );
  await expect(about).toContainText(
    "This prototype instead runs on Mutinynet, where the proposal's required opcodes are available",
  );
  await expect(
    about.getByRole("link", { name: "How BIP448 rebinding works.", exact: true }),
  ).toHaveAttribute(
    "href",
    "https://github.com/w0xlt/mercurylayer/blob/rebindable_statechains/docs/bip448_rebindable_statechains.md",
  );
  await expect(about).toContainText("OP_TEMPLATEHASH");
  await expect(about).toContainText("OP_CHECKSIGFROMSTACK");
  await expect(about).toContainText("OP_INTERNALKEY");
  const templateHashOpcode = about.locator("code", { hasText: "OP_TEMPLATEHASH" });
  await expect(templateHashOpcode).toHaveCSS("color", "rgb(0, 0, 128)");
  await expect(templateHashOpcode).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await expect(templateHashOpcode).toHaveCSS("font-weight", "700");
  await expect(about).toContainText("Replacing only the update's input outpoint");
  await expect(about).toContainText("higher locktime satisfies the older update path");
  await expect(about).toContainText("Enclavia.io AWS Nitro enclave");
  await expect(about).toContainText("anti-rollback protection");
  await expect(about.getByRole("link", { name: "anti-rollback protection" })).toHaveAttribute(
    "href",
    "https://enclavia.io/blog/how-we-solved-rollback-attacks/",
  );
  await expect(about).toContainText("previous owner and Mercury could steal from a future owner");
  await expect(about).toContainText(
    "TEE is intended to verify that the Mercury server deleted its previous signing share",
  );
  await expect(about).toContainText("Verify enclave");
  await expect(about).toContainText("Verify coin");
  await expect(about).toContainText("direct SDK Noise channel");
  await expect(about).toContainText("Mercury cannot read or forge");
  await expect(about).toContainText("no automatic watcher");
  await expect(about).toContainText("If a previous owner attempts to withdraw via their old state");
  await expect(about).toContainText("delegated watcher");
  await expect(about).toContainText("have 144 blocks");
  await expect(about).not.toContainText("synchronizer");
  await expect(about).not.toContainText("test harness");
  await expect(about).toContainText("Review is welcome");
  await expect(about).not.toContainText("issue reports are welcome");
  await expect(about).toContainText("Mutinynet research prototype by @lx.dev");
  await expect(about.getByRole("link", { name: "@lx.dev", exact: true })).toHaveAttribute(
    "href",
    "https://x.com/lxdev_",
  );
  await expect(about.getByRole("link", { name: "GitHub branch" })).toHaveAttribute(
    "href",
    "https://github.com/stutxo/mercurylayer/tree/feature/bip448-web-wallet-mutinynet",
  );
  await expect(about.getByRole("link", { name: "localhost" })).toHaveAttribute(
    "href",
    "https://x.com/lclhostresearch",
  );
  await expect(about).toContainText("rebindable-signature BIP448 work was done by localhost");
  await expect(about.getByRole("link", { name: "w0xlt" })).toHaveAttribute(
    "href",
    "https://github.com/w0xlt/mercurylayer/tree/rebindable_statechains",
  );
  await page.getByRole("button", { name: "Close" }).click();
  await expect(about).toBeHidden();
  await expect(page.locator(".app-tabs a")).toHaveCount(1);
  await expect(page.locator(".app-tabs a")).toHaveText("Wallet");
  expect(Math.round(await page.locator(".app-window").evaluate((node) => node.getBoundingClientRect().width))).toBe(780);

  await page.setViewportSize({ width: 390, height: 844 });
  expect(Math.round(await page.locator(".app-window").evaluate((node) => node.getBoundingClientRect().width))).toBe(390);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  expect(await page.locator("html").evaluate((node) => getComputedStyle(node).touchAction))
    .toBe("manipulation");
  expect(await page.locator("#deposit-amount").evaluate((node) => getComputedStyle(node).fontSize))
    .toBe("16px");
  expect(await page.locator("#deposit-amount").evaluate((node) => getComputedStyle(node).touchAction))
    .toBe("manipulation");
  await page.getByRole("button", { name: "About", exact: true }).click();
  await expect(about).toBeVisible();
  await expect(page.locator("#about-title")).toBeFocused();
  expect(await about.locator(".about-content").evaluate((node) => node.scrollTop)).toBe(0);
  expect(await about.evaluate((node) => node.scrollTop)).toBe(0);
  await page.getByRole("button", { name: "Close" }).click();

  const text = await page.locator("body").innerText();
  expect(text.match(/bip448\.cash/gi)).toHaveLength(1);
  expect(text).not.toContain("ONLINE");
  expect(text).not.toContain("Bitcoin signet");
  expect(text).not.toContain("Atomic payments");
  expect(text).not.toContain("Token payment");
  expect(text).not.toContain("Connection settings");
  await expect(page.locator("#enclave-details")).toBeVisible();
  await expect(page.locator("#deposit-section")).toBeVisible();
  await expect(page.locator("#transfer-section")).toBeVisible();
  await expect(page.locator("#statecoins-section")).toBeVisible();
});

test("About remains available while a wallet command is in progress", async ({ page }) => {
  const snapshot = blankFixture();
  let releaseDeposit;
  let markDepositStarted;
  const depositGate = new Promise((resolve) => {
    releaseDeposit = resolve;
  });
  const depositStarted = new Promise((resolve) => {
    markDepositStarted = resolve;
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await installWalletHarness(page, {
    snapshot,
    async onMercury({ request, path }) {
      if (request.method() === "POST" && path === "deposit/init/pod") {
        markDepositStarted();
        await depositGate;
        return {
          body: {
            server_pubkey: generatorPublicKey,
            statechain_id: "busy-about-deposit",
          },
        };
      }
      return undefined;
    },
  });
  await loadSnapshot(page, snapshot);
  await page.evaluate(async () => {
    const { MercuryWallet } = await import("./pkg/mercury_web_wallet.js");
    const free = MercuryWallet.prototype.free;
    window.__walletFreeCalls = 0;
    MercuryWallet.prototype.free = function () {
      window.__walletFreeCalls += 1;
      return free.call(this);
    };
  });

  const submit = page.locator("#deposit-form button[type=submit]");
  await page.locator("#deposit-amount").fill("2500");
  await submit.click();
  await depositStarted;
  await expect(page.locator("#status")).toHaveText(
    "Working: Generating a deposit key in the signing enclave…",
  );
  await expect(submit).toBeDisabled();

  const openAbout = page.getByRole("button", { name: "About", exact: true });
  await expect(openAbout).toBeEnabled();
  await openAbout.click();
  const about = page.getByRole("dialog", { name: "About this wallet" });
  await expect(about).toBeVisible();
  const closeAbout = about.getByRole("button", { name: "Close" });
  await expect(closeAbout).toBeEnabled();
  await closeAbout.click();
  await expect(about).toBeHidden();
  await expect(page.locator("#status")).toHaveText(
    /Still working \(\d+s\): Waiting for the signing enclave\. The pending deposit remains retryable\./,
    { timeout: 5_000 },
  );

  releaseDeposit();
  await expect(page.locator("#status")).toHaveText("Deposit address created.");
  expect(await page.evaluate(() => window.__walletFreeCalls)).toBe(0);
});

test("one-second transfer polling avoids repeated full-wallet round trips", async ({ page }) => {
  const snapshot = blankFixture();
  let releaseSync;
  let markSyncStarted;
  let holdSync = false;
  let heldMailboxRequest = false;
  let heldMailboxCompleted = false;
  const syncGate = new Promise((resolve) => {
    releaseSync = resolve;
  });
  const syncStarted = new Promise((resolve) => {
    markSyncStarted = resolve;
  });
  const state = await installWalletHarness(page, {
    snapshot,
    async onMercury({ request, path }) {
      if (
        holdSync && !heldMailboxRequest
        && request.method() === "GET"
        && path.startsWith("transfer/get_msg_addr/")
      ) {
        heldMailboxRequest = true;
        markSyncStarted();
        await syncGate;
        heldMailboxCompleted = true;
        return { body: { list_enc_transfer_msg: [] } };
      }
      return undefined;
    },
  });
  await loadSnapshot(page, snapshot);
  await page.locator("#create-receive-address").click();
  await expect(page.locator("#receive-addresses .address-item")).toHaveCount(1);

  await expect(page.locator("#sync-wallet")).toHaveCount(0);
  const amount = page.locator("#deposit-amount");
  const createReceiveAddress = page.locator("#create-receive-address");
  const mailboxRequestCount = () => state.mercuryRequests.filter(
    ({ method, path }) => method === "GET" && path.startsWith("transfer/get_msg_addr/"),
  ).length;
  const tipRequestCount = () => state.chainRequests.filter(
    ({ method, path }) => method === "GET" && path === "blocks/tip/height",
  ).length;
  const tipsBeforeFastSync = tipRequestCount();
  holdSync = true;

  await expect.poll(() => heldMailboxRequest, { timeout: 3_000 }).toBe(true);
  await syncStarted;
  await expect(page.locator("#status")).toHaveText("Receive address created.");
  await expect(amount).toBeEnabled();
  await expect(createReceiveAddress).toBeEnabled();
  expect(tipRequestCount()).toBe(tipsBeforeFastSync);

  await expect(amount).toBeEnabled();
  await amount.fill("2600");
  await expect(amount).toHaveValue("2600");

  releaseSync();
  await expect.poll(() => heldMailboxCompleted).toBe(true);
  await expect(page.locator("#status")).toHaveText("Receive address created.");
  await expect(amount).toHaveValue("2600");
  expect(tipRequestCount()).toBe(tipsBeforeFastSync);

  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await page.waitForTimeout(100);
  const beforeHidden = mailboxRequestCount();
  await page.waitForTimeout(1_500);
  expect(mailboxRequestCount()).toBe(beforeHidden);

  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(() => mailboxRequestCount() > beforeHidden, { timeout: 2_000 }).toBe(true);
  expect(tipRequestCount()).toBe(tipsBeforeFastSync);

  await expect.poll(tipRequestCount, { timeout: 4_000 }).toBeGreaterThan(tipsBeforeFastSync);
  await expect(amount).toHaveValue("2600");
});

test("storage events cannot replace the wallet used by an in-flight sync", async ({ page }) => {
  const snapshot = blankFixture();
  let releaseSync;
  let markSyncStarted;
  let holdSync = false;
  let heldMailboxRequest = false;
  let heldMailboxCompleted = false;
  const syncGate = new Promise((resolve) => {
    releaseSync = resolve;
  });
  const syncStarted = new Promise((resolve) => {
    markSyncStarted = resolve;
  });
  await installWalletHarness(page, {
    snapshot,
    async onMercury({ request, path }) {
      if (
        holdSync && !heldMailboxRequest
        && request.method() === "GET"
        && path.startsWith("transfer/get_msg_addr/")
      ) {
        heldMailboxRequest = true;
        markSyncStarted();
        await syncGate;
        heldMailboxCompleted = true;
        return { body: { list_enc_transfer_msg: [] } };
      }
      return undefined;
    },
  });
  await loadSnapshot(page, snapshot);
  await page.locator("#create-receive-address").click();
  await expect(page.locator("#status")).toHaveText("Receive address created.");

  holdSync = true;
  await expect.poll(() => heldMailboxRequest, { timeout: 3_000 }).toBe(true);
  await syncStarted;
  await expect(page.locator("#sync-wallet")).toHaveCount(0);

  await page.evaluate((key) => {
    const current = localStorage.getItem(key);
    const alternateEncoding = JSON.stringify(JSON.parse(current), null, 1);
    window.dispatchEvent(new StorageEvent("storage", {
      key,
      oldValue: current,
      newValue: alternateEncoding,
      url: location.href,
    }));
  }, STORAGE_KEY);
  await expect(page.locator("#status")).toHaveText("Receive address created.");

  releaseSync();
  await expect.poll(() => heldMailboxCompleted).toBe(true);
  await expect(page.locator("#status")).not.toContainText("null pointer");
  await expect(page.locator("#status")).not.toContainText("Blocked:");
  await expect(page.locator("#status")).not.toContainText("Sync warning:");

  await page.locator("#create-receive-address").click();
  await expect(page.locator("#status")).toHaveText("Receive address created.");
  await expect(page.locator("#receive-addresses .address-item")).toHaveCount(2);
});

test("wallet replacement conceals the previously revealed seed", async ({ page }) => {
  const snapshot = blankFixture();
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  await page.locator("#backup-details").click();
  await page.locator("#show-mnemonic").click();
  const originalSeed = (await page.locator("#mnemonic").textContent()).trim();
  expect(originalSeed.split(/\s+/)).toHaveLength(12);

  page.once("dialog", (dialog) => dialog.accept("ERASE"));
  await page.locator("#reset-wallet").click();
  await expect(page.locator("#status")).toHaveText("New wallet created.");
  await expect(page.locator("#mnemonic")).toBeHidden();
  await expect(page.locator("#mnemonic")).toBeEmpty();
  await expect(page.locator("#show-mnemonic")).toHaveText("Reveal");

  await page.locator("#show-mnemonic").click();
  await expect(page.locator("#mnemonic")).toBeVisible();
  await page.locator("#seed-import").fill(originalSeed);
  await page.locator("#seed-import-form button[type=submit]").click();
  await expect(page.locator("#status")).toHaveText("Wallet restored.");
  await expect(page.locator("#mnemonic")).toBeHidden();
  await expect(page.locator("#mnemonic")).toBeEmpty();
  await expect(page.locator("#show-mnemonic")).toHaveText("Reveal");
});


test("onboarding links its funding transaction and counts down confirmations", async ({ page }) => {
  const snapshot = blankFixture();
  const fundingTxid = "42".repeat(32);
  const state = await installWalletHarness(page, {
    snapshot,
    addressUtxos: () => [confirmedUtxo(fundingTxid, 0, 2500)],
    onChain({ request, path }) {
      if (request.method() === "GET" && path === "blocks/tip/height") return "100";
      return undefined;
    },
    onMercury({ request, path }) {
      if (request.method() === "POST" && path === "deposit/init/pod") {
        return {
          body: {
            server_pubkey: generatorPublicKey,
            statechain_id: "deposit-e2e",
          },
        };
      }
      return undefined;
    },
  });
  await loadSnapshot(page, snapshot);

  await page.locator("#deposit-amount").fill("2500");
  await page.locator("#deposit-form button[type=submit]").click();
  await expect(page.locator("#status")).toHaveText("Deposit address created.");
  await expect(page.locator("#pending-deposits .pending-deposit-item")).toHaveCount(1);
  await expect(page.locator(".pending-deposit-address")).toHaveText(/^tb1/);
  await expect(page.locator("#pending-deposits")).toContainText("2,500 sat deposit");
  expect(await page.locator(".pending-deposit-address").evaluate(
    (node) => getComputedStyle(node).color,
  )).toBe("rgb(0, 0, 0)");

  await expect(page.locator("#sync-wallet")).toHaveCount(0);
  await expect(page.locator(".pending-deposit-detail")).toContainText(
    "1 block remaining",
    { timeout: 7_000 },
  );
  await expect(page.locator("#status")).toHaveText("Deposit address created.");
  const fundingLink = page.locator(".pending-deposit-detail a");
  await expect(fundingLink).toHaveText("tx 42424242…2424242");
  await expect(fundingLink).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${fundingTxid}`,
  );

  expect(state.mercuryRequests.some((entry) => entry.path === "deposit/get_token")).toBe(true);
  const init = state.mercuryRequests.find((entry) => entry.path === "deposit/init/pod");
  expect(init.body.token_id).toBe("e2e-token");
  expect(init.body.auth_key).toMatch(/^[0-9a-f]{64}$/);
  expect(init.body.signed_token_id).toMatch(/^[0-9a-f]{128}$/);
  const saved = await storedSnapshot(page);
  expect(saved.pending_deposits[0].token_id).toBe("e2e-token");
  expect(saved.pending_deposits[0].amount).toBe(2500);
  expect(saved.pending_deposits[0].funding_confirmations).toBe(1);
  expect(saved.pending_deposits[0].coin.statechain_id).toBe("deposit-e2e");

  await page.reload();
  await expect(page.locator("#status")).toHaveText("Ready.");
  await expect(page.locator(".pending-deposit-address")).toHaveText(/^tb1/);
  await expect(page.locator(".pending-deposit-detail")).toContainText("1 block remaining");
  await expect(page.locator("#deposit-form button[type=submit]")).toBeEnabled();
});

test("unused deposit addresses stay recoverable in the compact mobile onboard panel", async ({ page }) => {
  const snapshot = blankFixture();
  await page.setViewportSize({ width: 320, height: 568 });
  let depositNumber = 0;
  const state = await installWalletHarness(page, {
    snapshot,
    addressUtxos: () => [],
    onMercury({ request, path }) {
      if (request.method() === "POST" && path === "deposit/init/pod") {
        depositNumber += 1;
        if (depositNumber === 3) {
          return { status: 503, body: "intentional e2e deposit interruption" };
        }
        return {
          body: {
            server_pubkey: generatorPublicKey,
            statechain_id: `pending-deposit-${depositNumber}`,
          },
        };
      }
      return undefined;
    },
  });
  await loadSnapshot(page, snapshot);

  await page.locator("#deposit-amount").fill("2500");
  await page.locator("#deposit-form button[type=submit]").click();
  await expect(page.locator("#pending-deposits .pending-deposit-item")).toHaveCount(1);
  const firstAddress = await page.locator(".pending-deposit-address").textContent();
  await expect(page.locator(".pending-deposit-detail")).toHaveText("Waiting for funding");
  await expect(page.locator("#pending-deposit-select")).toHaveCount(0);
  await expect(page.locator("#cancel-pending-deposit")).toHaveCount(0);
  await expect(page.locator("#deposit-amount")).toBeEnabled();

  await page.locator("#deposit-amount").fill("3500");
  await page.locator("#deposit-form button[type=submit]").click();
  await expect(page.locator("#status")).toHaveText("Deposit address created.");
  await expect(page.locator("#pending-deposits .pending-deposit-item")).toHaveCount(1);
  const depositSelect = page.locator("#pending-deposit-select");
  await expect(depositSelect.locator("option")).toHaveCount(2);
  await expect(depositSelect.locator("option")).toHaveText([
    /^3,500 sats · Waiting for funding · /,
    /^2,500 sats · Waiting for funding · /,
  ]);
  const secondAddress = await page.locator(".pending-deposit-address").textContent();
  expect(secondAddress).not.toBe(firstAddress);
  await expect(page.locator(".pending-deposit-item")).toContainText("3,500 sat deposit");
  await depositSelect.selectOption("pending-deposit-1");
  await expect(page.locator(".pending-deposit-address")).toHaveText(firstAddress);
  await expect(page.locator(".pending-deposit-item")).toContainText("2,500 sat deposit");
  await depositSelect.selectOption("pending-deposit-2");
  await expect(page.locator(".pending-deposit-address")).toHaveText(secondAddress);
  const onboardLayout = await page.evaluate(() => {
    const form = document.querySelector("#deposit-form");
    const create = form.querySelector("button[type=submit]").getBoundingClientRect();
    const faucet = form.querySelector(".button-link").getBoundingClientRect();
    const picker = document.querySelector(".pending-deposit-picker").getBoundingClientRect();
    const select = document.querySelector("#pending-deposit-select").getBoundingClientRect();
    const addressLine = document.querySelector("#pending-deposits .copy-line");
    const address = addressLine.querySelector("code");
    const copy = addressLine.querySelector("button").getBoundingClientRect();
    return {
      pageFits: document.documentElement.scrollWidth <= window.innerWidth,
      formFits: form.scrollWidth <= form.clientWidth,
      buttonsShareRow: Math.abs(create.top - faucet.top) < 1 && create.right <= faucet.left,
      pickerIsStacked: select.top > picker.top && Math.abs(select.width - picker.width) < 1,
      addressLineFits: addressLine.scrollWidth <= addressLine.clientWidth,
      addressIsSingleLine: getComputedStyle(address).whiteSpace === "nowrap",
      addressLineHeight: addressLine.getBoundingClientRect().height,
      copyHeight: copy.height,
    };
  });
  expect(onboardLayout).toMatchObject({
    pageFits: true,
    formFits: true,
    buttonsShareRow: true,
    pickerIsStacked: true,
    addressLineFits: true,
    addressIsSingleLine: true,
  });
  expect(onboardLayout.addressLineHeight).toBeLessThanOrEqual(40);
  expect(onboardLayout.copyHeight).toBeLessThanOrEqual(40);

  await page.locator("#deposit-amount").fill("4500");
  await page.locator("#deposit-form button[type=submit]").click();
  await expect(page.locator("#status")).toContainText("intentional e2e deposit interruption");
  await expect(depositSelect.locator("option")).toHaveCount(3);
  await expect(depositSelect).toHaveValue("incomplete");
  await expect(depositSelect.locator("option:checked")).toContainText(
    "Request interrupted · retry available",
  );
  await expect(page.locator(".pending-deposit-item")).toContainText("4,500 sat deposit");
  await expect(page.locator(".pending-deposit-detail")).toHaveText(
    "Request interrupted · retry available",
  );

  await depositSelect.focus();
  await page.keyboard.press("ArrowDown");
  await expect(depositSelect).toBeFocused();
  await expect(depositSelect).toHaveValue("pending-deposit-2");
  await expect(page.locator(".pending-deposit-address")).toHaveText(secondAddress);
  await page.keyboard.press("ArrowDown");
  await expect(depositSelect).toBeFocused();
  await expect(depositSelect).toHaveValue("pending-deposit-1");
  await expect(page.locator(".pending-deposit-address")).toHaveText(firstAddress);
  expect(state.completions).toHaveLength(0);

  const saved = await storedSnapshot(page);
  expect(saved.pending_deposits).toHaveLength(3);
  expect(saved.pending_deposits.map((pending) => pending.amount)).toEqual([2500, 3500, 4500]);
  expect(saved.pending_deposits.map((pending) => pending.coin.index)).toEqual([0, 1, 2]);

  await page.reload();
  await expect(page.locator("#pending-deposit-select option")).toHaveCount(3);
  await expect(page.locator("#pending-deposits .pending-deposit-item")).toHaveCount(1);
  await expect(page.locator("#pending-deposit-select")).toHaveValue("incomplete");
  await expect(page.locator("#pending-deposit-select option:checked")).toContainText(
    "Request interrupted · retry available",
  );
  await expect(page.locator(".pending-deposit-detail")).toHaveText(
    "Request interrupted · retry available",
  );
  await page.locator("#pending-deposit-select").selectOption("pending-deposit-2");
  await expect(page.locator(".pending-deposit-address")).toHaveText(secondAddress);
});

test("deposit halts when the enclave does not hold the advertised share", async ({ page }) => {
  const snapshot = blankFixture();
  const state = await installWalletHarness(page, {
    snapshot,
    enclaveServerPubkey: "02" + "22".repeat(32),
    onMercury({ request, path }) {
      if (request.method() === "POST" && path === "deposit/init/pod") {
        return {
          body: {
            server_pubkey: generatorPublicKey,
            statechain_id: "unattested-deposit",
          },
        };
      }
    },
  });
  await loadSnapshot(page, snapshot);

  await page.locator("#deposit-amount").fill("2500");
  await page.locator("#deposit-form button[type=submit]").click();
  await expect(page.locator("#status")).toContainText(
    "server share the signing enclave does not hold",
  );
  expect(state.enclaveRequests.some((entry) => entry.path === "verify_statechain")).toBe(true);
  const saved = await storedSnapshot(page);
  expect(saved.pending_deposits[0].coin.statechain_id).toBeNull();
  expect(saved.pending_deposits[0].coin.aggregated_address).toBeNull();
});

test("receive lists each one-time address exactly once on mobile", async ({ page }) => {
  const snapshot = blankFixture();
  await page.setViewportSize({ width: 390, height: 844 });
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);
  await expect(page.locator("#receive-auto-note")).toHaveText(
    "Incoming transfers appear automatically while this wallet is open.",
  );

  await page.locator("#create-receive-address").click();
  await expect(page.locator("#status")).toHaveText("Receive address created.");
  await expect(page.locator("#receive-addresses .address-item")).toHaveCount(1);
  const firstAddress = await page.locator("#receive-addresses .address-item code").textContent();
  expect(firstAddress).toMatch(/^tml1/);
  await expect(page.locator("#receive-addresses code", { hasText: firstAddress })).toHaveCount(1);

  await page.locator("#create-receive-address").click();
  await expect(page.locator("#receive-addresses .address-item")).toHaveCount(2);
  const addresses = await page.locator("#receive-addresses .address-item code").allTextContents();
  expect(new Set(addresses).size).toBe(2);
  for (const address of addresses) {
    await expect(page.locator("#receive-addresses code", { hasText: address })).toHaveCount(1);
  }

  await expect(page.locator("#create-receive-address")).toHaveText("New receive address");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  const saved = await storedSnapshot(page);
  expect(saved.wallet.coins).toHaveLength(2);
  expect(saved.wallet.coins.every((coin) => coin.status === "INITIALISED")).toBe(true);
  await page.reload();
  await expect(page.locator("#receive-addresses .address-item")).toHaveCount(2);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("offboard selector renders details for only the selected coin", async ({ page }) => {
  const snapshot = clone(recoveryFixture);
  const secondCoin = clone(snapshot.wallet.coins[0]);
  secondCoin.statechain_id = "statechain-two";
  secondCoin.index = 1;
  snapshot.wallet.coins.push(secondCoin);
  const secondRecord = clone(snapshot.statechains[0]);
  secondRecord.statechain_id = "statechain-two";
  snapshot.statechains.push(secondRecord);
  snapshot.state_histories["statechain-two"] = clone(snapshot.state_histories.statechain);

  await page.setViewportSize({ width: 390, height: 844 });
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  const select = page.locator("#offboard-statechain-id");
  await expect(select.locator("option")).toHaveCount(2);
  await expect(page.locator("#coins .coin-card")).toHaveCount(1);
  await expect(page.locator("#coins .coin-id")).toHaveText("statechain");
  await select.selectOption("statechain-two");
  await expect(page.locator("#coins .coin-card")).toHaveCount(1);
  await expect(page.locator("#coins .coin-id")).toHaveText("statechain-two");
  const selectStyle = await select.evaluate((node) => {
    const style = getComputedStyle(node);
    return {
      appearance: style.appearance,
      backgroundImage: style.backgroundImage,
      fontSize: style.fontSize,
    };
  });
  expect(selectStyle.appearance).toBe("none");
  expect(selectStyle.backgroundImage).not.toBe("none");
  expect(selectStyle.fontSize).toBe("12px");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.locator(".cooperative-withdrawal > summary").click();
  await page.locator(".unilateral-exit > summary").click();
  const offboardLayout = await page.evaluate(() => {
    const actions = document.querySelector(".coin-actions");
    const cooperative = document.querySelector(".cooperative-withdrawal");
    const unilateral = document.querySelector(".unilateral-exit");
    return {
      actionsWidth: actions.getBoundingClientRect().width,
      actionsScrollWidth: actions.scrollWidth,
      cooperativeWidth: cooperative.getBoundingClientRect().width,
      unilateralWidth: unilateral.getBoundingClientRect().width,
      pageFits: document.documentElement.scrollWidth <= window.innerWidth,
    };
  });
  expect(offboardLayout.pageFits).toBe(true);
  expect(offboardLayout.actionsScrollWidth).toBeLessThanOrEqual(offboardLayout.actionsWidth);
  expect(offboardLayout.cooperativeWidth).toBe(offboardLayout.actionsWidth);
  expect(offboardLayout.unilateralWidth).toBe(offboardLayout.actionsWidth);

  const mobileSession = await page.context().newCDPSession(page);
  await mobileSession.send("Emulation.setDeviceMetricsOverride", {
    width: 844,
    height: 390,
    deviceScaleFactor: 3,
    mobile: true,
  });
  await mobileSession.send("Emulation.setTouchEmulationEnabled", {
    enabled: true,
    maxTouchPoints: 5,
  });
  await expect(page.locator(".withdraw-address")).toHaveCSS("font-size", "16px");
  await page.locator(".withdraw-address").focus();
  expect(await page.evaluate(() => visualViewport.scale)).toBe(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
    .toBe(true);
  await mobileSession.detach();
});
test("direct enclave verification renders and persists the current runtime", async ({ page }) => {
  const snapshot = blankFixture();
  snapshot.enclave_runtime_proof = {
    verificationMethod: "browser-direct-enclavia-sdk-v1",
    checkedAt: "2026-01-01T00:00:00.000Z",
    endpoint: snapshot.deployment.enclaviaProxyUrl.replace("https://", "wss://"),
    mode: "production",
    pcr0: snapshot.deployment.expectedPcr0,
    pcr1: snapshot.deployment.expectedPcr1,
    pcr2: snapshot.deployment.expectedPcr2,
    authentication: "attested Noise",
    trustModel: "Browser established a direct Enclavia SDK Noise channel with production Nitro PCR measurements.",
  };
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  await expect(page.locator("#enclave-summary-status")).toHaveText("Verified · production");
  await page.locator("#enclave-details").click();
  await expect(page.locator("#enclave-verification-status")).toHaveText(
    "Verified directly · production.",
  );
  await expect(page.locator("#enclave-endpoint")).toHaveText(
    snapshot.deployment.enclaviaProxyUrl.replace("https://", "wss://"),
  );
  await expect(page.locator("#enclave-authentication")).toHaveText("attested Noise");
  await expect(page.locator("#enclave-pcr0")).toHaveText(snapshot.deployment.expectedPcr0);
  await expect(page.locator("#enclave-trust")).toContainText("direct Enclavia SDK Noise channel");

  await page.reload();
  await expect(page.locator("#enclave-summary-status")).toHaveText("Verified · production");
  await page.locator("#enclave-details").click();
  await expect(page.locator("#enclave-proof")).toBeVisible();
});

test("legacy Mercury relay proofs are never relabeled as direct verification", async ({ page }) => {
  const snapshot = blankFixture();
  snapshot.enclave_runtime_proof = {
    checkedAt: "2026-01-01T00:00:00.000Z",
    endpoint: snapshot.deployment.enclaviaProxyUrl.replace("https://", "wss://"),
    mode: "production",
    pcr0: snapshot.deployment.expectedPcr0,
    pcr1: snapshot.deployment.expectedPcr1,
    pcr2: snapshot.deployment.expectedPcr2,
    authentication: "bearer",
    trustModel: "Verified by Mercury.",
  };
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  await expect(page.locator("#enclave-summary-status")).toHaveText("Not checked");
  await page.locator("#enclave-details").click();
  await expect(page.locator("#enclave-verification-status")).toHaveText("Not checked.");
  await expect(page.locator("#enclave-proof")).toBeHidden();
});

test("persisted direct coin proof displays the attested server share", async ({ page }) => {
  const snapshot = clone(recoveryFixture);
  const coin = snapshot.wallet.coins[0];
  snapshot.enclave_verification = {
    verificationMethod: "browser-direct-enclavia-sdk-v1",
    statechainId: coin.statechain_id,
    verifiedAt: "2026-01-01T00:00:00.000Z",
    challenge: "ab".repeat(32),
    serverPubkey: coin.server_pubkey,
    pcr0: snapshot.deployment.expectedPcr0,
    pcr1: snapshot.deployment.expectedPcr1,
    pcr2: snapshot.deployment.expectedPcr2,
    trustModel: "Browser-direct Enclavia SDK proof; Mercury cannot read or forge the exchange.",
  };
  await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  await page.locator(".coin-enclave > summary").click();
  await expect(page.locator(".coin-enclave-status")).toHaveText("Verified");
  await expect(page.locator(".verify-coin-enclave")).toHaveText("Verified");
  await expect(page.locator(".verify-coin-enclave")).toBeDisabled();
  await expect(page.locator(".coin-enclave-result")).toHaveText(
    "Verified: server share and PCRs match.",
  );
  await expect(page.locator(".coin-enclave-server-pubkey")).toHaveText(coin.server_pubkey);
  await expect(page.locator(".coin-enclave-pcr0")).toHaveText(snapshot.deployment.expectedPcr0);
  await expect(page.locator(".coin-enclave-challenge")).toHaveText("ab".repeat(32));
  await expect(page.locator(".coin-enclave-trust")).toContainText(
    "Mercury cannot read or forge",
  );

  await page.reload();
  await page.locator(".coin-enclave > summary").click();
  await expect(page.locator(".coin-enclave-proof")).toBeVisible();
  await expect(page.locator(".coin-enclave-status")).toHaveText("Verified");
  await expect(page.locator(".verify-coin-enclave")).toHaveText("Verified");
  await expect(page.locator(".verify-coin-enclave")).toBeDisabled();
});


test("send journals the recipient and resumes after interruption", async ({ page }) => {
  const snapshot = clone(recoveryFixture);
  const state = await installWalletHarness(page, { snapshot });
  await loadSnapshot(page, snapshot);

  await page.locator("#create-receive-address").click();
  await expect(page.locator("#receive-addresses .address-item code")).toHaveText(/^tml1/);
  const recipient = await page.locator("#receive-addresses .address-item code").textContent();
  await page.locator("#send-statecoin-address").fill(recipient);
  await page.locator("#send-statecoin").click();

  await expect(page.locator("#status")).toContainText("intentional e2e signing boundary");
  await expect(page.locator("#pending-transfer")).toBeVisible();
  await expect(page.locator("#pending-transfer-recipient")).toHaveText(recipient);
  await expect(page.locator("#cancel-transfer")).toBeVisible();
  await expect(page.locator("#cancel-transfer")).toHaveText("Cancel transfer");
  const senderInit = state.mercuryRequests.find((entry) => entry.path === "transfer/sender");
  expect(senderInit.body.statechain_id).toBe("statechain");
  expect(senderInit.body.batch_id).toBeNull();

  const saved = await storedSnapshot(page);
  expect(saved.pending_outgoing_transfer.recipient_address).toBe(recipient);
  expect(saved.pending_outgoing_transfer.batch_id).toBeNull();
  expect(saved.pending_outgoing_transfer.acknowledge_cooperative_duplicates).toBe(false);
  expect(saved.pending_outgoing_transfer.x1).toBe("09".repeat(32));
  expect(saved.pending_outgoing_transfer.delivered).toBe(false);

  await page.reload();
  await expect(page.locator("#send-statecoin-address")).toHaveValue(recipient);
  await expect(page.locator("#send-statecoin")).toHaveText("Retry send");

  const pending = saved.pending_outgoing_transfer;
  const record = saved.statechains[0];
  const nextHistory = clone(saved.state_histories.statechain.at(-1));
  nextHistory.state_number = record.latest_state_number + 1;
  nextHistory.owner_public_key = pending.receiver_user_pubkey.slice(2);
  pending.message = {
    msg_version: 1,
    statechain_id: pending.statechain_id,
    transfer_signature: "00".repeat(64),
    sender_user_public_key: saved.wallet.coins[0].user_pubkey,
    receiver_user_public_key: pending.receiver_user_pubkey,
    server_public_key: saved.wallet.coins[0].server_pubkey,
    aggregate_pubkey: record.aggregate_pubkey,
    funding_outpoint: record.funding_outpoint,
    latest_state_number: record.latest_state_number + 1,
    challenge_delay: record.challenge_delay,
    amount_sats: record.amount_sats,
    network: record.network,
    value_schedule: record.latest_state.value_schedule,
    latest_state: record.latest_state,
    server_signature_count: record.latest_state_number + 1,
    t1: Array(32).fill(1),
    state_history: [...saved.state_histories.statechain, nextHistory],
  };
  pending.encrypted_message = "00";
  pending.delivered = true;
  saved.wallet.coins[0].status = "IN_TRANSFER";
  await loadSnapshot(page, saved);
  await expect(page.locator("#pending-transfer-title")).toHaveText("Statecoin sent");
  await expect(page.locator("#pending-transfer-detail")).toContainText(
    "Sent · completes when recipient wallet syncs",
  );
  await expect(page.locator("#cancel-transfer")).toBeHidden();
});

test("cooperative withdrawal preserves its irreversible signing journal", async ({ page }) => {
  const snapshot = clone(recoveryFixture);
  const coin = snapshot.wallet.coins[0];
  await installWalletHarness(page, {
    snapshot,
    addressUtxos(address) {
      return address === coin.aggregated_address
        ? [confirmedUtxo(coin.utxo_txid, coin.utxo_vout, coin.amount)]
        : [];
    },
  });
  await loadSnapshot(page, snapshot);

  const destination = await page.locator(".fee-address").textContent();
  await page.locator(".cooperative-withdrawal > summary").click();
  await page.locator(".withdraw-address").fill(destination);
  await expect(page.locator(".withdraw-fee")).toHaveAttribute("min", "0.1");
  await expect(page.locator(".withdraw-fee")).toHaveValue("0.1");
  await page.locator(".withdraw-statecoin").click();

  await expect(page.locator("#status")).toContainText("intentional e2e signing boundary");
  await expect(page.locator(".withdrawal-detail")).toContainText("prepared · not broadcast");
  await expect(page.locator(".withdraw-statecoin")).toHaveText("Resume withdrawal");
  const saved = await storedSnapshot(page);
  expect(saved.withdrawal_attempts).toHaveLength(1);
  expect(saved.withdrawal_attempts[0].kind).toBe("canonical");
  expect(saved.withdrawal_attempts[0].phase).toBe("prepared");
  expect(saved.withdrawal_attempts[0].destinationAddress).toBe(destination);
  expect(saved.withdrawal_attempts[0].feeRateSatPerVbyte).toBe(0.1);

  await page.reload();
  await page.locator(".cooperative-withdrawal > summary").click();
  await expect(page.locator(".withdraw-address")).toHaveValue(destination);
  await expect(page.locator(".withdraw-statecoin")).toHaveText("Resume withdrawal");
});

test("extra deposits remain recoverable before cooperative withdrawal", async ({ page }) => {
  const snapshot = clone(recoveryFixture);
  const coin = snapshot.wallet.coins[0];
  const duplicateTxid = "0e".repeat(32);
  snapshot.funding_bindings.push({
    ...snapshot.funding_bindings[0],
    bindingIndex: 1,
    txid: duplicateTxid,
    vout: 1,
    valueSats: 25_000,
  });
  await installWalletHarness(page, {
    snapshot,
    addressUtxos(address) {
      return address === coin.aggregated_address
        ? [
          confirmedUtxo(coin.utxo_txid, coin.utxo_vout, coin.amount),
          confirmedUtxo(duplicateTxid, 1, 25_000),
        ]
        : [];
    },
  });
  await loadSnapshot(page, snapshot);

  await page.locator(".cooperative-withdrawal > summary").click();
  await expect(page.locator(".withdraw-statecoin")).toBeDisabled();
  await page.locator(".duplicates-panel > summary").click();
  await expect(page.locator(".duplicate-row")).toHaveCount(1);
  await expect(page.locator(".duplicate-row")).toContainText("Extra deposit 1 · 25,000 sats");
  const destination = await page.locator(".fee-address").textContent();
  await page.locator(".duplicate-address").fill(destination);
  await expect(page.locator(".duplicate-fee")).toHaveAttribute("min", "0.1");
  await expect(page.locator(".duplicate-fee")).toHaveValue("0.1");
  await page.locator(".sweep-duplicate").click();

  await expect(page.locator("#status")).toContainText("intentional e2e signing boundary");
  await expect(page.locator(".sweep-duplicate")).toHaveText("Resume sweep");
  const saved = await storedSnapshot(page);
  expect(saved.withdrawal_attempts).toHaveLength(1);
  expect(saved.withdrawal_attempts[0].kind).toBe("duplicate");
  expect(saved.withdrawal_attempts[0].bindingIndex).toBe(1);
  expect(saved.withdrawal_attempts[0].sourceTxid).toBe(duplicateTxid);
});
