import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { installWalletHarness, loadSnapshot, storedSnapshot } from "./support/wallet-harness.js";

const fixturePath = fileURLToPath(new URL("../fixtures/recovery-ready.json", import.meta.url));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const coin = fixture.wallet.coins[0];
const feeTxids = ["02".repeat(32), "03".repeat(32)];

function confirmedUtxo(txid, vout, value) {
  return { txid, vout, value, status: { confirmed: true, block_height: 90 } };
}

async function downloadHex(page, selector, expectedFilename) {
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator(selector).click(),
  ]);
  expect(download.suggestedFilename()).toBe(expectedFilename);
  return readFileSync(await download.path(), "utf8").trim();
}

test("unilateral exit broadcasts both durable recovery packages", async ({ page }) => {
  let settlementFeeAvailable = false;
  const state = await installWalletHarness(page, {
    snapshot: fixture,
    addressUtxos(address, harness) {
      if (address === coin.aggregated_address) {
        return [confirmedUtxo(coin.utxo_txid, coin.utxo_vout, coin.amount)];
      }
      if (harness.packages.length === 0) {
        return [confirmedUtxo(feeTxids[0], 0, 10_000)];
      }
      return settlementFeeAvailable
        ? [confirmedUtxo(feeTxids[1], 1, 10_000)]
        : [];
    },
    transactionStatus(_txid, harness) {
      return harness.mature
        ? { confirmed: true, block_height: 100 }
        : { confirmed: false };
    },
  });
  await loadSnapshot(page, fixture);

  await expect(page).toHaveTitle("BIP448 Mercury Layer wallet");
  await expect(page.locator(".coin-card")).toHaveCount(1);
  await expect(page.locator("#wallet-balance")).toHaveText("50,000 sats");
  await page.locator(".unilateral-exit > summary").click();
  await expect(page.locator(".fee-address")).toContainText("tb1");
  expect(await downloadHex(page, ".download-update", "bip448-statechain-update.hex")).toBe(
    fixture.statechains[0].latest_state.update_tx,
  );
  expect(
    await downloadHex(page, ".download-settlement", "bip448-statechain-settlement.hex"),
  ).toBe(fixture.statechains[0].latest_state.settlement_tx);
  await expect(page.locator("#status")).toHaveText("Raw transaction downloaded.");

  const update = page.locator(".broadcast-update");
  const settlement = page.locator(".broadcast-settlement");
  const updateFee = page.locator(".update-fee");
  const settlementFee = page.locator(".settlement-fee");
  await expect(updateFee).toHaveAttribute("min", "0.1");
  await expect(settlementFee).toHaveAttribute("min", "0.1");
  await expect(updateFee).toHaveValue("0.1");
  await expect(settlementFee).toHaveValue("0.1");
  await expect(update).toBeEnabled();
  await expect(settlement).toBeDisabled();
  await expect(page.locator(".recovery-fee-detail")).toHaveText(
    "Fund this address. Waiting for confirmation.",
  );

  await expect(page.locator(".recovery-fee-detail")).toContainText(
    "10,000 sats · ready",
    { timeout: 7_000 },
  );
  await expect(page.locator("#status")).toHaveText("Raw transaction downloaded.");
  await expect(page.locator(".recovery-fee-detail a")).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${feeTxids[0]}`,
  );
  await expect(update).toBeEnabled();

  await update.click();
  await expect(page.locator("#status")).toContainText(
    "Update package broadcast. Parent txid:",
  );
  const storedAfterUpdate = await storedSnapshot(page);
  const updateAttempt = storedAfterUpdate.recovery_attempts.find(
    (attempt) => attempt.role === "funding_update",
  );
  await expect(page.locator("#status")).toHaveText(
    `Update package broadcast. Parent txid: ${updateAttempt.parentTxid}. Fee child txid: ${updateAttempt.childTxid}.`,
  );
  expect(state.packages).toHaveLength(1);
  expect(state.packages[0]).toHaveLength(2);
  expect(state.packages[0][0]).toMatch(/^03000000/);
  await expect(update).toHaveText("Rebroadcast update");
  await expect(page.locator(".update-detail a").nth(0)).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${updateAttempt.parentTxid}`,
  );
  await expect(page.locator(".update-detail a").nth(1)).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${updateAttempt.childTxid}`,
  );
  await expect(settlement).toBeEnabled();
  await expect(settlement).toHaveText("Check settlement");
  await expect(page.locator(".coin-status")).toHaveText("WITHDRAWING");
  await expect(page.locator(".coin-alert")).toHaveText("Exit in progress.");
  await expect(page.locator(".coin-alert")).toBeVisible();

  state.mature = true;
  await expect(page.locator(".wait-detail")).toHaveText("144 blocks remaining.");
  await expect(settlement).toBeEnabled();

  await settlement.click();
  await expect(page.locator("#status")).toContainText(
    "Error: fund the confirmed recovery-fee address",
  );
  await expect(page.locator(".settlement-detail")).toContainText(
    "Error: fund the confirmed recovery-fee address",
  );
  await expect(page.locator(".wait-detail")).toHaveText("Delay complete.");
  await expect(page.locator(".recovery-fee-detail")).toHaveText(
    "Fund this address. Waiting for confirmation.",
  );
  await expect(update).toBeDisabled();
  await expect(update).toHaveText("Update confirmed");
  expect(state.packages).toHaveLength(1);

  settlementFeeAvailable = true;
  await settlement.click();
  await expect(page.locator("#status")).toContainText(
    "Settlement package broadcast. Parent txid:",
  );
  const storedAfterSettlement = await storedSnapshot(page);
  const settlementAttempt = storedAfterSettlement.recovery_attempts.find(
    (attempt) => attempt.role === "settlement",
  );
  await expect(page.locator("#status")).toHaveText(
    `Settlement package broadcast. Parent txid: ${settlementAttempt.parentTxid}. Fee child txid: ${settlementAttempt.childTxid}.`,
  );
  expect(state.packages).toHaveLength(2);
  expect(state.packages[1]).toHaveLength(2);
  expect(state.packages[1][0]).toMatch(/^03000000/);
  expect(state.packages[1][0]).not.toBe(state.packages[0][0]);
  await expect(page.locator(".coin-status")).toHaveText("WITHDRAWING");
  await expect(settlement).toBeEnabled();
  await expect(settlement).toHaveText("Rebroadcast settlement");
  await expect(page.locator(".settlement-detail a").nth(0)).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${settlementAttempt.parentTxid}`,
  );
  await expect(page.locator(".settlement-detail a").nth(1)).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${settlementAttempt.childTxid}`,
  );

  await expect(page.locator(".coin-status")).toHaveText("WITHDRAWN", { timeout: 7_000 });
  await expect(page.locator("#wallet-balance")).toHaveText("0 sats");
  await expect(page.locator("#wallet-coin-count")).toHaveText("0");
  await expect(update).toBeDisabled();
  await expect(settlement).toBeDisabled();
  await expect(settlement).toHaveText("Settlement confirmed");
  await expect(page.locator(".coin-alert")).toBeHidden();
  await expect(page.locator("#offboard-statechain-id option:checked")).toContainText("WITHDRAWN");
  await expect(page.locator(".coin-card")).not.toHaveAttribute("open", "");
  await expect(page.locator(".coin-id-row")).toBeHidden();
  await page.locator(".coin-card > .coin-header").click();
  await expect(page.locator(".coin-id-row")).toBeVisible();
  await expect(page.locator(".coin-alert")).toHaveClass(/hidden/);

  await page.reload();
  await expect(page.locator("#status")).toHaveText("Ready.");
  await expect(page.locator(".coin-card")).not.toHaveAttribute("open", "");
  await page.locator(".coin-card > .coin-header").click();
  await expect(page.locator(".coin-alert")).toHaveClass(/hidden/);
  await page.locator(".unilateral-exit > summary").click();
  await expect(page.locator(".update-detail")).toContainText("confirmed");
  await expect(page.locator(".settlement-detail")).toContainText("confirmed");
});

test("unconfirmed fee funding links its transaction and blocks broadcast with feedback", async ({ page }) => {
  const feeTxid = "04".repeat(32);
  await installWalletHarness(page, {
    snapshot: fixture,
    addressUtxos(address) {
      if (address === coin.aggregated_address) {
        return [confirmedUtxo(coin.utxo_txid, coin.utxo_vout, coin.amount)];
      }
      return [{
        txid: feeTxid,
        vout: 0,
        value: 10_000,
        status: { confirmed: false, block_height: null },
      }];
    },
  });
  await loadSnapshot(page, fixture);
  await page.locator(".unilateral-exit > summary").click();

  await expect(page.locator(".recovery-fee-detail")).toContainText(
    "10,000 sats · 1 block remaining",
    { timeout: 7_000 },
  );
  await expect(page.locator(".recovery-fee-detail a")).toHaveAttribute(
    "href",
    `https://mutinynet.com/tx/${feeTxid}`,
  );
  const update = page.locator(".broadcast-update");
  await expect(update).toBeEnabled();
  await update.click();
  await expect(page.locator("#status")).toContainText(
    "Error: fund the confirmed recovery-fee address",
  );
  await expect(page.locator(".update-detail")).toContainText(
    "Error: fund the confirmed recovery-fee address",
  );
});
