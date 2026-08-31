import init, { MercuryWallet } from "./pkg/mercury_web_wallet.js";

const STORAGE_PREFIX = "mercury-bip448-mutinynet-browser-wallet-";
const STORAGE_KEY = `${STORAGE_PREFIX}v1`;

let wallet = null;
let storageRevision = null;
let busy = false;
let syncPromise = null;
let pollTimer = null;
let nextFullSyncAt = 0;
let wasmReady = false;
let runtimeProblem = null;
const coinDrafts = new Map();
const recoveryFeedback = new Map();
let selectedPendingDepositKey = null;
const TRANSFER_SYNC_INTERVAL_MS = 1_000;
const FULL_SYNC_INTERVAL_MS = 5_000;
const SENT_TRANSFER_STATUS = "Sent · completes when recipient wallet syncs";
const TERMINAL_COIN_STATUSES = new Set(["WITHDRAWN", "TRANSFERRED"]);

const byId = (id) => document.getElementById(id);
const statusNode = byId("status");
const coinsNode = byId("coins");
const coinTemplate = byId("coin-template");

class StorageFailure extends Error {}
class StaleCommand extends Error {}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function setStatus(message, state = "ready") {
  statusNode.textContent = message;
  statusNode.className = `status ${state}`;
}

function readStoredSnapshot() {
  return localStorage.getItem(STORAGE_KEY);
}

function writeStoredSnapshot(snapshot, expected) {
  const current = readStoredSnapshot();
  if (current !== expected) {
    throw new StaleCommand("wallet storage changed in another tab");
  }
  localStorage.setItem(STORAGE_KEY, snapshot);
  if (readStoredSnapshot() !== snapshot) {
    throw new StorageFailure("browser storage did not retain the wallet snapshot");
  }
  storageRevision = snapshot;
}
function removeObsoleteStoredWallets() {
  for (let index = localStorage.length - 1; index >= 0; index -= 1) {
    const key = localStorage.key(index);
    if (key?.startsWith(STORAGE_PREFIX) && key !== STORAGE_KEY) {
      localStorage.removeItem(key);
    }
  }
}



function loadRevision(revision) {
  if (!revision) {
    wallet = null;
    storageRevision = null;
    return;
  }
  wallet = MercuryWallet.fromSnapshot(revision);
  storageRevision = revision;
}

async function withWalletLock(callback, options = {}) {
  if (!navigator.locks?.request) {
    throw new Error("Web Locks are required for wallet mutations");
  }
  return navigator.locks.request(
    STORAGE_KEY,
    { ...options, mode: "exclusive" },
    callback,
  );
}

async function executeWalletOperation(operation, lockOptions = {}) {
  return withWalletLock(async (lock) => {
    if (!lock) return null;
    const live = readStoredSnapshot();
    if (live !== storageRevision) loadRevision(live);
    if (!wallet) throw new Error("no browser wallet is loaded");
    const baseRevision = storageRevision;
    const outcome = await operation(wallet);
    const stored = readStoredSnapshot();
    storageRevision = stored;
    return { outcome, changed: stored !== baseRevision };
  }, lockOptions);
}

async function run(label, operation, {
  slowLabel = null,
  slowAfterMs = 3_000,
} = {}) {
  if (busy || runtimeProblem) return false;
  if (syncPromise) await syncPromise;
  if (busy || runtimeProblem) return false;
  busy = true;
  setStatus(`Working: ${label}…`, "busy");
  setDisabled(true);
  const startedAt = performance.now();
  let slowTimer = null;
  let elapsedTimer = null;
  if (slowLabel) {
    const updateSlowStatus = () => {
      const elapsedSeconds = Math.max(1, Math.floor((performance.now() - startedAt) / 1_000));
      setStatus(`Still working (${elapsedSeconds}s): ${slowLabel}`, "busy");
    };
    slowTimer = window.setTimeout(() => {
      updateSlowStatus();
      elapsedTimer = window.setInterval(updateSlowStatus, 1_000);
    }, slowAfterMs);
  }
  try {
    const command = await executeWalletOperation(operation);
    const outcome = command.outcome;
    render();
    setStatus(outcome?.message || `${label} complete.`, outcome?.state || "ready");
    return true;
  } catch (error) {
    try {
      loadRevision(readStoredSnapshot());
    } catch (restoreError) {
      runtimeProblem = errorMessage(restoreError);
    }
    render();
    setStatus(`Error: ${errorMessage(error)}`, "error");
    console.error(error);
    return false;
  } finally {
    if (slowTimer !== null) window.clearTimeout(slowTimer);
    if (elapsedTimer !== null) window.clearInterval(elapsedTimer);
    busy = false;
    setDisabled(false);
    render();
  }
}


function syncWallet({
  ifAvailable = false,
  transfersOnly = false,
} = {}) {
  if (busy || syncPromise || runtimeProblem || !wallet) return Promise.resolve(false);
  const commandPromise = executeWalletOperation(async (activeWallet) => {
    const result = transfersOnly
      ? await activeWallet.syncTransfers()
      : await activeWallet.syncWallet();
    return result.warnings;
  }, ifAvailable ? { ifAvailable: true } : {});

  syncPromise = (async () => {
    try {
      const command = await commandPromise;
      if (!command) return false;
      if (!transfersOnly) nextFullSyncAt = Date.now() + FULL_SYNC_INTERVAL_MS;
      if (command.changed) render();
      if (command.outcome.length) {
        console.warn(`Wallet sync warning: ${command.outcome.join("; ")}`);
      }
      return true;
    } catch (error) {
      try {
        loadRevision(readStoredSnapshot());
      } catch (restoreError) {
        runtimeProblem = errorMessage(restoreError);
      }
      render();
      if (runtimeProblem) {
        setDisabled(false);
        setStatus(`Blocked: ${runtimeProblem}`, "error");
      }
      console.warn("Background wallet sync failed:", error);
      return false;
    } finally {
      syncPromise = null;
    }
  })();
  return syncPromise;
}

function view() {
  if (!wallet) return null;
  return wallet.view();
}

function setDisabled(disabled) {
  document.querySelectorAll("button, input, textarea, select").forEach((element) => {
    element.disabled = !element.hasAttribute("data-always-enabled")
      && (disabled || Boolean(runtimeProblem));
  });
}

function captureCoinUiState() {
  const states = new Map();
  for (const card of coinsNode.querySelectorAll(".coin-card")) {
    const statechainId = card.dataset.statechainId;
    states.set(statechainId, {
      open: card.open,
      status: card.querySelector(".coin-status")?.textContent ?? "",
      panels: new Set(
        [...card.querySelectorAll("details[open]")]
          .map((details) => [...details.classList].sort().join(".")),
      ),
    });
    for (const input of card.querySelectorAll("[data-draft]")) {
      coinDrafts.set(`${statechainId}:${input.dataset.draft}`, input.value);
    }
  }
  return states;
}

function activeCoinBalance(current) {
  return current.coins
    .filter((coin) => !TERMINAL_COIN_STATUSES.has(coin.status))
    .reduce((total, coin) => total + coin.amount, 0);
}


function render() {
  const current = view();
  if (!current) return;
  const coinUiStates = captureCoinUiState();

  const activeCoins = current.coins.filter(
    (coin) => !TERMINAL_COIN_STATUSES.has(coin.status),
  );
  byId("wallet-balance").textContent = `${activeCoinBalance(current).toLocaleString()} sats`;
  byId("wallet-coin-count").textContent = String(activeCoins.length);

  renderDeposit(current);
  renderSendStatecoin(current);
  renderReceiveAddresses(current);
  renderEnclave(current);

  renderOffboard(current, coinUiStates);
}

function renderOffboard(current, coinUiStates) {
  const select = byId("offboard-statechain-id");
  const previousSelection = select.value;
  select.replaceChildren();

  for (const coin of current.coins) {
    const option = document.createElement("option");
    option.value = coin.statechainId;
    option.textContent =
      `${coin.amount.toLocaleString()} sats · ${shortId(coin.statechainId)} · ${coin.status}`;
    select.append(option);
  }

  const selected = current.coins.find((coin) => coin.statechainId === previousSelection)
    ?? current.coins.find((coin) => !TERMINAL_COIN_STATUSES.has(coin.status))
    ?? current.coins[0];
  if (selected) select.value = selected.statechainId;

  byId("offboard-coin-picker").classList.toggle("hidden", !selected);
  byId("coins-empty").classList.toggle("hidden", Boolean(selected));
  coinsNode.replaceChildren();
  if (selected) {
    coinsNode.append(renderCoin(
      selected,
      current,
      coinUiStates.get(selected.statechainId),
    ));
  }
  select.disabled = busy || !selected || Boolean(runtimeProblem);
}

function pendingDepositKey(pending) {
  return pending.statechainId || pending.address || "incomplete";
}

function pendingDepositStatus(pending) {
  if (!pending.statechainId) return "Request interrupted · retry available";
  if (pending.signingStarted) return "Funding confirmed · finalizing";
  if (!pending.fundingTxid) return "Waiting for funding";
  const remaining = pending.confirmationBlocksRemaining;
  return remaining > 0
    ? `${remaining} block${remaining === 1 ? "" : "s"} remaining`
    : "Funding confirmed";
}

function pendingDepositItem(pending, current) {
  const item = element("div", "address-item pending-deposit-item");
  const label = element("strong", "", `${pending.amount.toLocaleString()} sat deposit`);
  const addressLine = element("div", "copy-line");
  const address = element(
    "code",
    "pending-deposit-address",
    pending.address || "Creating address…",
  );
  const copy = element("button", "", "Copy");
  copy.type = "button";
  copy.disabled = !pending.address;
  if (pending.address) copy.dataset.copyValue = pending.address;
  addressLine.append(address, copy);

  const detail = element(
    "p",
    "field-note pending-deposit-detail",
    pendingDepositStatus(pending),
  );
  if (pending.fundingTxid) {
    const link = txLink(
      current.deployment.explorerUrl,
      pending.fundingTxid,
      `tx ${shortId(pending.fundingTxid)}`,
    );
    link.title = pending.fundingTxid;
    detail.append(" · ", link);
  }
  item.append(label, addressLine, detail);
  return item;
}

function renderDeposit(current) {
  const list = byId("pending-deposits");
  const restorePickerFocus = document.activeElement?.id === "pending-deposit-select";
  const incomplete = current.pendingDeposits.find((pending) => !pending.statechainId);
  const selected = current.pendingDeposits.find(
    (pending) => pendingDepositKey(pending) === selectedPendingDepositKey,
  )
    ?? incomplete
    ?? current.pendingDeposits[current.pendingDeposits.length - 1];
  list.replaceChildren();
  list.classList.toggle("hidden", !selected);

  if (selected) {
    selectedPendingDepositKey = pendingDepositKey(selected);
    if (current.pendingDeposits.length > 1) {
      const picker = element("label", "pending-deposit-picker", "Deposit address");
      const select = document.createElement("select");
      select.id = "pending-deposit-select";
      for (let index = current.pendingDeposits.length - 1; index >= 0; index -= 1) {
        const pending = current.pendingDeposits[index];
        const option = document.createElement("option");
        option.value = pendingDepositKey(pending);
        const identifier = pending.address || pending.statechainId;
        option.textContent = [
          `${pending.amount.toLocaleString()} sats`,
          pendingDepositStatus(pending),
          identifier && shortId(identifier),
        ].filter(Boolean).join(" · ");
        select.append(option);
      }
      select.value = selectedPendingDepositKey;
      picker.append(select);
      list.append(picker);
      if (restorePickerFocus) select.focus();
    }
    list.append(pendingDepositItem(selected, current));
  }

  if (incomplete) byId("deposit-amount").value = incomplete.amount;
  byId("deposit-amount").disabled = busy || Boolean(incomplete) || Boolean(runtimeProblem);
  const button = byId("deposit-form").querySelector("button[type=submit]");
  button.textContent = incomplete ? "Retry deposit request" : "Create deposit address";
  button.disabled = busy || Boolean(runtimeProblem);
}

function renderSendStatecoin(current) {
  const select = byId("send-statecoin-id");
  const address = byId("send-statecoin-address");
  const force = byId("force-send-duplicates");
  const forceRow = byId("duplicate-send-warning");
  const button = byId("send-statecoin");
  const status = byId("send-statecoin-status");
  const previousSelection = select.value;
  const pending = current.pendingOutgoingTransfer;
  const available = current.coins.filter(
    (coin) => coin.canSendOffchain || pending?.statechainId === coin.statechainId,
  );

  select.replaceChildren();
  for (const coin of available) {
    const option = document.createElement("option");
    option.value = coin.statechainId;
    option.textContent = `${coin.amount.toLocaleString()} sats · ${shortId(coin.statechainId)}`;
    select.append(option);
  }
  if (pending && available.some((coin) => coin.statechainId === pending.statechainId)) {
    select.value = pending.statechainId;
    address.value = pending.recipientAddress;
    force.checked = pending.acknowledgeCooperativeDuplicates;
  } else if (available.some((coin) => coin.statechainId === previousSelection)) {
    select.value = previousSelection;
  }

  const selected = available.find((coin) => coin.statechainId === select.value);
  const hasDuplicates = Boolean(selected?.duplicates.length);
  const sent = pending?.status === SENT_TRANSFER_STATUS;
  const canRetry = Boolean(pending && !sent && pending.intentKind === "user_transfer");
  forceRow.classList.toggle(
    "hidden",
    !hasDuplicates && !pending?.acknowledgeCooperativeDuplicates,
  );
  select.disabled = busy || !available.length || Boolean(pending) || Boolean(runtimeProblem);
  address.disabled = busy || !available.length || Boolean(pending) || Boolean(runtimeProblem);
  force.disabled = busy || !available.length || Boolean(pending) || Boolean(runtimeProblem);
  button.disabled = busy || !selected || (!selected.canSendOffchain && !canRetry) || Boolean(runtimeProblem);
  button.textContent = canRetry ? "Retry send" : "Send";
  status.textContent = selected?.offchainTransferStatus
    || pending?.status
    || (selected ? "Ready to send." : "No spendable statecoin.");

  byId("pending-transfer").classList.toggle("hidden", !pending);
  if (pending) {
    const pendingCoin = current.coins.find((coin) => coin.statechainId === pending.statechainId);
    byId("pending-transfer-detail").textContent =
      `${shortId(pending.statechainId)} · ${pending.status}`;
    byId("pending-transfer-recipient").textContent = pending.recipientAddress;
    const title = byId("pending-transfer-title");
    const cancel = byId("cancel-transfer");
    const cancellation = pending.intentKind === "cancellation";
    title.textContent = cancellation
      ? "Cancelling transfer"
      : sent
        ? "Statecoin sent"
        : "Pending transfer";
    cancel.classList.toggle("hidden", sent && !cancellation);
    cancel.textContent = cancellation ? "Resume cancellation" : "Cancel transfer";
    cancel.classList.toggle("danger", !sent);
    cancel.disabled = busy || Boolean(runtimeProblem)
      || (!cancellation && (!pendingCoin?.canCancelTransfer || Boolean(pending.batchId)));
    cancel.title = pending.batchId && !cancellation
      ? "This legacy batched transfer cannot be cancelled yet"
      : "";
  }
}

byId("send-statecoin-id").addEventListener("change", () => renderSendStatecoin(view()));
byId("offboard-statechain-id").addEventListener("change", render);
byId("pending-deposits").addEventListener("change", (event) => {
  if (!event.target.matches("#pending-deposit-select")) return;
  selectedPendingDepositKey = event.target.value;
  renderDeposit(view());
});

function renderReceiveAddresses(current) {
  const node = byId("receive-addresses");
  node.replaceChildren();
  if (!current.receiveAddresses.length) {
    node.append(element("p", "empty-state", "Create a one-time address to receive."));
    return;
  }
  for (let index = current.receiveAddresses.length - 1; index >= 0; index -= 1) {
    const entry = current.receiveAddresses[index];
    const item = element("div", "address-item");
    const label = element("strong", "", `Receive address ${index + 1}`);
    const address = element("code", "", entry.address);
    const copy = element("button", "", "Copy");
    copy.type = "button";
    copy.dataset.copyValue = entry.address;
    const state = element("p", "field-note", entry.status);
    item.append(label, document.createElement("br"), address, " ", copy, state);
    node.append(item);
  }
}

function renderEnclave(current) {
  const proof = current.enclaveRuntimeProof;
  const mode = proof?.mode === "debug" ? "debug/QEMU" : proof?.mode;
  byId("enclave-summary-status").textContent = proof ? `Verified · ${mode}` : "Not checked";
  byId("enclave-verification-status").textContent =
    proof ? `Verified directly · ${mode}.` : "Not checked.";
  byId("enclave-proof").classList.toggle("hidden", !proof);
  if (!proof) return;
  byId("enclave-mode").textContent = mode;
  byId("enclave-endpoint").textContent = proof.endpoint;
  byId("enclave-checked-at").textContent = proof.checkedAt;
  byId("enclave-authentication").textContent = proof.authentication;
  byId("enclave-pcr0").textContent = proof.pcr0;
  byId("enclave-pcr1").textContent = proof.pcr1;
  byId("enclave-pcr2").textContent = proof.pcr2;
  byId("enclave-trust").textContent = proof.trustModel;
}

function renderCoinEnclave(fragment, coin, current) {
  const proof = current.enclaveVerifications.find(
    (candidate) => candidate.statechainId === coin.statechainId,
  );
  fragment.querySelector(".coin-enclave-status").textContent = proof ? "Verified" : "Not checked";
  fragment.querySelector(".coin-enclave-result").textContent = proof
    ? "Verified: server share and PCRs match."
    : "Not checked.";
  const button = fragment.querySelector(".verify-coin-enclave");
  button.textContent = proof ? "Verified" : "Verify coin";
  button.disabled = Boolean(proof)
    || busy
    || ["WITHDRAWN", "TRANSFERRED"].includes(coin.status)
    || Boolean(runtimeProblem);
  button.title = proof ? "Verification is saved in this browser." : "";
  fragment.querySelector(".coin-enclave-proof").classList.toggle("hidden", !proof);
  if (!proof) return;
  fragment.querySelector(".coin-enclave-verified-at").textContent = proof.verifiedAt;
  fragment.querySelector(".coin-enclave-server-pubkey").textContent = proof.serverPubkey;
  fragment.querySelector(".coin-enclave-challenge").textContent = proof.challenge;
  fragment.querySelector(".coin-enclave-pcr0").textContent = proof.pcr0;
  fragment.querySelector(".coin-enclave-pcr1").textContent = proof.pcr1;
  fragment.querySelector(".coin-enclave-pcr2").textContent = proof.pcr2;
  fragment.querySelector(".coin-enclave-trust").textContent = proof.trustModel;
}

function renderCoin(coin, current, uiState) {
  const fragment = coinTemplate.content.cloneNode(true);
  const card = fragment.querySelector(".coin-card");
  card.dataset.statechainId = coin.statechainId;
  card.open = uiState?.status === coin.status
    ? uiState.open
    : !TERMINAL_COIN_STATUSES.has(coin.status);
  fragment.querySelector(".coin-id").textContent = coin.statechainId;
  fragment.querySelector(".copy-coin-id").dataset.copyValue = coin.statechainId;
  fragment.querySelector(".coin-amount").textContent = `${coin.amount.toLocaleString()} sats`;
  fragment.querySelector(".coin-status").textContent = coin.status;
  fragment.querySelector(".state-number").textContent = `State ${coin.latestStateNumber}`;
  fragment.querySelector(".challenge-delay").textContent = `${coin.challengeDelayBlocks}-block exit delay`;
  fragment.querySelector(".duplicate-count").textContent = coin.duplicates.length
    ? `${coin.duplicates.length} extra deposit${coin.duplicates.length === 1 ? "" : "s"}`
    : "No extra deposits";
  fragment.querySelector(".duplicate-summary-count").textContent = `(${coin.duplicates.length})`;
  fragment.querySelector(".saved-exit-detail").textContent =
    `Recovery state ${coin.latestStateNumber} is stored in this browser.`;
  fragment.querySelector(".fee-address").textContent = current.recoveryFeeAddress;
  fragment.querySelector(".copy-fee-address").dataset.copyValue = current.recoveryFeeAddress;
  const feeDetail = fragment.querySelector(".recovery-fee-detail");
  const feeUtxo = current.recoveryFeeUtxo;
  feeDetail.replaceChildren();
  if (feeUtxo) {
    const status = feeUtxo.ready
      ? "ready"
      : `${feeUtxo.confirmationBlocksRemaining} block${feeUtxo.confirmationBlocksRemaining === 1 ? "" : "s"} remaining`;
    const link = txLink(
      current.deployment.explorerUrl,
      feeUtxo.txid,
      `tx ${shortId(feeUtxo.txid)}`,
    );
    link.title = feeUtxo.txid;
    feeDetail.append(`${feeUtxo.amountSats.toLocaleString()} sats · ${status} · `, link);
  } else {
    feeDetail.textContent = "Fund this address. Waiting for confirmation.";
  }

  const alert = fragment.querySelector(".coin-alert");
  if (coin.exitOnly) {
    alert.textContent = "Exit in progress.";
    alert.classList.remove("hidden");
  } else if (coin.duplicates.some((duplicate) => duplicate.serverDependent)) {
    alert.textContent = "Sweep extra deposits before withdrawing.";
    alert.classList.remove("hidden");
  }

  renderCoinEnclave(fragment, coin, current);
  renderWithdrawal(fragment, coin, current);
  renderDuplicates(fragment, coin, current);
  renderRecovery(fragment, coin, current);
  restoreCoinDrafts(card, coin.statechainId);

  for (const details of card.querySelectorAll("details")) {
    const key = [...details.classList].sort().join(".");
    details.open = uiState?.panels.has(key) ?? false;
  }
  return fragment;
}

function renderWithdrawal(fragment, coin, current) {
  const attempt = current.withdrawalAttempts.find(
    (candidate) => candidate.statechainId === coin.statechainId && candidate.bindingIndex === 0,
  );
  const detail = fragment.querySelector(".withdrawal-detail");
  if (attempt) {
    detail.textContent = `${coin.withdrawalStatus || attempt.phase} · ${attempt.txid || "not broadcast"}`;
    fragment.querySelector(".withdraw-address").value = attempt.destinationAddress;
    fragment.querySelector(".withdraw-fee").value = attempt.feeRateSatPerVbyte;
  } else {
    detail.textContent = coin.duplicates.length
      ? "Sweep extra deposits first."
      : "Spend cooperatively to an onchain address.";
  }
  const button = fragment.querySelector(".withdraw-statecoin");
  button.disabled = busy || !coin.canWithdraw || Boolean(runtimeProblem);
  if (attempt) {
    button.textContent = attempt.completionStatus === "closed"
      ? "Withdrawal complete"
      : "Resume withdrawal";
  }
}

function renderDuplicates(fragment, coin, current) {
  const panel = fragment.querySelector(".duplicates-panel");
  panel.classList.toggle("hidden", !coin.duplicates.length);
  const list = fragment.querySelector(".duplicates-list");
  list.replaceChildren();
  for (const duplicate of coin.duplicates) {
    const attempt = current.withdrawalAttempts.find(
      (candidate) => candidate.statechainId === coin.statechainId
        && candidate.bindingIndex === duplicate.duplicateIndex,
    );
    const row = element("article", "duplicate-row");
    row.dataset.duplicateIndex = String(duplicate.duplicateIndex);
    if (duplicate.observationStatus === "SpentConfirmed") row.classList.add("duplicate-resolved");
    const meta = element("div");
    meta.append(
      element("h4", "", `Extra deposit ${duplicate.duplicateIndex} · ${duplicate.amountSats.toLocaleString()} sats`),
      element("p", "duplicate-meta", `${duplicate.txid}:${duplicate.vout}`),
      element("p", "duplicate-meta", duplicate.observationStatus),
    );

    const form = element("form", "duplicate-form");
    form.dataset.duplicateIndex = String(duplicate.duplicateIndex);
    const addressLabel = element("label", "", "Destination");
    const address = document.createElement("input");
    address.className = "duplicate-address";
    address.dataset.draft = `duplicate-${duplicate.duplicateIndex}-address`;
    address.autocomplete = "off";
    address.spellcheck = false;
    address.placeholder = "tb1…";
    address.required = true;
    if (attempt) address.value = attempt.destinationAddress;
    addressLabel.append(address);
    const feeLabel = element("label", "", "sat/vB");
    const fee = document.createElement("input");
    fee.className = "duplicate-fee";
    fee.dataset.draft = `duplicate-${duplicate.duplicateIndex}-fee`;
    fee.type = "number";
    fee.min = "0.1";
    fee.max = "10";
    fee.step = "0.1";
    fee.value = attempt?.feeRateSatPerVbyte ?? "0.1";
    fee.required = true;
    feeLabel.append(fee);
    const button = element("button", "sweep-duplicate", attempt ? "Resume sweep" : "Sweep");
    button.type = "submit";
    button.disabled = busy || !duplicate.canSweep || Boolean(runtimeProblem);
    form.append(addressLabel, feeLabel, button);
    row.append(meta, form);
    list.append(row);
  }
}

function renderRecovery(fragment, coin, current) {
  const updateAttempt = current.recoveryAttempts.find(
    (attempt) => attempt.statechainId === coin.statechainId && attempt.role === "funding_update",
  );
  const settlementAttempt = current.recoveryAttempts.find(
    (attempt) => attempt.statechainId === coin.statechainId && attempt.role === "settlement",
  );
  const filenameStatechainId = safeFilenamePart(coin.statechainId);
  const updateDownload = fragment.querySelector(".download-update");
  updateDownload.dataset.downloadValue = coin.updateTxHex;
  updateDownload.dataset.downloadFilename = `bip448-${filenameStatechainId}-update.hex`;
  updateDownload.disabled = !coin.updateTxHex || Boolean(runtimeProblem);
  const settlementDownload = fragment.querySelector(".download-settlement");
  settlementDownload.dataset.downloadValue = coin.settlementTxHex;
  settlementDownload.dataset.downloadFilename =
    `bip448-${filenameStatechainId}-settlement.hex`;
  settlementDownload.disabled = !coin.settlementTxHex || Boolean(runtimeProblem);
  const updateDetail = fragment.querySelector(".update-detail");
  updateDetail.replaceChildren();
  if (updateAttempt) {
    renderRecoveryAttemptDetail(updateDetail, updateAttempt, current);
  } else {
    updateDetail.textContent = "Uses the saved update transaction.";
  }
  appendRecoveryFeedback(updateDetail, coin.statechainId, "funding_update");
  const updateButton = fragment.querySelector(".broadcast-update");
  updateButton.disabled = busy || !coin.canStartUnilateralExit || Boolean(runtimeProblem);
  updateButton.title = !coin.canStartUnilateralExit
    ? "This update is not currently eligible for broadcast."
    : !updateAttempt && !current.recoveryFeeUtxo?.ready
      ? "Click to check for a confirmed fee input and get funding instructions."
      : "";
  if (updateAttempt) {
    updateButton.textContent =
      updateAttempt.status === "confirmed" ? "Update confirmed" : "Rebroadcast update";
  }

  const progress = Math.min(100, (coin.updateConfirmations / coin.challengeDelayBlocks) * 100);
  const bar = fragment.querySelector(".progress");
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", String(coin.challengeDelayBlocks));
  bar.setAttribute("aria-valuenow", String(coin.updateConfirmations));
  bar.querySelector("span").style.width = `${Number.isFinite(progress) ? progress : 0}%`;
  fragment.querySelector(".wait-detail").textContent = updateAttempt
    ? coin.settlementBlocksRemaining === 0
      ? "Delay complete."
      : `${coin.settlementBlocksRemaining} block${coin.settlementBlocksRemaining === 1 ? "" : "s"} remaining.`
    : "Starts after the update confirms.";

  const settlementDetail = fragment.querySelector(".settlement-detail");
  settlementDetail.replaceChildren();
  if (settlementAttempt) {
    renderRecoveryAttemptDetail(settlementDetail, settlementAttempt, current);
  } else {
    settlementDetail.textContent = "Available after the delay.";
  }
  appendRecoveryFeedback(settlementDetail, coin.statechainId, "settlement");
  const settlementButton = fragment.querySelector(".broadcast-settlement");
  settlementButton.disabled = busy || !coin.canSettleUnilateralExit || Boolean(runtimeProblem);
  settlementButton.title = !updateAttempt
    ? "Broadcast and confirm the update first."
    : coin.settlementBlocksRemaining > 0
      ? `Click to refresh chain status; ${coin.settlementBlocksRemaining} block${coin.settlementBlocksRemaining === 1 ? "" : "s"} remain in the saved view.`
      : !settlementAttempt && !current.recoveryFeeUtxo?.ready
        ? "Click to check for a fresh confirmed fee input and get funding instructions."
        : "";
  if (settlementAttempt) {
    settlementButton.textContent =
      settlementAttempt.status === "confirmed" ? "Settlement confirmed" : "Rebroadcast settlement";
  } else if (updateAttempt && coin.settlementBlocksRemaining > 0) {
    settlementButton.textContent = "Check settlement";
  }
}

function restoreCoinDrafts(card, statechainId) {
  for (const input of card.querySelectorAll("[data-draft]")) {
    const value = coinDrafts.get(`${statechainId}:${input.dataset.draft}`);
    if (value !== undefined) input.value = value;
  }
}

function shortId(value) {
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-7)}` : value;
}

function safeFilenamePart(value) {
  return value.replace(/[^A-Za-z0-9._-]/g, "-");
}

function downloadText(filename, value) {
  const url = URL.createObjectURL(new Blob([`${value}\n`], { type: "text/plain;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== "") node.textContent = text;
  return node;
}

function txLink(explorer, txid, label) {
  const link = document.createElement("a");
  link.href = `${explorer.replace(/\/$/, "")}/tx/${encodeURIComponent(txid)}`;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = label;
  return link;
}

function renderRecoveryAttemptDetail(node, attempt, current) {
  node.append(`${attempt.status} · parent txid `);
  const parentLink = txLink(
    current.deployment.explorerUrl,
    attempt.parentTxid,
    shortId(attempt.parentTxid),
  );
  parentLink.title = attempt.parentTxid;
  const childLink = txLink(
    current.deployment.explorerUrl,
    attempt.childTxid,
    shortId(attempt.childTxid),
  );
  childLink.title = attempt.childTxid;
  node.append(parentLink, " · fee child txid ", childLink);
}

function appendRecoveryFeedback(node, statechainId, role) {
  const feedback = recoveryFeedback.get(`${statechainId}:${role}`);
  if (!feedback) return;
  node.append(document.createElement("br"));
  node.append(element("span", "inline-error", feedback));
}


async function submitRecovery(activeWallet, card, role) {
  const statechainId = card.dataset.statechainId;
  const feeRate = Number(card.querySelector(role === "funding_update" ? ".update-fee" : ".settlement-fee").value);
  if (!Number.isFinite(feeRate)) throw new Error("fee rate is required");
  return activeWallet.submitUnilateralExit(statechainId, role, feeRate);
}

async function broadcastRecovery(card, role) {
  const roleLabel = role === "funding_update" ? "Update" : "Settlement";
  const detail = card.querySelector(
    role === "funding_update" ? ".update-detail" : ".settlement-detail",
  );
  detail.textContent = `Broadcasting ${roleLabel.toLowerCase()} package…`;
  const feedbackKey = `${card.dataset.statechainId}:${role}`;
  recoveryFeedback.delete(feedbackKey);
  const completed = await run(`Broadcasting ${roleLabel.toLowerCase()}`, async (activeWallet) => {
    const result = await submitRecovery(activeWallet, card, role);
    return {
      message: `${roleLabel} package broadcast. Parent txid: ${result.parentTxid}. Fee child txid: ${result.childTxid}.`,
    };
  });
  if (!completed) {
    recoveryFeedback.set(feedbackKey, statusNode.textContent);
  }
  render();
}


const aboutDialog = byId("about-dialog");
const aboutContent = aboutDialog.querySelector(".about-content");
byId("open-about").addEventListener("click", () => {
  aboutDialog.showModal();
  byId("about-title").focus({ preventScroll: true });
  aboutDialog.scrollTop = 0;
  aboutContent.scrollTop = 0;
});
byId("close-about").addEventListener("click", () => aboutDialog.close());

document.querySelector(".app-tabs").addEventListener("click", (event) => {
  const link = event.target.closest("a");
  if (!link?.getAttribute("href")?.startsWith("#")) return;
  document.querySelectorAll(".app-tabs a").forEach((tab) => tab.classList.toggle("active", tab === link));
});

byId("deposit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const amount = Number(byId("deposit-amount").value);
  await run("Generating a deposit key in the signing enclave", async (activeWallet) => {
    if (!Number.isSafeInteger(amount)) throw new Error("deposit amount must be a whole number");
    selectedPendingDepositKey = "incomplete";
    const deposit = await activeWallet.createDepositWithToken(amount, undefined);
    selectedPendingDepositKey = deposit.statechainId;
    return { message: "Deposit address created." };
  }, {
    slowLabel: "Waiting for the signing enclave. The pending deposit remains retryable.",
  });
});

byId("create-receive-address").addEventListener("click", () => run(
  "Creating receive address",
  async (activeWallet) => {
    activeWallet.createTransferAddressWithBatch(false);
    return { message: "Receive address created." };
  },
));



byId("verify-enclave").addEventListener("click", () => run(
  "Verifying enclave",
  async (activeWallet) => {
    await activeWallet.verifyEnclaveRuntime();
    return { message: "Enclave verified." };
  },
));

byId("send-statecoin-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const statechainId = byId("send-statecoin-id").value;
  const recipient = byId("send-statecoin-address").value.trim();
  const acknowledgeDuplicates = byId("force-send-duplicates").checked;
  await run("Sending statecoin", async (activeWallet) => {
    if (!statechainId) throw new Error("select a statecoin to send");
    if (!recipient) throw new Error("recipient address is required");
    await activeWallet.sendStatecoinWithOptions(
      statechainId,
      recipient,
      undefined,
      acknowledgeDuplicates,
    );
    return { message: "Statecoin sent." };
  });
});

byId("cancel-transfer").addEventListener("click", async () => {
  const pending = view()?.pendingOutgoingTransfer;
  if (!pending) return;
  await run("Cancelling transfer", async (activeWallet) => {
    await activeWallet.cancelStatecoinTransfer(pending.statechainId);
    return { message: "Transfer cancelled." };
  });
});


coinsNode.addEventListener("input", (event) => {
  const card = event.target.closest(".coin-card");
  if (!card || !event.target.dataset.draft) return;
  coinDrafts.set(`${card.dataset.statechainId}:${event.target.dataset.draft}`, event.target.value);
});

coinsNode.addEventListener("submit", async (event) => {
  event.preventDefault();
  const card = event.target.closest(".coin-card");
  if (!card) return;
  const statechainId = card.dataset.statechainId;
  if (event.target.matches(".withdrawal-form")) {
    const address = event.target.querySelector(".withdraw-address").value.trim();
    const feeRate = Number(event.target.querySelector(".withdraw-fee").value);
    await run("Withdrawing statecoin", async (activeWallet) => {
      await activeWallet.withdrawStatecoin(statechainId, address, feeRate);
      return { message: "Withdrawal broadcast." };
    });
  } else if (event.target.matches(".duplicate-form")) {
    const index = Number(event.target.dataset.duplicateIndex);
    const address = event.target.querySelector(".duplicate-address").value.trim();
    const feeRate = Number(event.target.querySelector(".duplicate-fee").value);
    await run(`Sweeping extra deposit ${index}`, async (activeWallet) => {
      await activeWallet.sweepDuplicate(statechainId, index, address, feeRate);
      return { message: "Extra deposit sweep broadcast." };
    });
  }
});

coinsNode.addEventListener("click", async (event) => {
  const card = event.target.closest(".coin-card");
  if (!card) return;
  if (event.target.closest(".verify-coin-enclave")) {
    await run("Verifying coin enclave", async (activeWallet) => {
      await activeWallet.verifyEnclave(card.dataset.statechainId);
      return { message: "Coin enclave verified." };
    });
  } else if (event.target.closest(".broadcast-update")) {
    await broadcastRecovery(card, "funding_update");
  } else if (event.target.closest(".broadcast-settlement")) {
    await broadcastRecovery(card, "settlement");
  }
});

document.addEventListener("click", async (event) => {
  const downloadButton = event.target.closest("[data-download-value]");
  if (downloadButton) {
    downloadText(downloadButton.dataset.downloadFilename, downloadButton.dataset.downloadValue);
    setStatus("Raw transaction downloaded.");
    return;
  }

  const copyButton = event.target.closest("[data-copy-target], [data-copy-value]");
  if (!copyButton) return;
  const value = copyButton.dataset.copyValue
    || byId(copyButton.dataset.copyTarget)?.textContent;
  if (value && value !== "—") {
    await navigator.clipboard.writeText(value);
    setStatus("Copied.");
  }
});

function concealMnemonic() {
  const node = byId("mnemonic");
  node.classList.add("hidden");
  node.textContent = "";
  byId("show-mnemonic").textContent = "Reveal";
}

byId("show-mnemonic").addEventListener("click", () => {
  const node = byId("mnemonic");
  const hidden = node.classList.toggle("hidden");
  node.textContent = hidden ? "" : wallet.mnemonic();
  byId("show-mnemonic").textContent = hidden ? "Reveal" : "Hide seed phrase";
});

byId("seed-import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const phrase = byId("seed-import").value.trim().replace(/\s+/g, " ");
  if (!phrase) return setStatus("Error: seed phrase is empty.", "error");
  const current = view();
  if ((current.pendingDeposits.length
    || current.coins.length
    || current.receiveAddresses.length
    || current.pendingOutgoingTransfer
    || current.pendingIncoming
    || current.recoveryAttempts.length
    || current.withdrawalAttempts.length)
    && prompt("Type REPLACE to discard the current browser wallet.") !== "REPLACE") return;
  busy = true;
  setStatus("[working] import seed phrase", "busy");
  setDisabled(true);
  try {
    await withWalletLock(async () => {
      const expected = readStoredSnapshot();
      const replacement = await MercuryWallet.fromSeedPhrase(phrase);
      const snapshot = replacement.exportSnapshot();
      writeStoredSnapshot(snapshot, expected);
      wallet = replacement;
    });
    coinDrafts.clear();
    concealMnemonic();
    byId("seed-import").value = "";
    setStatus("Wallet restored.");
  } catch (error) {
    setStatus(`Error: ${errorMessage(error)}`, "error");
  } finally {
    busy = false;
    setDisabled(false);
    render();
  }
});

byId("reset-wallet").addEventListener("click", async () => {
  if (prompt("Type ERASE to delete the browser wallet.") !== "ERASE") return;
  await withWalletLock(async () => {
    const expected = readStoredSnapshot();
    const replacement = await MercuryWallet.create();
    const snapshot = replacement.exportSnapshot();
    writeStoredSnapshot(snapshot, expected);
    wallet = replacement;
  });
  coinDrafts.clear();
  concealMnemonic();
  render();
  setStatus("New wallet created.");
});

async function boot() {
  setDisabled(true);
  try {
    if (!window.isSecureContext && !["127.0.0.1", "localhost"].includes(location.hostname)) {
      throw new Error("a dedicated HTTPS origin is required outside loopback development");
    }
    await init();
    wasmReady = true;
    if (!navigator.locks?.request) {
      runtimeProblem = "Web Locks are unavailable; wallet mutations are disabled";
    }
    await (navigator.locks?.request
      ? withWalletLock(async () => {
          const saved = readStoredSnapshot();
          if (saved) {
            loadRevision(saved);
          } else {
            const created = await MercuryWallet.create();
            const snapshot = created.exportSnapshot();
            writeStoredSnapshot(snapshot, null);
            wallet = created;
          }
        })
      : Promise.resolve().then(() => loadRevision(readStoredSnapshot())));
    removeObsoleteStoredWallets();
    render();
    setStatus(runtimeProblem ? `Blocked: ${runtimeProblem}` : "Ready.", runtimeProblem ? "error" : "ready");
    startPolling();
  } catch (error) {
    runtimeProblem = errorMessage(error);
    setStatus(`Error: ${runtimeProblem}`, "error");
    console.error(error);
  } finally {
    busy = false;
    setDisabled(false);
    render();
  }
}

function requestBackgroundSync() {
  if (document.visibilityState !== "visible") return;
  const transfersOnly = Date.now() < nextFullSyncAt;
  if (transfersOnly) {
    const current = view();
    const hasTransferWork = Boolean(
      current?.pendingOutgoingTransfer
      || current?.pendingIncoming
      || current?.receiveAddresses.length,
    );
    if (!hasTransferWork) return;
  }
  void syncWallet({ ifAvailable: true, transfersOnly });
}

function startPolling() {
  clearInterval(pollTimer);
  nextFullSyncAt = Date.now() + FULL_SYNC_INTERVAL_MS;
  pollTimer = setInterval(requestBackgroundSync, TRANSFER_SYNC_INTERVAL_MS);
}

document.addEventListener("visibilitychange", requestBackgroundSync);

window.addEventListener("storage", (event) => {
  if (event.key !== STORAGE_KEY || busy || syncPromise || !wasmReady) return;
  try {
    loadRevision(event.newValue);
    render();
  } catch (error) {
    runtimeProblem = errorMessage(error);
    setStatus(`Blocked: ${runtimeProblem}`, "error");
  }
});

boot();
