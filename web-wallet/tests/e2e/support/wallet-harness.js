import { expect } from "@playwright/test";

export const STORAGE_PREFIX = "mercury-bip448-mutinynet-browser-wallet-";
export const STORAGE_KEY = `${STORAGE_PREFIX}v1`;

const GENERATOR_PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

function relativePath(base, requestUrl) {
  const basePath = new URL(base).pathname.replace(/\/$/, "");
  const requestPath = new URL(requestUrl).pathname;
  return requestPath.slice(basePath.length).replace(/^\//, "");
}

function requestBody(request) {
  const raw = request.postData();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

async function fulfill(route, response) {
  if (response === undefined) return false;
  if (typeof response === "string") {
    await route.fulfill({ status: 200, contentType: "text/plain", body: response });
    return true;
  }
  const status = response.status ?? 200;
  const body = response.body ?? response;
  const serialized = typeof body === "string" ? body : JSON.stringify(body);
  await route.fulfill({
    status,
    contentType: response.contentType ?? (typeof body === "string" ? "text/plain" : "application/json"),
    headers: response.headers,
    body: serialized,
  });
  return true;
}

export async function installWalletHarness(page, options) {
  const snapshot = options.snapshot;
  const deployment = snapshot.deployment;
  const walletCoin = snapshot.wallet.coins.find((coin) => coin.statechain_id);
  const state = {
    mercuryRequests: [],
    chainRequests: [],
    packages: [],
    broadcasts: [],
    completions: [],
    mature: false,
  };

  await page.route(`${deployment.mercuryUrl}/**`, async (route) => {
    const request = route.request();
    const path = relativePath(deployment.mercuryUrl, request.url());
    const body = requestBody(request);
    const observed = { method: request.method(), path, body };
    state.mercuryRequests.push(observed);

    const custom = await options.onMercury?.({ route, request, path, body, state });
    if (await fulfill(route, custom)) return;

    if (request.method() === "GET" && path === "info/config") {
      return fulfill(route, { body: { version: "e2e", batchtimeout: 120 } });
    }
    if (request.method() === "GET" && path === "deposit/get_token") {
      return fulfill(route, {
        body: {
          token_id: "e2e-token",
          payment_method: "free",
          deposit_address: null,
          fee: 0,
          confirmation_target: 0,
        },
      });
    }
    if (request.method() === "POST" && path === "transfer/unlock") {
      return fulfill(route, { body: { message: "updated" } });
    }
    if (request.method() === "GET" && path.startsWith("transfer/get_msg_addr/")) {
      return fulfill(route, { body: { list_enc_transfer_msg: [] } });
    }
    if (request.method() === "GET" && path.startsWith("info/statechain/")) {
      return fulfill(route, {
        body: {
          protocol_version: 1,
          enclave_public_key: walletCoin.server_pubkey,
          num_sigs: 1,
          lockbox_key_generation: 0,
          statechain_info: [],
          x1_pub: GENERATOR_PUBLIC_KEY,
        },
      });
    }
    if (request.method() === "POST" && path === "transfer/sender") {
      return fulfill(route, { body: { x1: "09".repeat(32) } });
    }
    if (request.method() === "GET" && path.startsWith("bip448-statechain/signature-count/")) {
      return fulfill(route, { status: 503, body: "intentional e2e signing boundary" });
    }
    if (request.method() === "POST" && path === "withdraw/complete") {
      state.completions.push(body);
      return fulfill(route, { body: { message: "withdrawn" } });
    }
    return route.fulfill({ status: 500, body: `unexpected Mercury request: ${request.method()} ${path}` });
  });

  await page.route(`${deployment.chainUrl}/**`, async (route) => {
    const request = route.request();
    const path = relativePath(deployment.chainUrl, request.url());
    const body = requestBody(request);
    state.chainRequests.push({ method: request.method(), path, body });

    const custom = await options.onChain?.({ route, request, path, body, state });
    if (await fulfill(route, custom)) return;

    if (request.method() === "GET" && path === "blocks/tip/height") {
      return fulfill(route, String(state.mature ? 300 : 105));
    }
    if (request.method() === "GET" && path.startsWith("address/") && path.endsWith("/utxo")) {
      const address = decodeURIComponent(path.slice("address/".length, -"/utxo".length));
      const utxos = await options.addressUtxos?.(address, state) ?? [];
      return fulfill(route, { body: utxos });
    }
    if (request.method() === "GET" && path.startsWith("tx/") && path.endsWith("/status")) {
      const txid = path.slice("tx/".length, -"/status".length);
      const status = await options.transactionStatus?.(txid, state)
        ?? { confirmed: false };
      return fulfill(route, { body: status });
    }
    if (request.method() === "GET" && path.includes("/outspend/")) {
      const outspend = await options.outspend?.(path, state)
        ?? { spent: false, txid: null, status: null };
      return fulfill(route, { body: outspend });
    }
    if (request.method() === "POST" && path === "txs/package") {
      state.packages.push(body);
      return fulfill(route, { body: { package_msg: "success" } });
    }
    if (request.method() === "POST" && path === "tx") {
      const attempt = snapshot.withdrawal_attempts?.find((candidate) => candidate.signedTxHex === body);
      if (!attempt?.txid) {
        return route.fulfill({ status: 400, body: "unknown signed transaction" });
      }
      state.broadcasts.push(body);
      return fulfill(route, attempt.txid);
    }
    return route.fulfill({ status: 500, body: `unexpected Mutinynet request: ${request.method()} ${path}` });
  });

  return state;
}

export async function loadSnapshot(page, snapshot) {
  await page.goto("/");
  await expect(page.locator("#status")).toHaveText("Ready.");
  await page.evaluate(({ key, value }) => {
    localStorage.setItem(key, JSON.stringify(value));
  }, { key: STORAGE_KEY, value: snapshot });
  await page.reload();
  await expect(page.locator("#status")).toHaveText("Ready.");
}

export async function storedSnapshot(page) {
  return page.evaluate((key) => JSON.parse(localStorage.getItem(key)), STORAGE_KEY);
}
