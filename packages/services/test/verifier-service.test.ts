/**
 * Verifier-service tests — the redeem state machine end-to-end.
 *
 * The tokens here are real: minted, blinded, blind-signed by a real Issuer,
 * unblinded, then presented over HTTP. What these tests pin, in ADR terms
 * (topology ADR §2–§3):
 *
 *   - a valid redeem returns a receipt that verifies against the receipt key
 *     and the spent-set / counters / transparency log all advance;
 *   - re-presenting the same (token, c) is idempotent: same 200, byte-identical
 *     receipt, and — asserted via an appendLog/increment spy — NO second log
 *     entry or counter bump;
 *   - the same token with a different c is a conflicting commitment (409);
 *   - an invalid or foreign signature never touches the spent-set;
 *   - P90 redeem latency is measured over ≥100 iterations and printed
 *     (recorded in the README and PROGRESS.md).
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";

import { Storage } from "../src/storage.ts";
import {
  createVerifierApp,
  verifyReceipt,
  type VerifierAppConfig,
} from "../src/verifier-service.ts";
import {
  generateIssuerKey,
  publicKeyOf,
  mintToken,
  blind,
  unblind,
  Issuer,
  toHex,
  tokenHash,
  TEST_MODULUS_BITS,
  type SignedToken,
} from "../../anonymity-core/src/index.ts";

// Shared (expensive) key material generated once.
let issuerPair: CryptoKeyPair;
let issuerPub: CryptoKey;
let issuer: Issuer;
let receiptKeys: CryptoKeyPair;

before(async () => {
  issuerPair = await generateIssuerKey(TEST_MODULUS_BITS);
  issuerPub = publicKeyOf(issuerPair);
  issuer = new Issuer(issuerPair.privateKey);
  receiptKeys = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
});

/** Mint → blind → blind-sign → unblind: a genuinely issued token. */
async function issuedToken(): Promise<SignedToken> {
  const req = await blind(mintToken(), issuerPub);
  const blindSig = await issuer.blindSign(req.blindedMsg, true);
  return unblind(req, blindSig, issuerPub);
}

async function buildApp(overrides: Partial<VerifierAppConfig> = {}) {
  const storage = await Storage.open(":memory:");
  const app = createVerifierApp({
    storage,
    verifiers: new Map([["survey-1", { issuerPublicKey: issuerPub }]]),
    receiptSigningKey: receiptKeys.privateKey,
    receiptKeyId: "receipt-key-1",
    ...overrides,
  });
  return { app, storage };
}

const C_1 = "a".repeat(64);
const C_2 = "b".repeat(64);

function redeem(
  app: Awaited<ReturnType<typeof buildApp>>["app"],
  t: SignedToken,
  c: string = C_1,
  surveyId = "survey-1",
) {
  return app.request("/redeem", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ surveyId, token: toHex(t.token), signature: toHex(t.signature), c }),
  });
}

// ---------- happy path ----------

test("redeem: valid token → 200, verifiable receipt, spent-set/counters/log all advance", async () => {
  const { app, storage } = await buildApp();
  const t = await issuedToken();

  const res = await redeem(app, t);
  assert.equal(res.status, 200);
  const body = (await res.json()) as { receipt: string; receiptKeyId: string; tokenHash: string };
  assert.equal(body.receiptKeyId, "receipt-key-1");

  const th = await tokenHash(t.token);
  assert.equal(body.tokenHash, th);

  // The receipt binds (surveyId, tokenHash, c) under the receipt key.
  assert.ok(
    await verifyReceipt(body.receipt, { surveyId: "survey-1", tokenHash: th, c: C_1 }, receiptKeys.publicKey),
  );
  // ... and fails against any altered binding.
  assert.ok(
    !(await verifyReceipt(body.receipt, { surveyId: "survey-1", tokenHash: th, c: C_2 }, receiptKeys.publicKey)),
  );

  // State advanced exactly once.
  assert.deepEqual(await storage.counters("survey-1"), { issued: 0, redeemed: 1 });
  const entry = await storage.logEntryBytes(1);
  assert.ok(entry, "redeem log entry appended at seq 1");
  const logged = JSON.parse(new TextDecoder().decode(entry!));
  assert.equal(logged.type, "redeem");
  assert.equal(logged.tokenHash, th);
  assert.equal(logged.c, C_1);
});

// ---------- idempotent re-present (the ADR §3 atomicity rule) ----------

test("redeem: re-presenting the same (token, c) → same receipt, no second log entry or counter bump", async () => {
  const { app, storage } = await buildApp();
  const t = await issuedToken();

  const first = await redeem(app, t);
  assert.equal(first.status, 200);
  const firstBody = (await first.json()) as { receipt: string };

  // Spy on the state-advancing calls before the retry.
  const advanced: string[] = [];
  for (const m of ["appendLog", "incrementRedeemed"] as const) {
    const real = (storage[m] as (...a: unknown[]) => unknown).bind(storage);
    (storage as unknown as Record<string, unknown>)[m] = (...a: unknown[]) => {
      advanced.push(m);
      return real(...a);
    };
  }

  const second = await redeem(app, t);
  assert.equal(second.status, 200, "safe retry — the SDK must never strand a respondent");
  const secondBody = (await second.json()) as { receipt: string };

  assert.equal(secondBody.receipt, firstBody.receipt, "byte-identical receipt");
  assert.deepEqual(advanced, [], "no second log entry, no second counter bump");
  assert.deepEqual(await storage.counters("survey-1"), { issued: 0, redeemed: 1 });
  assert.equal(await storage.logEntryBytes(2), null, "log has exactly one redeem entry");
});

test("redeem: same token with a different c → 409 conflicting-commitment", async () => {
  const { app, storage } = await buildApp();
  const t = await issuedToken();

  assert.equal((await redeem(app, t, C_1)).status, 200);
  const res = await redeem(app, t, C_2);
  assert.equal(res.status, 409);
  assert.deepEqual(await res.json(), { error: "conflicting-commitment" });

  // The double-spend attempt advanced nothing.
  assert.deepEqual(await storage.counters("survey-1"), { issued: 0, redeemed: 1 });
  assert.equal(await storage.logEntryBytes(2), null);
});

// ---------- signature gate ----------

test("redeem: a bad signature is rejected and never touches the spent-set", async () => {
  const { app, storage } = await buildApp();
  const t = await issuedToken();

  // Corrupt one signature byte.
  const badSig = t.signature.slice();
  badSig[0] ^= 0xff;
  const res = await redeem(app, { token: t.token, signature: badSig } as SignedToken);
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: "invalid-signature" });

  // The token is NOT spent — the legitimate holder can still redeem.
  assert.equal((await redeem(app, t)).status, 200);
});

test("redeem: a token signed by a different issuer is rejected", async () => {
  const { app } = await buildApp();
  const foreignPair = await generateIssuerKey(TEST_MODULUS_BITS);
  const foreignPub = publicKeyOf(foreignPair);
  const req = await blind(mintToken(), foreignPub);
  const foreignSig = await new Issuer(foreignPair.privateKey).blindSign(req.blindedMsg, true);
  const t = await unblind(req, foreignSig, foreignPub);

  assert.equal((await redeem(app, t)).status, 401);
});

// ---------- request validation ----------

test("redeem: malformed requests are 400/404 without state changes", async () => {
  const { app, storage } = await buildApp();
  const t = await issuedToken();
  const post = (body: unknown) =>
    app.request("/redeem", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  assert.equal((await post({})).status, 400);
  assert.equal((await post({ surveyId: "survey-1", token: "zz", signature: "aa", c: C_1 })).status, 400, "bad hex token");
  assert.equal(
    (await post({ surveyId: "survey-1", token: toHex(t.token), signature: toHex(t.signature), c: "short" })).status,
    400,
    "commitment must be 64 hex chars",
  );
  assert.equal((await redeem(app, t, C_1, "no-such-survey")).status, 404);

  assert.deepEqual(await storage.counters("survey-1"), { issued: 0, redeemed: 0 });
  assert.equal(await storage.logEntryBytes(1), null, "nothing logged");
});

// ---------- receipt verification is not fooled ----------

test("verifyReceipt: rejects non-hex, wrong key, and forged bindings", async () => {
  const { app } = await buildApp();
  const t = await issuedToken();
  const th = await tokenHash(t.token);
  const body = (await (await redeem(app, t)).json()) as { receipt: string };

  const bound = { surveyId: "survey-1", tokenHash: th, c: C_1 };
  assert.ok(await verifyReceipt(body.receipt, bound, receiptKeys.publicKey));

  assert.ok(!(await verifyReceipt("not-hex!", bound, receiptKeys.publicKey)));
  const otherKeys = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  assert.ok(!(await verifyReceipt(body.receipt, bound, otherKeys.publicKey)));
  assert.ok(!(await verifyReceipt(body.receipt, { ...bound, surveyId: "survey-2" }, receiptKeys.publicKey)));
  assert.ok(!(await verifyReceipt(body.receipt, { ...bound, tokenHash: "0".repeat(64) }, receiptKeys.publicKey)));
});

// ---------- CORS ----------

test("redeem: CORS headers are present (browser-direct topology requires them)", async () => {
  const { app } = await buildApp();
  const t = await issuedToken();
  const res = await app.request("/redeem", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://vendor.example" },
    body: JSON.stringify({ surveyId: "survey-1", token: toHex(t.token), signature: toHex(t.signature), c: C_1 }),
  });
  assert.ok(res.headers.get("access-control-allow-origin"), "ACAO header set");
});

// ---------- rate limiting ----------

test("redeem: rate limiting returns 429 past the window limit", async () => {
  const { app } = await buildApp({ rateLimit: { limit: 3, windowMs: 60_000 } });
  const headers = { "x-forwarded-for": "198.51.100.7", "content-type": "application/json" };
  const statuses: number[] = [];
  for (let i = 0; i < 4; i++) {
    const res = await app.request("/redeem", { method: "POST", headers, body: JSON.stringify({ bad: true }) });
    statuses.push(res.status);
  }
  assert.deepEqual(statuses, [400, 400, 400, 429]);
});

// ---------- P90 latency (acceptance: measured locally, recorded) ----------

test("redeem: P90 latency over 100 iterations", async () => {
  const { app } = await buildApp();
  const N = 100;

  // Pre-issue all tokens so the measurement isolates the redeem path.
  const tokens = await Promise.all(Array.from({ length: N }, () => issuedToken()));

  const times: number[] = [];
  for (const t of tokens) {
    const start = performance.now();
    const res = await redeem(app, t); // same c across loops is fine — tokens are distinct
    times.push(performance.now() - start);
    assert.equal(res.status, 200);
  }

  times.sort((a, b) => a - b);
  const p50 = times[Math.floor(N * 0.5)];
  const p90 = times[Math.floor(N * 0.9)];
  console.log(
    `redeem latency over ${N} iterations (in-process, ${TEST_MODULUS_BITS}-bit test keys, :memory: db): P50 ${p50.toFixed(1)}ms, P90 ${p90.toFixed(1)}ms`,
  );
  assert.ok(p90 < 5_000, "sanity ceiling only — the number itself is what gets recorded");
});
