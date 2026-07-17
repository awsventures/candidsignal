/**
 * Issuer-service tests.
 *
 * The happy path is driven end-to-end through the real crypto: the "browser"
 * blinds a token, the service blind-signs it, and we unblind and verify the
 * result — proving the HTTP layer carries the RFC 9474 flow intact. The rest
 * pin the guard rails: assertion verification, one-per-subject, and the
 * side-channel rule (the service persists and logs nothing identifying).
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";
import { sign } from "hono/jwt";

import { Storage } from "../src/storage.ts";
import { createIssuerApp, type IssuerAppConfig } from "../src/issuer-service.ts";
import {
  generateIssuerKey,
  publicKeyOf,
  mintToken,
  blind,
  unblind,
  Issuer,
  Verifier,
  toHex,
  TEST_MODULUS_BITS,
} from "../../anonymity-core/src/index.ts";

// Shared (expensive) key material generated once.
let vendorKeys: CryptoKeyPair;
let issuerPair: CryptoKeyPair;
let issuerPub: CryptoKey;

before(async () => {
  vendorKeys = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  issuerPair = await generateIssuerKey(TEST_MODULUS_BITS);
  issuerPub = publicKeyOf(issuerPair);
});

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A fresh app + storage for one test, sharing the key material. */
async function buildApp(overrides: Partial<IssuerAppConfig> = {}) {
  const storage = await Storage.open(":memory:");
  const issuers = new Map([["survey-1", { issuer: new Issuer(issuerPair.privateKey), keyId: "key-1" }]]);
  const app = createIssuerApp({ storage, vendorPublicKey: vendorKeys.publicKey, issuers, ...overrides });
  return { app, storage };
}

/** Mint a vendor eligibility assertion (defaults valid for 5 minutes). */
async function assertion(claims: Record<string, unknown> = {}, key = vendorKeys.privateKey): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return sign(
    { surveyId: "survey-1", cohortLabel: "cohort-A", subjectRef: "subject-1", exp: now + 300, ...claims },
    key,
    "EdDSA",
  );
}

function post(app: Awaited<ReturnType<typeof buildApp>>["app"], body: unknown, headers: Record<string, string> = {}) {
  return app.request("/issue", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

// ---------- happy path ----------

test("issue: blind → sign → unblind → verify, and the counter increments", async () => {
  const { app, storage } = await buildApp();
  const req = await blind(mintToken(), issuerPub);

  const res = await post(app, { assertion: await assertion(), blindedMsg: toHex(req.blindedMsg) });
  assert.equal(res.status, 200);
  const { blindSignature, keyId } = (await res.json()) as { blindSignature: string; keyId: string };
  assert.equal(keyId, "key-1");

  // Unblind the issuer's blind signature and verify it — the issuer never saw
  // this token, yet the signature is valid over it.
  const signed = await unblind(req, fromHex(blindSignature), issuerPub);
  assert.ok(await new Verifier(issuerPub).isValidSignature(signed));

  assert.deepEqual(await storage.counters("survey-1"), { issued: 1, redeemed: 0 });
});

// ---------- one token per subject ----------

test("issue: a second request for the same subject is refused (409), counter unchanged", async () => {
  const { app, storage } = await buildApp();
  const first = await post(app, { assertion: await assertion({ subjectRef: "dup" }), blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) });
  assert.equal(first.status, 200);

  const second = await post(app, { assertion: await assertion({ subjectRef: "dup" }), blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) });
  assert.equal(second.status, 409);
  assert.equal((await storage.counters("survey-1")).issued, 1, "no second signing");
});

// ---------- assertion verification ----------

test("issue: a malformed assertion is rejected 401, subject not claimed", async () => {
  const { app, storage } = await buildApp();
  const res = await post(app, { assertion: "not.a.jwt", blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) });
  assert.equal(res.status, 401);
  assert.equal(await storage.seenSubject("survey-1", "subject-1"), false, "subject still free");
});

test("issue: an expired assertion is rejected 401", async () => {
  const { app } = await buildApp();
  const now = Math.floor(Date.now() / 1000);
  const expired = await assertion({ exp: now - 10 });
  const res = await post(app, { assertion: expired, blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) });
  assert.equal(res.status, 401);
});

test("issue: an assertion signed by the wrong key is rejected 401", async () => {
  const { app } = await buildApp();
  const attacker = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const forged = await assertion({}, attacker.privateKey);
  const res = await post(app, { assertion: forged, blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) });
  assert.equal(res.status, 401);
});

test("issue: an unknown survey is 404", async () => {
  const { app } = await buildApp();
  const res = await post(app, { assertion: await assertion({ surveyId: "no-such-survey" }), blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) });
  assert.equal(res.status, 404);
});

test("issue: a missing field is 400", async () => {
  const { app } = await buildApp();
  assert.equal((await post(app, { blindedMsg: "aa" })).status, 400);
  assert.equal((await post(app, { assertion: await assertion() })).status, 400);
  assert.equal((await post(app, { assertion: await assertion(), blindedMsg: "zz" })).status, 400); // bad hex
});

// ---------- side-channel discipline ----------

test("issue: persists only (surveyId, subjectRef) and logs nothing identifying", async () => {
  const { app, storage } = await buildApp();

  // Record exactly what the service hands to storage.
  const calls: { method: string; args: unknown[] }[] = [];
  for (const m of ["seenSubject", "incrementIssued", "spend", "appendLog", "recordKey"] as const) {
    const real = (storage[m] as (...a: unknown[]) => unknown).bind(storage);
    (storage as unknown as Record<string, unknown>)[m] = (...a: unknown[]) => {
      calls.push({ method: m, args: a });
      return real(...a);
    };
  }

  // Capture everything the service might print.
  const printed: string[] = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  for (const k of Object.keys(orig) as (keyof typeof orig)[]) {
    console[k] = (...a: unknown[]) => printed.push(a.map(String).join(" "));
  }

  const SECRET_IP = "203.0.113.42";
  const SUBJECT = "subject-super-secret";
  const blindedHex = toHex((await blind(mintToken(), issuerPub)).blindedMsg);
  try {
    const res = await post(
      app,
      { assertion: await assertion({ subjectRef: SUBJECT }), blindedMsg: blindedHex },
      { "x-forwarded-for": SECRET_IP },
    );
    assert.equal(res.status, 200);
  } finally {
    Object.assign(console, orig);
  }

  // The service touched storage only with (surveyId, subjectRef) and (surveyId).
  assert.deepEqual(
    calls.map((c) => c.method).sort(),
    ["incrementIssued", "seenSubject"],
    "only the subject claim and the issued counter are persisted",
  );
  const persisted = JSON.stringify(calls);
  assert.ok(!persisted.includes(SECRET_IP), "IP never reaches storage");
  assert.ok(!persisted.includes(blindedHex), "blinded message never reaches storage");
  assert.ok(persisted.includes(SUBJECT), "subjectRef is the only identifier stored (by design)");

  // And nothing identifying was logged.
  const logs = printed.join("\n");
  for (const secret of [SECRET_IP, SUBJECT, blindedHex]) {
    assert.ok(!logs.includes(secret), `"${secret}" must not appear in logs`);
  }
});

// ---------- CORS + rate limiting ----------

test("issue: CORS headers are present", async () => {
  const { app } = await buildApp();
  const res = await post(app, { assertion: await assertion(), blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg) }, { origin: "https://vendor.example" });
  assert.ok(res.headers.get("access-control-allow-origin"), "ACAO header set");
});

test("issue: rate limiting returns 429 past the window limit", async () => {
  const { app } = await buildApp({ rateLimit: { limit: 3, windowMs: 60_000 } });
  const headers = { "x-forwarded-for": "198.51.100.7" };
  // Cheap malformed bodies still consume a slot (the limiter runs first).
  const statuses: number[] = [];
  for (let i = 0; i < 4; i++) statuses.push((await post(app, { bad: true }, headers)).status);
  assert.deepEqual(statuses, [400, 400, 400, 429]);
});
