/**
 * sdk-server tests — the vendor backend SDK, pinned against the REAL services.
 *
 * These do not mock the issuer or verifier: an assertion minted here is fed to
 * the real `createIssuerApp`, and a receipt produced by the real
 * `createVerifierApp` is verified here. That is the whole point of the suite —
 * it proves format compatibility (JWT shape, receipt-message bytes) end to end,
 * so drift between the SDK and the services cannot pass silently.
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";

import {
  mintEligibilityAssertion,
  verifyReceipt,
  subjectRef,
  type VendorSubmission,
} from "../src/index.ts";

import { Storage } from "../../services/src/index.ts";
import { createIssuerApp } from "../../services/src/index.ts";
import { createVerifierApp } from "../../services/src/index.ts";

import {
  generateIssuerKey,
  publicKeyOf,
  mintToken,
  blind,
  unblind,
  Issuer,
  commit,
  newSalt,
  toHex,
  tokenHash,
  TEST_MODULUS_BITS,
  type JsonValue,
  type SignedToken,
} from "../../anonymity-core/src/index.ts";

// Shared (expensive) key material generated once.
let vendorKeys: CryptoKeyPair;
let issuerPair: CryptoKeyPair;
let issuerPub: CryptoKey;
let receiptKeys: CryptoKeyPair;

before(async () => {
  vendorKeys = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  issuerPair = await generateIssuerKey(TEST_MODULUS_BITS);
  issuerPub = publicKeyOf(issuerPair);
  receiptKeys = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
});

function nowExp(seconds = 300): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

async function issuerApp() {
  const storage = await Storage.open(":memory:");
  const issuers = new Map([["survey-1", { issuer: new Issuer(issuerPair.privateKey), keyId: "key-1" }]]);
  const app = createIssuerApp({ storage, vendorPublicKey: vendorKeys.publicKey, issuers });
  return { app, storage };
}

async function verifierApp() {
  const storage = await Storage.open(":memory:");
  const app = createVerifierApp({
    storage,
    verifiers: new Map([["survey-1", { issuerPublicKey: issuerPub }]]),
    receiptSigningKey: receiptKeys.privateKey,
    receiptKeyId: "receipt-key-1",
  });
  return { app, storage };
}

/** Mint → blind → blind-sign → unblind: a genuinely issued token. */
async function issuedToken(): Promise<SignedToken> {
  const req = await blind(mintToken(), issuerPub);
  const blindSig = await new Issuer(issuerPair.privateKey).blindSign(req.blindedMsg, true);
  return unblind(req, blindSig, issuerPub);
}

// ---------- 1. eligibility assertion round-trips through the REAL issuer ----------

test("mintEligibilityAssertion: accepted by the real issuer service → 200", async () => {
  const { app, storage } = await issuerApp();
  const assertion = await mintEligibilityAssertion(
    { surveyId: "survey-1", cohortLabel: "cohort-A", subjectRef: "subject-1", exp: nowExp() },
    vendorKeys.privateKey,
  );
  const req = await blind(mintToken(), issuerPub);

  const res = await app.request("/issue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ assertion, blindedMsg: toHex(req.blindedMsg) }),
  });

  assert.equal(res.status, 200, "the issuer accepted the SDK-minted assertion");
  const body = (await res.json()) as { blindSignature: string; keyId: string };
  assert.equal(body.keyId, "key-1");
  // The signature is real: unblind + it would verify (covered by services tests);
  // here we only need the issuer to have accepted the assertion format.
  assert.ok(body.blindSignature.length > 0);
  assert.deepEqual(await storage.counters("survey-1"), { issued: 1, redeemed: 0 });
});

test("mintEligibilityAssertion: an assertion from the wrong vendor key is rejected (401)", async () => {
  const { app } = await issuerApp();
  const foreign = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const assertion = await mintEligibilityAssertion(
    { surveyId: "survey-1", cohortLabel: "cohort-A", subjectRef: "subject-1", exp: nowExp() },
    foreign.privateKey,
  );
  const req = await blind(mintToken(), issuerPub);

  const res = await app.request("/issue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ assertion, blindedMsg: toHex(req.blindedMsg) }),
  });
  assert.equal(res.status, 401);
});

test("mintEligibilityAssertion: an expired assertion is rejected (401)", async () => {
  const { app } = await issuerApp();
  const assertion = await mintEligibilityAssertion(
    { surveyId: "survey-1", cohortLabel: "cohort-A", subjectRef: "subject-1", exp: nowExp(-10) },
    vendorKeys.privateKey,
  );
  const req = await blind(mintToken(), issuerPub);

  const res = await app.request("/issue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ assertion, blindedMsg: toHex(req.blindedMsg) }),
  });
  assert.equal(res.status, 401);
});

// ---------- 2. receipt from the REAL verifier verifies through the SDK ----------

const PAYLOAD: JsonValue = { q1: "agree", q2: 4, q3: ["a", "c"] };

/** Redeem a token at the real verifier and return the vendor submission. */
async function redeemToVendorSubmission(
  app: Awaited<ReturnType<typeof verifierApp>>["app"],
  payload: JsonValue = PAYLOAD,
): Promise<VendorSubmission> {
  const t = await issuedToken();
  const salt = newSalt();
  const cHex = toHex(await commit(payload, salt));

  const res = await app.request("/redeem", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      surveyId: "survey-1",
      token: toHex(t.token),
      signature: toHex(t.signature),
      c: cHex,
    }),
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as { receipt: string; tokenHash: string };
  // Sanity: the tokenHash the verifier echoed is the one we'd compute.
  assert.equal(body.tokenHash, await tokenHash(t.token));

  return { surveyId: "survey-1", payload, salt, tokenHash: body.tokenHash, receipt: body.receipt };
}

test("verifyReceipt: a receipt from the real verifier verifies (bytes + hex salt)", async () => {
  const { app } = await verifierApp();
  const sub = await redeemToVendorSubmission(app);

  assert.ok(await verifyReceipt(sub, receiptKeys.publicKey), "salt as raw bytes");
  // The browser submits salt as hex over JSON — that path must verify too.
  const hexSalt: VendorSubmission = { ...sub, salt: toHex(sub.salt as Uint8Array) };
  assert.ok(await verifyReceipt(hexSalt, receiptKeys.publicKey), "salt as hex string");
});

test("verifyReceipt: tampered payload / salt / tokenHash / surveyId / receipt all fail", async () => {
  const { app } = await verifierApp();
  const sub = await redeemToVendorSubmission(app);

  // baseline
  assert.ok(await verifyReceipt(sub, receiptKeys.publicKey));

  // altered stored answer → recomputed c no longer matches
  assert.ok(
    !(await verifyReceipt({ ...sub, payload: { ...(PAYLOAD as object), q2: 5 } as JsonValue }, receiptKeys.publicKey)),
    "tampered payload",
  );

  // altered salt
  const badSalt = (sub.salt as Uint8Array).slice();
  badSalt[0] ^= 0xff;
  assert.ok(!(await verifyReceipt({ ...sub, salt: badSalt }, receiptKeys.publicKey)), "tampered salt");

  // altered tokenHash binding
  assert.ok(
    !(await verifyReceipt({ ...sub, tokenHash: "0".repeat(64) }, receiptKeys.publicKey)),
    "tampered tokenHash",
  );

  // altered surveyId binding
  assert.ok(!(await verifyReceipt({ ...sub, surveyId: "survey-2" }, receiptKeys.publicKey)), "wrong surveyId");

  // tampered receipt bytes
  const badReceipt = sub.receipt.slice(0, -2) + (sub.receipt.endsWith("00") ? "11" : "00");
  assert.ok(!(await verifyReceipt({ ...sub, receipt: badReceipt }, receiptKeys.publicKey)), "tampered receipt");
});

test("verifyReceipt: wrong receipt key and malformed input return false, never throw", async () => {
  const { app } = await verifierApp();
  const sub = await redeemToVendorSubmission(app);

  const otherKeys = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  assert.ok(!(await verifyReceipt(sub, otherKeys.publicKey)), "wrong receipt key");

  assert.ok(!(await verifyReceipt({ ...sub, receipt: "not-hex!" }, receiptKeys.publicKey)), "non-hex receipt");
  assert.ok(!(await verifyReceipt({ ...sub, salt: "zz" }, receiptKeys.publicKey)), "non-hex salt");
  assert.ok(
    !(await verifyReceipt({ ...sub, salt: new Uint8Array(8) }, receiptKeys.publicKey)),
    "wrong-length salt (commit throws → false)",
  );
});

// ---------- 3. subjectRef: deterministic + key-separated ----------

test("subjectRef: deterministic, key-separated, and accepts bytes or a CryptoKey", async () => {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const otherKey = crypto.getRandomValues(new Uint8Array(32));

  const a = await subjectRef(rawKey, "user-123");
  const b = await subjectRef(rawKey, "user-123");
  assert.equal(a, b, "same key + id → same ref");
  assert.match(a, /^[0-9a-f]{64}$/, "hex SHA-256 output");

  assert.notEqual(a, await subjectRef(rawKey, "user-456"), "different user → different ref");
  assert.notEqual(a, await subjectRef(otherKey, "user-123"), "different key → different ref (key separation)");

  // An imported HMAC CryptoKey must produce the identical result to raw bytes.
  const imported = await crypto.subtle.importKey(
    "raw",
    rawKey as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  assert.equal(await subjectRef(imported, "user-123"), a, "CryptoKey path == raw-bytes path");
});

// ---------- glue: the subjectRef flows into an assertion the issuer accepts ----------

test("integration: subjectRef → assertion → issuer accept, and one-per-subject holds", async () => {
  const { app } = await issuerApp();
  const hmacKey = crypto.getRandomValues(new Uint8Array(32));
  const ref = await subjectRef(hmacKey, "vendor-user-42");

  const mint = async () =>
    app.request("/issue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        assertion: await mintEligibilityAssertion(
          { surveyId: "survey-1", cohortLabel: "cohort-A", subjectRef: ref, exp: nowExp() },
          vendorKeys.privateKey,
        ),
        blindedMsg: toHex((await blind(mintToken(), issuerPub)).blindedMsg),
      }),
    });

  assert.equal((await mint()).status, 200, "first token issued for the subject");
  assert.equal((await mint()).status, 409, "second token for the same subjectRef refused");
});
