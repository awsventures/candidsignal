/**
 * sdk-web tests — the respondent-browser SDK, driven against the REAL services.
 *
 * No mocks of the issuer or verifier: the SDK's fetch is routed to the actual
 * Hono apps from `@aws-cbd/services` in-process, assertions are minted by the
 * real `@aws-cbd/sdk-server`, and the final submission is verified by the real
 * `verifyReceipt` — so wire-format drift between browser SDK, server SDK, and
 * services cannot pass silently.
 *
 * The retry suite is the ⚑ fable-review core (topology ADR §3):
 *   - a redeem whose RESPONSE is lost after the verifier spent the token is
 *     recovered by a fresh client over the same session storage (reload
 *     simulation) and yields the byte-identical receipt, without
 *     double-counting or double-logging;
 *   - the pinned commitment can never change: a different payload after the
 *     first redeem attempt throws locally and no conflicting `c` is ever sent;
 *   - a second token is never minted for one survey attempt, and an issuance
 *     retry re-sends the very same blinded message.
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";

import {
  createSurveyClient,
  MemoryStorage,
  IssueError,
  RedeemError,
  NoTokenError,
  CommitmentMismatchError,
  type VendorSubmission,
} from "../src/index.ts";

import { Storage, createIssuerApp, createVerifierApp } from "../../services/src/index.ts";
import { mintEligibilityAssertion, verifyReceipt } from "../../sdk-server/src/index.ts";
import {
  generateIssuerKey,
  publicKeyOf,
  Issuer,
  toHex,
  TEST_MODULUS_BITS,
  type JsonValue,
} from "../../anonymity-core/src/index.ts";

const SURVEY = "survey-1";
const PAYLOAD: JsonValue = { q1: "agree", q2: 4, q3: ["a", "c"] };

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

let subjectCounter = 0;
async function assertion(overrides: Partial<{ key: CryptoKey; subjectRef: string }> = {}) {
  return mintEligibilityAssertion(
    {
      surveyId: SURVEY,
      cohortLabel: "cohort-A",
      subjectRef: overrides.subjectRef ?? `subject-${++subjectCounter}`,
      exp: Math.floor(Date.now() / 1000) + 300,
    },
    overrides.key ?? vendorKeys.privateKey,
  );
}

/**
 * One in-process deployment: shared storage, real issuer + verifier apps, and
 * a fetch that routes by hostname, records every call, and can inject network
 * failures before dispatch (request never arrived) or after dispatch (the
 * service processed it but the response was lost — the stranded-token window).
 */
async function deployment() {
  const storage = await Storage.open(":memory:");
  const issuerApp = createIssuerApp({
    storage,
    vendorPublicKey: vendorKeys.publicKey,
    issuers: new Map([[SURVEY, { issuer: new Issuer(issuerPair.privateKey), keyId: "key-1" }]]),
  });
  const verifierApp = createVerifierApp({
    storage,
    verifiers: new Map([[SURVEY, { issuerPublicKey: issuerPub }]]),
    receiptSigningKey: receiptKeys.privateKey,
    receiptKeyId: "receipt-key-1",
  });

  const calls: { url: string; body: Record<string, unknown> }[] = [];
  let failBeforeNext = false;
  let failAfterNext = false;

  const fetchFn = async (url: string, init: RequestInit): Promise<Response> => {
    calls.push({ url, body: JSON.parse(init.body as string) as Record<string, unknown> });
    if (failBeforeNext) {
      failBeforeNext = false;
      throw new TypeError("network down (request never sent)");
    }
    const { hostname, pathname } = new URL(url);
    const app = hostname === "issuer" ? issuerApp : verifierApp;
    const res = await app.request(pathname, init);
    if (failAfterNext) {
      failAfterNext = false;
      throw new TypeError("network down (response lost after processing)");
    }
    return res;
  };

  const sessionStore = new MemoryStorage();
  const client = (storageOverride = sessionStore) =>
    createSurveyClient({
      surveyId: SURVEY,
      issuerUrl: "http://issuer",
      verifierUrl: "http://verifier",
      issuerPublicKey: issuerPub,
      storage: storageOverride,
      fetchFn,
    });

  return {
    storage,
    calls,
    sessionStore,
    client,
    fetchFn,
    failBefore: () => (failBeforeNext = true),
    failAfter: () => (failAfterNext = true),
  };
}

// ---------- the whole flow, end to end, against real services ----------

test("happy path: requestToken → redeem → submitToVendor, and sdk-server verifies the receipt", async () => {
  const d = await deployment();
  const c = d.client();

  const issued = await c.requestToken(await assertion());
  assert.equal(issued.keyId, "key-1");
  assert.match(issued.tokenHash, /^[0-9a-f]{64}$/);

  const receipt = await c.redeem(PAYLOAD);
  assert.equal(receipt.tokenHash, issued.tokenHash, "receipt is for the issued token");
  assert.equal(receipt.receiptKeyId, "receipt-key-1");
  assert.match(receipt.salt, /^[0-9a-f]{64}$/, "32-byte salt as hex");

  let delivered: VendorSubmission | null = null;
  const submission = await c.submitToVendor(PAYLOAD, async (s) => {
    delivered = s;
  });
  assert.deepEqual(delivered, submission);
  assert.deepEqual(submission, {
    surveyId: SURVEY,
    payload: PAYLOAD,
    salt: receipt.salt,
    tokenHash: receipt.tokenHash,
    receipt: receipt.receipt,
  });
  // `c` is never on the wire to the vendor — and never in the submission.
  assert.ok(!("c" in submission), "commitment c is not transmitted");

  // The REAL vendor-side check accepts it.
  assert.ok(await verifyReceipt(submission, receiptKeys.publicKey));

  // Vendor acked → session state cleared.
  assert.equal(c.receipt(), null);
  assert.deepEqual(await d.storage.counters(SURVEY), { issued: 1, redeemed: 1 });
});

// ---------- issuance: never a second token, retry-verbatim ----------

test("requestToken is idempotent: a held token is returned without any network call", async () => {
  const d = await deployment();
  const c = d.client();

  const first = await c.requestToken(await assertion());
  const callsAfterFirst = d.calls.length;

  const second = await c.requestToken(await assertion());
  assert.deepEqual(second, first, "same token, same keyId");
  assert.equal(d.calls.length, callsAfterFirst, "no second /issue request");

  // Even a brand-new client over the same session storage (page reload) holds
  // the same token and stays off the network.
  const reloaded = d.client();
  assert.deepEqual(await reloaded.requestToken(await assertion()), first);
  assert.equal(d.calls.length, callsAfterFirst);
  assert.deepEqual(await d.storage.counters(SURVEY), { issued: 1, redeemed: 0 });
});

test("issuance retry after a network failure re-sends the SAME blinded message", async () => {
  const d = await deployment();
  const c = d.client();
  const a = await assertion();

  d.failBefore();
  await assert.rejects(c.requestToken(a), TypeError);

  const issued = await c.requestToken(a);
  assert.match(issued.tokenHash, /^[0-9a-f]{64}$/);

  const issueCalls = d.calls.filter((x) => x.url.endsWith("/issue"));
  assert.equal(issueCalls.length, 2);
  assert.equal(
    issueCalls[0].body.blindedMsg,
    issueCalls[1].body.blindedMsg,
    "retry re-sent the persisted blinded message — no re-mint",
  );
});

test("a forged assertion is rejected by the real issuer; a good retry still uses the same blinded message", async () => {
  const d = await deployment();
  const c = d.client();
  const foreign = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;

  await assert.rejects(
    c.requestToken(await assertion({ key: foreign.privateKey })),
    (e: unknown) => e instanceof IssueError && e.status === 401 && e.code === "invalid-assertion",
  );

  // Recovery with a genuine assertion — same blinded message, token still valid
  // all the way through redemption.
  await c.requestToken(await assertion());
  const issueCalls = d.calls.filter((x) => x.url.endsWith("/issue"));
  assert.equal(issueCalls[0].body.blindedMsg, issueCalls[1].body.blindedMsg);

  const receipt = await c.redeem(PAYLOAD);
  assert.ok(
    await verifyReceipt(
      { surveyId: SURVEY, payload: PAYLOAD, salt: receipt.salt, tokenHash: receipt.tokenHash, receipt: receipt.receipt },
      receiptKeys.publicKey,
    ),
  );
});

// ---------- redemption: the ⚑ retry state machine ----------

test("stranded-token recovery: redeem response lost after the verifier spent the token; a reloaded client recovers the byte-identical receipt", async () => {
  const d = await deployment();
  const c = d.client();
  await c.requestToken(await assertion());

  // The verifier processes the redeem (token IS spent) but the response never
  // reaches the browser — topology ADR §3's stranded-token window.
  d.failAfter();
  await assert.rejects(c.redeem(PAYLOAD), TypeError);
  assert.deepEqual(await d.storage.counters(SURVEY), { issued: 1, redeemed: 1 }, "token really was spent");

  // Page reload: a NEW client over the same session storage retries.
  const reloaded = d.client();
  const receipt = await reloaded.redeem(PAYLOAD);

  const redeemCalls = d.calls.filter((x) => x.url.endsWith("/redeem"));
  assert.equal(redeemCalls.length, 2);
  assert.equal(redeemCalls[0].body.c, redeemCalls[1].body.c, "identical commitment re-presented");
  assert.equal(redeemCalls[0].body.token, redeemCalls[1].body.token, "identical token re-presented");

  // Idempotent re-present: no double-count, no double-log, same receipt bytes.
  assert.deepEqual(await d.storage.counters(SURVEY), { issued: 1, redeemed: 1 });
  const decoder = new TextDecoder();
  const redeemEntries = (await d.storage.allLogEntries())
    .map((bytes) => JSON.parse(decoder.decode(bytes)) as { type: string })
    .filter((e) => e.type === "redeem");
  assert.equal(redeemEntries.length, 1, "exactly one redeem log entry");

  // And the recovered receipt verifies vendor-side.
  assert.ok(
    await verifyReceipt(
      { surveyId: SURVEY, payload: PAYLOAD, salt: receipt.salt, tokenHash: receipt.tokenHash, receipt: receipt.receipt },
      receiptKeys.publicKey,
    ),
  );
});

test("redeem retry after a request-never-sent failure re-presents the same (t, c)", async () => {
  const d = await deployment();
  const c = d.client();
  await c.requestToken(await assertion());

  d.failBefore();
  await assert.rejects(c.redeem(PAYLOAD), TypeError);
  assert.deepEqual(await d.storage.counters(SURVEY), { issued: 1, redeemed: 0 }, "nothing spent yet");

  const receipt = await c.redeem(PAYLOAD);
  const redeemCalls = d.calls.filter((x) => x.url.endsWith("/redeem"));
  assert.equal(redeemCalls.length, 2);
  assert.equal(redeemCalls[0].body.c, redeemCalls[1].body.c, "the pinned c never changed");
  assert.equal(receipt.receiptKeyId, "receipt-key-1");
});

test("redeem on a held receipt returns it from storage without any network call", async () => {
  const d = await deployment();
  const c = d.client();
  await c.requestToken(await assertion());

  const first = await c.redeem(PAYLOAD);
  const callsAfter = d.calls.length;
  const second = await c.redeem(PAYLOAD);
  assert.deepEqual(second, first, "byte-identical receipt");
  assert.equal(d.calls.length, callsAfter, "no network");
});

test("a different payload after the commitment is pinned throws locally — a conflicting c is never transmitted", async () => {
  const d = await deployment();
  const c = d.client();
  await c.requestToken(await assertion());

  // Pin the commitment via a failed first attempt (response lost, token spent).
  d.failAfter();
  await assert.rejects(c.redeem(PAYLOAD), TypeError);

  // Changing the answer now must be refused client-side...
  await assert.rejects(c.redeem({ q1: "disagree" }), CommitmentMismatchError);
  // ...and the same after a receipt is held.
  await c.redeem(PAYLOAD);
  await assert.rejects(c.redeem({ q1: "disagree" }), CommitmentMismatchError);
  await assert.rejects(c.submitToVendor({ q1: "disagree" }), CommitmentMismatchError);

  // Every /redeem that ever hit the wire carried the one pinned c.
  const cs = new Set(d.calls.filter((x) => x.url.endsWith("/redeem")).map((x) => x.body.c));
  assert.equal(cs.size, 1, "exactly one commitment value ever sent");
});

test("concurrent redeems are serialized: same payload → one salt, one spend; different payload → local refusal", async () => {
  const d = await deployment();
  const c = d.client();
  await c.requestToken(await assertion());

  const [r1, r2] = await Promise.all([c.redeem(PAYLOAD), c.redeem(PAYLOAD)]);
  assert.deepEqual(r1, r2, "one pinned salt, identical receipts");
  assert.deepEqual(await d.storage.counters(SURVEY), { issued: 1, redeemed: 1 });

  const results = await Promise.allSettled([c.redeem(PAYLOAD), c.redeem({ q1: "other" })]);
  assert.equal(results[0].status, "fulfilled");
  assert.equal(results[1].status, "rejected");
  assert.ok((results[1] as PromiseRejectedResult).reason instanceof CommitmentMismatchError);
});

// ---------- guardrails & receipt handling ----------

test("redeem before requestToken throws NoTokenError; the verifier's refusal surfaces as RedeemError", async () => {
  const d = await deployment();
  const c = d.client();
  await assert.rejects(c.redeem(PAYLOAD), NoTokenError);

  await c.requestToken(await assertion());
  // Sabotage: copy the held-token state under a survey the verifier doesn't
  // know, and redeem there — the 404 must surface as a typed RedeemError.
  const state = d.sessionStore.getItem(`aws-cbd/sdk-web/v1/${SURVEY}`)!;
  d.sessionStore.setItem("aws-cbd/sdk-web/v1/survey-unknown", state);
  const misconfigured = createSurveyClient({
    surveyId: "survey-unknown",
    issuerUrl: "http://issuer",
    verifierUrl: "http://verifier",
    issuerPublicKey: issuerPub,
    storage: d.sessionStore,
    fetchFn: d.fetchFn,
  });
  await assert.rejects(
    misconfigured.redeem(PAYLOAD),
    (e: unknown) => e instanceof RedeemError && e.status === 404 && e.code === "unknown-survey",
  );
});

test("receipt() is null before redemption, populated after, and clear() abandons the attempt", async () => {
  const d = await deployment();
  const c = d.client();
  assert.equal(c.receipt(), null);

  await c.requestToken(await assertion());
  assert.equal(c.receipt(), null, "token held but nothing redeemed yet");

  const receipt = await c.redeem(PAYLOAD);
  assert.deepEqual(c.receipt(), receipt);
  // A reloaded client sees the same held receipt.
  assert.deepEqual(d.client().receipt(), receipt);

  c.clear();
  assert.equal(c.receipt(), null);
  assert.equal(d.sessionStore.getItem(`aws-cbd/sdk-web/v1/${SURVEY}`), null, "state fully removed");
});

test("submitToVendor without a deliver callback assembles the submission and keeps the state", async () => {
  const d = await deployment();
  const c = d.client();
  await c.requestToken(await assertion());

  const submission = await c.submitToVendor(PAYLOAD);
  assert.ok(await verifyReceipt(submission, receiptKeys.publicKey));
  assert.notEqual(c.receipt(), null, "no vendor ack yet → state retained for retry");

  // Failed delivery must NOT clear the state either.
  await assert.rejects(
    c.submitToVendor(PAYLOAD, async () => {
      throw new Error("vendor 500");
    }),
  );
  assert.notEqual(c.receipt(), null, "state survives a failed vendor submit");

  // Successful delivery clears it.
  await c.submitToVendor(PAYLOAD, async () => {});
  assert.equal(c.receipt(), null);
});
