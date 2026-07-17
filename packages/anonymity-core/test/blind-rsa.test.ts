/**
 * Tests for the blind-token anonymity core (RFC 9474 / RSABSSA via
 * @cloudflare/blindrsa-ts). Runs on Node's built-in test runner:  npm test
 *
 * RFC 9474 conformance vectors and fast-check property tests are plan task
 * M0-2 and land separately.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateIssuerKey,
  publicKeyOf,
  mintToken,
  blind,
  unblind,
  Issuer,
  Verifier,
  TEST_MODULUS_BITS,
} from "../src/index.ts";

// One key pair reused across tests for speed (2048-bit permitted in tests
// per the crypto-primitive ADR; production default is 3072).
const pair = await generateIssuerKey(TEST_MODULUS_BITS);
const pub = publicKeyOf(pair);

async function issueOne(issuer: Issuer) {
  const req = await blind(mintToken(), pub);
  const blindSig = await issuer.blindSign(req.blindedMsg, true);
  return unblind(req, blindSig, pub);
}

test("happy path: issued token verifies and redeems once", async () => {
  const issuer = new Issuer(pair.privateKey);
  const verifier = new Verifier(pub);

  const signed = await issueOne(issuer);

  assert.ok(await verifier.isValidSignature(signed), "signature should verify");
  assert.deepEqual(await verifier.redeem(signed), { accepted: true });
  assert.equal(issuer.issuedCount, 1);
  assert.equal(verifier.spentCount, 1);
});

test("double-spend is rejected", async () => {
  const issuer = new Issuer(pair.privateKey);
  const verifier = new Verifier(pub);
  const signed = await issueOne(issuer);

  assert.deepEqual(await verifier.redeem(signed), { accepted: true });
  assert.deepEqual(await verifier.redeem(signed), {
    accepted: false,
    reason: "already-spent",
  });
  assert.equal(verifier.spentCount, 1);
});

test("forged signature is rejected", async () => {
  const verifier = new Verifier(pub);
  const forged = {
    token: mintToken(),
    signature: crypto.getRandomValues(new Uint8Array(TEST_MODULUS_BITS / 8)),
  };
  assert.deepEqual(await verifier.redeem(forged), {
    accepted: false,
    reason: "invalid-signature",
  });
});

test("tampered token is rejected", async () => {
  const issuer = new Issuer(pair.privateKey);
  const verifier = new Verifier(pub);
  const signed = await issueOne(issuer);

  const tampered = { token: signed.token.slice(), signature: signed.signature };
  tampered.token[0] ^= 0xff;
  assert.deepEqual(await verifier.redeem(tampered), {
    accepted: false,
    reason: "invalid-signature",
  });
});

test("signature from a different issuer key is rejected", async () => {
  const otherPair = await generateIssuerKey(TEST_MODULUS_BITS);
  const otherIssuer = new Issuer(otherPair.privateKey);
  const verifier = new Verifier(pub); // expects OUR issuer's key

  // Issue a perfectly valid token — under the wrong key.
  const req = await blind(mintToken(), publicKeyOf(otherPair));
  const blindSig = await otherIssuer.blindSign(req.blindedMsg, true);
  const signed = await unblind(req, blindSig, publicKeyOf(otherPair));

  assert.deepEqual(await verifier.redeem(signed), {
    accepted: false,
    reason: "invalid-signature",
  });
});

test("ineligible respondent is refused issuance", async () => {
  const issuer = new Issuer(pair.privateKey);
  const req = await blind(mintToken(), pub);
  await assert.rejects(issuer.blindSign(req.blindedMsg, false), /not eligible/);
  assert.equal(issuer.issuedCount, 0, "refused signings must not count as issued");
});

test("client rejects a corrupted blind signature at finalize", async () => {
  const issuer = new Issuer(pair.privateKey);
  const req = await blind(mintToken(), pub);
  const blindSig = await issuer.blindSign(req.blindedMsg, true);
  blindSig[0] ^= 0xff;
  await assert.rejects(unblind(req, blindSig, pub));
});

test("unlinkability shape: what the issuer sees is disjoint from what is redeemed", async () => {
  const issuer = new Issuer(pair.privateKey);
  const req = await blind(mintToken(), pub);
  const blindSig = await issuer.blindSign(req.blindedMsg, true);
  const signed = await unblind(req, blindSig, pub);

  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
  // The issuer's entire view is `blindedMsg`; neither the redeemed token nor
  // the final signature ever equals it (nor the blind signature it produced).
  assert.notEqual(hex(req.blindedMsg), hex(signed.token));
  assert.notEqual(hex(req.blindedMsg), hex(signed.signature));
  assert.notEqual(hex(blindSig), hex(signed.signature));
  assert.ok(await new Verifier(pub).isValidSignature(signed));
});

test("randomized preparation: same seed yields distinct tokens (RFC 9474 Randomized variant)", async () => {
  const seed = mintToken();
  const a = await blind(seed, pub);
  const b = await blind(seed, pub);
  const hex = (x: Uint8Array) => Buffer.from(x).toString("hex");
  assert.notEqual(hex(a.token), hex(b.token), "prepare() must add a fresh randomizer");
});
