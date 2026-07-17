/**
 * Tests for the key-lifecycle partition protocol: the k_issue floor,
 * auditable key events, and sign-after-destroy refusal.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { IssuancePartition, K_ISSUE_FLOOR } from "../src/key-lifecycle.ts";
import { validateLogEntry } from "../src/encoding.ts";
import {
  mintToken,
  blind,
  unblind,
  Issuer,
  Verifier,
  TEST_MODULUS_BITS,
} from "../src/index.ts";

const opts = {
  surveyId: "eng-pulse-2026Q2:cohort-eng",
  expectedTokenCount: K_ISSUE_FLOOR,
  modulusBits: TEST_MODULUS_BITS,
};

test("partition below the k_issue floor is refused, at the floor accepted", async () => {
  await assert.rejects(
    IssuancePartition.create({ ...opts, expectedTokenCount: K_ISSUE_FLOOR - 1 }),
    /anonymity-set floor/,
  );
  const partition = await IssuancePartition.create(opts);
  assert.equal(partition.destroyed, false);
});

test("created and destroyed events are spec-valid log entries with the same keyId", async () => {
  const partition = await IssuancePartition.create(opts);
  assert.doesNotThrow(() => validateLogEntry(partition.createdEntry));
  assert.equal(partition.createdEntry.event, "created");

  const destroyedEntry = partition.destroy();
  assert.doesNotThrow(() => validateLogEntry(destroyedEntry));
  assert.equal(destroyedEntry.event, "destroyed");
  assert.equal(destroyedEntry.keyId, partition.createdEntry.keyId);
});

test("after destroy: signing is impossible, verifying earlier tokens still works", async () => {
  const partition = await IssuancePartition.create(opts);
  const issuer = new Issuer(partition.privateKey);

  // Issue one token while the partition is live.
  const req = await blind(mintToken(), partition.publicKey);
  const signed = await unblind(req, await issuer.blindSign(req.blindedMsg, true), partition.publicKey);

  partition.destroy();

  // No further signatures can exist…
  assert.throws(() => partition.privateKey, /destroyed/);
  assert.throws(() => partition.destroy(), /already destroyed/);

  // …but redemption of already-issued tokens (grace window) is unaffected:
  // verification needs only the public key.
  const verifier = new Verifier(partition.publicKey);
  assert.deepEqual(await verifier.redeem(signed), { accepted: true });
});
