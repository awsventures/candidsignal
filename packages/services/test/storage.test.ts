/**
 * Storage-layer invariant tests.
 *
 * The point of this layer is that uniqueness is a DB constraint, not an
 * app-level check-then-write. So the load-bearing tests fire *concurrent*
 * claims and assert the database — not luck — lets exactly one through.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { Storage, type SpendResult } from "../src/storage.ts";
import { encodeLogEntry, type LogEntry } from "../../anonymity-core/src/index.ts";

const TOKEN = "a".repeat(64);
const C1 = "b".repeat(64);
const C2 = "c".repeat(64);

async function fresh(): Promise<Storage> {
  return Storage.open(":memory:");
}

// ---------- spend: idempotency + commitment binding ----------

test("spend: first claim is accepted and not idempotent", async () => {
  const s = await fresh();
  assert.deepEqual(await s.spend({ surveyId: "x", tokenHash: TOKEN, c: C1 }), {
    accepted: true,
    idempotent: false,
  });
  s.close();
});

test("spend: re-presenting the same (token, c) is an idempotent accept", async () => {
  const s = await fresh();
  await s.spend({ surveyId: "x", tokenHash: TOKEN, c: C1 });
  assert.deepEqual(await s.spend({ surveyId: "x", tokenHash: TOKEN, c: C1 }), {
    accepted: true,
    idempotent: true,
  });
  s.close();
});

test("spend: the same token with a different commitment is rejected", async () => {
  const s = await fresh();
  await s.spend({ surveyId: "x", tokenHash: TOKEN, c: C1 });
  assert.deepEqual(await s.spend({ surveyId: "x", tokenHash: TOKEN, c: C2 }), {
    accepted: false,
    reason: "conflicting-commitment",
  });
  s.close();
});

test("double-spend race: concurrent distinct-commitment claims → exactly one wins", async () => {
  const s = await fresh();
  const N = 25;
  // Same token, N *different* commitments racing — the dangerous case: two
  // different responses trying to consume one token. Exactly one must win.
  const results = await Promise.all(
    Array.from({ length: N }, (_, i) =>
      s.spend({ surveyId: "x", tokenHash: TOKEN, c: i.toString(16).padStart(64, "0") }),
    ),
  );
  const firstTime = results.filter((r): r is Extract<SpendResult, { accepted: true }> => r.accepted && !r.idempotent);
  const rejected = results.filter((r) => !r.accepted);
  assert.equal(firstTime.length, 1, "exactly one first-time accept");
  assert.equal(rejected.length, N - 1, "everyone else rejected");
  // And the token is now durably spent: any later different-c claim is rejected.
  const afterward = await s.spend({ surveyId: "x", tokenHash: TOKEN, c: C2 });
  assert.equal(afterward.accepted, false);
  s.close();
});

test("concurrent identical (token, c) → all accepted, exactly one non-idempotent", async () => {
  const s = await fresh();
  const N = 25;
  const results = await Promise.all(
    Array.from({ length: N }, () => s.spend({ surveyId: "x", tokenHash: TOKEN, c: C1 })),
  );
  assert.ok(results.every((r) => r.accepted), "all accepted (same submission retried)");
  const firstTime = results.filter((r) => r.accepted && !r.idempotent);
  assert.equal(firstTime.length, 1, "exactly one first-time accept; the rest idempotent");
  s.close();
});

// ---------- seenSubject: one token per subject per survey ----------

test("seenSubject: first call claims (false), second reports seen (true)", async () => {
  const s = await fresh();
  assert.equal(await s.seenSubject("survey-1", "subject-A"), false);
  assert.equal(await s.seenSubject("survey-1", "subject-A"), true);
  // Same subject ref under a different survey is independent.
  assert.equal(await s.seenSubject("survey-2", "subject-A"), false);
  s.close();
});

test("seenSubject race: concurrent claims of one subject → exactly one first claim", async () => {
  const s = await fresh();
  const N = 25;
  const results = await Promise.all(
    Array.from({ length: N }, () => s.seenSubject("survey-1", "subject-A")),
  );
  const firstClaims = results.filter((seen) => seen === false);
  assert.equal(firstClaims.length, 1, "exactly one call gets to claim the subject");
  s.close();
});

// ---------- appendLog ----------

test("appendLog: sequential indexes and byte-faithful storage", async () => {
  const s = await fresh();
  const e1: LogEntry = { type: "counters", surveyId: "x", issued: 20, redeemed: 3, at: "2026-07-08T04:00Z" };
  const e2: LogEntry = { type: "redeem", surveyId: "x", tokenHash: TOKEN, c: C1, batchTime: "2026-07-08T04:00Z" };
  const seq1 = await s.appendLog(e1);
  const seq2 = await s.appendLog(e2);
  assert.equal(seq2, seq1 + 1, "sequence increments");

  const stored = await s.logEntryBytes(seq1);
  assert.ok(stored, "entry is readable back");
  assert.deepEqual(stored, encodeLogEntry(e1), "stored bytes equal canonical encoding");
  assert.equal(await s.logEntryBytes(9999), null, "absent seq → null");
  s.close();
});

test("appendLog: an invalid entry is rejected, never stored", async () => {
  const s = await fresh();
  await assert.rejects(
    s.appendLog({ type: "mystery" } as unknown as LogEntry),
    /unknown type/,
  );
  s.close();
});

// ---------- counters ----------

test("counters: default to zero, then increment independently", async () => {
  const s = await fresh();
  assert.deepEqual(await s.counters("x"), { issued: 0, redeemed: 0 });
  await s.incrementIssued("x");
  await s.incrementIssued("x");
  await s.incrementRedeemed("x");
  assert.deepEqual(await s.counters("x"), { issued: 2, redeemed: 1 });
  // A different survey is isolated.
  assert.deepEqual(await s.counters("y"), { issued: 0, redeemed: 0 });
  s.close();
});

test("counters: concurrent increments do not lose updates", async () => {
  const s = await fresh();
  const N = 30;
  await Promise.all(Array.from({ length: N }, () => s.incrementIssued("x")));
  assert.equal((await s.counters("x")).issued, N);
  s.close();
});

// ---------- key metadata ----------

test("keys: record, read, destroy", async () => {
  const s = await fresh();
  assert.equal(await s.getKey("k1"), null);
  await s.recordKey({ keyId: "k1", surveyId: "x", spkiHex: "de", createdAt: "2026-07-08T04:00Z" });
  const active = await s.getKey("k1");
  assert.equal(active?.status, "active");
  assert.equal(active?.destroyedAt, null);

  await s.destroyKey("k1", "2026-07-08T06:00Z");
  const dead = await s.getKey("k1");
  assert.equal(dead?.status, "destroyed");
  assert.equal(dead?.destroyedAt, "2026-07-08T06:00Z");
  s.close();
});
