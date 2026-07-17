/**
 * Tests for the canonical encoding layer (docs/canonical-encoding.md).
 * Determinism is the property under test: same logical value → same bytes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  canonicalJson,
  commit,
  newSalt,
  toHex,
  tokenHash,
  coarseTime,
  encodeLogEntry,
  validateLogEntry,
  SALT_LENGTH,
  type LogEntry,
} from "../src/encoding.ts";

const text = (b: Uint8Array) => new TextDecoder().decode(b);

test("canonical JSON: key order is irrelevant, output is byte-identical", () => {
  const a = canonicalJson({ b: 1, a: [true, null, "x"], c: { z: 1, y: 2 } });
  const b = canonicalJson({ c: { y: 2, z: 1 }, a: [true, null, "x"], b: 1 });
  assert.equal(text(a), text(b));
  assert.equal(text(a), '{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}');
});

test("canonical JSON: no whitespace, ECMAScript number forms", () => {
  assert.equal(text(canonicalJson({ n: 1.5, m: 10, z: -0 })), '{"m":10,"n":1.5,"z":0}');
});

test("canonical JSON: rejects non-finite numbers and undefined values", () => {
  assert.throws(() => canonicalJson({ x: NaN }), /non-finite/);
  assert.throws(() => canonicalJson({ x: Infinity }), /non-finite/);
  assert.throws(
    () => canonicalJson({ x: undefined as unknown as null }),
    /undefined/,
  );
});

test("property: canonical JSON is insensitive to construction order", () => {
  fc.assert(
    fc.property(
      fc.dictionary(fc.string(), fc.oneof(fc.integer(), fc.string(), fc.boolean())),
      (obj) => {
        const reversed = Object.fromEntries(Object.entries(obj).reverse());
        assert.equal(text(canonicalJson(obj)), text(canonicalJson(reversed)));
      },
    ),
    { numRuns: 50 },
  );
});

test("commitment: deterministic under same salt, distinct under fresh salt", async () => {
  const payload = { answers: [4, 5, 2], comment: "fine" };
  const salt = newSalt();
  assert.equal(salt.length, SALT_LENGTH);
  const c1 = toHex(await commit(payload, salt));
  const c2 = toHex(await commit({ comment: "fine", answers: [4, 5, 2] }, salt));
  assert.equal(c1, c2, "logically equal payloads must commit identically");
  const c3 = toHex(await commit(payload, newSalt()));
  assert.notEqual(c1, c3, "fresh salt must change the commitment");
});

test("commitment: wrong salt length is refused", async () => {
  await assert.rejects(commit({ a: 1 }, new Uint8Array(16)), /exactly 32/);
});

test("coarseTime truncates to the hour", () => {
  assert.equal(coarseTime(new Date("2026-07-01T15:23:45.678Z")), "2026-07-01T15:00Z");
});

test("log entries: golden canonical forms", async () => {
  const th = await tokenHash(new Uint8Array(64));
  const redeem: LogEntry = {
    type: "redeem",
    surveyId: "eng-pulse-2026Q2",
    tokenHash: th,
    c: th, // any valid hex64 works for the golden-form check
    batchTime: "2026-07-01T15:00Z",
  };
  assert.equal(
    text(encodeLogEntry(redeem)),
    `{"batchTime":"2026-07-01T15:00Z","c":"${th}","surveyId":"eng-pulse-2026Q2","tokenHash":"${th}","type":"redeem"}`,
  );

  const counters: LogEntry = {
    type: "counters",
    surveyId: "s",
    issued: 412,
    redeemed: 388,
    at: "2026-07-01T15:00Z",
  };
  assert.equal(
    text(encodeLogEntry(counters)),
    '{"at":"2026-07-01T15:00Z","issued":412,"redeemed":388,"surveyId":"s","type":"counters"}',
  );
});

test("log entries: validation rejects, never repairs", async () => {
  const th = await tokenHash(new Uint8Array(8));
  const base = {
    type: "redeem",
    surveyId: "s",
    tokenHash: th,
    c: th,
    batchTime: "2026-07-01T15:00Z",
  } as const;

  // unknown type
  assert.throws(
    () => validateLogEntry({ ...base, type: "mystery" } as unknown as LogEntry),
    /unknown type/,
  );
  // extra field
  assert.throws(
    () => validateLogEntry({ ...base, extra: 1 } as unknown as LogEntry),
    /unexpected field/,
  );
  // missing field
  const { c: _c, ...missing } = base;
  assert.throws(() => validateLogEntry(missing as unknown as LogEntry), /missing field/);
  // uppercase / wrong-length hex
  assert.throws(
    () => validateLogEntry({ ...base, c: th.toUpperCase() } as unknown as LogEntry),
    /lowercase hex/,
  );
  // fine-grained timestamp (side-channel discipline)
  assert.throws(
    () => validateLogEntry({ ...base, batchTime: "2026-07-01T15:23Z" } as unknown as LogEntry),
    /coarse ISO time/,
  );
  // negative / non-integer counters
  assert.throws(
    () =>
      validateLogEntry({
        type: "counters",
        surveyId: "s",
        issued: -1,
        redeemed: 0,
        at: "2026-07-01T15:00Z",
      } as unknown as LogEntry),
    /non-negative integer/,
  );
});
