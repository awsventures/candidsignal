/**
 * Tests for the public audit CLI.
 *
 * Each command is driven end-to-end the way an auditor would drive it: real
 * fixtures (STHs, entries, proofs) are generated with MerkleLog, written to a
 * throwaway temp dir as the exact plain-JSON files the CLI reads, and the CLI's
 * process return code (0 PASS / 1 FAIL / 2 usage) is asserted — plus the
 * human-readable output, since "readable for non-cryptographers" is acceptance.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { main } from "../audit/audit.ts";
import {
  MerkleLog,
  generateLogKey,
  signTreeHead,
} from "../src/merkle-log.ts";
import { toHex, type LogEntry } from "../src/encoding.ts";

// ---------- fixtures ----------

function entry(i: number): LogEntry {
  return {
    type: "counters",
    surveyId: `s-${i}`,
    issued: i + 20,
    redeemed: i,
    at: "2026-07-01T15:00Z",
  };
}

const FIRST_SIZE = 4;
const SECOND_SIZE = 7;

let dir: string;
let log: MerkleLog;
let keys: CryptoKeyPair;

/** Absolute path inside the temp fixture dir. */
const p = (name: string): string => join(dir, name);

async function writeJson(name: string, value: unknown): Promise<string> {
  await writeFile(p(name), JSON.stringify(value));
  return p(name);
}

/** Drive the CLI in-process, capturing return code and printed output. */
async function run(...args: string[]): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const log = console.log;
  const err = console.error;
  console.log = (...a: unknown[]) => chunks.push(a.join(" "));
  console.error = (...a: unknown[]) => chunks.push(a.join(" "));
  try {
    const code = await main(args);
    return { code, out: chunks.join("\n") };
  } finally {
    console.log = log;
    console.error = err;
  }
}

before(async () => {
  dir = await mkdtemp(join(tmpdir(), "cbd-audit-"));
  log = new MerkleLog();
  for (let i = 0; i < SECOND_SIZE; i++) await log.append(entry(i));
  keys = await generateLogKey();

  // Log public key as SPKI hex (what an auditor is handed out of band).
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
  await writeFile(p("logkey.spki.hex"), toHex(spki));

  // Two STHs: an early one and the current head.
  await writeJson("sth1.json", await signTreeHead(log, keys.privateKey, FIRST_SIZE));
  await writeJson("sth2.json", await signTreeHead(log, keys.privateKey, SECOND_SIZE));

  // Inclusion fixture: entry 2 against the current head.
  await writeJson("entry2.json", entry(2));
  await writeJson(
    "inclusion2.json",
    (await log.inclusionProof(2, SECOND_SIZE)).map(toHex),
  );

  // Consistency fixture: FIRST_SIZE -> SECOND_SIZE.
  await writeJson(
    "consistency.json",
    (await log.consistencyProof(FIRST_SIZE, SECOND_SIZE)).map(toHex),
  );

  // Counters ndjson: mixed entry types, all honest (redeemed <= issued).
  await writeFile(
    p("counters.ndjson"),
    [
      JSON.stringify({ type: "counters", surveyId: "spring", issued: 100, redeemed: 40, at: "2026-07-01T15:00Z" }),
      JSON.stringify({ type: "key-event", surveyId: "spring", event: "created", keyId: "a".repeat(64), at: "2026-07-01T15:00Z" }),
      JSON.stringify({ type: "counters", surveyId: "spring", issued: 100, redeemed: 95, at: "2026-07-01T16:00Z" }),
      JSON.stringify({ type: "counters", surveyId: "fall", issued: 30, redeemed: 30, at: "2026-07-01T15:00Z" }),
    ].join("\n") + "\n",
  );

  // Counters ndjson with an integrity break (redeemed > issued).
  await writeFile(
    p("counters-bad.ndjson"),
    [
      JSON.stringify({ type: "counters", surveyId: "spring", issued: 100, redeemed: 40, at: "2026-07-01T15:00Z" }),
      JSON.stringify({ type: "counters", surveyId: "spring", issued: 100, redeemed: 101, at: "2026-07-01T16:00Z" }),
    ].join("\n") + "\n",
  );
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

// ---------- verify-sth ----------

test("verify-sth: PASS on a genuine STH", async () => {
  const { code, out } = await run("verify-sth", p("sth1.json"), p("logkey.spki.hex"));
  assert.equal(code, 0);
  assert.match(out, /PASS/);
});

test("verify-sth: FAIL on a tampered root", async () => {
  const original = JSON.parse(await readFile(p("sth1.json"), "utf8"));
  const tampered = await writeJson("sth-tampered.json", { ...original, rootHash: "f".repeat(64) });
  const { code, out } = await run("verify-sth", tampered, p("logkey.spki.hex"));
  assert.equal(code, 1);
  assert.match(out, /FAIL/);
});

test("verify-sth: usage error (code 2) on a missing key file", async () => {
  const { code } = await run("verify-sth", p("sth1.json"), p("nope.hex"));
  assert.equal(code, 2);
});

// ---------- verify-inclusion ----------

test("verify-inclusion: PASS for a real entry + proof", async () => {
  const { code, out } = await run(
    "verify-inclusion", p("entry2.json"), "2", p("sth2.json"), p("inclusion2.json"),
  );
  assert.equal(code, 0);
  assert.match(out, /PASS/);
});

test("verify-inclusion: FAIL at the wrong index", async () => {
  const { code, out } = await run(
    "verify-inclusion", p("entry2.json"), "3", p("sth2.json"), p("inclusion2.json"),
  );
  assert.equal(code, 1);
  assert.match(out, /FAIL/);
});

test("verify-inclusion: FAIL for a tampered entry", async () => {
  const bad = await writeJson("entry2-bad.json", { ...entry(2), redeemed: 999 });
  const { code } = await run(
    "verify-inclusion", bad, "2", p("sth2.json"), p("inclusion2.json"),
  );
  assert.equal(code, 1);
});

test("verify-inclusion: usage error on a non-integer index", async () => {
  const { code } = await run(
    "verify-inclusion", p("entry2.json"), "two", p("sth2.json"), p("inclusion2.json"),
  );
  assert.equal(code, 2);
});

// ---------- verify-consistency ----------

test("verify-consistency: PASS for an append-only extension", async () => {
  const { code, out } = await run(
    "verify-consistency", p("sth1.json"), p("sth2.json"), p("consistency.json"),
  );
  assert.equal(code, 0);
  assert.match(out, /PASS/);
});

test("verify-consistency: FAIL when the proof is for the wrong pair", async () => {
  // Reuse the FIRST->SECOND proof but claim it proves SECOND->SECOND.
  const { code } = await run(
    "verify-consistency", p("sth2.json"), p("sth2.json"), p("consistency.json"),
  );
  assert.equal(code, 1);
});

// ---------- check-counters ----------

test("check-counters: PASS when every survey has redeemed <= issued", async () => {
  const { code, out } = await run("check-counters", p("counters.ndjson"));
  assert.equal(code, 0);
  assert.match(out, /PASS/);
  assert.match(out, /spring/);
  assert.match(out, /fall/);
});

test("check-counters: FAIL when a survey redeemed more than it issued", async () => {
  const { code, out } = await run("check-counters", p("counters-bad.ndjson"));
  assert.equal(code, 1);
  assert.match(out, /FAIL/);
});

// ---------- dispatch / usage ----------

test("unknown command exits 2", async () => {
  const { code } = await run("frobnicate");
  assert.equal(code, 2);
});

test("--help exits 0", async () => {
  const { code, out } = await run("--help");
  assert.equal(code, 0);
  assert.match(out, /Usage:/);
});

test("no command prints usage and exits 2", async () => {
  const { code } = await run();
  assert.equal(code, 2);
});
