/**
 * STH-publisher tests.
 *
 * Pins: published files verify with the log public key; a later publish is
 * consistent with an earlier one (append-only, proven via consistency proof);
 * missing target directories are created; and the storage→MerkleLog rebuild
 * is byte-faithful (the root over re-appended entries equals the root over
 * the exact stored bytes).
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Storage } from "../src/storage.ts";
import { buildLogFromStorage, publishSth } from "../src/sth-publisher.ts";
import {
  MerkleLog,
  generateLogKey,
  verifyTreeHead,
  verifyConsistency,
  type SignedTreeHead,
  type LogEntry,
} from "../../anonymity-core/src/index.ts";
import { fromHex } from "../src/http.ts";

let logKeys: CryptoKeyPair;

before(async () => {
  logKeys = await generateLogKey();
});

function entry(n: number): LogEntry {
  return {
    type: "counters",
    surveyId: `survey-${n}`,
    issued: n,
    redeemed: 0,
    at: "2026-07-11T00:00Z",
  };
}

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "sth-pub-"));
}

test("publish: files exist in every target and verify with the log public key", async () => {
  const storage = await Storage.open(":memory:");
  for (let i = 1; i <= 5; i++) await storage.appendLog(entry(i));

  const t1 = await tempDir();
  const t2 = await tempDir();
  try {
    const sth = await publishSth(storage, logKeys.privateKey, [t1, t2]);
    assert.equal(sth.size, 5);

    for (const dir of [t1, t2]) {
      for (const name of [`sth-5.json`, "latest.json"]) {
        const read = JSON.parse(await readFile(join(dir, name), "utf8")) as SignedTreeHead;
        assert.deepEqual(read, sth, `${name} round-trips`);
        assert.ok(await verifyTreeHead(read, logKeys.publicKey), `${name} verifies`);
      }
    }
  } finally {
    storage.close();
    await rm(t1, { recursive: true, force: true });
    await rm(t2, { recursive: true, force: true });
  }
});

test("publish: a second publish after appends is consistent with the first (append-only proof)", async () => {
  const storage = await Storage.open(":memory:");
  for (let i = 1; i <= 3; i++) await storage.appendLog(entry(i));

  const dir = await tempDir();
  try {
    const first = await publishSth(storage, logKeys.privateKey, [dir]);

    for (let i = 4; i <= 8; i++) await storage.appendLog(entry(i));
    const second = await publishSth(storage, logKeys.privateKey, [dir]);

    // Both STH files coexist; latest.json is the second.
    const latest = JSON.parse(await readFile(join(dir, "latest.json"), "utf8")) as SignedTreeHead;
    assert.equal(latest.size, 8);
    const old = JSON.parse(await readFile(join(dir, "sth-3.json"), "utf8")) as SignedTreeHead;
    assert.equal(old.size, 3);

    // The append-only claim, proven: consistency between the two published roots.
    const log = await buildLogFromStorage(storage);
    const proof = await log.consistencyProof(first.size, second.size);
    assert.ok(
      await verifyConsistency(
        first.size,
        second.size,
        proof,
        fromHex(first.rootHash),
        fromHex(second.rootHash),
      ),
    );
  } finally {
    storage.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("publish: a target directory that does not exist is created", async () => {
  const storage = await Storage.open(":memory:");
  await storage.appendLog(entry(1));

  const base = await tempDir();
  const nested = join(base, "does", "not", "exist");
  try {
    const sth = await publishSth(storage, logKeys.privateKey, [nested]);
    const read = JSON.parse(await readFile(join(nested, "latest.json"), "utf8")) as SignedTreeHead;
    assert.deepEqual(read, sth);
  } finally {
    storage.close();
    await rm(base, { recursive: true, force: true });
  }
});

test("rebuild is byte-faithful: root over re-appended entries equals root over stored bytes", async () => {
  const storage = await Storage.open(":memory:");
  for (let i = 1; i <= 6; i++) await storage.appendLog(entry(i));

  try {
    // Root via the publisher's parse-and-reappend path.
    const rebuilt = await buildLogFromStorage(storage);

    // Root via a log fed the raw stored objects directly (no storage round-trip).
    const direct = new MerkleLog();
    for (let i = 1; i <= 6; i++) await direct.append(entry(i));

    assert.deepEqual(await rebuilt.root(), await direct.root());
  } finally {
    storage.close();
  }
});
