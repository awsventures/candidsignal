/**
 * Tests for the Merkle transparency log. Proof algorithms are exercised
 * exhaustively over small trees (every index × every size, every size pair)
 * rather than sampled — small-tree edge cases are exactly where RFC 6962
 * implementations go wrong.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MerkleLog,
  verifyInclusion,
  verifyConsistency,
  generateLogKey,
  signTreeHead,
  verifyTreeHead,
} from "../src/merkle-log.ts";
import { toHex, type LogEntry } from "../src/encoding.ts";

const N = 9; // exhaustive up to a two-level-unbalanced tree

function entry(i: number): LogEntry {
  return {
    type: "counters",
    surveyId: `s-${i}`,
    issued: i + 20,
    redeemed: i,
    at: "2026-07-01T15:00Z",
  };
}

async function buildLog(n: number): Promise<MerkleLog> {
  const log = new MerkleLog();
  for (let i = 0; i < n; i++) await log.append(entry(i));
  return log;
}

const log = await buildLog(N);

test("empty tree root is SHA-256 of the empty string (RFC 6962)", async () => {
  assert.equal(
    toHex(await new MerkleLog().root()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});

test("append rejects invalid entries (log has no repair path)", async () => {
  const l = new MerkleLog();
  await assert.rejects(
    l.append({ type: "mystery" } as unknown as LogEntry),
    /unknown type/,
  );
  assert.equal(l.size, 0);
});

test("inclusion proofs verify for every index at every tree size", async () => {
  for (let size = 1; size <= N; size++) {
    const root = await log.root(size);
    for (let index = 0; index < size; index++) {
      const proof = await log.inclusionProof(index, size);
      assert.ok(
        await verifyInclusion(log.entryBytes(index), index, size, proof, root),
        `inclusion failed at index=${index} size=${size}`,
      );
    }
  }
});

test("inclusion fails for tampered entries, wrong index, wrong size, wrong root", async () => {
  const size = N;
  const root = await log.root(size);
  const proof = await log.inclusionProof(3, size);

  const tampered = log.entryBytes(3);
  tampered[tampered.length - 2] ^= 0x01;
  assert.equal(await verifyInclusion(tampered, 3, size, proof, root), false);

  assert.equal(await verifyInclusion(log.entryBytes(3), 4, size, proof, root), false);
  assert.equal(await verifyInclusion(log.entryBytes(3), 3, size - 1, proof, root), false);

  const wrongRoot = root.slice();
  wrongRoot[0] ^= 0xff;
  assert.equal(await verifyInclusion(log.entryBytes(3), 3, size, proof, wrongRoot), false);

  // Proof for one entry must not verify another entry.
  assert.equal(await verifyInclusion(log.entryBytes(2), 2, size, proof, root), false);
});

test("consistency proofs verify for every size pair", async () => {
  for (let first = 1; first <= N; first++) {
    for (let second = first; second <= N; second++) {
      const proof = await log.consistencyProof(first, second);
      assert.ok(
        await verifyConsistency(
          first,
          second,
          proof,
          await log.root(first),
          await log.root(second),
        ),
        `consistency failed for ${first} -> ${second}`,
      );
    }
  }
});

test("consistency fails against a forked log (append-only violation)", async () => {
  // A "log" that rewrote entry 2 after an STH at size 4 was published.
  const forked = new MerkleLog();
  for (let i = 0; i < N; i++) {
    await forked.append(i === 2 ? { ...entry(2), redeemed: 999 } : entry(i));
  }
  const proof = await forked.consistencyProof(4, N);
  const honestOldRoot = await log.root(4); // what the published STH pinned
  const forkedNewRoot = await forked.root(N);
  assert.equal(await verifyConsistency(4, N, proof, honestOldRoot, forkedNewRoot), false);
});

test("signed tree heads: round-trip verifies, any field tamper fails", async () => {
  const keys = await generateLogKey();
  const sth = await signTreeHead(log, keys.privateKey);
  assert.equal(sth.size, N);
  assert.ok(await verifyTreeHead(sth, keys.publicKey));

  assert.equal(await verifyTreeHead({ ...sth, size: N - 1 }, keys.publicKey), false);
  assert.equal(
    await verifyTreeHead({ ...sth, rootHash: sth.rootHash.replace(/^./, "f") }, keys.publicKey),
    false,
  );
  assert.equal(
    await verifyTreeHead({ ...sth, at: "2026-07-01T16:00Z" }, keys.publicKey),
    false,
  );

  const otherKeys = await generateLogKey();
  assert.equal(await verifyTreeHead(sth, otherKeys.publicKey), false);
});

test("STH at an earlier size matches the root the log had then", async () => {
  const keys = await generateLogKey();
  const sth5 = await signTreeHead(log, keys.privateKey, 5);
  assert.equal(sth5.rootHash, toHex(await log.root(5)));
  assert.ok(await verifyTreeHead(sth5, keys.publicKey));
});
