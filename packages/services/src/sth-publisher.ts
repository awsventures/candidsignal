/**
 * STH publisher — the batch job that makes the log *public*.
 *
 * Rebuilds the Merkle tree from the storage layer's canonical log bytes,
 * signs a tree head with the operator's Ed25519 log key, and writes
 * `sth-<size>.json` + `latest.json` to every configured publication target.
 * v1 targets are local directories (dev); the public GitHub repo target
 * (M4-2) plugs into the same list.
 *
 * Byte-fidelity note: storage stored exactly `encodeLogEntry(entry)` output,
 * and canonical JSON is deterministic, so parsing a stored entry back to an
 * object and re-appending it through `MerkleLog.append` reproduces identical
 * leaf bytes. The round-trip test pins this.
 *
 * Auditors verify the published files with the M1-2 audit CLI:
 * `npm run audit -- verify-sth latest.json <logkey.spki.hex>`.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  MerkleLog,
  signTreeHead,
  type SignedTreeHead,
  type LogEntry,
} from "../../anonymity-core/src/index.ts";
import type { Storage } from "./storage.ts";

/** Rebuild the Merkle log from storage (ordered, canonical, validated). */
export async function buildLogFromStorage(storage: Storage): Promise<MerkleLog> {
  const log = new MerkleLog();
  const dec = new TextDecoder();
  for (const bytes of await storage.allLogEntries()) {
    // append re-validates and re-canonicalises; identical bytes by construction.
    await log.append(JSON.parse(dec.decode(bytes)) as LogEntry);
  }
  return log;
}

/**
 * Publish a signed tree head over the log's current state.
 * Creates target directories that don't exist yet.
 */
export async function publishSth(
  storage: Storage,
  logPrivateKey: CryptoKey,
  targets: string[],
): Promise<SignedTreeHead> {
  const log = await buildLogFromStorage(storage);
  const sth = await signTreeHead(log, logPrivateKey);
  const json = JSON.stringify(sth, null, 2) + "\n";
  for (const dir of targets) {
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, `sth-${sth.size}.json`), json);
    await writeFile(join(dir, "latest.json"), json);
  }
  return sth;
}
