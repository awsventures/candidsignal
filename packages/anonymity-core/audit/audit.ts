/**
 * Public audit CLI — what an outside auditor runs to check the log.
 *
 * The whole point of the transparency log is that nobody has to trust us: given
 * the published artifacts (STHs, log entries, proofs) an independent party can
 * re-derive every claim with off-the-shelf Certificate-Transparency logic. This
 * script is that party's tool. It has ONE job — read plain JSON files off disk
 * and print PASS/FAIL — so an auditor needs no server, no database, and no
 * account; a checkout of this package and Node is the entire dependency.
 *
 * Run it:
 *   node --experimental-strip-types audit/audit.ts <command> [args]
 *   npm run audit -- <command> [args]
 *
 * Commands:
 *   verify-sth        <sth.json> <logkey.spki.hex>
 *   verify-inclusion  <entry.json> <index> <sth.json> <proof.json>
 *   verify-consistency <sth1.json> <sth2.json> <proof.json>
 *   check-counters    <entries.ndjson>
 *
 * File formats (all plain JSON, deliberately):
 *   sth.json      { size, rootHash (hex), at, signature (hex) } — a SignedTreeHead
 *   logkey.spki.hex  the log's Ed25519 public key, SPKI bytes as one hex string
 *   entry.json    a single log entry object ({ type: "redeem", ... } etc.)
 *   proof.json    a JSON array of hex strings (the node hashes of the proof path)
 *   entries.ndjson  one log entry per line (as the log ships them)
 *
 * Exit codes: 0 = PASS, 1 = FAIL (a check did not verify), 2 = usage/IO error.
 */

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  verifyInclusion,
  verifyConsistency,
  verifyTreeHead,
  type SignedTreeHead,
} from "../src/merkle-log.ts";
import {
  encodeLogEntry,
  validateLogEntry,
  type LogEntry,
} from "../src/encoding.ts";

// ---------- small IO / parsing helpers ----------

/** Raised for anything the auditor mistyped or handed us a bad file for. */
class UsageError extends Error {}

function fromHex(hex: string, name: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new UsageError(`${name} is not valid hex`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function readJson(path: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    throw new UsageError(`cannot read file: ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`${path} is not valid JSON`);
  }
}

async function readText(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    throw new UsageError(`cannot read file: ${path}`);
  }
}

/** Shape-check just enough of an STH to fail loudly on the wrong file. */
function asSth(value: unknown, path: string): SignedTreeHead {
  const v = value as Record<string, unknown>;
  if (
    typeof v?.size !== "number" ||
    typeof v?.rootHash !== "string" ||
    typeof v?.at !== "string" ||
    typeof v?.signature !== "string"
  ) {
    throw new UsageError(`${path} is not a signed tree head (need size, rootHash, at, signature)`);
  }
  return v as unknown as SignedTreeHead;
}

/** A proof file is a JSON array of hex strings; decode to node-hash bytes. */
function asProof(value: unknown, path: string): Uint8Array[] {
  if (!Array.isArray(value) || !value.every((x) => typeof x === "string")) {
    throw new UsageError(`${path} must be a JSON array of hex strings`);
  }
  return value.map((h, i) => fromHex(h as string, `${path}[${i}]`));
}

function parseIndex(raw: string): number {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) throw new UsageError(`index must be a non-negative integer, got "${raw}"`);
  return n;
}

// ---------- result reporting ----------

interface Report {
  pass: boolean;
  lines: string[];
}

/** Short hex preview so root hashes stay readable in the terminal. */
function short(hex: string): string {
  return hex.length > 16 ? `${hex.slice(0, 8)}…${hex.slice(-8)}` : hex;
}

// ---------- commands ----------

async function cmdVerifySth(args: string[]): Promise<Report> {
  const [sthPath, keyPath] = args;
  if (!sthPath || !keyPath) throw new UsageError("verify-sth <sth.json> <logkey.spki.hex>");

  const sth = asSth(await readJson(sthPath), sthPath);
  const spki = fromHex(await readText(keyPath), keyPath);

  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      "spki",
      spki as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch {
    throw new UsageError(`${keyPath} is not a valid Ed25519 SPKI public key`);
  }

  const ok = await verifyTreeHead(sth, publicKey);
  return {
    pass: ok,
    lines: ok
      ? [
          `PASS  STH signature is valid.`,
          `      tree size ${sth.size}, root ${short(sth.rootHash)}, at ${sth.at}`,
          `      This root is genuinely the log operator's published head at that size.`,
        ]
      : [
          `FAIL  STH signature does NOT verify against the provided log key.`,
          `      Either the STH was altered or it was not signed by this key.`,
        ],
  };
}

async function cmdVerifyInclusion(args: string[]): Promise<Report> {
  const [entryPath, indexRaw, sthPath, proofPath] = args;
  if (!entryPath || indexRaw === undefined || !sthPath || !proofPath) {
    throw new UsageError("verify-inclusion <entry.json> <index> <sth.json> <proof.json>");
  }

  const index = parseIndex(indexRaw);
  let entryBytes: Uint8Array;
  try {
    entryBytes = encodeLogEntry((await readJson(entryPath)) as LogEntry);
  } catch (e) {
    throw new UsageError(`${entryPath} is not a valid log entry: ${(e as Error).message}`);
  }
  const sth = asSth(await readJson(sthPath), sthPath);
  const proof = asProof(await readJson(proofPath), proofPath);
  const root = fromHex(sth.rootHash, `${sthPath}.rootHash`);

  const ok = await verifyInclusion(entryBytes, index, sth.size, proof, root);
  return {
    pass: ok,
    lines: ok
      ? [
          `PASS  Entry ${index} is included in the log.`,
          `      Its inclusion proof re-derives the STH root ${short(sth.rootHash)} (size ${sth.size}).`,
          `      The log operator cannot have shown this entry to you and a different one to the tree.`,
        ]
      : [
          `FAIL  Entry ${index} is NOT provably in the tree of size ${sth.size}.`,
          `      The proof does not reconstruct root ${short(sth.rootHash)}.`,
          `      Check the entry bytes, the index, and that the proof matches this STH.`,
        ],
  };
}

async function cmdVerifyConsistency(args: string[]): Promise<Report> {
  const [sth1Path, sth2Path, proofPath] = args;
  if (!sth1Path || !sth2Path || !proofPath) {
    throw new UsageError("verify-consistency <sth1.json> <sth2.json> <proof.json>");
  }

  const sth1 = asSth(await readJson(sth1Path), sth1Path);
  const sth2 = asSth(await readJson(sth2Path), sth2Path);
  const proof = asProof(await readJson(proofPath), proofPath);
  const root1 = fromHex(sth1.rootHash, `${sth1Path}.rootHash`);
  const root2 = fromHex(sth2.rootHash, `${sth2Path}.rootHash`);

  const ok = await verifyConsistency(sth1.size, sth2.size, proof, root1, root2);
  return {
    pass: ok,
    lines: ok
      ? [
          `PASS  The log grew append-only from size ${sth1.size} to size ${sth2.size}.`,
          `      Every entry the earlier STH committed to is unchanged in the later one.`,
          `      Nothing was rewritten or deleted between the two heads.`,
        ]
      : [
          `FAIL  Size ${sth2.size} is NOT a consistent extension of size ${sth1.size}.`,
          `      The later tree rewrote or dropped history the earlier STH pinned — an append-only violation.`,
        ],
  };
}

async function cmdCheckCounters(args: string[]): Promise<Report> {
  const [ndjsonPath] = args;
  if (!ndjsonPath) throw new UsageError("check-counters <entries.ndjson>");

  const text = await readText(ndjsonPath);
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);

  // Worst (largest) redeemed-minus-issued gap seen per survey, so one bad
  // counters entry can't be hidden behind a later well-formed one.
  const worst = new Map<string, { issued: number; redeemed: number }>();
  let counted = 0;

  for (let i = 0; i < lines.length; i++) {
    let entry: LogEntry;
    try {
      entry = JSON.parse(lines[i]) as LogEntry;
      validateLogEntry(entry); // rejects corrupted/foreign lines, never repairs
    } catch (e) {
      throw new UsageError(`${ndjsonPath} line ${i + 1}: ${(e as Error).message}`);
    }
    if (entry.type !== "counters") continue;
    counted++;
    const prev = worst.get(entry.surveyId);
    const gap = entry.redeemed - entry.issued;
    if (!prev || gap > prev.redeemed - prev.issued) {
      worst.set(entry.surveyId, { issued: entry.issued, redeemed: entry.redeemed });
    }
  }

  if (counted === 0) {
    return { pass: false, lines: [`FAIL  No counters entries found in ${ndjsonPath}.`] };
  }

  const out: string[] = [];
  let pass = true;
  for (const [surveyId, { issued, redeemed }] of [...worst].sort()) {
    const ok = redeemed <= issued;
    if (!ok) pass = false;
    out.push(
      ok
        ? `  PASS  ${surveyId}: redeemed ${redeemed} ≤ issued ${issued}`
        : `  FAIL  ${surveyId}: redeemed ${redeemed} > issued ${issued}  (more responses than eligible tokens!)`,
    );
  }
  out.unshift(
    pass
      ? `PASS  Every survey redeemed no more tokens than it issued (${worst.size} survey(s), ${counted} counters entries).`
      : `FAIL  At least one survey redeemed more tokens than it issued — integrity is broken.`,
  );
  return { pass, lines: out };
}

// ---------- dispatch ----------

const COMMANDS: Record<string, (args: string[]) => Promise<Report>> = {
  "verify-sth": cmdVerifySth,
  "verify-inclusion": cmdVerifyInclusion,
  "verify-consistency": cmdVerifyConsistency,
  "check-counters": cmdCheckCounters,
};

const USAGE = `anonymity-core audit — verify the transparency log from plain JSON files.

Usage:
  audit verify-sth         <sth.json> <logkey.spki.hex>
  audit verify-inclusion   <entry.json> <index> <sth.json> <proof.json>
  audit verify-consistency <sth1.json> <sth2.json> <proof.json>
  audit check-counters     <entries.ndjson>

Exit codes: 0 = all checks passed, 1 = a check failed, 2 = usage/IO error.`;

export async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (!command || command === "-h" || command === "--help") {
    console.log(USAGE);
    return command ? 0 : 2;
  }
  const handler = COMMANDS[command];
  if (!handler) {
    console.error(`unknown command: ${command}\n\n${USAGE}`);
    return 2;
  }
  try {
    const { pass, lines } = await handler(args);
    console.log(lines.join("\n"));
    return pass ? 0 : 1;
  } catch (e) {
    if (e instanceof UsageError) {
      console.error(`error: ${e.message}`);
      return 2;
    }
    throw e;
  }
}

// Run only when invoked directly (not when imported by tests).
// pathToFileURL handles Windows paths (drive letters, backslashes) correctly.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
