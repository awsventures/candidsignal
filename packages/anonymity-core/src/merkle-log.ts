/**
 * Merkle transparency log — the integrity anchor's core.
 *
 * An append-only Merkle tree over canonical log entries, with signed tree
 * heads (STHs), inclusion proofs, and consistency proofs. Hashing follows
 * RFC 6962 (domain separation: 0x00 for leaves, 0x01 for interior nodes);
 * proof verification follows the algorithms in RFC 9162 §2.1.3.2 / §2.1.4.2
 * so that third-party verifiers can check our proofs with off-the-shelf
 * Certificate-Transparency logic.
 *
 * The verification functions are standalone (no log instance needed): they
 * are what the public audit script and external auditors run.
 *
 * See docs/canonical-encoding.md for entry byte formats and
 * adr/2026-07-01-integrity-anchor-transparency-log.md for the design.
 */

import { canonicalJson, coarseTime, toHex, encodeLogEntry, type LogEntry } from "./encoding.ts";

// ---------- Hashing (RFC 6962 domain separation) ----------

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  let total = 0;
  for (const p of parts) total += p.length;
  const input = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    input.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input as BufferSource));
}

/** Leaf hash: SHA-256(0x00 ‖ entryBytes). */
export async function leafHash(entryBytes: Uint8Array): Promise<Uint8Array> {
  return sha256(LEAF_PREFIX, entryBytes);
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(NODE_PREFIX, left, right);
}

/** Largest power of two strictly less than n (n ≥ 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- The log ----------

export class MerkleLog {
  readonly #entries: Uint8Array[] = [];
  readonly #leafHashes: Uint8Array[] = [];

  /** Append a validated entry. Returns its leaf index. */
  async append(entry: LogEntry): Promise<number> {
    const bytes = encodeLogEntry(entry); // validates; rejects garbage
    this.#entries.push(bytes);
    this.#leafHashes.push(await leafHash(bytes));
    return this.#entries.length - 1;
  }

  get size(): number {
    return this.#entries.length;
  }

  /** The canonical bytes of entry `index` (what gets shipped to auditors). */
  entryBytes(index: number): Uint8Array {
    const e = this.#entries[index];
    if (e === undefined) throw new Error(`no entry at index ${index}`);
    return e.slice();
  }

  /** MTH over leaves [lo, hi) per RFC 6962. */
  async #mth(lo: number, hi: number): Promise<Uint8Array> {
    const n = hi - lo;
    if (n === 0) return sha256(); // MTH({}) = SHA-256("")
    if (n === 1) return this.#leafHashes[lo];
    const k = splitPoint(n);
    const [left, right] = await Promise.all([
      this.#mth(lo, lo + k),
      this.#mth(lo + k, hi),
    ]);
    return nodeHash(left, right);
  }

  /** Tree root over the first `size` entries (defaults to the full log). */
  async root(size: number = this.size): Promise<Uint8Array> {
    if (size < 0 || size > this.size) throw new Error(`invalid tree size ${size}`);
    return this.#mth(0, size);
  }

  /** RFC 6962 PATH(m, D[n]): inclusion proof for leaf `index` in tree `size`. */
  async inclusionProof(index: number, size: number = this.size): Promise<Uint8Array[]> {
    if (size < 1 || size > this.size) throw new Error(`invalid tree size ${size}`);
    if (index < 0 || index >= size) throw new Error(`index ${index} not in tree of size ${size}`);
    const path = async (m: number, lo: number, hi: number): Promise<Uint8Array[]> => {
      const n = hi - lo;
      if (n === 1) return [];
      const k = splitPoint(n);
      if (m < k) {
        return [...(await path(m, lo, lo + k)), await this.#mth(lo + k, hi)];
      }
      return [...(await path(m - k, lo + k, hi)), await this.#mth(lo, lo + k)];
    };
    return path(index, 0, size);
  }

  /** RFC 6962 PROOF(m, D[n]): consistency proof from size `first` to `second`. */
  async consistencyProof(first: number, second: number = this.size): Promise<Uint8Array[]> {
    if (first < 1 || second > this.size || first > second) {
      throw new Error(`invalid consistency range ${first} -> ${second}`);
    }
    const subproof = async (
      m: number,
      lo: number,
      hi: number,
      complete: boolean,
    ): Promise<Uint8Array[]> => {
      const n = hi - lo;
      if (m === n) {
        return complete ? [] : [await this.#mth(lo, hi)];
      }
      const k = splitPoint(n);
      if (m <= k) {
        return [...(await subproof(m, lo, lo + k, complete)), await this.#mth(lo + k, hi)];
      }
      return [...(await subproof(m - k, lo + k, hi, false)), await this.#mth(lo, lo + k)];
    };
    return subproof(first, 0, second, true);
  }
}

// ---------- Standalone verification (what auditors run) ----------

/**
 * Verify an inclusion proof (RFC 9162 §2.1.3.2).
 * `entryBytes` are the canonical entry bytes; the leaf hash is derived here so
 * a caller cannot accidentally skip domain separation.
 */
export async function verifyInclusion(
  entryBytes: Uint8Array,
  index: number,
  size: number,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (index < 0 || size < 1 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = await leafHash(entryBytes);
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(r, root);
}

/**
 * Verify a consistency proof between two tree sizes (RFC 9162 §2.1.4.2):
 * that the tree of size `second` with root `secondRoot` is an append-only
 * extension of the tree of size `first` with root `firstRoot`.
 */
export async function verifyConsistency(
  first: number,
  second: number,
  proof: Uint8Array[],
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
): Promise<boolean> {
  if (first < 1 || first > second) return false;
  if (first === second) {
    return proof.length === 0 && equalBytes(firstRoot, secondRoot);
  }
  // If first is an exact power of two, prepend firstRoot to the path.
  const path = (first & (first - 1)) === 0 ? [firstRoot, ...proof] : [...proof];
  if (path.length === 0) return false;

  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0];
  let sr = path[0];
  for (const p of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(p, fr);
      sr = await nodeHash(p, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = await nodeHash(sr, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(fr, firstRoot) && equalBytes(sr, secondRoot);
}

// ---------- Signed tree heads ----------

export interface SignedTreeHead {
  size: number;
  rootHash: string; // hex
  at: string; // coarse time
  signature: string; // hex Ed25519 over canonicalJson({at, rootHash, size})
}

function sthMessage(sth: Pick<SignedTreeHead, "size" | "rootHash" | "at">): Uint8Array {
  return canonicalJson({ at: sth.at, rootHash: sth.rootHash, size: sth.size });
}

/** Generate the log operator's STH signing key (Ed25519). */
export async function generateLogKey(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

/** Produce a signed tree head for the log's current (or given) size. */
export async function signTreeHead(
  log: MerkleLog,
  privateKey: CryptoKey,
  size: number = log.size,
  at: string = coarseTime(),
): Promise<SignedTreeHead> {
  const rootHash = toHex(await log.root(size));
  const head = { size, rootHash, at };
  const sig = await crypto.subtle.sign("Ed25519", privateKey, sthMessage(head) as BufferSource);
  return { ...head, signature: toHex(new Uint8Array(sig)) };
}

/** Verify an STH signature (auditors run this against the published log key). */
export async function verifyTreeHead(
  sth: SignedTreeHead,
  publicKey: CryptoKey,
): Promise<boolean> {
  const sig = Uint8Array.from(
    sth.signature.match(/.{2}/g)?.map((h) => parseInt(h, 16)) ?? [],
  );
  try {
    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      sig as BufferSource,
      sthMessage(sth) as BufferSource,
    );
  } catch {
    return false;
  }
}
