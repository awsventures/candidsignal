/**
 * Storage layer — the durable state behind the trust services.
 *
 * Every uniqueness guarantee that matters (a token is spent at most once; a
 * subject is issued at most one token per survey) is enforced by a **database
 * constraint**, not by application logic. Application logic that "checks then
 * writes" has a race between the check and the write; a UNIQUE index does not.
 * So the spent-set and the one-per-subject rule are UNIQUE keys, and every
 * claim is a single `INSERT ... ON CONFLICT ... RETURNING` statement whose
 * atomicity the database owns. The invariant tests fire concurrent claims to
 * prove exactly one wins.
 *
 * Backed by libSQL (embedded SQLite): a local file in dev, `:memory:` in tests.
 * The interface is deliberately narrow — issuer/verifier/publisher services
 * (M2-2..M2-4) compose these primitives; they do not reach past them into SQL.
 *
 * Log entries are validated and canonicalised through `anonymity-core`'s
 * encoding before they are stored, so what the STH publisher later reads back
 * is byte-identical to what the Merkle log will hash.
 */

import { createClient, type Client } from "@libsql/client";

import {
  encodeLogEntry,
  coarseTime,
  type LogEntry,
} from "../../anonymity-core/src/index.ts";

// ---------- public types ----------

export interface SpendInput {
  surveyId: string;
  /** SHA-256 of the redeemed token, hex — the nullifier. */
  tokenHash: string;
  /** The response commitment c bound to this spend, hex. */
  c: string;
}

export type SpendResult =
  | { accepted: true; idempotent: boolean }
  | { accepted: false; reason: "conflicting-commitment" };

export interface Counters {
  issued: number;
  redeemed: number;
}

export interface KeyMeta {
  keyId: string;
  surveyId: string;
  /** Public key SPKI, hex. */
  spkiHex: string;
  status: "active" | "destroyed";
  createdAt: string;
  destroyedAt: string | null;
}

// ---------- schema ----------

const SCHEMA = [
  // Spent-set: token_hash is the nullifier and the whole point of the table's
  // PRIMARY KEY — one spend per token, enforced by the DB.
  `CREATE TABLE IF NOT EXISTS spent (
     token_hash TEXT PRIMARY KEY,
     survey_id  TEXT NOT NULL,
     c          TEXT NOT NULL,
     at         TEXT NOT NULL
   )`,
  // One token per subject per survey — again a DB constraint, not a lookup.
  `CREATE TABLE IF NOT EXISTS subjects (
     survey_id   TEXT NOT NULL,
     subject_ref TEXT NOT NULL,
     at          TEXT NOT NULL,
     PRIMARY KEY (survey_id, subject_ref)
   )`,
  // Append-only transparency log. seq is the leaf index; entry is the exact
  // canonical JSON the Merkle log will hash (byte-fidelity guaranteed).
  `CREATE TABLE IF NOT EXISTS log (
     seq   INTEGER PRIMARY KEY AUTOINCREMENT,
     entry TEXT NOT NULL,
     at    TEXT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS counters (
     survey_id TEXT PRIMARY KEY,
     issued    INTEGER NOT NULL DEFAULT 0,
     redeemed  INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS keys (
     key_id       TEXT PRIMARY KEY,
     survey_id    TEXT NOT NULL,
     spki_hex     TEXT NOT NULL,
     status       TEXT NOT NULL,
     created_at   TEXT NOT NULL,
     destroyed_at TEXT
   )`,
];

// ---------- storage ----------

export class Storage {
  readonly #client: Client;

  private constructor(client: Client) {
    this.#client = client;
  }

  /**
   * Open a storage layer and ensure the schema exists.
   * @param url libSQL URL — `:memory:` for tests, `file:cbd.db` for dev.
   */
  static async open(url = ":memory:"): Promise<Storage> {
    const client = createClient({ url });
    for (const stmt of SCHEMA) await client.execute(stmt);
    return new Storage(client);
  }

  close(): void {
    this.#client.close();
  }

  /**
   * Claim a token as spent. The UNIQUE token_hash is the arbiter:
   * - first claim wins → `{ accepted: true, idempotent: false }`
   * - re-presenting the *same* `(tokenHash, c)` → `{ accepted: true, idempotent: true }`
   *   (safe to retry; the redeem is not double-counted)
   * - the same token with a *different* `c` → rejected: one token cannot back
   *   two different responses.
   *
   * Spent rows are immutable, so reading the existing `c` after a conflict is
   * race-free.
   */
  async spend(input: SpendInput): Promise<SpendResult> {
    const { surveyId, tokenHash, c } = input;
    const inserted = await this.#client.execute({
      sql: `INSERT INTO spent (token_hash, survey_id, c, at) VALUES (?, ?, ?, ?)
            ON CONFLICT(token_hash) DO NOTHING
            RETURNING token_hash`,
      args: [tokenHash, surveyId, c, coarseTime()],
    });
    if (inserted.rows.length > 0) return { accepted: true, idempotent: false };

    const existing = await this.#client.execute({
      sql: `SELECT c FROM spent WHERE token_hash = ?`,
      args: [tokenHash],
    });
    const existingC = existing.rows[0]?.c as string | undefined;
    if (existingC === c) return { accepted: true, idempotent: true };
    return { accepted: false, reason: "conflicting-commitment" };
  }

  /**
   * Atomically record that `subjectRef` has been issued a token for `surveyId`.
   * Returns whether the subject had **already** been seen: `true` means a token
   * was issued before and the caller (the issuer) must refuse a second one;
   * `false` means this call is the first to claim the subject.
   */
  async seenSubject(surveyId: string, subjectRef: string): Promise<boolean> {
    const claimed = await this.#client.execute({
      sql: `INSERT INTO subjects (survey_id, subject_ref, at) VALUES (?, ?, ?)
            ON CONFLICT(survey_id, subject_ref) DO NOTHING
            RETURNING subject_ref`,
      args: [surveyId, subjectRef, coarseTime()],
    });
    // A returned row means we just claimed it — so it was NOT seen before.
    return claimed.rows.length === 0;
  }

  /** Append a validated log entry; returns its sequence (leaf) index. */
  async appendLog(entry: LogEntry): Promise<number> {
    // encodeLogEntry validates and canonicalises; store the exact bytes as text.
    const canonical = new TextDecoder().decode(encodeLogEntry(entry));
    const res = await this.#client.execute({
      sql: `INSERT INTO log (entry, at) VALUES (?, ?) RETURNING seq`,
      args: [canonical, coarseTime()],
    });
    return Number(res.rows[0].seq);
  }

  /**
   * All log entries in sequence order, as canonical bytes. What the STH
   * publisher hashes — byte-identical to what `appendLog` stored.
   */
  async allLogEntries(): Promise<Uint8Array[]> {
    const res = await this.#client.execute(`SELECT entry FROM log ORDER BY seq`);
    const enc = new TextEncoder();
    return res.rows.map((row) => enc.encode(row.entry as string));
  }

  /** Canonical entry bytes at a log sequence, or null if absent. */
  async logEntryBytes(seq: number): Promise<Uint8Array | null> {
    const res = await this.#client.execute({
      sql: `SELECT entry FROM log WHERE seq = ?`,
      args: [seq],
    });
    const row = res.rows[0];
    if (!row) return null;
    return new TextEncoder().encode(row.entry as string);
  }

  /** Current issued/redeemed counters for a survey (zeros if none recorded). */
  async counters(surveyId: string): Promise<Counters> {
    const res = await this.#client.execute({
      sql: `SELECT issued, redeemed FROM counters WHERE survey_id = ?`,
      args: [surveyId],
    });
    const row = res.rows[0];
    if (!row) return { issued: 0, redeemed: 0 };
    return { issued: Number(row.issued), redeemed: Number(row.redeemed) };
  }

  async incrementIssued(surveyId: string): Promise<void> {
    await this.#client.execute({
      sql: `INSERT INTO counters (survey_id, issued, redeemed) VALUES (?, 1, 0)
            ON CONFLICT(survey_id) DO UPDATE SET issued = issued + 1`,
      args: [surveyId],
    });
  }

  async incrementRedeemed(surveyId: string): Promise<void> {
    await this.#client.execute({
      sql: `INSERT INTO counters (survey_id, issued, redeemed) VALUES (?, 0, 1)
            ON CONFLICT(survey_id) DO UPDATE SET redeemed = redeemed + 1`,
      args: [surveyId],
    });
  }

  /** Record issuer key metadata at creation. */
  async recordKey(meta: Omit<KeyMeta, "status" | "destroyedAt">): Promise<void> {
    await this.#client.execute({
      sql: `INSERT INTO keys (key_id, survey_id, spki_hex, status, created_at, destroyed_at)
            VALUES (?, ?, ?, 'active', ?, NULL)`,
      args: [meta.keyId, meta.surveyId, meta.spkiHex, meta.createdAt],
    });
  }

  /** Mark a key destroyed (per-wave key destruction; no signing after this). */
  async destroyKey(keyId: string, at: string = coarseTime()): Promise<void> {
    await this.#client.execute({
      sql: `UPDATE keys SET status = 'destroyed', destroyed_at = ? WHERE key_id = ?`,
      args: [at, keyId],
    });
  }

  async getKey(keyId: string): Promise<KeyMeta | null> {
    const res = await this.#client.execute({
      sql: `SELECT key_id, survey_id, spki_hex, status, created_at, destroyed_at
            FROM keys WHERE key_id = ?`,
      args: [keyId],
    });
    const row = res.rows[0];
    if (!row) return null;
    return {
      keyId: row.key_id as string,
      surveyId: row.survey_id as string,
      spkiHex: row.spki_hex as string,
      status: row.status as "active" | "destroyed",
      createdAt: row.created_at as string,
      destroyedAt: (row.destroyed_at as string | null) ?? null,
    };
  }
}
