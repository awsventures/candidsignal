/**
 * Canonical encoding — the byte-determinism layer.
 *
 * Implements docs/canonical-encoding.md: RFC 8785 (JCS) canonical JSON,
 * response commitments, and transparency-log entry encodings. Everything that
 * gets hashed, signed, or logged goes through this file, because verification
 * across parties and years only works if the bytes are identical.
 *
 * WebCrypto-portable: no Node built-ins.
 */

// ---------- Canonical JSON (RFC 8785 semantics, restricted) ----------

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

function serialize(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("canonical JSON: non-finite numbers are rejected");
      }
      return JSON.stringify(value); // ECMAScript ToString — matches JCS
    case "string":
      return JSON.stringify(value); // JSON.stringify escaping matches JCS
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map(serialize).join(",")}]`;
      }
      // Sort keys by UTF-16 code units (default sort order), per JCS.
      const keys = Object.keys(value).sort();
      const parts = keys.map((k) => {
        const v = (value as { [key: string]: JsonValue })[k];
        if (v === undefined) {
          throw new Error(`canonical JSON: undefined value at key ${JSON.stringify(k)}`);
        }
        return `${JSON.stringify(k)}:${serialize(v)}`;
      });
      return `{${parts.join(",")}}`;
    }
    default:
      throw new Error(`canonical JSON: unsupported type ${typeof value}`);
  }
}

/** Canonical UTF-8 bytes for a JSON value (RFC 8785 semantics). */
export function canonicalJson(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(serialize(value));
}

// ---------- Hex ----------

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

// ---------- Hashing / commitment ----------

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

export const SALT_LENGTH = 32;

/** Fresh 32-byte commitment salt (held by the respondent, given to the vendor). */
export function newSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/**
 * Response commitment: c = SHA-256(salt ‖ canonicalJson(payload)).
 * The fixed-length salt makes the concatenation unambiguous.
 */
export async function commit(payload: JsonValue, salt: Uint8Array): Promise<Uint8Array> {
  if (salt.length !== SALT_LENGTH) {
    throw new Error(`commitment salt must be exactly ${SALT_LENGTH} bytes`);
  }
  const canonical = canonicalJson(payload);
  const input = new Uint8Array(salt.length + canonical.length);
  input.set(salt, 0);
  input.set(canonical, salt.length);
  return sha256(input);
}

/** The log form of a spent token: SHA-256(token), hex. */
export async function tokenHash(token: Uint8Array): Promise<string> {
  return toHex(await sha256(token));
}

/** keyId for key-events: SHA-256 of the public key's SPKI encoding, hex. */
export async function keyId(publicKeySpki: Uint8Array): Promise<string> {
  return toHex(await sha256(publicKeySpki));
}

// ---------- Transparency-log entries ----------

/** Coarse time: ISO 8601 UTC truncated to the hour (side-channel discipline). */
export function coarseTime(date: Date = new Date()): string {
  const iso = date.toISOString(); // 2026-07-01T15:23:45.678Z
  return `${iso.slice(0, 13)}:00Z`;
}

const COARSE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:00Z$/;

export interface RedeemEntry {
  type: "redeem";
  surveyId: string;
  tokenHash: string; // hex SHA-256 of the spent token
  c: string; // hex SHA-256 response commitment
  batchTime: string; // coarse time
}

export interface CountersEntry {
  type: "counters";
  surveyId: string;
  issued: number;
  redeemed: number;
  at: string; // coarse time
}

export interface KeyEventEntry {
  type: "key-event";
  surveyId: string;
  event: "created" | "destroyed";
  keyId: string; // hex SHA-256 of public-key SPKI
  at: string; // coarse time
}

export type LogEntry = RedeemEntry | CountersEntry | KeyEventEntry;

function fail(msg: string): never {
  throw new Error(`log entry rejected: ${msg}`);
}

function requireFields(entry: Record<string, unknown>, fields: string[]): void {
  for (const f of fields) if (!(f in entry)) fail(`missing field ${f}`);
  for (const k of Object.keys(entry)) if (!fields.includes(k)) fail(`unexpected field ${k}`);
}

function requireId(v: unknown, name: string): void {
  if (typeof v !== "string" || v.length === 0) fail(`${name} must be a non-empty string`);
}

function requireHex(v: unknown, name: string): void {
  if (typeof v !== "string" || !SHA256_HEX.test(v)) {
    fail(`${name} must be 64 lowercase hex chars`);
  }
}

function requireCoarseTime(v: unknown, name: string): void {
  if (typeof v !== "string" || !COARSE_TIME.test(v)) {
    fail(`${name} must be coarse ISO time (YYYY-MM-DDTHH:00Z)`);
  }
}

function requireCount(v: unknown, name: string): void {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    fail(`${name} must be a non-negative integer`);
  }
}

/** Validate per spec §4. Rejects, never repairs — a log has no repair path. */
export function validateLogEntry(entry: LogEntry): void {
  const e = entry as unknown as Record<string, unknown>;
  switch (entry.type) {
    case "redeem":
      requireFields(e, ["type", "surveyId", "tokenHash", "c", "batchTime"]);
      requireId(e.surveyId, "surveyId");
      requireHex(e.tokenHash, "tokenHash");
      requireHex(e.c, "c");
      requireCoarseTime(e.batchTime, "batchTime");
      return;
    case "counters":
      requireFields(e, ["type", "surveyId", "issued", "redeemed", "at"]);
      requireId(e.surveyId, "surveyId");
      requireCount(e.issued, "issued");
      requireCount(e.redeemed, "redeemed");
      requireCoarseTime(e.at, "at");
      return;
    case "key-event":
      requireFields(e, ["type", "surveyId", "event", "keyId", "at"]);
      requireId(e.surveyId, "surveyId");
      if (e.event !== "created" && e.event !== "destroyed") {
        fail("event must be 'created' or 'destroyed'");
      }
      requireHex(e.keyId, "keyId");
      requireCoarseTime(e.at, "at");
      return;
    default:
      fail(`unknown type ${String((entry as { type: unknown }).type)}`);
  }
}

/** Canonical leaf bytes for a validated log entry. */
export function encodeLogEntry(entry: LogEntry): Uint8Array {
  validateLogEntry(entry);
  return canonicalJson(entry as unknown as JsonValue);
}
