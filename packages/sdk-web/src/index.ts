/**
 * AWS Confidential-by-Design — `sdk-web` (respondent browser SDK).
 *
 * This is what a survey vendor's page embeds so the respondent's browser can
 * participate in Profile A of the topology ADR
 * (docs/04-implementation-plan/adr/2026-07-01-data-flow-topology.md) without
 * any secret ever reaching a server:
 *
 *   1. `requestToken(assertion)` — mint a random token, blind it locally, send
 *      only the blinded message (plus the vendor's eligibility assertion) to
 *      the issuer, and unblind the returned blind-signature. The issuer signs
 *      something it cannot read and can never recognise again.
 *   2. `redeem(payload)` — commit to the answer (`c = SHA-256(salt ‖
 *      canonicalJson(payload))`), present `{token, signature, c}` to the
 *      verifier, and receive the commitment-bound Ed25519 receipt.
 *   3. `submitToVendor(payload, deliver?)` — assemble the vendor submission
 *      `{surveyId, payload, salt(hex), tokenHash, receipt}` that the
 *      `sdk-server` `verifyReceipt` consumes (`c` is NEVER transmitted — the
 *      vendor recomputes it from the stored answer).
 *   4. `receipt()` / `clear()` — receipt handling: read the held receipt, and
 *      clear the session state once the vendor has acknowledged the answer.
 *
 * ## Retry state machine (the trust-load-bearing part — topology ADR §3)
 *
 * State lives in session-scoped storage (`window.sessionStorage` in browsers;
 * injectable for tests), one entry per surveyId, and every network call is
 * preceded by persisting exactly the material needed to repeat it verbatim:
 *
 *   PHASE 0  (empty)      —requestToken→  persist {token, blindedMsg, inv}
 *                                          BEFORE POST /issue
 *   PHASE 1  blind-held   —200→           persist {token, signature}; drop inv
 *                          —failure→       state unchanged; retry re-sends the
 *                                          SAME blindedMsg (never re-mint)
 *   PHASE 2  token-held   —redeem→        persist {salt, c} BEFORE POST /redeem
 *   PHASE 3  committed    —200→           persist receipt
 *                          —failure→       state unchanged; retry re-presents
 *                                          the SAME (token, c) and the verifier
 *                                          (idempotent on (t, c)) returns the
 *                                          byte-identical receipt
 *   PHASE 4  receipt-held —submit ack→    clear()
 *
 * Consequences, each pinned by a test:
 *   - The SDK never mints a second token for one survey attempt: a held (or
 *     pending) token short-circuits `requestToken`, and `redeem` only ever uses
 *     the persisted one.
 *   - A token spent with the response lost (network blip after the verifier
 *     processed the redeem, or a page reload in that window) is recoverable:
 *     `{token, signature, salt, c}` were persisted before the POST, so the
 *     retry re-presents the same pair and recovers the same receipt.
 *   - `c` can never change across retries: the commitment is pinned in storage
 *     at the first redeem attempt. Calling `redeem` with a *different* payload
 *     after pinning throws `CommitmentMismatchError` locally — the SDK refuses
 *     to even send a conflicting commitment (the verifier would 409 it as a
 *     double-spend). One attempt, one answer.
 *   - State is cleared on vendor ack (not at redemption): clearing earlier
 *     would reopen the stranded-token window across a reload — the receipt and
 *     salt are exactly what recovery needs. This is the ADR §3 rule taking
 *     precedence over eager hygiene; nothing held is identity-linkable either
 *     way (browser-delivery ADR §5).
 *
 * Runtime surface: anonymity-core only (pure TS on WebCrypto per the
 * browser-delivery ADR — no WASM, no other runtime dependency). `fetch` and
 * storage are injectable so tests drive the real Hono services in-process.
 */

import { mintToken, blind, unblind } from "../../anonymity-core/src/client.ts";
import type { SignedToken } from "../../anonymity-core/src/client.ts";
import { commit, newSalt, toHex, tokenHash } from "../../anonymity-core/src/encoding.ts";
import type { JsonValue } from "../../anonymity-core/src/encoding.ts";

// ---------- errors ----------

/** The issuer refused (or the request never completed cleanly). Retryable
 * unless `status` says otherwise (401 forged/expired assertion, 409
 * already-issued). */
export class IssueError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(`issuer refused: ${status} ${code}`);
    this.name = "IssueError";
    this.status = status;
    this.code = code;
  }
}

/** The verifier refused the redemption. */
export class RedeemError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(`verifier refused: ${status} ${code}`);
    this.name = "RedeemError";
    this.status = status;
    this.code = code;
  }
}

/** `redeem`/`submitToVendor` was called before `requestToken` succeeded. */
export class NoTokenError extends Error {
  constructor() {
    super("no signed token held for this survey — call requestToken first");
    this.name = "NoTokenError";
  }
}

/** A commitment is already pinned for this attempt and the payload given now
 * hashes to a different `c`. The SDK refuses to transmit a conflicting
 * commitment: the answer for this attempt is already fixed. */
export class CommitmentMismatchError extends Error {
  constructor() {
    super(
      "a different answer was already committed for this survey attempt; " +
        "re-present the original payload or clear() to abandon the attempt",
    );
    this.name = "CommitmentMismatchError";
  }
}

// ---------- injectable surfaces ----------

/** The subset of the Web Storage API the SDK uses. `window.sessionStorage`
 * satisfies it in browsers; tests inject a Map-backed stand-in. */
export interface WebStorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** Minimal in-memory fallback (Node tests without injection; also the ADR's
 * preferred "in memory where possible" mode if a caller passes one in). */
export class MemoryStorage implements WebStorageLike {
  private readonly map = new Map<string, string>();
  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

// ---------- config & result types ----------

export interface SurveyClientConfig {
  surveyId: string;
  /** Base URL of the hosted issuer service (no trailing slash needed). */
  issuerUrl: string;
  /** Base URL of the hosted verifier service. */
  verifierUrl: string;
  /** The survey's RSA issuer public key (validates the blind signature). */
  issuerPublicKey: CryptoKey;
  /** Session-scoped storage; defaults to `window.sessionStorage` when present,
   * else an in-memory store (single-page-lifetime only). */
  storage?: WebStorageLike;
  /** Injectable fetch (tests dispatch to in-process Hono apps). */
  fetchFn?: FetchLike;
}

/** What redemption yields — everything the vendor submission needs. */
export interface HeldReceipt {
  /** Ed25519 receipt hex over canonicalJson({c, surveyId, tokenHash}). */
  receipt: string;
  /** Which verifier key signed it (vendors pick the right pin). */
  receiptKeyId: string;
  /** SHA-256(token) hex, echoed by the verifier. */
  tokenHash: string;
  /** Commitment salt, hex — the vendor stores it beside the payload. */
  salt: string;
}

/** The vendor-submit contract fixed in M3-1 (see sdk-server README):
 * `c` is deliberately absent — the vendor recomputes it from payload+salt. */
export interface VendorSubmission {
  surveyId: string;
  payload: JsonValue;
  /** 32-byte commitment salt, hex. */
  salt: string;
  tokenHash: string;
  receipt: string;
}

// ---------- persisted state (all fields hex) ----------

interface StateV1 {
  v: 1;
  /** Pending issuance: persisted BEFORE POST /issue so a retry re-sends the
   * same blinded message and never re-mints. `inv` never leaves this store. */
  blind?: { token: string; blindedMsg: string; inv: string };
  /** Held token (issuance finalized; `inv` dropped). */
  signed?: { token: string; signature: string; keyId: string };
  /** Pinned commitment: persisted BEFORE POST /redeem. Once present, `c` for
   * this attempt can never change. */
  commitment?: { salt: string; c: string };
  /** Held receipt (redemption acknowledged). */
  receipt?: { receipt: string; receiptKeyId: string; tokenHash: string };
}

// ---------- hex ----------

function fromHex(hex: string): Uint8Array {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("not hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function errorCode(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: unknown };
    return typeof body?.error === "string" ? body.error : "unknown";
  } catch {
    return "unknown";
  }
}

function trimSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

// ---------- the client ----------

export interface SurveyClient {
  /** (1) Obtain a signed token via blind issuance. Idempotent: a held token is
   * returned from storage without touching the network; a pending (persisted)
   * blinded request is re-sent verbatim. */
  requestToken(assertion: string): Promise<{ tokenHash: string; keyId: string }>;
  /** (2) Redeem the held token for a commitment-bound receipt. Safe to retry:
   * the same (token, c) is re-presented and the verifier returns the identical
   * receipt. A held receipt is returned without touching the network. */
  redeem(payload: JsonValue): Promise<HeldReceipt>;
  /** (3) Vendor-submit glue: ensure a receipt (redeeming if needed), assemble
   * the `{surveyId, payload, salt, tokenHash, receipt}` submission, optionally
   * deliver it, and clear session state once delivery succeeds. */
  submitToVendor(
    payload: JsonValue,
    deliver?: (submission: VendorSubmission) => Promise<void>,
  ): Promise<VendorSubmission>;
  /** (4) The held receipt, or null before redemption. */
  receipt(): HeldReceipt | null;
  /** Abandon/complete the attempt: remove all session state for the survey. */
  clear(): void;
}

export function createSurveyClient(config: SurveyClientConfig): SurveyClient {
  const surveyId = config.surveyId;
  const issuerUrl = trimSlash(config.issuerUrl);
  const verifierUrl = trimSlash(config.verifierUrl);
  const storage: WebStorageLike =
    config.storage ??
    ((globalThis as { sessionStorage?: WebStorageLike }).sessionStorage ?? new MemoryStorage());
  const fetchFn: FetchLike =
    config.fetchFn ?? ((url, init) => (globalThis.fetch as FetchLike)(url, init));

  const storageKey = `aws-cbd/sdk-web/v1/${surveyId}`;

  function load(): StateV1 {
    const raw = storage.getItem(storageKey);
    if (raw === null) return { v: 1 };
    const parsed = JSON.parse(raw) as StateV1;
    if (parsed.v !== 1) throw new Error(`unsupported sdk-web state version: ${String(parsed.v)}`);
    return parsed;
  }
  function save(state: StateV1): void {
    storage.setItem(storageKey, JSON.stringify(state));
  }

  // Serialize all mutating operations: two overlapping redeem() calls must not
  // race to pin two different salts.
  let chain: Promise<unknown> = Promise.resolve();
  function locked<T>(fn: () => Promise<T>): Promise<T> {
    const run = chain.then(fn);
    chain = run.catch(() => undefined);
    return run;
  }

  async function post(url: string, body: unknown): Promise<Response> {
    return fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  function heldReceipt(state: StateV1): HeldReceipt | null {
    if (!state.receipt || !state.commitment) return null;
    return { ...state.receipt, salt: state.commitment.salt };
  }

  /** Recompute c under the pinned salt and refuse a diverging payload. */
  async function assertPinned(state: StateV1, payload: JsonValue): Promise<void> {
    const pin = state.commitment!;
    const c = toHex(await commit(payload, fromHex(pin.salt)));
    if (c !== pin.c) throw new CommitmentMismatchError();
  }

  const client: SurveyClient = {
    requestToken(assertion: string) {
      return locked(async () => {
        const state = load();

        // Held token → never mint (or fetch) a second one for this attempt.
        if (state.signed) {
          return {
            tokenHash: await tokenHash(fromHex(state.signed.token)),
            keyId: state.signed.keyId,
          };
        }

        // No pending blinded request → mint and persist it BEFORE the network
        // call, so any retry re-sends this exact blinded message.
        if (!state.blind) {
          const req = await blind(mintToken(), config.issuerPublicKey);
          state.blind = {
            token: toHex(req.token),
            blindedMsg: toHex(req.blindedMsg),
            inv: toHex(req.inv),
          };
          save(state);
        }

        const res = await post(`${issuerUrl}/issue`, {
          assertion,
          blindedMsg: state.blind.blindedMsg,
        });
        if (!res.ok) throw new IssueError(res.status, await errorCode(res));
        const body = (await res.json()) as { blindSignature: string; keyId: string };

        // unblind() verifies the signature — a bad blind signature throws and
        // leaves the pending request intact for a retry.
        const signed: SignedToken = await unblind(
          {
            token: fromHex(state.blind.token),
            blindedMsg: fromHex(state.blind.blindedMsg),
            inv: fromHex(state.blind.inv),
          },
          fromHex(body.blindSignature),
          config.issuerPublicKey,
        );

        state.signed = {
          token: toHex(signed.token),
          signature: toHex(signed.signature),
          keyId: body.keyId,
        };
        delete state.blind; // the unblinding secret is no longer needed
        save(state);

        return { tokenHash: await tokenHash(signed.token), keyId: body.keyId };
      });
    },

    redeem(payload: JsonValue) {
      return locked(async () => {
        const state = load();

        // Receipt already held → return it (after checking the payload still
        // matches the pinned commitment — a diverging caller is a bug).
        if (state.receipt) {
          await assertPinned(state, payload);
          return heldReceipt(state)!;
        }

        if (!state.signed) throw new NoTokenError();

        if (state.commitment) {
          // A redeem was already attempted (token possibly spent). Re-present
          // the SAME (t, c); never a different c.
          await assertPinned(state, payload);
        } else {
          // First attempt: pin (salt, c) BEFORE the POST. This closes the
          // stranded-token window of topology ADR §3.
          const salt = newSalt();
          state.commitment = { salt: toHex(salt), c: toHex(await commit(payload, salt)) };
          save(state);
        }

        const res = await post(`${verifierUrl}/redeem`, {
          surveyId,
          token: state.signed.token,
          signature: state.signed.signature,
          c: state.commitment.c,
        });
        if (!res.ok) throw new RedeemError(res.status, await errorCode(res));
        const body = (await res.json()) as {
          receipt: string;
          receiptKeyId: string;
          tokenHash: string;
        };

        state.receipt = {
          receipt: body.receipt,
          receiptKeyId: body.receiptKeyId,
          tokenHash: body.tokenHash,
        };
        save(state);

        return heldReceipt(state)!;
      });
    },

    async submitToVendor(payload, deliver) {
      // redeem() is idempotent (cached receipt / idempotent verifier), so this
      // is safe even when a receipt is already held.
      const r = await client.redeem(payload);
      const submission: VendorSubmission = {
        surveyId,
        payload,
        salt: r.salt,
        tokenHash: r.tokenHash,
        receipt: r.receipt,
      };
      if (deliver) {
        await deliver(submission);
        // Vendor acknowledged — only now is the session state disposable.
        client.clear();
      }
      return submission;
    },

    receipt() {
      return heldReceipt(load());
    },

    clear() {
      storage.removeItem(storageKey);
    },
  };

  return client;
}
