/**
 * Verifier/redemption service — `POST /redeem`.
 *
 * This is the redeem state machine of the topology ADR (Profile A §2–§3), the
 * trust-critical path of the whole system:
 *
 *   1. verify the RFC 9474 issuer signature over the token — an unsigned token
 *      buys nothing;
 *   2. spend the nullifier `(tokenHash, c)` — the DB constraint in storage is
 *      the arbiter, and redemption is **idempotent on (t, c)**: re-presenting
 *      the same token with the same commitment returns the same receipt (safe
 *      SDK retry; a respondent can never be stranded by a network blip), while
 *      the same token with a *different* commitment is a double-spend, refused;
 *   3. on a first-time accept only: bump the redeemed counter and append the
 *      `redeem` entry to the transparency log. An idempotent re-present must
 *      not double-count or double-log — the log is append-only evidence, not
 *      a request journal;
 *   4. return the commitment-bound receipt `R`: Ed25519 over
 *      `canonicalJson({ c, surveyId, tokenHash })`.
 *
 * Receipt determinism note (recorded in PROGRESS.md): the ADR's illustrative
 * formula includes `batchTime`; the receipt here deliberately signs only
 * `(surveyId, tokenHash, c)` so that Ed25519's determinism makes the
 * re-present receipt byte-identical without the service storing receipts.
 * `batchTime` still reaches the log via the `redeem` entry, which is where
 * auditors read it.
 *
 * The service never sees the answer payload — only its salted commitment `c`.
 * Nothing identifying reaches disk or logs: the spend row is
 * `(tokenHash, surveyId, c, coarse-hour)` and the service prints nothing.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";

import {
  Verifier,
  canonicalJson,
  coarseTime,
  toHex,
  tokenHash,
} from "../../anonymity-core/src/index.ts";
import type { Storage } from "./storage.ts";
import { fromHex, rateLimiter, type RateLimit } from "./http.ts";

// ---------- config ----------

/** One survey's verification config: the issuer public key tokens must carry. */
export interface SurveyVerifier {
  issuerPublicKey: CryptoKey;
}

export interface VerifierAppConfig {
  storage: Storage;
  /** surveyId → the issuer public key that validates its tokens. */
  verifiers: Map<string, SurveyVerifier>;
  /** Ed25519 private key that signs receipts. */
  receiptSigningKey: CryptoKey;
  /** Identifier of the receipt key, echoed so vendors pick the right pin. */
  receiptKeyId: string;
  /** In-memory rate limit (never persisted, never logged). */
  rateLimit?: RateLimit;
}

interface RedeemRequest {
  surveyId: string;
  /** Hex token (the pre-image; we store only its hash). */
  token: string;
  /** Hex RFC 9474 signature over the token. */
  signature: string;
  /** Hex SHA-256 response commitment. */
  c: string;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

// ---------- receipt ----------

/** The exact bytes a receipt signs — one definition, shared with verifiers. */
export function receiptMessage(surveyId: string, tokenHashHex: string, c: string): Uint8Array {
  return canonicalJson({ c, surveyId, tokenHash: tokenHashHex });
}

/**
 * Verify a receipt against the verifier's published receipt key. This is the
 * check the server SDK (M3-1) runs — with `c` recomputed from the vendor's
 * stored payload and salt, so a stored response provably backs one accepted
 * token.
 */
export async function verifyReceipt(
  receiptHex: string,
  bound: { surveyId: string; tokenHash: string; c: string },
  receiptPublicKey: CryptoKey,
): Promise<boolean> {
  let sig: Uint8Array;
  try {
    sig = fromHex(receiptHex);
  } catch {
    return false;
  }
  try {
    return await crypto.subtle.verify(
      "Ed25519",
      receiptPublicKey,
      sig as BufferSource,
      receiptMessage(bound.surveyId, bound.tokenHash, bound.c) as BufferSource,
    );
  } catch {
    return false;
  }
}

// ---------- app ----------

/** Build the verifier Hono app. Testable in-process via `app.request(...)`. */
export function createVerifierApp(config: VerifierAppConfig): Hono {
  const app = new Hono();

  app.use("*", cors());
  if (config.rateLimit) app.use("*", rateLimiter(config.rateLimit));

  app.post("/redeem", async (c) => {
    const body = (await c.req.json().catch(() => null)) as RedeemRequest | null;
    if (
      !body ||
      typeof body.surveyId !== "string" ||
      body.surveyId.length === 0 ||
      typeof body.token !== "string" ||
      typeof body.signature !== "string" ||
      typeof body.c !== "string"
    ) {
      return c.json({ error: "bad-request" }, 400);
    }
    // The commitment must be log-shape (64 lowercase hex) up front: appendLog
    // rejects anything else, and by then the token would already be spent.
    if (!SHA256_HEX.test(body.c)) return c.json({ error: "bad-request" }, 400);

    let token: Uint8Array;
    let signature: Uint8Array;
    try {
      token = fromHex(body.token);
      signature = fromHex(body.signature);
    } catch {
      return c.json({ error: "bad-request" }, 400);
    }

    const surveyVerifier = config.verifiers.get(body.surveyId);
    if (!surveyVerifier) return c.json({ error: "unknown-survey" }, 404);

    // (1) Signature first — an invalid token must not touch the spent-set.
    const verifier = new Verifier(surveyVerifier.issuerPublicKey);
    if (!(await verifier.isValidSignature({ token, signature }))) {
      return c.json({ error: "invalid-signature" }, 401);
    }

    // (2) Spend the nullifier. The DB constraint decides races.
    const th = await tokenHash(token);
    const spent = await config.storage.spend({ surveyId: body.surveyId, tokenHash: th, c: body.c });
    if (!spent.accepted) return c.json({ error: spent.reason }, 409);

    // (3) First-time accept only: counter + transparency-log entry.
    if (!spent.idempotent) {
      await config.storage.incrementRedeemed(body.surveyId);
      await config.storage.appendLog({
        type: "redeem",
        surveyId: body.surveyId,
        tokenHash: th,
        c: body.c,
        batchTime: coarseTime(),
      });
    }

    // (4) The commitment-bound receipt. Ed25519 is deterministic, so an
    // idempotent re-present yields the byte-identical receipt.
    const sig = await crypto.subtle.sign(
      "Ed25519",
      config.receiptSigningKey,
      receiptMessage(body.surveyId, th, body.c) as BufferSource,
    );

    return c.json({
      receipt: toHex(new Uint8Array(sig)),
      receiptKeyId: config.receiptKeyId,
      tokenHash: th,
    });
  });

  return app;
}
