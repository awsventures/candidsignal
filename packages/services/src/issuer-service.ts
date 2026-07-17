/**
 * Issuer service — `POST /issue`.
 *
 * The issuer blind-signs a token it cannot read, but only after the vendor has
 * vouched for the respondent. The vendor's vouch is a short-lived **eligibility
 * assertion**: an EdDSA-signed JWT, minted by the vendor backend (M3-1) with a
 * key pre-registered here, carrying `{ surveyId, cohortLabel, subjectRef, exp }`
 * (topology ADR, Profile A). We verify that assertion, enforce one token per
 * subject per survey, blind-sign, and bump the issuance counter.
 *
 * Side-channel discipline is a hard requirement, not a nicety: the only thing
 * that ever reaches disk is `(surveyId, subjectRef, coarse-hour)` — no IP, no
 * fine-grained timestamp, no blinded message, no token. This service logs
 * nothing about a request. The invariant test inspects exactly what gets
 * persisted and printed and asserts none of it is identifying.
 *
 * The subject is claimed **before** signing: two concurrent requests for one
 * subject must never both get a token, so the atomic one-per-subject claim is
 * the gate. (A malformed blinded message is rejected before the claim so it
 * cannot burn a legitimate subject.)
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { verify } from "hono/jwt";

import { Issuer, toHex } from "../../anonymity-core/src/index.ts";
import type { Storage } from "./storage.ts";
import { fromHex, rateLimiter, type RateLimit } from "./http.ts";

// ---------- config ----------

/** One survey's issuer: the blind-signer plus the keyId it publishes under. */
export interface SurveyIssuer {
  issuer: Issuer;
  keyId: string;
}

export interface IssuerAppConfig {
  storage: Storage;
  /** Pre-registered vendor key that signs eligibility assertions (Ed25519). */
  vendorPublicKey: CryptoKey;
  /** surveyId → the issuer that signs for it. */
  issuers: Map<string, SurveyIssuer>;
  /** In-memory rate limit (never persisted, never logged). */
  rateLimit?: RateLimit;
}

interface IssueRequest {
  assertion: string;
  /** Hex-encoded blinded message the respondent's browser produced. */
  blindedMsg: string;
}

// ---------- app ----------

/** Build the issuer Hono app. Testable in-process via `app.request(...)`. */
export function createIssuerApp(config: IssuerAppConfig): Hono {
  const app = new Hono();

  app.use("*", cors());
  if (config.rateLimit) app.use("*", rateLimiter(config.rateLimit));

  app.post("/issue", async (c) => {
    const body = (await c.req.json().catch(() => null)) as IssueRequest | null;
    if (!body || typeof body.assertion !== "string" || typeof body.blindedMsg !== "string") {
      return c.json({ error: "bad-request" }, 400);
    }

    // Verify the vendor's eligibility assertion (also checks exp/nbf).
    let claims: Record<string, unknown>;
    try {
      claims = await verify(body.assertion, config.vendorPublicKey, "EdDSA");
    } catch {
      return c.json({ error: "invalid-assertion" }, 401);
    }
    const surveyId = claims.surveyId;
    const subjectRef = claims.subjectRef;
    if (typeof surveyId !== "string" || typeof subjectRef !== "string") {
      return c.json({ error: "invalid-assertion" }, 401);
    }

    const surveyIssuer = config.issuers.get(surveyId);
    if (!surveyIssuer) return c.json({ error: "unknown-survey" }, 404);

    // Parse the blinded message before claiming the subject, so a malformed
    // request cannot burn a legitimate subject's one-time eligibility.
    let blindedMsg: Uint8Array;
    try {
      blindedMsg = fromHex(body.blindedMsg);
    } catch {
      return c.json({ error: "bad-request" }, 400);
    }

    // One token per subject per survey — the atomic claim is the gate.
    const alreadyIssued = await config.storage.seenSubject(surveyId, subjectRef);
    if (alreadyIssued) return c.json({ error: "already-issued" }, 409);

    // The verified, unexpired assertion IS the eligibility proof.
    let blindSignature: Uint8Array;
    try {
      blindSignature = await surveyIssuer.issuer.blindSign(blindedMsg, true);
    } catch {
      return c.json({ error: "sign-failed" }, 500);
    }

    // Count only successful signings.
    await config.storage.incrementIssued(surveyId);

    return c.json({ blindSignature: toHex(blindSignature), keyId: surveyIssuer.keyId });
  });

  return app;
}
