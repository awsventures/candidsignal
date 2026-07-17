/**
 * AWS Confidential-by-Design — `sdk-server` (vendor backend SDK).
 *
 * This is the small, dependency-light library a survey vendor runs on their
 * own backend to participate in Profile A of the topology ADR
 * (docs/04-implementation-plan/adr/2026-07-01-data-flow-topology.md). It does
 * exactly three things, and nothing about surveys, dashboards, or respondents:
 *
 *   1. `mintEligibilityAssertion(...)` — vouch that a respondent may take a
 *      survey, as the short-lived EdDSA JWT the hosted **issuer** service
 *      verifies before it will blind-sign a token. The vendor is the only party
 *      that knows who is eligible; we never see the raw identity.
 *
 *   2. `verifyReceipt(...)` — after the respondent redeems their token at the
 *      hosted **verifier** service and submits `{ payload, salt, tokenHash,
 *      receipt }` back to the vendor, check that the receipt is a genuine,
 *      commitment-bound acknowledgement for exactly that stored answer. This is
 *      what lets a vendor trust "this row in my database is backed by one
 *      accepted, unlinkable token" without ever learning which respondent it
 *      was.
 *
 *   3. `subjectRef(...)` — derive the opaque `subjectRef` the issuer dedupes on
 *      (one token per subject per survey) from a raw vendor user id, via
 *      HMAC-SHA-256 under a vendor-held key. Vendors never send raw user ids to
 *      us; the HMAC is a stable, key-separated pseudonym.
 *
 * Runtime surface: WebCrypto + `hono/jwt` for the assertion format (pinned to
 * the same `hono` the services verify with, to eliminate format drift) +
 * `anonymity-core` for the canonical commitment and receipt-message encoding.
 * The receipt-message binding here is byte-identical to the verifier service's
 * `receiptMessage`; the test suite pins that by verifying a receipt produced by
 * the *real* verifier service and minting an assertion accepted by the *real*
 * issuer service.
 */

import { sign } from "hono/jwt";

import { canonicalJson, commit, toHex } from "../../anonymity-core/src/index.ts";
import type { JsonValue } from "../../anonymity-core/src/index.ts";

// ---------- hex ----------

/** Decode lowercase/uppercase hex. Throws on non-hex or odd length. */
function fromHex(hex: string): Uint8Array {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("not hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Coerce a salt given as raw bytes or hex into bytes. */
function saltBytes(salt: Uint8Array | string): Uint8Array {
  return typeof salt === "string" ? fromHex(salt) : salt;
}

// ---------- 1. eligibility assertion ----------

/**
 * The claims the issuer service reads. `exp` is a Unix timestamp in **seconds**
 * (hono/jwt checks it automatically); keep the lifetime short — this is a
 * single-use vouch, not a session.
 */
export interface EligibilityClaims {
  surveyId: string;
  cohortLabel: string;
  subjectRef: string;
  /** Expiry, Unix seconds. Auto-enforced by the issuer. */
  exp: number;
}

/**
 * Mint the eligibility assertion for one respondent, signed with the vendor's
 * Ed25519 private key (its public half is pre-registered with the issuer).
 * Produces exactly the EdDSA JWT `POST /issue` verifies — same library, same
 * `"EdDSA"` alg, so there is no format to keep in sync by hand.
 */
export async function mintEligibilityAssertion(
  claims: EligibilityClaims,
  vendorPrivateKey: CryptoKey,
): Promise<string> {
  return sign(
    {
      surveyId: claims.surveyId,
      cohortLabel: claims.cohortLabel,
      subjectRef: claims.subjectRef,
      exp: claims.exp,
    },
    vendorPrivateKey,
    "EdDSA",
  );
}

// ---------- 2. receipt verification ----------

/**
 * The exact bytes a receipt signs. **Must** stay byte-identical to the verifier
 * service's `receiptMessage` (packages/services/src/verifier-service.ts) — the
 * cross-service test pins this. `canonicalJson` (RFC 8785) fixes key order, so
 * the object literal order below is irrelevant to the output.
 */
function receiptMessage(surveyId: string, tokenHashHex: string, cHex: string): Uint8Array {
  return canonicalJson({ c: cHex, surveyId, tokenHash: tokenHashHex });
}

/**
 * What the respondent's browser submits to the vendor after redeeming. `c` is
 * NOT sent — it is recomputed here from the stored answer, which is the point:
 * a valid receipt proves the stored `payload`/`salt` is what was committed to
 * and accepted. `salt` may be raw bytes or hex (browsers submit hex over JSON).
 */
export interface VendorSubmission {
  surveyId: string;
  /** The answer payload the browser committed to (canonicalised here). */
  payload: JsonValue;
  /** 32-byte commitment salt, raw bytes or hex. */
  salt: Uint8Array | string;
  /** SHA-256(token) hex, echoed by the verifier's redeem response. */
  tokenHash: string;
  /** Ed25519 receipt hex, from the verifier's redeem response. */
  receipt: string;
}

/**
 * Verify a commitment-bound receipt against the verifier's published receipt
 * public key. Recomputes `c = commit(payload, salt)`, rebuilds the receipt
 * message the verifier signed over `(surveyId, tokenHash, c)`, and checks the
 * Ed25519 signature. Any tamper — payload, salt, tokenHash, surveyId, or the
 * receipt itself — flips this to `false`. Never throws on bad input.
 */
export async function verifyReceipt(
  submission: VendorSubmission,
  receiptPublicKey: CryptoKey,
): Promise<boolean> {
  let sig: Uint8Array;
  let cHex: string;
  try {
    sig = fromHex(submission.receipt);
    cHex = toHex(await commit(submission.payload, saltBytes(submission.salt)));
  } catch {
    return false;
  }
  try {
    return await crypto.subtle.verify(
      "Ed25519",
      receiptPublicKey,
      sig as BufferSource,
      receiptMessage(submission.surveyId, submission.tokenHash, cHex) as BufferSource,
    );
  } catch {
    return false;
  }
}

// ---------- 3. subject reference ----------

/**
 * Derive the opaque `subjectRef` from a raw vendor user id via HMAC-SHA-256,
 * hex. Deterministic (so the issuer's one-per-subject dedupe works across a
 * respondent's retries) and key-separated (a different `hmacKey` yields a
 * completely different ref, so refs can't be correlated across surveys/vendors
 * that use distinct keys). Accepts a raw key as bytes or an imported HMAC
 * `CryptoKey`.
 */
export async function subjectRef(
  hmacKey: CryptoKey | Uint8Array,
  vendorUserId: string,
): Promise<string> {
  const key =
    hmacKey instanceof Uint8Array
      ? await crypto.subtle.importKey(
          "raw",
          hmacKey as BufferSource,
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"],
        )
      : hmacKey;
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(vendorUserId));
  return toHex(new Uint8Array(mac));
}
