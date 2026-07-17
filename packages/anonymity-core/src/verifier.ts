/**
 * Verifier service — the open, auditable trust core.
 *
 * This is the component that makes the anonymity claim *checkable*. It does two
 * things and nothing else:
 *
 *   1. verifies that a redeemed token carries a valid RFC 9474 issuer
 *      signature, and
 *   2. enforces one-response-per-token by rejecting any token it has already
 *      seen — the spent token itself is the nullifier.
 *
 * It never learns who the respondent is. It does not see, store, or touch the
 * answer payload — that stays with the vendor. Because this file is short and
 * (beyond the audited RFC 9474 suite) dependency-free, anyone can audit the
 * guarantee by reading it.
 */

import { suite } from "./suite.ts";
import type { SignedToken } from "./client.ts";

export type RedeemResult =
  | { accepted: true }
  | { accepted: false; reason: "invalid-signature" | "already-spent" };

/** Hex-encode bytes (portable — no Buffer, runs in browsers too). */
function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export class Verifier {
  private readonly issuerPublicKey: CryptoKey;
  /** The spent-set: tokens already redeemed. Carries no identity. */
  private readonly spent = new Set<string>();

  constructor(issuerPublicKey: CryptoKey) {
    this.issuerPublicKey = issuerPublicKey;
  }

  /** Check a signature without spending the token (side-effect free). */
  async isValidSignature(t: SignedToken): Promise<boolean> {
    try {
      return await suite.verify(this.issuerPublicKey, t.signature, t.token);
    } catch {
      // Malformed inputs (wrong lengths, corrupt encodings) are simply invalid.
      return false;
    }
  }

  /**
   * Redeem a token for one response. Accepts at most once per token.
   *
   * @param t  the (token, signature) pair presented at submission time
   * @returns  whether the submission is accepted, with a reason on rejection
   */
  async redeem(t: SignedToken): Promise<RedeemResult> {
    if (!(await this.isValidSignature(t))) {
      return { accepted: false, reason: "invalid-signature" };
    }
    const nullifier = toHex(t.token);
    if (this.spent.has(nullifier)) {
      return { accepted: false, reason: "already-spent" };
    }
    this.spent.add(nullifier);
    return { accepted: true };
  }

  /** Number of accepted (spent) tokens — feeds the transparency counters. */
  get spentCount(): number {
    return this.spent.size;
  }
}
