/**
 * Issuer service.
 *
 * The issuer blind-signs a value it cannot read. It only ever sees the blinded
 * message, never the token, so it cannot link an issuance to a later
 * redemption. Eligibility is enforced *before* signing: in production this is
 * the vendor's authenticated handoff (a signed eligibility assertion — see
 * adr/2026-07-01-data-flow-topology.md); in the prototype it is a supplied
 * predicate.
 */

import { suite } from "./suite.ts";

export class Issuer {
  private readonly privateKey: CryptoKey;
  /** Count of signatures emitted — feeds the issuance-transparency counters. */
  private issued = 0;

  constructor(privateKey: CryptoKey) {
    this.privateKey = privateKey;
  }

  /**
   * Blind-sign a blinded message after an eligibility check.
   *
   * @param blindedMsg  the respondent's blinded token (unreadable to the issuer)
   * @param eligible    result of the vendor's authenticated eligibility check
   * @returns the blind signature, or throws if the respondent is not eligible
   */
  async blindSign(blindedMsg: Uint8Array, eligible: boolean): Promise<Uint8Array> {
    if (!eligible) throw new Error("issuer refused: respondent not eligible");
    const blindSignature = await suite.blindSign(this.privateKey, blindedMsg);
    this.issued += 1;
    return blindSignature;
  }

  /** How many signatures this issuer has emitted (no identity information). */
  get issuedCount(): number {
    return this.issued;
  }
}
