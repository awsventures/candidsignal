/**
 * Respondent-side (browser) logic.
 *
 * In the real product this runs in the respondent's browser so that no secret
 * ever reaches a server. The respondent:
 *   1. mints a random token seed,
 *   2. prepares it (RFC 9474 randomizer prefix) and blinds it before showing
 *      it to the issuer,
 *   3. finalizes the issuer's blind signature to recover a signature the
 *      issuer has never seen.
 *
 * The blinding is the source of anonymity: the issuer signs `blindedMsg`,
 * which carries no information about the token, and cannot later recognise
 * the (token, signature) pair at redemption.
 *
 * Everything here is runtime-portable (WebCrypto only — no Node built-ins),
 * because this file is the future browser SDK's core.
 */

import { suite } from "./suite.ts";

/** A prepared, blinded token plus the client-held secret needed to finalize. */
export interface BlindedRequest {
  /** The prepared message (randomizer ‖ seed). This is the redeemable token. */
  token: Uint8Array;
  /** What the issuer sees and signs — reveals nothing about `token`. */
  blindedMsg: Uint8Array;
  /** Unblinding secret. Never leaves the client. */
  inv: Uint8Array;
}

/** A token with a valid issuer signature, ready to redeem exactly once. */
export interface SignedToken {
  token: Uint8Array;
  signature: Uint8Array;
}

/** Mint a fresh random token seed (256 bits of entropy). */
export function mintToken(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Prepare and blind a token seed under the issuer's public key.
 * The returned `token` (prepared message) is what will be redeemed; the
 * randomizer prefix added by prepare() makes it unique per issuance even if
 * the same seed were ever reused.
 */
export async function blind(
  tokenSeed: Uint8Array,
  issuerPublicKey: CryptoKey,
): Promise<BlindedRequest> {
  const token = suite.prepare(tokenSeed);
  const { blindedMsg, inv } = await suite.blind(issuerPublicKey, token);
  return { token, blindedMsg, inv };
}

/**
 * Finalize (unblind) the issuer's blind signature into a valid signature over
 * the token. Throws if the blind signature does not verify under the issuer's
 * public key — a client never accepts a bad signature.
 */
export async function unblind(
  req: BlindedRequest,
  blindSignature: Uint8Array,
  issuerPublicKey: CryptoKey,
): Promise<SignedToken> {
  const signature = await suite.finalize(
    issuerPublicKey,
    req.token,
    blindSignature,
    req.inv,
  );
  return { token: req.token, signature };
}
