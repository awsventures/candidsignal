/**
 * Issuer key generation and public parameters.
 *
 * The issuer holds a WebCrypto RSA key pair. Only the public key is published,
 * so that anyone — respondents, vendors, auditors — can verify signatures. The
 * private key never leaves the issuer.
 *
 * One key corresponds to one issuance context (one survey wave × coarse
 * cohort): partitioning by key is how eligibility classes work without
 * revealing attributes. Partition sizing rules (the k_issue ≥ 20 floor) and
 * per-wave key destruction are specified in
 * docs/04-implementation-plan/adr/2026-07-01-crypto-primitive-production-path.md
 * and enforced by the key-lifecycle module (plan task M0-4).
 */

import { suite, RECOMMENDED_MODULUS_BITS } from "./suite.ts";

/** RSA public exponent 65537. */
const F4 = new Uint8Array([0x01, 0x00, 0x01]);

/**
 * Generate a fresh issuer key pair for one issuance context.
 * Defaults to 3072-bit per the crypto-primitive ADR; 2048 is permitted in tests.
 */
export async function generateIssuerKey(
  modulusBits: number = RECOMMENDED_MODULUS_BITS,
): Promise<CryptoKeyPair> {
  return suite.generateKey({
    modulusLength: modulusBits,
    publicExponent: F4,
  });
}

/** Extract the publishable public key from an issuer key pair. */
export function publicKeyOf(pair: CryptoKeyPair): CryptoKey {
  return pair.publicKey;
}

/** Export the public key as SPKI bytes for publication/audit artifacts. */
export async function exportPublicKey(publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
}
