/**
 * AWS Confidential-by-Design — anonymity-core (prototype)
 *
 * Blind-signed one-time tokens delivering mathematical anonymity via
 * blind-signature unlinkability. RFC 9474 (RSABSSA-SHA384-PSS-Randomized)
 * via Cloudflare's audited implementation. See
 * docs/04-implementation-plan/adr/2026-07-01-crypto-primitive-production-path.md.
 */

export { suite, RECOMMENDED_MODULUS_BITS, TEST_MODULUS_BITS } from "./suite.ts";
export { generateIssuerKey, publicKeyOf, exportPublicKey } from "./keys.ts";
export { mintToken, blind, unblind } from "./client.ts";
export type { BlindedRequest, SignedToken } from "./client.ts";
export { Issuer } from "./issuer.ts";
export { Verifier } from "./verifier.ts";
export type { RedeemResult } from "./verifier.ts";
export {
  canonicalJson,
  commit,
  newSalt,
  toHex,
  tokenHash,
  keyId,
  coarseTime,
  encodeLogEntry,
  validateLogEntry,
  SALT_LENGTH,
} from "./encoding.ts";
export type { JsonValue, LogEntry, RedeemEntry, CountersEntry, KeyEventEntry } from "./encoding.ts";
export { IssuancePartition, K_ISSUE_FLOOR } from "./key-lifecycle.ts";
export type { CreatePartitionOptions } from "./key-lifecycle.ts";
export {
  MerkleLog,
  leafHash,
  verifyInclusion,
  verifyConsistency,
  generateLogKey,
  signTreeHead,
  verifyTreeHead,
} from "./merkle-log.ts";
export type { SignedTreeHead } from "./merkle-log.ts";
