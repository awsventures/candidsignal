/**
 * The single cryptographic suite used across the package.
 *
 * RSABSSA-SHA384-PSS-Randomized per RFC 9474, provided by Cloudflare's audited
 * `@cloudflare/blindrsa-ts`. This is the package's one deliberate runtime
 * dependency (see adr/2026-07-01-crypto-primitive-production-path.md): an
 * audited implementation of the standardized primitive is a smaller total
 * audit surface than maintaining our own big-integer arithmetic.
 *
 * The Randomized variant prepends a 32-byte message randomizer at prepare()
 * time, and PSS (non-zero salt) keeps us on the widely-reviewed encoding —
 * both per the RFC's recommended default.
 */

import { RSABSSA } from "@cloudflare/blindrsa-ts";

export const suite = RSABSSA.SHA384.PSS.Randomized();

/** Key size for anything shown outside the repo (audit posture). */
export const RECOMMENDED_MODULUS_BITS = 3072;
/** Permitted in tests where keygen speed matters. */
export const TEST_MODULUS_BITS = 2048;
