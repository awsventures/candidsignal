/**
 * Property-based tests (fast-check) for the blind-token composition.
 *
 * These test *our* composition of the RFC 9474 primitive, not the primitive
 * itself: conformance of the primitive to the RFC's test vectors is delegated
 * to the pinned upstream (`@cloudflare/blindrsa-ts` runs the Appendix vectors
 * in its own CI); `suite parameters` below pins that we are actually on the
 * intended variant.
 *
 * Run counts are deliberately small — each run does real 2048-bit RSA.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  suite,
  generateIssuerKey,
  publicKeyOf,
  blind,
  unblind,
  Issuer,
  Verifier,
  TEST_MODULUS_BITS,
} from "../src/index.ts";

const pair = await generateIssuerKey(TEST_MODULUS_BITS);
const pub = publicKeyOf(pair);
const issuer = new Issuer(pair.privateKey);

test("suite parameters are the ADR-decided variant", () => {
  // RSABSSA-SHA384-PSS-Randomized: SHA-384, salt length 48, randomized prepare.
  assert.match(suite.toString(), /RSABSSA-SHA384-PSS-Randomized/);
});

test("property: any seed round-trips to a valid, redeemable token", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      async (seed) => {
        const req = await blind(seed, pub);
        const signed = await unblind(req, await issuer.blindSign(req.blindedMsg, true), pub);
        const verifier = new Verifier(pub);
        const first = await verifier.redeem(signed);
        assert.deepEqual(first, { accepted: true });
      },
    ),
    { numRuns: 8 },
  );
});

test("property: flipping any byte of token or signature invalidates it", async () => {
  const req = await blind(crypto.getRandomValues(new Uint8Array(32)), pub);
  const signed = await unblind(req, await issuer.blindSign(req.blindedMsg, true), pub);
  const verifier = new Verifier(pub);

  await fc.assert(
    fc.asyncProperty(
      fc.boolean(),
      fc.nat(4096),
      fc.integer({ min: 1, max: 255 }),
      async (flipToken, posSeed, xor) => {
        const token = signed.token.slice();
        const signature = signed.signature.slice();
        const target = flipToken ? token : signature;
        target[posSeed % target.length] ^= xor;
        assert.deepEqual(await verifier.redeem({ token, signature }), {
          accepted: false,
          reason: "invalid-signature",
        });
      },
    ),
    { numRuns: 12 },
  );
});

test("property: redeeming any interleaving of duplicates accepts each token exactly once", async () => {
  // Issue a small pool of tokens once (expensive), then property-test the
  // verifier's state machine over arbitrary redemption sequences drawn from it.
  const pool = [];
  for (let i = 0; i < 4; i++) {
    const req = await blind(crypto.getRandomValues(new Uint8Array(32)), pub);
    pool.push(await unblind(req, await issuer.blindSign(req.blindedMsg, true), pub));
  }

  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.nat(pool.length - 1), { minLength: 1, maxLength: 12 }),
      async (indices) => {
        const verifier = new Verifier(pub);
        const seen = new Set<number>();
        for (const i of indices) {
          const result = await verifier.redeem(pool[i]);
          if (seen.has(i)) {
            assert.deepEqual(result, { accepted: false, reason: "already-spent" });
          } else {
            assert.deepEqual(result, { accepted: true });
            seen.add(i);
          }
        }
        assert.equal(verifier.spentCount, seen.size);
      },
    ),
    { numRuns: 10 },
  );
});
