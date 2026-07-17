/**
 * End-to-end demonstration of the blind-token anonymity loop (RFC 9474).
 *
 * Run:  npm run demo   (from packages/anonymity-core)
 *
 * Shows:
 *   1. issue → blind-sign → unblind → redeem for several respondents,
 *   2. that the issuer's view (blinded values) cannot be linked to redemptions,
 *   3. one-response-per-token enforcement (double-spend rejected),
 *   4. forged tokens rejected.
 *
 * For the raw mathematics in textbook form, see education/chaum-textbook.ts.
 */

import {
  generateIssuerKey,
  publicKeyOf,
  mintToken,
  blind,
  unblind,
  Issuer,
  Verifier,
  RECOMMENDED_MODULUS_BITS,
} from "../src/index.ts";

function line(label: string, value: string) {
  console.log(`  ${label.padEnd(22)} ${value}`);
}

function short(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString("hex");
  return hex.length <= 20
    ? hex
    : `${hex.slice(0, 10)}…${hex.slice(-6)} (${bytes.length * 8} bits)`;
}

console.log("\n=== AWS Confidential-by-Design — blind-token prototype (RFC 9474) ===\n");

// --- Setup: the issuer generates a key for one survey context. ---
console.log(
  `Issuer generates a ${RECOMMENDED_MODULUS_BITS}-bit RSABSSA key for survey 'eng-pulse-2026Q2'…`,
);
const pair = await generateIssuerKey();
const pub = publicKeyOf(pair);
const issuer = new Issuer(pair.privateKey);
const verifier = new Verifier(pub);
console.log(
  "  (suite: RSABSSA-SHA384-PSS-Randomized; only the public key is published,\n" +
    "   the private key never leaves the issuer)\n",
);

// --- Issuance for three eligible respondents. ---
console.log("Three eligible respondents each obtain a blind-signed token:\n");
const respondents = ["Maya", "Devon", "Priya"];
const wallet: { name: string; token: Uint8Array; signature: Uint8Array }[] = [];
const issuerSaw: { name: string; blindedMsg: Uint8Array }[] = [];

for (const name of respondents) {
  // Respondent's browser mints, prepares, and blinds a token.
  const req = await blind(mintToken(), pub);

  // Issuer checks eligibility (vendor handoff) and blind-signs what it cannot read.
  const eligible = true; // would be the vendor's authenticated eligibility result
  const blindSig = await issuer.blindSign(req.blindedMsg, eligible);
  issuerSaw.push({ name, blindedMsg: req.blindedMsg });

  // Respondent finalizes to recover a signature the issuer has never seen.
  const signed = await unblind(req, blindSig, pub);
  wallet.push({ name, ...signed });

  line(`${name} token`, short(signed.token));
}

console.log(`\nIssuer emitted ${issuer.issuedCount} signatures. What the issuer actually saw:\n`);
for (const s of issuerSaw) line(`blinded from ${s.name}`, short(s.blindedMsg));
console.log(
  "\n  ↑ These blinded values are statistically independent of the tokens above.\n" +
    "    The issuer cannot map any blinded value to any redeemed token.\n",
);

// --- Submission: respondents redeem in a SHUFFLED order. ---
console.log("Respondents submit answers in shuffled order (verifier sees only token+signature):\n");
const submissions = [...wallet].sort(() => Math.random() - 0.5);
for (const sub of submissions) {
  const result = await verifier.redeem({ token: sub.token, signature: sub.signature });
  line(`redeem ${sub.name}`, result.accepted ? "ACCEPTED ✓" : `REJECTED (${result.reason})`);
}
console.log(
  "\n  The verifier accepted each response and recorded its nullifier (the spent\n" +
    "  token) WITHOUT learning which person submitted it. Anonymity holds.\n",
);

// --- Attack 1: double-spend. ---
console.log("Attack — double-spend (Maya tries to submit twice):");
const maya = wallet[0];
const second = await verifier.redeem({ token: maya.token, signature: maya.signature });
line("second redeem", second.accepted ? "ACCEPTED ✗ (BUG)" : `REJECTED ✓ (${(second as { reason: string }).reason})`);

// --- Attack 2: forged token. ---
console.log("\nAttack — forged token (no valid issuer signature):");
const forged = await verifier.redeem({
  token: mintToken(),
  signature: crypto.getRandomValues(new Uint8Array(RECOMMENDED_MODULUS_BITS / 8)),
});
line("forged redeem", forged.accepted ? "ACCEPTED ✗ (BUG)" : `REJECTED ✓ (${(forged as { reason: string }).reason})`);

console.log(`\nVerifier spent-set size: ${verifier.spentCount} (one per legitimate respondent).`);
console.log("\n=== Done. Mathematical anonymity via RFC 9474 — no ZK circuit, no trusted setup. ===\n");
