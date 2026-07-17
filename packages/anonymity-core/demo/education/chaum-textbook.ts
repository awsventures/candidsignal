/**
 * EDUCATIONAL ONLY — textbook Chaum blind RSA, preserved from the first
 * prototype because it explains the mathematics in ~100 readable lines.
 *
 * This file is NOT part of the trust path. Nothing in `src/` imports it.
 * The production primitive is RFC 9474 (RSABSSA) via `@cloudflare/blindrsa-ts`
 * — see src/suite.ts and
 * docs/04-implementation-plan/adr/2026-07-01-crypto-primitive-production-path.md.
 *
 * Run it directly to see the raw math walk through one blind-sign cycle:
 *   node --experimental-strip-types demo/education/chaum-textbook.ts
 */

import { createHash, randomBytes, generateKeyPairSync } from "node:crypto";

// ---------- BigInt modular arithmetic ----------

/** Modular exponentiation: base^exp mod m, via square-and-multiply. */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  let result = 1n;
  let b = base % m;
  if (b < 0n) b += m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return result;
}

function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x, y] = egcd(b, a % b);
  return [g, y, x - (a / b) * y];
}

/** Modular inverse of a mod m, or throws if a is not invertible. */
export function modInverse(a: bigint, m: bigint): bigint {
  let aa = a % m;
  if (aa < 0n) aa += m;
  const [g, x] = egcd(aa, m);
  if (g !== 1n) throw new Error("no modular inverse (value not coprime to modulus)");
  return ((x % m) + m) % m;
}

export function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y) [x, y] = [y, x % y];
  return x;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const byte of bytes) acc = (acc << 8n) | BigInt(byte);
  return acc;
}

function base64urlToBigInt(b64u: string): bigint {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  return bytesToBigInt(new Uint8Array(Buffer.from(b64, "base64")));
}

function byteLength(n: bigint): number {
  return Math.ceil(n.toString(16).length / 2);
}

// ---------- Full-domain hash (MGF1-SHA256) ----------

function mgf1(seed: Uint8Array, length: number): Uint8Array {
  const out = Buffer.alloc(length);
  let counter = 0;
  let pos = 0;
  while (pos < length) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter, 0);
    const block = createHash("sha256").update(seed).update(c).digest();
    const take = Math.min(block.length, length - pos);
    block.copy(out, pos, 0, take);
    pos += take;
    counter += 1;
  }
  return new Uint8Array(out);
}

/** Map an arbitrary message to an element of Z_n (with slight, tolerable bias). */
export function fullDomainHash(message: Uint8Array, n: bigint): bigint {
  const expanded = mgf1(message, byteLength(n));
  const value = bytesToBigInt(expanded) % n;
  return value === 0n ? 1n : value;
}

function randomBelow(n: bigint): bigint {
  const widthBytes = byteLength(n);
  while (true) {
    const candidate = bytesToBigInt(new Uint8Array(randomBytes(widthBytes))) % n;
    if (candidate >= 2n) return candidate;
  }
}

// ---------- The Chaum blind-signature cycle ----------

export interface TextbookKey {
  n: bigint;
  e: bigint;
  d: bigint;
}

export function generateTextbookKey(modulusBits = 2048): TextbookKey {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: modulusBits });
  const jwk = privateKey.export({ format: "jwk" }) as { n: string; e: string; d: string };
  return {
    n: base64urlToBigInt(jwk.n),
    e: base64urlToBigInt(jwk.e),
    d: base64urlToBigInt(jwk.d),
  };
}

/** Client: blind the message m with random factor r: blinded = m·r^e mod n. */
export function blind(m: bigint, key: Pick<TextbookKey, "n" | "e">) {
  let r: bigint;
  do {
    r = randomBelow(key.n);
  } while (gcd(r, key.n) !== 1n);
  return { blinded: (m * modPow(r, key.e, key.n)) % key.n, r };
}

/** Issuer: sign the blinded value it cannot read: σ' = blinded^d mod n. */
export function blindSign(blinded: bigint, key: TextbookKey): bigint {
  return modPow(blinded, key.d, key.n);
}

/** Client: strip the blinding: σ = σ'·r⁻¹ mod n = m^d mod n. */
export function unblind(blindSig: bigint, r: bigint, n: bigint): bigint {
  return (blindSig * modInverse(r, n)) % n;
}

/** Anyone: verify σ^e mod n == m. */
export function verify(sig: bigint, m: bigint, key: Pick<TextbookKey, "n" | "e">): boolean {
  return modPow(sig, key.e, key.n) === m;
}

// ---------- Self-demonstration when run directly ----------

if (process.argv[1]?.endsWith("chaum-textbook.ts")) {
  console.log("\nTextbook Chaum blind RSA — one cycle:\n");
  const key = generateTextbookKey(2048);
  const token = new Uint8Array(randomBytes(32));
  const m = fullDomainHash(token, key.n);
  const { blinded, r } = blind(m, key);
  const sig = unblind(blindSign(blinded, key), r, key.n);
  console.log("  issuer saw:      ", blinded.toString(16).slice(0, 24) + "…");
  console.log("  client recovered:", sig.toString(16).slice(0, 24) + "…");
  console.log("  verifies:        ", verify(sig, m, key));
  console.log("\nThe issuer signed a value it could not read, and the recovered");
  console.log("signature is valid over the token it never saw. That is the math.\n");
}
