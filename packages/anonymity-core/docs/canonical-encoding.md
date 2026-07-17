# Canonical Encoding Specification

**Status:** v1, 2026-07-01 (plan task M0-3; spec review at fable tier per work-streams.md)
**Scope:** every byte string that gets hashed, signed, committed, or logged in the anonymity layer.

## Why this exists

The transparency log, the response commitments, and the receipts are only verifiable if every party — our verifier, the vendor's backend, an external auditor re-deriving roots years later — produces **exactly the same bytes** for the same logical value. Any non-determinism (key order, whitespace, number formatting, encoding of time) silently breaks verification. `cryptographic-design.md` names this as a break-the-verifier risk; this spec is the mitigation. Divergence from this spec is a defect, not a compatibility concern.

## 1. Canonical JSON

We adopt **RFC 8785 (JSON Canonicalization Scheme, JCS)** semantics, restricted:

1. Values are the JSON types only: `null`, booleans, finite numbers, strings, arrays, objects.
2. Object keys are sorted by UTF-16 code units (JavaScript's default `Array.prototype.sort()` order), recursively.
3. No insignificant whitespace anywhere.
4. Numbers serialize per ECMAScript `ToString` on doubles (what `JSON.stringify` does). `NaN`, `±Infinity`, `BigInt`, `undefined`, and functions are **rejected with an error** — never coerced, never skipped.
5. Strings serialize with `JSON.stringify` escaping (which matches JCS).
6. The canonical byte form is the UTF-8 encoding of the resulting string.

**Unicode caution (vendor guidance, not enforced):** JCS does not normalize Unicode. Two visually identical strings in different normalization forms produce different bytes. Vendors should NFC-normalize free-text before submission if they intend cross-system comparison of payload hashes.

## 2. Response commitment

Binds a stored response to a spent token without revealing the response (topology ADR).

```
salt  = 32 cryptographically random bytes (exactly 32; enforced)
c     = SHA-256( salt ‖ canonicalJson(payload) )
```

- Fixed-length salt makes the concatenation unambiguous with no length prefix.
- The salt is held by the respondent's browser and handed to the vendor together with the payload; the vendor recomputes `c` to check the receipt. The salt prevents outsiders who see `c` in the public log from confirming guessed payloads.
- `c` is transmitted and logged as lowercase hex.

## 3. Transparency-log entries

Each entry is a canonical-JSON object (per §1) with a `type` discriminator; the log leaf bytes are the UTF-8 canonical form. (Merkle leaf/node domain separation — `0x00`/`0x01` prefixes per RFC 6962 — is applied by the log layer in M1, not here.)

### 3.1 `redeem` — one accepted redemption

```json
{"batchTime":"2026-07-01T15:00Z","c":"<hex sha-256>","tokenHash":"<hex sha-256>","type":"redeem","surveyId":"<opaque id>"}
```
*(shown unsorted for readability; canonical form sorts keys)*

- `tokenHash = SHA-256(token)` — the spent token is the nullifier, but the log carries its hash so log readers cannot replay-probe the verifier with raw tokens.
- `batchTime` is **coarse**: ISO 8601 UTC truncated to the hour (`YYYY-MM-DDTHH:00Z`). Finer timestamps would rebuild the issuance-timing side channel the trust-model ADR forbids.

### 3.2 `counters` — issuance transparency, per survey partition

```json
{"at":"2026-07-01T15:00Z","issued":412,"redeemed":388,"type":"counters","surveyId":"<opaque id>"}
```

Emitted at wave close (and optionally per batch). Auditors check `redeemed ≤ issued`; a vendor's customer checks `issued ≤ eligible population`.

### 3.3 `key-event` — key lifecycle

```json
{"at":"2026-07-01T15:00Z","event":"created","keyId":"<hex sha-256 of SPKI>","type":"key-event","surveyId":"<opaque id>"}
```

- `event` ∈ `created` | `destroyed`. `keyId` is the SHA-256 of the public key's SPKI encoding, hex.
- The `destroyed` event is what converts "trust us not to sign more" into "nobody can sign more" (crypto-primitive ADR).

## 4. Validation rules

Encoders MUST reject (not repair): unknown `type`; missing or extra fields for a type; non-string ids; hex fields that aren't lowercase hex of the exact expected length (64 chars for SHA-256); `batchTime`/`at` not matching `^\d{4}-\d{2}-\d{2}T\d{2}:00Z$`; negative or non-integer counters. Rejection keeps garbage out of the log — an append-only structure has no repair path.

## 5. Versioning

This is v1. Any change to these rules is a **new leaf type or a new log**, never a reinterpretation of existing bytes — logged history must stay verifiable under the rules it was written with.
