# @aws-cbd/services (prototype)

The trust services — issuer, verifier, STH publisher — for AWS
Confidential-by-Design. They are built on one narrow storage layer whose
uniqueness guarantees are enforced by the **database**, not by application code.

**Shipped:** the storage layer (M2-1), the **issuer service** (M2-2), the
**verifier/redemption service** (M2-3), and the **STH publisher** (M2-4) —
milestone M2 complete.

## Why DB-enforced uniqueness

The two guarantees that hold the system together are *a token is spent at most
once* and *a subject is issued at most one token per survey*. An application
that reads-then-writes to enforce these has a race between the read and the
write; under concurrency two requests can both pass the check. A `UNIQUE`
constraint has no such gap. So the spent-set and the one-per-subject rule are
UNIQUE keys, and every claim is a single `INSERT ... ON CONFLICT ... RETURNING`
statement whose atomicity the database owns. The invariant tests fire
concurrent claims and assert exactly one wins.

## The storage interface

```ts
const store = await Storage.open(":memory:"); // or "file:cbd.db"

await store.spend({ surveyId, tokenHash, c }); // nullifier claim (idempotent on (token,c))
await store.seenSubject(surveyId, subjectRef); // atomic one-per-subject claim
await store.appendLog(entry);                  // validated, canonical, append-only
await store.counters(surveyId);                // { issued, redeemed }
await store.incrementIssued(surveyId);
await store.incrementRedeemed(surveyId);
await store.recordKey(meta); await store.getKey(keyId); await store.destroyKey(keyId);
```

`spend` returns whether the claim was accepted and whether it was *idempotent*
(a safe retry of the same `(token, c)`); a different `c` on an already-spent
token is rejected as `conflicting-commitment`. `seenSubject` returns whether the
subject had already been seen — `true` means the issuer must refuse a second
token.

Log entries are validated and canonicalised through
[`@aws-cbd/anonymity-core`](../anonymity-core)'s encoding before storage, so the
bytes the STH publisher reads back are identical to what the Merkle log hashes.

## The issuer service — `POST /issue`

A [Hono](https://hono.dev) app that blind-signs a token after the vendor
vouches for the respondent. The vouch is an **eligibility assertion**: an
EdDSA-signed JWT (minted by the vendor backend with a pre-registered key)
carrying `{ surveyId, cohortLabel, subjectRef, exp }`.

```ts
const app = createIssuerApp({
  storage,
  vendorPublicKey,                              // verifies eligibility assertions
  issuers: new Map([[surveyId, { issuer, keyId }]]),
  rateLimit: { limit: 100, windowMs: 60_000 },  // optional, in-memory
});
```

Flow: verify the assertion (rejecting expired/forged ones `401`) → claim the
subject atomically, refusing a second token `409` → blind-sign → count the
issuance. **Side-channel discipline is enforced and tested**: the only thing
persisted is `(surveyId, subjectRef, coarse-hour)`; no IP, no fine timestamp,
no blinded message, and the service logs nothing about a request. The subject
is claimed *before* signing, so two concurrent requests for one subject can
never both get a token. CORS is on; an in-memory fixed-window rate limiter is
available (its key, which may be an IP, lives only in memory for one window).

## The verifier/redemption service — `POST /redeem`

The redeem state machine of the topology ADR — the trust-critical path. The
browser presents `{ surveyId, token, signature, c }` where `c` is the salted
SHA-256 commitment to the answer payload (which this service never sees).

```ts
const app = createVerifierApp({
  storage,
  verifiers: new Map([[surveyId, { issuerPublicKey }]]),
  receiptSigningKey,                            // Ed25519 private
  receiptKeyId: "receipt-key-1",
  rateLimit: { limit: 100, windowMs: 60_000 },  // optional, in-memory
});
```

Flow: verify the RFC 9474 signature (`401` on failure, spent-set untouched) →
spend the nullifier `(tokenHash, c)` — **idempotent on `(t, c)`**, so a safe
SDK retry returns the byte-identical receipt with **no** second log entry or
counter bump, while a different `c` on a spent token is `409
conflicting-commitment` → on a first-time accept, bump the redeemed counter
and append the `redeem` transparency-log entry → return the commitment-bound
receipt `R` = Ed25519 over `canonicalJson({ c, surveyId, tokenHash })`.
`verifyReceipt(receipt, { surveyId, tokenHash, c }, receiptPublicKey)` is what
the server SDK (M3-1) runs, with `c` recomputed from the vendor's stored
payload — binding every stored response to exactly one accepted token.

Measured locally (in-process Hono dispatch, 2048-bit test keys, `:memory:`
db): redeem **P90 ≈ 5ms** (P50 ≈ 4ms) over 100 iterations.

## The STH publisher

The batch job that makes the log public: rebuilds the Merkle tree from
storage's canonical log bytes, signs a tree head with the operator's Ed25519
log key, and writes `sth-<size>.json` + `latest.json` to every configured
publication target (v1: local directories; the public GitHub repo target of
M4-2 plugs into the same list).

```bash
npm run publish-sth -- [--db file:cbd.db] [--key logkey.pkcs8.hex] <target-dir> [more...]
```

First run generates the log key and writes the public half alongside as
`logkey.spki.hex` — publish that file; auditors verify every published head
against it with the anonymity-core audit CLI:
`npm run audit -- verify-sth latest.json logkey.spki.hex`. Programmatic use:
`publishSth(storage, logPrivateKey, targets)`.

## Run it

Requires Node ≥ 22.6.

```bash
cd packages/services
npm install   # @libsql/client
npm test      # storage invariants + issuer + verifier suites (incl. concurrency races)
```

## Storage backend

libSQL (embedded SQLite): `:memory:` in tests, a local `file:` DB in dev. The
service-stack ADR keeps hosting deferred-but-bounded; nothing here assumes a
particular deployment.

## License

Apache-2.0.
