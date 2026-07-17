# `@aws-cbd/sdk-server` — vendor backend SDK

The small library a survey vendor runs on **their own backend** to participate
in the confidential-by-design flow (Profile A of the
[data-flow-topology ADR](../../docs/04-implementation-plan/adr/2026-07-01-data-flow-topology.md)).
It does three things and nothing else — no survey logic, no dashboards, no
respondent state:

1. **`mintEligibilityAssertion(claims, vendorPrivateKey)`** — vouch that a
   respondent may take a survey, as the short-lived EdDSA JWT the hosted
   **issuer** service verifies before it blind-signs a token.
2. **`verifyReceipt(submission, receiptPublicKey)`** — check that a redeemed
   token's receipt is a genuine, commitment-bound acknowledgement for exactly
   the answer the vendor stored.
3. **`subjectRef(hmacKey, vendorUserId)`** — derive the opaque per-respondent
   reference the issuer dedupes on, so raw user ids never leave the vendor.

The SDK is WebCrypto + `hono/jwt` (pinned to the same `hono` the services
verify with, so the assertion format can't drift) + `@aws-cbd/anonymity-core`
for the canonical commitment and receipt-message encoding.

## The whole vendor integration (under one page)

```ts
import {
  mintEligibilityAssertion,
  verifyReceipt,
  subjectRef,
} from "@aws-cbd/sdk-server";

// One vendor-held secret; never leaves your backend.
const HMAC_KEY = /* 32 random bytes from your secret store */;

// (A) A respondent is eligible → hand their browser an assertion.
//     `subjectRef` is a stable, key-separated pseudonym for your user id, so
//     the issuer can enforce one-token-per-subject without ever seeing the id.
app.post("/eligibility", async (req, res) => {
  const ref = await subjectRef(HMAC_KEY, req.user.id);
  const assertion = await mintEligibilityAssertion(
    {
      surveyId: "2026-q3-engagement",
      cohortLabel: "engineering",
      subjectRef: ref,
      exp: Math.floor(Date.now() / 1000) + 300, // 5 min, single use
    },
    vendorPrivateKey, // Ed25519; public half pre-registered with the issuer
  );
  res.json({ assertion });
});

// (B) The browser redeems its token and submits the answer back to you with the
//     receipt. Verify the receipt binds that exact stored answer before you
//     trust the row. `c` is NOT sent — it is recomputed here from payload+salt.
app.post("/submit", async (req, res) => {
  const { surveyId, payload, salt, tokenHash, receipt } = req.body;
  const ok = await verifyReceipt(
    { surveyId, payload, salt, tokenHash, receipt },
    receiptPublicKey, // the verifier's published receipt key
  );
  if (!ok) return res.status(400).json({ error: "unverified-receipt" });
  await db.storeAnswer({ surveyId, payload, salt, tokenHash, receipt });
  res.json({ stored: true });
});
```

That is the entire backend surface: mint on eligibility, verify on submit.

## Vendor-submit contract (decided in M3-1)

The respondent's browser submits `{ surveyId, payload, salt, tokenHash, receipt }`:

| Field | Type | Source |
|---|---|---|
| `surveyId` | string | the survey being answered |
| `payload`  | JSON | the answer the browser committed to |
| `salt`     | 32-byte hex (or raw bytes) | the browser's commitment salt |
| `tokenHash`| SHA-256 hex | echoed by the verifier's redeem response |
| `receipt`  | Ed25519 hex | the verifier's redeem response |

The commitment `c` is **deliberately not transmitted**. The vendor recomputes
`c = SHA-256(salt ‖ canonicalJson(payload))` and verifies the receipt over
`(surveyId, tokenHash, c)`. This is what makes the receipt bind to the *stored*
answer: a vendor cannot swap the payload after the fact without the receipt
failing. The receipt-message bytes are byte-identical to the verifier service's
`receiptMessage`; the test suite pins that by verifying a receipt from the real
verifier and minting an assertion accepted by the real issuer.

## Tests

```
npm test
```

Drives the SDK against the **real** issuer and verifier services (imported from
`@aws-cbd/services`), not mocks, so any assertion/receipt format drift fails the
build. 8 tests: assertion accept / wrong-key reject / expired reject, receipt
verify (bytes + hex salt), five-way tamper rejection, malformed-input safety,
`subjectRef` determinism + key separation, and a `subjectRef → assertion →
one-per-subject` integration.
