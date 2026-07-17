# `@aws-cbd/sdk-web` — respondent browser SDK

What a survey vendor's page embeds so the **respondent's browser** runs Profile
A of the [data-flow-topology ADR](../../docs/04-implementation-plan/adr/2026-07-01-data-flow-topology.md):
blind a token locally (the issuer signs what it cannot read), redeem it for a
commitment-bound receipt, and hand the vendor an answer they can verify came
from exactly one accepted, unlinkable token. Pure TypeScript over WebCrypto —
no WASM, no runtime dependency beyond `anonymity-core` — per the
[browser-crypto-delivery ADR](../../docs/04-implementation-plan/adr/2026-07-01-browser-crypto-delivery.md).

## API — four functions on one client

```ts
import { createSurveyClient } from "@aws-cbd/sdk-web";

const client = createSurveyClient({
  surveyId: "2026-q3-engagement",
  issuerUrl: "https://issuer.example",
  verifierUrl: "https://verifier.example",
  issuerPublicKey,          // the survey's RSA issuer key
  // storage: window.sessionStorage is the default in browsers
});

// (1) The vendor's backend handed the page an eligibility assertion.
await client.requestToken(assertion);

// (2..4) Answer collected by the vendor's UI → redeem, submit, done.
await client.submitToVendor(payload, async (submission) => {
  // {surveyId, payload, salt, tokenHash, receipt} — what sdk-server's
  // verifyReceipt consumes. `c` is never transmitted anywhere.
  await fetch("/vendor/submit", { method: "POST", body: JSON.stringify(submission) });
});
```

`redeem(payload)` and `receipt()` are also public for callers that want the
steps separately; `clear()` abandons an attempt.

## The retry state machine (the part audits care about)

Session-scoped state (`sessionStorage`, injectable), one entry per survey, and
**every network call is preceded by persisting exactly what is needed to repeat
it verbatim**:

| Phase | Persisted before the call | On failure |
|---|---|---|
| issue | `{token, blindedMsg, inv}` | retry re-sends the **same** blinded message — a second token is never minted for one attempt |
| redeem | `{salt, c}` pinned | retry re-presents the **same** `(token, c)`; the verifier is idempotent on `(t, c)` and returns the byte-identical receipt |
| vendor submit | receipt held | state is cleared **only on vendor ack** — clearing at redemption would reopen the stranded-token window across a reload |

Consequences (each pinned by a test against the *real* issuer/verifier apps):

- **Stranded-token recovery** (topology ADR §3): a redeem whose response is
  lost after the verifier spent the token is recovered — even by a fresh page
  load — with no double-count and no duplicate log entry.
- **One attempt, one answer:** the commitment is pinned at the first redeem
  attempt; calling `redeem` with a different payload afterwards throws
  `CommitmentMismatchError` locally — a conflicting `c` is never transmitted
  (the verifier would refuse it as a double-spend anyway).
- **No durable client secret:** nothing survives the browser session, and
  nothing stored is identity-linkable even if exfiltrated (a blind token
  pre-redemption, a salt, a receipt).

## Build, reproducibility & SRI

```
npm run build   # esbuild → dist/sdk-web.esm.js (NPM) + dist/sdk-web.iife.js (CDN, global AwsCbdSdkWeb)
                # ...and dist/sri.json + dist/sdk-web.*.js.sri + dist/sri-snippet.html
```

The SDK is the trust surface, so the build is **reproducible bit-for-bit** and
every release ships **Subresource Integrity** hashes — the browser-delivery ADR
§4 answer to "SDK modified in transit." The bundle is byte-identical across
rebuilds *and* across working directories (esbuild is pinned to an exact version
and `build.mjs` sets `absWorkingDir` so its embedded provenance comments don't
drift with the cwd). `npm run build` regenerates the artifacts and their sha384
SRI hashes together — they can never fall out of sync — and `test/sri.test.ts`
pins that invariant.

The full step-by-step release/verify recipe (what's pinned, how to prove
reproducibility, how to compare against the last published hash, and where the
CDN artifact + hash get published) is in **[`RELEASE.md`](RELEASE.md)**.

A vendor embeds the CDN bundle with the integrity hash pinned — the only
supported form (regenerated with the live hash at `dist/sri-snippet.html`):

```html
<script
  src="https://YOUR-CDN/@aws-cbd/sdk-web@VERSION/sdk-web.iife.js"
  integrity="sha384-…"
  crossorigin="anonymous"></script>
```

`crossorigin="anonymous"` is required for the browser to enforce SRI on a
cross-origin script; pin the exact version in the URL, never a floating
`latest`. (No CDN is provisioned yet — the host is chosen in task M6-1;
`RELEASE.md` is written to apply once it exists.)

## Tests

```
npm test
```

17 tests, no mocks: the SDK's `fetch` dispatches to the real issuer/verifier
Hono apps from `@aws-cbd/services` in-process, assertions come from the real
`@aws-cbd/sdk-server`, and the final submission is verified by its
`verifyReceipt` — wire-format drift anywhere in the chain fails the build.
Covers the full happy path, issuance/redemption retries (before-send and
response-lost), reload recovery, commitment pinning, serialized concurrent
redeems, error surfaces, a build smoke test that evaluates the IIFE, and the
M3-4 reproducibility/SRI pins (two-build byte-identity, no path/CRLF leak, and
SRI hash equals an independently recomputed sha384).
