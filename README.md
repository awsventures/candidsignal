# CandidSignal — core packages

Provably anonymous employee surveys. Not a survey platform — a math-proven
anonymity layer that existing survey vendors integrate to make responses
untraceable to individuals, without either party trusting the other.

- **Anonymity is unconditional.** The respondent's browser blinds a
  one-time token before it's signed (RSABSSA, RFC 9474, via Cloudflare's
  `blindrsa-ts`). The information needed to link a response back to a
  person is never created — not by us, not by the vendor, not by both
  colluding.
- **Integrity is conditional but auditable.** Every redemption and every
  per-survey issued/redeemed counter is appended to a signed Merkle
  transparency log (RFC 6962/9162, the mechanism behind Certificate
  Transparency), mirrored publicly at
  [aws-candidsignal-transparency-log](https://github.com/awsventures/aws-candidsignal-transparency-log).
  Tampering is detectable, not impossible — and we say so.

Live demo: **https://app.candidsignal.com** — take a survey as a fake
employee, watch each cryptographic step narrated, try to submit twice
(refused), and verify your own receipt against the public log.

Site: **https://www.candidsignal.com** · Trust/verification page:
**https://www.candidsignal.com/trust.html**

## Packages

| Package | What it is | Tests |
|---|---|---|
| `packages/anonymity-core` | RFC 9474 blind-token core, canonical encoding, key lifecycle, Merkle transparency log, audit CLI. Single runtime dependency (`@cloudflare/blindrsa-ts`); otherwise dependency-free WebCrypto. | 47 |
| `packages/services` | Issuer + verifier services (Hono), libSQL storage with DB-constraint-enforced uniqueness, STH publisher. | 39 |
| `packages/sdk-server` | Vendor-side SDK: mint eligibility assertions, verify receipts, derive `subjectRef`. | 8 |
| `packages/sdk-web` | Respondent-side browser SDK: session-scoped retry-safe state machine, reproducible esbuild build with SRI. | 17 |

## Running

Each package is independently testable. Because packages import
`anonymity-core` by relative path, install it first:

```bash
cd packages/anonymity-core && npm install && npm test
cd packages/services && npm install && npm test
cd packages/sdk-server && npm install && npm test
cd packages/sdk-web && npm install && npm test
```

Requires Node ≥22.6 (TypeScript runs natively via
`--experimental-strip-types`; no build step for tests). CI
(`.github/workflows/test.yml`) runs the same matrix on every push.

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Verify us

The [trust page](https://www.candidsignal.com/trust.html) is the honest
index: what you can check yourself right now, the trust model in one
paragraph, and the explicit list of how we could cheat and how you'd
catch us.
