# @aws-cbd/anonymity-core (prototype)

Blind-signed one-time tokens that deliver **mathematical anonymity** for survey
responses — with **no zero-knowledge circuit and no trusted setup**, built on
**RFC 9474 (RSABSSA-SHA384-PSS-Randomized)** via Cloudflare's audited
[`@cloudflare/blindrsa-ts`](https://github.com/cloudflare/blindrsa-ts). That
library is the package's single, deliberate runtime dependency: an audited
implementation of the standardized primitive is a smaller total audit surface
than maintaining our own big-integer arithmetic
([crypto-primitive ADR](../../docs/04-implementation-plan/adr/2026-07-01-crypto-primitive-production-path.md)).

This is the Phase B prototype described in
[`../../docs/04-implementation-plan/2026-06-16-prototype-blind-tokens.md`](../../docs/04-implementation-plan/2026-06-16-prototype-blind-tokens.md),
hardened per plan task M0-1.

## The guarantee, in one sentence

The issuer signs a token it cannot see (the respondent *blinds* it first), and
at redemption the issuer cannot recognise the unblinded token. So the system can
prove a respondent was eligible and prevent double-voting **without ever being
able to link a response to a person.** That unlinkability is the math — it is a
property of the blind-signature construction, not a promise.

## Run it

Requires Node ≥ 22.6 (for native TypeScript via `--experimental-strip-types`).

```bash
cd packages/anonymity-core
npm install     # one dependency: @cloudflare/blindrsa-ts
npm run demo    # end-to-end walk-through with a printed narrative
npm test        # the test suite (Node's built-in runner)
```

## Auditing the transparency log

The integrity claim is only worth something if an outsider can check it without
trusting us. The `audit` CLI is that tool: it reads the log's **published plain
JSON files** off disk and prints `PASS`/`FAIL` — no server, no database, no
account required, just this package and Node.

```bash
npm run audit -- verify-sth         <sth.json> <logkey.spki.hex>
npm run audit -- verify-inclusion   <entry.json> <index> <sth.json> <proof.json>
npm run audit -- verify-consistency <sth1.json> <sth2.json> <proof.json>
npm run audit -- check-counters     <entries.ndjson>
```

| Command | Answers the question |
|---|---|
| `verify-sth` | Is this signed tree head really the log operator's published head? |
| `verify-inclusion` | Is my receipt genuinely in the log the STH commits to? |
| `verify-consistency` | Did the log only ever grow — nothing rewritten or deleted? |
| `check-counters` | Did any survey redeem more tokens than it issued? |

Exit codes are `0` (all checks passed), `1` (a check failed), `2` (usage/IO
error), so the CLI drops straight into CI or a shell script. File formats are
documented at the top of [`audit/audit.ts`](audit/audit.ts).

## The flow

```
respondent browser            issuer (trusted to sign)        verifier (open core)
─────────────────             ────────────────────────        ────────────────────
mint token t
blind:  t' = H(t)·rᵉ  ───────► eligibility check, then
                               blind-sign: σ' = t'ᵈ
unblind: σ = σ'·r⁻¹  ◄───────  (issuer never saw t)
                                                               redeem {t, σ}:
submit {answer, t, σ}  ──────────────────────────────────────► verify σᵉ == H(t)
                                                               reject if t already spent
                                                               (never learns who)
```

## What's in here

| File | Role |
|---|---|
| `src/suite.ts` | The RFC 9474 suite (RSABSSA-SHA384-PSS-Randomized) + key-size policy |
| `src/keys.ts` | Issuer key generation; only the public key is published |
| `src/client.ts` | Respondent browser logic: mint, prepare+blind, finalize (WebCrypto-portable) |
| `src/issuer.ts` | Blind-signs after an eligibility check; never sees the token |
| `src/verifier.ts` | **The open trust core**: verify signature + spent-set (nullifier) check |
| `src/merkle-log.ts` | RFC 6962 transparency log: append, STHs, inclusion + consistency proofs |
| `audit/audit.ts` | **Public audit CLI** — verify the log from plain JSON files, no infrastructure |
| `demo/demo.ts` | Printed end-to-end demonstration |
| `demo/education/chaum-textbook.ts` | Textbook Chaum math, education only — not in the trust path |
| `test/blind-rsa.test.ts` | Correctness, double-spend, forgery, cross-key, tamper, unlinkability tests |

The **verifier** is the component that makes the anonymity claim independently
checkable. It is deliberately short and dependency-free so an auditor can read it
in a sitting. This is why the package is Apache-2.0 open source.

## What this prototype is NOT (yet)

This is a deliberately minimal proof of the core guarantee. It does **not** yet
include — and these are tracked as later iterations:

- **RFC 9474 conformance vectors + property tests** (plan task M0-2). The
  primitive is already RFC 9474 via `blindrsa-ts`; the vectors pin *our usage*
  of it in CI.
- **Browser execution.** The real trust model requires the blind/unblind step to
  run in the respondent's browser. This CLI proves the math; the browser SDK is a
  later iteration.
- **Integrity anchor** (G4) — tamper-evidence via a transparency log.
- **k-anonymity + differential-privacy gate** on analytics (the fifth layer).
- **Longitudinal linking** across survey waves (would require BBS+ pseudonyms).

See the ADR for the full list of deferred work and the revisit conditions.

## License

Apache-2.0. The patent grant matters for a cryptographic product; the open
verifier is the credibility anchor for the whole system.
