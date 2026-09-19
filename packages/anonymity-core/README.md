# @aws-cbd/anonymity-core

Blind-signed one-time tokens that deliver **mathematical anonymity** for survey
responses, with **no zero-knowledge circuit and no trusted setup**, built on
**RFC 9474 (RSABSSA-SHA384-PSS-Randomized)** via Cloudflare's audited
[`@cloudflare/blindrsa-ts`](https://github.com/cloudflare/blindrsa-ts). That
library is the package's single, deliberate runtime dependency: an audited
implementation of the standardized primitive is a smaller total audit surface
than maintaining our own big-integer arithmetic
(crypto-primitive ADR (design notes, private repo)).

The cryptographic core of CandidSignal. Milestones M0 (core hardening) and M1 (transparency log and
public audit CLI) are complete; see `work-streams.md` (design notes, private repo).
The original scope decision is in the
prototype ADR (design notes, private repo).

## The guarantee, in one sentence

The issuer signs a token it cannot see (the respondent *blinds* it first), and
at redemption the issuer cannot recognise the unblinded token. So the system can
prove a respondent was eligible and prevent double-voting **without ever being
able to link a response to a person.** That unlinkability is the math, it is a
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
JSON files** off disk and prints `PASS`/`FAIL`, no server, no database, no
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
| `verify-consistency` | Did the log only ever grow, nothing rewritten or deleted? |
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
| `audit/audit.ts` | **Public audit CLI**, verify the log from plain JSON files, no infrastructure |
| `demo/demo.ts` | Printed end-to-end demonstration |
| `demo/education/chaum-textbook.ts` | Textbook Chaum math, education only, not in the trust path |
| `test/*.test.ts` | Six suites: correctness and unlinkability, fast-check properties, canonical encoding, key lifecycle, Merkle log, audit CLI |

The **verifier** is the component that makes the anonymity claim independently
checkable. It is deliberately short and readable so an auditor can read it
in a sitting. This is why the package is Apache-2.0 open source.

## Status: what is built, and what is deliberately not

**Built and tested in this package:**

- RFC 9474 blind signatures (RSABSSA-SHA384-PSS-Randomized), 3072-bit default
- Property tests via fast-check: seed round-trip, byte-flip tamper rejection, and the
  verifier state machine over arbitrary redemption interleavings
- Canonical encoding spec and implementation (RFC 8785 / JCS profile)
- Key lifecycle with a minimum-partition floor enforced by refusal, and key destruction
- RFC 6962 Merkle transparency log: append, signed tree heads, inclusion and
  consistency proofs, with exhaustive tests over small trees
- The public audit CLI documented above

Browser execution is built too, in the sibling `sdk-web` package: real WebCrypto in a
real tab, covered by a Playwright lane including mid-flow page-reload recovery. This
package is the portable core it imports, not a CLI-only prototype.

**Deliberately not built:**

- **k-anonymity and differential-privacy analytics gate.** Milestone M5, gated on vendor
  signal so its scope is shaped by a real partner's dashboards rather than guessed.
  Until it exists, cohort-size discipline is the vendor's responsibility.
- **Zero-knowledge predicate proofs.** Eligibility is gated at issuance instead. ZK
  returns only if a partner needs predicates over hidden attributes.
- **Longitudinal linking** across survey waves. Would require BBS+ pseudonyms.
- **Blockchain anchoring.** The signed Merkle log replaces it. Available only if a buyer
  explicitly requires a chain.

**Outstanding, and stated plainly:** no **external cryptographic audit** has been
commissioned. The primitive comes from an audited upstream library, but our composition,
the spent-set logic, the log format, and the SDK build pipeline have not been reviewed by
a third party. That review is milestone M6 and is the honest gap in every claim here.

One known residual failure mode: if the `/issue` response is lost after the issuer has
claimed the subject, the retry receives a 409 and that blind signature is unrecoverable.
Idempotency covers redemption, not issuance. Documented rather than hidden.

## License

Apache-2.0. The patent grant matters for a cryptographic product, and the open verifier
is the credibility anchor for the whole system.
