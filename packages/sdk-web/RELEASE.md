# Release recipe — `@aws-cbd/sdk-web`

The respondent-side SDK **is** the trust surface: the browser-crypto-delivery
ADR names "SDK modified in transit to leak secrets" as a threat, and answers it
with a **reproducible build** (an auditor can rebuild the published bytes
bit-for-bit) plus **Subresource Integrity** (the browser refuses to run bytes
that don't match the pinned hash). This document is the human checklist that
keeps those two guarantees true for every release.

> `dist/` is git-ignored on purpose — the published artifact is *derived*, and
> the recipe below regenerates it. What's committed is the pinned input
> (`package.json` + both `package-lock.json`s + source); what's published is the
> output of running this recipe against that input.

## What is pinned (the reproducibility claim, stated honestly)

The build is byte-identical when **all** of the following match:

| Input | Pin | Where |
|---|---|---|
| Bundler | esbuild **exactly `0.25.12`** (no `^`) | `packages/sdk-web/package.json` + its `package-lock.json` |
| SDK source | this repo at the release tag | git |
| `anonymity-core` source | bundled by relative import | `packages/anonymity-core/src/` at the release tag |
| `@cloudflare/blindrsa-ts` | esbuild inlines it from anonymity-core's `node_modules` | `packages/anonymity-core/package-lock.json` |
| Node | major **22** (`engines: >=22.6.0`) | see note below |

**Node version — the honest claim.** esbuild is a self-contained native binary;
its output depends on the esbuild version and the input bytes, **not** on the
Node patch release. We verified byte-identical output across Node 22.x. The
reproducibility guarantee is therefore *"same esbuild version + same source +
same lockfiles → same bytes,"* independent of Node patch. We keep
`engines: >=22.6.0` (matching the rest of the monorepo, which needs native
TS-strip) rather than pinning an exact Node patch, because doing so would imply
a dependency that does not exist and would break contributors on newer 22.x for
no reproducibility gain. If a future esbuild bump ever makes output
Node-sensitive, tighten this line and say so here.

**Two determinism hazards handled in `build.mjs`, not just documented:**

1. **cwd-relative provenance comments.** esbuild embeds `// <path>` comments
   derived from the working directory, so a rebuild from the repo root produced
   *different bytes* than one from the package dir. Fixed with
   `absWorkingDir: root` — output is now identical regardless of where the build
   is invoked. Pinned by `test/sri.test.ts`.
2. **No timestamps / absolute paths / CRLF in the bundle.** `sourcemap: false`
   (no build-time paths), esbuild emits LF only, and no drive-letter path leaks
   in. A test asserts the bundle contains neither a `C:\`-style path nor a CR
   byte.

## Release steps

Run from a clean checkout at the release tag.

1. **Verify Node major.** `node --version` → must be `v22.x`.
2. **Clean-install pinned deps (never `npm install` at release time):**
   ```
   cd packages/anonymity-core && npm ci
   cd ../sdk-web             && npm ci
   ```
   `npm ci` installs exactly the lockfile; `npm install` may drift a transitive
   dep and silently change the output hash.
3. **Build + generate SRI (one command — they can never be out of sync):**
   ```
   npm run build     # esbuild → dist/*.js, then writes dist/sri.json + *.sri
   ```
   The command prints the sha384 SRI value for each bundle.
4. **Prove reproducibility (optional but recommended for an audited release):**
   ```
   npm test          # includes the two-build byte-identity + SRI tests
   ```
   Or by hand: hash `dist/sdk-web.iife.js`, `rm -rf dist`, rebuild, hash again —
   the two hashes must be equal.
5. **Compare against the previously published hash.** Diff the new
   `dist/sri.json` integrity value against the one from the last release.
   - **Unchanged source but changed hash → STOP.** A dependency drifted without
     a version bump (most likely esbuild or a `blindrsa-ts`/anonymity-core
     lockfile change). Investigate before publishing.
   - **Changed only because source/deps legitimately changed → expected;** the
     new hash becomes the one vendors must re-pin to.
6. **Publish the artifact + hash to the CDN.** *No CDN is provisioned yet — the
   host is chosen in task M6-1.* When it exists, publish
   `dist/sdk-web.iife.js` (and `.esm.js` for NPM consumers) under an
   **immutable, version-pinned URL** (never a floating `latest`), alongside the
   `sha384-…` integrity value. Add npm provenance attestation and a signed
   release tag per the browser-delivery ADR §4.
7. **Update the integration docs** (this package's README embed snippet and any
   vendor-facing guide) with the new version URL + integrity value.

## The vendor embed (the only supported form)

The IIFE bundle is loaded with SRI pinned — this is the *recommended* profile
(the browser-delivery ADR: vendors self-host the file with an SRI lock). The
exact snippet, with the live hash filled in, is regenerated every build at
`dist/sri-snippet.html`:

```html
<script
  src="https://YOUR-CDN/@aws-cbd/sdk-web@VERSION/sdk-web.iife.js"
  integrity="sha384-…"
  crossorigin="anonymous"></script>
<script>
  const client = AwsCbdSdkWeb.createSurveyClient({ /* ... */ });
</script>
```

`crossorigin="anonymous"` is **required** for SRI to be enforced on a
cross-origin script; without it the browser will not check the integrity value.
Pin the exact version in the URL so the pinned hash always matches the bytes.
