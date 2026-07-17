/**
 * esbuild bundling for sdk-web: (a) ESM for NPM consumers, (b) single-file
 * IIFE for CDN/script-tag embedding — per the browser-delivery ADR. Output is
 * reproducible bit-for-bit (task M3-4): the toolchain is pinned to an exact
 * esbuild version (no `^`) in package.json + package-lock.json, and the build
 * is made cwd-independent below so an auditor rebuilding from any directory
 * gets a byte-identical artifact.
 *
 * Bundles anonymity-core (relative-path import) and its one runtime dep
 * (@cloudflare/blindrsa-ts, resolved from anonymity-core's node_modules) into
 * self-contained files — pure TS over WebCrypto, no WASM.
 */

import { build } from "esbuild";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

const OUTPUTS = {
  esm: path.join(root, "dist", "sdk-web.esm.js"),
  iife: path.join(root, "dist", "sdk-web.iife.js"),
};

export async function buildAll({ silent = false } = {}) {
  const common = {
    entryPoints: [path.join(root, "src", "index.ts")],
    bundle: true,
    target: "es2022",
    sourcemap: false,
    // Determinism: esbuild derives the `// path` provenance comments it embeds
    // from the working directory. Pinning it to the package root makes those
    // comments — and thus the byte output — independent of the process cwd, so
    // `node build.mjs` and `node packages/sdk-web/build.mjs` produce the SAME
    // bytes. Without this, a rebuild from the repo root differs (M3-4 finding).
    absWorkingDir: root,
    logLevel: silent ? "silent" : "info",
  };
  await build({ ...common, format: "esm", outfile: OUTPUTS.esm });
  await build({
    ...common,
    format: "iife",
    globalName: "AwsCbdSdkWeb",
    outfile: OUTPUTS.iife,
  });
  return [OUTPUTS.esm, OUTPUTS.iife];
}

/**
 * Subresource Integrity per the W3C SRI spec: sha384-<base64(sha384(bytes))>.
 * Computed over the exact file bytes a CDN would serve.
 */
export function sriFor(bytes) {
  return `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
}

/**
 * Emit SRI metadata for the built bundles: a per-bundle `.sri` text file (the
 * bare `integrity=` value) plus a machine-readable `dist/sri.json` manifest
 * and a human-readable `dist/sri-snippet.html` showing the exact <script> embed
 * a vendor pins. Returns the manifest object.
 */
export async function writeSri() {
  const iifeBytes = await readFile(OUTPUTS.iife);
  const esmBytes = await readFile(OUTPUTS.esm);
  const iifeSri = sriFor(iifeBytes);
  const esmSri = sriFor(esmBytes);

  await writeFile(`${OUTPUTS.iife}.sri`, iifeSri + "\n");
  await writeFile(`${OUTPUTS.esm}.sri`, esmSri + "\n");

  const manifest = {
    algorithm: "sha384",
    files: {
      "sdk-web.iife.js": { integrity: iifeSri, bytes: iifeBytes.length },
      "sdk-web.esm.js": { integrity: esmSri, bytes: esmBytes.length },
    },
    note: "Recompute with `npm run build` (or `node build.mjs`); test/sri.test.ts pins these against drift.",
  };
  await writeFile(
    path.join(root, "dist", "sri.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );

  const snippet = `<!-- CDN embed for the AWS Confidential-by-Design browser SDK.
     Pin BOTH the exact version URL and the SRI hash; the browser refuses to
     run the script if the fetched bytes do not match the integrity value. -->
<script
  src="https://YOUR-CDN/@aws-cbd/sdk-web@VERSION/sdk-web.iife.js"
  integrity="${iifeSri}"
  crossorigin="anonymous"></script>
<script>
  // The global the IIFE bundle defines:
  const client = AwsCbdSdkWeb.createSurveyClient({ /* ... */ });
</script>
`;
  await writeFile(path.join(root, "dist", "sri-snippet.html"), snippet);

  return manifest;
}

// Run-as-main check via pathToFileURL — the bare-string comparison silently
// fails on Windows (see CHANGES.md 2026-07-11, audit-CLI fix).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildAll();
  const manifest = await writeSri();
  console.log("SRI (sha384):");
  for (const [name, { integrity }] of Object.entries(manifest.files)) {
    console.log(`  ${name}  ${integrity}`);
  }
}
