/**
 * M3-4 reproducible-build + SRI pins. Three properties an auditor relies on:
 *
 *  1. Two independent clean builds are byte-identical (deterministic output).
 *  2. The build is cwd-independent — the same bytes whether invoked from the
 *     package dir or the repo root (esbuild embeds cwd-relative provenance
 *     comments; `absWorkingDir` in build.mjs neutralises that).
 *  3. The emitted SRI value equals an independently recomputed sha384 of the
 *     bundle bytes, per the W3C SRI spec (sha384-<base64>), so the published
 *     integrity hash can never silently drift from the artifact.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// @ts-expect-error plain-JS build script, no declaration file
import { buildAll, writeSri, sriFor } from "../build.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const dist = path.join(root, "dist");

function sha384Base64(bytes: Buffer): string {
  return createHash("sha384").update(bytes).digest("base64");
}

test("two clean builds produce byte-identical bundles", async () => {
  await buildAll({ silent: true });
  const a1 = await readFile(path.join(dist, "sdk-web.iife.js"));
  const e1 = await readFile(path.join(dist, "sdk-web.esm.js"));

  await buildAll({ silent: true });
  const a2 = await readFile(path.join(dist, "sdk-web.iife.js"));
  const e2 = await readFile(path.join(dist, "sdk-web.esm.js"));

  assert.ok(a1.equals(a2), "IIFE bundle is bit-identical across rebuilds");
  assert.ok(e1.equals(e2), "ESM bundle is bit-identical across rebuilds");
});

test("no absolute path or CRLF leaks into the reproducible bundle", async () => {
  await buildAll({ silent: true });
  const iife = await readFile(path.join(dist, "sdk-web.iife.js"));
  // A Windows absolute path (C:\ or C:/) leaking in would make the hash
  // machine-specific; esbuild's provenance comments must stay relative.
  assert.doesNotMatch(iife.toString("latin1"), /[A-Za-z]:[\\/]/, "no drive-letter path");
  assert.equal(iife.includes(0x0d), false, "no CR byte (LF-only output)");
});

test("SRI value matches an independently recomputed sha384 of the bytes", async () => {
  await buildAll({ silent: true });
  const manifest = await writeSri();

  for (const name of ["sdk-web.iife.js", "sdk-web.esm.js"]) {
    const bytes = await readFile(path.join(dist, name));
    const expected = `sha384-${sha384Base64(bytes)}`;

    // (a) the helper agrees with a hand-rolled hash
    assert.equal(sriFor(bytes), expected, `sriFor() matches spec hash for ${name}`);
    // (b) the manifest agrees
    assert.equal(manifest.files[name].integrity, expected, `sri.json matches for ${name}`);
    assert.equal(manifest.files[name].bytes, bytes.length, `byte count recorded for ${name}`);
    // (c) the per-file .sri text file agrees
    const sriFile = (await readFile(path.join(dist, `${name}.sri`), "utf8")).trim();
    assert.equal(sriFile, expected, `${name}.sri matches`);
  }
});

test("sri.json manifest and human snippet are emitted and well-formed", async () => {
  await buildAll({ silent: true });
  await writeSri();

  const parsed = JSON.parse(await readFile(path.join(dist, "sri.json"), "utf8"));
  assert.equal(parsed.algorithm, "sha384");
  assert.match(parsed.files["sdk-web.iife.js"].integrity, /^sha384-[A-Za-z0-9+/]+=*$/);

  const snippet = await readFile(path.join(dist, "sri-snippet.html"), "utf8");
  assert.match(snippet, /integrity="sha384-[A-Za-z0-9+/]+=*"/, "snippet shows the integrity attr");
  assert.match(snippet, /crossorigin="anonymous"/, "snippet shows crossorigin (SRI requires it)");
  // The snippet's integrity value must be the real one for the current bundle.
  const iifeBytes = await readFile(path.join(dist, "sdk-web.iife.js"));
  assert.ok(
    snippet.includes(`sha384-${sha384Base64(iifeBytes)}`),
    "snippet integrity equals the live bundle hash",
  );
});
