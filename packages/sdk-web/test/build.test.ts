/**
 * Build smoke test — the esbuild ESM + IIFE outputs required by M3-2's
 * acceptance. (Bit-for-bit reproducibility and SRI are task M3-4; here we only
 * prove the two artifacts build and are shaped right.)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// @ts-expect-error plain-JS build script, no declaration file
import { buildAll } from "../build.mjs";

test("esbuild produces self-contained ESM and IIFE bundles", async () => {
  const [esmPath, iifePath] = (await buildAll({ silent: true })) as [string, string];

  const esm = await readFile(esmPath, "utf8");
  assert.ok(esm.length > 1000, "ESM bundle is non-trivial");
  assert.match(esm, /export\s*\{[^}]*createSurveyClient/s, "ESM exports the client factory");

  const iife = await readFile(iifePath, "utf8");
  assert.ok(iife.length > 1000, "IIFE bundle is non-trivial");
  assert.doesNotMatch(iife, /^\s*(import|export)\s/m, "IIFE has no module syntax");

  // Evaluating the IIFE must yield the `AwsCbdSdkWeb` binding a CDN <script>
  // tag consumer gets. (Indirect eval can't observe it — the bundle's
  // "use strict" scopes eval vars — so run it in a function and return it.)
  const api = new Function(`${iife}; return AwsCbdSdkWeb;`)() as Record<string, unknown>;
  assert.ok(api, "IIFE defines the AwsCbdSdkWeb global");
  assert.equal(typeof api.createSurveyClient, "function");
  assert.equal(typeof api.MemoryStorage, "function");
});
