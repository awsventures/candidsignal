/**
 * STH publisher runner — `npm run publish-sth -- [--db <url>] [--key <file>] <target-dir> [more-dirs...]`
 *
 * Dev-shaped: opens the storage DB (default `file:cbd.db`), loads the Ed25519
 * log key from `--key` (default `logkey.pkcs8.hex`; generated on first run,
 * with the public half written alongside as `<name>.spki.hex` — that public
 * file is what auditors pass to the audit CLI's `verify-sth`), publishes an
 * STH to every target directory, and prints the tree head.
 */

import { readFile, writeFile } from "node:fs/promises";
import { toHex } from "../../anonymity-core/src/index.ts";
import { Storage } from "./storage.ts";
import { publishSth } from "./sth-publisher.ts";
import { fromHex } from "./http.ts";

function parseArgs(argv: string[]) {
  let db = "file:cbd.db";
  let keyFile = "logkey.pkcs8.hex";
  const targets: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--db") db = argv[++i];
    else if (argv[i] === "--key") keyFile = argv[++i];
    else targets.push(argv[i]);
  }
  return { db, keyFile, targets };
}

async function loadOrCreateKey(keyFile: string): Promise<CryptoKey> {
  try {
    const pkcs8 = fromHex((await readFile(keyFile, "utf8")).trim());
    return await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, "Ed25519", true, ["sign"]);
  } catch {
    const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    await writeFile(keyFile, toHex(pkcs8) + "\n");
    await writeFile(keyFile.replace(/\.pkcs8\.hex$/, "").concat(".spki.hex"), toHex(spki) + "\n");
    console.log(`generated new log key: ${keyFile} (publish the .spki.hex, guard the .pkcs8.hex)`);
    return pair.privateKey;
  }
}

const { db, keyFile, targets } = parseArgs(process.argv.slice(2));
if (targets.length === 0) {
  console.error("usage: npm run publish-sth -- [--db <url>] [--key <pkcs8-hex-file>] <target-dir> [more...]");
  process.exit(2);
}

const storage = await Storage.open(db);
try {
  const sth = await publishSth(storage, await loadOrCreateKey(keyFile), targets);
  console.log(`published STH: size=${sth.size} at=${sth.at} root=${sth.rootHash.slice(0, 16)}… → ${targets.join(", ")}`);
} finally {
  storage.close();
}
