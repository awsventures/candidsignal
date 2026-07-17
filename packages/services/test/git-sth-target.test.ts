/**
 * Git-backed STH target tests (M4-2).
 *
 * Exercises `ensureWorkingRepo` / `commitAndPush` / `publishSthToGitRepo`
 * against a LOCAL `git init --bare` repo in a temp dir — no network. A bare
 * repo behaves identically to a real remote for git's purposes (clone/fetch/
 * push all work over a filesystem path), so this proves the same code path
 * that will run against the real public GitHub repo.
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Storage } from "../src/storage.ts";
import { publishSthToGitRepo } from "../src/git-sth-target.ts";
import { generateLogKey, verifyTreeHead, type SignedTreeHead, type LogEntry } from "../../anonymity-core/src/index.ts";

const execFileAsync = promisify(execFile);
async function git(args: string[], cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}

let logKeys: CryptoKeyPair;

before(async () => {
  logKeys = await generateLogKey();
});

function entry(n: number): LogEntry {
  return {
    type: "counters",
    surveyId: `survey-${n}`,
    issued: n,
    redeemed: 0,
    at: "2026-07-11T00:00Z",
  };
}

async function bareRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sth-bare-"));
  try {
    await git(["init", "--bare", "--initial-branch=main", dir], dir);
  } catch {
    // Older git without --initial-branch: init then rename default branch via config.
    await git(["init", "--bare", dir], dir);
    await git(["symbolic-ref", "HEAD", "refs/heads/main"], dir);
  }
  return dir;
}

async function cloneAndRead(remote: string, file: string): Promise<string> {
  const checkoutDir = await mkdtemp(join(tmpdir(), "sth-checkout-"));
  try {
    await git(["clone", remote, checkoutDir], checkoutDir);
    return await readFile(join(checkoutDir, file), "utf8");
  } finally {
    await rm(checkoutDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

test("publishSthToGitRepo: seeds an empty bare repo, an outside clone sees the STH", async () => {
  const remote = await bareRepo();
  const workDir = await mkdtemp(join(tmpdir(), "sth-work-"));
  const storage = await Storage.open(":memory:");
  for (let i = 1; i <= 4; i++) await storage.appendLog(entry(i));

  try {
    const spkiHex = Buffer.from(
      new Uint8Array(await crypto.subtle.exportKey("spki", logKeys.publicKey)),
    ).toString("hex");

    const result = await publishSthToGitRepo(storage, logKeys.privateKey, {
      workDir,
      remote,
      logPublicKeySpkiHex: spkiHex,
    });
    assert.equal(result.pushed, true, "first publish must produce a commit");
    assert.ok(result.sha, "a commit sha is returned");
    assert.equal(result.sth.size, 4);

    // Simulate an outside auditor: clone the bare repo fresh (no shared workDir).
    const latestRaw = await cloneAndRead(remote, "latest.json");
    const latest = JSON.parse(latestRaw) as SignedTreeHead;
    assert.equal(latest.size, 4);
    assert.ok(await verifyTreeHead(latest, logKeys.publicKey), "cloned STH verifies with the log public key");

    const keyHex = (await cloneAndRead(remote, "logkey.spki.hex")).trim();
    assert.equal(keyHex, spkiHex, "the public key file round-trips through the repo");
  } finally {
    storage.close();
    await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    await rm(remote, { recursive: true, force: true }).catch(() => undefined);
  }
});

test("publishSthToGitRepo: a second publish after appends is a new commit, git history preserves the first", async () => {
  const remote = await bareRepo();
  const workDir = await mkdtemp(join(tmpdir(), "sth-work-"));
  const storage = await Storage.open(":memory:");
  for (let i = 1; i <= 2; i++) await storage.appendLog(entry(i));

  try {
    const first = await publishSthToGitRepo(storage, logKeys.privateKey, { workDir, remote });
    assert.equal(first.sth.size, 2);

    for (let i = 3; i <= 5; i++) await storage.appendLog(entry(i));
    const second = await publishSthToGitRepo(storage, logKeys.privateKey, { workDir, remote });
    assert.equal(second.sth.size, 5);
    assert.notEqual(second.sha, first.sha, "second publish is a distinct commit");

    // History is append-only and visible: both commits exist in the bare repo's log.
    const log = await git(["log", "--oneline", "main"], remote);
    const lines = log.trim().split("\n");
    assert.equal(lines.length, 2, "two commits landed in git history");

    // A fresh clone sees the LATEST state, and the older sth-<size>.json still exists
    // (both files were committed, so the older head remains independently verifiable).
    const oldRaw = await cloneAndRead(remote, "sth-2.json");
    const old = JSON.parse(oldRaw) as SignedTreeHead;
    assert.equal(old.size, 2);
    assert.ok(await verifyTreeHead(old, logKeys.publicKey));
  } finally {
    storage.close();
    await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    await rm(remote, { recursive: true, force: true }).catch(() => undefined);
  }
});

test("publishSthToGitRepo: republishing an identical log makes no new commit", async () => {
  const remote = await bareRepo();
  const workDir = await mkdtemp(join(tmpdir(), "sth-work-"));
  const storage = await Storage.open(":memory:");
  await storage.appendLog(entry(1));

  try {
    const first = await publishSthToGitRepo(storage, logKeys.privateKey, { workDir, remote });
    const second = await publishSthToGitRepo(storage, logKeys.privateKey, { workDir, remote });
    assert.equal(second.pushed, false, "no new commit when the STH is byte-identical");
    assert.equal(second.sha, null);
    assert.ok(first.sha);
  } finally {
    storage.close();
    await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    await rm(remote, { recursive: true, force: true }).catch(() => undefined);
  }
});
