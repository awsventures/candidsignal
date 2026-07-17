/**
 * Git-backed STH publication target (M4-2).
 *
 * `sth-publisher.ts`'s `publishSth(storage, key, targets: string[])` already
 * writes `sth-<size>.json` + `latest.json` to any list of local directories.
 * This module adds a *second kind* of target on top of that: a git working
 * copy that gets committed and pushed after each publish. Landing STHs in a
 * git repo (rather than a bare filesystem dir) gets the transparency log a
 * durable, outsider-checkable history for free — git log IS the append-only
 * record, and a force-push to rewrite it is visible to anyone holding a prior
 * clone or `git log` of the remote. That is the property M4-2 is for: a place
 * to publish STHs that we (the operator) cannot silently rewrite.
 *
 * Kept dependency-free per repo convention: shells out to the `git` binary
 * (assumed on PATH, as it must be for `gh`/CI) rather than adding a git
 * library. Tests exercise this against a local `git init --bare` repo in a
 * temp dir — no network involved.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { access, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { publishSth } from "./sth-publisher.ts";
import type { Storage } from "./storage.ts";
import type { SignedTreeHead } from "../../anonymity-core/src/index.ts";

const execFileAsync = promisify(execFile);

async function git(args: string[], cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Make `workDir` a working copy of `remote` on `branch`, up to date with
 * whatever the remote currently holds. Idempotent: safe to call before every
 * publish. Handles the brand-new-empty-repo case (no commits, no branch yet).
 */
export async function ensureWorkingRepo(
  workDir: string,
  remote: string,
  branch = "main",
): Promise<void> {
  if (await pathExists(join(workDir, ".git"))) {
    await git(["fetch", "origin", branch], workDir).catch(() => undefined);
    const hasRemoteBranch = await git(["ls-remote", "--heads", "origin", branch], workDir)
      .then((out) => out.trim().length > 0)
      .catch(() => false);
    if (hasRemoteBranch) {
      await git(["checkout", "-B", branch, `origin/${branch}`], workDir);
    } else {
      await git(["checkout", "-B", branch], workDir).catch(() => undefined);
    }
    return;
  }

  await mkdir(dirname(workDir), { recursive: true });
  try {
    await git(["clone", "--branch", branch, remote, workDir], dirname(workDir));
  } catch {
    // Empty remote (no commits yet) or the branch doesn't exist remotely —
    // clone the default state and create the branch locally.
    await git(["clone", remote, workDir], dirname(workDir));
    await git(["checkout", "-B", branch], workDir);
  }
}

/**
 * Stage everything under `workDir`, commit if there's anything new, and push
 * `branch`. Returns `pushed: false` (no commit made) when the tree is
 * unchanged from the last publish — republishing an identical STH is a no-op,
 * not an empty commit.
 */
export async function commitAndPush(
  workDir: string,
  message: string,
  branch = "main",
): Promise<{ pushed: boolean; sha: string | null }> {
  await git(["add", "-A"], workDir);
  const status = await git(["status", "--porcelain"], workDir);
  if (!status.trim()) return { pushed: false, sha: null };

  await git(
    [
      "-c",
      "user.email=transparency-log@aws-cbd.invalid",
      "-c",
      "user.name=aws-cbd transparency log",
      "commit",
      "-m",
      message,
    ],
    workDir,
  );
  await git(["push", "origin", `HEAD:${branch}`], workDir);
  const sha = (await git(["rev-parse", "HEAD"], workDir)).trim();
  return { pushed: true, sha };
}

export interface GitPublishOptions {
  /** Local working-copy directory (created/reused; becomes a git clone of `remote`). */
  workDir: string;
  /** Remote URL or local path (`git init --bare` dirs work — that's what the tests use). */
  remote: string;
  branch?: string;
  /** Written as `logkey.spki.hex` alongside the STH, so a fresh clone of the repo is self-verifying. */
  logPublicKeySpkiHex?: string;
}

/**
 * Publish an STH into a git-backed target: sync the working copy, write the
 * STH files (delegating to `publishSth` for byte-identical output with every
 * other target kind), optionally drop the log public key, commit, and push.
 */
export async function publishSthToGitRepo(
  storage: Storage,
  logPrivateKey: CryptoKey,
  opts: GitPublishOptions,
): Promise<{ sth: SignedTreeHead; pushed: boolean; sha: string | null }> {
  const branch = opts.branch ?? "main";
  await ensureWorkingRepo(opts.workDir, opts.remote, branch);

  const sth = await publishSth(storage, logPrivateKey, [opts.workDir]);

  if (opts.logPublicKeySpkiHex) {
    await writeFile(join(opts.workDir, "logkey.spki.hex"), opts.logPublicKeySpkiHex.trim() + "\n");
  }

  const { pushed, sha } = await commitAndPush(
    opts.workDir,
    `sth: size=${sth.size} at=${sth.at} root=${sth.rootHash.slice(0, 16)}…`,
    branch,
  );
  return { sth, pushed, sha };
}
