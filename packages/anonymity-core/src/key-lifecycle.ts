/**
 * Key lifecycle — the partition protocol around issuer keys.
 *
 * One key pair serves one issuance partition (survey wave × coarse cohort);
 * partitioning by key is how eligibility classes work without attributes.
 * Two rules from the crypto-primitive ADR are enforced here:
 *
 *  1. **Anonymity-set floor (k_issue):** a partition whose expected token
 *     count is below K_ISSUE_FLOOR is REFUSED, not warned about. Partitioning
 *     finer than the floor silently shrinks the anonymity set toward 1 and
 *     would let cohort labels do exactly what the blind signature prevents.
 *  2. **Key destruction is a logged event:** destroying the private key after
 *     wave close converts "trust us not to sign more" into "nobody can sign
 *     more", and the `key-event` entries make creation and destruction
 *     independently auditable in the transparency log.
 *
 * NOTE: in this in-process prototype, "destruction" drops the reference and
 * disables signing; actual key-material destruction is the KMS/HSM's job in a
 * hosted deployment. This module owns the *protocol* — the floor, the events,
 * and the sign-after-destroy refusal — which is what an auditor checks.
 *
 * USAGE RULE (binding on services): resolve `partition.privateKey` at signing
 * time — do not cache an `Issuer` (or the CryptoKey) across wave close, or the
 * destroy refusal cannot bite. The M2 issuer service enforces this.
 */

import { generateIssuerKey, exportPublicKey } from "./keys.ts";
import { keyId as computeKeyId, coarseTime, type KeyEventEntry } from "./encoding.ts";

/** Minimum expected tokens per key partition (crypto-primitive ADR). */
export const K_ISSUE_FLOOR = 20;

export interface CreatePartitionOptions {
  /** Opaque partition id: identifies one survey wave × coarse cohort. */
  surveyId: string;
  /** Expected number of tokens this partition will issue (eligible headcount). */
  expectedTokenCount: number;
  /** RSA modulus size; defaults to the ADR's 3072. */
  modulusBits?: number;
}

export class IssuancePartition {
  readonly surveyId: string;
  readonly keyId: string;
  readonly publicKey: CryptoKey;
  /** The `created` log entry, ready to append to the transparency log. */
  readonly createdEntry: KeyEventEntry;

  #privateKey: CryptoKey | null;

  private constructor(
    surveyId: string,
    keyId: string,
    pair: CryptoKeyPair,
    createdEntry: KeyEventEntry,
  ) {
    this.surveyId = surveyId;
    this.keyId = keyId;
    this.publicKey = pair.publicKey;
    this.createdEntry = createdEntry;
    this.#privateKey = pair.privateKey;
  }

  static async create(opts: CreatePartitionOptions): Promise<IssuancePartition> {
    if (!opts.surveyId) throw new Error("partition refused: surveyId required");
    if (
      !Number.isInteger(opts.expectedTokenCount) ||
      opts.expectedTokenCount < K_ISSUE_FLOOR
    ) {
      throw new Error(
        `partition refused: expected token count ${opts.expectedTokenCount} is below ` +
          `the anonymity-set floor k_issue=${K_ISSUE_FLOOR}. Use a coarser cohort.`,
      );
    }
    const pair = await generateIssuerKey(opts.modulusBits);
    const id = await computeKeyId(await exportPublicKey(pair.publicKey));
    const createdEntry: KeyEventEntry = {
      type: "key-event",
      surveyId: opts.surveyId,
      event: "created",
      keyId: id,
      at: coarseTime(),
    };
    return new IssuancePartition(opts.surveyId, id, pair, createdEntry);
  }

  /** The signing key. Throws once the partition is destroyed. */
  get privateKey(): CryptoKey {
    if (this.#privateKey === null) {
      throw new Error(
        `partition ${this.surveyId} is destroyed: no further signatures can exist`,
      );
    }
    return this.#privateKey;
  }

  get destroyed(): boolean {
    return this.#privateKey === null;
  }

  /**
   * Destroy the partition's signing capability and emit the auditable event.
   * Idempotent-hostile by design: destroying twice is a caller bug and throws.
   */
  destroy(): KeyEventEntry {
    if (this.#privateKey === null) {
      throw new Error(`partition ${this.surveyId} is already destroyed`);
    }
    this.#privateKey = null;
    return {
      type: "key-event",
      surveyId: this.surveyId,
      event: "destroyed",
      keyId: this.keyId,
      at: coarseTime(),
    };
  }
}
