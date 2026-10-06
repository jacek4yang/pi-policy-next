// Approval grant ledger: bounded, in-memory, session-scoped. No journal —
// one-time and exact-action grants need no durable history for correctness
// (audit trail is the pinx.policy.decision event stream, which consumers may
// persist). Corruption is impossible by construction (no persistence).
// Scope semantics (P3): `once` is consumed on use; `exact-action` remains
// valid for identical digests until expiry; `session-class` covers an action
// CLASS for the session and is ONLY created on an explicit user selection.

import { intentDigest } from "./digest.ts";
import type { ApprovalGrant, ApprovalIntent, PolicyActionClass } from "./types.ts";

const MAX_GRANTS = 128;

export class ApprovalLedger {
  private grants = new Map<string, ApprovalGrant>(); // key: digest (or class key)

  /** Record a grant; bounded (oldest non-`once` entry evicted at capacity). */
  grant(
    intent: ApprovalIntent,
    scope: ApprovalGrant["scope"],
    grantedAt: number,
    opts?: { ttlMs?: number; actionClass?: PolicyActionClass },
  ): ApprovalGrant {
    const effective: ApprovalIntent =
      scope === "session-class"
        ? { v: 1, actionClass: opts?.actionClass ?? intent.actionClass, op: "*" }
        : intent;
    const key =
      scope === "session-class" ? `class:${effective.actionClass}` : intentDigest(effective);
    const record: ApprovalGrant = {
      digest: key,
      scope,
      actionClass: opts?.actionClass,
      grantedAt,
      expiresAt: opts?.ttlMs !== undefined ? grantedAt + opts.ttlMs : undefined,
    };
    if (this.grants.size >= MAX_GRANTS && !this.grants.has(key)) {
      const oldest = this.grants.keys().next().value;
      if (oldest !== undefined) this.grants.delete(oldest);
    }
    this.grants.set(key, record);
    return record;
  }

  /** All currently recorded grants (expiry checked by the caller/engine). */
  list(): ReadonlyArray<ApprovalGrant> {
    return [...this.grants.values()];
  }

  /**
   * Consume semantics after EXECUTION of an allowed action: `once` grants
   * are removed; others persist until expiry or session end.
   */
  consume(digest: string): void {
    const record = this.grants.get(digest);
    if (record?.scope === "once") this.grants.delete(digest);
  }

  clear(): void {
    this.grants.clear();
  }

  get size(): number {
    return this.grants.size;
  }
}

export { intentDigest };
