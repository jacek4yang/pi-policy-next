// Material-action digest (P2). Approval authorizes the EXACT material
// action: canonical serialization over intent fields only — no timestamps,
// no UI text, no request ids, no tool name. Identical material actions
// share one digest; any material change produces a different digest.

import { createHash } from "node:crypto";
import type { ApprovalIntent, MaterialRef } from "./types.ts";

/**
 * Canonical JSON: object keys sorted recursively, arrays kept in order
 * EXCEPT `paths` which is sorted by the caller (order-independence for
 * path sets is asserted by tests), undefined fields omitted.
 */
export function canonicalJson(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${serialize(v)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

function stableRef(ref?: MaterialRef): MaterialRef | undefined {
  if (!ref) return undefined;
  return {
    kind: ref.kind,
    repo: ref.repo,
    id: ref.id,
    head: ref.head,
    method: ref.method,
  };
}

/** Normalize an ApprovalIntent for hashing: deterministic path ordering. */
export function normalizeIntent(intent: ApprovalIntent): ApprovalIntent {
  return {
    v: 1,
    actionClass: intent.actionClass,
    op: intent.op,
    paths: intent.paths ? [...intent.paths].sort() : undefined,
    recursive: intent.recursive,
    ref: stableRef(intent.ref),
    command: intent.command,
    impactBytes: intent.impactBytes,
  };
}

/** sha256 digest over the canonical material intent. */
export function intentDigest(intent: ApprovalIntent): string {
  const canonical = canonicalJson(normalizeIntent(intent));
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/** True when two intents are materially identical (digest equality). */
export function sameMaterialAction(a: ApprovalIntent, b: ApprovalIntent): boolean {
  return intentDigest(a) === intentDigest(b);
}
