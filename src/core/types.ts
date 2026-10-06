// Pure policy core types (POLICY-MODEL contract). No Pi imports here — this
// module is deterministic, platform-injectable, and independently testable.

/** Action classes (small useful taxonomy; risk matters more than ontology). */
export type PolicyActionClass =
  | "read" // search, grep, stat, list, file reads
  | "write" // in-place content mutation
  | "create" // new file/dir
  | "overwrite" // replace existing content wholesale
  | "delete" // remove file / empty dir
  | "recursive-delete" // remove trees
  | "execute" // run programs, tests, builds, scripts
  | "git-safe" // status/log/diff/branch inspection
  | "git-destructive" // reset --hard, clean, force push, branch delete
  | "github-read"
  | "github-write"
  | "github-destructive"
  | "ci-read"
  | "ci-control"
  | "system-change" // services, drivers, system config, privileges
  | "credential-change" // auth/credential stores — never allowed via agent
  | "network-side-effect" // publish/upload/send with external effect
  | "unknown"; // unclassifiable — fails toward approval (P4)

/** Policy verdicts. The resource owner executes only after a valid decision. */
export type PolicyDecisionKind = "allow" | "deny" | "require-approval";

export interface NormalizedPath {
  /** Canonical absolute path (platform-normalized, case-folded on win32). */
  canonical: string;
  /** Original presentation form (never used for identity decisions). */
  input: string;
}

/** Git/GitHub/CI material reference — only fields that change identity. */
export interface MaterialRef {
  kind: "git" | "github" | "ci";
  repo?: string;
  id?: string; // PR number, run id, workflow id, branch/ref name
  head?: string; // expected head SHA where relevant
  method?: string; // merge method, dispatch target, etc.
}

/**
 * Normalized material action. Every field here participates in the action
 * digest EXCEPT `tool`/`source`/`presentation` — approval authorizes the
 * material action, not the tool that happened to carry it.
 */
export interface PolicyAction {
  class: PolicyActionClass;
  op: string; // operation verb, e.g. "read" | "delete" | "git-reset-hard"
  paths?: NormalizedPath[];
  recursive?: boolean;
  ref?: MaterialRef;
  /** Exact command for execute/shell classes (part of identity). */
  command?: string;
  /** Estimated impact when available (bytes). */
  impactBytes?: number;
  /** Origin — observability only, never part of the digest. */
  source: "tool" | "user-bash";
  tool: string;
}

/** Deterministic policy inputs (no wall clock inside the engine). */
export interface PolicyContext {
  platform: "win32" | "linux" | "darwin";
  /** Trusted-project flag — reduces friction, never lifts high-impact gates. */
  isProjectTrusted: boolean;
  /** Workspace root (canonical) when known. */
  workspaceRoot?: string;
  /** Home directory (canonical) — protected by default. */
  homeDir?: string;
  /** Pi agent dir (canonical) — credential/auth state, protected by default. */
  agentDir?: string;
  /** Additional operator-declared protected paths (canonical). */
  protectedPaths?: string[];
  /** Explicit profile. */
  profile: PolicyProfileName;
}

export type PolicyProfileName = "safe" | "balanced" | "autonomous";

export interface PolicyDecision {
  kind: PolicyDecisionKind;
  /** Why — shown to the human in approval prompts, to the model on block. */
  reason: string;
  /** The action class that drove the decision. */
  actionClass: PolicyActionClass;
  /** Present for deny: this action is never allowed under current trust. */
  permanent?: boolean;
}

/**
 * Canonical approval intent: ONLY material fields. Volatile presentation
 * metadata (timestamps, UI text, request ids) is excluded so identical
 * actions share one digest — approval is cache-friendly and stable (P2).
 */
export interface ApprovalIntent {
  v: 1;
  actionClass: PolicyActionClass;
  op: string;
  paths?: string[]; // canonical paths, sorted
  recursive?: boolean;
  ref?: MaterialRef;
  command?: string;
  impactBytes?: number;
}

/** A granted approval bound to one intent digest. */
export interface ApprovalGrant {
  digest: string;
  scope: "once" | "exact-action" | "session-class";
  /** For session-class: the action class covered (explicit user grant only). */
  actionClass?: PolicyActionClass;
  grantedAt: number;
  /** Wall-clock expiry; absent = session lifetime. */
  expiresAt?: number;
}

export interface ApprovalRequestPresentation {
  title: string;
  lines: string[]; // what / why / impact / scope — human-readable, structured
  scopes: Array<ApprovalGrant["scope"]>; // scopes offered to the user
}
