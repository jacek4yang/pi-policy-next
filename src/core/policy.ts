// Pure policy decision engine (P1/P3/P4 core). Deterministic: all inputs
// (context, action, grants, now) are provided; no wall clock, no platform
// reads, no I/O, no model. Rules:
//   - DENY only for actions that are never allowed under current trust
//     (protected-resource mutation, credential change, root deletion);
//   - REQUIRE_APPROVAL for high-impact or uncertain actions (P4);
//   - ALLOW for provably read-only actions and (profile-dependent) trusted
//     workspace edits/execution;
//   - project trust reduces friction, NEVER lifts high-impact gates.

import { isInside, relationToWorkspace } from "./paths.ts";
import type { ApprovalGrant, PolicyAction, PolicyContext, PolicyDecision } from "./types.ts";

export interface DecideInput {
  action: PolicyAction;
  /** Digest of the action's canonical ApprovalIntent. */
  digest: string;
  ctx: PolicyContext;
  /** Valid grants available (already decoded); engine never mutates them. */
  grants: ReadonlyArray<ApprovalGrant>;
  /** Deterministic clock for expiry checks. */
  now: number;
}

export function decide(input: DecideInput): PolicyDecision {
  const { action, ctx } = input;
  const rootDenial = protectedDenial(action, ctx);
  if (rootDenial) return rootDenial;

  // A valid grant covers the action when it is not permanently denied.
  const granted = matchGrant(input);
  if (granted) {
    return {
      kind: "allow",
      reason: grantReason(granted),
      actionClass: action.class,
    };
  }

  switch (action.class) {
    case "read":
      return allow(action, "read-only operation");
    case "git-safe":
      return allow(action, "inspection-only git operation");
    case "github-read":
    case "ci-read":
      return allow(action, "read-only remote inspection");

    case "write":
    case "create":
    case "overwrite":
      return decideWorkspaceEdit(action, ctx);

    case "execute": {
      if (ctx.profile === "safe") {
        return requireApproval(action, "execution requires approval in safe profile");
      }
      if (ctx.isProjectTrusted && allInsideWorkspace(action, ctx)) {
        return allow(action, "trusted workspace execution");
      }
      return requireApproval(action, "execution outside trusted workspace");
    }

    case "delete":
      if (ctx.profile === "autonomous" && allInsideWorkspace(action, ctx)) {
        return allow(action, "non-recursive in-workspace delete (autonomous profile)");
      }
      return requireApproval(action, "delete operations require explicit approval");

    case "recursive-delete":
      return requireApproval(action, "recursive destructive operation");

    case "git-destructive":
      return requireApproval(action, "destructive git operation");

    case "github-write":
    case "github-destructive":
    case "ci-control":
    case "network-side-effect":
      return requireApproval(action, `high-impact remote operation (${action.class})`);

    case "system-change":
      return requireApproval(action, "system/service configuration requires approval");

    case "credential-change":
      return {
        kind: "deny",
        reason: "credential mutation is never allowed through the agent",
        actionClass: action.class,
        permanent: true,
      };

    case "unknown":
      return requireApproval(action, "unclassifiable action fails toward approval (P4)");

    default: {
      // Exhaustiveness guard: an unrecognized class must never allow.
      const exhaustive: never = action.class;
      void exhaustive;
      return requireApproval(action, "unrecognized action class");
    }
  }
}

function allow(action: PolicyAction, reason: string): PolicyDecision {
  return { kind: "allow", reason, actionClass: action.class };
}

function requireApproval(action: PolicyAction, reason: string): PolicyDecision {
  return { kind: "require-approval", reason, actionClass: action.class };
}

function grantReason(grant: ApprovalGrant): string {
  switch (grant.scope) {
    case "once":
      return "approved once for this exact action";
    case "exact-action":
      return "approved for this exact action (session scope)";
    case "session-class":
      return `approved for all ${grant.actionClass} actions this session (explicit user grant)`;
  }
}

function decideWorkspaceEdit(action: PolicyAction, ctx: PolicyContext): PolicyDecision {
  if (sealedPathHit(action, ctx)) {
    return {
      kind: "deny",
      reason: "path is protected by policy",
      actionClass: action.class,
      permanent: true,
    };
  }
  if (ctx.profile === "safe") {
    return requireApproval(action, "workspace mutation requires approval in safe profile");
  }
  const inside = allInsideWorkspace(action, ctx);
  if (inside && ctx.isProjectTrusted) {
    return allow(action, "trusted workspace edit");
  }
  return requireApproval(
    action,
    inside ? "workspace is not trusted" : "mutation outside the workspace",
  );
}

function allInsideWorkspace(action: PolicyAction, ctx: PolicyContext): boolean {
  const paths = action.paths ?? [];
  if (paths.length === 0) return action.class === "execute";
  return paths.every((p) => relationToWorkspace(p.canonical, ctx.workspaceRoot) === "inside");
}

/**
 * Sealed resources: mutation of/inside them is denied outright (agent
 * credentials, home, operator-declared). The workspace root is a BOUNDARY,
 * not sealed — its contents are the normal work surface.
 */
function sealedPathHit(action: PolicyAction, ctx: PolicyContext): boolean {
  const targets = (action.paths ?? []).map((p) => p.canonical);
  const resources = sealedResources(ctx);
  for (const t of targets) {
    for (const r of resources) {
      if (isInside(t, r, ctx.platform === "win32")) return true;
    }
  }
  return false;
}

export function sealedResources(ctx: PolicyContext): string[] {
  const list: string[] = [];
  if (ctx.agentDir) list.push(ctx.agentDir);
  // homeDir is deliberately NOT sealed: workspaces usually live under it
  // (its ROOT deletion is denied as a boundary, contents stay workable).
  if (ctx.protectedPaths) list.push(...ctx.protectedPaths);
  return list;
}

/** Denials that hold regardless of grants or profile. */
function protectedDenial(action: PolicyAction, ctx: PolicyContext): PolicyDecision | undefined {
  if (action.class === "credential-change") {
    return {
      kind: "deny",
      reason: "credential mutation is never allowed through the agent",
      actionClass: action.class,
      permanent: true,
    };
  }
  if (action.class === "delete" || action.class === "recursive-delete") {
    // Sealed resources (credential stores, agent state, declared paths):
    // deny any delete of/inside them. Boundary roots (home, workspace):
    // deny deleting the ROOT itself; contents are approval-gated work.
    if (sealedPathHit(action, ctx)) {
      return {
        kind: "deny",
        reason: "delete target is a protected resource",
        actionClass: action.class,
        permanent: true,
      };
    }
    if (isBoundaryRootDeletion(action, ctx)) {
      return {
        kind: "deny",
        reason: "deleting a home or workspace root is never allowed",
        actionClass: action.class,
        permanent: true,
      };
    }
  }
  return undefined;
}

function isBoundaryRootDeletion(action: PolicyAction, ctx: PolicyContext): boolean {
  const roots: string[] = [];
  if (ctx.workspaceRoot) roots.push(ctx.workspaceRoot);
  if (ctx.homeDir) roots.push(ctx.homeDir);
  return (action.paths ?? []).some((p) => roots.some((r) => r === p.canonical));
}

/**
 * Grant matching (P2/P3): digest equality, expiry, scope. `once` grants are
 * consumed by the CALLER (ledger) on execution, not by the engine.
 */
export function matchGrant(input: DecideInput): ApprovalGrant | undefined {
  const { grants, now } = input;
  for (const grant of grants) {
    if (grant.scope === "session-class") {
      if (grant.actionClass === input.action.class && !expired(grant, now)) return grant;
      continue;
    }
    if (grant.digest !== input.digest) continue;
    if (!expired(grant, now)) return grant;
  }
  return undefined;
}

function expired(grant: ApprovalGrant, now: number): boolean {
  return grant.expiresAt !== undefined && now >= grant.expiresAt;
}
