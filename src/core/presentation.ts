// Human approval presentation: structured, concise, honest. The decision
// object stays structured; this module only renders WHAT/WHY/IMPACT/SCOPE
// lines for the blocking dialog. It never includes protected-resource
// contents — paths and material identity only.

import type {
  ApprovalRequestPresentation,
  PolicyAction,
  PolicyContext,
  PolicyDecision,
} from "./types.ts";

const MAX_SHOWN_PATHS = 5;

export function buildPresentation(
  action: PolicyAction,
  decision: PolicyDecision,
  ctx: PolicyContext,
): ApprovalRequestPresentation {
  const lines: string[] = [];
  lines.push(`Operation: ${humanOp(action)}`);

  const paths = action.paths ?? [];
  if (paths.length > 0) {
    const shown = paths.slice(0, MAX_SHOWN_PATHS).map((p) => `  ${p.input}`);
    if (paths.length > MAX_SHOWN_PATHS) shown.push(`  … ${paths.length - MAX_SHOWN_PATHS} more`);
    lines.push("Target:", ...shown);
  }
  if (action.ref) {
    const r = action.ref;
    lines.push(
      `Resource: ${r.kind}${r.repo ? ` ${r.repo}` : ""}${r.id ? ` #${r.id}` : ""}${r.head ? ` @ ${r.head}` : ""}${r.method ? ` (${r.method})` : ""}`,
    );
  }
  if (action.recursive) lines.push("Recursive: yes");
  if (action.impactBytes !== undefined) {
    lines.push(`Estimated impact: ${formatBytes(action.impactBytes)}`);
  }
  lines.push(`Reason: ${decision.reason}`);
  if (ctx.isProjectTrusted) lines.push("Project trust: active (does not lift this gate)");

  return {
    title: title(action),
    lines,
    scopes: ["once", "exact-action", "session-class"],
  };
}

function title(action: PolicyAction): string {
  switch (action.class) {
    case "recursive-delete":
      return "Delete recursively?";
    case "delete":
      return "Delete?";
    case "git-destructive":
      return "Destructive git operation?";
    case "execute":
      return "Execute command?";
    case "system-change":
      return "System change?";
    case "unknown":
      return "Unrecognized operation?";
    default:
      return "Allow operation?";
  }
}

function humanOp(action: PolicyAction): string {
  switch (action.op) {
    case "git-reset-hard":
      return "git reset --hard";
    case "git-clean":
      return "git clean";
    case "git-force-push":
      return "git push --force";
    case "git-branch-delete":
      return "git branch delete";
    case "privilege-escalation":
      return "privilege escalation (sudo/runas)";
    default:
      return action.op;
  }
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
