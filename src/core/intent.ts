// Intent normalization: turn raw interception inputs (tool_call events,
// user_bash commands) into PolicyActions and canonical ApprovalIntents.
// Deterministic; platform-injected; no Pi imports.

import { canonicalize, isRoot, sepFor, type Platform } from "./paths.ts";
import { classifyShell } from "./shell.ts";
import type { ApprovalIntent, PolicyAction, PolicyActionClass, PolicyContext } from "./types.ts";

const GIT_SAFE_SUBCOMMANDS = new Set([
  "status",
  "log",
  "diff",
  "show",
  "branch",
  "tag",
  "remote",
  "blame",
  "rev-parse",
  "ls-files",
  "config",
  "--version",
  "stash",
  "list",
]);
const GIT_MUTATING_OK = new Set([
  "add",
  "commit",
  "checkout",
  "switch",
  "restore",
  "merge",
  "rebase",
  "pull",
  "mv",
  "stash",
  "worktree",
]);
const MUTATING_FILE_TOOLS = new Set(["write", "edit", "multiedit", "notebookedit"]);
const READ_TOOLS = new Set(["read", "grep", "glob", "ls", "find", "fff", "ffgrep", "pinx_recall"]);
/** Tools of the runtime stack that execute source (deterministic mapping). */
const EXECUTE_TOOLS = new Set(["code", "node", "python", "code_buffer", "code_job"]);

export interface RawToolCall {
  toolName: string;
  input: Record<string, unknown>;
}

/** Build the normalized action for a model-issued tool call. */
export function actionFromToolCall(call: RawToolCall, ctx: PolicyContext): PolicyAction {
  const tool = call.toolName;
  const input = call.input ?? {};

  if (tool === "bash") {
    return actionFromShell(String(input.command ?? ""), "tool", "bash", ctx);
  }
  if (tool === "read" || READ_TOOLS.has(tool)) {
    const paths = pathInputs(input, ctx);
    return {
      class: "read",
      op: "read",
      paths,
      source: "tool",
      tool,
    };
  }
  if (tool === "github") {
    return actionFromGithubTool(input, ctx);
  }
  if (tool === "ci") {
    return actionFromCiTool(input, ctx);
  }
  if (EXECUTE_TOOLS.has(tool)) {
    // code_buffer/code_job may also mutate retained-source state; "execute"
    // is the correct risk class for both (their filesystem footprint is the
    // runtime's own state root, not the workspace).
    return { class: "execute", op: "execute", source: "tool", tool };
  }
  if (tool === "write") {
    // Create-vs-overwrite is not decidable without filesystem access; both
    // are content mutation and carry the same risk class here.
    return {
      class: "write",
      op: "write",
      paths: pathInputs(input, ctx),
      source: "tool",
      tool,
    };
  }
  if (tool === "edit" || tool === "multiedit" || tool === "notebookedit") {
    return {
      class: "write",
      op: "edit",
      paths: pathInputs(input, ctx),
      source: "tool",
      tool,
    };
  }
  if (MUTATING_FILE_TOOLS.has(tool)) {
    return { class: "write", op: "write", paths: pathInputs(input, ctx), source: "tool", tool };
  }
  // Unknown tools are P4 material: fail toward approval.
  return {
    class: "unknown",
    op: "unknown",
    source: "tool",
    tool,
  };
}

/** Build the normalized action for a direct `!`-shell command. */
export function actionFromUserBash(command: string, ctx: PolicyContext): PolicyAction {
  return actionFromShell(command, "user-bash", "user-bash", ctx);
}

function actionFromShell(
  command: string,
  source: PolicyAction["source"],
  tool: string,
  ctx: PolicyContext,
): PolicyAction {
  const platform: Platform = ctx.platform;
  const cls = classifyShell(command);
  // Highest-risk finding wins.
  const rank: Record<string, number> = {
    "recursive-delete": 12,
    "git-force-push": 11,
    "git-reset-hard": 10,
    "git-clean": 10,
    "system-change": 9,
    "privilege-escalation": 9,
    "git-branch-delete": 8,
    delete: 6,
    execute: 3,
    "network-fetch": 1,
  };
  const worst = cls.findings.slice().sort((a, b) => (rank[b.op] ?? 0) - (rank[a.op] ?? 0))[0];

  if (!worst) {
    return {
      class: cls.uncertain ? "unknown" : "execute",
      op: "shell",
      command,
      source,
      tool,
    };
  }

  const canonPaths = worst.paths
    .filter((p) => p.length > 0)
    .map((p) => ({
      input: p,
      canonical: canonicalize(p, { platform }, ctx.workspaceRoot),
    }));

  const opByFinding: Record<string, string> = {
    "recursive-delete": "recursive-delete",
    delete: "delete",
    "git-reset-hard": "git-reset-hard",
    "git-clean": "git-clean",
    "git-force-push": "git-force-push",
    "git-branch-delete": "git-branch-delete",
    "privilege-escalation": "privilege-escalation",
    "system-change": "system-change",
    execute: "execute",
    "network-fetch": "network-fetch",
  };

  const actionClass: PolicyActionClass = (() => {
    switch (worst.op) {
      case "recursive-delete":
        return "recursive-delete";
      case "delete":
        return "delete";
      case "git-reset-hard":
      case "git-clean":
      case "git-force-push":
      case "git-branch-delete":
        return "git-destructive";
      case "privilege-escalation":
      case "system-change":
        return "system-change";
      case "execute":
        return "execute";
      case "network-fetch":
        return cls.uncertain ? "unknown" : "execute";
      default:
        return "unknown";
    }
  })();

  // Escalate to unknown when the classifier was uncertain AND the worst
  // finding is plausibly destructive (P4: never silently allow).
  const escalated: PolicyActionClass =
    cls.uncertain && (rank[worst.op] ?? 0) >= 6 ? "unknown" : actionClass;

  return {
    class: escalated,
    op: opByFinding[worst.op] ?? worst.op,
    paths: canonPaths.length > 0 ? canonPaths : undefined,
    recursive: worst.op === "recursive-delete",
    command,
    source,
    tool,
  };
}

/** Extract + canonicalize path-ish inputs from a tool input object. */
function pathInputs(input: Record<string, unknown>, ctx: PolicyContext) {
  const candidates: string[] = [];
  for (const key of ["path", "file_path", "file", "target", "notebook_path", "dir"]) {
    const value = input[key];
    if (typeof value === "string" && value.length > 0) candidates.push(value);
  }
  const platform = ctx.platform;
  return candidates.map((p) => ({
    input: p,
    canonical: canonicalize(p, { platform }, ctx.workspaceRoot),
  }));
}

const GITHUB_READ_ACTIONS = new Set(["summary", "detail", "list", "pr_file_patch", "status"]);
const GITHUB_DESTRUCTIVE_OPERATIONS = new Set(["merge_pr"]);
const GITHUB_WRITE_OPERATIONS = new Set([
  "create_issue",
  "comment",
  "update_issue",
  "create_pr",
  "add_labels",
]);

/**
 * Map pi-github-next's `github` tool calls to normalized policy actions.
 * Material identity: repository, resource number, expected head SHA, and
 * merge method — exactly the fields an approval binds to (P2 for GitHub).
 */
function actionFromGithubTool(input: Record<string, unknown>, ctx: PolicyContext): PolicyAction {
  const action = typeof input.action === "string" ? input.action : "";
  const operation = typeof input.operation === "string" ? input.operation : "";
  const repository = typeof input.repository === "string" ? input.repository : undefined;
  const number = typeof input.number === "number" ? input.number : undefined;
  const headSha = typeof input.head_sha === "string" ? input.head_sha : undefined;
  const method = typeof input.method === "string" ? input.method : undefined;

  if (action === "mutate" || action === "promote_issue_candidate") {
    const actionClass: PolicyActionClass = GITHUB_DESTRUCTIVE_OPERATIONS.has(operation)
      ? "github-destructive"
      : GITHUB_WRITE_OPERATIONS.has(operation)
        ? "github-write"
        : "github-write";
    return {
      class: actionClass,
      op: operation || action,
      ref: {
        kind: "github",
        repo: repository,
        id: number !== undefined ? String(number) : undefined,
        head: headSha,
        method,
      },
      source: "tool",
      tool: "github",
    };
  }
  if (GITHUB_READ_ACTIONS.has(action) || action === "") {
    void ctx;
    return {
      class: "github-read",
      op: action || "github-read",
      ref: repository ? { kind: "github", repo: repository } : undefined,
      source: "tool",
      tool: "github",
    };
  }
  return {
    class: "unknown",
    op: "unknown",
    source: "tool",
    tool: "github",
  };
}

const CI_READ_ACTIONS = new Set([
  "resolve",
  "status",
  "wait",
  "wait_all",
  "failure_digest",
  "logs",
  "artifacts",
]);
const CI_MUTATIONS = new Set(["rerun_failed", "cancel", "dispatch"]);

/**
 * Map pi-ci-next `ci` tool calls to policy actions. Reads auto-allow;
 * CI control mutations classify ci-control (approval per policy profile)
 * with repo+run identity in the material ref.
 */
function actionFromCiTool(input: Record<string, unknown>, ctx: PolicyContext): PolicyAction {
  void ctx;
  const action = typeof input.action === "string" ? input.action : "";
  const repository = typeof input.repository === "string" ? input.repository : undefined;
  const runId = typeof input.run_id === "number" ? String(input.run_id) : undefined;
  if (CI_MUTATIONS.has(action)) {
    return {
      class: "ci-control",
      op: action,
      ref: { kind: "ci", repo: repository, id: runId },
      source: "tool",
      tool: "ci",
    };
  }
  if (CI_READ_ACTIONS.has(action)) {
    return {
      class: "ci-read",
      op: action,
      ref: repository ? { kind: "ci", repo: repository } : undefined,
      source: "tool",
      tool: "ci",
    };
  }
  return { class: "unknown", op: "unknown", source: "tool", tool: "ci" };
}

/**
 * Canonical ApprovalIntent for an action — the identity that approvals bind
 * to. Material fields only; presentation fields (tool, source) excluded.
 */
export function approvalIntent(action: PolicyAction): ApprovalIntent {
  return {
    v: 1,
    actionClass: action.class,
    op: action.op,
    paths: action.paths?.map((p) => p.canonical).sort(),
    recursive: action.recursive,
    ref: action.ref,
    command: action.command,
    impactBytes: action.impactBytes,
  };
}

/**
 * Guard used by the policy engine: never treat filesystem-root or the
 * workspace/home root itself as an ordinary delete target.
 */
export function isProtectedRootDeletion(action: PolicyAction, ctx: PolicyContext): boolean {
  if (action.class !== "recursive-delete" && action.class !== "delete") return false;
  const platform = ctx.platform;
  for (const p of action.paths ?? []) {
    if (isRoot(p.canonical, platform)) return true;
    if (ctx.homeDir && p.canonical === canonicalize(ctx.homeDir, { platform })) return true;
    if (ctx.workspaceRoot && p.canonical === canonicalize(ctx.workspaceRoot, { platform })) {
      return true;
    }
  }
  // deleting a whole drive-letter prefix like "D:" without trailing sep
  for (const p of action.paths ?? []) {
    if (platform === "win32" && /^[A-Za-z]:$/.test(p.canonical)) return true;
    if (p.canonical === sepFor(platform)) return true;
  }
  return false;
}

/** True when a git command string is inspection-only. */
export function isGitSafeCommand(command: string): boolean {
  const tokens = command.trim().split(/\s+/);
  if (tokens[0]?.toLowerCase() !== "git") return false;
  const sub = tokens[1]?.toLowerCase() ?? "";
  if (GIT_MUTATING_OK.has(sub)) return false;
  return GIT_SAFE_SUBCOMMANDS.has(sub);
}
