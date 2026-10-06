// pi-policy-next — deterministic authorization policy for Pi.
//
// ENFORCEMENT MODEL (P1): every model-issued tool call passes through the
// awaited `tool_call` event BEFORE execution; policy-sensitive actions
// require a valid decision (allow / grant match / human approval) or they
// are blocked with `{ block: true, reason }`. Pi itself fail-closes when a
// handler throws. Direct `!`-shell commands are gated via `user_bash` by
// full replacement. Prompt instructions are never treated as enforcement.
//
// CACHEABILITY DISCIPLINE (§14): policy state lives OUTSIDE model context.
// Decisions are emitted as pinx.policy.* EventBus events (UI/audit only).
// The model sees a policy result ONLY when a call is actually blocked —
// which is semantically necessary and arrives as a normal tool error.
// Routine ALLOWs inject nothing. No tools are registered (zero schema cost).
//
// APPROVAL UX: the structured presentation goes to the chat log via
// ui.notify (what / target / reason / trust), then a blocking select parks
// the turn while the user chooses (event-driven resume, never polling).

import { getAgentDir } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import { canonicalize, type Platform } from "./core/paths.ts";
import { intentDigest } from "./core/digest.ts";
import { actionFromToolCall, actionFromUserBash, approvalIntent } from "./core/intent.ts";
import { ApprovalLedger } from "./core/ledger.ts";
import { decide } from "./core/policy.ts";
import { buildPresentation } from "./core/presentation.ts";
import { classifyShell } from "./core/shell.ts";
import { STACK_INFO, type PolicyProfile } from "./info.ts";
import type { PolicyAction, PolicyContext, PolicyDecision } from "./core/types.ts";

const PLATFORM: Platform =
  process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux";

const DESTRUCTIVE_SHELL_OPS = new Set([
  "recursive-delete",
  "delete",
  "git-reset-hard",
  "git-clean",
  "git-force-push",
  "git-branch-delete",
  "system-change",
  "privilege-escalation",
]);

export default function piPolicyNext(pi: ExtensionAPI) {
  const disabled = process.env[STACK_INFO.env.disable] === "1";
  const ledger = new ApprovalLedger();

  const profile: PolicyProfile = ((): PolicyProfile => {
    const raw = process.env[STACK_INFO.env.profile];
    return raw === "safe" || raw === "autonomous" ? raw : "balanced";
  })();

  const extraProtected = (process.env[STACK_INFO.env.protected] ?? "")
    .split(delimiter)
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => canonicalize(p, { platform: PLATFORM }));

  /**
   * Small built-in sealed set: credential stores next to the home
   * directory. The home itself is a BOUNDARY (root deletion denied, its
   * contents are normal approval-gated work), not a sealed resource —
   * workspaces usually live under it.
   */
  const CREDENTIAL_DIRS = [".ssh", ".aws", ".gnupg"];

  function policyCtx(ctx: { isProjectTrusted(): boolean; cwd?: string }): PolicyContext {
    const home = canonicalize(homedir(), { platform: PLATFORM });
    return {
      platform: PLATFORM,
      isProjectTrusted: safeTrust(ctx),
      workspaceRoot: canonicalize(ctx.cwd ?? process.cwd(), { platform: PLATFORM }),
      homeDir: home,
      agentDir: canonicalize(getAgentDir(), { platform: PLATFORM }),
      protectedPaths: [
        ...extraProtected,
        ...CREDENTIAL_DIRS.map((dir) => canonicalize(join(home, dir), { platform: PLATFORM })),
      ],
      profile,
    };
  }

  function safeTrust(ctx: { isProjectTrusted(): boolean }): boolean {
    try {
      return ctx.isProjectTrusted() === true;
    } catch {
      return false; // unknown trust = untrusted (conservative)
    }
  }

  function emit(channel: string, payload: Record<string, unknown>): void {
    try {
      pi.events.emit(channel, payload);
    } catch {
      // observability is best-effort; enforcement must not depend on it
    }
  }

  function emitRequest(digest: string, action: PolicyAction, intentPaths: string[]): void {
    emit(STACK_INFO.events.request, {
      v: 1,
      digest,
      actionClass: action.class,
      op: action.op,
      tool: action.tool,
      source: action.source,
      paths: intentPaths,
      recursive: action.recursive === true,
    });
  }

  function emitDecision(decision: PolicyDecision, digest: string, action: PolicyAction): void {
    emit(STACK_INFO.events.decision, {
      v: 1,
      digest,
      decision: decision.kind,
      reason: decision.reason,
      actionClass: decision.actionClass,
      tool: action.tool,
    });
  }

  /** The single pre-execution gate for model-issued tool calls. */
  pi.on("tool_call", async (event, ctx) => {
    if (disabled) return undefined;
    const pctx = policyCtx(ctx);
    const action = actionFromToolCall(
      { toolName: event.toolName, input: event.input as Record<string, unknown> },
      pctx,
    );
    const intent = approvalIntent(action);
    const digest = intentDigest(intent);
    emitRequest(digest, action, intent.paths ?? []);

    const decision = decide({ action, digest, ctx: pctx, grants: ledger.list(), now: Date.now() });
    emitDecision(decision, digest, action);

    if (decision.kind === "allow") {
      ledger.consume(digest);
      return undefined; // no policy text enters the model on routine allows
    }
    if (decision.kind === "deny") {
      return { block: true, reason: `policy: ${decision.reason}` };
    }

    // require-approval: park the turn on a blocking dialog (no polling).
    if (!ctx.hasUI) {
      return {
        block: true,
        reason: `policy: ${decision.reason} (approval required but no UI is available)`,
      };
    }
    const presentation = buildPresentation(action, decision, pctx);
    // Structured detail goes to the chat log; the dialog carries the choice.
    ctx.ui.notify(presentation.lines.join("\n"), "warning");
    const options = [
      "Deny",
      "Allow once",
      "Allow this exact action (this session)",
      `Allow ALL ${action.class} actions this session`,
    ];
    const choice = await ctx.ui.select(presentation.title, options);

    if (choice === undefined) {
      emitDecision(
        { kind: "deny", reason: "approval cancelled", actionClass: action.class },
        digest,
        action,
      );
      return { block: true, reason: "policy: approval cancelled" };
    }
    if (choice === "Deny") {
      emitDecision(
        { kind: "deny", reason: "denied by user", actionClass: action.class },
        digest,
        action,
      );
      return { block: true, reason: "policy: denied by user" };
    }
    if (choice === "Allow once") {
      // `once` permits EXACTLY this execution — nothing is recorded, so the
      // next identical action needs a fresh decision (P1/P3).
      emitDecision(
        { kind: "allow", reason: "approved by user (once)", actionClass: action.class },
        digest,
        action,
      );
      return undefined;
    }
    if (choice === "Allow this exact action (this session)") {
      ledger.grant(intent, "exact-action", Date.now());
    } else {
      ledger.grant(intent, "session-class", Date.now(), { actionClass: action.class });
    }
    emitDecision(
      { kind: "allow", reason: `approved by user (${choice})`, actionClass: action.class },
      digest,
      action,
    );
    return undefined; // approved: proceed
  });

  /**
   * Direct `!`-shell gate. The human issued the command, so read/execute
   * classes pass; destructive or unclassifiable commands get a confirm
   * dialog. Blocking is by full replacement — the command never executes.
   */
  pi.on("user_bash", async (event, ctx) => {
    if (disabled) return undefined;
    const cls = classifyShell(event.command);
    const destructive = cls.uncertain || cls.findings.some((f) => DESTRUCTIVE_SHELL_OPS.has(f.op));
    if (!destructive) return undefined;

    const pctx = policyCtx(ctx);
    const action = actionFromUserBash(event.command, pctx);
    const intent = approvalIntent(action);
    const digest = intentDigest(intent);
    emitRequest(digest, action, intent.paths ?? []);

    const denial = {
      output: `blocked by pi-policy-next: ${
        cls.uncertain
          ? "unrecognized shell command requires confirmation"
          : "destructive shell command requires confirmation"
      }`,
      exitCode: 1 as number | undefined,
      cancelled: false,
      truncated: false,
    };

    if (!ctx.hasUI) {
      emitDecision(
        { kind: "deny", reason: "destructive shell command and no UI", actionClass: action.class },
        digest,
        action,
      );
      return { result: denial } as never; // BashResult shape; type not root-exported
    }
    const confirmed = await ctx.ui.confirm(
      cls.uncertain ? "Unrecognized shell command" : "Destructive shell command",
      `${event.command}\n\nRun anyway?`,
    );
    if (confirmed) {
      emitDecision(
        { kind: "allow", reason: "confirmed by user", actionClass: action.class },
        digest,
        action,
      );
      return undefined; // pass through to normal execution
    }
    emitDecision(
      { kind: "deny", reason: "denied by user", actionClass: action.class },
      digest,
      action,
    );
    return { result: denial } as never;
  });

  pi.registerCommand("policy-next", {
    description: "Show pi-policy-next status (profile, approvals, protected paths)",
    handler: async (_args, ctx) => {
      const pctx = policyCtx(ctx);
      const lines = [
        `pi-policy-next ${STACK_INFO.contractVersion} · profile ${profile}${disabled ? " · ENFORCEMENT DISABLED (no protection claimed)" : ""}`,
        `project trust: ${pctx.isProjectTrusted ? "trusted" : "untrusted"} · active grants: ${ledger.size}`,
        `sealed: agent dir, home dir${extraProtected.length > 0 ? `, +${extraProtected.length} declared` : ""} · boundary: workspace root`,
      ];
      await ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
