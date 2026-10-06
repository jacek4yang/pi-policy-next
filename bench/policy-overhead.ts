// Policy latency overhead bench (§26): the normal path must be cheap and
// NEVER invoke a model. Classification/digest/decision are measured over
// deterministic inputs; numbers are wall-clock microseconds for scale
// orientation, not nano-optimization targets.

import { actionFromToolCall, actionFromUserBash, approvalIntent } from "../src/core/intent.ts";
import { intentDigest } from "../src/core/digest.ts";
import { decide } from "../src/core/policy.ts";
import type { PolicyContext } from "../src/core/types.ts";

const ctx: PolicyContext = {
  platform: process.platform === "win32" ? "win32" : "linux",
  isProjectTrusted: true,
  workspaceRoot: process.platform === "win32" ? "d:\\ws" : "/home/dev/ws",
  homeDir: process.platform === "win32" ? "c:\\users\\dev" : "/home/dev",
  agentDir: process.platform === "win32" ? "c:\\users\\dev\\.pi\\agent" : "/home/dev/.pi/agent",
  protectedPaths: [],
  profile: "balanced",
};

function bench(fn: () => void, iterations = 20_000): number {
  // warmup
  for (let i = 0; i < 1000; i++) fn();
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
  const perCallUs = (elapsedMs * 1000) / iterations;
  return perCallUs;
}

const readAction = actionFromToolCall({ toolName: "read", input: { path: "src/module.ts" } }, ctx);
const readDigest = intentDigest(approvalIntent(readAction));

const editAction = actionFromToolCall(
  { toolName: "edit", input: { file_path: "src/module.ts" } },
  ctx,
);
const editDigest = intentDigest(approvalIntent(editAction));

const classifyBench = () => actionFromUserBash("git status", ctx);
const digestBench = () => intentDigest(approvalIntent(editAction));
const decideAllowBench = () =>
  decide({ action: readAction, digest: readDigest, ctx, grants: [], now: 0 });

const results = {
  bench: "pi-policy-next steady-state overhead",
  note: "no LLM anywhere on this path — deterministic classification only",
  safeReadAllowLatencyUs: bench(decideAllowBench),
  workspaceEditClassifyAndDecideUs: bench(() => {
    const a = actionFromToolCall({ toolName: "edit", input: { file_path: "src/m.ts" } }, ctx);
    decide({ action: a, digest: intentDigest(approvalIntent(a)), ctx, grants: [], now: 0 });
  }),
  approvalClassificationUs: bench(classifyBench),
  intentDigestUs: bench(digestBench),
  editDigestPrecomputed: editDigest.slice(0, 8),
};

process.stdout.write(JSON.stringify(results, null, 2) + "\n");
