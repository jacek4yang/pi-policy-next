// Pi integration gate tests ([P1] enforcement before side effect, [P3]
// stale/denied approval, §28 zero tool-schema cost). Drives the REAL
// extension wiring through a mock registration adapter — no private APIs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { default as piPolicyNext } from "../src/index.ts";

type Handler = (event: unknown, ctx: unknown) => Promise<unknown> | unknown;

interface UiStub {
  notify: (message: string, type?: string) => void;
  select: (title: string, options: string[]) => Promise<string | undefined>;
  confirm: (title: string, message: string) => Promise<boolean>;
}

function harness(
  opts: { ui?: UiStub; hasUI?: boolean; trusted?: boolean; env?: Record<string, string> } = {},
) {
  const handlers = new Map<string, Handler[]>();
  const bus: Array<{ channel: string; payload: unknown }> = [];
  const commands: string[] = [];
  const tools: Array<{ name?: string }> = [];
  const notifications: string[] = [];

  const ui: UiStub =
    opts.ui ??
    ({
      notify: (message: string) => notifications.push(message),
      select: async () => undefined,
      confirm: async () => false,
    } as UiStub);

  const pi = {
    on: (event: string, handler: Handler) => {
      const list = handlers.get(event) ?? [];
      list.push(handler);
      handlers.set(event, list);
      return () => {};
    },
    registerTool: (tool: { name?: string }) => {
      tools.push(tool);
    },
    registerCommand: (name: string) => {
      commands.push(name);
    },
    events: {
      emit: (channel: string, payload: unknown) => {
        bus.push({ channel, payload });
      },
    },
  };

  // Disposable homes: agent dir and workspace are DISTINCT directories so
  // delete targets in the workspace never hit the sealed agent dir.
  const agentHome = mkdtempSync(join(tmpdir(), "pinx-policy-agent-"));
  const workspace = mkdtempSync(join(tmpdir(), "pinx-policy-ws-"));
  process.env.PI_CODING_AGENT_DIR = agentHome;
  for (const [k, v] of Object.entries(opts.env ?? {})) process.env[k] = v;

  piPolicyNext(pi as never);

  const ctx = {
    isProjectTrusted: () => opts.trusted ?? true,
    cwd: workspace,
    hasUI: opts.hasUI ?? true,
    ui,
  };

  const toolCall = async (toolName: string, input: Record<string, unknown>) => {
    const results: unknown[] = [];
    for (const h of handlers.get("tool_call") ?? []) {
      results.push(await h({ type: "tool_call", toolCallId: "tc1", toolName, input }, ctx));
    }
    return results[0];
  };

  const userBash = async (command: string) => {
    const results: unknown[] = [];
    for (const h of handlers.get("user_bash") ?? []) {
      results.push(
        await h({ type: "user_bash", command, excludeFromContext: false, cwd: tmpdir() }, ctx),
      );
    }
    return results[0];
  };

  const cleanup = () => {
    delete process.env.PI_CODING_AGENT_DIR;
    for (const k of Object.keys(opts.env ?? {})) delete process.env[k];
    rmSync(agentHome, { recursive: true, force: true });
    rmSync(workspace, { recursive: true, force: true });
  };

  return { toolCall, userBash, bus, tools, commands, notifications, cleanup };
}

test("[P1] safe reads are allowed with no model-visible policy text", async () => {
  const h = harness();
  const result = await h.toolCall("read", { path: join(tmpdir(), "a.ts") });
  assert.equal(result, undefined, "allow returns undefined — tool proceeds");
  const decisions = h.bus.filter((e) => e.channel === "pinx.policy.decision");
  assert.equal(decisions.length, 1, "decision emitted on the bus (UI/audit only)");
  assert.equal((decisions[0]!.payload as { decision: string }).decision, "allow");
  h.cleanup();
});

test("[P1] sensitive operation is blocked BEFORE execution with no UI", async () => {
  const h = harness({ hasUI: false });
  const result = (await h.toolCall("bash", { command: "rm -rf target" })) as {
    block?: boolean;
    reason?: string;
  };
  assert.equal(result?.block, true, "blocked before execution");
  assert.match(result?.reason ?? "", /recursive|approval/i);
  h.cleanup();
});

test("[P1] unknown tool fails toward approval (never silent allow)", async () => {
  const h = harness({ hasUI: false });
  const result = (await h.toolCall("mystery_tool", {})) as { block?: boolean };
  assert.equal(result?.block, true);
  h.cleanup();
});

test("[P1] approval dialog parks the turn; Allow once proceeds exactly once", async () => {
  let asked = 0;
  const h = harness({
    ui: {
      notify: () => {},
      select: async (_title: string, options: string[]) => {
        asked++;
        assert.ok(options.includes("Allow once"));
        return "Allow once";
      },
      confirm: async () => false,
    },
  });
  const first = await h.toolCall("bash", { command: "rm -rf target" });
  assert.equal(first, undefined, "approved call proceeds");
  assert.equal(asked, 1);
  // `once` does not persist: the next identical action needs a new decision
  await h.toolCall("bash", { command: "rm -rf target" });
  assert.equal(asked, 2, "second identical action asks again");
  h.cleanup();
});

test("[P1] Deny blocks the operation", async () => {
  const h = harness({
    ui: {
      notify: () => {},
      select: async () => "Deny",
      confirm: async () => false,
    },
  });
  const result = (await h.toolCall("bash", { command: "rm -rf target" })) as { block?: boolean };
  assert.equal(result?.block, true);
  const decisions = h.bus.filter((e) => e.channel === "pinx.policy.decision");
  assert.equal((decisions.at(-1)!.payload as { decision: string }).decision, "deny");
  h.cleanup();
});

test("[P3] cancelling the approval dialog blocks (no silent fallback)", async () => {
  const h = harness(); // select returns undefined (Esc)
  const result = (await h.toolCall("bash", { command: "rm -rf target" })) as {
    block?: boolean;
    reason?: string;
  };
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /cancelled/i);
  h.cleanup();
});

test("[P3] exact-action grant permits identical action, refuses changed action", async () => {
  let calls = 0;
  const h = harness({
    ui: {
      notify: () => {},
      select: async (_t: string, options: string[]) => {
        calls++;
        return options.find((o) => o.startsWith("Allow this exact action")) ?? "Deny";
      },
      confirm: async () => false,
    },
  });
  await h.toolCall("bash", { command: "rm -rf target" });
  const second = await h.toolCall("bash", { command: "rm -rf target" });
  assert.equal(second, undefined, "identical material action authorized by session grant");
  assert.equal(calls, 1, "no second dialog for identical action");

  const changed = (await h.toolCall("bash", { command: "rm -rf other" })) as { block?: boolean };
  assert.equal(changed?.block ?? false, false, "different path still needs a decision");
  assert.equal(calls, 2, "material change triggers a fresh decision (P2)");
  h.cleanup();
});

test("[P5] approval state and events never carry protected-resource contents", async () => {
  const h = harness();
  await h.toolCall("read", { path: join(tmpdir(), "a.ts") });
  for (const e of h.bus) {
    const payload = JSON.stringify(e.payload);
    assert.ok(!payload.includes("auth.json"), "no credential file names in events");
    assert.ok(!payload.includes("api_key"), "no secrets in events");
  }
  h.cleanup();
});

test("[P1] user_bash destructive command is replaced by a denial result", async () => {
  const h = harness({
    ui: {
      notify: () => {},
      select: async () => undefined,
      confirm: async () => false,
    },
  });
  const result = (await h.userBash("rm -rf target")) as { result?: { output: string } };
  assert.ok(result?.result?.output.includes("blocked by pi-policy-next"), "command never executes");
  // benign command passes through untouched
  const pass = await h.userBash("git status");
  assert.equal(pass, undefined);
  h.cleanup();
});

test("[P1] user_bash confirmed destructive command passes through", async () => {
  const h = harness({
    ui: {
      notify: () => {},
      select: async () => undefined,
      confirm: async () => true,
    },
  });
  const result = await h.userBash("rm -rf target");
  assert.equal(result, undefined, "confirmed command proceeds to normal execution");
  h.cleanup();
});

test("[P1] PINX_POLICY_DISABLE=1 disables enforcement (no protection claimed)", async () => {
  const h = harness({ hasUI: false, env: { PINX_POLICY_DISABLE: "1" } });
  const result = await h.toolCall("bash", { command: "rm -rf target" });
  assert.equal(result, undefined, "disabled policy does not intercept");
  assert.equal(h.bus.filter((e) => e.channel === "pinx.policy.request").length, 0);
  h.cleanup();
});

test("[P28] policy registers zero model-visible tools", async () => {
  const h = harness();
  assert.equal(h.tools.length, 0, "no tool schema cost");
  assert.ok(h.commands.includes("policy-next"), "status command registered (UI-only)");
  h.cleanup();
});

test("[P5] no-UI approvals fail closed with an explicit reason", async () => {
  const h = harness({ hasUI: false });
  const result = (await h.toolCall("bash", { command: "git reset --hard" })) as {
    block?: boolean;
    reason?: string;
  };
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /no UI is available/);
  h.cleanup();
});
