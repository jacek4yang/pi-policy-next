// Real-Pi load smoke: load this package's extension through the actual Pi SDK
// with a disposable agent home, assert clean load, zero registered tools
// (policy must add no model-visible schema) and the /policy-next command.
// No model calls.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const tempAgentDir = mkdtempSync(join(tmpdir(), "pi-policy-smoke-"));
process.env.PI_CODING_AGENT_DIR = tempAgentDir;

const { createAgentSession, DefaultResourceLoader, SessionManager } =
  await import("@earendil-works/pi-coding-agent");

const probe = { commands: null, tools: null, policyRequests: 0 };
const loader = new DefaultResourceLoader({
  cwd: repoRoot,
  agentDir: tempAgentDir,
  additionalExtensionPaths: [join(repoRoot, "src", "index.ts")],
  extensionFactories: [
    (pi) => {
      pi.on("session_start", () => {
        probe.commands = pi.getCommands().map((c) => c.name);
        probe.tools = pi.getAllTools().map((t) => t.name);
      });
      pi.on("tool_call", () => {
        probe.policyRequests++;
        return undefined; // a second opinion that never blocks
      });
    },
  ],
});
await loader.reload();
const { errors, warnings } = loader.extensionsResult;
assert.deepEqual(errors, [], `extension load errors: ${JSON.stringify(errors)}`);
console.log(`pi-load-smoke: extensions loaded (${warnings?.length ?? 0} warnings)`);

const { session } = await createAgentSession({
  resourceLoader: loader,
  sessionManager: SessionManager.inMemory(),
});
try {
  await session.bindExtensions({ mode: "json" });
  await new Promise((r) => setImmediate(r));
  assert.ok(Array.isArray(probe.commands), "session_start probe never ran");
  assert.ok(
    probe.commands?.includes("policy-next"),
    `policy-next command registered (commands: ${probe.commands?.join(", ")})`,
  );
  const policyTools = probe.tools?.filter((t) => t.startsWith("pinx_policy")) ?? [];
  assert.equal(policyTools.length, 0, "policy registers no model-visible tools");
  console.log(
    `pi-load-smoke OK: /policy-next present, tools=${probe.tools?.length ?? 0} (policy adds none)`,
  );
} finally {
  session.dispose();
  rmSync(tempAgentDir, { recursive: true, force: true });
}
