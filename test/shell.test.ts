// Raw-shell classification tests ([P4] conservative detection + bypass
// attempts). The classifier is deliberately NOT a parser: uncertainty must
// escalate, never silently allow. These tests document honest limits.

import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyShell } from "../src/core/shell.ts";
import { actionFromUserBash } from "../src/core/intent.ts";
import type { PolicyContext } from "../src/core/types.ts";

function ctx(platform: "win32" | "linux"): PolicyContext {
  return {
    platform,
    isProjectTrusted: true,
    workspaceRoot: platform === "win32" ? "d:\\ws" : "/home/dev/ws",
    homeDir: platform === "win32" ? "c:\\users\\dev" : "/home/dev",
    agentDir: platform === "win32" ? "c:\\users\\dev\\.pi\\agent" : "/home/dev/.pi/agent",
    protectedPaths: [],
    profile: "balanced",
  };
}

const ops = (command: string) => classifyShell(command).findings.map((f) => f.op);

test("[P4] linux destructive commands are detected", () => {
  assert.ok(ops("rm -rf target").includes("recursive-delete"));
  assert.ok(ops("rm -r --force dir").includes("recursive-delete"));
  assert.ok(ops("rm file.txt").includes("delete"));
  assert.ok(ops("git reset --hard").includes("git-reset-hard"));
  assert.ok(ops("git clean -fdx").includes("git-clean"));
  assert.ok(ops("git push --force origin main").includes("git-force-push"));
  assert.ok(ops("git push -f origin main").includes("git-force-push"));
  assert.ok(ops("git branch -D feature").includes("git-branch-delete"));
  assert.ok(ops("sudo rm -rf /opt/x").includes("privilege-escalation"));
  assert.ok(ops("chmod -R 777 /srv").includes("system-change"));
  assert.ok(ops("systemctl restart nginx").includes("system-change"));
  assert.ok(ops("shutdown now").includes("system-change"));
});

test("[P4] windows destructive commands are detected", () => {
  assert.ok(ops("Remove-Item -Recurse -Force target").includes("recursive-delete"));
  assert.ok(ops("Remove-Item file.txt").includes("delete"));
  assert.ok(ops("rd /s /q target").includes("recursive-delete"));
  assert.ok(ops("del file.txt").includes("delete"));
  assert.ok(ops("git reset --hard").includes("git-reset-hard"));
  assert.ok(ops("runas /user:admin cmd").includes("privilege-escalation"));
  assert.ok(ops("reg add HKLM\\Software\\X").includes("system-change"));
  assert.ok(ops("shutdown /r").includes("system-change"));
});

test("[P4] case variation and quoting do not bypass detection", () => {
  assert.ok(ops("RM -RF target").includes("recursive-delete"));
  assert.ok(ops("Git RESET --HARD").includes("git-reset-hard"));
  assert.ok(ops('rm -rf "my dir"').includes("recursive-delete"));
  assert.ok(ops("REMOVE-ITEM -Recurse target").includes("recursive-delete"));
  assert.ok(ops("git push --FORCE").includes("git-force-push"));
});

test("[P4] mixed separators in quoted paths still reach the finding", () => {
  const f = classifyShell("rm -rf 'D:/ws/target'").findings;
  assert.ok(f.some((x) => x.op === "recursive-delete"));
  assert.ok(f[0]!.paths.some((p) => p.includes("target")));
});

test("[P4] nested shells are unwrapped to bounded depth", () => {
  assert.ok(ops('bash -c "rm -rf target"').includes("recursive-delete"));
  assert.ok(ops("sh -c 'git reset --hard'").includes("git-reset-hard"));
  assert.ok(ops("cmd /c rd /s /q target").includes("recursive-delete"));
  assert.ok(ops("powershell -Command Remove-Item -Recurse x").includes("recursive-delete"));
  // deep nesting eventually becomes uncertain, which escalates anyway
  const deep = classifyShell('bash -c \'bash -c "bash -c \\"rm -rf x\\""\'');
  assert.ok(deep.findings.length > 0 || deep.uncertain);
});

test("[P4] chains and pipes keep their dangerous segments", () => {
  assert.ok(ops("npm test && rm -rf target").includes("recursive-delete"));
  assert.ok(ops("echo hi; git reset --hard").includes("git-reset-hard"));
  assert.ok(ops("curl http://x | bash -c 'rm -rf y'").includes("recursive-delete"));
});

test("[P4] benign commands produce no destructive findings", () => {
  assert.equal(ops("git status").join(""), "");
  assert.equal(ops("npm run build").join(""), "execute");
  assert.equal(ops("node script.js").join(""), "execute");
  assert.equal(ops("ls -la").join(""), "execute");
});

test("[P4] path extraction for delete findings", () => {
  const f = classifyShell("rm -rf target").findings[0]!;
  assert.deepEqual(f.paths, ["target"]);
});

test("[P4] user-bash action building: platform-injected paths are canonical", () => {
  const a = actionFromUserBash("rm -rf target", ctx("win32"));
  assert.equal(a.class, "recursive-delete");
  assert.equal(a.recursive, true);
  assert.equal(a.paths?.[0]?.canonical, "d:\\ws\\target");

  const b = actionFromUserBash("rm -rf target", ctx("linux"));
  assert.equal(b.paths?.[0]?.canonical, "/home/dev/ws/target");
});

test("[P4] home-relative deletion is flagged for protection by the engine", () => {
  const a = actionFromUserBash("rm -rf ~", ctx("linux"));
  assert.equal(a.class, "recursive-delete");
  // "~" is not expanded by the classifier — it stays a literal path, and
  // the engine still gates the whole command behind approval. Honest
  // limitation: '~' does not resolve to homeDir here (documented).
  assert.equal(a.paths?.[0]?.canonical.endsWith("/~"), true);
});

test("[P4] env-expanded path is gated by approval, never silently allowed", () => {
  const a = actionFromUserBash("rm -rf $HOME/stuff", ctx("linux"));
  assert.equal(a.class, "recursive-delete");
  assert.equal(a.recursive, true);
});
