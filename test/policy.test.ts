// Pure decision-engine tests ([P1]/[P3]/[P4] semantics + default policy).

import { test } from "node:test";
import assert from "node:assert/strict";
import { decide } from "../src/core/policy.ts";
import { intentDigest } from "../src/core/digest.ts";
import { approvalIntent } from "../src/core/intent.ts";
import type { ApprovalGrant, PolicyAction, PolicyContext } from "../src/core/types.ts";

const NOW = 1_700_000_000_000;

function ctx(partial: Partial<PolicyContext> = {}): PolicyContext {
  return {
    platform: "win32",
    isProjectTrusted: true,
    workspaceRoot: "d:\\ws",
    homeDir: "c:\\users\\dev",
    agentDir: "c:\\users\\dev\\.pi\\agent",
    protectedPaths: [],
    profile: "balanced",
    ...partial,
  };
}

function action(partial: Partial<PolicyAction>): PolicyAction {
  return { class: "read", op: "read", source: "tool", tool: "read", ...partial };
}

function run(a: PolicyAction, c: PolicyContext, grants: ApprovalGrant[] = []) {
  return decide({ action: a, digest: intentDigest(approvalIntent(a)), ctx: c, grants, now: NOW });
}

test("[P1] reads and git inspection are allowed without ceremony", () => {
  assert.equal(
    run(action({ paths: [{ input: "a.ts", canonical: "d:\\ws\\a.ts" }] }), ctx()).kind,
    "allow",
  );
  assert.equal(
    run(action({ class: "git-safe", op: "git-status", tool: "bash", command: "git status" }), ctx())
      .kind,
    "allow",
  );
});

test("[P1] trusted workspace edits are allowed; untrusted or outside are not", () => {
  const inside = action({
    class: "write",
    op: "edit",
    paths: [{ input: "a.ts", canonical: "d:\\ws\\a.ts" }],
  });
  assert.equal(run(inside, ctx()).kind, "allow");

  const untrusted = run(inside, ctx({ isProjectTrusted: false }));
  assert.equal(untrusted.kind, "require-approval");

  const outside = action({
    class: "write",
    op: "edit",
    paths: [{ input: "C:\\other\\a.ts", canonical: "c:\\other\\a.ts" }],
  });
  assert.equal(run(outside, ctx()).kind, "require-approval");
});

test("[P1] execution inside a trusted workspace is allowed; safe profile gates it", () => {
  const exec = action({ class: "execute", op: "execute", tool: "code" });
  assert.equal(run(exec, ctx()).kind, "allow");
  assert.equal(run(exec, ctx({ profile: "safe" })).kind, "require-approval");
  assert.equal(
    run(exec, ctx({ isProjectTrusted: false })).kind,
    "require-approval",
    "untrusted workspace execution requires approval",
  );
});

test("[P4] recursive delete and raw deletes require approval, never silent allow", () => {
  const rd = action({
    class: "recursive-delete",
    op: "recursive-delete",
    recursive: true,
    paths: [{ input: "target", canonical: "d:\\ws\\target" }],
  });
  assert.equal(run(rd, ctx()).kind, "require-approval");
  const del = action({
    class: "delete",
    op: "delete",
    paths: [{ input: "a.ts", canonical: "d:\\ws\\a.ts" }],
  });
  assert.equal(run(del, ctx()).kind, "require-approval");
  // project trust does NOT lift the gate
  assert.equal(run(rd, ctx({ isProjectTrusted: true })).kind, "require-approval");
});

test("[P1] protected resources are DENIED outright, even with a grant", () => {
  const delHome = action({
    class: "recursive-delete",
    op: "recursive-delete",
    recursive: true,
    paths: [{ input: "~", canonical: "c:\\users\\dev" }],
  });
  const grant: ApprovalGrant = { digest: "x", scope: "once", grantedAt: NOW };
  const d = run(delHome, ctx(), [grant]);
  assert.equal(d.kind, "deny");
  assert.equal(d.permanent, true);

  const editAgent = action({
    class: "write",
    op: "edit",
    paths: [{ input: "auth.json", canonical: "c:\\users\\dev\\.pi\\agent\\auth.json" }],
  });
  assert.equal(run(editAgent, ctx(), [grant]).kind, "deny", "agent dir is sealed");

  const declared = ctx({ protectedPaths: ["d:\\secrets"] });
  const editSecret = action({
    class: "write",
    op: "edit",
    paths: [{ input: "k.txt", canonical: "d:\\secrets\\k.txt" }],
  });
  assert.equal(run(editSecret, declared).kind, "deny", "operator-declared protected path");
});

test("[P1] workspace-root deletion is denied; subdirectory deletion is approval-gated", () => {
  const rootDel = action({
    class: "recursive-delete",
    op: "recursive-delete",
    recursive: true,
    paths: [{ input: ".", canonical: "d:\\ws" }],
  });
  assert.equal(run(rootDel, ctx()).kind, "deny");

  const subDel = action({
    class: "recursive-delete",
    op: "recursive-delete",
    recursive: true,
    paths: [{ input: "target", canonical: "d:\\ws\\target" }],
  });
  assert.equal(run(subDel, ctx()).kind, "require-approval");
});

test("[P1] writes inside home (outside sealed stores) are approval-gated, not denied", () => {
  const editHome = action({
    class: "write",
    op: "edit",
    paths: [{ input: "~/notes.txt", canonical: "c:\\users\\dev\\notes.txt" }],
  });
  const d = run(editHome, ctx());
  assert.notEqual(d.kind, "deny", "home is a boundary, not sealed");
  assert.equal(d.kind, "require-approval");
});

test("[P4] unknown actions fail toward approval", () => {
  const d = run(action({ class: "unknown", op: "unknown", tool: "mystery-tool" }), ctx());
  assert.equal(d.kind, "require-approval");
});

test("[P1] credential change is denied permanently", () => {
  const d = run(
    action({ class: "credential-change", op: "credential-write", tool: "bash" }),
    ctx(),
  );
  assert.equal(d.kind, "deny");
  assert.equal(d.permanent, true);
});

test("[P1] destructive git and remote write classes require approval", () => {
  for (const cls of [
    "git-destructive",
    "github-write",
    "github-destructive",
    "ci-control",
    "system-change",
    "network-side-effect",
  ] as const) {
    assert.equal(run(action({ class: cls, op: cls }), ctx()).kind, "require-approval", cls);
  }
});

test("[P2] an exact-action grant permits the identical action only", () => {
  const del = action({
    class: "delete",
    op: "delete",
    paths: [{ input: "a.ts", canonical: "d:\\ws\\a.ts" }],
  });
  const digest = intentDigest(approvalIntent(del));
  const other = action({
    class: "delete",
    op: "delete",
    paths: [{ input: "b.ts", canonical: "d:\\ws\\b.ts" }],
  });
  const grants: ApprovalGrant[] = [{ digest, scope: "exact-action", grantedAt: NOW }];
  assert.equal(run(del, ctx(), grants).kind, "allow");
  assert.equal(
    run(other, ctx(), grants).kind,
    "require-approval",
    "different path is a different action",
  );
});

test("[P2] path order in a multi-path action does not break grant matching", () => {
  const a = action({
    class: "delete",
    op: "delete",
    paths: [
      { input: "a", canonical: "d:\\ws\\a" },
      { input: "b", canonical: "d:\\ws\\b" },
    ],
  });
  const b = action({
    class: "delete",
    op: "delete",
    paths: [
      { input: "b", canonical: "d:\\ws\\b" },
      { input: "a", canonical: "d:\\ws\\a" },
    ],
  });
  const grants: ApprovalGrant[] = [
    { digest: intentDigest(approvalIntent(a)), scope: "once", grantedAt: NOW },
  ];
  assert.equal(run(b, ctx(), grants).kind, "allow");
});

test("[P3] an expired grant is never interpreted as allow", () => {
  const del = action({
    class: "delete",
    op: "delete",
    paths: [{ input: "a.ts", canonical: "d:\\ws\\a.ts" }],
  });
  const grants: ApprovalGrant[] = [
    {
      digest: intentDigest(approvalIntent(del)),
      scope: "exact-action",
      grantedAt: NOW - 1000,
      expiresAt: NOW - 1,
    },
  ];
  const d = run(del, ctx(), grants);
  assert.equal(d.kind, "require-approval");
});

test("[P3] a denied decision is never stored or interpreted as allow", () => {
  // the engine receives only explicit grants; a deny produces no grant and
  // a repeat of the action re-evaluates from scratch
  const delHome = action({
    class: "recursive-delete",
    op: "recursive-delete",
    recursive: true,
    paths: [{ input: "~", canonical: "c:\\users\\dev" }],
  });
  const d1 = run(delHome, ctx());
  assert.equal(d1.kind, "deny");
  // even a session-class grant for the class does NOT lift a permanent deny
  const grants: ApprovalGrant[] = [
    {
      digest: "class:recursive-delete",
      scope: "session-class",
      actionClass: "recursive-delete",
      grantedAt: NOW,
    },
  ];
  assert.equal(run(delHome, ctx(), grants).kind, "deny");
});

test("[P3] session-class grants cover only their action class (explicit grant)", () => {
  const grants: ApprovalGrant[] = [
    { digest: "class:delete", scope: "session-class", actionClass: "delete", grantedAt: NOW },
  ];
  const del = action({
    class: "delete",
    op: "delete",
    paths: [{ input: "a.ts", canonical: "d:\\ws\\a.ts" }],
  });
  assert.equal(run(del, ctx(), grants).kind, "allow");
  const rd = action({
    class: "recursive-delete",
    op: "recursive-delete",
    recursive: true,
    paths: [{ input: "t", canonical: "d:\\ws\\t" }],
  });
  assert.equal(
    run(rd, ctx(), grants).kind,
    "require-approval",
    "class grant does not leak across classes",
  );
});
