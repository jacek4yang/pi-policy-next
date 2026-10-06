// Material-action identity tests ([P2] digest semantics).

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, intentDigest, sameMaterialAction } from "../src/core/digest.ts";
import type { ApprovalIntent } from "../src/core/types.ts";

function intent(partial: Partial<ApprovalIntent>): ApprovalIntent {
  return { v: 1, actionClass: "recursive-delete", op: "recursive-delete", ...partial };
}

test("[P2] identical material actions share one digest", () => {
  const a = intent({ paths: ["d:\\ws\\target"], recursive: true });
  const b = intent({ paths: ["d:\\ws\\target"], recursive: true });
  assert.equal(intentDigest(a), intentDigest(b));
  assert.ok(sameMaterialAction(a, b));
});

test("[P2] path set ordering does not change the digest", () => {
  const a = intent({ paths: ["d:\\ws\\a", "d:\\ws\\b"] });
  const b = intent({ paths: ["d:\\ws\\b", "d:\\ws\\a"] });
  assert.equal(intentDigest(a), intentDigest(b));
});

test("[P2] approved path A does not authorize path B", () => {
  const a = intent({ paths: ["d:\\ws\\a"] });
  const b = intent({ paths: ["d:\\ws\\b"] });
  assert.notEqual(intentDigest(a), intentDigest(b));
});

test("[P2] recursive=false does not authorize recursive=true", () => {
  const a = intent({ paths: ["d:\\ws\\t"], recursive: false });
  const b = intent({ paths: ["d:\\ws\\t"], recursive: true });
  assert.notEqual(intentDigest(a), intentDigest(b));
});

test("[P2] PR head change invalidates the approval identity", () => {
  const a = intent({
    actionClass: "github-destructive",
    op: "merge-pr",
    ref: { kind: "github", repo: "o/r", id: "42", head: "aaaa", method: "squash" },
  });
  const b = intent({
    actionClass: "github-destructive",
    op: "merge-pr",
    ref: { kind: "github", repo: "o/r", id: "42", head: "bbbb", method: "squash" },
  });
  assert.notEqual(intentDigest(a), intentDigest(b));
});

test("[P2] merge method change invalidates the approval identity", () => {
  const a = intent({
    actionClass: "github-destructive",
    op: "merge-pr",
    ref: { kind: "github", repo: "o/r", id: "42", head: "aaaa", method: "squash" },
  });
  const b = intent({
    actionClass: "github-destructive",
    op: "merge-pr",
    ref: { kind: "github", repo: "o/r", id: "42", head: "aaaa", method: "rebase" },
  });
  assert.notEqual(intentDigest(a), intentDigest(b));
});

test("[P2] different repository is a different material action", () => {
  const a = intent({
    actionClass: "github-write",
    op: "comment",
    ref: { kind: "github", repo: "o/r", id: "42" },
  });
  const b = intent({
    actionClass: "github-write",
    op: "comment",
    ref: { kind: "github", repo: "o/other", id: "42" },
  });
  assert.notEqual(intentDigest(a), intentDigest(b));
});

test("[P2] volatile presentation fields do not change the digest", () => {
  const a = intent({ command: "npm test" });
  const b = intent({ command: "npm test" });
  // tool/source are NOT part of ApprovalIntent at all — asserting the
  // digest of the same material action is stable regardless of carrier
  assert.equal(intentDigest(a), intentDigest(b));
});

test("[P2] command identity is exact", () => {
  const a = intent({ command: "npm test" });
  const b = intent({ command: "npm test --watch" });
  assert.notEqual(intentDigest(a), intentDigest(b));
});

test("[P2] canonical JSON is key-order independent and drops undefined", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), canonicalJson({ a: 2, b: 1 }));
  assert.equal(canonicalJson({ a: 1, c: undefined }), canonicalJson({ a: 1 }));
  assert.equal(canonicalJson({ z: { y: 1, x: 2 } }), canonicalJson({ z: { x: 2, y: 1 } }));
});
