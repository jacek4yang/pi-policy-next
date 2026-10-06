// Approval ledger tests ([P3] scope + expiry + bounded state).

import { test } from "node:test";
import assert from "node:assert/strict";
import { ApprovalLedger } from "../src/core/ledger.ts";
import { intentDigest } from "../src/core/digest.ts";
import type { ApprovalIntent } from "../src/core/types.ts";

const intent: ApprovalIntent = {
  v: 1,
  actionClass: "delete",
  op: "delete",
  paths: ["d:\\ws\\a.ts"],
};
const digest = intentDigest(intent);
const NOW = 1_700_000_000_000;

test("[P3] exact-action grants persist and are class-exact", () => {
  const ledger = new ApprovalLedger();
  ledger.grant(intent, "exact-action", NOW);
  const grants = ledger.list();
  assert.equal(grants.length, 1);
  assert.equal(grants[0]!.digest, digest);
  assert.equal(grants[0]!.scope, "exact-action");
});

test("[P3] expiry timestamps are enforced by the engine, not the ledger", () => {
  const ledger = new ApprovalLedger();
  const g = ledger.grant(intent, "exact-action", NOW - 1000, { ttlMs: 500 });
  assert.ok(g.expiresAt! < NOW);
  // ledger stores it; decide() refuses it (covered in policy.test.ts P3)
  assert.equal(ledger.size, 1);
});

test("[P3] once grants are removed on consume", () => {
  const ledger = new ApprovalLedger();
  ledger.grant(intent, "once", NOW);
  assert.equal(ledger.size, 1);
  ledger.consume(digest);
  assert.equal(ledger.size, 0, "once grant consumed");
  // exact-action grants survive consume
  ledger.grant(intent, "exact-action", NOW);
  ledger.consume(digest);
  assert.equal(ledger.size, 1);
});

test("[P3] session-class grants are keyed by class, not digest", () => {
  const ledger = new ApprovalLedger();
  ledger.grant(intent, "session-class", NOW, { actionClass: "delete" });
  const grants = ledger.list();
  assert.equal(grants[0]!.scope, "session-class");
  assert.equal(grants[0]!.actionClass, "delete");
  assert.equal(grants[0]!.digest, "class:delete");
});

test("[P3] state is bounded (oldest evicted at capacity)", () => {
  const ledger = new ApprovalLedger();
  for (let i = 0; i < 200; i++) {
    ledger.grant({ ...intent, paths: [`d:\\ws\\f${i}.ts`] }, "exact-action", NOW + i);
  }
  assert.ok(ledger.size <= 128, `ledger size ${ledger.size} exceeds bound`);
});

test("[P3] clear wipes state", () => {
  const ledger = new ApprovalLedger();
  ledger.grant(intent, "exact-action", NOW);
  ledger.clear();
  assert.equal(ledger.size, 0);
});
