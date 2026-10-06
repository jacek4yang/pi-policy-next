// Path normalization tests — Windows and Linux are BOTH tested on every
// platform via injected platform semantics ([P-PATH] gates).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalize,
  isAbsoluteFor,
  isInside,
  isRoot,
  lexicalNormalize,
  normalizeSeparators,
  unquote,
} from "../src/core/paths.ts";

const WIN = { platform: "win32" } as const;
const LINUX = { platform: "linux" } as const;

test("[P-PATH] win32: drive-letter absolute paths canonicalize case-folded", () => {
  const c = canonicalize(String.raw`D:\Workspace\Project`, WIN);
  assert.equal(c, "d:\\workspace\\project");
});

test("[P-PATH] win32: forward slashes normalize to backslashes", () => {
  assert.equal(
    canonicalize("D:/Workspace/Project/file.ts", WIN),
    "d:\\workspace\\project\\file.ts",
  );
});

test("[P-PATH] win32: relative input resolves against injected cwd", () => {
  assert.equal(canonicalize("src\\a.ts", WIN, String.raw`D:\ws`), "d:\\ws\\src\\a.ts");
  assert.equal(canonicalize("src/a.ts", WIN, String.raw`D:\ws`), "d:\\ws\\src\\a.ts");
});

test("[P-PATH] traversal cannot fake workspace containment", () => {
  const esc = canonicalize(String.raw`D:\ws\..\outside`, WIN);
  assert.equal(esc, "d:\\outside");
  assert.equal(isInside(esc, String.raw`D:\ws`, true), false);
  // interior .. that stays inside is fine but the check must not be fooled
  // by raw string prefixes either way
  assert.equal(isInside(String.raw`D:\ws\sub\..\sub2\x`, String.raw`D:\ws`, true), true);
  assert.equal(isInside(String.raw`D:\ws\..\escape`, String.raw`D:\ws`, true), false);
});

test("[P-PATH] lexicalNormalize resolves .. and . segments", () => {
  assert.equal(lexicalNormalize(String.raw`D:\a\b\..\..\c`, "win32"), "D:\\c");
  assert.equal(lexicalNormalize("D:\\a\\.\\b\\", "win32"), "D:\\a\\b");
  assert.equal(lexicalNormalize("/a/b/../../c", "linux"), "/c");
  assert.equal(lexicalNormalize("/../..", "linux"), "/");
});

test("[P-PATH] linux: case-sensitive identity", () => {
  const a = canonicalize("/tmp/Work", LINUX);
  const b = canonicalize("/tmp/work", LINUX);
  assert.notEqual(a, b);
  assert.equal(canonicalize("/tmp/x/../y", LINUX), "/tmp/y");
});

test("[P-PATH] nonexistents resolve lexically through nearest existing ancestor", () => {
  // linux real fs: /tmp exists
  const c = canonicalize("/tmp/policy-next-test-does-not-exist/child", LINUX);
  assert.ok(c.startsWith("/tmp/"));
  assert.ok(c.endsWith("policy-next-test-does-not-exist/child"));
});

test("[P-PATH] root detection on both platforms", () => {
  assert.equal(isRoot("C:\\", "win32"), true);
  assert.equal(isRoot("C:", "win32"), true);
  assert.equal(isRoot("\\\\server\\share", "win32"), true);
  assert.equal(isRoot("/", "linux"), true);
  assert.equal(isRoot("/tmp", "linux"), false);
  assert.equal(isRoot(String.raw`D:\ws`, "win32"), false);
});

test("[P-PATH] containment is separator-boundary aware", () => {
  assert.equal(isInside(String.raw`D:\ws\file`, String.raw`D:\ws`, true), true);
  assert.equal(isInside(String.raw`D:\wsx\file`, String.raw`D:\ws`, true), false);
  assert.equal(isInside(String.raw`D:\ws`, String.raw`D:\ws`, true), true);
  assert.equal(isInside("/ws/file", "/ws"), true);
  assert.equal(isInside("/wsx/file", "/ws"), false);
});

test("[P-PATH] absolute detection per platform", () => {
  assert.equal(isAbsoluteFor(String.raw`D:\x`, "win32"), true);
  assert.equal(isAbsoluteFor("D:/x", "win32"), true);
  assert.equal(isAbsoluteFor("\\\\srv\\share", "win32"), true);
  assert.equal(isAbsoluteFor("relative\\x", "win32"), false);
  assert.equal(isAbsoluteFor("/x", "linux"), true);
  assert.equal(isAbsoluteFor("x/y", "linux"), false);
});

test("[P-PATH] CJK and spaces survive normalization", () => {
  assert.equal(canonicalize(String.raw`D:\项目 目录\文件.ts`, WIN), "d:\\项目 目录\\文件.ts");
  assert.equal(canonicalize("/tmp/项目 目录/文件", LINUX), "/tmp/项目 目录/文件");
});

test("[P-PATH] unquote strips matched quotes only", () => {
  assert.equal(unquote('"a b"'), "a b");
  assert.equal(unquote("'a b'"), "a b");
  assert.equal(unquote("ab"), "ab");
  assert.equal(unquote('"unterminated'), '"unterminated');
});

test("[P-PATH] normalizeSeparators is idempotent", () => {
  const once = normalizeSeparators("D:/a//b\\c", "win32");
  assert.equal(normalizeSeparators(once, "win32"), once);
});
