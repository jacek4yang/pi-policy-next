// Portable path normalization (P-invariant groundwork). Windows and Linux
// are first-class: the platform is INJECTED, not read from process, so
// Windows semantics are testable on Linux CI and vice versa.
//
// Semantics (documented contract):
// - canonical form: absolute, realpath-resolved for the nearest existing
//   ancestor (symlinks/junctions resolved where the filesystem allows),
//   separators normalized to the injected platform, case-folded on win32;
// - a nonexistent target is canonicalized through its nearest existing
//   ancestor plus the remaining lexical tail — no lexical-only escapes;
// - workspace/protected containment is computed on canonical paths with an
//   explicit separator-boundary check (never naive prefix strings).

import { existsSync, realpathSync } from "node:fs";

export type Platform = "win32" | "linux" | "darwin";

export interface PathOps {
  platform: Platform;
}

export const sepFor = (platform: Platform): string => (platform === "win32" ? "\\" : "/");

function joinFor(platform: Platform, base: string, tail: string): string {
  return normalizeSeparators(base, platform) + sepFor(platform) + tail;
}

/**
 * Best-effort canonicalization, fully platform-INJECTED. When the injected
 * platform differs from the host, resolution is purely lexical — the real
 * filesystem must never resolve a foreign-platform path (a host may treat
 * `/tmp` as one of its own directories). When the platform matches the
 * host, symlinks are resolved through the real filesystem for the nearest
 * existing ancestor; nonexistent targets resolve through that ancestor
 * plus the lexical remainder (create-target safe). Case-folded on win32.
 */
export function canonicalize(
  input: string,
  ops: PathOps,
  cwd?: string,
  exists: (p: string) => boolean = existsSync,
  realpath: (p: string) => string = realpathSync,
): string {
  const base = isAbsoluteFor(input, ops.platform)
    ? lexicalNormalize(normalizeSeparators(input, ops.platform), ops.platform)
    : lexicalNormalize(
        joinFor(ops.platform, cwd ?? process.cwd(), normalizeSeparators(input, ops.platform)),
        ops.platform,
      );
  const hostPlatform: Platform =
    process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux";
  if (ops.platform !== hostPlatform) {
    return normalizeCase(base, ops.platform);
  }
  let current = base;
  const tail: string[] = [];
  for (let i = 0; i < 64; i++) {
    if (exists(current)) {
      try {
        const real = realpath(current);
        // drive roots realpath to "D:\" — strip trailing separators so the
        // lexical tail joins with exactly one separator
        const trimmed = real.replace(/[\\/]+$/, "");
        // fold case on the WHOLE result (resolved ancestor + lexical tail)
        return normalizeCase(
          normalizeSeparators(trimmed, ops.platform) +
            tail.map((t) => sepFor(ops.platform) + t).join(""),
          ops.platform,
        );
      } catch {
        break; // unreadable ancestor — fall through to lexical form
      }
    }
    const parent = dirnameOf(current, ops.platform);
    if (parent === current) break; // reached root
    tail.unshift(basenameOf(current, ops.platform));
    current = parent;
  }
  return normalizeCase(base, ops.platform);
}

export function normalizeSeparators(p: string, platform: Platform): string {
  const wanted = sepFor(platform);
  const other = platform === "win32" ? "/" : "\\";
  return p.split(other).join(wanted);
}

/**
 * Resolve ".", ".." and duplicate/interior separator segments lexically.
 * Prevents the canonical-form bypass where `ws\..\outside` would still
 * string-prefix-match `ws\` (separator-boundary checks alone are NOT
 * enough when ".." survives). Drive letters and UNC/posix roots survive.
 */
export function lexicalNormalize(p: string, platform: Platform): string {
  const sep = sepFor(platform);
  const isUnc = platform === "win32" && p.startsWith("\\\\");
  const driveMatch = platform === "win32" ? /^[A-Za-z]:/.exec(p) : null;
  const rootPrefix = isUnc
    ? "\\\\"
    : driveMatch
      ? driveMatch[0] + sep
      : p.startsWith(sep)
        ? sep
        : "";

  let body = rootPrefix ? p.slice(rootPrefix.length) : p;
  const out: string[] = [];
  for (const seg of body.split(sep)) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0) out.pop();
      continue; // .. at root: discard (stays at root)
    }
    out.push(seg);
  }
  body = out.join(sep);
  if (rootPrefix && body === "") return rootPrefix;
  return rootPrefix + body;
}

function normalizeCase(p: string, platform: Platform): string {
  // Windows filesystems are case-insensitive: fold case for identity.
  return platform === "win32" ? p.toLowerCase() : p;
}

function dirnameOf(p: string, platform: Platform): string {
  const s = sepFor(platform);
  const idx = p.lastIndexOf(s);
  if (idx <= 0) return p;
  if (idx === p.length - 1) return dirnameOf(p.slice(0, -1), platform);
  let parent = p.slice(0, idx);
  // keep "C:\" drive roots intact on win32
  if (platform === "win32" && /^[A-Za-z]:$/.test(parent)) parent += s;
  return parent;
}

function basenameOf(p: string, platform: Platform): string {
  return p.split(sepFor(platform)).filter(Boolean).pop() ?? p;
}

export type WorkspaceRelation = "inside" | "outside" | "workspace-root";

/** Separator-boundary containment check on canonical paths. */
export function relationToWorkspace(
  canonicalPath: string,
  workspaceRoot: string | undefined,
): WorkspaceRelation {
  if (!workspaceRoot) return "outside";
  if (canonicalPath === workspaceRoot) return "workspace-root";
  const prefix = workspaceRoot.endsWith(sepFor(platformOf(workspaceRoot)))
    ? workspaceRoot
    : workspaceRoot + sepFor(platformOf(workspaceRoot));
  return canonicalPath.startsWith(prefix) ? "inside" : "outside";
}

function platformOf(p: string): Platform {
  return p.includes("\\") ? "win32" : "linux";
}

/**
 * True when `target` is `resource` itself or lies inside it (separator-
 * boundary aware). Both sides are lexically normalized first, so ".."
 * cannot fake containment. `caseFold` applies Windows-insensitive
 * comparison.
 */
export function isInside(target: string, resource: string, caseFold = false): boolean {
  const platform: Platform = target.includes("\\") || resource.includes("\\") ? "win32" : "linux";
  const t0 = lexicalNormalize(normalizeSeparators(target, platform), platform);
  const r0 = lexicalNormalize(normalizeSeparators(resource, platform), platform);
  const t = caseFold ? t0.toLowerCase() : t0;
  const r = caseFold ? r0.toLowerCase() : r0;
  if (t === r) return true;
  const rr = r.endsWith(sepFor(platform)) ? r : r + sepFor(platform);
  return t.startsWith(rr);
}

/**
 * Parse a command-line-ish path argument that may be quoted. Returns the
 * unquoted token. Deliberately small: shell detection is conservative
 * (P4 fails toward approval on uncertainty), not a parser.
 */
export function unquote(token: string): string {
  if (
    (token.startsWith('"') && token.endsWith('"') && token.length >= 2) ||
    (token.startsWith("'") && token.endsWith("'") && token.length >= 2)
  ) {
    return token.slice(1, -1);
  }
  return token;
}

/** Absolute check per injected platform (win32 drive letters/UNC, posix root). */
export function isAbsoluteFor(p: string, platform: Platform): boolean {
  if (platform === "win32") return /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\");
  return p.startsWith("/");
}

/** True for paths that are a platform root (e.g. `C:\`, `\\srv\share`, `/`). */
export function isRoot(p: string, platform: Platform): boolean {
  const norm = lexicalNormalize(normalizeSeparators(p, platform), platform);
  if (platform === "win32") {
    return /^[A-Za-z]:\\?$/.test(norm) || /^\\\\[^\\]+\\[^\\]+\\?$/.test(norm);
  }
  return norm === "/";
}

/** Validate a path is representable for identity (no NUL, non-empty). */
export function isValidPath(input: string): boolean {
  return input.length > 0 && !input.includes("\0");
}
