// Conservative raw-shell classification. NOT a shell parser — a deliberately
// bounded detector over tokenized commands. Uncertainty + potential impact
// fails toward approval (P4); this module never silently allows anything it
// cannot classify. Nested shells (bash -c, sh -c, cmd /c, pwsh -Command)
// are unwrapped to a bounded depth.
//
// Honest limits (documented, tested): no environment-expansion evaluation,
// no variable tracing, no alias resolution, no process substitution. A
// command that LOOKS destructive but is obfuscated will usually still trip
// the destructive-token or unknown-risk path; one that is semantically
// dangerous but lexically innocent may be misclassified — the policy layer
// answers that by requiring approval for unknown/execute outside trusted
// workspaces rather than pretending perfection.

import { unquote } from "./paths.ts";

export interface ShellClassification {
  /** Actions detected in the command (may be several). */
  findings: ShellFinding[];
  /** True when the command could not be classified with confidence. */
  uncertain: boolean;
}

export interface ShellFinding {
  op:
    | "recursive-delete"
    | "delete"
    | "git-reset-hard"
    | "git-clean"
    | "git-force-push"
    | "git-branch-delete"
    | "privilege-escalation"
    | "system-change"
    | "execute"
    | "network-fetch";
  /** Best-effort path arguments detected for the finding. */
  paths: string[];
}

const MAX_NESTING = 3;

export function classifyShell(command: string): ShellClassification {
  const findings: ShellFinding[] = [];
  let uncertain = false;
  visit(command, 0, findings, () => {
    uncertain = true;
  });
  return { findings, uncertain };
}

function visit(
  command: string,
  depth: number,
  findings: ShellFinding[],
  onUncertain: () => void,
): void {
  if (depth > MAX_NESTING) {
    onUncertain();
    return;
  }
  const segments = splitSegments(command);
  for (const segment of segments) {
    const tokens = tokenize(segment);
    if (tokens.length === 0) continue;
    const unwrapped = unwrapNestedShell(tokens);
    if (unwrapped) {
      visit(unwrapped, depth + 1, findings, onUncertain);
      continue;
    }
    classifySegment(tokens, findings, onUncertain);
  }
}

/** Split on shell command separators that start a NEW command. */
function splitSegments(command: string): string[] {
  return command.split(/(?:&&|\|\||;|\|)/g).map((s) => s.trim());
}

/** Tokenize respecting simple quoting; no expansion. */
function tokenize(segment: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | undefined;
  for (const ch of segment) {
    if (quote) {
      if (ch === quote) quote = undefined;
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) tokens.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (quote) onUnterminated();
  if (current) tokens.push(current);
  return tokens;

  function onUnterminated() {
    // unterminated quote: leave the quote character in the token; the
    // classifier will likely be uncertain — which is the safe direction.
  }
}

/** Detect `bash -c "..."`, `sh -c`, `cmd /c`, `powershell -Command` wrappers. */
function unwrapNestedShell(tokens: string[]): string | undefined {
  const head = tokens[0]!.toLowerCase().split(/[\\/]/).pop()!;
  const rest = tokens.slice(1).map((t) => t.toLowerCase());
  const innerIdx = (() => {
    if (["bash", "sh", "zsh", "dash"].includes(head)) {
      const i = rest.indexOf("-c");
      return i >= 0 ? i + 1 : -1;
    }
    if (head === "cmd") {
      const i = rest.findIndex((t) => t === "/c" || t === "/k");
      return i >= 0 ? i + 1 : -1;
    }
    if (head === "powershell" || head === "pwsh") {
      const i = rest.findIndex((t) => t === "-command" || t === "-c");
      return i >= 0 ? i + 1 : -1;
    }
    return -1;
  })();
  if (innerIdx < 0 || innerIdx >= tokens.length) return undefined;
  // innerIdx indexes `rest` (tokens minus the shell head); re-join the
  // inner command from the ORIGINAL (case-preserved) tokens.
  return tokens.slice(innerIdx + 1).join(" ");
}

function classifySegment(
  tokens: string[],
  findings: ShellFinding[],
  onUncertain: () => void,
): void {
  const exe = tokens[0]!
    .toLowerCase()
    .split(/[\\/]/)
    .pop()!
    .replace(/\.exe$/, "");
  const args = tokens.slice(1);
  const lowered = args.map((a) => a.toLowerCase());

  switch (exe) {
    case "rm":
    case "rmdir": {
      const recursive = lowered.some((a) => /^(-[a-z]*r[a-z]*|--recursive)$/.test(a));
      const force = lowered.some((a) => /^(-[a-z]*f[a-z]*|--force)$/.test(a));
      const targets = pathArgs(args);
      findings.push({
        op: recursive ? "recursive-delete" : "delete",
        paths: targets,
      });
      if (recursive && targets.length === 0) onUncertain();
      void force;
      break;
    }
    case "del":
    case "rd":
    case "erase": {
      const recursive = lowered.some((a) => a === "/s");
      findings.push({ op: recursive ? "recursive-delete" : "delete", paths: pathArgs(args) });
      break;
    }
    case "remove-item": {
      const recursive = lowered.some((a) => a === "-recurse" || a === "-r");
      findings.push({ op: recursive ? "recursive-delete" : "delete", paths: pathArgs(args) });
      break;
    }
    case "git": {
      const sub = args[0]?.toLowerCase();
      if (sub === "reset" && lowered.includes("--hard")) {
        findings.push({ op: "git-reset-hard", paths: [] });
      } else if (sub === "clean") {
        findings.push({ op: "git-clean", paths: [] });
      } else if (sub === "push" && lowered.some((a) => a.includes("force") || a.startsWith("-f"))) {
        findings.push({ op: "git-force-push", paths: [] });
      } else if (
        (sub === "branch" && lowered.some((a) => a === "-d" || a === "-d" || a === "--delete")) ||
        (sub === "push" && lowered.includes("--delete"))
      ) {
        findings.push({ op: "git-branch-delete", paths: pathArgs(args) });
      }
      // other git subcommands are inspected by the policy layer as git-safe/unknown
      break;
    }
    case "sudo":
    case "doas":
    case "runas": {
      findings.push({ op: "privilege-escalation", paths: [] });
      // classify the inner command too
      if (args.length > 0) classifySegment(args, findings, onUncertain);
      break;
    }
    case "chmod":
    case "chown":
    case "icacls":
    case "attrib": {
      if (lowered.some((a) => /^(-r|--recursive|\/t)$/.test(a))) {
        findings.push({ op: "system-change", paths: pathArgs(args) });
      }
      break;
    }
    case "mkfs":
    case "dd":
    case "format":
    case "diskpart":
    case "shutdown":
    case "reboot":
    case "sc":
    case "systemctl":
    case "reg":
    case "regedit": {
      findings.push({ op: "system-change", paths: [] });
      break;
    }
    case "curl":
    case "wget":
    case "invoke-webrequest":
    case "invoke-restmethod": {
      // fetching alone is not a side effect on this machine; recorded so the
      // policy layer can treat piping-to-shell with suspicion
      findings.push({ op: "network-fetch", paths: [] });
      break;
    }
    default: {
      if (exe.includes("powershell") || exe === "pwsh") {
        // powershell without -Command wrapper: still executes scripts
        findings.push({ op: "execute", paths: [] });
        break;
      }
      // Any other program execution is the "execute" class; the policy
      // layer decides allow (trusted workspace) vs approval.
      findings.push({ op: "execute", paths: pathArgs(args) });
      break;
    }
  }
  void onUncertain;
}

/** Non-flag, non-empty arguments as unquoted strings. */
function pathArgs(args: string[]): string[] {
  return args
    .filter((a) => !a.startsWith("-"))
    .map((a) => unquote(a))
    .filter((p) => p.length > 0);
}
