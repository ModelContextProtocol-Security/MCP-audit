#!/usr/bin/env node
import { runAudit, shouldFail } from "./audit.js";
import { loadConfig, normalizeConfig } from "./config.js";
import type { McpAuditConfig } from "./config.js";
import { connectStdio, parseCommand } from "./transport/stdio.js";
import { connectHttp } from "./transport/http.js";
import { loadManifest } from "./static/manifest.js";
import { DEFAULT_LIMITS, type ProbeLimits } from "./transport/limits.js";
import { readFile } from "node:fs/promises";
import { renderTerminal } from "./reporters/terminal.js";
import { renderJson } from "./reporters/json.js";
import { renderSarif } from "./reporters/sarif.js";
import { ALL_RULES } from "./rules/index.js";
import type { AuditTarget, Severity } from "./types.js";
import { ALL_SEVERITIES } from "./types.js";

const VERSION = "0.1.0";

type CliFlag = string | boolean | string[];

interface CliArgs {
  command?: string;
  positional: string[];
  flags: Record<string, CliFlag>;
}

export function parseArgs(argv: string[]): CliArgs {
  const positional: string[] = [];
  const flags: Record<string, CliFlag> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      let key = arg.slice(2);
      let inlineValue: string | undefined;
      const eq = key.indexOf("=");
      if (eq !== -1) {
        inlineValue = key.slice(eq + 1);
        key = key.slice(0, eq);
      }
      const next = argv[i + 1];
      if (inlineValue !== undefined) {
        if (key === "header" && flags[key] !== undefined) {
          const previous = flags[key];
          flags[key] = Array.isArray(previous)
            ? [...previous, inlineValue]
            : typeof previous === "string"
              ? [previous, inlineValue]
              : inlineValue;
        } else {
          flags[key] = inlineValue;
        }
      } else if (next !== undefined && !next.startsWith("--")) {
        if (key === "header" && flags[key] !== undefined) {
          const previous = flags[key];
          flags[key] = Array.isArray(previous)
            ? [...previous, next]
            : typeof previous === "string"
              ? [previous, next]
              : next;
        } else {
          flags[key] = next;
        }
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  const [command, ...rest] = positional;
  return { command, positional: rest, flags };
}

function usage(): string {
  return `mcp-audit v${VERSION} — security scanner and linter for MCP servers

USAGE
  mcp-audit stdio  "<command> [args...]"   Spawn a server over stdio and audit it
  mcp-audit http   <url>                   Audit a server over HTTP/SSE
  mcp-audit static <manifest.json>         Lint a manifest without connecting
  mcp-audit rules                          List the built-in rule catalog

OPTIONS
  --json                 Emit JSON instead of terminal output
  --sarif                Emit SARIF 2.1.0 (for GitHub code scanning)
  --output <file>        Write the report to a file instead of stdout
  --config <file>        Use a specific config file
  --fail-on <severity>   Exit non-zero at/above this severity (default: high)
  --disable <ids>        Comma-separated rule ids to disable
  --only <ids>           Comma-separated rule ids to run exclusively
  --token <token>        Bearer token for http transport (visible to ps)
  --token-file <file>    Read the bearer token from a file (preferred)
  --header <k:v>         Extra header for http transport (repeatable)
  --sse                  Use legacy SSE transport for http
  --timeout <ms>         Deadline for the whole probe (default: 60000)
  --max-pages <n>        Max pages followed per capability (default: 100)
  --max-items <n>        Max items collected per capability (default: 10000)
  --allow-truncated      Audit a partial surface instead of failing on a bound

ENVIRONMENT
  MCP_AUDIT_TOKEN        Bearer token for http transport, if no flag is given
  --no-color             Disable colored output
  --help                 Show this help
  --version              Show version

EXIT CODES
  0  no findings at/above --fail-on
  1  findings at/above --fail-on
  2  usage or runtime error
`;
}

/** Parse a positive-integer flag, rejecting anything that is not one. */
function positiveInt(
  value: CliFlag | undefined,
  flag: string,
  fallback: number,
): number {
  if (value === undefined) return fallback;
  const n = Number(String(value));
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`Invalid ${flag} "${String(value)}"; expected a positive integer.`);
  }
  return n;
}

export function collectLimits(flags: Record<string, CliFlag>): ProbeLimits {
  return {
    timeoutMs: positiveInt(flags["timeout"], "--timeout", DEFAULT_LIMITS.timeoutMs),
    maxPages: positiveInt(flags["max-pages"], "--max-pages", DEFAULT_LIMITS.maxPages),
    maxItems: positiveInt(flags["max-items"], "--max-items", DEFAULT_LIMITS.maxItems),
    allowTruncated: flags["allow-truncated"] === true,
  };
}

function csv(value: CliFlag | undefined): string[] {
  if (typeof value !== "string") return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function overlayFlags(
  base: McpAuditConfig,
  flags: Record<string, CliFlag>,
): McpAuditConfig {
  const overlay: Record<string, unknown> = {};
  if (flags["fail-on"]) {
    const fo = String(flags["fail-on"]);
    if (!ALL_SEVERITIES.includes(fo as Severity)) {
      throw new Error(
        `Invalid --fail-on "${fo}"; expected one of ${ALL_SEVERITIES.join(", ")}.`,
      );
    }
    overlay.failOn = fo;
  }
  if (flags["disable"]) overlay.disabledRules = csv(flags["disable"]);
  if (flags["only"] !== undefined) {
    overlay.enabledRules = csv(flags["only"]);
    overlay.enforceEnabledRules = true;
  }
  return normalizeConfig(overlay, base);
}

/**
 * Resolve the bearer token for an http target.
 *
 * Order is --token-file, then MCP_AUDIT_TOKEN, then --token. A token on the
 * command line is visible to every process on the host via `ps`, lands in shell
 * history, and lands in CI logs, so it is accepted last and warned about rather
 * than removed — removing it would break existing callers into doing something
 * worse.
 */
export async function resolveToken(
  flags: Record<string, CliFlag>,
  env: NodeJS.ProcessEnv = process.env,
  warn: (msg: string) => void = (m) => process.stderr.write(m),
): Promise<string | undefined> {
  const file = flags["token-file"];
  if (typeof file === "string") {
    const contents = await readFile(file, "utf8");
    const token = contents.trim();
    if (!token) throw new Error(`Token file "${file}" is empty.`);
    return token;
  }
  const fromEnv = env["MCP_AUDIT_TOKEN"]?.trim();
  if (fromEnv) return fromEnv;

  const flag = flags["token"];
  if (typeof flag === "string" && flag !== "") {
    warn(
      "mcp-audit: WARNING — --token is visible to other processes via `ps` and is " +
        "recorded in shell history. Prefer --token-file or MCP_AUDIT_TOKEN.\n",
    );
    return flag;
  }
  return undefined;
}

export function collectHeaders(
  flags: Record<string, CliFlag>,
): Record<string, string> {
  const headers: Record<string, string> = {};
  const raw = flags["header"];
  const values = Array.isArray(raw) ? raw : raw ? [raw] : [];
  for (const v of values) {
    if (typeof v !== "string") continue;
    const idx = v.indexOf(":");
    if (idx <= 0) {
      throw new Error(
        `Invalid --header "${v}"; expected "Name: value" with a colon separator.`,
      );
    }
    headers[v.slice(0, idx).trim()] = v.slice(idx + 1).trim();
  }
  return headers;
}

function printRules(): void {
  const rows = ALL_RULES.map(
    (r) => `${r.id}  ${r.severity.padEnd(8)} ${r.category.padEnd(12)} ${r.title}`,
  );
  process.stdout.write(
    `mcp-audit rule catalog (${ALL_RULES.length} rules)\n\n` +
      rows.join("\n") +
      "\n",
  );
}

async function resolveTarget(args: CliArgs): Promise<AuditTarget> {
  const { command, positional, flags } = args;
  const limits = collectLimits(flags);
  switch (command) {
    case "stdio": {
      const cmd = positional.join(" ");
      if (!cmd) throw new Error('stdio requires a command, e.g. mcp-audit stdio "node server.js"');
      const { command: bin, args: binArgs } = parseCommand(cmd);
      return connectStdio({ command: bin, args: binArgs }, limits);
    }
    case "http": {
      const url = positional[0];
      if (!url) throw new Error("http requires a URL");
      return connectHttp(
        {
          url,
          token: await resolveToken(flags),
          headers: collectHeaders(flags),
          useSse: flags["sse"] === true,
        },
        limits,
      );
    }
    case "static": {
      const path = positional[0];
      if (!path) throw new Error("static requires a manifest path");
      return loadManifest(path);
    }
    default:
      throw new Error(`Unknown command "${command ?? ""}". Run --help.`);
  }
}

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const { command, flags } = args;

  if (flags["version"]) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (flags["help"] || command === "help" || command === undefined) {
    process.stdout.write(usage());
    return command === undefined && !flags["help"] ? 2 : 0;
  }
  if (command === "rules") {
    printRules();
    return 0;
  }

  const { config: fileConfig } = await loadConfig({
    explicitPath:
      typeof flags["config"] === "string" ? flags["config"] : undefined,
  });
  const config = overlayFlags(fileConfig, flags);

  const target = await resolveTarget(args);
  const result = runAudit(target, config);

  let output: string;
  if (flags["sarif"]) {
    output = renderSarif(result, ALL_RULES);
  } else if (flags["json"]) {
    output = renderJson(result);
  } else {
    output = renderTerminal(result, { color: flags["no-color"] !== true });
  }

  if (target.truncated?.length) {
    process.stderr.write(
      `mcp-audit: WARNING — the surface was truncated (${target.truncated.join(", ")}). ` +
        `This report does not cover the whole server.\n`,
    );
  }

  if (typeof flags["output"] === "string") {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(flags["output"], output + "\n", "utf8");
    process.stderr.write(`report written to ${flags["output"]}\n`);
  } else {
    process.stdout.write(output + "\n");
  }

  return shouldFail(result, config.failOn) ? 1 : 0;
}

// Execute only when run as a binary, not when imported.
const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === `file://${process.argv[1]}`;

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(
        `mcp-audit: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exit(2);
    });
}
