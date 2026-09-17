import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { AuditTarget } from "../types.js";
import { probe } from "./probe.js";
import { DEFAULT_LIMITS, type ProbeLimits } from "./limits.js";
import { redactCommandLine } from "../redact.js";

export interface StdioTargetOptions {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

/**
 * Spawn a local MCP server over stdio and audit-probe it. The command is run as
 * a child process; its stdout/stdin carry the MCP protocol.
 */
export async function connectStdio(
  options: StdioTargetOptions,
  limits: ProbeLimits = DEFAULT_LIMITS,
): Promise<AuditTarget> {
  const transport = new StdioClientTransport({
    command: options.command,
    args: options.args ?? [],
    env: options.env,
    cwd: options.cwd,
    stderr: "ignore",
  });

  // The plaintext command line never reaches AuditTarget: a stdio MCP server
  // is routinely configured with its credential in argv.
  const source = redactCommandLine(options.command, options.args ?? []);
  return probe(transport, { kind: "stdio", source }, limits);
}

/**
 * Parse a shell-ish command string into a command and argument list. This is a
 * simple whitespace/quote splitter, sufficient for CLI usage.
 */
export function parseCommand(input: string): {
  command: string;
  args: string[];
} {
  const tokens: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(input)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3] ?? "");
  }
  const [command, ...args] = tokens;
  if (!command) throw new Error("Empty stdio command");
  return { command, args };
}
