/**
 * Core type definitions shared across the mcp-audit engine, rules, and reporters.
 */

/** Severity levels, ordered from least to most serious. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Numeric rank for a severity, used for thresholds and sorting. */
export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const ALL_SEVERITIES: Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

/** A JSON-schema-ish object as exposed by MCP tool input schemas. */
export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  required?: string[];
  additionalProperties?: boolean | JsonSchema;
  enum?: unknown[];
  description?: string;
  [key: string]: unknown;
}

/** MCP tool annotations (e.g. hints for clients and auto-approval). */
export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  [key: string]: unknown;
}

/** A tool as enumerated from an MCP server (or a static manifest). */
export interface ToolSpec {
  name: string;
  description?: string;
  inputSchema?: JsonSchema;
  annotations?: ToolAnnotations;
}

/** A resource exposed by an MCP server. */
export interface ResourceSpec {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/** A prompt exposed by an MCP server. */
export interface PromptSpec {
  name: string;
  description?: string;
  arguments?: { name: string; description?: string; required?: boolean }[];
}

/** How the target was reached. */
export type TransportKind = "stdio" | "http" | "static";

/** Server identity/metadata returned during initialization. */
export interface ServerInfo {
  name?: string;
  version?: string;
  instructions?: string;
  protocolVersion?: string;
}

/**
 * The complete surface of an MCP target that rules inspect. Produced either by
 * connecting to a live server or by parsing a static manifest.
 */
export interface AuditTarget {
  transport: TransportKind;
  /** Human-readable description of the target (command line or URL or path). */
  source: string;
  serverInfo: ServerInfo;
  tools: ToolSpec[];
  resources: ResourceSpec[];
  prompts: PromptSpec[];
  /** Raw connection details useful to some rules. */
  connection: {
    /** Present for http transport. */
    url?: string;
    /** Whether an auth header/token was supplied when connecting. */
    authProvided?: boolean;
  };
  /**
   * Capabilities whose enumeration stopped at a bound rather than at the end of
   * the list. Only set when `--allow-truncated` was passed; otherwise a bound
   * is an error and no target is produced.
   */
  truncated?: string[];
}

/** A single finding produced by a rule. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  remediation: string;
  /** What the finding is attached to, e.g. tool name or resource uri. */
  location?: string;
}

/** Static metadata describing a rule. */
export interface RuleMeta {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  /** Short category used for grouping in docs. */
  category:
    | "permissions"
    | "schema"
    | "injection"
    | "secrets"
    | "transport"
    | "metadata"
    | "hygiene";
}

/** A rule: metadata plus an evaluation function. */
export interface Rule extends RuleMeta {
  evaluate(target: AuditTarget, ctx: RuleContext): Finding[];
}

/** Helpers passed to each rule during evaluation. */
export interface RuleContext {
  /** Build a finding pre-filled with this rule's id and default severity. */
  report(
    partial: Omit<Finding, "ruleId" | "severity"> & { severity?: Severity },
  ): Finding;
}
