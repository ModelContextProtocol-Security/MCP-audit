import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { AuditTarget } from "../types.js";
import { probe } from "./probe.js";
import { DEFAULT_LIMITS, type ProbeLimits } from "./limits.js";

export interface HttpTargetOptions {
  url: string;
  /** Optional bearer token; when supplied the target is marked authenticated. */
  token?: string;
  /** Extra headers to send on every request. */
  headers?: Record<string, string>;
  /** Force the legacy SSE transport instead of Streamable HTTP. */
  useSse?: boolean;
}

/**
 * Connect to a remote MCP server over HTTP and audit-probe it. Uses the
 * Streamable HTTP transport by default, falling back to SSE when requested.
 */
export async function connectHttp(
  options: HttpTargetOptions,
  limits: ProbeLimits = DEFAULT_LIMITS,
): Promise<AuditTarget> {
  const url = new URL(options.url);
  const headers: Record<string, string> = { ...options.headers };
  if (options.token) headers["Authorization"] = `Bearer ${options.token}`;
  const authProvided =
    options.token !== undefined ||
    Object.keys(headers).some((h) => h.toLowerCase() === "authorization");

  const requestInit: RequestInit =
    Object.keys(headers).length > 0 ? { headers } : {};

  const transport: Transport = options.useSse
    ? new SSEClientTransport(url, { requestInit })
    : new StreamableHTTPClientTransport(url, { requestInit });

  return probe(
    transport,
    {
      kind: "http",
      source: options.url,
      url: options.url,
      authProvided,
    },
    limits,
  );
}
