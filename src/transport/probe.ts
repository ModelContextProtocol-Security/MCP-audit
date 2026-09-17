import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type {
  AuditTarget,
  PromptSpec,
  ResourceSpec,
  ToolSpec,
  TransportKind,
} from "../types.js";
import {
  DEFAULT_LIMITS,
  ProbeLimitError,
  withDeadline,
  type ProbeLimits,
} from "./limits.js";

const CLIENT_INFO = { name: "mcp-audit", version: "0.1.0" };

/**
 * Connect a {@link Client} over an already-constructed transport, enumerate the
 * server's tools/resources/prompts, and return a normalized {@link AuditTarget}.
 * Capabilities the server does not advertise are treated as empty rather than
 * an error.
 */
export async function probe(
  transport: Transport,
  meta: {
    kind: TransportKind;
    source: string;
    url?: string;
    authProvided?: boolean;
  },
  limits: ProbeLimits = DEFAULT_LIMITS,
): Promise<AuditTarget> {
  const client = new Client(CLIENT_INFO, {
    capabilities: {},
  });

  // The deadline covers the whole probe, handshake included: a server that
  // accepts the connection and then answers nothing is the cheapest way to
  // hang a client, and it never reaches the listing calls below.
  const startedAt = Date.now();
  const remaining = (): number =>
    Math.max(1, limits.timeoutMs - (Date.now() - startedAt));

  await withDeadline(client.connect(transport), remaining(), "connect");
  try {
    const version = client.getServerVersion();
    const instructions = client.getInstructions();
    const truncated: string[] = [];

    const tools = await safeList(async () =>
      (await listAllPages(
        client.listTools.bind(client),
        "tools",
        limits,
        remaining,
        truncated,
      )) as ToolSpec[],
    );
    const resources = await safeList(async () =>
      (await listAllPages(
        client.listResources.bind(client),
        "resources",
        limits,
        remaining,
        truncated,
      )) as ResourceSpec[],
    );
    const prompts = await safeList(async () =>
      (await listAllPages(
        client.listPrompts.bind(client),
        "prompts",
        limits,
        remaining,
        truncated,
      )) as PromptSpec[],
    );

    return {
      transport: meta.kind,
      source: meta.source,
      serverInfo: {
        name: version?.name,
        version: version?.version,
        instructions,
      },
      tools,
      resources,
      prompts,
      connection: { url: meta.url, authProvided: meta.authProvided },
      truncated: truncated.length > 0 ? truncated : undefined,
    };
  } finally {
    await client.close().catch(() => undefined);
  }
}

type PaginatedListResult<T> = {
  tools?: T[];
  resources?: T[];
  prompts?: T[];
  nextCursor?: string;
};

/**
 * Follow {@link nextCursor} until the capability is exhausted or a bound is
 * hit. Three things end the loop early, and all three are conditions a server
 * can create at will:
 *
 * - a cursor that does not change, which means the server is not advancing;
 * - more pages or items than the configured caps allow;
 * - the probe deadline.
 *
 * Unless `allowTruncated` is set, each raises rather than returning a partial
 * list, because a partial surface that reads as a whole one is worse than no
 * answer.
 */
async function listAllPages<T>(
  listPage: (params?: { cursor?: string }) => Promise<PaginatedListResult<T>>,
  capability: string,
  limits: ProbeLimits,
  remaining: () => number,
  truncated: string[],
): Promise<T[]> {
  const items: T[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  let pages = 0;

  do {
    const res = await withDeadline(
      listPage(cursor ? { cursor } : undefined),
      remaining(),
      `listing ${capability}`,
    );
    pages++;
    const page = res.tools ?? res.resources ?? res.prompts ?? ([] as T[]);
    items.push(...page);
    cursor = res.nextCursor;

    if (cursor !== undefined) {
      // A repeated cursor is the signature of a server that never terminates,
      // and it is reached identically by a hostile server and an off-by-one
      // bug. Catch it on the second page rather than at the page cap.
      if (seenCursors.has(cursor)) {
        throw new ProbeLimitError(
          `Server repeated the pagination cursor for ${capability} after ${pages} pages, so it is not making progress.`,
          "stalled-cursor",
        );
      }
      seenCursors.add(cursor);
    }

    if (pages >= limits.maxPages && cursor !== undefined) {
      if (!limits.allowTruncated) {
        throw new ProbeLimitError(
          `Server returned more than ${limits.maxPages} pages of ${capability}. Raise --max-pages, or pass --allow-truncated to audit what was read.`,
          "pages",
        );
      }
      truncated.push(`${capability} (page cap)`);
      break;
    }

    if (items.length >= limits.maxItems && cursor !== undefined) {
      if (!limits.allowTruncated) {
        throw new ProbeLimitError(
          `Server returned more than ${limits.maxItems} ${capability}. Raise --max-items, or pass --allow-truncated to audit what was read.`,
          "items",
        );
      }
      truncated.push(`${capability} (item cap)`);
      break;
    }
  } while (cursor);

  return items;
}

/**
 * List a capability, returning an empty array when the server does not support
 * it (the SDK throws a "Method not found" error in that case).
 */
async function safeList<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch (err) {
    // A bound is never "this capability is unsupported"; let it out.
    if (err instanceof ProbeLimitError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    if (/method not found|-32601|not supported|no such/i.test(message)) {
      return [];
    }
    throw err;
  }
}
