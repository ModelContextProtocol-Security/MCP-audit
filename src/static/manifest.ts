import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type {
  AuditTarget,
  PromptSpec,
  ResourceSpec,
  ServerInfo,
  ToolSpec,
} from "../types.js";
import { redactUrl } from "../redact.js";

/**
 * Shape of a static manifest that mcp-audit can lint without connecting. All
 * fields are optional; the loader also accepts a bare array of tools.
 */
export interface ManifestFile {
  serverInfo?: ServerInfo;
  server?: ServerInfo;
  tools?: ToolSpec[];
  resources?: ResourceSpec[];
  prompts?: PromptSpec[];
  /** Marks the declared transport so transport rules apply in static mode. */
  transport?: "stdio" | "http";
  /** For http manifests: whether auth is declared. */
  url?: string;
  authProvided?: boolean;
}

/**
 * Load and normalize a static MCP manifest into an {@link AuditTarget}. This
 * lets mcp-audit lint a server's declared surface from source control without
 * ever executing it.
 */
export async function loadManifest(path: string): Promise<AuditTarget> {
  const absolute = resolve(path);
  const raw = await readFile(absolute, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Failed to parse manifest ${absolute}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  return normalize(parsed, absolute);
}

/** Normalize an already-parsed manifest object into an {@link AuditTarget}. */
export function normalize(parsed: unknown, source: string): AuditTarget {
  const manifest: ManifestFile = Array.isArray(parsed)
    ? { tools: parsed as ToolSpec[] }
    : ((parsed as ManifestFile) ?? {});

  if (manifest.tools != null && !Array.isArray(manifest.tools)) {
    throw new Error(`Invalid manifest ${source}: tools must be an array.`);
  }

  const serverInfo = manifest.serverInfo ?? manifest.server ?? {};
  const declaredHttp = manifest.transport === "http";

  return {
    transport: declaredHttp ? "http" : "static",
    source,
    serverInfo,
    tools: manifest.tools ?? [],
    resources: manifest.resources ?? [],
    prompts: manifest.prompts ?? [],
    connection: {
      // A manifest committed to a repo can carry a credential in its declared
      // url just as a live target can.
      url: manifest.url === undefined ? undefined : redactUrl(manifest.url),
      authProvided: manifest.authProvided,
    },
  };
}
