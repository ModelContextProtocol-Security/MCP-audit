import { describe, it, expect } from "vitest";
import { writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveToken } from "../src/cli.js";

const silent = () => {};

describe("resolveToken", () => {
  it("prefers --token-file over everything else", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-audit-"));
    const file = join(dir, "token");
    await writeFile(file, "from-file\n", "utf8");

    const token = await resolveToken(
      { "token-file": file, token: "from-flag" },
      { MCP_AUDIT_TOKEN: "from-env" },
      silent,
    );
    expect(token).toBe("from-file");
  });

  it("trims the token file, since editors add a newline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-audit-"));
    const file = join(dir, "token");
    await writeFile(file, "  padded  \n", "utf8");
    expect(await resolveToken({ "token-file": file }, {}, silent)).toBe("padded");
  });

  it("rejects an empty token file rather than connecting unauthenticated", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-audit-"));
    const file = join(dir, "token");
    await writeFile(file, "\n\n", "utf8");
    await expect(resolveToken({ "token-file": file }, {}, silent)).rejects.toThrow(
      /is empty/,
    );
  });

  it("falls back to MCP_AUDIT_TOKEN before --token", async () => {
    const token = await resolveToken(
      { token: "from-flag" },
      { MCP_AUDIT_TOKEN: "from-env" },
      silent,
    );
    expect(token).toBe("from-env");
  });

  it("accepts --token but warns that it is visible to other processes", async () => {
    const warnings: string[] = [];
    const token = await resolveToken({ token: "from-flag" }, {}, (m) =>
      warnings.push(m),
    );
    expect(token).toBe("from-flag");
    expect(warnings.join("")).toMatch(/visible to other processes/);
  });

  it("returns undefined when no token is supplied anywhere", async () => {
    expect(await resolveToken({}, {}, silent)).toBeUndefined();
  });
});
