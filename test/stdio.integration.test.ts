import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { connectStdio, parseCommand } from "../src/transport/stdio.js";
import { runAudit, shouldFail } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { ALL_RULES } from "../src/rules/index.js";
import { renderSarif } from "../src/reporters/sarif.js";
import { renderJson } from "../src/reporters/json.js";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");
const server = resolve(root, "fixtures/mock-server.mjs");

describe("parseCommand", () => {
  it("splits a command respecting quotes", () => {
    expect(parseCommand('node server.js --flag "a b"')).toEqual({
      command: "node",
      args: ["server.js", "--flag", "a b"],
    });
  });
  it("throws on an empty command", () => {
    expect(() => parseCommand("   ")).toThrow();
  });
});

describe("live stdio audit", () => {
  it("connects to the insecure mock server and finds critical issues", async () => {
    const target = await connectStdio({
      command: "node",
      args: [server, "insecure"],
    });
    expect(target.transport).toBe("stdio");
    expect(target.serverInfo.name).toBe("insecure-demo-server");
    expect(target.tools.length).toBe(7);
    expect(target.resources.length).toBe(2);

    const result = runAudit(target, DEFAULT_CONFIG, ALL_RULES);
    expect(result.counts.critical).toBeGreaterThan(0);
    expect(shouldFail(result, "high")).toBe(true);
  });

  it("connects to the clean mock server with no high/critical findings", async () => {
    const target = await connectStdio({
      command: "node",
      args: [server, "clean"],
    });
    const result = runAudit(target, DEFAULT_CONFIG, ALL_RULES);
    expect(result.counts.critical).toBe(0);
    expect(result.counts.high).toBe(0);
    expect(shouldFail(result, "high")).toBe(false);
  });
});

describe("credentials do not reach a report", () => {
  // The regression this exists for: a credential in argv reaching a SARIF file,
  // which is a format whose purpose is upload to GitHub code scanning.
  const SECRET = "sk-live-NEVERPUBLISHME1234567890";

  it("keeps a credential out of SARIF, JSON and the target itself", async () => {
    const target = await connectStdio({
      command: "node",
      args: [server, "insecure", `--api-key=${SECRET}`],
    });

    const result = runAudit(target, DEFAULT_CONFIG);
    const sarif = renderSarif(result, ALL_RULES);
    const json = renderJson(result);

    expect(JSON.stringify(target)).not.toContain(SECRET);
    expect(sarif).not.toContain(SECRET);
    expect(json).not.toContain(SECRET);

    // Still identifies which server was audited.
    expect(target.source).toContain("mock-server.mjs");
    expect(target.source).toContain("--api-key=REDACTED");
  });
});
