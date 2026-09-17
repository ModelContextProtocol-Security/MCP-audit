import { afterEach, describe, expect, it, vi } from "vitest";
import { collectHeaders, main, overlayFlags, parseArgs, collectLimits } from "../src/cli.js";
import { DEFAULT_LIMITS } from "../src/transport/limits.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { runAudit } from "../src/audit.js";
import { makeTarget } from "./helpers.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("top-level information flags", () => {
  it("prints only the version and succeeds without a command", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main(["--version"])).resolves.toBe(0);

    expect(write).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledWith(expect.stringMatching(/^\d+\.\d+\.\d+\n$/));
  });

  it("keeps a bare invocation as a usage error", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main([])).resolves.toBe(2);
    expect(write).toHaveBeenCalledWith(expect.stringContaining("USAGE"));
  });

  it("keeps explicit help successful", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main(["--help"])).resolves.toBe(0);
    expect(write).toHaveBeenCalledWith(expect.stringContaining("USAGE"));
  });
});

describe("parseArgs", () => {
  it("parses --flag=value as a string flag value", () => {
    const { flags } = parseArgs(["audit", "--fail-on=high"]);
    expect(flags["fail-on"]).toBe("high");
  });
});

describe("HTTP headers", () => {
  it("collects every repeated --header flag", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "X-Tenant: acme",
      "--header",
      "X-Env: prod",
    ]);

    expect(collectHeaders(flags)).toEqual({
      "X-Tenant": "acme",
      "X-Env": "prod",
    });
  });

  it("preserves colons in header values", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "Authorization: Bearer a:b",
    ]);

    expect(collectHeaders(flags)).toEqual({ Authorization: "Bearer a:b" });
  });


  it("treats --only \"\" as an empty allowlist (zero rules run)", () => {
    const { flags } = parseArgs(["static", "manifest.json", "--only", ""]);
    const config = overlayFlags(DEFAULT_CONFIG, flags);
    const result = runAudit(makeTarget(), config);
    expect(result.rulesRun).toEqual([]);
});

it("rejects a header value without a colon", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "Authorization",
    ]);

    expect(() => collectHeaders(flags)).toThrow(
      /header.*colon/i,
    );
  });

  it("keeps last-wins behavior for repeated non-header flags", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--config",
      "one.json",
      "--config",
      "two.json",
    ]);

    expect(flags.config).toBe("two.json");
  });
});

describe("collectLimits", () => {
  it("defaults to the shipped bounds", () => {
    expect(collectLimits({})).toEqual(DEFAULT_LIMITS);
  });
  it("reads the bound flags", () => {
    expect(
      collectLimits({
        timeout: "5000",
        "max-pages": "7",
        "max-items": "9",
        "allow-truncated": true,
      }),
    ).toEqual({
      timeoutMs: 5000,
      maxPages: 7,
      maxItems: 9,
      allowTruncated: true,
    });
  });
  it("rejects a non-positive or non-integer bound", () => {
    expect(() => collectLimits({ "max-pages": "0" })).toThrow(/positive integer/);
    expect(() => collectLimits({ timeout: "abc" })).toThrow(/positive integer/);
    expect(() => collectLimits({ "max-items": "1.5" })).toThrow(/positive integer/);
  });
  it("does not truncate unless asked", () => {
    expect(collectLimits({}).allowTruncated).toBe(false);
  });
});
