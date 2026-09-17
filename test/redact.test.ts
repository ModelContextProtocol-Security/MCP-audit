import { describe, it, expect } from "vitest";
import {
  redactUrl,
  redactCommandLine,
  redactSecretValues,
} from "../src/redact.js";

describe("redactUrl", () => {
  it("strips userinfo", () => {
    expect(redactUrl("https://svc:hunter2@mcp.example.com/mcp")).toBe(
      "https://REDACTED:REDACTED@mcp.example.com/mcp",
    );
  });

  it("redacts secret-named query parameters and keeps the rest", () => {
    const out = redactUrl(
      "https://mcp.example.com/mcp?api_key=sk-live-abcdefghijk&tenant=csa&page=2",
    );
    expect(out).not.toContain("sk-live-abcdefghijk");
    expect(out).toContain("api_key=REDACTED");
    // Non-secret parameters survive: the identity still distinguishes servers.
    expect(out).toContain("tenant=csa");
    expect(out).toContain("page=2");
  });

  it("drops the fragment, which can carry a token and identifies nothing", () => {
    expect(redactUrl("https://mcp.example.com/mcp#access_token=abc")).toBe(
      "https://mcp.example.com/mcp",
    );
  });

  it("redacts a recognisable credential even under an innocuous name", () => {
    const out = redactUrl("https://mcp.example.com/mcp?note=ghp_" + "a".repeat(36));
    expect(out).toContain("REDACTED");
    expect(out).not.toContain("ghp_aaaa");
  });

  it("treats an unparseable url as opaque text rather than trusting it", () => {
    expect(redactUrl("not a url sk-live-abcdefghijk")).toBe("not a url REDACTED");
  });

  it("leaves a clean url byte-identical", () => {
    const clean = "https://mcp.example.com/mcp?tenant=csa";
    expect(redactUrl(clean)).toBe(clean);
  });
});

describe("redactCommandLine", () => {
  it("redacts the value after a secret-named flag", () => {
    expect(
      redactCommandLine("uv", ["run", "csa-skilljar", "--api-key", "live-abc123"]),
    ).toBe("uv run csa-skilljar --api-key REDACTED");
  });

  it("redacts an inline secret-named flag value", () => {
    expect(redactCommandLine("node", ["server.js", "--token=abc123"])).toBe(
      "node server.js --token=REDACTED",
    );
  });

  it("keeps the binary and flag names, which are what identify the server", () => {
    const out = redactCommandLine("npx", [
      "@csa/server",
      "--tenant",
      "csa",
      "--secret",
      "s3cret",
    ]);
    expect(out).toBe("npx @csa/server --tenant csa --secret REDACTED");
  });

  it("redacts a recognisable credential passed as a bare argument", () => {
    const out = redactCommandLine("server", ["--mode", "AKIA" + "A".repeat(16)]);
    expect(out).toBe("server --mode REDACTED");
  });

  it("leaves a credential-free command line intact", () => {
    expect(redactCommandLine("node", ["fixtures/mock-server.mjs", "clean"])).toBe(
      "node fixtures/mock-server.mjs clean",
    );
  });
});

describe("redactSecretValues", () => {
  it("catches common token shapes anywhere in a string", () => {
    for (const secret of [
      "sk-live-abcdefghijklmn",
      "xoxb-1234567890-abcdef",
      "glpat-abcdefghij1234567890",
      "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4",
    ]) {
      expect(redactSecretValues(`prefix ${secret} suffix`)).not.toContain(secret);
    }
  });

  it("does not mangle ordinary text", () => {
    const text = "node fixtures/mock-server.mjs --tenant csa";
    expect(redactSecretValues(text)).toBe(text);
  });
});
