import { describe, it, expect, vi } from "vitest";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

const { listToolsMock, connectMock } = vi.hoisted(() => ({
  listToolsMock: vi.fn(),
  connectMock: vi.fn(async () => {}),
}));

vi.mock("@modelcontextprotocol/sdk/client/index.js", () => {
  class Client {
    async connect(transport: Transport) {
      return connectMock(transport);
    }
    getServerVersion() {
      return { name: "bounded-server", version: "1.0.0" };
    }
    getInstructions() {
      return undefined;
    }
    async listTools(params?: { cursor?: string }) {
      return listToolsMock(params);
    }
    async listResources() {
      return { resources: [] };
    }
    async listPrompts() {
      return { prompts: [] };
    }
    async close() {}
  }
  return { Client };
});

import { probe } from "../src/transport/probe.js";
import { DEFAULT_LIMITS, ProbeLimitError } from "../src/transport/limits.js";

const meta = { kind: "stdio" as const, source: "test://bounded" };
const tool = (name: string) => ({
  name,
  description: "x",
  inputSchema: { type: "object" as const },
});

describe("probe bounds", () => {
  it("stops on a repeated cursor rather than following it forever", async () => {
    // The shape a hostile server and an off-by-one cursor bug share.
    listToolsMock.mockImplementation(() => ({
      tools: [tool("t")],
      nextCursor: "never-changes",
    }));

    await expect(probe({} as Transport, meta)).rejects.toThrow(ProbeLimitError);
    await expect(probe({} as Transport, meta)).rejects.toThrow(
      /repeated the pagination cursor/,
    );
    // Caught on the second page, not at the page cap.
    expect(listToolsMock.mock.calls.length).toBeLessThanOrEqual(4);
  });

  it("fails closed at the page cap when every cursor is distinct", async () => {
    let n = 0;
    listToolsMock.mockImplementation(() => ({
      tools: [tool(`t${n}`)],
      nextCursor: `cursor-${n++}`,
    }));

    await expect(
      probe({} as Transport, meta, { ...DEFAULT_LIMITS, maxPages: 5 }),
    ).rejects.toThrow(/more than 5 pages/);
  });

  it("fails closed at the item cap", async () => {
    let n = 0;
    listToolsMock.mockImplementation(() => ({
      tools: [tool(`a${n}`), tool(`b${n}`)],
      nextCursor: `cursor-${n++}`,
    }));

    await expect(
      probe({} as Transport, meta, { ...DEFAULT_LIMITS, maxItems: 4 }),
    ).rejects.toThrow(/more than 4 tools/);
  });

  it("returns a partial surface, marked, when truncation is allowed", async () => {
    let n = 0;
    listToolsMock.mockImplementation(() => ({
      tools: [tool(`t${n}`)],
      nextCursor: `cursor-${n++}`,
    }));

    const target = await probe({} as Transport, meta, {
      ...DEFAULT_LIMITS,
      maxPages: 3,
      allowTruncated: true,
    });

    expect(target.tools).toHaveLength(3);
    // The caller must be able to tell this is not the whole server.
    expect(target.truncated).toEqual(["tools (page cap)"]);
  });

  it("leaves truncated unset on a complete enumeration", async () => {
    listToolsMock.mockImplementation(() => ({ tools: [tool("only")] }));
    const target = await probe({} as Transport, meta);
    expect(target.truncated).toBeUndefined();
  });

  it("gives up on a handshake that never completes", async () => {
    connectMock.mockImplementationOnce(() => new Promise<void>(() => {}));
    listToolsMock.mockImplementation(() => ({ tools: [] }));

    await expect(
      probe({} as Transport, meta, { ...DEFAULT_LIMITS, timeoutMs: 50 }),
    ).rejects.toThrow(/connect exceeded the 50ms deadline/);
  });

  it("gives up on a list call that never returns", async () => {
    listToolsMock.mockImplementation(() => new Promise(() => {}));
    await expect(
      probe({} as Transport, meta, { ...DEFAULT_LIMITS, timeoutMs: 50 }),
    ).rejects.toThrow(/listing tools exceeded/);
  });
});
