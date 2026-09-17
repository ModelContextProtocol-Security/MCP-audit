# mcp-audit

> Security scanner and linter for Model Context Protocol (MCP) servers. Like `npm audit` and `eslint`, but for the tools you hand your AI agents.

[![CI](https://github.com/AgentPostmortem/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentPostmortem/mcp-audit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@royalpinto007/mcp-audit.svg)](https://www.npmjs.com/package/@royalpinto007/mcp-audit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)

**npm:** https://www.npmjs.com/package/@royalpinto007/mcp-audit

```bash
npm install -g @royalpinto007/mcp-audit
# or run it directly
npx @royalpinto007/mcp-audit stdio "node my-mcp-server.js"
```

## Why

MCP servers give language models real capabilities: run commands, read files, hit
internal URLs, mutate databases. A single over-scoped tool or a `.env` exposed as
a resource turns a helpful agent into a remote code execution or data-exfiltration
path. Yet most MCP servers ship with no security review at all.

`mcp-audit` connects to an MCP server (or lints its manifest), enumerates every
tool, resource, and prompt, and runs a catalog of security rules over that surface.
It finds the dangerous stuff before your agent does:

- arbitrary command / shell execution tools,
- destructive actions with no confirmation or scoping,
- prompt-injection sinks planted in tool descriptions,
- secrets and system paths exposed as resources,
- SSRF-prone URL arguments and unauthenticated HTTP transports,
- unconstrained input schemas that let the model pass anything, anywhere.

It runs offline, is fully deterministic, and drops straight into CI with JSON and
SARIF output for GitHub code scanning.

## Quickstart

```bash
# Audit a server you spawn over stdio
npx @royalpinto007/mcp-audit stdio "node my-mcp-server.js"

# Audit a remote server over HTTP (with a bearer token)
MCP_AUDIT_TOKEN="$MCP_TOKEN" npx @royalpinto007/mcp-audit http https://mcp.example.com/mcp

# Lint a server's declared surface from a manifest, without running it
npx @royalpinto007/mcp-audit static ./mcp-manifest.json

# List every built-in rule
npx @royalpinto007/mcp-audit rules
```

## Example output

```
mcp-audit — stdio target node my-mcp-server.js
server: insecure-demo-server v0.0.0-internal
surface: 5 tools, 2 resources, 1 prompts

 CRITICAL   (3)
  ✖ MCP002 Arbitrary execution tool detected  @ run_shell
      Tool "run_shell" appears to execute commands or code (matched "shell").
      fix: Avoid exposing raw exec. If unavoidable, allowlist commands, drop privileges, sandbox execution, and require human approval.
  ✖ MCP030 Resource surfaces sensitive material  @ file:///home/app/.env
      Resource "file:///home/app/.env" references ".env", which commonly holds secrets or system credentials.
      fix: Remove the resource or restrict it to non-sensitive content.

 HIGH  (4)
  ✖ MCP001 Destructive tool has no confirmation argument  @ delete_file
  ✖ MCP031 Unconstrained filesystem path argument  @ delete_file.path
  ...

20 findings   3 critical, 4 high, 5 medium, 6 low, 2 info
```

The process exits `1` when any finding reaches the `--fail-on` threshold (default
`high`), so a failing audit breaks the build.

## Rule catalog

19 built-in rules, each with a stable id, severity, and remediation. Toggle any of
them via config.

| Rule | Severity | Category | Description |
| ---- | -------- | -------- | ----------- |
| `MCP001` | high | permissions | Destructive tool lacks scoping or confirmation |
| `MCP002` | critical | permissions | Tool exposes arbitrary command execution |
| `MCP003` | medium | permissions | Mutating tool has an unscoped input surface |
| `MCP004` | high | permissions | Mutating tool advertises readOnlyHint |
| `MCP010` | medium | schema | Tool is missing an input schema |
| `MCP011` | low | schema | Schema allows unbounded additional properties |
| `MCP012` | low | schema | Unconstrained string argument |
| `MCP013` | info | schema | Object schema has no required properties |
| `MCP020` | high | injection | Description contains probable prompt-injection text |
| `MCP021` | medium | injection | Tool advertises overly broad capability |
| `MCP022` | medium | injection | Description directs cross-tool chaining |
| `MCP030` | critical | secrets | Resource exposes secrets or sensitive paths |
| `MCP031` | high | secrets | Path argument is vulnerable to traversal |
| `MCP040` | high | transport | HTTP transport has no authentication |
| `MCP041` | medium | transport | Tool accepts a caller-controlled URL (SSRF risk) |
| `MCP050` | medium | metadata | Server metadata leaks internal information |
| `MCP051` | info | metadata | Server does not report a version |
| `MCP060` | high | hygiene | Duplicate tool names |
| `MCP061` | low | hygiene | Excessive number of tools |
| `MCP062` | info | hygiene | Tool has no description |

## Configuration

Drop a `.mcpauditrc` (or `.mcpauditrc.json` / `mcpaudit.config.json`) in your repo.
mcp-audit discovers the nearest one walking up from the working directory.

```json
{
  "failOn": "high",
  "disabledRules": ["MCP013"],
  "severityOverrides": {
    "MCP011": "info"
  },
  "ignore": ["fetch_url.note"]
}
```

| Key | Meaning |
| --- | ------- |
| `failOn` | Findings at or above this severity cause a non-zero exit. Default `high`. |
| `disabledRules` | Rule ids to skip entirely. |
| `enabledRules` | If set, run **only** these rule ids. |
| `severityOverrides` | Remap a rule's severity, e.g. downgrade a noisy check. |
| `ignore` | Substrings matched against a finding's location or rule id to suppress it. |

Severities, lowest to highest: `info`, `low`, `medium`, `high`, `critical`.

### CLI flags

```
--json                 Emit JSON instead of terminal output
--sarif                Emit SARIF 2.1.0 (for GitHub code scanning)
--output <file>        Write the report to a file instead of stdout
--config <file>        Use a specific config file
--fail-on <severity>   Exit non-zero at/above this severity
--disable <ids>        Comma-separated rule ids to disable
--only <ids>           Comma-separated rule ids to run exclusively
--token <token>        Bearer token for http transport (visible to ps)
--token-file <file>    Read the bearer token from a file (preferred)
--header <k:v>         Extra header for http transport (repeatable)
--sse                  Use the legacy SSE transport for http
--timeout <ms>         Deadline for the whole probe (default: 60000)
--max-pages <n>        Max pages followed per capability (default: 100)
--max-items <n>        Max items collected per capability (default: 10000)
--allow-truncated      Audit a partial surface instead of failing on a bound

# environment
MCP_AUDIT_TOKEN        Bearer token for http transport, if no flag is given
--no-color             Disable colored output
```

## SARIF and CI usage

`mcp-audit` emits [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) so findings
show up as annotations in GitHub code scanning.

```yaml
- run: npx @royalpinto007/mcp-audit static ./mcp-manifest.json --sarif --output mcp-audit.sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0` | No findings at or above `--fail-on`. |
| `1` | Findings at or above `--fail-on`. |
| `2` | Usage or runtime error. |

## Static mode

Static mode lints a server's declared surface from a JSON manifest without ever
executing it, which is ideal for scanning untrusted servers in code review. A
manifest is just the tools/resources/prompts the server would advertise:

```json
{
  "transport": "http",
  "url": "https://mcp.example.com/mcp",
  "authProvided": false,
  "server": { "name": "billing-mcp", "version": "1.0.0" },
  "tools": [
    {
      "name": "charge_card",
      "description": "Charge a saved payment method.",
      "inputSchema": {
        "type": "object",
        "properties": { "amount": { "type": "number" } },
        "required": ["amount"],
        "additionalProperties": false
      }
    }
  ]
}
```

A bare JSON array of tools is also accepted.

## Programmatic API

```ts
import { connectStdio, runAudit, DEFAULT_CONFIG, renderJson } from "mcp-audit";

const target = await connectStdio({ command: "node", args: ["server.js"] });
const result = runAudit(target, DEFAULT_CONFIG);
console.log(renderJson(result));
```

## Development

```bash
npm install
npm run build      # compile TypeScript to dist/
npm test           # run the vitest suite (includes a live mock server)
npm run typecheck  # type-only check
```

The repo ships a real mock MCP server (`fixtures/mock-server.mjs`) so the test
suite is hermetic and reproducible.

## Contributing

Contributions are welcome. A good new rule is: independently coded, has a stable
`MCPxxx` id, a clear severity and remediation, and a test that fires it against a
fixture (plus one that proves it stays quiet on a clean surface). Add the rule
module under `src/rules/`, register it in `src/rules/index.ts`, and cover it in
`test/rules.test.ts`.

## License

[MIT](./LICENSE) © royalpinto007
