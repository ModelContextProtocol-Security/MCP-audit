/**
 * Redaction of target identity.
 *
 * `mcp-audit` records what it audited so a reader can tell which server a
 * report is about. That identity is a URL or a command line, and both are
 * ordinary places to keep a credential: MCP servers are routinely configured
 * with a secret in `argv`, and hosted ones with one in a query string.
 *
 * The identity then travels into JSON and into SARIF — a format whose purpose
 * is upload to code scanning. So redaction happens here, at the point the
 * identity is captured, rather than at each reporter: the plaintext never
 * enters `AuditTarget`, and there is one place to audit rather than three.
 *
 * This is deliberately lossy. A redacted identity is still unique enough to
 * tell two servers apart, which is all a report needs it for.
 */

// ASCII and URL-safe: a marker that survives URL.toString() without
// percent-encoding into noise, and reads the same in a command line.
const REDACTED = "REDACTED";

/** Query/header/flag names whose value is a credential by convention. */
const SECRET_NAMES = [
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "api_key",
  "apikey",
  "key",
  "secret",
  "client_secret",
  "password",
  "passwd",
  "pwd",
  "auth",
  "authorization",
  "signature",
  "sig",
  "credential",
  "session",
  "x-amz-signature",
  "x-amz-credential",
  "x-amz-security-token",
];

/** Values that are recognisably credentials whatever they are called. */
const SECRET_VALUES: RegExp[] = [
  /\bsk-[a-zA-Z0-9_-]{10,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bASIA[0-9A-Z]{16}\b/g,
  /\bxox[baprs]-[0-9a-zA-Z-]{10,}/g,
  /\bghp_[0-9a-zA-Z]{36}\b/g,
  /\bgho_[0-9a-zA-Z]{36}\b/g,
  /\bghs_[0-9a-zA-Z]{36}\b/g,
  /\bgithub_pat_[0-9a-zA-Z_]{20,}/g,
  /\bglpat-[0-9a-zA-Z_-]{20,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
];

function isSecretName(name: string): boolean {
  const n = name.toLowerCase();
  return SECRET_NAMES.some((s) => n === s || n.endsWith(`_${s}`) || n.endsWith(`-${s}`));
}

/** Replace any recognisable credential value anywhere in a string. */
export function redactSecretValues(text: string): string {
  let out = text;
  for (const p of SECRET_VALUES) out = out.replace(p, REDACTED);
  return out;
}

/**
 * Strip credentials from a URL: userinfo, secret-named query parameters, and
 * any recognisable secret value in what remains. An unparseable URL is treated
 * as opaque text rather than trusted.
 */
export function redactUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return redactSecretValues(raw);
  }

  if (url.username || url.password) {
    url.username = url.username ? REDACTED : "";
    url.password = url.password ? REDACTED : "";
  }
  for (const [name] of [...url.searchParams]) {
    if (isSecretName(name)) url.searchParams.set(name, REDACTED);
  }
  // A fragment can carry a token too and is never needed to identify a server.
  url.hash = "";
  return redactSecretValues(url.toString());
}

/**
 * Render a spawn as an identity without its secrets. The binary and the flag
 * *names* survive, because they are what distinguishes one server from another;
 * a value that follows a secret-named flag, or that looks like a credential on
 * its own, does not.
 */
export function redactCommandLine(command: string, args: string[]): string {
  const out: string[] = [command];
  let redactNext = false;

  for (const arg of args) {
    if (redactNext) {
      out.push(REDACTED);
      redactNext = false;
      continue;
    }
    const inline = /^(--?[A-Za-z0-9][\w.-]*)=(.*)$/s.exec(arg);
    if (inline) {
      const [, flag, value] = inline;
      out.push(isSecretName(flag.replace(/^-+/, "")) ? `${flag}=${REDACTED}` : `${flag}=${redactSecretValues(value)}`);
      continue;
    }
    if (/^--?[A-Za-z0-9][\w.-]*$/.test(arg) && isSecretName(arg.replace(/^-+/, ""))) {
      out.push(arg);
      redactNext = true;
      continue;
    }
    out.push(redactSecretValues(arg));
  }
  return out.join(" ");
}
