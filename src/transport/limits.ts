/**
 * Bounds on what a probe will do before giving up.
 *
 * `mcp-audit` connects to servers it does not control and, by design, believes
 * what they tell it. Without bounds, a server that never stops paginating or
 * never answers the handshake holds the process forever — which a buggy cursor
 * reaches just as easily as a hostile one.
 */
export interface ProbeLimits {
  /** Wall-clock deadline for the whole probe, in milliseconds. */
  timeoutMs: number;
  /** Maximum pages followed per capability. */
  maxPages: number;
  /** Maximum items collected per capability. */
  maxItems: number;
  /**
   * When false (the default), hitting a bound is an error rather than a
   * truncated result. An audit of part of a surface that reads as an audit of
   * the surface is the false-confidence failure this tool exists to prevent,
   * so the bound fails closed and the operator opts out explicitly.
   */
  allowTruncated: boolean;
}

export const DEFAULT_LIMITS: ProbeLimits = {
  timeoutMs: 60_000,
  maxPages: 100,
  maxItems: 10_000,
  allowTruncated: false,
};

/** Raised when a probe hits one of its bounds. */
export class ProbeLimitError extends Error {
  constructor(
    message: string,
    readonly limit: "timeout" | "pages" | "items" | "stalled-cursor",
  ) {
    super(message);
    this.name = "ProbeLimitError";
  }
}

/**
 * Reject if `promise` has not settled within `timeoutMs`. The underlying work
 * is not cancellable — the caller closes the transport in its own `finally` —
 * so this bounds how long we *wait*, not how long the server takes.
 */
export async function withDeadline<T>(
  promise: Promise<T>,
  timeoutMs: number,
  what: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new ProbeLimitError(
            `${what} exceeded the ${timeoutMs}ms deadline. Raise --timeout if the server is legitimately slow.`,
            "timeout",
          ),
        ),
      timeoutMs,
    );
    timer.unref?.();
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
