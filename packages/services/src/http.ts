/**
 * Shared HTTP-layer helpers for the trust services.
 *
 * The rate limiter's side-channel rule: the key (which may be an IP) lives
 * only in an in-memory Map for one window and is never written to disk or a
 * log. Both issuer and verifier must hold this line, which is why the limiter
 * lives here and not per-service.
 */

// ---------- hex ----------

export function fromHex(hex: string): Uint8Array {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("not hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---------- rate limiting ----------

export interface RateLimit {
  limit: number;
  windowMs: number;
}

/**
 * Minimal in-memory fixed-window limiter. Keyed by caller so a flood from one
 * source can't drain service for everyone. The key is held one window and
 * never persisted or logged.
 */
export function rateLimiter(opts: RateLimit) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return async (c: import("hono").Context, next: () => Promise<void>) => {
    const key = c.req.header("x-forwarded-for") ?? "anon";
    const now = Date.now();
    const rec = hits.get(key);
    if (!rec || now >= rec.resetAt) {
      hits.set(key, { count: 1, resetAt: now + opts.windowMs });
    } else {
      rec.count += 1;
      if (rec.count > opts.limit) return c.json({ error: "rate-limited" }, 429);
    }
    await next();
  };
}
