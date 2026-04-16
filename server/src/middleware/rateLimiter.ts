import rateLimit from 'express-rate-limit';

/**
 * Global management API limiter: 100 req / 15 min per IP
 * Applied to all API_Server management endpoints (Req 2.7, 10.4)
 */
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

/**
 * Health endpoint limiter: 60 req / min per IP
 * Applied to GET /health on both API_Server and Proxy_Engine (Req 17.4, 17.5)
 */
export const healthLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many health check requests.' },
});

// ---------------------------------------------------------------------------
// Per-org signing rate limiter (Req 10.5)
//
// 5 signing operations per minute per orgId.
// Implemented as an in-process sliding-window counter (Map<orgId, number[]>)
// to avoid an extra Redis round-trip on the proxy hot path.
// Each entry stores the timestamps (ms) of recent signing calls; entries older
// than the 60-second window are pruned on every check.
// ---------------------------------------------------------------------------

const SIGNING_WINDOW_MS = 60_000; // 1 minute
const SIGNING_MAX = 5;            // max signing ops per window per org

// orgId → array of call timestamps within the current window
const _signingWindows = new Map<string, number[]>();

/**
 * Returns true if the org is within its signing quota, false if the limit is exceeded.
 * Calling this function counts as consuming one signing operation slot.
 */
export function checkSigningRateLimit(orgId: string): boolean {
  const now = Date.now();
  const cutoff = now - SIGNING_WINDOW_MS;

  // Get or create the timestamp list for this org
  let timestamps = _signingWindows.get(orgId);
  if (!timestamps) {
    timestamps = [];
    _signingWindows.set(orgId, timestamps);
  }

  // Prune timestamps outside the sliding window
  const pruned = timestamps.filter((t) => t > cutoff);

  if (pruned.length >= SIGNING_MAX) {
    // Restore pruned list (don't record this rejected attempt)
    _signingWindows.set(orgId, pruned);
    return false;
  }

  // Record this attempt and allow it
  pruned.push(now);
  _signingWindows.set(orgId, pruned);
  return true;
}
