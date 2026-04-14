import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * API key hashing and verification utilities.
 *
 * Why SHA-256 instead of bcrypt/argon2?
 * API keys are 32-byte cryptographically random tokens (256 bits of entropy).
 * That entropy makes brute-force impossible regardless of hash speed, so the
 * slow KDF cost of bcrypt (~100ms) would dominate proxy hot-path latency on
 * every request. SHA-256 takes microseconds and is sufficient here.
 *
 * Requirement: 6.3
 */

/**
 * Returns the SHA-256 hex digest of a raw API key.
 * This is what gets stored in the database — never the raw key itself.
 */
export function hashApiKey(rawKey: string): string {
  return createHash('sha256').update(rawKey).digest('hex');
}

/**
 * Constant-time comparison of an incoming raw key against a stored hash.
 *
 * Uses `timingSafeEqual` to prevent timing attacks — a naive `===` comparison
 * leaks information about how many characters match via response time differences.
 */
export function verifyApiKey(rawKey: string, storedHash: string): boolean {
  const incomingHash = Buffer.from(hashApiKey(rawKey), 'hex');
  const stored = Buffer.from(storedHash, 'hex');

  // Lengths must match before timingSafeEqual (it throws on mismatched lengths)
  if (incomingHash.length !== stored.length) return false;

  return timingSafeEqual(incomingHash, stored);
}
