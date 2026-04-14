/**
 * URL-safe slug generation utilities.
 * Requirements: 3.1, 3.2
 */

/**
 * Converts an arbitrary org name to a URL-safe slug.
 * - Lowercases the input
 * - Replaces non-alphanumeric characters with hyphens
 * - Collapses multiple consecutive hyphens into one
 * - Strips leading and trailing hyphens
 */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    || 'org';
}

/**
 * Same as slugify but appends a short random alphanumeric suffix (4–6 chars).
 * Used to resolve Org_Slug collisions (Requirement 3.2).
 */
export function slugifyWithSuffix(name: string): string {
  const base = slugify(name);
  const suffix = randomAlphanumeric(5);
  return `${base}-${suffix}`;
}

function randomAlphanumeric(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  // Use crypto.getRandomValues if available (Node 19+), otherwise Math.random
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      result += chars[byte % chars.length];
    }
  } else {
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
  }
  return result;
}
