import { createHash } from 'crypto';
import { redis } from '../../config/redis.js';
import { env } from '../../config/env.js';
import logger from '../../utils/logger.js';

/**
 * MediaStack Live News service (server-side /news proxy + cache).
 *
 * Docs:      https://mediastack.com/documentation
 * Endpoint:  https://api.mediastack.com/v1/news
 *
 * Why this lives on the backend: the MediaStack access_key must never ship to
 * the browser (every `VITE_` var is public in the bundle, and the free plan
 * blocks cross-origin browser calls). Here the key stays in `server/.env`
 * (validated by zod in config/env.ts), requests are validated at this trust
 * boundary, and results are cached in the shared Redis instance so the whole
 * fleet of users shares one upstream call per query per TTL window.
 *
 * Contract: `searchNews` NEVER throws. Any failure (no key, network, timeout,
 * upstream error, bad input) returns `[]` so the public `/news` route can
 * always answer `res.json([])` and the dashboard never crashes.
 */

const MEDIASTACK_ENDPOINT = 'https://api.mediastack.com/v1/news';
const DEFAULT_TIMEOUT_MS = 10_000; // AbortController deadline for the upstream call
const MIN_LIMIT = 1;
const MAX_LIMIT = 100; // MediaStack caps page size at 100 on the free plan
const DEFAULT_LIMIT = 25;
const CACHE_TTL_SECONDS = 300; // 5 min — trades news freshness for upstream quota + latency
const CACHE_PREFIX = 'news:mediastack:';

export type MediaStackCategory =
  | 'general'
  | 'business'
  | 'entertainment'
  | 'health'
  | 'science'
  | 'sports'
  | 'technology';

export type MediaStackSort =
  | 'published_desc'
  | 'published_asc'
  | 'popularity'
  | 'relevance';

/** A single MediaStack article (their `data[]` element). */
export interface MediaStackArticle {
  author: string | null;
  title: string;
  description: string | null;
  url: string;
  source: string;
  image: string | null;
  category: string;
  language: string;
  country: string;
  published_at: string;
}

export interface MediaStackNewsOptions {
  keyword?: string;
  category?: string; // comma-separated list allowed
  country?: string; // comma-separated ISO-3166-1 alpha-2 list allowed
  language?: string; // comma-separated ISO-639-1 alpha-2 list allowed
  limit?: number;
  offset?: number;
  sort?: MediaStackSort;
  date?: string; // YYYY-MM-DD, or YYYY-MM-DD,YYYY-MM-DD range
  sources?: string; // comma-separated source ids
}

/** Upstream envelope — MediaStack answers 200 with `error` on bad key/quota. */
interface MediaStackResponse {
  data?: MediaStackArticle[];
  error?: { code: number | string; message?: string; type?: string };
}

const ALLOWED_CATEGORIES: ReadonlySet<MediaStackCategory> = new Set<MediaStackCategory>([
  'general', 'business', 'entertainment', 'health', 'science', 'sports', 'technology',
]);

const ALLOWED_SORTS: ReadonlySet<MediaStackSort> = new Set<MediaStackSort>([
  'published_desc', 'published_asc', 'popularity', 'relevance',
]);

/** YYYY-MM-DD or YYYY-MM-DD,YYYY-MM-DD range. */
const DATE_RE = /^\d{4}-\d{2}-\d{2}(?:,\d{4}-\d{2}-\d{2})?$/;

// --- validation helpers (authoritative — this is the trust boundary) --------

/** Lowercase-comma-join only tokens passing `pred`; drop invalid/empty. */
function validateCsv(
  input: string | undefined,
  pred: (token: string) => boolean,
  lower = true,
): string {
  if (!input) return '';
  const kept = input
    .split(',')
    .map((t) => (lower ? t.trim().toLowerCase() : t.trim()))
    .filter(Boolean)
    .filter(pred);
  return kept.join(',');
}

function cleanKeyword(keyword: string | undefined): string {
  if (!keyword) return '';
  const trimmed = keyword.trim();
  return trimmed ? trimmed.slice(0, 512) : '';
}

function clampInt(
  value: number | undefined,
  min: number,
  max: number,
  fallback: number,
): number {
  if (value === undefined) return fallback;
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

/**
 * Build + validate the MediaStack querystring. Invalid user inputs are dropped
 * (never forwarded upstream) so a malformed client can never trigger a weird
 * MediaStack response. `access_key` is pulled from env, never an argument.
 */
function buildQueryParams(options: MediaStackNewsOptions): URLSearchParams {
  const params = new URLSearchParams();
  params.set('access_key', env.MEDIASTACK_API_KEY);

  // Singular, human-friendly options → MediaStack's plural query params.
  const keyword = cleanKeyword(options.keyword);
  const category = validateCsv(options.category, (c) =>
    ALLOWED_CATEGORIES.has(c as MediaStackCategory),
  );
  const country = validateCsv(options.country, (c) => /^[a-z]{2}$/.test(c));
  const language = validateCsv(options.language, (c) => /^[a-z]{2}$/.test(c));
  const sources = validateCsv(options.sources, (s) => /^[\w.-]+$/.test(s), false);
  const sort = options.sort && ALLOWED_SORTS.has(options.sort) ? options.sort : '';
  const date = options.date && DATE_RE.test(options.date.trim()) ? options.date.trim() : '';

  if (keyword) params.set('keywords', keyword);
  if (category) params.set('categories', category);
  if (country) params.set('countries', country);
  if (language) params.set('languages', language);
  if (sources) params.set('sources', sources);
  if (sort) params.set('sort', sort);
  if (date) params.set('date', date);
  params.set('limit', String(clampInt(options.limit, MIN_LIMIT, MAX_LIMIT, DEFAULT_LIMIT)));
  params.set('offset', String(clampInt(options.offset, 0, Number.MAX_SAFE_INTEGER, 0)));

  return params;
}

/** Stable cache key = hash of the validated querystring (excluding access_key). */
function cacheKey(options: MediaStackNewsOptions): string {
  const qs = buildQueryParams(options).toString();
  const h = createHash('sha1').update(qs).digest('hex').slice(0, 24);
  return `${CACHE_PREFIX}${h}`;
}

// --- Redis cache (best-effort: never blocks or breaks the request) ---------

async function cacheGet(key: string): Promise<MediaStackArticle[] | null> {
  try {
    const raw = await redis.get(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as MediaStackArticle[]) : null;
  } catch {
    return null; // Redis down / corrupt JSON → treat as miss
  }
}

/** Fire-and-forget write; a cache write failure must never break the request. */
function cacheSet(key: string, articles: MediaStackArticle[]): void {
  redis.set(key, JSON.stringify(articles), 'EX', CACHE_TTL_SECONDS).catch(() => {
    /* ignore — caching is best-effort */
  });
}

/**
 * Fetch + validate + cache. Never throws.
 *
 * Flow:
 *   1. No key configured → return [].
 *   2. Cache hit → return cached array.
 *   3. Upstream fetch (AbortController timeout). Non-2xx or network error → [].
 *   4. 200-with-`error` (bad key/quota) → [] (logged). Successful data cached.
 *   5. Empty-but-valid data → [] (cached, so repeated misses don't hammer upstream).
 */
export async function searchNews(
  options: MediaStackNewsOptions = {},
): Promise<MediaStackArticle[]> {
  if (!env.MEDIASTACK_API_KEY) {
    logger.warn('[news] MEDIASTACK_API_KEY is not set; /news returning []');
    return [];
  }

  const key = cacheKey(options);
  const cached = await cacheGet(key);
  if (cached) return cached;

  const url = `${MEDIASTACK_ENDPOINT}?${buildQueryParams(options).toString()}`;

  // Timeout via AbortController so a hung upstream never wedges the request.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      logger.warn(`[news] MediaStack HTTP ${res.status}`);
      return [];
    }

    const payload = (await res.json()) as MediaStackResponse;
    if (payload.error) {
      logger.warn(
        `[news] MediaStack error (${payload.error.code}): ${payload.error.message ?? 'unknown'}`,
      );
      return [];
    }

    const articles = Array.isArray(payload.data) ? payload.data : [];
    cacheSet(key, articles); // cache hits/misses alike for the TTL window
    return articles;
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      logger.warn(`[news] MediaStack request timed out after ${DEFAULT_TIMEOUT_MS}ms`);
    } else {
      const msg = err instanceof Error ? err.message : 'unknown error';
      logger.warn(`[news] MediaStack request failed: ${msg}`);
    }
    return [];
  } finally {
    clearTimeout(timer);
  }
}
