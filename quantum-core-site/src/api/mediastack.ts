import apiClient from './client';

/**
 * MediaStack Live News — frontend client.
 *
 * Talks to the backend `/api/news` route (see `server/src/modules/news/`),
 * NOT MediaStack directly. vite dev-proxies `/api/*` → `:3000` (strips `/api`),
 * so `apiClient.get('/news')` reaches the backend `GET /news` handler. The
 * backend keeps the MediaStack access_key server-side, validates inputs at the
 * trust boundary, caches results in Redis, and shields the browser from CORS /
 * mixed-content / key-leak issues the direct-call version would hit in prod.
 *
 * Contract: every function NEVER throws — on any error they return `[]`,
 * matching the sibling `news.ts` (NewsAPI) module so the news UI never breaks.
 * Authoritative validation lives server-side; here we only normalize input
 * (trim strings, clamp numeric limits) before sending.
 */

const MIN_LIMIT = 1;
const MAX_LIMIT = 100; // MediaStack page cap on the free plan
const DEFAULT_LIMIT = 25;

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

/**
 * Flexible search options. Singular, human-friendly names — the backend maps
 * them to MediaStack's plural query params (`category`→`categories`, etc.).
 * All fields optional.
 */
export interface MediaStackNewsOptions {
  keyword?: string;
  category?: string; // comma-separated list allowed
  country?: string; // comma-separated ISO-3166-1 alpha-2 list allowed
  language?: string; // comma-separated ISO-639-1 alpha-2 list allowed
  limit?: number;
  offset?: number;
  sort?: MediaStackSort;
  date?: string; // YYYY-MM-DD or YYYY-MM-DD,YYYY-MM-DD
  sources?: string; // comma-separated source ids
}

/** Trim + drop empty; caps length to avoid abusing the upstream on free-text. */
function cleanKeyword(keyword: string | undefined): string | undefined {
  if (keyword === undefined) return undefined;
  const trimmed = keyword.trim();
  return trimmed ? trimmed.slice(0, 512) : undefined;
}

/** Coerce to a finite int clamped to [min, max], falling back when invalid. */
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

function strOrUndef(v: string | undefined): string | undefined {
  if (v === undefined) return undefined;
  const trimmed = v.trim();
  return trimmed ? trimmed : undefined;
}

/**
 * Core primitive every public helper delegates to. Sends normalized query
 * params to `/news` and unwraps the article array. On any HTTP/network error,
 * degrade to `[]` (the backend also returns `[]` on its own failures).
 */
async function fetchNews(options: MediaStackNewsOptions = {}): Promise<MediaStackArticle[]> {
  // Build only non-empty params so the querystring stays clean.
  const params: Record<string, string> = {
    limit: String(clampInt(options.limit, MIN_LIMIT, MAX_LIMIT, DEFAULT_LIMIT)),
    offset: String(clampInt(options.offset, 0, Number.MAX_SAFE_INTEGER, 0)),
  };
  const keyword = cleanKeyword(options.keyword);
  if (keyword) params.keyword = keyword;
  const category = strOrUndef(options.category);
  if (category) params.category = category;
  const country = strOrUndef(options.country);
  if (country) params.country = country;
  const language = strOrUndef(options.language);
  if (language) params.language = language;
  const sources = strOrUndef(options.sources);
  if (sources) params.sources = sources;
  const date = strOrUndef(options.date);
  if (date) params.date = date;
  if (options.sort) params.sort = options.sort;

  try {
    const { data } = await apiClient.get<MediaStackArticle[]>('/news', { params });
    return Array.isArray(data) ? data : [];
  } catch {
    // backend down / network error / non-2xx → degrade silently to [].
    return [];
  }
}

/**
 * Latest news — MediaStack returns newest-first by default, the closest
 * equivalent to "top headlines".
 */
export function getTopHeadlines(limit = DEFAULT_LIMIT): Promise<MediaStackArticle[]> {
  return fetchNews({ limit });
}

/** News filtered to one or more categories (e.g. "technology", "business,sports"). */
export function getNewsByCategory(
  category: string,
  limit = DEFAULT_LIMIT,
): Promise<MediaStackArticle[]> {
  const c = strOrUndef(category);
  if (!c) return Promise.resolve([]);
  return fetchNews({ category: c, limit });
}

/** News matching a free-text keyword (MediaStack supports a leading "-" to exclude). */
export function getNewsByKeyword(
  keyword: string,
  limit = DEFAULT_LIMIT,
): Promise<MediaStackArticle[]> {
  const kw = cleanKeyword(keyword);
  if (!kw) return Promise.resolve([]);
  return fetchNews({ keyword: kw, limit });
}

/** News from one or more ISO-3166-1 alpha-2 country codes (e.g. "in", "us,gb"). */
export function getNewsByCountry(
  country: string,
  limit = DEFAULT_LIMIT,
): Promise<MediaStackArticle[]> {
  const c = strOrUndef(country);
  if (!c) return Promise.resolve([]);
  return fetchNews({ country: c, limit });
}

/** Flexible search across every MediaStack filter; all options are optional. */
export function searchNews(
  options: MediaStackNewsOptions = {},
): Promise<MediaStackArticle[]> {
  return fetchNews(options);
}
