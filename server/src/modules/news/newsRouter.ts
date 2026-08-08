import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { searchNews, type MediaStackNewsOptions, type MediaStackSort } from './newsService.js';

/**
 * GET /news — public, MediaStack-backed news proxy.
 *
 * Unauthenticated (news is non-sensitive, and both the public landing page and
 * the authed dashboard need it), but rate-limited per IP and validated/served
 * server-side so the MediaStack key never reaches the browser. All validation +
 * caching happens in {@link searchNews}; this router is a thin pass-through.
 *
 * Query params (all optional):
 *   keyword, category, country, language, sources, date,
 *   limit (1–100, default 25), offset (≥0, default 0),
 *   sort (published_desc|published_asc|popularity|relevance)
 *
 * Always returns 200 with an array (possibly []) — the news UI must never break.
 *   curl 'http://localhost:3000/news?category=technology&limit=6'
 *   curl 'http://localhost:3000/news?keyword=artificial+intelligence&limit=5'
 *   curl 'http://localhost:3000/news?country=in&limit=5'
 */
const newsLimiter = rateLimit({
  windowMs: 60_000, // 1 minute
  max: 60, // generous — cache absorbs bursts for identical queries
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many news requests. Try again in a minute.' },
});

export const newsRouter = Router();

newsRouter.get('/', newsLimiter, async (req: Request, res: Response): Promise<void> => {
  const q = req.query as Record<string, unknown>;

  // Coerce qs output (string | string[] | object) to single strings/numbers.
  const strParam = (v: unknown): string | undefined => {
    if (Array.isArray(v)) return typeof v[0] === 'string' ? (v[0] as string) : undefined;
    return typeof v === 'string' ? v : undefined;
  };
  const numParam = (v: unknown): number | undefined => {
    const s = strParam(v);
    if (s === undefined) return undefined;
    const n = Number(s);
    return Number.isFinite(n) ? n : undefined;
  };

  const options: MediaStackNewsOptions = {
    keyword: strParam(q.keyword),
    category: strParam(q.category),
    country: strParam(q.country),
    language: strParam(q.language),
    sources: strParam(q.sources),
    date: strParam(q.date),
    sort: strParam(q.sort) as MediaStackSort | undefined,
    limit: numParam(q.limit),
    offset: numParam(q.offset),
  };

  const articles = await searchNews(options);
  res.json(articles);
});
