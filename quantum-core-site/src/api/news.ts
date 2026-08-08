import { env } from '../lib/env';

export interface NewsArticle {
  title: string;
  description: string | null;
  url: string;
  publishedAt: string;
  source: { name: string } | null;
  urlToImage: string | null;
}

interface NewsApiResponse {
  status: string;
  totalResults: number;
  articles: NewsArticle[];
  code?: string;
  message?: string;
}

/**
 * Fetch post-quantum / quantum-security news from NewsAPI.org (`/v2/everything`).
 *
 * Returns [] on any error (missing key, CORS block, rate limit) so callers
 * can fall back to curated static items — the news section never breaks.
 * ponytail: client-side fetch directly to NewsAPI.org. The free "Developer"
 * plan permits browser requests only from localhost, so production deploys
 * outside localhost will hit a 426 and fall back to static items. Route this
 * through the backend `/news` endpoint when production freshness matters.
 */
export async function fetchQuantumNews(): Promise<NewsArticle[]> {
  const key = env.newsApiKey;
  if (!key) return [];

  const url = `https://newsapi.org/v2/everything?q=${encodeURIComponent(
    'post-quantum cryptography OR quantum computing security'
  )}&language=en&sortBy=publishedAt&pageSize=6&apiKey=${key}`;

  try {
    const res = await fetch(url);
    if (!res.ok) return [];
    const data: NewsApiResponse = await res.json();
    if (!data || data.status !== 'ok') return [];
    return data.articles ?? [];
  } catch {
    // Network/CORS error — degrade silently to curated static items.
    return [];
  }
}
