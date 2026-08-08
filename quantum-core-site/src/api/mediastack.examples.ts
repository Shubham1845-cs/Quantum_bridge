/**
 * Example usage for the MediaStack news service (see `mediastack.ts`).
 *
 * This module is side-effect-free: importing it does NOT fire any requests.
 * Call `runMediaStackExamples()` from a dev console / component to exercise
 * each query, or copy the individual calls into a page. In a real page, prefer
 * wiring the relevant function into a `useEffect` + state — mirror
 * `src/components/landing/NewsSection.tsx` which does exactly that for the
 * NewsAPI module.
 */
import {
  getTopHeadlines,
  getNewsByCategory,
  getNewsByKeyword,
  getNewsByCountry,
  searchNews,
  type MediaStackArticle,
} from './mediastack';

function preview(a: MediaStackArticle): string {
  return `  • [${a.category}] ${a.title} — ${a.source || 'unknown'} (${a.country})`;
}

/** Run all six example queries and log results to the console. */
export async function runMediaStackExamples(): Promise<void> {
  // 1. Latest News — no filters, newest-first.
  console.log('Latest News:');
  for (const a of await getTopHeadlines(5)) console.log(preview(a));

  // 2. Technology News — category = technology.
  console.log('Technology News:');
  for (const a of await getNewsByCategory('technology', 5)) console.log(preview(a));

  // 3. Business News — category = business.
  console.log('Business News:');
  for (const a of await getNewsByCategory('business', 5)) console.log(preview(a));

  // 4. AI News — free-text keyword search.
  console.log('AI News:');
  for (const a of await getNewsByKeyword('artificial intelligence', 5)) console.log(preview(a));

  // 5. India News — country = in (ISO-3166-1 alpha-2).
  console.log('India News:');
  for (const a of await getNewsByCountry('in', 5)) console.log(preview(a));

  // 6. Sports News — also demonstrates the flexible searchNews() entry point,
  //    combining a category filter with popularity sorting.
  console.log('Sports News:');
  for (const a of await searchNews({ category: 'sports', limit: 5, sort: 'popularity' }))
    console.log(preview(a));
}
