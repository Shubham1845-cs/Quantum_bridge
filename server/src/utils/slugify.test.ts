import { describe, it, expect } from 'vitest';
import { slugify, slugifyWithSuffix } from './slugify';

describe('slugify', () => {
  it('lowercases the input', () => {
    expect(slugify('ACME')).toBe('acme');
  });

  it('replaces spaces with hyphens', () => {
    expect(slugify('Acme Corp')).toBe('acme-corp');
  });

  it('replaces special characters with hyphens', () => {
    expect(slugify('Acme & Co.')).toBe('acme-co');
  });

  it('collapses multiple hyphens', () => {
    expect(slugify('Acme   Corp!!!')).toBe('acme-corp');
  });

  it('strips leading and trailing hyphens', () => {
    expect(slugify('---acme---')).toBe('acme');
  });

  it('handles unicode / accented characters', () => {
    const result = slugify('Ångström Labs');
    expect(result).toMatch(/^[a-z0-9-]+$/);
    expect(result).not.toMatch(/^-|-$/);
  });

  it('returns "org" for an empty or symbol-only string', () => {
    expect(slugify('')).toBe('org');
    expect(slugify('!!!')).toBe('org');
  });

  it('preserves alphanumeric characters', () => {
    expect(slugify('abc123')).toBe('abc123');
  });
});

describe('slugifyWithSuffix', () => {
  it('starts with the slugified base', () => {
    const result = slugifyWithSuffix('Acme Corp');
    expect(result.startsWith('acme-corp-')).toBe(true);
  });

  it('appends a 5-char alphanumeric suffix', () => {
    const result = slugifyWithSuffix('Acme Corp');
    const parts = result.split('-');
    const suffix = parts[parts.length - 1];
    expect(suffix).toMatch(/^[a-z0-9]{5}$/);
  });

  it('produces a URL-safe result', () => {
    const result = slugifyWithSuffix('My Org & Partners!');
    expect(result).toMatch(/^[a-z0-9-]+$/);
  });

  it('produces different suffixes on repeated calls', () => {
    const results = new Set(Array.from({ length: 20 }, () => slugifyWithSuffix('test')));
    // With 36^5 = ~60M possibilities, 20 calls should almost certainly yield > 1 unique value
    expect(results.size).toBeGreaterThan(1);
  });
});
