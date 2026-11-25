/**
 * Wikipedia / Wikimedia Access & Cleanup Bridge (`hub/src/wikipedia.ts`) — delegates URL parsing, namespace guards,
 * robots suggestions, and linear MediaWiki Markdown cleanup to Go `internal/extract/wikipedia.go` via `edgefetch-core.wasm`,
 * while keeping per-isolate caller quota & sitemap LRU caches at the Cloudflare Worker edge.
 */

import { callCoreWasm } from './wasm-bridge';

export const DEFAULT_WIKIPEDIA_MAX_AGE_MS = 24 * 60 * 60_000;
export const DEFAULT_WIKIPEDIA_HOURLY_ARTICLE_LIMIT = 200;

const WIKIPEDIA_QUOTA_WINDOW_MS = 60 * 60_000;
const MAX_WIKIPEDIA_QUOTA_BUCKETS = 4_096;
const MAX_WIKIPEDIA_SITEMAP_CACHE_ENTRIES = 64;
const WIKIPEDIA_SITEMAP_CACHE_TTL_MS = 24 * 60 * 60_000;

export const WIKIPEDIA_BULK_CHANNELS = Object.freeze({
  wikimediaEnterprise: 'https://enterprise.wikimedia.com/',
  dumps: 'https://dumps.wikimedia.org/',
  huggingFaceDataset: 'https://huggingface.co/datasets/wikimedia/wikipedia',
});

export interface ParsedWikipediaArticle {
  canonicalUrl: string;
  host: string;
  lang: string;
  title: string;
  encodedTitle: string;
  sectionAnchor?: string;
  canonicalTitle?: string;
  underscoredTitle?: string;
}

export function isWikipediaHost(rawHost: string): boolean {
  return callCoreWasm<{ isWikipedia: boolean }>('wiki_host_info', { host: String(rawHost ?? '') }).isWikipedia;
}

export function isWikimediaHost(rawHost: string): boolean {
  return callCoreWasm<{ isWikimedia: boolean }>('wiki_host_info', { host: String(rawHost ?? '') }).isWikimedia;
}

export function extractWikipediaLangFromHost(rawHost: string): string | null {
  const lang = callCoreWasm<{ lang: string }>('wiki_host_info', { host: String(rawHost ?? '') }).lang;
  return lang || null;
}

export function normalizeWikipediaLang(rawLang: unknown, fallback = 'en'): string {
  const s = typeof rawLang === 'string' ? rawLang.trim().toLowerCase() : '';
  if (/^[a-z]{2,12}(?:-[a-z0-9]{1,12}){0,2}$/.test(s)) {
    const isWiki = isWikipediaHost(`${s}.wikipedia.org`);
    if (isWiki) return s;
  }
  return fallback.trim().toLowerCase() || 'en';
}

export function isDisallowedWikipediaTitle(decodedTitle: string): boolean {
  return callCoreWasm<{ disallowed: boolean }>('wiki_is_disallowed_title', {
    title: String(decodedTitle ?? ''),
  }).disallowed;
}

export function parseWikipediaArticleUrl(rawUrl: string): ParsedWikipediaArticle | null {
  return callCoreWasm<{ article: ParsedWikipediaArticle | null }>('wiki_parse_url', {
    url: String(rawUrl ?? ''),
  }).article;
}

export function resolveWikipediaCanonicalFinalUrl(params: {
  requestedUrl: string;
  storedFinalUrl?: string;
  responseFinalUrl?: string;
  title?: string;
  markdown?: string;
}): string {
  const url = callCoreWasm<{ url: string }>('wiki_canonical_final', {
    requestedUrl: params.requestedUrl,
    storedFinalUrl: params.storedFinalUrl ?? params.responseFinalUrl ?? '',
    title: params.title ?? '',
    markdown: params.markdown ?? '',
  }).url;
  return url || params.storedFinalUrl || params.responseFinalUrl || params.requestedUrl;
}

export function buildWikipediaDirectTitleGuessUrl(rawQuery: string, lang = 'en'): string | null {
  const url = callCoreWasm<{ url: string }>('wiki_title_guess', {
    query: String(rawQuery ?? ''),
    lang: normalizeWikipediaLang(lang, 'en'),
  }).url;
  return url || null;
}

export function buildWikimediaRobotsSuggestion(rawHost: string): string {
  return callCoreWasm<{ suggestion: string }>('wiki_robots_suggestion', {
    host: String(rawHost ?? ''),
  }).suggestion;
}

interface WikipediaQuotaBucketEntry {
  stamps: number[];
  blocked: boolean;
}

const wikipediaCallerBuckets = new Map<string, WikipediaQuotaBucketEntry>();
let customHourlyLimitForTests: number | null = null;

export function resetWikipediaStateForTests(customHourlyLimit?: number | null): void {
  wikipediaCallerBuckets.clear();
  wikipediaSitemapCache.clear();
  customHourlyLimitForTests = typeof customHourlyLimit === 'number' && customHourlyLimit > 0 ? customHourlyLimit : null;
}

export interface WikipediaBulkChannelBlock {
  ok: false;
  outcome: 'use_bulk_channel';
  error: 'use_bulk_channel';
  retryable: false;
  host: string;
  limitPerHour: number;
  requestsInWindow: number;
  message: string;
  bulkChannels: typeof WIKIPEDIA_BULK_CHANNELS;
}

function makeBulkChannelBlock(host: string, limit: number, requestsInWindow: number): WikipediaBulkChannelBlock {
  return {
    ok: false,
    outcome: 'use_bulk_channel',
    error: 'use_bulk_channel',
    retryable: false,
    host,
    limitPerHour: limit,
    requestsInWindow,
    message:
      `Exceeded polite single-article limit (${limit} requests/hour on ${host}). ` +
      `For bulk or structured corpus work, use Wikimedia Enterprise (${WIKIPEDIA_BULK_CHANNELS.wikimediaEnterprise}), ` +
      `Wikimedia Dumps (${WIKIPEDIA_BULK_CHANNELS.dumps}), or the Hugging Face wikimedia/wikipedia dataset (${WIKIPEDIA_BULK_CHANNELS.huggingFaceDataset}).`,
    bulkChannels: WIKIPEDIA_BULK_CHANNELS,
  };
}

function sweepExpiredWikipediaBuckets(cutoff: number): void {
  for (const [k, entry] of wikipediaCallerBuckets.entries()) {
    let firstValid = 0;
    while (firstValid < entry.stamps.length && entry.stamps[firstValid]! <= cutoff) {
      firstValid++;
    }
    if (firstValid >= entry.stamps.length) {
      wikipediaCallerBuckets.delete(k);
    } else if (firstValid > 0) {
      entry.stamps = entry.stamps.slice(firstValid);
    }
  }
}

export function checkAndRecordWikipediaArticleQuota(params: {
  callerKey: string;
  host: string;
  now?: number;
  limitPerHour?: number;
}): { allowed: true; count: number; limitPerHour: number } | { allowed: false; block: WikipediaBulkChannelBlock } {
  const now = params.now ?? Date.now();
  const limit = params.limitPerHour ?? customHourlyLimitForTests ?? DEFAULT_WIKIPEDIA_HOURLY_ARTICLE_LIMIT;
  const host = params.host.trim().toLowerCase().replace(/\.+$/, '');
  const caller = (params.callerKey || 'owner').trim().slice(0, 96) || 'owner';
  const bucketKey = `${caller}|${host}`;
  const cutoff = now - WIKIPEDIA_QUOTA_WINDOW_MS;

  const existing = wikipediaCallerBuckets.get(bucketKey);
  let stamps: number[];
  if (existing) {
    let firstValid = 0;
    while (firstValid < existing.stamps.length && existing.stamps[firstValid]! <= cutoff) {
      firstValid++;
    }
    stamps = firstValid > 0 ? existing.stamps.slice(firstValid) : existing.stamps;
    wikipediaCallerBuckets.delete(bucketKey);
  } else {
    stamps = [];
  }

  if (stamps.length >= limit) {
    if (wikipediaCallerBuckets.size < MAX_WIKIPEDIA_QUOTA_BUCKETS) {
      wikipediaCallerBuckets.set(bucketKey, { stamps, blocked: true });
    } else {
      sweepExpiredWikipediaBuckets(cutoff);
      if (wikipediaCallerBuckets.size < MAX_WIKIPEDIA_QUOTA_BUCKETS) {
        wikipediaCallerBuckets.set(bucketKey, { stamps, blocked: true });
      }
    }
    return { allowed: false, block: makeBulkChannelBlock(host, limit, stamps.length) };
  }

  if (wikipediaCallerBuckets.size >= MAX_WIKIPEDIA_QUOTA_BUCKETS) {
    sweepExpiredWikipediaBuckets(cutoff);
    if (wikipediaCallerBuckets.size >= MAX_WIKIPEDIA_QUOTA_BUCKETS) {
      return { allowed: false, block: makeBulkChannelBlock(host, limit, limit) };
    }
  }

  stamps.push(now);
  wikipediaCallerBuckets.set(bucketKey, { stamps, blocked: stamps.length >= limit });
  return { allowed: true, count: stamps.length, limitPerHour: limit };
}

const wikipediaSitemapCache = new Map<string, { urls: string[]; expiresAt: number }>();

export function getCachedWikipediaSitemapUrls(host: string, now = Date.now()): string[] | null {
  const key = host.trim().toLowerCase();
  const hit = wikipediaSitemapCache.get(key);
  if (!hit) return null;
  if (now >= hit.expiresAt) {
    wikipediaSitemapCache.delete(key);
    return null;
  }
  wikipediaSitemapCache.delete(key);
  wikipediaSitemapCache.set(key, hit);
  return hit.urls;
}

export function setCachedWikipediaSitemapUrls(host: string, urls: string[], now = Date.now()): void {
  const key = host.trim().toLowerCase();
  wikipediaSitemapCache.delete(key);
  while (wikipediaSitemapCache.size >= MAX_WIKIPEDIA_SITEMAP_CACHE_ENTRIES) {
    const oldest = wikipediaSitemapCache.keys().next().value;
    if (oldest === undefined) break;
    wikipediaSitemapCache.delete(oldest);
  }
  wikipediaSitemapCache.set(key, {
    urls: urls.slice(0, 5_000),
    expiresAt: now + WIKIPEDIA_SITEMAP_CACHE_TTL_MS,
  });
}

export function cleanMediaWikiMarkdownLinear(rawMd: string): string {
  return callCoreWasm<{ out: string }>('wiki_clean_markdown', { md: String(rawMd ?? '') }).out;
}
