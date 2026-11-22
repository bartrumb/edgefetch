import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { NodeSqliteD1Database } from '../portable/node-adapters.ts';
import { compileDeclarativeAdapter } from '../src/extractors/declarative.ts';
import { extractHtmlDocument } from '../src/scrape.ts';
import {
  buildDomainScopedQuery,
  classifySearchResultQuality,
  computeHostQualityFactor,
  detectNewsSearchIntent,
  executeSearchCall,
  resetSearchProviderPacingForTests,
  type SearchResultEntry,
} from '../src/web-search.ts';

function resolveRepoRoot(): string {
  const hubRoot = process.env.EDGEFETCH_HUB_ROOT || resolve(dirname(fileURLToPath(import.meta.url)), '..');
  return resolve(hubRoot, '..');
}

const simpleHtmlToMd = (frag: string, base?: string) => {
  const doc = extractHtmlDocument(`<!doctype html><html><body>${frag}</body></html>`, {
    baseUrl: base ?? 'https://example.com',
    onlyMainContent: false,
  });
  return { markdown: doc.markdown, links: doc.links };
};

test('R7-NEWS-1: Declarative news-feeds.yaml upgrades 9 broadcaster/news hubs to RSS/RDF feeds while leaving article URLs untouched', () => {
  const repoRoot = resolveRepoRoot();
  const yamlText = readFileSync(join(repoRoot, 'internal', 'extract', 'manifests', 'news-feeds.yaml'), 'utf8');
  const fixtureJson = JSON.parse(
    readFileSync(join(repoRoot, 'hub', 'test', 'fixtures', 'adapters', 'news-feeds.json'), 'utf8'),
  ) as {
    inputUrl: string;
    expectedFetchUrl: string;
    mockPayload: string;
    expectTitleIncludes: string;
    expectMarkdownIncludes: string[];
  };

  const adapter = compileDeclarativeAdapter(yamlText);
  assert.equal(adapter.id, 'news-feeds');
  assert.ok(adapter.resolveTwin, 'news-feeds must compile resolveTwin');

  const resolveFor = (rawUrl: string) => {
    const u = new URL(rawUrl);
    return adapter.resolveTwin!({
      url: u,
      urlStr: rawUrl,
      host: u.hostname.toLowerCase(),
      path: u.pathname,
      parts: u.pathname.split('/').filter(Boolean),
    });
  };

  const expectedFeedUpgrades: Array<[string, string]> = [
    // NPR (www.npr.org, npr.org, text.npr.org -> feeds.npr.org)
    ['https://www.npr.org/', 'https://feeds.npr.org/1001/rss.xml'],
    ['https://npr.org', 'https://feeds.npr.org/1001/rss.xml'],
    ['https://text.npr.org/', 'https://feeds.npr.org/1001/rss.xml'],
    ['https://www.npr.org/sections/news', 'https://feeds.npr.org/1001/rss.xml'],
    ['https://www.npr.org/sections/national', 'https://feeds.npr.org/1003/rss.xml'],
    ['https://www.npr.org/sections/world', 'https://feeds.npr.org/1004/rss.xml'],
    ['https://www.npr.org/sections/politics', 'https://feeds.npr.org/1014/rss.xml'],
    ['https://www.npr.org/sections/business', 'https://feeds.npr.org/1006/rss.xml'],
    ['https://www.npr.org/sections/technology', 'https://feeds.npr.org/1019/rss.xml'],
    ['https://www.npr.org/sections/science', 'https://feeds.npr.org/1007/rss.xml'],
    ['https://www.npr.org/sections/health', 'https://feeds.npr.org/1128/rss.xml'],
    // BBC News
    ['https://www.bbc.com/news', 'https://feeds.bbci.co.uk/news/rss.xml'],
    ['https://bbc.co.uk/news/world', 'https://feeds.bbci.co.uk/news/world/rss.xml'],
    ['https://www.bbc.com/news/business', 'https://feeds.bbci.co.uk/news/business/rss.xml'],
    ['https://www.bbc.co.uk/news/technology', 'https://feeds.bbci.co.uk/news/technology/rss.xml'],
    ['https://www.bbc.com/news/science_and_environment', 'https://feeds.bbci.co.uk/news/science_and_environment/rss.xml'],
    // CBS News
    ['https://www.cbsnews.com/', 'https://www.cbsnews.com/latest/rss/main'],
    ['https://cbsnews.com/us', 'https://www.cbsnews.com/latest/rss/us'],
    ['https://www.cbsnews.com/world', 'https://www.cbsnews.com/latest/rss/world'],
    ['https://www.cbsnews.com/politics', 'https://www.cbsnews.com/latest/rss/politics'],
    ['https://www.cbsnews.com/moneywatch', 'https://www.cbsnews.com/latest/rss/moneywatch'],
    ['https://www.cbsnews.com/technology', 'https://www.cbsnews.com/latest/rss/technology'],
    ['https://www.cbsnews.com/science', 'https://www.cbsnews.com/latest/rss/science'],
    ['https://www.cbsnews.com/health', 'https://www.cbsnews.com/latest/rss/health'],
    // NBC News
    ['https://www.nbcnews.com/', 'https://feeds.nbcnews.com/nbcnews/public/news'],
    ['https://nbcnews.com/news', 'https://feeds.nbcnews.com/nbcnews/public/news'],
    ['https://www.nbcnews.com/us-news', 'https://feeds.nbcnews.com/nbcnews/public/news'],
    ['https://www.nbcnews.com/world', 'https://feeds.nbcnews.com/nbcnews/public/news'],
    // ABC News (including uppercase /US, /International, /Politics, /Technology & lowercase variants)
    ['https://abcnews.go.com/', 'https://abcnews.go.com/abcnews/topstories'],
    ['https://abcnews.go.com/US', 'https://abcnews.go.com/abcnews/usheadlines'],
    ['https://abcnews.go.com/us/', 'https://abcnews.go.com/abcnews/usheadlines'],
    ['https://abcnews.go.com/International', 'https://abcnews.go.com/abcnews/internationalheadlines'],
    ['https://abcnews.go.com/Politics', 'https://abcnews.go.com/abcnews/politicsheadlines'],
    ['https://abcnews.go.com/Technology', 'https://abcnews.go.com/abcnews/technologyheadlines'],
    // The Guardian
    ['https://www.theguardian.com/', 'https://www.theguardian.com/international/rss'],
    ['https://theguardian.com/international', 'https://www.theguardian.com/international/rss'],
    ['https://www.theguardian.com/us', 'https://www.theguardian.com/us-news/rss'],
    ['https://www.theguardian.com/us-news', 'https://www.theguardian.com/us-news/rss'],
    ['https://www.theguardian.com/uk', 'https://www.theguardian.com/uk-news/rss'],
    ['https://www.theguardian.com/uk-news', 'https://www.theguardian.com/uk-news/rss'],
    ['https://www.theguardian.com/world', 'https://www.theguardian.com/world/rss'],
    ['https://www.theguardian.com/politics', 'https://www.theguardian.com/politics/rss'],
    ['https://www.theguardian.com/business', 'https://www.theguardian.com/business/rss'],
    ['https://www.theguardian.com/technology', 'https://www.theguardian.com/technology/rss'],
    ['https://www.theguardian.com/science', 'https://www.theguardian.com/science/rss'],
    // Al Jazeera
    ['https://www.aljazeera.com/', 'https://www.aljazeera.com/xml/rss/all.xml'],
    ['https://aljazeera.com/news', 'https://www.aljazeera.com/xml/rss/all.xml'],
    // DW
    ['https://www.dw.com/', 'https://rss.dw.com/rdf/rss-en-all'],
    ['https://dw.com/en', 'https://rss.dw.com/rdf/rss-en-all'],
    // Ars Technica
    ['https://arstechnica.com/', 'https://feeds.arstechnica.com/arstechnica/index'],
    ['https://www.arstechnica.com/', 'https://feeds.arstechnica.com/arstechnica/index'],
  ];

  for (const [inputUrl, expectedFetchUrl] of expectedFeedUpgrades) {
    const twin = resolveFor(inputUrl);
    assert.ok(twin, `expected news-feeds twin to match ${inputUrl}`);
    assert.equal(twin.fetchUrl, expectedFetchUrl, `unexpected feed URL for ${inputUrl}`);
    assert.equal(twin.kind, 'text');
    assert.equal(twin.accept, 'application/rss+xml');
  }

  // Individual article URLs MUST NOT match news-feeds so article HTML scrapes directly!
  const articleUrls = [
    'https://www.npr.org/2026/11/22/nx-s1-5210101/grid-modernization-midwest-transmission',
    'https://text.npr.org/nx-s1-5210101',
    'https://www.bbc.com/news/articles/c9876543210o',
    'https://www.cbsnews.com/news/winter-storm-travel-forecast-2026/',
    'https://www.nbcnews.com/news/us-news/infrastructure-grants-bridge-repairs-rcna199999',
    'https://abcnews.go.com/US/senate-committee-hearing-aviation-safety/story?id=116001234',
    'https://www.theguardian.com/world/2026/nov/22/europe-rail-corridor-agreement',
    'https://www.aljazeera.com/news/2026/11/22/global-climate-finance-summit',
    'https://www.dw.com/en/renewable-grid-storage-breakthrough/a-70987654',
    'https://arstechnica.com/gadgets/2026/11/open-risc-v-workstation-review/',
  ];
  for (const artUrl of articleUrls) {
    assert.equal(resolveFor(artUrl), null, `article URL ${artUrl} must NOT be hijacked by section RSS twin`);
  }

  // Verify RSS 2.0 fixture formatting AND DW RDF 1.0 (`<rdf:RDF>` + `<dc:date>`) formatting
  const nprTwin = resolveFor(fixtureJson.inputUrl)!;
  const formattedNpr = nprTwin.formatTwin(fixtureJson.mockPayload, fixtureJson.inputUrl, simpleHtmlToMd);
  assert.ok(formattedNpr);
  assert.ok(formattedNpr.title.includes(fixtureJson.expectTitleIncludes));
  for (const needle of fixtureJson.expectMarkdownIncludes) {
    assert.ok(formattedNpr.markdown.includes(needle), `missing "${needle}" in formatted NPR feed`);
  }
  assert.equal(formattedNpr.links?.length, 2);

  const dwTwin = resolveFor('https://www.dw.com/en')!;
  const dwRdfXml = `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://purl.org/rss/1.0/">
  <channel rdf:about="https://www.dw.com/">
    <title>DW.COM - Top Stories</title>
  </channel>
  <item rdf:about="https://www.dw.com/en/baltic-offshore-wind-interconnector-opens/a-71001122">
    <title>Baltic Offshore Wind Interconnector Opens</title>
    <link>https://www.dw.com/en/baltic-offshore-wind-interconnector-opens/a-71001122</link>
    <description>Cross-border HVDC subsea cable links two offshore wind hubs.</description>
    <dc:date>2026-11-22T11:30:00Z</dc:date>
  </item>
</rdf:RDF>`;
  const formattedDw = dwTwin.formatTwin(dwRdfXml, 'https://www.dw.com/en', simpleHtmlToMd);
  assert.ok(formattedDw);
  assert.ok(formattedDw.markdown.includes('[Baltic Offshore Wind Interconnector Opens](https://www.dw.com/en/baltic-offshore-wind-interconnector-opens/a-71001122)'));
  assert.ok(formattedDw.markdown.includes('2026-11-22T11:30:00Z'));
});

test('R7-NEWS-2: Multi-domain includeDomains/excludeDomains query compilation fixes 5-domain search across Serper, Brave & SearXNG', async () => {
  resetSearchProviderPacingForTests();

  const fiveDomains = ['npr.org', 'bbc.com', 'cbsnews.com', 'nbcnews.com', 'theguardian.com'];
  assert.equal(
    buildDomainScopedQuery('climate summit', ['npr.org'], ['pinterest.com']),
    'site:npr.org climate summit -site:pinterest.com',
  );
  assert.equal(
    buildDomainScopedQuery('climate summit', fiveDomains, ['youtube.com', 'facebook.com']),
    '(site:npr.org OR site:bbc.com OR site:cbsnews.com OR site:nbcnews.com OR site:theguardian.com) climate summit -site:youtube.com -site:facebook.com',
  );
  // Inline `site:` must not be duplicated by `includeDomains`, while `excludeDomains` still appends cleanly
  assert.equal(
    buildDomainScopedQuery('site:arxiv.org speculative decoding', fiveDomains, ['x.com']),
    'site:arxiv.org speculative decoding -site:x.com',
  );

  let serperBody: Record<string, unknown> | null = null;
  let braveUrl = '';
  let searxUrl = '';

  const out = await executeSearchCall({
    payload: {
      query: 'semiconductor supply chain',
      topic: 'general',
      mode: 'rrf',
      max_results: 5,
      include_domains: fiveDomains,
      exclude_domains: ['facebook.com', 'pinterest.com'],
    },
    env: {
      SERPER_API_KEY: 'serper_k',
      BRAVE_API_KEY: 'brave_k',
      SEARXNG_URL: 'https://searx.example.org',
    },
    executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    providerFetchFn: async (input, init) => {
      const u = String(input);
      if (u.includes('google.serper.dev')) {
        serperBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return Response.json({
          organic: [
            { link: 'https://www.npr.org/2026/11/22/semiconductor-packaging-plant', title: 'NPR Chip Report', snippet: 'New packaging facility opens.' },
            { link: 'https://www.bbc.com/news/articles/c1122334455o', title: 'BBC Chip Supply', snippet: 'European wafer capacity expands.' },
            { link: 'https://www.cbsnews.com/news/chip-supply-chain-update/', title: 'CBS Chip Update', snippet: 'Domestic foundry yield rises.' },
          ],
        });
      }
      if (u.includes('api.search.brave.com')) {
        braveUrl = u;
        return Response.json({
          web: {
            results: [
              { url: 'https://www.nbcnews.com/business/economy/chip-exports-rcna188888', title: 'NBC Chip Exports', description: 'Supply chain resilience.' },
              { url: 'https://www.theguardian.com/technology/2026/nov/22/semiconductor-fab', title: 'Guardian Fab Story', description: 'Lithography milestone.' },
            ],
          },
        });
      }
      searxUrl = u;
      return Response.json({ results: [] });
    },
  });

  assert.equal(out.status, 200);
  const expectedScoped =
    '(site:npr.org OR site:bbc.com OR site:cbsnews.com OR site:nbcnews.com OR site:theguardian.com) semiconductor supply chain -site:facebook.com -site:pinterest.com';
  assert.equal(serperBody?.q, expectedScoped);
  assert.equal(new URL(braveUrl).searchParams.get('q'), expectedScoped);
  assert.equal(new URL(searxUrl).searchParams.get('q'), expectedScoped);
  assert.equal((out.body.results as SearchResultEntry[]).length, 5, 'all 5 requested domains return results instead of collapsing to 1');
});

test('R7-NEWS-3: Dedicated /news SERP endpoint routing (Serper, Brave, Tavily, SearXNG), outlet/date attribution & D1 cache isolation', async () => {
  resetSearchProviderPacingForTests();

  // Intent detection checks: conservative on technical queries, accurate on explicit news/headline queries
  assert.equal(detectNewsSearchIntent('top news today'), true);
  assert.equal(detectNewsSearchIntent('breaking news'), true);
  assert.equal(detectNewsSearchIntent('Missouri news today'), true);
  assert.equal(detectNewsSearchIntent('latest news on fusion energy'), true);
  assert.equal(detectNewsSearchIntent('TaskGroup asyncio docs'), false);
  assert.equal(detectNewsSearchIntent('Hacker News API documentation'), false);
  assert.equal(detectNewsSearchIntent('TaskGroup asyncio docs', '', 'news'), true);
  assert.equal(detectNewsSearchIntent('breaking news', '', 'general'), false);

  const calledEndpoints: string[] = [];
  let tavilyBody: Record<string, unknown> | null = null;

  const newsOut = await executeSearchCall({
    payload: {
      query: 'breaking news global economy',
      mode: 'rrf',
      max_results: 5,
    },
    env: {
      SERPER_API_KEY: 'serper_k',
      BRAVE_API_KEY: 'brave_k',
      TAVILY_API_KEY: 'tavily_k',
      SEARXNG_URL: 'https://searx.example.org',
    },
    executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    providerFetchFn: async (input, init) => {
      const u = String(input);
      calledEndpoints.push(u);
      if (u === 'https://google.serper.dev/news') {
        return Response.json({
          news: [
            {
              title: 'Central Banks Coordinate Cross-Border Instant Settlement',
              link: 'https://www.bbc.com/news/articles/c5566778899o',
              snippet: 'New settlement rail cuts clearing latency.',
              date: '2 hours ago',
              source: 'BBC News',
            },
          ],
        });
      }
      if (u.startsWith('https://api.search.brave.com/res/v1/news/search')) {
        return Response.json({
          results: [
            {
              title: 'Manufacturing Orders Rebound in Q4 Survey',
              url: 'https://www.npr.org/2026/11/22/manufacturing-orders-q4',
              description: ' Regional factory gauges climbed.',
              age: '1 hour ago',
              meta_url: { hostname: 'www.npr.org', netloc: 'npr.org' },
            },
          ],
        });
      }
      if (u.startsWith('https://searx.example.org/search')) {
        return Response.json({ results: [] });
      }
      if (u === 'https://api.tavily.com/search') {
        tavilyBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return Response.json({
          results: [
            {
              url: 'https://www.theguardian.com/business/2026/nov/22/trade-corridor-report',
              title: 'Trade Corridor Report',
              content: 'Container throughput rose 4 percent.',
            },
          ],
        });
      }
      throw new Error(`Unexpected endpoint: ${u}`);
    },
  });

  assert.equal(newsOut.status, 200);
  assert.equal(newsOut.body.topic, 'news');
  assert.ok(calledEndpoints.includes('https://google.serper.dev/news'));
  assert.ok(calledEndpoints.some((u) => u.startsWith('https://api.search.brave.com/res/v1/news/search')));
  const searxCall = calledEndpoints.find((u) => u.startsWith('https://searx.example.org/search'))!;
  assert.equal(new URL(searxCall).searchParams.get('categories'), 'news');
  assert.equal(tavilyBody?.topic, 'news');

  const results = newsOut.body.results as SearchResultEntry[];
  const bbcHit = results.find((r) => r.url.includes('bbc.com'))!;
  assert.match(bbcHit.content, /^\[BBC News · 2 hours ago\] New settlement rail/);
  const nprHit = results.find((r) => r.url.includes('npr.org'))!;
  assert.match(nprHit.content, /^\[npr\.org · 1 hour ago\] Regional factory gauges/);

  // Verify D1 `search_cache` isolates `general` and `news` topics on identical query string
  const metaDb = new NodeSqliteD1Database(':memory:');
  const origFetch = globalThis.fetch;
  let liveFetchCalls = 0;
  try {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      liveFetchCalls++;
      const u = String(input);
      if (u === 'https://google.serper.dev/search') {
        return Response.json({
          organic: [{ link: 'https://www.npr.org/sections/economy-overview', title: 'General Economy Guide', snippet: 'Evergreen guide.' }],
        });
      }
      if (u === 'https://google.serper.dev/news') {
        return Response.json({
          news: [{ link: 'https://www.npr.org/2026/11/22/live-rate-decision', title: 'Live Rate Decision', snippet: 'Rates held steady.', source: 'NPR', date: '15 mins ago' }],
        });
      }
      throw new Error(`Unexpected live fetch: ${u}`);
    }) as typeof fetch;

    const genRes = await executeSearchCall({
      payload: { query: 'federal reserve outlook', topic: 'general', mode: 'serper', max_results: 3 },
      env: { META: metaDb as unknown as D1Database, SERPER_API_KEY: 'serper_k' },
      executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    });
    const newsRes = await executeSearchCall({
      payload: { query: 'federal reserve outlook', topic: 'news', mode: 'serper', max_results: 3 },
      env: { META: metaDb as unknown as D1Database, SERPER_API_KEY: 'serper_k' },
      executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    });

    assert.equal(liveFetchCalls, 2, 'topic=news must not collide with cached topic=general entry');
    assert.equal((genRes.body.results as SearchResultEntry[])[0]?.title, 'General Economy Guide');
    assert.equal((newsRes.body.results as SearchResultEntry[])[0]?.title, 'Live Rate Decision');
  } finally {
    globalThis.fetch = origFetch;
    metaDb.close();
  }
});

test('R7-NEWS-4: Known-good/adapter host boost, anti-bot/social/video/empty-hub demotion & explicit-domain protection', async () => {
  resetSearchProviderPacingForTests();

  // Direct unit checks on computeHostQualityFactor & classifySearchResultQuality
  const nprQ = classifySearchResultQuality('https://www.npr.org/2026/11/22/story-1', 'www.npr.org', { isNewsTopic: true });
  assert.equal(nprQ.qualityTier, 'adapter');
  assert.ok(nprQ.factor >= 1.3 && nprQ.factor <= 1.4);

  const nihQ = classifySearchResultQuality('https://www.nih.gov/news-events/news-releases/study', 'www.nih.gov', { isNewsTopic: true });
  assert.ok(nihQ.qualityTier === 'known_good' || nihQ.qualityTier === 'adapter');
  assert.ok(nihQ.factor >= 1.3);

  const fbFactor = computeHostQualityFactor('https://www.facebook.com/groups/scanner/posts/1', 'www.facebook.com', { isNewsTopic: true });
  assert.ok(fbFactor <= 0.35);

  const reutersFactor = computeHostQualityFactor('https://www.reuters.com/world/story-id', 'www.reuters.com', { isNewsTopic: true });
  assert.equal(reutersFactor, 0.4);

  // Explicit domain target (`includeDomains` / `site:`) waives host penalty while still preferring articles over `/video/`
  const explicitReutersArticle = computeHostQualityFactor('https://www.reuters.com/world/story-id', 'www.reuters.com', {
    isExplicitDomainTarget: true,
    isNewsTopic: true,
  });
  const explicitReutersVideo = computeHostQualityFactor('https://www.reuters.com/video/watch/id123', 'www.reuters.com', {
    isExplicitDomainTarget: true,
    isNewsTopic: true,
  });
  assert.equal(explicitReutersArticle, 1.0);
  assert.equal(explicitReutersVideo, 0.45);

  // Dynamic getHostHealth boost (okCount >= 2, challengeCount === 0) & challenge demotion (challengeCount >= 2, okCount === 0)
  const healthyDynamic = classifySearchResultQuality('https://regionalpaper.example.com/2026/story', 'regionalpaper.example.com', {
    getHostHealth: () => ({ okCount: 4, challengeCount: 0, rateLimitCount: 0, error5xxCount: 0 }),
  });
  assert.equal(healthyDynamic.factor, 1.2);
  assert.equal(healthyDynamic.qualityTier, 'known_good');

  const challengedDynamic = classifySearchResultQuality('https://wafwall.example.com/2026/story', 'wafwall.example.com', {
    getHostHealth: () => ({ okCount: 0, challengeCount: 3, rateLimitCount: 0, error5xxCount: 0 }),
  });
  assert.equal(challengedDynamic.factor, 0.35);
  assert.equal(challengedDynamic.qualityTier, 'demoted');

  // Empty hub penalty in news mode when deeper article URLs exist
  const bareHubFactor = computeHostQualityFactor('https://example-outlet.com/news', 'example-outlet.com', {
    isNewsTopic: true,
    snippetLength: 12,
    hasDeeperArticleUrls: true,
  });
  assert.equal(bareHubFactor, 0.55);

  // End-to-end RRF reranking: open/adapter outlets outrank higher-SERP-position NYT/Reuters/YouTube/Facebook/bare-hub hits
  const out = await executeSearchCall({
    payload: { query: 'top news today', max_results: 6 },
    env: { SERPER_API_KEY: 'serper_k' },
    executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    providerFetchFn: async () =>
      Response.json({
        news: [
          { link: 'https://www.nytimes.com/2026/11/22/us/paywalled-briefing.html', title: 'NYT Briefing', snippet: 'Morning briefing behind hard meter.' },
          { link: 'https://www.youtube.com/watch?v=abcd1234', title: 'Live News Stream Video', snippet: 'Watch live stream.' },
          { link: 'https://www.reuters.com/world/wire-brief-2026-11-22/', title: 'Reuters Wire', snippet: 'Blocked by DataDome.' },
          { link: 'https://generic-news.example.com/news', title: 'News Hub', snippet: 'Latest news' },
          { link: 'https://www.npr.org/2026/11/22/nx-s1-9001/senate-appropriations-vote', title: 'Senate Passes Appropriations Package', snippet: 'Lawmakers approved the bipartisan measure late Saturday.', source: 'NPR', date: '1 hour ago' },
          { link: 'https://www.bbc.com/news/articles/c900200300o', title: 'Global Satellite Weather Constellation Launches', snippet: 'Next-generation polar orbiters enter service.', source: 'BBC News', date: '2 hours ago' },
        ],
      }),
  });

  const ranked = out.body.results as SearchResultEntry[];
  assert.equal(ranked[0]?.url, 'https://www.npr.org/2026/11/22/nx-s1-9001/senate-appropriations-vote');
  assert.equal(ranked[0]?.qualityTier, 'adapter');
  assert.equal(ranked[1]?.url, 'https://www.bbc.com/news/articles/c900200300o');
  assert.equal(ranked[1]?.qualityTier, 'adapter');
});
