#!/usr/bin/env node
/**
 * Reproducible HTML-to-Markdown Comparison & Fidelity Benchmark (`bench/compare.mjs`).
 *
 * Bundles `hub/src/scrape.ts`, `hub/src/waf.ts`, and `hub/src/overflow.ts` via `esbuild` into a temporary
 * ES module so anyone with Node.js 22+ (`cd hub && npm ci`) can run the benchmark in < 3 seconds with
 * zero API keys, zero running servers, and zero external accounts.
 *
 * Modes:
 *   node bench/compare.mjs                    # Default deterministic --offline corpus (6 HTML fixtures)
 *   node bench/compare.mjs --offline          # Explicit offline mode
 *   node bench/compare.mjs --live             # Polite live fetch (checks /robots.txt first) on 3 public docs URLs
 *   node bench/compare.mjs --live --with-jina # Also compares live output sizes against https://r.jina.ai/<url>
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const args = new Set(process.argv.slice(2));
const isLive = args.has('--live');
const withJina = args.has('--with-jina');
const USER_AGENT = 'EdgeFetch-Bench/2.7.2 (+https://github.com/bartrumb/edgefetch)';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
const hubDir = resolve(repoRoot, 'hub');
const reqFromHub = createRequire(resolve(hubDir, 'package.json'));
const { build } = reqFromHub('esbuild');

const tmpDir = mkdtempSync(join(tmpdir(), 'edgefetch-compare-'));
const bundlePath = join(tmpDir, 'edgefetch-compare-bundle.mjs');

let ef;
try {
  await build({
    stdin: {
      contents: `
        export { extractHtmlDocument, finalizeScrapedMarkdown } from './src/scrape.ts';
        export { recoverSsrHydrationContent } from './src/waf.ts';
        export { parseOverflowRobotsTxt, isRobotsAllowed } from './src/overflow.ts';
      `,
      resolveDir: hubDir,
      sourcefile: 'compare-entry.ts',
      loader: 'ts',
    },
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    banner: {
      js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);",
    },
    loader: {
      '.yaml': 'text',
      '.yml': 'text',
    },
    alias: {
      'cloudflare:workers': resolve(hubDir, 'test/cloudflare-workers-stub.ts'),
    },
    outfile: bundlePath,
  });
  ef = await import(pathToFileURL(bundlePath).href);
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}

const {
  extractHtmlDocument,
  finalizeScrapedMarkdown,
  recoverSsrHydrationContent,
  parseOverflowRobotsTxt,
  isRobotsAllowed,
} = ef;

function estTokens(str) {
  return Math.ceil(str.length / 4);
}

/**
 * Baseline 1-liner HTML tag stripper commonly used in ad-hoc agent scripts:
 * decodes basic HTML entities and strips `<...>` tags.
 * Demonstrates two classic failure modes on real technical pages:
 *  1. Leaves `<script>` hydration JSON, `<style>` rules, and `<nav>`/`<footer>` link chrome in context.
 *  2. Treats `<T>`, `<Array<string>>`, or `<Result<T, Error>>` as unknown HTML tags and deletes them.
 */
function naiveHtmlTagStrip(rawHtml) {
  return rawHtml
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Verifies CommonMark fenced code blocks (` ``` ` or ` ~~~ ` with 0..3 leading spaces) are balanced.
 */
function hasBalancedCodeFences(markdown) {
  let openChar = '';
  let openLen = 0;
  for (const rawLine of markdown.split(/\r?\n/)) {
    if (!openChar) {
      const m = /^[ ]{0,3}(`{3,}|~{3,})(.*)$/.exec(rawLine);
      if (!m) continue;
      const fence = m[1];
      const info = m[2] ?? '';
      if (fence[0] === '`' && info.includes('`')) continue;
      openChar = fence[0];
      openLen = fence.length;
    } else {
      const closeRe = openChar === '`' ? /^[ ]{0,3}(`{3,})[ \t]*$/ : /^[ ]{0,3}(~{3,})[ \t]*$/;
      const cm = closeRe.exec(rawLine);
      if (cm && cm[1].length >= openLen) {
        openChar = '';
        openLen = 0;
      }
    }
  }
  return openChar === '';
}

/**
 * Runs EdgeFetch's production HTML -> SSR-hydration fallback -> Markdown sanitizer pipeline.
 */
function runEdgeFetchPipeline(rawHtml, url) {
  const extracted = extractHtmlDocument(rawHtml, {
    baseUrl: url,
    onlyMainContent: true,
    includeImages: false,
  });
  let md = extracted.markdown;
  const wordCount = (md.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
  if (wordCount < 80 && rawHtml.includes('<script')) {
    const hydrated = recoverSsrHydrationContent(rawHtml, url, (frag, base) =>
      extractHtmlDocument(frag, { baseUrl: base, onlyMainContent: false, includeImages: false }),
    );
    if (hydrated && hydrated.markdown.length > md.length) {
      md = hydrated.markdown;
    }
  }
  return finalizeScrapedMarkdown(md, {
    isPdf: false,
    includeImages: false,
    baseUrl: url,
  }).markdown;
}

const navLinks = Array.from(
  { length: 45 },
  (_, i) => `<li><a href="https://docs.example.dev/nav/section-${i}">Navigation Item ${i}</a></li>`,
).join('');
const cookieModal = `<div role="dialog" aria-modal="true" class="cookie-consent-banner"><p>We and our 148 partners store cookies and telemetry identifiers for personalized advertising.</p><button>Accept All</button><button>Manage Preferences</button></div>`;
const clientBundleState = `<script>window.__CLIENT_CHUNKS__ = ${JSON.stringify({
  buildId: '2026-11-22-prod',
  assets: Array.from({ length: 75 }, (_, i) => `/_assets/chunk-${i}-9f8e7d6c5b4a.js`),
})};</script>`;

const OFFLINE_CORPUS = [
  {
    name: 'TypeScript SDK Docs (`<T>` Generics + Code Fences)',
    url: 'https://docs.example.dev/sdk/streaming-generics',
    rawHtml: `<!doctype html><html lang="en"><head><title>Streaming Generics — SDK Docs</title>${clientBundleState}</head><body>
      <header><nav><ul>${navLinks}</ul></nav></header>${cookieModal}
      <main>
        <article>
          <h1>Streaming Generic Parsers</h1>
          <p>Use <code>parseStream&lt;T&gt;</code> when transforming a byte stream into <code>Promise&lt;Array&lt;string&gt;&gt;</code> or <code>Result&lt;T, Error&gt;</code> without buffering the entire response in memory.</p>
          <pre><code class="language-ts">export async function collectLines&lt;T extends Record&lt;string, unknown&gt;&gt;(
  source: ReadableStream&lt;Uint8Array&gt;,
  mapFn: (raw: string) =&gt; Promise&lt;Array&lt;string&gt;&gt;,
): Promise&lt;Result&lt;T[], Error&gt;&gt; {
  const out: T[] = [];
  return { ok: true, value: out };
}</code></pre>
        </article>
      </main>
      <footer><p>Copyright 2026 Example Developer Docs</p></footer>
    </body></html>`,
    mustPreserve: ['Promise<Array<string>>', 'Result<T, Error>', 'ReadableStream<Uint8Array>'],
    noise: ['Navigation Item 12', '148 partners', 'chunk-10-9f8e7d6c5b4a'],
  },
  {
    name: 'Politeness & Rate-Limit Reference (GFM Table + Callout)',
    url: 'https://docs.example.dev/reference/politeness',
    rawHtml: `<!doctype html><html lang="en"><head><title>Host Pacing &amp; Retry-After</title>${clientBundleState}</head><body>
      <header><nav><ul>${navLinks}</ul></nav></header>
      <aside class="VPSidebar"><ul>${navLinks}</ul></aside>${cookieModal}
      <main>
        <h1>Host Pacing &amp; Retry-After</h1>
        <div class="custom-block warning"><p class="custom-block-title">IMPORTANT</p><p>Track per-origin windows in <code>Map&lt;string, HostState&gt;</code> and honor HTTP 429 <code>Retry-After</code> headers.</p></div>
        <table>
          <thead><tr><th>Status</th><th>Action</th><th>Retry Policy</th></tr></thead>
          <tbody>
            <tr><td>429 Too Many Requests</td><td>Honor Retry-After seconds</td><td>Up to 3 adaptive attempts</td></tr>
            <tr><td>403 Challenge</td><td>Halt immediately</td><td>Never bypass CAPTCHA</td></tr>
            <tr><td>304 Not Modified</td><td>Serve verified cache</td><td>0 re-extraction cost</td></tr>
          </tbody>
        </table>
      </main>
      <footer>Built with VitePress</footer>
    </body></html>`,
    mustPreserve: ['Map<string, HostState>', '| Status | Action | Retry Policy |'],
    noise: ['Navigation Item 5', '148 partners', 'chunk-20-9f8e7d6c5b4a'],
  },
  {
    name: 'E-Commerce / Tech Review Page (Ad Chrome + Spec Table)',
    url: 'https://hardware.example.com/reviews/arm64-homelab-node',
    rawHtml: `<!doctype html><html lang="en"><head><title>ARM64 Homelab Node Review</title>${clientBundleState}<style>.ad-slot{min-height:280px;display:block}</style></head><body>
      <header><nav><ul>${navLinks}</ul></nav></header>${cookieModal}
      <div class="ad-banner" data-ad-unit="leaderboard">Sponsored: Cloud Enterprise SaaS Promo</div>
      <main>
        <article>
          <h1>ARM64 Fanless Homelab Node Review</h1>
          <p>Drawing 4.2 watts at idle, this compact ARM64 box runs an outbound WebSocket worker and local SQLite FTS5 index behind CGNAT with zero port forwarding.</p>
          <p>In sustained HTTP/2 benchmarks using <code>Channel&lt;FetchJob&gt;</code> worker pools, tail latency stayed below 18 ms across 10,000 sequential requests.</p>
          <table>
            <thead><tr><th>Metric</th><th>Idle</th><th>Load</th></tr></thead>
            <tbody>
              <tr><td>Wall Power</td><td>4.2 W</td><td>9.8 W</td></tr>
              <tr><td>RSS Memory</td><td>14 MiB</td><td>31 MiB</td></tr>
            </tbody>
          </table>
        </article>
      </main>
      <aside class="related-stories"><h2>Trending Deals</h2><ul>${Array.from({ length: 20 }, (_, i) => `<li><a href="/deals/${i}">Affiliate Gadget Deal #${i} — Save 45% Today</a></li>`).join('')}</ul></aside>
      <footer>All rights reserved 2026 Media Corp.</footer>
    </body></html>`,
    mustPreserve: ['Channel<FetchJob>', '| Metric | Idle | Load |'],
    noise: ['Affiliate Gadget Deal #3', '148 partners', 'chunk-30-9f8e7d6c5b4a'],
  },
  {
    name: 'Next.js SPA Shell (`__NEXT_DATA__` SSR Hydration)',
    url: 'https://app.example.dev/docs/ssr-hydration',
    rawHtml: `<!doctype html><html lang="en"><head><title>Zero-Browser SSR Hydration</title>${clientBundleState}</head><body>
      <header><nav><ul>${navLinks}</ul></nav></header>${cookieModal}
      <div id="__next"><div class="loading-skeleton">Loading documentation...</div></div>
      <script id="__NEXT_DATA__" type="application/json">${JSON.stringify({
        buildId: 'next-prod-2026',
        props: {
          pageProps: {
            title: 'Zero-Browser SSR Hydration',
            content:
              'Modern single-page shells frequently render a thin loading placeholder in visible HTML while embedding the full article inside hydration state. EdgeFetch recovers `AsyncGenerator<Uint8Array, void>` prose and fenced code blocks directly in one HTTP pass:\n\n```ts\nexport type StreamChunk<T> = { seq: number; payload: Promise<Array<T>> };\n```\n\nThis avoids launching a 300 MB headless browser on static documentation and changelogs.',
          },
        },
      })}</script>
    </body></html>`,
    mustPreserve: ['AsyncGenerator<Uint8Array, void>', 'Promise<Array<T>>'],
    noise: ['Navigation Item 1', '148 partners', 'chunk-40-9f8e7d6c5b4a'],
  },
  {
    name: 'Algorithm Reference (KaTeX MathML + Wiki Edit Chrome)',
    url: 'https://en.wikipedia.org/wiki/Reciprocal_rank_fusion',
    rawHtml: `<!doctype html><html lang="en"><head><title>Reciprocal rank fusion - Wikipedia</title>${clientBundleState}</head><body>
      <nav><ul>${navLinks}</ul></nav>
      <main>
        <h1>Reciprocal rank fusion</h1>
        <p><b>Reciprocal rank fusion</b> (<b>RRF</b>)<span class="mw-editsection">[<a href="/w/index.php?action=edit">edit</a>]</span> merges ranked candidate slices <code>Vec&lt;ScoredDoc&gt;</code> from multiple retrieval backends without score calibration.[citation needed]</p>
        <p>Given rankings <i>R</i>, the fused score is <span class="katex"><math><semantics><annotation encoding="application/x-tex">\\text{RRF}(d) = \\sum_{r \\in R} \\frac{1}{60 + r(d)}</annotation></semantics></math></span>.</p>
        <ul class="interlanguage-links">${Array.from({ length: 25 }, (_, i) => `<li class="interlanguage-link"><a href="https://lang${i}.wikipedia.org/wiki/RRF">Language ${i}</a></li>`).join('')}</ul>
      </main>
    </body></html>`,
    mustPreserve: ['Vec<ScoredDoc>', '\\sum_{r \\in R}'],
    noise: ['[edit]', '[citation needed]', 'Language 4'],
  },
  {
    name: 'IETF RFC Specification (Page-Break Chrome + Headings)',
    url: 'https://www.rfc-editor.org/rfc/rfc9309',
    rawHtml: `<!doctype html><html lang="en"><head><title>RFC 9309: Robots Exclusion Protocol</title>${clientBundleState}</head><body>
      <header><nav><ul>${navLinks}</ul></nav></header>
      <pre class="newpage">RFC 9309                Robots Exclusion Protocol         September 2022

2.2.2. The "Allow" and "Disallow" Lines

Crawlers MUST use longest-match path precedence when evaluating rules
and MUST process at least 500 KiB of UTF-8 rules per origin.

Koster, et al.               Standards Track                    [Page 8]</pre>
      <pre class="newpage">RFC 9309                Robots Exclusion Protocol         September 2022

2.3.1.5. Redirects

Crawlers SHOULD follow up to five consecutive redirects when fetching /robots.txt.

Koster, et al.               Standards Track                    [Page 9]</pre>
    </body></html>`,
    mustPreserve: ['#### 2.2.2. The "Allow" and "Disallow" Lines', '500 KiB'],
    noise: ['[Page 8]', '[Page 9]', 'chunk-5-9f8e7d6c5b4a', 'Navigation Item 2'],
  },
];

function runOfflineBenchmark() {
  const iterations = 25;
  const rows = [];
  let sumRawBytes = 0;
  let sumRawTok = 0;
  let sumNaiveTok = 0;
  let sumEfChars = 0;
  let sumEfTok = 0;
  let sumMs = 0;
  let allEfPassed = true;
  let naivePassCount = 0;

  for (const fixture of OFFLINE_CORPUS) {
    // Warmup
    const efMd = runEdgeFetchPipeline(fixture.rawHtml, fixture.url);
    const naiveOut = naiveHtmlTagStrip(fixture.rawHtml);

    const t0 = performance.now();
    for (let i = 0; i < iterations; i++) {
      runEdgeFetchPipeline(fixture.rawHtml, fixture.url);
    }
    const avgMs = (performance.now() - t0) / iterations;

    const rawBytes = Buffer.byteLength(fixture.rawHtml, 'utf8');
    const rawTok = estTokens(fixture.rawHtml);
    const naiveTok = estTokens(naiveOut);
    const efChars = efMd.length;
    const efTok = estTokens(efMd);
    const reductionPct = (((rawTok - efTok) / rawTok) * 100).toFixed(1);

    const efPreserved = fixture.mustPreserve.every((g) => efMd.includes(g));
    const efNoiseFree = fixture.noise.every((n) => !efMd.includes(n));
    const efFencesOk = hasBalancedCodeFences(efMd);
    const efPassed = efPreserved && efNoiseFree && efFencesOk;
    if (!efPassed) {
      allEfPassed = false;
      console.error(
        `FAIL [${fixture.name}]: preserved=${efPreserved} noiseFree=${efNoiseFree} fences=${efFencesOk}\n${efMd}`,
      );
    }

    const naivePreserved = fixture.mustPreserve.every((g) => naiveOut.includes(g));
    const naiveNoiseFree = fixture.noise.every((n) => !naiveOut.includes(n));
    if (naivePreserved && naiveNoiseFree) naivePassCount++;

    const hasGenericCheck = fixture.mustPreserve.some((g) => g.includes('<'));
    const naiveDetail = [
      hasGenericCheck ? (naivePreserved ? '`<T>` ok' : '`<T>` broken') : naivePreserved ? 'text ok' : 'structure lost',
      naiveNoiseFree ? 'clean' : 'nav/script noise',
    ].join(', ');

    sumRawBytes += rawBytes;
    sumRawTok += rawTok;
    sumNaiveTok += naiveTok;
    sumEfChars += efChars;
    sumEfTok += efTok;
    sumMs += avgMs;

    rows.push({
      name: fixture.name,
      rawBytes,
      rawTok,
      naiveTok,
      naiveDetail,
      efChars,
      efTok,
      reductionPct,
      avgMs: avgMs.toFixed(2),
      efStatus: efPassed ? 'PASS' : 'FAIL',
    });
  }

  const totalReductionPct = (((sumRawTok - sumEfTok) / sumRawTok) * 100).toFixed(1);
  console.log(
    `## Offline Deterministic HTML Comparison (\`node bench/compare.mjs\` — ${OFFLINE_CORPUS.length} Fixtures × ${iterations} Runs)\n`,
  );
  console.log(
    '| Fixture | Raw HTML (`bytes` / `~tok`) | Naive Tag-Strip (`~tok` / failure mode) | EdgeFetch (`chars` / `~tok`) | Token Reduction | Latency | Gate (`<T>` + Fences + Clean) |',
  );
  console.log('|---|---:|---:|---:|---:|---:|:---:|');
  for (const r of rows) {
    console.log(
      `| ${r.name} | ${r.rawBytes.toLocaleString('en-US')} B / ${r.rawTok.toLocaleString('en-US')} | ${r.naiveTok.toLocaleString('en-US')} (${r.naiveDetail}) | **${r.efChars.toLocaleString('en-US')}** / **${r.efTok.toLocaleString('en-US')}** | **-${r.reductionPct}%** | ${r.avgMs} ms | ${r.efStatus} |`,
    );
  }
  console.log(
    `| **Total / Sum** | **${sumRawBytes.toLocaleString('en-US')} B / ${sumRawTok.toLocaleString('en-US')}** | **${sumNaiveTok.toLocaleString('en-US')} (${naivePassCount}/${OFFLINE_CORPUS.length} clean)** | **${sumEfChars.toLocaleString('en-US')}** / **${sumEfTok.toLocaleString('en-US')}** | **-${totalReductionPct}%** | **${sumMs.toFixed(2)} ms** | **${allEfPassed ? `${OFFLINE_CORPUS.length}/${OFFLINE_CORPUS.length} PASS` : 'FAIL'}** |`,
  );

  if (!allEfPassed) {
    process.exitCode = 1;
  }
}

const LIVE_TARGETS = [
  'https://example.com/',
  'https://go.dev/doc/effective_go',
  'https://www.rfc-editor.org/rfc/rfc9309.html',
];

async function checkPoliteRobotsAllowed(targetUrl) {
  const u = new URL(targetUrl);
  const robotsUrl = `${u.origin}/robots.txt`;
  const res = await fetch(robotsUrl, {
    headers: { 'User-Agent': USER_AGENT, Accept: 'text/plain,*/*;q=0.8' },
    redirect: 'follow',
    signal: AbortSignal.timeout(10_000),
  });
  if (res.status >= 400 && res.status < 500) {
    // RFC 9309 §2.3.1.4: 4xx on /robots.txt means no restrictions.
    return true;
  }
  if (!res.ok) {
    return false;
  }
  const body = await res.text();
  const parsed = parseOverflowRobotsTxt(body, USER_AGENT);
  return isRobotsAllowed(parsed, `${u.pathname}${u.search}`);
}

async function runLiveBenchmark() {
  console.log(
    `## Live Public Technical Pages (\`node bench/compare.mjs --live${withJina ? ' --with-jina' : ''}\`)\n`,
  );
  if (withJina) {
    console.log(
      '| Public URL (`robots.txt` checked) | Raw HTML (`bytes` / `~tok`) | EdgeFetch (`~tok` / delta / extract `ms`) | Jina Reader `r.jina.ai` (`~tok` / delta) | EdgeFetch Fences |',
    );
    console.log('|---|---:|---:|---:|:---:|');
  } else {
    console.log(
      '| Public URL (`robots.txt` checked) | Raw HTML (`bytes` / `~tok`) | Naive Strip (`~tok`) | EdgeFetch (`chars` / `~tok`) | Token Reduction | Fetch / Extract `ms` | Balanced Fences |',
    );
    console.log('|---|---:|---:|---:|---:|---:|:---:|');
  }

  for (const url of LIVE_TARGETS) {
    const allowed = await checkPoliteRobotsAllowed(url);
    if (!allowed) {
      console.log(`| \`${url}\` | SKIPPED (\`robots.txt\`) | — | — | — |`);
      continue;
    }

    const fetchT0 = performance.now();
    const res = await fetch(url, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(15_000),
    });
    const rawHtml = await res.text();
    const fetchMs = performance.now() - fetchT0;

    const extT0 = performance.now();
    const efMd = runEdgeFetchPipeline(rawHtml, url);
    const extractMs = performance.now() - extT0;

    const rawBytes = Buffer.byteLength(rawHtml, 'utf8');
    const rawTok = estTokens(rawHtml);
    const naiveTok = estTokens(naiveHtmlTagStrip(rawHtml));
    const efTok = estTokens(efMd);
    const efDelta = (((rawTok - efTok) / rawTok) * 100).toFixed(1);
    const fencesOk = hasBalancedCodeFences(efMd);

    if (withJina) {
      let jinaCell = 'unavailable';
      try {
        const jinaHeaders = {
          'User-Agent': USER_AGENT,
          Accept: 'text/plain',
          ...(process.env.JINA_API_KEY ? { Authorization: `Bearer ${process.env.JINA_API_KEY}` } : {}),
        };
        const jRes = await fetch(`https://r.jina.ai/${url}`, {
          headers: jinaHeaders,
          signal: AbortSignal.timeout(20_000),
        });
        if (jRes.ok) {
          const jText = await jRes.text();
          const jTok = estTokens(jText);
          const jDelta = (((rawTok - jTok) / rawTok) * 100).toFixed(1);
          jinaCell = `${jTok.toLocaleString('en-US')} (-${jDelta}%)`;
        } else {
          jinaCell = jRes.status === 401 ? 'HTTP 401 (set JINA_API_KEY)' : `HTTP ${jRes.status}`;
        }
      } catch (err) {
        jinaCell = `err (${err instanceof Error ? err.message.slice(0, 24) : 'timeout'})`;
      }
      console.log(
        `| \`${url}\` | ${rawBytes.toLocaleString('en-US')} B / ${rawTok.toLocaleString('en-US')} | **${efTok.toLocaleString('en-US')}** (**-${efDelta}%**, ${extractMs.toFixed(1)} ms) | ${jinaCell} | ${fencesOk ? 'PASS' : 'FAIL'} |`,
      );
    } else {
      console.log(
        `| \`${url}\` | ${rawBytes.toLocaleString('en-US')} B / ${rawTok.toLocaleString('en-US')} | ${naiveTok.toLocaleString('en-US')} | **${efMd.length.toLocaleString('en-US')}** / **${efTok.toLocaleString('en-US')}** | **-${efDelta}%** | ${fetchMs.toFixed(0)} / ${extractMs.toFixed(1)} ms | ${fencesOk ? 'PASS' : 'FAIL'} |`,
      );
    }
  }
}

if (isLive) {
  await runLiveBenchmark();
} else {
  runOfflineBenchmark();
}
