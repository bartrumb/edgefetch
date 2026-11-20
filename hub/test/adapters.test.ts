import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  applyPostFetchSiteExtractor,
  getRawRegisteredSiteAdapters,
  listRegisteredAdapters,
  resolveSiteExtractorTwin,
} from '../src/extractors/registry.ts';
import worker from '../src/index.ts';
import {
  buildBlockedInfo,
  classifyAtsBoardStatus,
  discoverAtsBoardsFromHtml,
  executeJobsCall,
  resolveAtsPreFetchSpec,
} from '../src/jobs.ts';
import { extractHtmlDocument } from '../src/scrape.ts';
import { classifyContentState } from '../src/waf.ts';

const simpleHtmlToMd = (frag: string, base?: string) => {
  const doc = extractHtmlDocument(`<!doctype html><html><body>${frag}</body></html>`, {
    baseUrl: base ?? 'https://example.com',
    onlyMainContent: false,
  });
  return { markdown: doc.markdown, links: doc.links };
};

test('ADAPTER-1: Registry catalog integrity, unique IDs, categories & SSRF https:// guard', () => {
  const catalog = listRegisteredAdapters();
  assert.ok(catalog.length >= 45, `expected >= 45 registered adapters, got ${catalog.length}`);

  const ids = new Set<string>();
  const validCategories = new Set([
    'developer',
    'genai',
    'jobs',
    'finance',
    'public-records',
    'research-health',
    'commerce-social',
  ]);

  for (const entry of catalog) {
    assert.ok(!ids.has(entry.id), `duplicate adapter id: ${entry.id}`);
    ids.add(entry.id);
    assert.ok(validCategories.has(entry.category), `invalid category on ${entry.id}: ${entry.category}`);
    assert.ok(entry.name.length >= 2, `missing name on ${entry.id}`);
    assert.ok(entry.description.length >= 10, `missing description on ${entry.id}`);
    assert.ok(entry.domains.length >= 1, `missing domains on ${entry.id}`);
    assert.ok(entry.exampleUrls.length >= 1, `missing exampleUrls on ${entry.id}`);
    for (const ex of entry.exampleUrls) {
      assert.ok(ex.startsWith('https://'), `exampleUrl on ${entry.id} must use https://: ${ex}`);
    }
  }

  // Category filtering
  const jobsOnly = listRegisteredAdapters('jobs');
  assert.ok(jobsOnly.length >= 12);
  assert.ok(jobsOnly.every((x) => x.category === 'jobs'));

  // Non-HTTPS URLs must never resolve a twin
  assert.equal(resolveSiteExtractorTwin('http://www.npmjs.com/package/esbuild'), null);
  assert.equal(getRawRegisteredSiteAdapters().length >= 40, true);
});

test('ADAPTER-2: Auto-discovered contributor JSON fixtures in test/fixtures/adapters/*.json', () => {
  const hubRoot = process.env.EDGEFETCH_HUB_ROOT || resolve('.');
  const fixturesDir = join(hubRoot, 'test', 'fixtures', 'adapters');
  const files = readdirSync(fixturesDir).filter((f) => f.endsWith('.json'));
  assert.ok(files.length >= 5, `expected >= 5 JSON adapter fixtures, found ${files.length}`);

  for (const file of files) {
    const fx = JSON.parse(readFileSync(join(fixturesDir, file), 'utf8')) as {
      adapterId: string;
      mode: 'twin' | 'html';
      inputUrl: string;
      expectedFetchUrl?: string;
      mockPayload: string;
      expectTitleIncludes?: string;
      expectMarkdownIncludes: string[];
    };

    if (fx.mode === 'twin') {
      const twin = resolveSiteExtractorTwin(fx.inputUrl);
      assert.ok(twin, `[fixture ${file}] expected resolveSiteExtractorTwin to match ${fx.inputUrl}`);
      assert.equal(twin.id, fx.adapterId, `[fixture ${file}] adapterId mismatch`);
      if (fx.expectedFetchUrl) {
        assert.equal(twin.fetchUrl, fx.expectedFetchUrl, `[fixture ${file}] fetchUrl mismatch`);
      }
      const formatted = twin.formatTwin(fx.mockPayload, fx.inputUrl, simpleHtmlToMd);
      assert.ok(formatted, `[fixture ${file}] formatTwin returned null`);
      if (fx.expectTitleIncludes) {
        assert.ok(
          formatted.title.includes(fx.expectTitleIncludes),
          `[fixture ${file}] expected title "${formatted.title}" to include "${fx.expectTitleIncludes}"`,
        );
      }
      for (const needle of fx.expectMarkdownIncludes) {
        assert.ok(
          formatted.markdown.includes(needle),
          `[fixture ${file}] expected markdown to include "${needle}", got:\n${formatted.markdown}`,
        );
      }
    } else {
      const baseDoc = extractHtmlDocument(fx.mockPayload, { baseUrl: fx.inputUrl, onlyMainContent: true });
      const htmlRes = applyPostFetchSiteExtractor(fx.mockPayload, fx.inputUrl, baseDoc.markdown, simpleHtmlToMd);
      assert.ok(htmlRes, `[fixture ${file}] expected applyPostFetchSiteExtractor to match ${fx.inputUrl}`);
      assert.equal(htmlRes.extractorId, fx.adapterId, `[fixture ${file}] extractorId mismatch`);
      if (fx.expectTitleIncludes && htmlRes.title) {
        assert.ok(htmlRes.title.includes(fx.expectTitleIncludes), `[fixture ${file}] title mismatch`);
      }
      for (const needle of fx.expectMarkdownIncludes) {
        assert.ok(
          htmlRes.markdown.includes(needle),
          `[fixture ${file}] expected markdown to include "${needle}", got:\n${htmlRes.markdown}`,
        );
      }
    }
  }
});

test('ADAPTER-3: Alexandria Public Providers — Finance, Open Data, Research, Health, Developer, GenAI & Commerce', () => {
  // 1. YC & Work at a Startup -> YC public Inertia data-page mirror
  const waasTwin = resolveSiteExtractorTwin('https://www.workatastartup.com/companies/supabase');
  assert.equal(waasTwin?.fetchUrl, 'https://www.ycombinator.com/companies/supabase/jobs');
  const ycHtml = `<div id="ycdc_new/pages/Companies/ShowPage" data-page="{&quot;props&quot;:{&quot;company&quot;:{&quot;name&quot;:&quot;Supabase&quot;,&quot;batch_name&quot;:&quot;S20&quot;,&quot;one_liner&quot;:&quot;Open source Firebase alternative&quot;,&quot;team_size&quot;:120,&quot;founders&quot;:[{&quot;full_name&quot;:&quot;Paul Copplestone&quot;,&quot;title&quot;:&quot;CEO&quot;}]},&quot;jobPostings&quot;:[{&quot;title&quot;:&quot;Postgres Kernel Engineer&quot;,&quot;location&quot;:&quot;Remote&quot;,&quot;salary_range&quot;:&quot;$190K - $240K&quot;,&quot;url&quot;:&quot;/companies/supabase/jobs/1&quot;}]}}"></div>`;
  const waasDoc = waasTwin!.formatTwin(ycHtml, 'https://www.workatastartup.com/companies/supabase', simpleHtmlToMd);
  assert.ok(waasDoc?.markdown.includes('Supabase (YC S20)'));
  assert.ok(waasDoc?.markdown.includes('Paul Copplestone'));
  assert.ok(waasDoc?.markdown.includes('Postgres Kernel Engineer'));

  const ycPost = applyPostFetchSiteExtractor(ycHtml, 'https://www.ycombinator.com/companies/supabase', '', simpleHtmlToMd);
  assert.equal(ycPost?.extractorId, 'ycombinator');
  assert.ok(ycPost?.markdown.includes('$190K - $240K'));

  // 2. Polymarket
  const polyTwin = resolveSiteExtractorTwin('https://polymarket.com/event/fed-rate-cut');
  assert.equal(polyTwin?.fetchUrl, 'https://gamma-api.polymarket.com/events?slug=fed-rate-cut');
  const polyDoc = polyTwin!.formatTwin(
    JSON.stringify([
      {
        title: 'Fed Rate Cut in December?',
        volume: 12500000,
        liquidity: 850000,
        endDate: '2026-12-18T00:00:00Z',
        markets: [{ groupItemTitle: '25 bps cut', outcomes: '["Yes","No"]', outcomePrices: '["0.72","0.28"]', volume: 9000000 }],
      },
    ]),
    'https://polymarket.com/event/fed-rate-cut',
    simpleHtmlToMd,
  );
  assert.ok(polyDoc?.markdown.includes('Yes: 72.0%'));
  assert.ok(polyDoc?.markdown.includes('$12.50M'));

  // 3. CKAN, ArcGIS, Legistar & USAspending
  const ckanTwin = resolveSiteExtractorTwin('https://catalog.data.gov/dataset/electric-vehicle-population-data');
  assert.equal(ckanTwin?.fetchUrl, 'https://catalog.data.gov/api/3/action/package_show?id=electric-vehicle-population-data');
  const ckanDoc = ckanTwin!.formatTwin(
    JSON.stringify({
      success: true,
      result: {
        title: 'Electric Vehicle Population Data',
        license_title: 'Public Domain',
        organization: { title: 'State of Washington' },
        resources: [{ name: 'CSV Download', format: 'CSV', url: 'https://data.wa.gov/rows.csv' }],
      },
    }),
    'https://catalog.data.gov/dataset/electric-vehicle-population-data',
    simpleHtmlToMd,
  );
  assert.ok(ckanDoc?.markdown.includes('State of Washington'));
  assert.ok(ckanDoc?.markdown.includes('CSV Download'));

  const arcTwin = resolveSiteExtractorTwin(
    'https://services.arcgis.com/P3ePLMYs2RVChkJx/arcgis/rest/services/USA_States/FeatureServer/0',
  );
  assert.ok(arcTwin?.fetchUrl.endsWith('?f=json'));
  const arcDoc = arcTwin!.formatTwin(
    JSON.stringify({
      name: 'USA States',
      geometryType: 'esriGeometryPolygon',
      fields: [{ name: 'STATE_NAME', alias: 'State Name', type: 'esriFieldTypeString' }],
    }),
    'https://services.arcgis.com/P3ePLMYs2RVChkJx/arcgis/rest/services/USA_States/FeatureServer/0',
    simpleHtmlToMd,
  );
  assert.ok(arcDoc?.markdown.includes('`STATE_NAME`'));

  const legTwin = resolveSiteExtractorTwin('https://seattle.legistar.com/Legislation.aspx');
  assert.equal(legTwin?.fetchUrl, 'https://webapi.legistar.com/v1/seattle/matters?$top=25&$orderby=MatterIntroDate%20desc');
  const legDoc = legTwin!.formatTwin(
    JSON.stringify([{ MatterFile: 'CB 120999', MatterTypeName: 'Ordinance', MatterStatusName: 'Passed', MatterIntroDate: '2026-11-01', MatterTitle: 'Housing Zoning Update' }]),
    'https://seattle.legistar.com/Legislation.aspx',
    simpleHtmlToMd,
  );
  assert.ok(legDoc?.markdown.includes('CB 120999'));

  const usaTwin = resolveSiteExtractorTwin('https://www.usaspending.gov/award/CONT_AWD_1234');
  assert.equal(usaTwin?.fetchUrl, 'https://api.usaspending.gov/api/v2/awards/CONT_AWD_1234/');
  const usaDoc = usaTwin!.formatTwin(
    JSON.stringify({
      piid: 'NNK17MA01B',
      category: 'contract',
      total_obligation: 42000000,
      recipient: { recipient_name: 'Space Exploration Technologies Corp.' },
      awarding_agency: { toptier_agency: { name: 'NASA' } },
    }),
    'https://www.usaspending.gov/award/CONT_AWD_1234',
    simpleHtmlToMd,
  );
  assert.ok(usaDoc?.markdown.includes('Space Exploration Technologies Corp.'));
  assert.ok(usaDoc?.markdown.includes('$42.00M'));

  // 4. DOI/Crossref, OpenAlex, ClinicalTrials, PubChem, openFDA
  const doiTwin = resolveSiteExtractorTwin('https://doi.org/10.1038/s41586-021-03819-2');
  assert.equal(doiTwin?.fetchUrl, 'https://api.crossref.org/works/10.1038%2Fs41586-021-03819-2');
  const doiDoc = doiTwin!.formatTwin(
    JSON.stringify({
      message: {
        title: ['Highly accurate protein structure prediction with AlphaFold'],
        author: [{ given: 'John', family: 'Jumper' }],
        'container-title': ['Nature'],
        'is-referenced-by-count': 28500,
        abstract: '<jats:p>Proteins are essential to life.</jats:p>',
      },
    }),
    'https://doi.org/10.1038/s41586-021-03819-2',
    simpleHtmlToMd,
  );
  assert.ok(doiDoc?.markdown.includes('John Jumper'));
  assert.ok(doiDoc?.markdown.includes('28,500'));
  assert.ok(doiDoc?.markdown.includes('Proteins are essential to life.'));

  const oaTwin = resolveSiteExtractorTwin('https://openalex.org/W2741809807');
  const oaDoc = oaTwin!.formatTwin(
    JSON.stringify({
      display_name: 'State of OA',
      cited_by_count: 912,
      publication_date: '2018-02-13',
      authorships: [{ author: { display_name: 'Heather Piwowar' } }],
      abstract_inverted_index: { Open: [0], access: [1], literature: [2], grows: [3] },
    }),
    'https://openalex.org/W2741809807',
    simpleHtmlToMd,
  );
  assert.ok(oaDoc?.markdown.includes('Open access literature grows'));

  const ctHtml = `<html><head><meta property="og:title" content="Adaptive COVID-19 Treatment Trial"></head><body><script>window.__DATA__ = {"protocolSection":{"identificationModule":{"briefTitle":"Adaptive COVID-19 Treatment Trial (ACTT)"},"statusModule":{"overallStatus":"COMPLETED"},"designModule":{"phases":["PHASE3"]},"conditionsModule":{"conditions":["COVID-19"]},"descriptionModule":{"briefSummary":"A randomized placebo-controlled trial."}}};</script></body></html>`;
  const ctRes = applyPostFetchSiteExtractor(ctHtml, 'https://clinicaltrials.gov/study/NCT04280705', '', simpleHtmlToMd);
  assert.equal(ctRes?.extractorId, 'clinicaltrials');
  assert.ok(ctRes?.markdown.includes('NCT04280705'));
  assert.ok(ctRes?.markdown.includes('PHASE3'));

  const pubchemHtml = `<html><head><script type="application/ld+json">{"@type":"MolecularEntity","name":"Aspirin","molecularFormula":"C9H8O4","molecularWeight":"180.16 g/mol","inChIKey":"BSYNRYMUTXBXSQ-UHFFFAOYSA-N"}</script></head><body></body></html>`;
  const pcRes = applyPostFetchSiteExtractor(pubchemHtml, 'https://pubchem.ncbi.nlm.nih.gov/compound/2244', '', simpleHtmlToMd);
  assert.equal(pcRes?.extractorId, 'pubchem');
  assert.ok(pcRes?.markdown.includes('`C9H8O4`'));

  const fdaTwin = resolveSiteExtractorTwin('https://api.fda.gov/food/enforcement.json?limit=1');
  const fdaDoc = fdaTwin!.formatTwin(
    JSON.stringify({
      meta: { results: { total: 120 } },
      results: [{ recall_number: 'F-0100-2026', classification: 'Class I', status: 'Ongoing', recalling_firm: 'Acme Foods', reason_for_recall: 'Undeclared allergen' }],
    }),
    'https://api.fda.gov/food/enforcement.json?limit=1',
    simpleHtmlToMd,
  );
  assert.ok(fdaDoc?.markdown.includes('F-0100-2026'));

  // 5. Internet Archive, OpenRouter, App Stores, Shopify, OpenFoodFacts & HN Algolia
  const iaTwin = resolveSiteExtractorTwin('https://archive.org/details/apollo11-audio');
  const iaDoc = iaTwin!.formatTwin(
    JSON.stringify({
      metadata: { title: 'Apollo 11 Onboard Audio', creator: 'NASA', mediatype: 'audio', date: '1969-07-20' },
      files: [{ name: 'eagle_landing.flac', format: 'FLAC', size: '10485760' }],
    }),
    'https://archive.org/details/apollo11-audio',
    simpleHtmlToMd,
  );
  assert.ok(iaDoc?.markdown.includes('eagle_landing.flac'));

  const orTwin = resolveSiteExtractorTwin('https://openrouter.ai/qwen/qwen-2.5-coder-32b-instruct');
  const orDoc = orTwin!.formatTwin(
    JSON.stringify({
      data: [
        {
          id: 'qwen/qwen-2.5-coder-32b-instruct',
          name: 'Qwen 2.5 Coder 32B Instruct',
          context_length: 32768,
          pricing: { prompt: '0.0000002', completion: '0.0000002' },
          supported_parameters: ['tools', 'temperature'],
        },
      ],
    }),
    'https://openrouter.ai/qwen/qwen-2.5-coder-32b-instruct',
    simpleHtmlToMd,
  );
  assert.ok(orDoc?.markdown.includes('32,768 tokens'));
  assert.ok(orDoc?.markdown.includes('$0.20 / 1M tokens'));

  const shopTwin = resolveSiteExtractorTwin('https://allbirds.myshopify.com/products/tree-runners');
  const shopDoc = shopTwin!.formatTwin(
    JSON.stringify({
      product: {
        title: 'Tree Runners',
        vendor: 'Allbirds',
        body_html: '<p>Breathable eucalyptus fiber sneaker.</p>',
        variants: [{ title: 'Size 10', sku: 'TR-10', price: '98.00', available: true }],
      },
    }),
    'https://allbirds.myshopify.com/products/tree-runners',
    simpleHtmlToMd,
  );
  assert.ok(shopDoc?.markdown.includes('`TR-10`'));
  assert.ok(shopDoc?.markdown.includes('$98.00'));

  const customShopifyHtml = `<html><head><script>Shopify.shop = "allbirds.myshopify.com";</script><script type="application/ld+json">{"@type":"Product","name":"Wool Dasher","brand":{"name":"Allbirds"},"offers":[{"name":"Size 11","sku":"WD-11","price":"125.00","priceCurrency":"USD","availability":"https://schema.org/InStock"}]}</script></head><body></body></html>`;
  const customShop = applyPostFetchSiteExtractor(customShopifyHtml, 'https://www.allbirds.com/products/wool-dasher', '', simpleHtmlToMd);
  assert.equal(customShop?.extractorId, 'shopify');
  assert.ok(customShop?.markdown.includes('USD 125.00'));

  const hnTwin = resolveSiteExtractorTwin('https://news.ycombinator.com/item?id=41000000');
  assert.equal(hnTwin?.fetchUrl, 'https://hn.algolia.com/api/v1/items/41000000');
});

test('ADAPTER-4: job-hunt-kit ATS Fleet — Gem, Pinpoint, Rippling uuid dedup, Greenhouse/Lever EU, BambooHR junk guard, Oracle HCM & RemoteOK', () => {
  // Greenhouse EU board
  const ghEu = resolveAtsPreFetchSpec('https://eu-boards.greenhouse.io/celonis');
  assert.equal(ghEu?.fetchUrl, 'https://boards-api.eu.greenhouse.io/v1/boards/celonis/jobs?content=true');

  // Lever EU board
  const levEu = resolveAtsPreFetchSpec('https://jobs.eu.lever.co/spotify');
  assert.equal(levEu?.fetchUrl, 'https://api.eu.lever.co/v0/postings/spotify?mode=json');

  // Rippling locale-prefix strip + multi-location row merge on `uuid`
  const rip = resolveAtsPreFetchSpec('https://ats.rippling.com/en-GB/acme/jobs');
  assert.equal(rip?.fetchUrl, 'https://api.rippling.com/platform/api/ats/v1/board/acme/jobs');
  const ripFormatted = rip!.format(
    JSON.stringify([
      { uuid: 'u-1', name: 'Principal Distributed Systems Engineer', workLocation: { label: 'San Francisco, CA' } },
      { uuid: 'u-1', name: 'Principal Distributed Systems Engineer', workLocation: { label: 'Remote (US)' } },
      { uuid: 'u-2', name: 'Security Engineer', workLocation: { label: 'London, UK' } },
    ]),
    'https://ats.rippling.com/en-GB/acme/jobs',
    simpleHtmlToMd,
  );
  assert.equal(ripFormatted?.jobs?.length, 2, 'Rippling must deduplicate multi-location rows sharing a uuid');
  assert.equal(ripFormatted?.jobs?.[0]?.workplaceType, 'remote');
  assert.deepEqual(ripFormatted?.jobs?.[0]?.locations, ['San Francisco, CA', 'Remote (US)']);

  // BambooHR rejects `resources.bamboohr.com` marketing subdomain while allowing `<org>.bamboohr.com/careers`
  assert.equal(resolveSiteExtractorTwin('https://resources.bamboohr.com/careers'), null);
  assert.equal(resolveSiteExtractorTwin('https://acme.bamboohr.com/careers')?.fetchUrl, 'https://acme.bamboohr.com/careers/list');

  // Pinpoint, Gem, Teamtailor, JazzHR, Oracle HCM
  assert.equal(resolveSiteExtractorTwin('https://acme.pinpointhq.com/')?.fetchUrl, 'https://acme.pinpointhq.com/postings.json');
  assert.equal(resolveSiteExtractorTwin('https://jobs.gem.com/linear')?.fetchUrl, 'https://api.gem.com/job_board/v0/linear/job_posts/');
  assert.equal(resolveSiteExtractorTwin('https://acme.na.teamtailor.com/jobs')?.fetchUrl, 'https://acme.na.teamtailor.com/jobs.rss');
  assert.equal(resolveSiteExtractorTwin('https://acme.applytojob.com/apply')?.fetchUrl, 'https://app.jazz.co/feeds/export/jobs/acme');
  assert.ok(
    resolveSiteExtractorTwin('https://acme.fa.us2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1/requisitions')?.fetchUrl.includes(
      'recruitingCEJobRequisitions',
    ),
  );

  // RemoteOK skips index-0 legal notice object
  const rokTwin = resolveSiteExtractorTwin('https://remoteok.com/api');
  const rokDoc = rokTwin!.formatTwin(
    JSON.stringify([
      { legal: 'API Terms of Service — do not redistribute without attribution' },
      { position: 'Staff Go Engineer', company: 'EdgeCo', location: 'Worldwide', salary_min: 180000, salary_max: 220000, url: 'https://remoteok.com/remote-jobs/1' },
    ]),
    'https://remoteok.com/api',
    simpleHtmlToMd,
  );
  assert.ok(rokDoc?.title.includes('(1)'));
  assert.ok(rokDoc?.markdown.includes('Staff Go Engineer'));
});

test('ADAPTER-5: job-hunt-kit Reliability — Domain->ATS Auto-Discovery, Script-Stripped closed_posting, Greenhouse ?error=true, 4-State boardStatus & Safe Href Unescaping', async () => {
  // 1. Safe `&amp;`-only href unescaping (`&currentTime=` & `&section=` & `&region=` must NEVER turn into `¤tTime=`, `§ion=`, `®ion=`)
  const videoHtml = `<!doctype html><html><body><main><a href="https://example.com/watch?v=abc&amp;currentTime=90&section=2&region=us">Jump</a></main></body></html>`;
  const extracted = extractHtmlDocument(videoHtml, { baseUrl: 'https://example.com', onlyMainContent: true });
  assert.deepEqual(extracted.links, ['https://example.com/watch?v=abc&currentTime=90&section=2&region=us']);
  assert.ok(extracted.markdown.includes('https://example.com/watch?v=abc&currentTime=90&section=2&region=us'));

  // 2. Dayforce & Rippling `<script>` bundles containing "Page not found!" or "this job is no longer available" must NOT false-trigger closed_posting / soft_404!
  const liveJobWithNoisyScript = {
    status: 200,
    url: 'https://ats.rippling.com/acme/jobs/1234',
    title: 'Senior Backend Engineer',
    markdown: '# Senior Backend Engineer\n\nBuild resilient distributed systems in Go.\n<script>window.__I18N__={"err":"This job is no longer available","404":"Page not found!"};</script>',
    rawHtml: '<html><body><h1>Senior Backend Engineer</h1><script>const m = "This job is no longer available";</script></body></html>',
  };
  assert.equal(classifyContentState(liveJobWithNoisyScript).state, 'active');

  // 3. Closed Greenhouse posting silently 200-redirected to `?error=true` MUST deterministically classify as `closed_posting`!
  const ghClosedRedirect = classifyContentState({
    status: 200,
    url: 'https://boards.greenhouse.io/acme/jobs/9999999',
    finalUrl: 'https://job-boards.greenhouse.io/acme?error=true',
    title: 'Current Openings at Acme',
    markdown: '# Current Openings at Acme\n\nBrowse 45 open roles across Engineering and Product.',
  });
  assert.equal(ghClosedRedirect.state, 'closed_posting');

  // 4. Four-state `classifyAtsBoardStatus` (`ok` vs `empty_board` vs `wrong_slug` vs `blocked_or_down`)
  assert.equal(classifyAtsBoardStatus({ httpStatus: 200, requestedUrl: 'https://jobs.ashbyhq.com/acme', jobCount: 5 }), 'ok');
  assert.equal(classifyAtsBoardStatus({ httpStatus: 200, requestedUrl: 'https://jobs.ashbyhq.com/acme', jobCount: 0 }), 'empty_board');
  assert.equal(
    classifyAtsBoardStatus({
      httpStatus: 200,
      requestedUrl: 'https://nonexistent.bamboohr.com/careers',
      finalUrl: 'https://www.bamboohr.com/',
      jobCount: 0,
    }),
    'wrong_slug',
  );
  assert.equal(classifyAtsBoardStatus({ httpStatus: 403, requestedUrl: 'https://jobs.ashbyhq.com/acme' }), 'blocked_or_down');

  // 5. OpenStreetMap ethical robots.txt suggestion
  const osmBlocked = buildBlockedInfo('https://www.openstreetmap.org/node/12345', 'robots_disallowed', 'robots.txt disallowed /node/12345', 0);
  assert.equal(osmBlocked?.reason, 'robots');
  assert.ok(osmBlocked?.suggestion.includes('Nominatim'));

  // 6. Company Domain -> ATS Auto-Discovery (`discoverAtsBoardsFromHtml` + `executeJobsCall({ domains })`)
  const careersHtml = `
    <html><body>
      <script src="https://boards.greenhouse.io/embed/job_board/js?for=ffive"></script>
      <a href="https://boards.greenhouse.io/embed/job_board?for=embed">Ignored Junk</a>
      <a href="https://resources.bamboohr.com/careers">Ignored Marketing</a>
      <a href="https://panw.wd5.myworkdayjobs.com/en-US/panwexternalcareers/job/123">Workday</a>
      <a href="https://ats.rippling.com/en-GB/ripplingco/jobs">Rippling</a>
    </body></html>
  `;
  const boards = discoverAtsBoardsFromHtml({
    sourceUrl: 'https://f5.com/careers',
    rawHtml: careersHtml,
  });
  assert.deepEqual(
    boards.map((b) => `${b.platform}:${b.slug}:${b.boardUrl}`),
    [
      'greenhouse:ffive:https://job-boards.greenhouse.io/ffive',
      'workday:panw/panwexternalcareers:https://panw.wd5.myworkdayjobs.com/panwexternalcareers',
      'rippling:ripplingco:https://ats.rippling.com/ripplingco/jobs',
    ],
  );

  // Full end-to-end `executeJobsCall` with `domains: ["f5.com"]` and zero search query required!
  const jobsRes = await executeJobsCall({
    payload: { domains: ['f5.com'], remote: true },
    env: {},
    executeSearch: async () => ({ status: 200, body: { results: [] } }),
    executeScrape: async (args) => {
      if (args.url === 'https://f5.com/careers') {
        return {
          status: 200,
          body: {
            ok: true,
            finalUrl: 'https://f5.com/careers',
            rawHtml: '<a href="https://apply.workable.com/ffive/">View Open Roles</a>',
            links: ['https://apply.workable.com/ffive/'],
          },
        };
      }
      if (args.url === 'https://apply.workable.com/ffive/') {
        return {
          status: 200,
          body: {
            ok: true,
            jobs: [
              {
                title: 'Principal Edge Engineer',
                company: 'F5',
                url: 'https://apply.workable.com/ffive/j/EDGE01/',
                applyUrl: 'https://apply.workable.com/ffive/j/EDGE01/apply/',
                workplaceType: 'remote',
                locations: ['Remote (US)'],
                pay: { min: 195000, max: 235000, currency: 'USD', period: 'year', basis: 'base' },
                postedAt: '2026-11-19',
                source: 'workable',
              },
            ],
          },
        };
      }
      return { status: 404, body: { ok: false } };
    },
  });
  assert.equal(jobsRes.status, 200);
  assert.equal(jobsRes.body.count, 1);
  const discovered = jobsRes.body.discoveredBoards as Array<{ platform: string; slug: string; boardStatus: string }>;
  assert.equal(discovered[0]?.platform, 'workable');
  assert.equal(discovered[0]?.slug, 'ffive');
  assert.equal(discovered[0]?.boardStatus, 'ok');
});

test('ADAPTER-6: GET /v1/extractors authenticated catalog endpoint', async () => {
  const token = 'test-caller-secret-token-1234567890';
  const env = { CALLER_TOKEN: token } as unknown as Parameters<typeof worker.fetch>[1];

  const unauthRes = await worker.fetch(new Request('https://edgefetch.example/v1/extractors'), env);
  assert.equal(unauthRes.status, 401);

  const okRes = await worker.fetch(
    new Request('https://edgefetch.example/v1/extractors?category=public-records', {
      headers: { authorization: `Bearer ${token}` },
    }),
    env,
  );
  assert.equal(okRes.status, 200);
  const body = (await okRes.json()) as { ok: boolean; total: number; extractors: Array<{ id: string }> };
  assert.equal(body.ok, true);
  assert.equal(body.total, 5);
  assert.ok(body.extractors.some((e) => e.id === 'socrata'));
});
