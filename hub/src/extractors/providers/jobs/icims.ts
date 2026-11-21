import {
  attrHasTokenLinear,
  defineAdapter,
  findAllOpenTagsLinear,
  findElementInnerLinear,
  findOpenTagLinear,
  getAttrValueLinear,
  type HtmlFragmentConverter,
  type TwinFormattedDoc,
} from '../../types';
import {
  extractBalancedDivAt,
  extractJsonLdObjects,
  formatGfmTable,
  stripScriptsAndStyles,
  stripTagsInline,
  unescapeHrefUrl,
} from '../../utils';

const ICIMS_EXCLUDED_SUBDOMAINS = new Set(['www', 'status', 'support', 'community', 'developer', 'developers', 'login']);

function formatIcimsHtml(
  rawHtml: string,
  origUrl: string,
  htmlToMd: HtmlFragmentConverter,
): TwinFormattedDoc | null {
  let u: URL;
  try {
    u = new URL(origUrl);
  } catch {
    return null;
  }

  const hostSlug = u.hostname.split('.')[0] ?? u.hostname;
  const isSingleJob = /\/jobs\/\d+(?:\/|$)/i.test(u.pathname);

  if (isSingleJob) {
    const ldObjects = extractJsonLdObjects(rawHtml);
    const jobLd = ldObjects.find((o) => /JobPosting/i.test(String(o['@type'] ?? '')));
    const clean = stripScriptsAndStyles(rawHtml);

    const title =
      (typeof jobLd?.title === 'string' ? stripTagsInline(jobLd.title) : '') ||
      stripTagsInline(findElementInnerLinear(clean, 'h1', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_Header')) ?? '') ||
      stripTagsInline(findElementInnerLinear(clean, 'h1') ?? '');
    if (!title) return null;

    const orgObj = jobLd?.hiringOrganization as Record<string, unknown> | string | undefined;
    const company =
      (typeof orgObj === 'string'
        ? stripTagsInline(orgObj)
        : typeof orgObj?.name === 'string'
          ? stripTagsInline(orgObj.name)
          : '') || hostSlug;

    const rawLocs = Array.isArray(jobLd?.jobLocation)
      ? jobLd.jobLocation
      : jobLd?.jobLocation
        ? [jobLd.jobLocation]
        : [];
    const locations: string[] = [];
    for (const loc of rawLocs) {
      if (loc && typeof loc === 'object') {
        const addr = ((loc as Record<string, unknown>).address ?? loc) as Record<string, unknown>;
        const parts = [addr.addressLocality, addr.addressRegion, addr.addressCountry]
          .map((x) => (typeof x === 'string' ? x.trim() : ''))
          .filter(Boolean);
        if (parts.length > 0) locations.push(parts.join(', '));
      }
    }

    const descOpen =
      findOpenTagLinear(clean, 'div', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_JobContent')) ??
      findOpenTagLinear(clean, 'div', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_InfoMsg_Job'));
    const descHtml =
      (typeof jobLd?.description === 'string' && jobLd.description.trim() ? jobLd.description : '') ||
      (descOpen ? extractBalancedDivAt(clean, descOpen.index) ?? '' : '');
    const bodyMd = descHtml ? htmlToMd(descHtml, origUrl).markdown.trim() : '';
    if (!bodyMd && !jobLd) return null;

    const posted = typeof jobLd?.datePosted === 'string' ? jobLd.datePosted.slice(0, 10) : '';
    const empType = typeof jobLd?.employmentType === 'string' ? jobLd.employmentType : '';
    const canonicalJobUrl = new URL(u.toString());
    canonicalJobUrl.searchParams.delete('in_iframe');

    const bullets = [`- **Company**: ${company}`];
    if (locations.length > 0) bullets.push(`- **Location**: ${locations.join('; ')}`);
    if (empType) bullets.push(`- **Employment Type**: ${empType}`);
    if (posted) bullets.push(`- **Posted**: ${posted}`);

    return {
      title: `${title} @ ${company}`,
      ...(posted ? { publishedTime: posted } : {}),
      markdown: [`# ${title} @ ${company}`, bullets.join('\n'), bodyMd].filter(Boolean).join('\n\n'),
      links: [canonicalJobUrl.toString()],
    };
  }

  // iCIMS Search / Board listing (`/jobs/search?in_iframe=1` or `/jobs/intro`)
  const clean = stripScriptsAndStyles(rawHtml);
  const anchorOpens = findAllOpenTagsLinear(clean, 'a', (a) => {
    const href = getAttrValueLinear(a, 'href') ?? '';
    return /\/jobs\/\d+\//i.test(href);
  }, 200);

  const byId = new Map<string, { id: string; title: string; url: string }>();
  for (const ao of anchorOpens) {
    const rawHref = unescapeHrefUrl(getAttrValueLinear(ao.attrStr, 'href') ?? '');
    const idMatch = /\/jobs\/(\d+)\//i.exec(rawHref);
    if (!idMatch?.[1]) continue;
    const jobId = idMatch[1];
    if (byId.has(jobId)) continue;

    const closeIdx = clean.toLowerCase().indexOf('</a>', ao.openEnd);
    const anchorInner = closeIdx !== -1 ? clean.slice(ao.openEnd, closeIdx) : '';
    const linkTitle =
      stripTagsInline(anchorInner).replace(/^Job\s+Title\s*/i, '').trim() ||
      (getAttrValueLinear(ao.attrStr, 'title') ?? '').trim();
    if (!linkTitle) continue;

    let resolvedUrl = '';
    try {
      const targetU = new URL(rawHref, u.origin);
      targetU.searchParams.delete('in_iframe');
      if (targetU.protocol === 'https:') resolvedUrl = targetU.toString();
    } catch {
      continue;
    }
    if (!resolvedUrl) continue;
    byId.set(jobId, { id: jobId, title: linkTitle, url: resolvedUrl });
  }

  if (byId.size === 0 && !rawHtml.includes('iCIMS')) return null;

  const jobs = [...byId.values()];
  const title = `${hostSlug} — iCIMS Career Portal (${jobs.length} open roles)`;
  if (jobs.length === 0) {
    return {
      title,
      markdown: `# ${title}\n\nNo open positions currently listed.`,
      links: [],
      records: [],
      total: 0,
      returned: 0,
      truncated: false,
    };
  }

  const links = jobs.map((j) => j.url);
  const rows = jobs.slice(0, 100).map((j) => [`[${j.title}](${j.url})`, `\`${j.id}\``]);
  return {
    title,
    markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Job ID'], rows)}`,
    links,
    records: jobs.map((j) => ({ id: j.id, title: j.title, company: hostSlug, url: j.url, source: 'icims' })),
    total: jobs.length,
    returned: rows.length,
    truncated: jobs.length > rows.length,
  };
}

export default defineAdapter({
  id: 'icims',
  name: 'iCIMS Enterprise Career Portals',
  category: 'jobs',
  description:
    'Upgrades *.icims.com/jobs/... portals and postings to their server-rendered ?in_iframe=1 twin, extracting JobPosting JSON-LD and open role links without outer iframe shells.',
  domains: ['*.icims.com'],
  exampleUrls: [
    'https://careers-acme.icims.com/jobs/search?ss=1',
    'https://careers-acme.icims.com/jobs/12345/senior-software-engineer/job',
  ],
  resolveTwin({ url, host, path }) {
    const subMatch = /^([a-z0-9-]+)\.icims\.com$/i.exec(host);
    if (!subMatch?.[1] || ICIMS_EXCLUDED_SUBDOMAINS.has(subMatch[1].toLowerCase())) return null;
    if (!/^\/jobs(?:\/|$)/i.test(path)) return null;

    const twinUrl = new URL(url.toString());
    if (/^\/jobs\/?(?:intro)?\/?$/i.test(twinUrl.pathname)) {
      twinUrl.pathname = '/jobs/search';
      if (!twinUrl.searchParams.has('ss')) twinUrl.searchParams.set('ss', '1');
    }
    twinUrl.searchParams.set('in_iframe', '1');

    return {
      id: 'icims',
      fetchUrl: twinUrl.toString(),
      kind: 'text',
      accept: 'text/html,application/xhtml+xml',
      formatTwin: (rawBody, origUrl, htmlToMd) => formatIcimsHtml(rawBody, origUrl, htmlToMd),
    };
  },
  extractHtml({ url, host, path, rawHtml, htmlToMd }) {
    const subMatch = /^([a-z0-9-]+)\.icims\.com$/i.exec(host);
    if (!subMatch?.[1] || ICIMS_EXCLUDED_SUBDOMAINS.has(subMatch[1].toLowerCase())) return null;
    if (!/^\/jobs(?:\/|$)/i.test(path)) return null;
    const formatted = formatIcimsHtml(rawHtml, url.toString(), htmlToMd);
    if (!formatted) return null;
    return {
      extractorId: 'icims',
      title: formatted.title,
      ...(formatted.publishedTime ? { publishedTime: formatted.publishedTime } : {}),
      markdown: formatted.markdown,
      links: formatted.links,
      records: formatted.records,
      total: formatted.total,
      returned: formatted.returned,
      truncated: formatted.truncated,
    };
  },
});
