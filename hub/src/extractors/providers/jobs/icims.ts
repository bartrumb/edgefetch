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

interface IcimsParsedCard {
  id: string;
  title: string;
  url: string;
  location: string;
  pay: string;
  postedAt: string;
}

function parseIcimsCardDetails(cardHtml: string): { location: string; pay: string; postedAt: string } {
  let location = '';
  let pay = '';
  let postedAt = '';

  const spanTags = findAllOpenTagsLinear(cardHtml, 'span', (a) => Boolean(getAttrValueLinear(a, 'title')), 12);
  for (const st of spanTags) {
    const tVal = (getAttrValueLinear(st.attrStr, 'title') ?? '').trim();
    if (/^\d{1,2}\/\d{1,2}\/\d{4}\b/.test(tVal)) {
      postedAt = tVal.split(/\s+/)[0] ?? tVal;
      break;
    }
  }

  const tagDivs = findAllOpenTagsLinear(cardHtml, 'div', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_JobHeaderTag'), 16);
  for (const td of tagDivs) {
    const block = extractBalancedDivAt(cardHtml, td.index);
    if (!block) continue;
    const dtTxt = stripTagsInline(findElementInnerLinear(block, 'dt') ?? '').toLowerCase();
    const ddTxt = stripTagsInline(findElementInnerLinear(block, 'dd') ?? '');
    if (!ddTxt) continue;
    if (!location && dtTxt.includes('location')) {
      location = ddTxt;
    } else if (!pay && (dtTxt.includes('salary') || dtTxt.includes('pay') || dtTxt.includes('compensation'))) {
      pay = ddTxt;
    }
  }

  if (!location || !pay) {
    const dts = findAllOpenTagsLinear(cardHtml, 'dt', undefined, 16);
    for (let k = 0; k < dts.length; k++) {
      const dtOpen = dts[k]!;
      const dtEnd = cardHtml.toLowerCase().indexOf('</dt>', dtOpen.openEnd);
      if (dtEnd === -1) continue;
      const dtTxt = stripTagsInline(cardHtml.slice(dtOpen.openEnd, dtEnd)).toLowerCase();
      const nextBound = k + 1 < dts.length ? dts[k + 1]!.index : cardHtml.length;
      const ddHtml = findElementInnerLinear(cardHtml.slice(dtEnd + 5, nextBound), 'dd');
      const ddTxt = stripTagsInline(ddHtml ?? '');
      if (!ddTxt) continue;
      if (!location && dtTxt.includes('location')) {
        location = ddTxt;
      } else if (!pay && (dtTxt.includes('salary') || dtTxt.includes('pay') || dtTxt.includes('compensation'))) {
        pay = ddTxt;
      }
    }
  }

  return { location, pay, postedAt };
}

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

  // iCIMS Search / Board listing (`/jobs/search?ss=1&in_iframe=1` or `/jobs/intro`)
  const clean = stripScriptsAndStyles(rawHtml);
  const cardStarts = [
    ...findAllOpenTagsLinear(clean, 'li', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_JobCardItem'), 200),
    ...findAllOpenTagsLinear(clean, 'div', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_JobCardItem'), 200),
  ].sort((a, b) => a.index - b.index);
  const cardSlicesByJobId = new Map<string, string>();
  for (let i = 0; i < cardStarts.length; i++) {
    const start = cardStarts[i]!.index;
    const end = i + 1 < cardStarts.length ? cardStarts[i + 1]!.index : Math.min(clean.length, start + 12_000);
    const slice = clean.slice(start, end);
    const idM = /\/jobs\/(\d+)\//i.exec(slice);
    if (idM?.[1] && !cardSlicesByJobId.has(idM[1])) {
      cardSlicesByJobId.set(idM[1], slice);
    }
  }

  const anchorOpens = findAllOpenTagsLinear(
    clean,
    'a',
    (a) => {
      const href = getAttrValueLinear(a, 'href') ?? '';
      return /\/jobs\/\d+\//i.test(href);
    },
    200,
  );

  const byId = new Map<string, IcimsParsedCard>();
  for (const ao of anchorOpens) {
    const rawHref = unescapeHrefUrl(getAttrValueLinear(ao.attrStr, 'href') ?? '');
    const idMatch = /\/jobs\/(\d+)\//i.exec(rawHref);
    if (!idMatch?.[1]) continue;
    const jobId = idMatch[1];
    if (byId.has(jobId)) continue;

    const closeIdx = clean.toLowerCase().indexOf('</a>', ao.openEnd);
    const anchorInner = closeIdx !== -1 ? clean.slice(ao.openEnd, closeIdx) : '';
    const h3Inner = findElementInnerLinear(anchorInner, 'h3');
    const rawTitleAttr = (getAttrValueLinear(ao.attrStr, 'title') ?? '').replace(/^\d+\s*-\s*/, '').trim();
    const linkTitle =
      stripTagsInline(h3Inner ?? anchorInner)
        .replace(/^(?:Job\s+Title|Title)\s+/i, '')
        .trim() || rawTitleAttr;
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

    const cardHtml = cardSlicesByJobId.get(jobId) ?? '';
    const meta = cardHtml ? parseIcimsCardDetails(cardHtml) : { location: '', pay: '', postedAt: '' };
    byId.set(jobId, { id: jobId, title: linkTitle, url: resolvedUrl, ...meta });
  }

  const jobs = [...byId.values()];
  if (jobs.length === 0) {
    // Never emit a confident false zero (`total: 0`) on an outer iframe shell or unsubmitted search form!
    // Only report `0` when iCIMS explicitly renders its zero-results message inside the search frame.
    const plainBody = stripTagsInline(clean);
    const explicitZero =
      /\b(?:no\s+results\s+found|sorry,\s+no\s+jobs|currently\s+no\s+open\s+positions|there\s+are\s+currently\s+no\s+open|0\s+results\s+available)\b/i.test(
        plainBody,
      );
    if (!explicitZero) {
      return null;
    }
    const emptyTitle = `${hostSlug} — iCIMS Career Portal (0 open roles)`;
    return {
      title: emptyTitle,
      markdown: `# ${emptyTitle}\n\nNo open positions currently listed.`,
      links: [],
      records: [],
      total: 0,
      returned: 0,
      truncated: false,
    };
  }

  const plainHeader = stripTagsInline(clean.slice(0, 80_000));
  const pageMatch = /\bPage\s+(\d+)\s+of\s+(\d+)\b/i.exec(plainHeader);
  const curPage = pageMatch?.[1] ? Math.max(1, parseInt(pageMatch[1], 10) || 1) : 1;
  const totalPages = pageMatch?.[2] ? Math.max(1, parseInt(pageMatch[2], 10) || 1) : 1;
  const hasNextRel = clean.includes('rel="next"') || clean.includes("rel='next'");
  const hasMorePages = curPage < totalPages || (totalPages === 1 && hasNextRel);

  const portalHeading = stripTagsInline(
    findElementInnerLinear(clean, 'h1', (a) => attrHasTokenLinear(a, 'class', 'iCIMS_Header')) ?? '',
  );
  const companyLabel = portalHeading ? portalHeading.replace(/\s*Career\s+Listings\s*$/i, '').trim() || hostSlug : hostSlug;

  const links = jobs.map((j) => j.url);
  const rows = jobs.slice(0, 100).map((j) => [
    `[${j.title}](${j.url})`,
    `\`${j.id}\``,
    j.location || '-',
    j.pay || '-',
  ]);
  const isTruncated = hasMorePages || jobs.length > rows.length;
  const title =
    totalPages > 1
      ? `${companyLabel} — iCIMS Career Portal (Page ${curPage} of ${totalPages}, ${rows.length} shown)`
      : `${companyLabel} — iCIMS Career Portal (${jobs.length} open roles)`;

  return {
    title,
    markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Job ID', 'Location', 'Salary'], rows)}`,
    links,
    records: jobs.map((j) => ({
      id: j.id,
      title: j.title,
      company: companyLabel,
      url: j.url,
      ...(j.location ? { location: j.location, locations: [j.location] } : {}),
      ...(j.pay ? { payRaw: j.pay, salary: j.pay } : {}),
      ...(j.postedAt ? { postedAt: j.postedAt } : {}),
      source: 'icims',
    })),
    ...(!hasMorePages ? { total: jobs.length } : {}),
    returned: rows.length,
    truncated: isTruncated,
    ...(hasMorePages ? { nextCursor: `pr=${curPage}` } : jobs.length > rows.length ? { nextCursor: String(rows.length) } : {}),
  };
}

export default defineAdapter({
  id: 'icims',
  name: 'iCIMS Enterprise Career Portals',
  category: 'jobs',
  description:
    'Upgrades *.icims.com/jobs/... portals and postings to their server-rendered ?ss=1&in_iframe=1 twin, extracting JobPosting JSON-LD and open role cards without outer iframe shells.',
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
    if (/^\/jobs\/?(?:intro|search)?\/?$/i.test(twinUrl.pathname)) {
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
      ...(formatted.total !== undefined ? { total: formatted.total } : {}),
      ...(formatted.returned !== undefined ? { returned: formatted.returned } : {}),
      ...(formatted.truncated !== undefined ? { truncated: formatted.truncated } : {}),
      ...(formatted.nextCursor !== undefined ? { nextCursor: formatted.nextCursor } : {}),
    };
  },
});
