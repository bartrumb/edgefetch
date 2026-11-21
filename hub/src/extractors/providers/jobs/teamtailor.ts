import { defineAdapter, extractXmlTagTextLinear, findAllElementInnersLinear, findElementInnerLinear } from '../../types';
import { formatGfmTable, stripTagsInline } from '../../utils';

function parseRssJobsXml(rawXml: string, fallbackOrg: string): {
  title: string;
  markdown: string;
  links: string[];
} | null {
  if (!/<rss\b|<channel\b/i.test(rawXml)) return null;
  const chanHeader = rawXml.slice(0, 4000);
  const firstItemIdx = chanHeader.toLowerCase().indexOf('<item');
  const chanScope = firstItemIdx !== -1 ? chanHeader.slice(0, firstItemIdx) : chanHeader;
  const chanTitle = stripTagsInline(findElementInnerLinear(chanScope, 'title') ?? '') || fallbackOrg;
  const items = findAllElementInnersLinear(rawXml, 'item', undefined, 500);
  const title = `${chanTitle} — Open Roles (${items.length})`;
  if (items.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.`, links: [] };

  const extractTag = (xml: string, tag: string): string => stripTagsInline(extractXmlTagTextLinear(xml, tag));

  const links: string[] = [];
  const rows: Array<Array<string>> = [];
  for (const block of items.slice(0, 100)) {
    const jTitle = extractTag(block, 'title');
    const jLink = extractTag(block, 'link');
    if (!jTitle) continue;
    if (jLink.startsWith('https://')) links.push(jLink);
    const loc = extractTag(block, 'tt:location') || extractTag(block, 'g:location') || extractTag(block, 'location') || '-';
    const dept = extractTag(block, 'tt:department') || extractTag(block, 'category') || '-';
    const pubDate = extractTag(block, 'pubDate').slice(0, 16) || '-';
    rows.push([jLink.startsWith('https://') ? `[${jTitle}](${jLink})` : jTitle, dept, loc, pubDate]);
  }

  return {
    title,
    markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Location', 'Published'], rows)}`,
    links,
  };
}

export default defineAdapter({
  id: 'teamtailor',
  name: 'Teamtailor Career Portals',
  category: 'jobs',
  description: 'Upgrades <org>[.na].teamtailor.com career roots to their /jobs.rss feed with locations and departments.',
  domains: ['*.teamtailor.com'],
  exampleUrls: ['https://acme.teamtailor.com/', 'https://acme.na.teamtailor.com/jobs'],
  resolveTwin({ host, parts }) {
    const m = /^([a-z0-9-]+)(?:\.[a-z]{2})?\.teamtailor\.com$/i.exec(host);
    if (!m?.[1] || m[1] === 'www' || m[1] === 'app' || m[1] === 'career') return null;
    if (parts.length > 1 || (parts.length === 1 && parts[0] !== 'jobs')) return null;

    return {
      id: 'teamtailor',
      fetchUrl: `https://${host}/jobs.rss`,
      kind: 'text',
      accept: 'application/rss+xml',
      formatTwin: (rawBody) => parseRssJobsXml(rawBody, m[1]!),
    };
  },
});
