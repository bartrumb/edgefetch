import { defineAdapter } from '../../types';
import { formatGfmTable, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'jazzhr',
  name: 'JazzHR Career Boards (applytojob.com)',
  category: 'jobs',
  description: 'Upgrades <org>.applytojob.com boards to app.jazz.co/feeds/export/jobs/<org> XML export (which includes full job descriptions and returns clean 404 on invalid slugs).',
  domains: ['*.applytojob.com'],
  exampleUrls: ['https://acme.applytojob.com/apply'],
  resolveTwin({ host, parts }) {
    const m = /^([a-z0-9-]+)\.applytojob\.com$/i.exec(host);
    if (!m?.[1] || m[1] === 'www' || m[1] === 'app') return null;
    const org = m[1];
    // Board root or `/apply`
    if (parts.length > 1) return null;

    return {
      id: 'jazzhr',
      fetchUrl: `https://app.jazz.co/feeds/export/jobs/${encodeURIComponent(org)}`,
      kind: 'text',
      accept: 'application/xml, text/xml',
      formatTwin: (rawBody) => {
        if (!/<jobs\b|<job\b/i.test(rawBody)) return null;
        const jobBlocks = [...rawBody.matchAll(/<job\b[^>]*>([\s\S]*?)<\/job>/gi)];
        const extractTag = (xml: string, tag: string): string => {
          const tm = new RegExp(`<${tag}\\b[^>]*>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))<\\/${tag}>`, 'i').exec(xml);
          return stripTagsInline(tm?.[1] ?? tm?.[2] ?? '');
        };

        const title = `${org} — JazzHR Job Board (${jobBlocks.length} open roles)`;
        if (jobBlocks.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
        const links: string[] = [];
        const rows: Array<Array<string>> = [];
        for (const jb of jobBlocks.slice(0, 100)) {
          const b = jb[1]!;
          const jTitle = extractTag(b, 'title');
          if (!jTitle) continue;
          const jUrl = extractTag(b, 'url');
          if (jUrl.startsWith('https://')) links.push(jUrl);
          const loc = [extractTag(b, 'city'), extractTag(b, 'state'), extractTag(b, 'country')].filter(Boolean).join(', ') || '-';
          const dept = extractTag(b, 'department') || '-';
          const jType = extractTag(b, 'type') || '-';
          rows.push([jUrl.startsWith('https://') ? `[${jTitle}](${jUrl})` : jTitle, dept, loc, jType]);
        }

        return {
          title,
          markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Location', 'Type'], rows)}`,
          links,
        };
      },
    };
  },
});
