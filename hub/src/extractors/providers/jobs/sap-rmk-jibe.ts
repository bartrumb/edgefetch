import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'sap-rmk-jibe',
  name: 'SAP SuccessFactors RMK & Jibe Enterprise Career Feeds',
  category: 'jobs',
  description: 'Formats Jibe /api/jobs JSON feeds and SAP SuccessFactors Recruiting Marketing (RMK) /sitemap.xml RSS job feeds.',
  domains: ['careers.*.com', 'jobs.*.com'],
  universalEngine: true,
  exampleUrls: [
    'https://careers.rivian.com/api/jobs?page=1&limit=25',
    'https://jobs.sap.com/sitemap.xml',
  ],
  resolveTwin({ url, urlStr }) {
    // Jibe enterprise career JSON (`/api/jobs?page=...`)
    if (url.pathname === '/api/jobs') {
      return {
        id: 'jibe-careers',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
          if (!jobs) return null;
          // Jibe wraps each job inside `{ data: { title, req_id, full_location, apply_url, ... } }`
          if (jobs.length > 0 && !jobs[0]?.data) return null;
          const total = typeof data?.totalCount === 'number' ? data.totalCount : jobs.length;
          const title = `${url.hostname} — Jibe Career Feed (${jobs.length} of ${total} open roles)`;
          const links: string[] = [];
          const rows = jobs.slice(0, 80).map((wrapper) => {
            const d = (wrapper.data as Record<string, unknown> | undefined) ?? wrapper;
            const jTitle = String(d.title ?? 'Role').trim();
            const reqId = String(d.req_id || d.slug || '');
            const loc = String(d.full_location || [d.city, d.state, d.country].filter(Boolean).join(', ') || '-');
            const cat = Array.isArray(d.categories)
              ? (d.categories as Array<Record<string, unknown>>).map((c) => String(c.name ?? '')).filter(Boolean).join(', ')
              : String(d.category ?? '-');
            const applyUrl = typeof d.meta_data === 'object' && d.meta_data && typeof (d.meta_data as Record<string, unknown>).canonical_url === 'string'
              ? String((d.meta_data as Record<string, unknown>).canonical_url)
              : typeof d.apply_url === 'string' && d.apply_url.startsWith('https://')
                ? d.apply_url
                : '';
            if (applyUrl.startsWith('https://')) links.push(applyUrl);
            return [applyUrl.startsWith('https://') ? `[${jTitle}](${applyUrl})` : jTitle, reqId ? `\`${reqId}\`` : '-', cat || '-', loc];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Req ID', 'Category', 'Location'], rows)}`,
            links,
          };
        },
      };
    }
    return null;
  },
  extractHtml({ path, host, rawHtml }) {
    // SAP SuccessFactors RMK `/sitemap.xml` is actually an RSS `<channel><item>` feed with `<g:location>` & `<g:employer>`!
    if (!/sitemap\.xml$/i.test(path)) return null;
    if (!/<g:location>|<g:employer>/i.test(rawHtml.slice(0, 20000))) return null;
    const items = [...rawHtml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)];
    if (items.length === 0) return null;

    const extractTag = (xml: string, tag: string): string => {
      const m = new RegExp(`<${tag}\\b[^>]*>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))<\\/${tag}>`, 'i').exec(xml);
      return stripTagsInline(m?.[1] ?? m?.[2] ?? '');
    };

    const employer = extractTag(items[0]![1]!, 'g:employer') || host;
    const title = `${employer} — SAP RMK Job Feed (${items.length} open roles)`;
    const links: string[] = [];
    const rows = items.slice(0, 100).map((it) => {
      const b = it[1]!;
      const jTitle = extractTag(b, 'title') || 'Role';
      const jLink = extractTag(b, 'link');
      if (jLink.startsWith('https://')) links.push(jLink);
      const loc = extractTag(b, 'g:location') || '-';
      const jId = extractTag(b, 'g:id') || '-';
      return [jLink.startsWith('https://') ? `[${jTitle}](${jLink})` : jTitle, jId, loc];
    });

    return {
      extractorId: 'sap-rmk',
      title,
      markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Req ID', 'Location'], rows)}`,
      links,
    };
  },
});
