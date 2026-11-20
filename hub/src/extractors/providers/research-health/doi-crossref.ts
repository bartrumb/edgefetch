import { defineAdapter } from '../../types';
import { parseJsonObject, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'doi-crossref',
  name: 'DOI.org & Crossref Bibliographic Resolver',
  category: 'research-health',
  description: 'Upgrades doi.org/10.<prefix>/<suffix> links to api.crossref.org/works/<doi> bibliographic JSON (authors, venue, citations, JATS abstract, and publisher URL).',
  domains: ['doi.org', 'www.doi.org', 'dx.doi.org'],
  exampleUrls: ['https://doi.org/10.1038/s41586-021-03819-2'],
  resolveTwin({ url }) {
    const rawDoi = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
    if (!/^10\.\d{4,9}\/\S+$/.test(rawDoi)) return null;

    return {
      id: 'doi-crossref',
      fetchUrl: `https://api.crossref.org/works/${encodeURIComponent(rawDoi)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const msg = data?.message as Record<string, unknown> | undefined;
        if (!msg) return null;

        const titleArr = Array.isArray(msg.title) ? msg.title.map(String) : [];
        const title = stripTagsInline(titleArr[0] ?? rawDoi);
        if (!title) return null;

        const authorsArr = Array.isArray(msg.author) ? (msg.author as Array<Record<string, unknown>>) : [];
        const authors = authorsArr
          .slice(0, 16)
          .map((a) => [a.given, a.family].filter((x) => typeof x === 'string' && x).join(' ') || String(a.name ?? ''))
          .filter(Boolean);

        const containerArr = Array.isArray(msg['container-title']) ? msg['container-title'].map(String) : [];
        const venue = containerArr[0] ?? '';
        const publisher = typeof msg.publisher === 'string' ? msg.publisher : '';
        const citations = typeof msg['is-referenced-by-count'] === 'number' ? msg['is-referenced-by-count'] : null;
        const pubUrl = typeof msg.URL === 'string' ? msg.URL : `https://doi.org/${rawDoi}`;

        const issued = (msg.issued as Record<string, unknown> | undefined)?.['date-parts'] as number[][] | undefined;
        const dateParts = Array.isArray(issued?.[0]) ? issued[0] : [];
        const pubDate = dateParts.length > 0 ? dateParts.map((n, idx) => (idx === 0 ? String(n) : String(n).padStart(2, '0'))).join('-') : '';

        const rawAbstract = typeof msg.abstract === 'string' ? msg.abstract : '';
        const cleanAbstract = rawAbstract
          ? stripTagsInline(rawAbstract.replace(/<\/?jats:[^>]+>/gi, ' ').replace(/^Abstract\s+/i, ''))
          : '';

        const bullets: string[] = [`- **DOI**: \`${rawDoi}\``];
        if (authors.length > 0) bullets.push(`- **Authors**: ${authors.join(', ')}`);
        if (venue) bullets.push(`- **Venue / Journal**: ${venue}${publisher ? ` (${publisher})` : ''}`);
        if (pubDate) bullets.push(`- **Published**: ${pubDate}`);
        if (citations !== null) bullets.push(`- **Cited By (Crossref)**: ${citations.toLocaleString('en-US')}`);
        if (pubUrl.startsWith('https://')) bullets.push(`- **Publisher Link**: ${pubUrl}`);

        const sections = [`# ${title}`, bullets.join('\n')];
        if (cleanAbstract) sections.push(`## Abstract\n\n${cleanAbstract}`);

        return {
          title,
          ...(cleanAbstract ? { description: cleanAbstract.slice(0, 260) } : {}),
          ...(authors.length > 0 ? { author: authors.slice(0, 4).join(', ') } : {}),
          ...(pubDate ? { publishedTime: pubDate } : {}),
          markdown: sections.join('\n\n'),
          links: pubUrl.startsWith('https://') ? [pubUrl] : [],
        };
      },
    };
  },
});
