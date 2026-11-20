import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

function reconstructInvertedAbstract(inv: Record<string, unknown> | undefined): string {
  if (!inv || typeof inv !== 'object') return '';
  const words: string[] = [];
  for (const [token, positions] of Object.entries(inv)) {
    if (!Array.isArray(positions)) continue;
    for (const pos of positions) {
      if (typeof pos === 'number' && pos >= 0 && pos < 10000) {
        words[pos] = token;
      }
    }
  }
  return words.filter(Boolean).join(' ').trim();
}

export default defineAdapter({
  id: 'openalex',
  name: 'OpenAlex Scholarly Works',
  category: 'research-health',
  description: 'Upgrades openalex.org work URLs to api.openalex.org JSON with reconstructed abstracts, citations, open-access PDF links, and topics.',
  domains: ['openalex.org', 'www.openalex.org', 'api.openalex.org'],
  exampleUrls: ['https://openalex.org/W2741809807', 'https://openalex.org/works/W2741809807'],
  resolveTwin({ parts }) {
    const workId = parts[0] === 'works' && parts[1] ? parts[1] : parts[0];
    if (!workId || !/^W\d{5,15}$/i.test(workId)) return null;
    const normId = workId.toUpperCase();

    return {
      id: 'openalex',
      fetchUrl: `https://api.openalex.org/works/${normId}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof (data.display_name ?? data.title) !== 'string') return null;

        const title = String(data.display_name ?? data.title).trim();
        const pubDate = typeof data.publication_date === 'string' ? data.publication_date : '';
        const citedBy = typeof data.cited_by_count === 'number' ? data.cited_by_count.toLocaleString('en-US') : '';
        const doi = typeof data.doi === 'string' ? data.doi : '';
        const oaObj = data.open_access as Record<string, unknown> | undefined;
        const oaUrl = typeof oaObj?.oa_url === 'string' ? oaObj.oa_url : '';

        const authorships = Array.isArray(data.authorships) ? (data.authorships as Array<Record<string, unknown>>) : [];
        const authors = authorships
          .slice(0, 15)
          .map((a) => String((a.author as Record<string, unknown> | undefined)?.display_name ?? ''))
          .filter(Boolean);

        const abstract = reconstructInvertedAbstract(data.abstract_inverted_index as Record<string, unknown> | undefined);

        const bullets: string[] = [`- **OpenAlex ID**: \`${normId}\``];
        if (authors.length > 0) bullets.push(`- **Authors**: ${authors.join(', ')}`);
        if (pubDate) bullets.push(`- **Published**: ${pubDate}`);
        if (citedBy) bullets.push(`- **Citations**: ${citedBy}`);
        if (doi) bullets.push(`- **DOI**: ${doi}`);
        if (oaUrl.startsWith('https://')) bullets.push(`- **Open Access PDF**: ${oaUrl}`);

        const links = [doi, oaUrl].filter((u) => u.startsWith('https://'));
        const sections = [`# ${title}`, bullets.join('\n')];
        if (abstract) sections.push(`## Abstract\n\n${abstract}`);

        return {
          title,
          ...(abstract ? { description: abstract.slice(0, 260) } : {}),
          ...(authors.length > 0 ? { author: authors.slice(0, 4).join(', ') } : {}),
          ...(pubDate ? { publishedTime: pubDate } : {}),
          markdown: sections.join('\n\n'),
          links,
        };
      },
    };
  },
});
