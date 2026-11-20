import { defineAdapter } from '../../types';
import { parseJsonObject, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'hackernews',
  name: 'Hacker News Stories & Who is Hiring (Algolia API)',
  category: 'commerce-social',
  description: 'Upgrades news.ycombinator.com/item?id=<id> threads (including monthly Who is Hiring threads) to hn.algolia.com/api/v1/items/<id> JSON.',
  domains: ['news.ycombinator.com'],
  exampleUrls: ['https://news.ycombinator.com/item?id=41000000'],
  resolveTwin({ url }) {
    if (url.pathname !== '/item') return null;
    const itemId = url.searchParams.get('id') ?? '';
    if (!/^\d{1,12}$/.test(itemId)) return null;

    return {
      id: 'hackernews',
      fetchUrl: `https://hn.algolia.com/api/v1/items/${itemId}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, _origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.id !== 'number') return null;

        const title = String(data.title || `HN Comment #${itemId}`).trim();
        const author = typeof data.author === 'string' ? data.author : '';
        const points = typeof data.points === 'number' ? data.points : null;
        const createdAt = typeof data.created_at === 'string' ? data.created_at : '';
        const storyUrl = typeof data.url === 'string' ? data.url : '';
        const storyText = typeof data.text === 'string' && data.text ? htmlToMd(data.text, 'https://news.ycombinator.com').markdown.trim() : '';

        const meta: string[] = [];
        if (points !== null) meta.push(`**Points**: ${points}`);
        if (author) meta.push(`**By**: ${author}`);
        if (createdAt) meta.push(`**Posted**: ${createdAt.slice(0, 10)}`);
        if (storyUrl) meta.push(`**URL**: ${storyUrl}`);

        const sections: string[] = [`# ${title}`];
        if (meta.length > 0) sections.push(meta.join(' · '));
        if (storyText) sections.push(storyText);

        const children = Array.isArray(data.children) ? (data.children as Array<Record<string, unknown>>) : [];
        const commentLines: string[] = [];
        const renderComments = (nodes: Array<Record<string, unknown>>, depth: number) => {
          for (const c of nodes) {
            if (commentLines.length >= 60) return;
            const cTextHtml = typeof c.text === 'string' ? c.text : '';
            if (!cTextHtml.trim()) continue;
            const cAuthor = typeof c.author === 'string' ? c.author : 'user';
            const cMd = htmlToMd(cTextHtml, 'https://news.ycombinator.com').markdown.trim();
            if (cMd) {
              const indent = '  '.repeat(Math.min(4, depth));
              const compact = depth === 0 ? cMd.replace(/\n+/g, `\n${indent}  `) : stripTagsInline(cTextHtml);
              commentLines.push(`${indent}- **${cAuthor}**: ${compact}`);
            }
            if (depth < 2 && Array.isArray(c.children)) {
              renderComments(c.children as Array<Record<string, unknown>>, depth + 1);
            }
          }
        };
        renderComments(children, 0);
        if (commentLines.length > 0) sections.push(`## Comments (${children.length} top-level)\n\n${commentLines.join('\n')}`);

        return {
          title,
          ...(author ? { author } : {}),
          ...(createdAt ? { publishedTime: createdAt } : {}),
          markdown: sections.join('\n\n'),
          ...(storyUrl.startsWith('https://') ? { links: [storyUrl] } : {}),
        };
      },
    };
  },
});
