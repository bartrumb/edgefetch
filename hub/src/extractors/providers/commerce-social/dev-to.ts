import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'dev-to',
  name: 'DEV Community Articles (dev.to)',
  category: 'commerce-social',
  description: 'Upgrades dev.to/<author>/<slug> articles to dev.to/api/articles raw body_markdown.',
  domains: ['dev.to', 'www.dev.to'],
  exampleUrls: ['https://dev.to/gopher/writing-fuzz-tests'],
  resolveTwin({ parts }) {
    if (parts.length !== 2) return null;
    const reservedDev = new Set(['t', 'top', 'latest', 'pod', 'videos', 'tags', 'search', 'settings', 'enter', 'new', 'about', 'privacy', 'terms']);
    if (reservedDev.has(parts[0]!.toLowerCase()) || !/^[A-Za-z0-9_-]+$/.test(parts[0]!) || !/^[A-Za-z0-9_-]+$/.test(parts[1]!)) {
      return null;
    }
    return {
      id: 'dev-to',
      fetchUrl: `https://dev.to/api/articles/${parts[0]}/${parts[1]}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.title !== 'string' || typeof data.body_markdown !== 'string') return null;
        const title = data.title.trim();
        const desc = typeof data.description === 'string' ? data.description.trim() : undefined;
        const userObj = data.user as Record<string, unknown> | undefined;
        const author = typeof userObj?.name === 'string' ? userObj.name : undefined;
        const publishedTime = typeof data.published_timestamp === 'string' ? data.published_timestamp : undefined;
        const cleanBody = data.body_markdown.replace(/^---[\s\S]{0,1500}?---\n+/, '').trim();
        const md = cleanBody.startsWith('# ') ? cleanBody : `# ${title}\n\n${cleanBody}`;
        return {
          title,
          ...(desc ? { description: desc } : {}),
          ...(author ? { author } : {}),
          ...(publishedTime ? { publishedTime } : {}),
          markdown: md,
        };
      },
    };
  },
});
