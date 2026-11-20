import { defineAdapter } from '../../types';
import { decodeBasicEntities, stripScriptsAndStyles } from '../../utils';

export default defineAdapter({
  id: 'reddit-thread',
  name: 'Reddit Threads & Comments',
  category: 'commerce-social',
  description: 'Extracts shreddit-post prose, subreddit/author/score metadata, and nested shreddit-comment trees.',
  domains: ['reddit.com', '*.reddit.com'],
  exampleUrls: ['https://www.reddit.com/r/golang/comments/1abc123/single_binary_deployments/'],
  extractHtml({ path, rawHtml, baseUrl, htmlToMd }) {
    if (!/\/comments\/[A-Za-z0-9]+/i.test(path)) return null;
    const clean = stripScriptsAndStyles(rawHtml);
    const shPost = /<shreddit-post\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/shreddit-post>/i.exec(clean);
    if (!shPost) return null;

    const attrs = shPost[1]!;
    const pTitle = decodeBasicEntities(/\bpost-title=["']([^"']+)["']/i.exec(attrs)?.[1] ?? '');
    const author = decodeBasicEntities(/\bauthor=["']([^"']+)["']/i.exec(attrs)?.[1] ?? '');
    const score = /\bscore=["'](-?\d+)["']/i.exec(attrs)?.[1] ?? '';
    const sub = decodeBasicEntities(/\bsubreddit-prefixed-name=["']([^"']+)["']/i.exec(attrs)?.[1] ?? '');
    const bodyMd = htmlToMd(shPost[2]!, baseUrl).markdown.trim();
    if (!pTitle) return null;

    const sections = [`# ${pTitle}`];
    const meta = [sub, author ? `u/${author}` : '', score ? `${score} upvotes` : ''].filter(Boolean);
    if (meta.length > 0) sections.push(`*${meta.join(' · ')}*`);
    if (bodyMd) sections.push(bodyMd);

    const comments: string[] = [];
    for (const cm of clean.matchAll(/<shreddit-comment\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/shreddit-comment>/gi)) {
      if (comments.length >= 25) break;
      const cAuthor = decodeBasicEntities(/\bauthor=["']([^"']+)["']/i.exec(cm[1]!)?.[1] ?? 'user');
      const cScore = /\bscore=["'](-?\d+)["']/i.exec(cm[1]!)?.[1] ?? '';
      const cDepth = Math.min(5, Math.max(0, parseInt(/\bdepth=["'](\d+)["']/i.exec(cm[1]!)?.[1] ?? '0', 10)));
      const cMd = htmlToMd(cm[2]!, baseUrl).markdown.trim().replace(/\n+/g, ' ');
      if (cMd) comments.push(`${'  '.repeat(cDepth)}- **u/${cAuthor}**${cScore ? ` (${cScore})` : ''}: ${cMd}`);
    }
    if (comments.length > 0) sections.push(`## Comments\n\n${comments.join('\n')}`);
    return {
      extractorId: 'reddit-thread',
      title: pTitle,
      ...(author ? { author: `u/${author}` } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
