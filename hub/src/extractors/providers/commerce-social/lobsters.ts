import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'lobsters',
  name: 'Lobste.rs Computing Stories',
  category: 'commerce-social',
  description: 'Upgrades lobste.rs/s/<id> story pages to their .json feed with nested plain-text comments.',
  domains: ['lobste.rs'],
  exampleUrls: ['https://lobste.rs/s/abc123/zero_alloc_go_parsers'],
  resolveTwin({ parts }) {
    if (parts[0] !== 's' || !parts[1] || !/^[A-Za-z0-9]{4,12}$/.test(parts[1])) return null;
    const shortId = parts[1];
    return {
      id: 'lobsters',
      fetchUrl: `https://lobste.rs/s/${shortId}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.title !== 'string') return null;
        const title = data.title.trim();
        const storyUrl = typeof data.url === 'string' && data.url ? data.url : '';
        const score = typeof data.score === 'number' ? data.score : 0;
        const user = typeof data.submitter_user === 'string' ? data.submitter_user : '';
        const created = typeof data.created_at === 'string' ? data.created_at : '';
        const tags = Array.isArray(data.tags) ? data.tags.map(String) : [];
        const descPlain = typeof data.description_plain === 'string' ? data.description_plain.trim() : '';
        const comments = Array.isArray(data.comments) ? (data.comments as Array<Record<string, unknown>>) : [];

        const metaParts = [`**Score**: ${score}`];
        if (user) metaParts.push(`**By**: @${user}`);
        if (tags.length > 0) metaParts.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);
        if (storyUrl) metaParts.push(`**Link**: ${storyUrl}`);

        const sections: string[] = [`# ${title}`, metaParts.join(' · ')];
        if (descPlain) sections.push(descPlain);

        if (comments.length > 0) {
          const commentLines: string[] = ['## Comments'];
          for (const c of comments.slice(0, 40)) {
            const cUser = typeof c.commenting_user === 'string' ? c.commenting_user : 'user';
            const cScore = typeof c.score === 'number' ? c.score : 0;
            const depth = typeof c.indent_level === 'number' ? Math.max(0, Math.min(6, c.indent_level - 1)) : 0;
            const indent = '  '.repeat(depth);
            const body = typeof c.comment_plain === 'string' ? c.comment_plain.trim().replace(/\n+/g, `\n${indent}  `) : '';
            if (body) commentLines.push(`${indent}- **@${cUser}** (${cScore} pts): ${body}`);
          }
          sections.push(commentLines.join('\n'));
        }

        return {
          title,
          ...(user ? { author: user } : {}),
          ...(created ? { publishedTime: created } : {}),
          markdown: sections.join('\n\n'),
          ...(storyUrl.startsWith('https://') ? { links: [storyUrl] } : {}),
        };
      },
    };
  },
});
