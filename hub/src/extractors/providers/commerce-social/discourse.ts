import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'discourse-topic',
  name: 'Discourse Forum Threads (Universal Engine)',
  category: 'commerce-social',
  description: 'Upgrades any Discourse forum thread (/t/<slug>/<id>) to its .json post_stream with Accepted Solution badges.',
  domains: ['meta.discourse.org', 'community.home-assistant.io', 'users.rust-lang.org', 'discuss.python.org'],
  universalEngine: true,
  exampleUrls: ['https://community.home-assistant.io/t/websocket-reconnect-backoff/712345'],
  resolveTwin({ host, parts }) {
    if (parts[0] !== 't' || parts.length < 3 || !/^\d+$/.test(parts[2]!)) return null;
    // Do not hijack firecrawl.dev `/app/t/<teamId>/...` (parts[0] === 'app', so already safe, and require numeric topicId).
    const slug = parts[1]!;
    const topicId = parts[2]!;
    return {
      id: 'discourse-topic',
      fetchUrl: `https://${host}/t/${slug}/${topicId}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, _origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const postStream = data?.post_stream as { posts?: Array<Record<string, unknown>> } | undefined;
        const posts = Array.isArray(postStream?.posts) ? postStream.posts : [];
        if (posts.length === 0 || typeof data?.title !== 'string') return null;

        const title = data.title.trim();
        const tags = Array.isArray(data.tags) ? data.tags.map(String).filter(Boolean) : [];
        const acceptedObj = data.accepted_answer as { post_number?: number; username?: string; excerpt?: string } | undefined;
        const acceptedPostNum = typeof acceptedObj?.post_number === 'number' ? acceptedObj.post_number : -1;

        const sections: string[] = [`# ${title}`];
        if (tags.length > 0) sections.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);

        const allLinks: string[] = [];
        for (const p of posts.slice(0, 20)) {
          const postNum = typeof p.post_number === 'number' ? p.post_number : 0;
          const user = typeof p.username === 'string' ? `@${p.username}` : 'user';
          const created = typeof p.created_at === 'string' ? p.created_at.slice(0, 10) : '';
          const cooked = typeof p.cooked === 'string' ? p.cooked : '';
          if (!cooked.trim()) continue;
          const converted = htmlToMd(cooked, `https://${host}/t/${slug}/${topicId}`);
          for (const l of converted.links) {
            if (!allLinks.includes(l) && allLinks.length < 100) allLinks.push(l);
          }
          const badge = postNum === 1 ? 'Original Post' : postNum === acceptedPostNum ? '✅ Accepted Solution' : `Reply #${postNum}`;
          sections.push(`## ${badge} — ${user}${created ? ` (${created})` : ''}\n\n${converted.markdown.trim()}`);
        }
        const firstAuthor = typeof posts[0]?.username === 'string' ? String(posts[0].username) : undefined;
        const firstCreated = typeof posts[0]?.created_at === 'string' ? String(posts[0].created_at) : undefined;
        return {
          title,
          ...(firstAuthor ? { author: firstAuthor } : {}),
          ...(firstCreated ? { publishedTime: firstCreated } : {}),
          markdown: sections.join('\n\n'),
          links: allLinks,
        };
      },
    };
  },
});
