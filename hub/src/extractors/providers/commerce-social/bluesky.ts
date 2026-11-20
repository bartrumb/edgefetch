import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'bluesky-thread',
  name: 'Bluesky ATProto Post Threads',
  category: 'commerce-social',
  description: 'Upgrades bsky.app post URLs to public.api.bsky.app ATProto getPostThread JSON with replies and embeds.',
  domains: ['bsky.app', 'staging.bsky.app'],
  exampleUrls: ['https://bsky.app/profile/golang.org/post/3lbxyz123'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'profile' || parts[2] !== 'post' || parts.length < 4) return null;
    const actor = decodeURIComponent(parts[1]!);
    const rkey = decodeURIComponent(parts[3]!);
    if (!/^[A-Za-z0-9._:-]+$/.test(actor) || !/^[A-Za-z0-9._-]+$/.test(rkey)) return null;
    const atUri = `at://${actor}/app.bsky.feed.post/${rkey}`;

    return {
      id: 'bluesky-thread',
      fetchUrl: `https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(atUri)}&depth=6`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const thread = data?.thread as Record<string, unknown> | undefined;
        const post = thread?.post as Record<string, unknown> | undefined;
        const record = post?.record as Record<string, unknown> | undefined;
        const authorObj = post?.author as Record<string, unknown> | undefined;
        if (!post || !record || typeof record.text !== 'string') return null;

        const handle = typeof authorObj?.handle === 'string' ? authorObj.handle : actor;
        const displayName = typeof authorObj?.displayName === 'string' && authorObj.displayName ? authorObj.displayName : handle;
        const createdAt = typeof record.createdAt === 'string' ? record.createdAt : '';
        const likes = typeof post.likeCount === 'number' ? post.likeCount : 0;
        const reposts = typeof post.repostCount === 'number' ? post.repostCount : 0;
        const title = `${displayName} (@${handle}) on Bluesky`;

        const embed = post.embed as Record<string, unknown> | undefined;
        const ext = embed?.external as Record<string, unknown> | undefined;
        const images = Array.isArray(embed?.images) ? (embed.images as Array<Record<string, unknown>>) : [];

        const sections: string[] = [
          `# ${title}`,
          record.text.trim(),
          `*Posted ${createdAt ? createdAt.slice(0, 16).replace('T', ' ') + ' UTC · ' : ''}${likes} likes · ${reposts} reposts*`,
        ];
        if (ext && typeof ext.uri === 'string') {
          sections.push(`> **Linked**: [${String(ext.title || ext.uri)}](${ext.uri})${ext.description ? ` — ${String(ext.description)}` : ''}`);
        }
        for (const img of images) {
          if (typeof img.alt === 'string' && img.alt.trim()) {
            sections.push(`- *Image alt*: ${img.alt.trim()}`);
          }
        }

        const replies = Array.isArray(thread?.replies) ? (thread.replies as Array<Record<string, unknown>>) : [];
        const replyLines: string[] = [];
        for (const rep of replies.slice(0, 15)) {
          const rp = rep.post as Record<string, unknown> | undefined;
          const rr = rp?.record as Record<string, unknown> | undefined;
          const ra = rp?.author as Record<string, unknown> | undefined;
          if (rr && typeof rr.text === 'string' && rr.text.trim()) {
            const rHandle = typeof ra?.handle === 'string' ? ra.handle : 'user';
            replyLines.push(`- **@${rHandle}**: ${rr.text.trim().replace(/\n+/g, ' ')}`);
          }
        }
        if (replyLines.length > 0) sections.push(`## Replies\n\n${replyLines.join('\n')}`);

        return {
          title,
          description: record.text.trim().slice(0, 220),
          author: `@${handle}`,
          ...(createdAt ? { publishedTime: createdAt } : {}),
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
});
