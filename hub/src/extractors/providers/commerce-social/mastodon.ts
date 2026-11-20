import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'mastodon-status',
  name: 'Mastodon & Fediverse Statuses (Universal Engine)',
  category: 'commerce-social',
  description: 'Upgrades Fediverse status permalinks (/@<user>/<numericId>) on any Mastodon instance to /api/v1/statuses/<id> JSON.',
  domains: ['mastodon.social', 'fosstodon.org', 'hachyderm.io'],
  universalEngine: true,
  exampleUrls: ['https://fosstodon.org/@user/113456789012345678'],
  resolveTwin({ host, parts }) {
    if (
      parts.length !== 2 ||
      !parts[0]!.startsWith('@') ||
      parts[0]!.length < 2 ||
      !/^\d{15,24}$/.test(parts[1]!) ||
      host === 'medium.com' ||
      host.endsWith('.medium.com') ||
      host === 'tiktok.com' ||
      host.endsWith('.tiktok.com') ||
      host === 'threads.net' ||
      host.endsWith('.threads.net')
    ) {
      return null;
    }
    const statusId = parts[1]!;
    return {
      id: 'mastodon-status',
      fetchUrl: `https://${host}/api/v1/statuses/${statusId}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, _origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const acctObj = data?.account as Record<string, unknown> | undefined;
        if (!data || typeof data.content !== 'string' || !acctObj || typeof acctObj.acct !== 'string') return null;
        const displayName = typeof acctObj.display_name === 'string' && acctObj.display_name ? acctObj.display_name : acctObj.acct;
        const createdAt = typeof data.created_at === 'string' ? data.created_at : '';
        const spoiler = typeof data.spoiler_text === 'string' ? data.spoiler_text.trim() : '';
        const converted = htmlToMd(data.content, `https://${host}`);
        const media = Array.isArray(data.media_attachments) ? (data.media_attachments as Array<Record<string, unknown>>) : [];
        const title = `${displayName} (@${acctObj.acct}@${host})`;

        const sections: string[] = [`# ${title}`];
        if (spoiler) sections.push(`> [!NOTE]\n> **Content Note**: ${spoiler}`);
        if (converted.markdown.trim()) sections.push(converted.markdown.trim());
        for (const m of media) {
          if (typeof m.description === 'string' && m.description.trim()) {
            sections.push(`- *Media description*: ${m.description.trim()}`);
          }
        }
        return {
          title,
          author: `@${acctObj.acct}@${host}`,
          ...(createdAt ? { publishedTime: createdAt } : {}),
          markdown: sections.join('\n\n'),
          links: converted.links,
        };
      },
    };
  },
});
