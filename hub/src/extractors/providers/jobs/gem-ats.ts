import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonValue } from '../../utils';

export default defineAdapter({
  id: 'gem-ats',
  name: 'Gem Job Boards',
  category: 'jobs',
  description: 'Upgrades jobs.gem.com/<org> boards and job posts to the keyless api.gem.com/job_board/v0/<org>/job_posts/ JSON feed.',
  domains: ['jobs.gem.com'],
  exampleUrls: ['https://jobs.gem.com/linear'],
  resolveTwin({ parts }) {
    if (parts.length < 1) return null;
    const org = parts[0]!;
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(org)) return null;
    const postId = parts[1] ?? '';

    return {
      id: 'gem-ats',
      fetchUrl: `https://api.gem.com/job_board/v0/${encodeURIComponent(org)}/job_posts/`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, origUrl, htmlToMd) => {
        const parsed = parseJsonValue(rawBody);
        if (!Array.isArray(parsed)) return null;
        const posts = parsed as Array<Record<string, unknown>>;

        if (postId) {
          const match = posts.find(
            (p) => String(p.id ?? '') === postId || String(p.public_id ?? '') === postId || String(p.absolute_url ?? '').endsWith(`/${postId}`),
          );
          if (match) {
            const title = String(match.title ?? 'Job Posting').trim();
            const loc = String((match.location as Record<string, unknown> | undefined)?.name ?? match.location_type ?? '');
            const depts = Array.isArray(match.departments)
              ? (match.departments as Array<Record<string, unknown>>).map((d) => String(d.name ?? '')).filter(Boolean).join(', ')
              : '';
            const contentHtml = typeof match.content === 'string' ? match.content : '';
            const contentPlain = typeof match.content_plain === 'string' ? match.content_plain : '';
            const bodyMd = contentHtml ? htmlToMd(contentHtml, origUrl).markdown.trim() : contentPlain.trim();
            const bullets = [`- **Company**: ${org}`];
            if (loc) bullets.push(`- **Location**: ${loc}`);
            if (depts) bullets.push(`- **Department**: ${depts}`);
            return {
              title: `${title} @ ${org}`,
              markdown: [`# ${title} @ ${org}`, bullets.join('\n'), bodyMd].filter(Boolean).join('\n\n'),
            };
          }
        }

        const title = `${org} — Gem Job Board (${posts.length} open roles)`;
        if (posts.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
        const links: string[] = [];
        const rows = posts.slice(0, 100).map((p) => {
          const pTitle = String(p.title ?? 'Role').trim();
          const pUrl = typeof p.absolute_url === 'string' && p.absolute_url.startsWith('https://')
            ? p.absolute_url
            : `https://jobs.gem.com/${org}/${String(p.id ?? '')}`;
          links.push(pUrl);
          const loc = String((p.location as Record<string, unknown> | undefined)?.name ?? '-');
          const wp = String(p.location_type ?? '-');
          const created = String(p.first_published_at ?? p.created_at ?? '').slice(0, 10) || '-';
          return [`[${pTitle}](${pUrl})`, loc, wp, created];
        });

        return {
          title,
          markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Location', 'Workplace', 'Published'], rows)}`,
          links,
        };
      },
    };
  },
});
