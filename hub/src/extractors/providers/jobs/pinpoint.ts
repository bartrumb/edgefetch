import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'pinpoint',
  name: 'Pinpoint ATS Job Boards',
  category: 'jobs',
  description: 'Upgrades <org>.pinpointhq.com career portals to /postings.json with compensation, responsibilities, and workplace types.',
  domains: ['*.pinpointhq.com'],
  exampleUrls: ['https://acme.pinpointhq.com/'],
  resolveTwin({ host, parts }) {
    const m = /^([a-z0-9-]+)\.pinpointhq\.com$/i.exec(host);
    if (!m?.[1] || m[1] === 'www' || m[1] === 'app') return null;
    const org = m[1];
    const targetPostingId = parts[0] === 'postings' && parts[1] ? parts[1] : '';

    return {
      id: 'pinpoint',
      fetchUrl: `https://${host}/postings.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const postings = Array.isArray(data?.data) ? (data.data as Array<Record<string, unknown>>) : null;
        if (!postings) return null;

        if (targetPostingId) {
          const hit = postings.find((p) => String(p.id ?? '') === targetPostingId || String(p.url ?? '').includes(targetPostingId));
          if (hit) {
            const title = String(hit.title ?? 'Job Posting').trim();
            const loc = String((hit.location as Record<string, unknown> | undefined)?.name ?? '');
            const wp = String(hit.workplace_type_text || hit.workplace_type || '');
            const compMin = hit.compensation_minimum;
            const compMax = hit.compensation_maximum;
            const cur = String(hit.compensation_currency ?? 'USD');
            const bullets = [`- **Company**: ${org}`];
            if (loc) bullets.push(`- **Location**: ${loc}`);
            if (wp) bullets.push(`- **Workplace**: ${wp}`);
            if (compMin || compMax) bullets.push(`- **Compensation**: ${cur} ${String(compMin ?? '')}${compMax ? ` – ${String(compMax)}` : ''}`);

            const sections = [`# ${title} @ ${org}`, bullets.join('\n')];
            for (const [label, htmlField] of [
              ['Description', hit.description],
              ['Key Responsibilities', hit.key_responsibilities],
              ['Skills & Expertise', hit.skills_knowledge_expertise],
              ['Benefits', hit.benefits],
            ] as const) {
              if (typeof htmlField === 'string' && htmlField.trim()) {
                sections.push(`## ${label}\n\n${htmlToMd(htmlField, origUrl).markdown.trim()}`);
              }
            }
            return { title: `${title} @ ${org}`, markdown: sections.join('\n\n') };
          }
        }

        const title = `${org} — Pinpoint Job Board (${postings.length} open roles)`;
        if (postings.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
        const links: string[] = [];
        const rows = postings.slice(0, 100).map((p) => {
          const pTitle = String(p.title ?? 'Role').trim();
          const pUrl = typeof p.url === 'string' && p.url.startsWith('https://') ? p.url : `https://${host}/postings/${String(p.id ?? '')}`;
          links.push(pUrl);
          const loc = String((p.location as Record<string, unknown> | undefined)?.name ?? '-');
          const wp = String(p.workplace_type_text || p.workplace_type || '-');
          const comp = p.compensation_minimum
            ? `${String(p.compensation_currency ?? 'USD')} ${String(p.compensation_minimum)}${p.compensation_maximum ? `–${String(p.compensation_maximum)}` : ''}`
            : '-';
          return [`[${pTitle}](${pUrl})`, loc, wp, comp];
        });

        return {
          title,
          markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Location', 'Workplace', 'Compensation'], rows)}`,
          links,
        };
      },
    };
  },
});
