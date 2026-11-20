import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'workable',
  name: 'Workable Job Boards & Postings',
  category: 'jobs',
  description: 'Upgrades apply.workable.com boards to /api/v1/widget/accounts/<org>?details=true (merging multi-location rows on shortcode) and single jobs to /api/v2/accounts/<org>/jobs/<code>.',
  domains: ['apply.workable.com'],
  exampleUrls: [
    'https://apply.workable.com/identiv/',
    'https://apply.workable.com/identiv/j/ABCD1234EF/',
  ],
  resolveTwin({ parts }) {
    if (parts.length < 1) return null;
    const reserved = new Set(['api', 'j', 'assets', 'static', 'favicon.ico', 'robots.txt']);
    const org = parts[0]!;
    if (reserved.has(org.toLowerCase()) || !/^[A-Za-z0-9_-]{1,80}$/.test(org)) return null;

    // Single job: `apply.workable.com/<org>/j/<shortcode>`
    if (parts[1] === 'j' && parts[2] && /^[A-Za-z0-9_-]{4,24}$/.test(parts[2])) {
      const code = parts[2];
      return {
        id: 'workable-job',
        fetchUrl: `https://apply.workable.com/api/v2/accounts/${encodeURIComponent(org)}/jobs/${encodeURIComponent(code)}`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody, origUrl, htmlToMd) => {
          const data = parseJsonObject(rawBody);
          if (!data || typeof data.title !== 'string') return null;

          const title = data.title.trim();
          const locObj = (data.location as Record<string, unknown> | undefined) ?? {};
          const locStr = [locObj.city, locObj.region, locObj.country].filter((x) => typeof x === 'string' && x).join(', ');
          const workplace = typeof data.workplace === 'string' ? data.workplace : locObj.telecommuting ? 'remote' : '';
          const dept = Array.isArray(data.department) ? data.department.join(', ') : typeof data.department === 'string' ? data.department : '';
          const empType = typeof data.type === 'string' ? data.type : '';
          const published = typeof data.published === 'string' ? data.published.slice(0, 10) : '';
          const salObj = data.salary as Record<string, unknown> | undefined;
          const salStr =
            salObj && (salObj.salary_from || salObj.salary_to)
              ? `${String(salObj.salary_currency ?? 'USD').toUpperCase()} ${String(salObj.salary_from ?? '')}${salObj.salary_to ? ` – ${String(salObj.salary_to)}` : ''}`
              : '';

          const bullets: string[] = [`- **Company**: ${org}`];
          if (locStr) bullets.push(`- **Location**: ${locStr}`);
          if (workplace) bullets.push(`- **Workplace**: ${workplace}`);
          if (dept) bullets.push(`- **Department**: ${dept}`);
          if (empType) bullets.push(`- **Type**: ${empType}`);
          if (salStr) bullets.push(`- **Salary**: ${salStr}`);
          if (published) bullets.push(`- **Published**: ${published}`);

          const sections: string[] = [`# ${title} @ ${org}`, bullets.join('\n')];
          for (const [label, field] of [
            ['Description', data.description],
            ['Requirements', data.requirements],
            ['Benefits', data.benefits],
          ] as const) {
            if (typeof field === 'string' && field.trim()) {
              sections.push(`## ${label}\n\n${htmlToMd(field, origUrl).markdown.trim()}`);
            }
          }

          return {
            title: `${title} @ ${org}`,
            ...(published ? { publishedTime: published } : {}),
            markdown: sections.join('\n\n'),
            links: [`https://apply.workable.com/${org}/j/${code}/apply/`],
          };
        },
      };
    }

    // Whole board: `apply.workable.com/<org>[/]` -> `v1/widget/accounts/<org>?details=true`
    // (`v3/accounts/<org>/jobs` 404s on real boards; `v1/widget` works reliably and emits 1 row per location — merge on `shortcode`!)
    if (parts.length === 1) {
      return {
        id: 'workable-board',
        fetchUrl: `https://apply.workable.com/api/v1/widget/accounts/${encodeURIComponent(org)}?details=true`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const rawJobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
          if (!rawJobs) return null;
          const orgName = typeof data?.name === 'string' && data.name ? data.name.trim() : org;

          // Merge duplicate multi-location rows by `shortcode`
          const merged = new Map<
            string,
            { title: string; url: string; locations: Set<string>; remote: boolean; department: string; published: string }
          >();
          for (const j of rawJobs) {
            const code = String(j.shortcode ?? '').trim();
            const jTitle = String(j.title ?? '').trim();
            if (!code || !jTitle) continue;
            const loc = [j.city, j.state, j.country].filter((x) => typeof x === 'string' && x).join(', ');
            const isRemote = Boolean(j.telecommuting) || /remote/i.test(String(j.workplace_type ?? ''));
            const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : `https://apply.workable.com/${org}/j/${code}/`;
            const existing = merged.get(code);
            if (existing) {
              if (loc) existing.locations.add(loc);
              if (isRemote) existing.remote = true;
            } else {
              merged.set(code, {
                title: jTitle,
                url: jUrl,
                locations: new Set(loc ? [loc] : []),
                remote: isRemote,
                department: typeof j.department === 'string' ? j.department : '',
                published: typeof j.published_on === 'string' ? j.published_on.slice(0, 10) : '',
              });
            }
          }

          const uniqueJobs = [...merged.values()];
          const title = `${orgName} — Open Roles (${uniqueJobs.length})`;
          if (uniqueJobs.length === 0) {
            return { title, markdown: `# ${title}\n\nNo open positions are currently listed on this Workable board.` };
          }

          const links = uniqueJobs.map((j) => j.url);
          const rows = uniqueJobs.slice(0, 100).map((j) => [
            `[${j.title}](${j.url})`,
            j.department || '-',
            [...j.locations].slice(0, 4).join('; ') || (j.remote ? 'Remote' : '-'),
            j.remote ? 'Remote' : 'On-site / Hybrid',
            j.published || '-',
          ]);

          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Locations', 'Workplace', 'Published'], rows)}`,
            links,
          };
        },
      };
    }

    return null;
  },
});
