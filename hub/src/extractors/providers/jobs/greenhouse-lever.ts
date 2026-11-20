import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject, parseJsonValue } from '../../utils';

export default defineAdapter({
  id: 'greenhouse-lever-boards',
  name: 'Greenhouse & Lever Whole-Board + EU APIs',
  category: 'jobs',
  description: 'Upgrades Greenhouse (US & EU) and Lever (US & EU) board root URLs to their official JSON posting feeds.',
  domains: [
    'boards.greenhouse.io',
    'job-boards.greenhouse.io',
    'eu-boards.greenhouse.io',
    'job-boards.eu.greenhouse.io',
    'jobs.lever.co',
    'jobs.eu.lever.co',
  ],
  exampleUrls: [
    'https://job-boards.greenhouse.io/cloudflare',
    'https://eu-boards.greenhouse.io/celonis',
    'https://jobs.lever.co/mistral',
  ],
  resolveTwin({ host, parts }) {
    if (parts.length === 0) return null;
    const reserved = new Set(['embed', 'v1', 'api', 'static', 'assets', 'favicon.ico']);
    const org = parts[0]!;
    if (reserved.has(org.toLowerCase()) || !/^[A-Za-z0-9_.-]{1,80}$/.test(org)) return null;

    const isGhUs = host === 'boards.greenhouse.io' || host === 'job-boards.greenhouse.io';
    const isGhEu = host === 'eu-boards.greenhouse.io' || host === 'job-boards.eu.greenhouse.io';
    if ((isGhUs || isGhEu) && parts.length === 1) {
      const apiHost = isGhEu ? 'boards-api.eu.greenhouse.io' : 'boards-api.greenhouse.io';
      return {
        id: isGhEu ? 'greenhouse-eu-board' : 'greenhouse-board',
        fetchUrl: `https://${apiHost}/v1/boards/${encodeURIComponent(org)}/jobs`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
          if (!jobs) return null;
          const title = `${org} — Greenhouse Job Board (${jobs.length} open roles)`;
          if (jobs.length === 0) {
            return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
          }
          const links: string[] = [];
          const rows = jobs.slice(0, 120).map((j) => {
            const jTitle = String(j.title ?? 'Role').trim();
            const loc = String((j.location as Record<string, unknown> | undefined)?.name ?? '-');
            const deptArr = Array.isArray(j.departments) ? (j.departments as Array<Record<string, unknown>>) : [];
            const dept = deptArr.map((d) => String(d.name ?? '')).filter(Boolean).join(', ') || '-';
            const updated = String(j.updated_at ?? '').slice(0, 10) || '-';
            const jUrl = typeof j.absolute_url === 'string' && j.absolute_url.startsWith('https://')
              ? j.absolute_url
              : `https://${host}/${org}/jobs/${String(j.id ?? '')}`;
            links.push(jUrl);
            return [`[${jTitle}](${jUrl})`, dept, loc, updated];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Location', 'Updated'], rows)}`,
            links,
          };
        },
      };
    }

    const isLeverUs = host === 'jobs.lever.co';
    const isLeverEu = host === 'jobs.eu.lever.co';
    if ((isLeverUs || isLeverEu) && parts.length === 1) {
      const apiHost = isLeverEu ? 'api.eu.lever.co' : 'api.lever.co';
      return {
        id: isLeverEu ? 'lever-eu-board' : 'lever-board',
        fetchUrl: `https://${apiHost}/v0/postings/${encodeURIComponent(org)}?mode=json`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const parsed = parseJsonValue(rawBody);
          if (!Array.isArray(parsed)) return null;
          const jobs = parsed as Array<Record<string, unknown>>;
          const title = `${org} — Lever Job Board (${jobs.length} open roles)`;
          if (jobs.length === 0) {
            return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
          }
          const links: string[] = [];
          const rows = jobs.slice(0, 120).map((j) => {
            const jTitle = String(j.text ?? 'Role').trim();
            const cats = (j.categories as Record<string, unknown> | undefined) ?? {};
            const team = String(cats.team || cats.department || '-');
            const loc = String(cats.location || '-');
            const wp = String(j.workplaceType || '-');
            const jUrl = typeof j.hostedUrl === 'string' && j.hostedUrl.startsWith('https://')
              ? j.hostedUrl
              : `https://${host}/${org}/${String(j.id ?? '')}`;
            links.push(jUrl);
            return [`[${jTitle}](${jUrl})`, team, loc, wp];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Team', 'Location', 'Workplace'], rows)}`,
            links,
          };
        },
      };
    }

    return null;
  },
});
