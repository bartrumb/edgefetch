import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject, parseJsonValue, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'public-job-feeds',
  name: 'Public Open Job Feeds (The Muse, Jobicy, Arbeitnow & RemoteOK)',
  category: 'jobs',
  description: 'Formats keyless public job board APIs (The Muse, Jobicy remote jobs, Arbeitnow, and RemoteOK skipping index-0 legal banner) into clean job tables.',
  domains: ['www.themuse.com', 'themuse.com', 'jobicy.com', 'www.arbeitnow.com', 'arbeitnow.com', 'remoteok.com'],
  exampleUrls: [
    'https://www.themuse.com/api/public/jobs?page=1',
    'https://jobicy.com/api/v2/remote-jobs?count=20',
    'https://www.arbeitnow.com/api/job-board-api',
    'https://remoteok.com/api',
  ],
  resolveTwin({ url, urlStr, host }) {
    // 1. The Muse (`www.themuse.com/api/public/jobs?...`)
    if ((host === 'www.themuse.com' || host === 'themuse.com') && url.pathname.startsWith('/api/public/jobs')) {
      return {
        id: 'themuse-feed',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const results = Array.isArray(data?.results) ? (data.results as Array<Record<string, unknown>>) : null;
          if (!results) return null;
          const total = typeof data?.total === 'number' ? data.total.toLocaleString('en-US') : String(results.length);
          const title = `The Muse Public Jobs (${results.length} of ${total})`;
          const links: string[] = [];
          const rows = results.slice(0, 50).map((r) => {
            const jTitle = String(r.name ?? 'Role').trim();
            const co = String((r.company as Record<string, unknown> | undefined)?.name ?? '-');
            const locs = Array.isArray(r.locations)
              ? (r.locations as Array<Record<string, unknown>>).map((l) => String(l.name ?? '')).filter(Boolean).join('; ')
              : '-';
            const refs = r.refs as Record<string, unknown> | undefined;
            const lUrl = typeof refs?.landing_page === 'string' ? refs.landing_page : '';
            if (lUrl.startsWith('https://')) links.push(lUrl);
            return [lUrl ? `[${jTitle}](${lUrl})` : jTitle, co, locs || '-', String(r.publication_date ?? '').slice(0, 10) || '-'];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Locations', 'Published'], rows)}`,
            links,
          };
        },
      };
    }

    // 2. Jobicy (`jobicy.com/api/v2/remote-jobs`)
    if (host === 'jobicy.com' && url.pathname.startsWith('/api/v2/remote-jobs')) {
      return {
        id: 'jobicy-feed',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
          if (!jobs) return null;
          const title = `Jobicy Remote Jobs (${jobs.length})`;
          const links: string[] = [];
          const rows = jobs.slice(0, 50).map((j) => {
            const jTitle = stripTagsInline(String(j.jobTitle ?? 'Role'));
            const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : '';
            if (jUrl) links.push(jUrl);
            const sal = j.annualSalaryMin
              ? `${String(j.salaryCurrency ?? 'USD')} ${String(j.annualSalaryMin)}${j.annualSalaryMax ? `–${String(j.annualSalaryMax)}` : ''}`
              : '-';
            return [jUrl ? `[${jTitle}](${jUrl})` : jTitle, String(j.companyName ?? '-'), String(j.jobGeo ?? 'Remote'), sal];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Region', 'Annual Salary'], rows)}`,
            links,
          };
        },
      };
    }

    // 3. Arbeitnow (`arbeitnow.com/api/job-board-api`)
    if ((host === 'www.arbeitnow.com' || host === 'arbeitnow.com') && url.pathname.startsWith('/api/job-board-api')) {
      return {
        id: 'arbeitnow-feed',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const jobs = Array.isArray(data?.data) ? (data.data as Array<Record<string, unknown>>) : null;
          if (!jobs) return null;
          const title = `Arbeitnow Job Feed (${jobs.length})`;
          const links: string[] = [];
          const rows = jobs.slice(0, 50).map((j) => {
            const jTitle = String(j.title ?? 'Role').trim();
            const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : '';
            if (jUrl) links.push(jUrl);
            return [jUrl ? `[${jTitle}](${jUrl})` : jTitle, String(j.company_name ?? '-'), String(j.location ?? '-'), j.remote ? 'Remote' : 'On-site'];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Location', 'Workplace'], rows)}`,
            links,
          };
        },
      };
    }

    // 4. RemoteOK (`remoteok.com/api` — element 0 is a legal notice object without `position`/`company`, skip it!)
    if (host === 'remoteok.com' && url.pathname === '/api') {
      return {
        id: 'remoteok-feed',
        fetchUrl: urlStr,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const parsed = parseJsonValue(rawBody);
          if (!Array.isArray(parsed)) return null;
          const jobs = (parsed as Array<Record<string, unknown>>).filter(
            (item) => item && typeof item === 'object' && typeof item.position === 'string' && item.position.trim() !== '',
          );
          const title = `RemoteOK Remote Jobs (${jobs.length})`;
          const links: string[] = [];
          const rows = jobs.slice(0, 50).map((j) => {
            const pos = String(j.position ?? 'Role').trim();
            const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : '';
            if (jUrl) links.push(jUrl);
            const sal = j.salary_min ? `$${String(j.salary_min)}${j.salary_max ? `–$${String(j.salary_max)}` : ''}` : '-';
            return [jUrl ? `[${pos}](${jUrl})` : pos, String(j.company ?? '-'), String(j.location || 'Remote'), sal];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Location', 'Salary'], rows)}`,
            links,
          };
        },
      };
    }

    return null;
  },
});
