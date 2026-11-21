import { defineAdapter, extractXmlTagTextLinear, findAllElementInnersLinear } from '../../types';
import { formatGfmTable, parseJsonObject, parseJsonValue, stripTagsInline } from '../../utils';

// Note: `remotive.com` is intentionally excluded because `remotive.com/robots.txt` disallows `/api/remote-jobs`.
export default defineAdapter({
  id: 'public-job-feeds',
  name: 'Public Open Job Feeds (WWR, Himalayas, Working Nomads, The Muse, Jobicy, Arbeitnow & RemoteOK)',
  category: 'jobs',
  description:
    'Formats robots.txt-allowed keyless public job feeds (We Work Remotely RSS, Himalayas, Working Nomads, The Muse, Jobicy, Arbeitnow, and RemoteOK) into clean job tables.',
  domains: [
    'weworkremotely.com',
    'www.weworkremotely.com',
    'himalayas.app',
    'www.himalayas.app',
    'www.workingnomads.com',
    'workingnomads.com',
    'www.themuse.com',
    'themuse.com',
    'jobicy.com',
    'www.arbeitnow.com',
    'arbeitnow.com',
    'remoteok.com',
  ],
  exampleUrls: [
    'https://weworkremotely.com/remote-jobs.rss',
    'https://himalayas.app/jobs/api?limit=50',
    'https://www.workingnomads.com/api/exposed_jobs/',
    'https://www.themuse.com/api/public/jobs?page=1',
    'https://jobicy.com/api/v2/remote-jobs?count=20',
    'https://www.arbeitnow.com/api/job-board-api',
    'https://remoteok.com/api',
  ],
  resolveTwin({ url, urlStr, host }) {
    // 1. We Work Remotely RSS (`weworkremotely.com/remote-jobs.rss` or `/categories/*.rss`)
    if (
      (host === 'weworkremotely.com' || host === 'www.weworkremotely.com') &&
      (/\.rss$/i.test(url.pathname) || url.pathname === '/remote-jobs')
    ) {
      const fetchTarget = /\.rss$/i.test(url.pathname) ? urlStr : 'https://weworkremotely.com/remote-jobs.rss';
      return {
        id: 'weworkremotely-feed',
        fetchUrl: fetchTarget,
        kind: 'text',
        accept: 'application/rss+xml, application/xml, text/xml',
        formatTwin: (rawXml) => {
          if (!/<rss\b|<channel\b/i.test(rawXml)) return null;
          const items = findAllElementInnersLinear(rawXml, 'item', undefined, 200);
          if (items.length === 0) return null;
          const title = `We Work Remotely Jobs (${items.length})`;
          const links: string[] = [];
          const records: Array<Record<string, unknown>> = [];
          const rows = items.slice(0, 50).map((block) => {
            const rawTitle = stripTagsInline(extractXmlTagTextLinear(block, 'title'));
            const colonIdx = rawTitle.indexOf(':');
            const company = colonIdx > 0 ? rawTitle.slice(0, colonIdx).trim() : 'We Work Remotely';
            const role = colonIdx > 0 ? rawTitle.slice(colonIdx + 1).trim() : rawTitle || 'Role';
            const jLink = stripTagsInline(extractXmlTagTextLinear(block, 'link'));
            const region = stripTagsInline(extractXmlTagTextLinear(block, 'region')) || 'Remote';
            const category = stripTagsInline(extractXmlTagTextLinear(block, 'category')) || '-';
            const pubDate = stripTagsInline(extractXmlTagTextLinear(block, 'pubDate'));
            if (jLink.startsWith('https://')) links.push(jLink);
            records.push({
              title: role,
              company,
              url: jLink,
              region,
              category,
              postedAt: pubDate || null,
              source: 'weworkremotely',
            });
            return [
              jLink.startsWith('https://') ? `[${role}](${jLink})` : role,
              company,
              region,
              pubDate ? pubDate.slice(0, 16) : category,
            ];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Region', 'Published'], rows)}`,
            links,
            records,
            total: items.length,
            returned: rows.length,
            truncated: items.length > rows.length,
          };
        },
      };
    }

    // 2. Himalayas (`himalayas.app/jobs/api?limit=50`)
    if ((host === 'himalayas.app' || host === 'www.himalayas.app') && url.pathname.startsWith('/jobs')) {
      const fetchTarget = url.pathname.startsWith('/jobs/api')
        ? urlStr
        : 'https://himalayas.app/jobs/api?limit=50';
      return {
        id: 'himalayas-feed',
        fetchUrl: fetchTarget,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
          if (!jobs) return null;
          const total = typeof data?.totalCount === 'number' ? data.totalCount : jobs.length;
          const title = `Himalayas Remote Jobs (${jobs.length} of ${total.toLocaleString('en-US')})`;
          const links: string[] = [];
          const records: Array<Record<string, unknown>> = [];
          const rows = jobs.slice(0, 50).map((j) => {
            const jTitle = String(j.title ?? 'Role').trim();
            const company = String(j.companyName ?? '-').trim();
            const jUrl =
              typeof j.applicationLink === 'string' && j.applicationLink.startsWith('https://')
                ? j.applicationLink
                : typeof j.guid === 'string' && j.guid.startsWith('https://')
                  ? j.guid
                  : '';
            if (jUrl) links.push(jUrl);
            const locs = Array.isArray(j.locationRestrictions)
              ? j.locationRestrictions.map(String).filter(Boolean).join(', ') || 'Worldwide'
              : 'Worldwide';
            const sal =
              typeof j.minSalary === 'number' && j.minSalary > 0
                ? `${String(j.currency ?? 'USD')} ${j.minSalary.toLocaleString('en-US')}${typeof j.maxSalary === 'number' && j.maxSalary > 0 ? `–${j.maxSalary.toLocaleString('en-US')}` : ''}`
                : '-';
            records.push({
              title: jTitle,
              company,
              url: jUrl,
              locations: locs,
              salary: sal !== '-' ? sal : null,
              source: 'himalayas',
            });
            return [jUrl ? `[${jTitle}](${jUrl})` : jTitle, company, locs, sal];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Region', 'Salary'], rows)}`,
            links,
            records,
            total,
            returned: rows.length,
            truncated: total > rows.length,
          };
        },
      };
    }

    // 3. Working Nomads (`www.workingnomads.com/api/exposed_jobs/`)
    if (
      (host === 'www.workingnomads.com' || host === 'workingnomads.com') &&
      (url.pathname.startsWith('/api/exposed_jobs') || url.pathname === '/jobs')
    ) {
      const fetchTarget = url.pathname.startsWith('/api/exposed_jobs')
        ? urlStr
        : 'https://www.workingnomads.com/api/exposed_jobs/';
      return {
        id: 'workingnomads-feed',
        fetchUrl: fetchTarget,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const parsed = parseJsonValue(rawBody);
          if (!Array.isArray(parsed)) return null;
          const jobs = parsed as Array<Record<string, unknown>>;
          const title = `Working Nomads Remote Jobs (${jobs.length})`;
          const links: string[] = [];
          const records: Array<Record<string, unknown>> = [];
          const rows = jobs.slice(0, 50).map((j) => {
            const jTitle = String(j.title ?? 'Role').trim();
            const company = String(j.company_name ?? '-').trim();
            const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : '';
            if (jUrl) links.push(jUrl);
            const loc = String(j.location || 'Remote').trim();
            const pub = String(j.pub_date ?? '').slice(0, 10) || '-';
            records.push({
              title: jTitle,
              company,
              url: jUrl,
              location: loc,
              postedAt: pub !== '-' ? pub : null,
              source: 'workingnomads',
            });
            return [jUrl ? `[${jTitle}](${jUrl})` : jTitle, company, loc, pub];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Company', 'Location', 'Published'], rows)}`,
            links,
            records,
            total: jobs.length,
            returned: rows.length,
            truncated: jobs.length > rows.length,
          };
        },
      };
    }

    // 4. The Muse (`www.themuse.com/api/public/jobs?...`)
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

    // 5. Jobicy (`jobicy.com/api/v2/remote-jobs` or `jobicy.com/jobs-rss-feed` / `/remote-*`)
    if (
      host === 'jobicy.com' &&
      (url.pathname.startsWith('/api/v2/remote-jobs') ||
        url.pathname === '/jobs-rss-feed' ||
        url.pathname.startsWith('/remote-'))
    ) {
      const fetchTarget = url.pathname.startsWith('/api/v2/remote-jobs')
        ? urlStr
        : 'https://jobicy.com/api/v2/remote-jobs?count=30';
      return {
        id: 'jobicy-feed',
        fetchUrl: fetchTarget,
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

    // 6. Arbeitnow (`arbeitnow.com/api/job-board-api` or `/jobs`)
    if (
      (host === 'www.arbeitnow.com' || host === 'arbeitnow.com') &&
      (url.pathname.startsWith('/api/job-board-api') || url.pathname === '/jobs' || url.pathname === '/jobs/')
    ) {
      const fetchTarget = url.pathname.startsWith('/api/job-board-api')
        ? urlStr
        : 'https://www.arbeitnow.com/api/job-board-api';
      return {
        id: 'arbeitnow-feed',
        fetchUrl: fetchTarget,
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

    // 7. RemoteOK (`remoteok.com/api` or `remoteok.com/remote-*-jobs` — element 0 is a legal notice object without `position`/`company`, skip it!)
    if (
      host === 'remoteok.com' &&
      (url.pathname === '/api' || url.pathname === '/' || /^\/remote-[a-z0-9-]+-jobs\/?$/i.test(url.pathname))
    ) {
      const catTag = /^\/remote-([a-z0-9-]+)-jobs\/?$/i.exec(url.pathname)?.[1]?.toLowerCase();
      return {
        id: 'remoteok-feed',
        fetchUrl: 'https://remoteok.com/api',
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const parsed = parseJsonValue(rawBody);
          if (!Array.isArray(parsed)) return null;
          let jobs = (parsed as Array<Record<string, unknown>>).filter(
            (item) => item && typeof item === 'object' && typeof item.position === 'string' && item.position.trim() !== '',
          );
          if (catTag && catTag !== 'dev') {
            const filtered = jobs.filter((j) =>
              Array.isArray(j.tags) && j.tags.some((t) => String(t).toLowerCase().includes(catTag)),
            );
            if (filtered.length > 0) jobs = filtered;
          }
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
