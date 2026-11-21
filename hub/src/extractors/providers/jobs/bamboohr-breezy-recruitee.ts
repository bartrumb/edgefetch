import { defineAdapter, extractXmlTagTextLinear, findAllElementInnersLinear } from '../../types';
import { formatGfmTable, parseJsonObject, parseJsonValue } from '../../utils';

const BAMBOO_JUNK_SUBDOMAINS = new Set(['www', 'resources', 'help', 'documentation', 'developers', 'blog', 'status', 'api']);

export default defineAdapter({
  id: 'bamboohr-breezy-recruitee',
  name: 'BambooHR, Breezy HR, Recruitee & Personio Boards',
  category: 'jobs',
  description: 'Upgrades BambooHR (/careers/list & /detail), Breezy HR (/json), Recruitee (/api/offers), and Personio (/xml) career boards to structured feeds.',
  domains: ['*.bamboohr.com', '*.breezy.hr', '*.recruitee.com', '*.jobs.personio.de', '*.jobs.personio.com'],
  exampleUrls: [
    'https://acme.bamboohr.com/careers',
    'https://acme.breezy.hr/',
    'https://acme.recruitee.com/',
    'https://acme.jobs.personio.de/',
  ],
  resolveTwin({ host, parts }) {
    // 1. BambooHR (`<org>.bamboohr.com/careers` & `/careers/<id>`)
    const bamboo = /^([a-z0-9-]+)\.bamboohr\.com$/i.exec(host);
    if (bamboo?.[1] && !BAMBOO_JUNK_SUBDOMAINS.has(bamboo[1].toLowerCase())) {
      const org = bamboo[1];
      if ((parts.length === 1 && (parts[0] === 'careers' || parts[0] === 'jobs')) || parts.length === 0) {
        return {
          id: 'bamboohr-board',
          fetchUrl: `https://${host}/careers/list`,
          kind: 'json',
          accept: 'application/json',
          formatTwin: (rawBody) => {
            const data = parseJsonObject(rawBody);
            const result = Array.isArray(data?.result) ? (data.result as Array<Record<string, unknown>>) : null;
            if (!result) return null;
            const title = `${org} — BambooHR Careers (${result.length} open roles)`;
            if (result.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
            const links: string[] = [];
            const rows = result.slice(0, 100).map((r) => {
              const id = String(r.id ?? '');
              const jTitle = String(r.jobOpeningName ?? 'Role').trim();
              const jUrl = `https://${host}/careers/${id}`;
              links.push(jUrl);
              const dept = String(r.departmentLabel ?? '-');
              const locObj = r.location as Record<string, unknown> | undefined;
              const loc = [locObj?.city, locObj?.state].filter(Boolean).join(', ') || (r.isRemote ? 'Remote' : '-');
              return [`[${jTitle}](${jUrl})`, dept, loc];
            });
            return {
              title,
              markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Location'], rows)}`,
              links,
            };
          },
        };
      }
      if (parts[0] === 'careers' && parts[1] && /^\d+$/.test(parts[1])) {
        const jobId = parts[1];
        return {
          id: 'bamboohr-job',
          fetchUrl: `https://${host}/careers/${jobId}/detail`,
          kind: 'json',
          accept: 'application/json',
          formatTwin: (rawBody, origUrl, htmlToMd) => {
            const data = parseJsonObject(rawBody);
            const job = (data?.result as Record<string, unknown> | undefined)?.jobOpening as Record<string, unknown> | undefined;
            if (!job || typeof job.jobOpeningName !== 'string') return null;
            const title = job.jobOpeningName.trim();
            const descHtml = typeof job.description === 'string' ? job.description : '';
            const bodyMd = descHtml ? htmlToMd(descHtml, origUrl).markdown.trim() : '';
            return {
              title: `${title} @ ${org}`,
              markdown: [`# ${title} @ ${org}`, bodyMd].filter(Boolean).join('\n\n'),
            };
          },
        };
      }
    }

    // 2. Breezy HR (`<org>.breezy.hr`)
    const breezy = /^([a-z0-9-]+)\.breezy\.hr$/i.exec(host);
    if (breezy?.[1] && breezy[1] !== 'www' && breezy[1] !== 'app' && parts.length === 0) {
      const org = breezy[1];
      return {
        id: 'breezy-hr',
        fetchUrl: `https://${host}/json`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const parsed = parseJsonValue(rawBody);
          if (!Array.isArray(parsed)) return null;
          const jobs = parsed as Array<Record<string, unknown>>;
          const title = `${org} — Breezy HR Board (${jobs.length} open roles)`;
          if (jobs.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
          const links: string[] = [];
          const rows = jobs.slice(0, 100).map((j) => {
            const jTitle = String(j.name ?? 'Role').trim();
            const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : `https://${host}`;
            links.push(jUrl);
            const locObj = j.location as Record<string, unknown> | undefined;
            const loc = String(locObj?.name ?? (locObj?.is_remote ? 'Remote' : '-'));
            const dept = String(j.department ?? '-');
            return [`[${jTitle}](${jUrl})`, dept, loc];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Location'], rows)}`,
            links,
          };
        },
      };
    }

    // 3. Recruitee (`<org>.recruitee.com`)
    const recruitee = /^([a-z0-9-]+)\.recruitee\.com$/i.exec(host);
    if (recruitee?.[1] && recruitee[1] !== 'www' && recruitee[1] !== 'app' && (parts.length === 0 || (parts[0] === 'o' && parts[1]))) {
      const org = recruitee[1];
      const targetSlug = parts[0] === 'o' ? parts[1] : '';
      return {
        id: 'recruitee',
        fetchUrl: `https://${host}/api/offers`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody, origUrl, htmlToMd) => {
          const data = parseJsonObject(rawBody);
          const offers = Array.isArray(data?.offers) ? (data.offers as Array<Record<string, unknown>>) : null;
          if (!offers) return null;
          if (targetSlug) {
            const hit = offers.find((o) => String(o.slug ?? '') === targetSlug);
            if (!hit) return null;
            const title = String(hit.title ?? 'Role').trim();
            const desc = typeof hit.description === 'string' ? htmlToMd(hit.description, origUrl).markdown.trim() : '';
            const reqs = typeof hit.requirements === 'string' ? htmlToMd(hit.requirements, origUrl).markdown.trim() : '';
            return {
              title: `${title} @ ${org}`,
              markdown: [`# ${title} @ ${org}`, desc, reqs ? `## Requirements\n\n${reqs}` : ''].filter(Boolean).join('\n\n'),
            };
          }
          const title = `${org} — Recruitee Job Board (${offers.length} open roles)`;
          if (offers.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
          const links: string[] = [];
          const rows = offers.slice(0, 100).map((o) => {
            const oTitle = String(o.title ?? 'Role').trim();
            const oUrl = typeof o.careers_url === 'string' && o.careers_url.startsWith('https://')
              ? o.careers_url
              : `https://${host}/o/${String(o.slug ?? '')}`;
            links.push(oUrl);
            const dept = String(o.department ?? '-');
            const loc = String(o.location ?? (o.remote ? 'Remote' : '-'));
            return [`[${oTitle}](${oUrl})`, dept, loc, o.remote ? 'Remote' : o.hybrid ? 'Hybrid' : 'On-site'];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Location', 'Workplace'], rows)}`,
            links,
          };
        },
      };
    }

    // 4. Personio (`<org>.jobs.personio.de` / `<org>.jobs.personio.com`)
    const personio = /^([a-z0-9-]+)\.jobs\.personio\.(?:de|com)$/i.exec(host);
    if (personio?.[1] && parts.length === 0) {
      const org = personio[1];
      return {
        id: 'personio',
        fetchUrl: `https://${host}/xml?language=en`,
        kind: 'text',
        accept: 'application/xml, text/xml',
        formatTwin: (rawBody) => {
          if (!/<workzag-jobs|<position\b/i.test(rawBody)) return null;
          const posBlocks = findAllElementInnersLinear(rawBody, 'position', undefined, 500);
          const tag = (xml: string, t: string) => extractXmlTagTextLinear(xml, t);
          const title = `${org} — Personio Job Board (${posBlocks.length} open roles)`;
          if (posBlocks.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
          const links: string[] = [];
          const rows = posBlocks.slice(0, 100).map((b) => {
            const id = tag(b, 'id');
            const pName = tag(b, 'name') || 'Role';
            const jUrl = `https://${host}/job/${id}`;
            links.push(jUrl);
            return [`[${pName}](${jUrl})`, tag(b, 'department') || '-', tag(b, 'office') || '-', tag(b, 'schedule') || '-'];
          });
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Office', 'Schedule'], rows)}`,
            links,
          };
        },
      };
    }

    return null;
  },
});
