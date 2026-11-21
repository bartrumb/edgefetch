import { defineAdapter, findElementInnerLinear, getAttrValueLinear } from '../../types';
import { formatGfmTable, parseJsonObject, parseJsonValue } from '../../utils';

export default defineAdapter({
  id: 'rippling',
  name: 'Rippling ATS Career Boards',
  category: 'jobs',
  description: 'Upgrades ats.rippling.com/[locale/]<org>/jobs to api.rippling.com (merging multi-location rows by uuid) and extracts __NEXT_DATA__ jobPost on detail pages.',
  domains: ['ats.rippling.com'],
  exampleUrls: ['https://ats.rippling.com/rippling/jobs', 'https://ats.rippling.com/en-GB/acme/jobs'],
  resolveTwin({ parts }) {
    if (parts.length < 1) return null;
    // Strip optional locale segment like `en-US` or `en-GB`
    const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
    const org = parts[idx]!;
    const rest = parts.slice(idx + 1);
    if (!org || !/^[A-Za-z0-9_-]{1,80}$/.test(org)) return null;
    // Only board listing (`/<org>` or `/<org>/jobs`), NOT single-job detail (`/<org>/jobs/<uuid>`)
    if (rest.length > 1 || (rest.length === 1 && rest[0] !== 'jobs')) return null;

    return {
      id: 'rippling-board',
      fetchUrl: `https://api.rippling.com/platform/api/ats/v1/board/${encodeURIComponent(org)}/jobs`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const parsed = parseJsonValue(rawBody);
        const items = Array.isArray(parsed)
          ? (parsed as Array<Record<string, unknown>>)
          : Array.isArray((parsed as Record<string, unknown> | undefined)?.results)
            ? ((parsed as Record<string, unknown>).results as Array<Record<string, unknown>>)
            : null;
        if (!items) return null;

        // Rippling emits one row per office location for the same `uuid` — merge by `uuid` to prevent 40-70% count inflation!
        const byUuid = new Map<string, { name: string; url: string; dept: string; locations: Set<string> }>();
        for (const item of items) {
          const uuid = String(item.uuid || item.id || '').trim();
          const name = String(item.name || item.title || '').trim();
          if (!uuid || !name) continue;
          const workLoc = item.workLocation as Record<string, unknown> | string | undefined;
          const locLabel = typeof workLoc === 'string' ? workLoc : typeof workLoc?.label === 'string' ? workLoc.label : '';
          const deptObj = item.department as Record<string, unknown> | string | undefined;
          const dept = typeof deptObj === 'string' ? deptObj : typeof deptObj?.label === 'string' ? deptObj.label : '';
          const jUrl = typeof item.url === 'string' && item.url.startsWith('https://')
            ? item.url
            : `https://ats.rippling.com/${org}/jobs/${uuid}`;
          const existing = byUuid.get(uuid);
          if (existing) {
            if (locLabel) existing.locations.add(locLabel);
          } else {
            byUuid.set(uuid, {
              name,
              url: jUrl,
              dept,
              locations: new Set(locLabel ? [locLabel] : []),
            });
          }
        }

        const unique = [...byUuid.values()];
        const title = `${org} — Rippling Job Board (${unique.length} open roles)`;
        if (unique.length === 0) return { title, markdown: `# ${title}\n\nNo open positions currently listed.` };
        const links = unique.map((u) => u.url);
        const rows = unique.slice(0, 100).map((u) => [
          `[${u.name}](${u.url})`,
          u.dept || '-',
          [...u.locations].slice(0, 4).join('; ') || '-',
        ]);
        return {
          title,
          markdown: `# ${title}\n\n${formatGfmTable(['Role', 'Department', 'Locations'], rows)}`,
          links,
        };
      },
    };
  },
  extractHtml({ rawHtml, baseUrl, htmlToMd }) {
    const nextDataRaw = findElementInnerLinear(rawHtml, 'script', (a) => getAttrValueLinear(a, 'id') === '__NEXT_DATA__');
    if (!nextDataRaw) return null;
    const parsed = parseJsonObject(nextDataRaw);
    const pageProps = (parsed?.props as Record<string, unknown> | undefined)?.pageProps as Record<string, unknown> | undefined;
    const jobPost = ((pageProps?.apiData as Record<string, unknown> | undefined)?.jobPost ?? pageProps?.jobPost) as
      | Record<string, unknown>
      | undefined;
    if (!jobPost || typeof (jobPost.name ?? jobPost.title) !== 'string') return null;

    const title = String(jobPost.name ?? jobPost.title).trim();
    const company = String(jobPost.companyName ?? 'Company').trim();
    const descObj = jobPost.description as Record<string, unknown> | string | undefined;
    const htmlBody =
      typeof descObj === 'string'
        ? descObj
        : [descObj?.company, descObj?.role, descObj?.requirements, descObj?.benefits]
            .filter((x) => typeof x === 'string' && x)
            .join('\n\n');
    if (!htmlBody) return null;
    const bodyMd = htmlToMd(htmlBody, baseUrl).markdown.trim();

    return {
      extractorId: 'rippling-job',
      title: `${title} @ ${company}`,
      markdown: `# ${title} @ ${company}\n\n${bodyMd}`,
    };
  },
});
