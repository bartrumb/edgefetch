import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject, stripTagsInline } from '../../utils';

const CKAN_PORTALS: Record<string, { apiBase: string; datasetPrefix: string[] }> = {
  'catalog.data.gov': { apiBase: 'https://catalog.data.gov/api/3/action', datasetPrefix: ['dataset'] },
  'data.boston.gov': { apiBase: 'https://data.boston.gov/api/3/action', datasetPrefix: ['dataset'] },
  'data.sanantonio.gov': { apiBase: 'https://data.sanantonio.gov/api/3/action', datasetPrefix: ['dataset'] },
  'data.sanjoseca.gov': { apiBase: 'https://data.sanjoseca.gov/api/3/action', datasetPrefix: ['dataset'] },
  'data.wprdc.org': { apiBase: 'https://data.wprdc.org/api/3/action', datasetPrefix: ['dataset'] },
  'data.gov.uk': { apiBase: 'https://data.gov.uk/api/action', datasetPrefix: ['dataset'] },
  'www.data.gov.uk': { apiBase: 'https://data.gov.uk/api/action', datasetPrefix: ['dataset'] },
  'data.gov.au': { apiBase: 'https://data.gov.au/data/api/3/action', datasetPrefix: ['data', 'dataset'] },
  'open.canada.ca': { apiBase: 'https://open.canada.ca/data/api/action', datasetPrefix: ['data', 'en', 'dataset'] },
};

export default defineAdapter({
  id: 'ckan',
  name: 'CKAN Open Data Portals (Data.gov, UK, AU, Canada & City Portals)',
  category: 'public-records',
  description: 'Upgrades CKAN open-data portal dataset pages to /api/3/action/package_show JSON with organization, license, and downloadable resources.',
  domains: Object.keys(CKAN_PORTALS),
  exampleUrls: [
    'https://catalog.data.gov/dataset/electric-vehicle-population-data',
    'https://data.boston.gov/dataset/building-permits',
  ],
  resolveTwin({ host, parts }) {
    const cfg = CKAN_PORTALS[host];
    if (!cfg) return null;
    const pref = cfg.datasetPrefix;
    if (parts.length !== pref.length + 1) return null;
    for (let i = 0; i < pref.length; i++) {
      if (parts[i]?.toLowerCase() !== pref[i]) return null;
    }
    const pkgId = decodeURIComponent(parts[pref.length]!);
    if (!/^[A-Za-z0-9_.-]{2,160}$/.test(pkgId)) return null;

    return {
      id: 'ckan',
      fetchUrl: `${cfg.apiBase}/package_show?id=${encodeURIComponent(pkgId)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const res = data?.result as Record<string, unknown> | undefined;
        if (!data || data.success !== true || !res) return null;

        const rawTitle = res.title;
        const title =
          typeof rawTitle === 'string'
            ? rawTitle.trim()
            : typeof (rawTitle as Record<string, unknown> | undefined)?.en === 'string'
              ? String((rawTitle as Record<string, unknown>).en).trim()
              : pkgId;
        const orgObj = res.organization as Record<string, unknown> | undefined;
        const orgTitle = typeof orgObj?.title === 'string' ? orgObj.title : '';
        const license = typeof res.license_title === 'string' ? res.license_title : '';
        const modified = typeof res.metadata_modified === 'string' ? res.metadata_modified.slice(0, 10) : '';
        const notesRaw = typeof res.notes === 'string' ? res.notes : '';
        const notes = notesRaw ? stripTagsInline(notesRaw) : '';
        const tags = Array.isArray(res.tags)
          ? (res.tags as Array<Record<string, unknown>>).map((t) => String(t.display_name || t.name || '')).filter(Boolean)
          : [];

        const bullets: string[] = [`- **Portal**: \`${host}\``];
        if (orgTitle) bullets.push(`- **Publisher**: ${orgTitle}`);
        if (license) bullets.push(`- **License**: ${license}`);
        if (modified) bullets.push(`- **Last Updated**: ${modified}`);
        if (tags.length > 0) bullets.push(`- **Tags**: ${tags.slice(0, 12).join(', ')}`);

        const resources = Array.isArray(res.resources) ? (res.resources as Array<Record<string, unknown>>) : [];
        const rows: Array<Array<string>> = [];
        const links: string[] = [];
        for (const r of resources.slice(0, 20)) {
          const rUrl = typeof r.url === 'string' ? r.url : '';
          const rName = String(r.name || r.description || r.format || 'Resource').trim();
          const rFmt = String(r.format || '-').toUpperCase();
          if (rUrl.startsWith('https://')) links.push(rUrl);
          rows.push([rUrl.startsWith('https://') ? `[${rName}](${rUrl})` : rName, rFmt]);
        }

        const sections = [`# ${title}`, bullets.join('\n')];
        if (notes) sections.push(`## Description\n\n${notes}`);
        if (rows.length > 0) sections.push(`## Data Resources (${resources.length})\n\n${formatGfmTable(['Resource', 'Format'], rows)}`);

        return {
          title,
          ...(notes ? { description: notes.slice(0, 260) } : {}),
          ...(orgTitle ? { author: orgTitle } : {}),
          ...(modified ? { publishedTime: modified } : {}),
          markdown: sections.join('\n\n'),
          links,
        };
      },
    };
  },
});
