import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

const KNOWN_SOCRATA_HOSTS = new Set([
  'data.cityofnewyork.us',
  'data.sfgov.org',
  'data.sf.gov',
  'data.seattle.gov',
  'data.cityofchicago.org',
  'data.lacity.org',
  'data.wa.gov',
  'data.nj.gov',
  'data.colorado.gov',
  'data.texas.gov',
  'data.ny.gov',
  'data.ct.gov',
  'data.oregon.gov',
  'data.austintexas.gov',
  'data.nola.gov',
  'data.cincinnati-oh.gov',
  'data.cambridgema.gov',
  'data.montgomerycountymd.gov',
  'data.brla.gov',
  'data.cdc.gov',
  'data.cms.gov',
  'data.medicare.gov',
]);

function isLikelySocrataHost(host: string): boolean {
  if (KNOWN_SOCRATA_HOSTS.has(host)) return true;
  if (host.endsWith('.socrata.com')) return true;
  if (/^data\.[a-z0-9-]+\.(?:gov|org|us)$/i.test(host)) return true;
  return false;
}

export default defineAdapter({
  id: 'socrata',
  name: 'Socrata Open Data Portals (SODA Universal Engine)',
  category: 'public-records',
  description: 'Upgrades city, state, and federal Socrata open-data dataset URLs (/d/<4x4-id> or /dataset/.../<4x4-id>) to /api/views/<id>.json column schemas and SODA endpoints.',
  domains: [
    'data.cityofnewyork.us',
    'data.sfgov.org',
    'data.sf.gov',
    'data.seattle.gov',
    'data.cityofchicago.org',
    'data.lacity.org',
    'data.wa.gov',
    'data.nj.gov',
    'data.colorado.gov',
    'data.texas.gov',
    'data.ny.gov',
    'data.cdc.gov',
    '*.socrata.com',
  ],
  universalEngine: true,
  exampleUrls: [
    'https://data.cityofnewyork.us/Housing-Development/DOB-Job-Application-Filings/ic3t-wcy2',
    'https://data.sfgov.org/d/i98e-djp9',
  ],
  resolveTwin({ host, parts }) {
    if (!isLikelySocrataHost(host) || parts.length < 2) return null;
    // Socrata 4x4 dataset view IDs match `^[a-z0-9]{4}-[a-z0-9]{4}$` (with at least one digit to avoid plain English words like `open-data`!).
    let viewId = '';
    if (parts[0] === 'd' && parts[1] && /^(?=.*\d)[a-z0-9]{4}-[a-z0-9]{4}$/i.test(parts[1])) {
      viewId = parts[1].toLowerCase();
    } else {
      const last = parts[parts.length - 1] === 'about_data' && parts.length >= 3 ? parts[parts.length - 2]! : parts[parts.length - 1]!;
      if (/^(?=.*\d)[a-z0-9]{4}-[a-z0-9]{4}$/i.test(last)) {
        viewId = last.toLowerCase();
      }
    }
    if (!viewId) return null;

    return {
      id: 'socrata',
      fetchUrl: `https://${host}/api/views/${viewId}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.name !== 'string' || typeof data.id !== 'string') return null;

        const name = data.name.trim();
        const desc = typeof data.description === 'string' ? data.description.trim() : '';
        const attribution = typeof data.attribution === 'string' ? data.attribution : '';
        const category = typeof data.category === 'string' ? data.category : '';
        const licenseObj = data.license as { name?: string } | undefined;
        const license = typeof licenseObj?.name === 'string' ? licenseObj.name : '';
        const updatedEpoch = typeof data.rowsUpdatedAt === 'number' ? new Date(data.rowsUpdatedAt * 1000).toISOString().slice(0, 10) : '';
        const sodaJsonUrl = `https://${host}/resource/${viewId}.json?$limit=50`;
        const csvExportUrl = `https://${host}/api/views/${viewId}/rows.csv?accessType=DOWNLOAD`;

        const bullets: string[] = [
          `- **Dataset ID**: \`${viewId}\` (${host})`,
          `- **SODA JSON API**: \`${sodaJsonUrl}\``,
          `- **CSV Download**: ${csvExportUrl}`,
        ];
        if (attribution) bullets.push(`- **Agency / Attribution**: ${attribution}`);
        if (category) bullets.push(`- **Category**: ${category}`);
        if (updatedEpoch) bullets.push(`- **Rows Last Updated**: ${updatedEpoch}`);
        if (license) bullets.push(`- **License**: ${license}`);

        const columns = Array.isArray(data.columns) ? (data.columns as Array<Record<string, unknown>>) : [];
        const visibleCols = columns.filter((c) => !String(c.fieldName ?? '').startsWith(':@')).slice(0, 40);
        const colRows = visibleCols.map((c) => [
          `\`${String(c.fieldName ?? '-')}\``,
          String(c.name ?? '-'),
          String(c.dataTypeName ?? '-'),
          String(c.description ?? '-'),
        ]);

        const sections = [`# ${name}`, bullets.join('\n')];
        if (desc) sections.push(`## Description\n\n${desc}`);
        if (colRows.length > 0) {
          sections.push(`## Schema (${visibleCols.length} Columns)\n\n${formatGfmTable(['Field Name', 'Label', 'Type', 'Description'], colRows)}`);
        }

        return {
          title: `${name} (${host})`,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          ...(updatedEpoch ? { publishedTime: updatedEpoch } : {}),
          markdown: sections.join('\n\n'),
          links: [sodaJsonUrl, csvExportUrl],
        };
      },
    };
  },
});
