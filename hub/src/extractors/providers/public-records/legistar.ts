import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonValue } from '../../utils';

export default defineAdapter({
  id: 'legistar',
  name: 'Legistar Municipal Council Legislation & Meetings',
  category: 'public-records',
  description: 'Upgrades <client>.legistar.com municipal council portals to the keyless webapi.legistar.com REST API for ordinances, resolutions, and meetings.',
  domains: ['*.legistar.com'],
  exampleUrls: ['https://nyc.legistar.com/Legislation.aspx', 'https://seattle.legistar.com/Calendar.aspx'],
  resolveTwin({ host, path }) {
    const m = /^([a-z0-9-]+)\.legistar\.com$/i.exec(host);
    if (!m?.[1]) return null;
    const client = m[1].toLowerCase();
    if (client === 'www' || client === 'webapi') return null;

    const isCalendar = /calendar/i.test(path);
    const endpoint = isCalendar
      ? `https://webapi.legistar.com/v1/${encodeURIComponent(client)}/events?$top=20&$orderby=EventDate%20desc`
      : `https://webapi.legistar.com/v1/${encodeURIComponent(client)}/matters?$top=25&$orderby=MatterIntroDate%20desc`;

    return {
      id: 'legistar',
      fetchUrl: endpoint,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const parsed = parseJsonValue(rawBody);
        if (!Array.isArray(parsed) || parsed.length === 0) return null;
        const rowsData = parsed as Array<Record<string, unknown>>;

        if (isCalendar) {
          const rows = rowsData.slice(0, 20).map((ev) => [
            String(ev.EventDate ?? '').slice(0, 10),
            String(ev.EventBodyName ?? '-'),
            String(ev.EventLocation ?? '-'),
            typeof ev.EventInSiteURL === 'string' && ev.EventInSiteURL.startsWith('https://')
              ? `[Agenda](${ev.EventInSiteURL})`
              : '-',
          ]);
          const title = `${client.toUpperCase()} Municipal Council — Recent Meetings (Legistar)`;
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Date', 'Body / Committee', 'Location', 'Link'], rows)}`,
          };
        }

        const rows = rowsData.slice(0, 25).map((mt) => [
          `\`${String(mt.MatterFile ?? '-')}\``,
          String(mt.MatterTypeName ?? '-'),
          String(mt.MatterStatusName ?? '-'),
          String(mt.MatterIntroDate ?? '').slice(0, 10),
          String(mt.MatterTitle || mt.MatterName || '-'),
        ]);
        const title = `${client.toUpperCase()} Municipal Legislation — Recent Matters (Legistar)`;
        return {
          title,
          markdown: `# ${title}\n\n${formatGfmTable(['File #', 'Type', 'Status', 'Introduced', 'Title'], rows)}`,
        };
      },
    };
  },
});
