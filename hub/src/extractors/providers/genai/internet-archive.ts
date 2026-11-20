import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'internet-archive',
  name: 'Internet Archive Items (archive.org)',
  category: 'genai',
  description: 'Upgrades archive.org/details/<id> pages to the official /metadata/<id> JSON feed with creator, license, and downloadable files.',
  domains: ['archive.org', 'www.archive.org'],
  exampleUrls: ['https://archive.org/details/apollo11-audio'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'details' || parts.length !== 2) return null;
    const identifier = decodeURIComponent(parts[1]!);
    if (!/^[A-Za-z0-9._-]{2,120}$/.test(identifier) || identifier.startsWith('@')) return null;

    return {
      id: 'internet-archive',
      fetchUrl: `https://archive.org/metadata/${encodeURIComponent(identifier)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const meta = data?.metadata as Record<string, unknown> | undefined;
        if (!meta || typeof meta !== 'object') return null;

        const title = String(meta.title ?? identifier).trim();
        const creator = Array.isArray(meta.creator) ? meta.creator.join(', ') : typeof meta.creator === 'string' ? meta.creator : '';
        const mediatype = typeof meta.mediatype === 'string' ? meta.mediatype : '';
        const date = typeof meta.date === 'string' ? meta.date : typeof meta.publicdate === 'string' ? meta.publicdate : '';
        const license = typeof meta.licenseurl === 'string' ? meta.licenseurl : '';
        const collections = Array.isArray(meta.collection)
          ? meta.collection.slice(0, 6).join(', ')
          : typeof meta.collection === 'string'
            ? meta.collection
            : '';
        const rawDesc = Array.isArray(meta.description) ? meta.description.join('\n\n') : typeof meta.description === 'string' ? meta.description : '';
        const desc = rawDesc ? stripTagsInline(rawDesc) : '';

        const bullets: string[] = [`- **Identifier**: \`${identifier}\``];
        if (creator) bullets.push(`- **Creator**: ${creator}`);
        if (mediatype) bullets.push(`- **Media Type**: ${mediatype}`);
        if (date) bullets.push(`- **Date**: ${date}`);
        if (collections) bullets.push(`- **Collections**: ${collections}`);
        if (license) bullets.push(`- **License**: ${license}`);

        const files = Array.isArray(data?.files) ? (data.files as Array<Record<string, unknown>>) : [];
        const originalFiles = files
          .filter((f) => typeof f.name === 'string' && !String(f.name).endsWith('_meta.xml') && !String(f.name).endsWith('_files.xml'))
          .slice(0, 15);
        const links: string[] = [];
        const rows: Array<Array<string>> = [];
        for (const f of originalFiles) {
          const fname = String(f.name);
          const format = typeof f.format === 'string' ? f.format : '-';
          const bytes = Number(f.size ?? 0);
          const sizeStr = bytes > 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : bytes > 0 ? `${Math.round(bytes / 1024)} KB` : '-';
          const dlUrl = `https://archive.org/download/${encodeURIComponent(identifier)}/${encodeURIComponent(fname)}`;
          links.push(dlUrl);
          rows.push([`[${fname}](${dlUrl})`, format, sizeStr]);
        }

        const sections: string[] = [`# ${title}`];
        sections.push(bullets.join('\n'));
        if (desc) sections.push(`## Description\n\n${desc}`);
        if (rows.length > 0) sections.push(`## Files\n\n${formatGfmTable(['File', 'Format', 'Size'], rows)}`);

        return {
          title,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          ...(creator ? { author: creator } : {}),
          ...(date ? { publishedTime: date } : {}),
          markdown: sections.join('\n\n'),
          links,
        };
      },
    };
  },
});
