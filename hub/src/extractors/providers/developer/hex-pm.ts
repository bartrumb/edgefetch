import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'hex-pm',
  name: 'Hex.pm Elixir & Erlang Registry',
  category: 'developer',
  description: 'Upgrades hex.pm package pages to /api/packages/<pkg> metadata and HexDocs links.',
  domains: ['hex.pm', 'www.hex.pm'],
  exampleUrls: ['https://hex.pm/packages/phoenix'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'packages' || parts.length !== 2) return null;
    const pkg = parts[1]!;
    if (!/^[A-Za-z0-9_-]+$/.test(pkg)) return null;
    return {
      id: 'hex-pm',
      fetchUrl: `https://hex.pm/api/packages/${encodeURIComponent(pkg)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.name !== 'string') return null;
        const meta = (data.meta as Record<string, unknown> | undefined) ?? {};
        const desc = typeof meta.description === 'string' ? meta.description.trim() : '';
        const licenses = Array.isArray(meta.licenses) ? meta.licenses.join(', ') : '';
        const linksObj = (meta.links as Record<string, string> | undefined) ?? {};
        const releases = Array.isArray(data.releases) ? (data.releases as Array<Record<string, unknown>>) : [];
        const ver = typeof releases[0]?.version === 'string' ? String(releases[0].version) : '';
        const docsUrl = typeof data.docs_html_url === 'string' ? data.docs_html_url : `https://hexdocs.pm/${data.name}`;
        const title = ver ? `${data.name} ${ver} (Hex)` : `${data.name} (Hex)`;
        const bullets = [`- **Mix**: \`{:${data.name}, "~> ${ver || '0.1'}"}\``, `- **HexDocs**: ${docsUrl}`];
        if (licenses) bullets.push(`- **License**: ${licenses}`);
        for (const [label, href] of Object.entries(linksObj)) {
          if (typeof href === 'string' && href.startsWith('https://')) bullets.push(`- **${label}**: ${href}`);
        }
        return {
          title,
          ...(desc ? { description: desc } : {}),
          markdown: [`# ${title}`, ...(desc ? [desc] : []), bullets.join('\n')].join('\n\n'),
        };
      },
    };
  },
});
