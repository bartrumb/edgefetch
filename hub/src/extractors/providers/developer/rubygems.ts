import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'rubygems',
  name: 'RubyGems Registry',
  category: 'developer',
  description: 'Upgrades rubygems.org gem pages to /api/v1/gems/<gem>.json metadata.',
  domains: ['rubygems.org', 'www.rubygems.org'],
  exampleUrls: ['https://rubygems.org/gems/rails'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'gems' || parts.length < 2) return null;
    const gem = decodeURIComponent(parts[1]!);
    if (!/^[A-Za-z0-9_.-]{1,80}$/.test(gem)) return null;
    return {
      id: 'rubygems',
      fetchUrl: `https://rubygems.org/api/v1/gems/${encodeURIComponent(gem)}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.name !== 'string') return null;
        const ver = typeof data.version === 'string' ? data.version : '';
        const info = typeof data.info === 'string' ? data.info.trim() : '';
        const licenses = Array.isArray(data.licenses) ? data.licenses.join(', ') : '';
        const authors = typeof data.authors === 'string' ? data.authors : '';
        const repo = typeof data.source_code_uri === 'string' ? data.source_code_uri : typeof data.homepage_uri === 'string' ? data.homepage_uri : '';
        const docs = typeof data.documentation_uri === 'string' ? data.documentation_uri : '';
        const title = ver ? `${data.name} ${ver} (RubyGem)` : `${data.name} (RubyGem)`;
        const bullets = [`- **Install**: \`gem install ${data.name}\``];
        if (ver) bullets.push(`- **Version**: \`${ver}\``);
        if (licenses) bullets.push(`- **License**: ${licenses}`);
        if (authors) bullets.push(`- **Authors**: ${authors}`);
        if (docs) bullets.push(`- **Documentation**: ${docs}`);
        if (repo) bullets.push(`- **Repository**: ${repo}`);
        return {
          title,
          ...(info ? { description: info.slice(0, 260) } : {}),
          ...(authors ? { author: authors } : {}),
          markdown: [`# ${title}`, ...(info ? [info] : []), bullets.join('\n')].join('\n\n'),
        };
      },
    };
  },
});
