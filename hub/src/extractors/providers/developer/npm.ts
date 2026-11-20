import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'npm-registry',
  name: 'npm Package Registry',
  category: 'developer',
  description: 'Upgrades npmjs.com package pages to registry.npmjs.org JSON metadata, TypeScript declarations, dependency list, and README.',
  domains: ['npmjs.com', 'www.npmjs.com'],
  exampleUrls: ['https://www.npmjs.com/package/@cloudflare/workers-types'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'package' || parts.length < 2) return null;
    let pkgName = '';
    let requestedVer = '';
    if (parts[1]!.startsWith('@') && parts.length >= 3) {
      pkgName = `${decodeURIComponent(parts[1]!)}/${decodeURIComponent(parts[2]!)}`;
      if (parts[3] === 'v' && parts[4]) requestedVer = decodeURIComponent(parts[4]);
    } else {
      pkgName = decodeURIComponent(parts[1]!);
      if (parts[2] === 'v' && parts[3]) requestedVer = decodeURIComponent(parts[3]);
    }
    if (!/^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i.test(pkgName)) return null;
    const encodedPkg = pkgName.startsWith('@')
      ? `@${encodeURIComponent(pkgName.slice(1).split('/')[0]!)}%2F${encodeURIComponent(pkgName.split('/')[1]!)}`
      : encodeURIComponent(pkgName);
    return {
      id: 'npm-registry',
      fetchUrl: `https://registry.npmjs.org/${encodedPkg}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.name !== 'string') return null;
        const distTags = (data['dist-tags'] as Record<string, string> | undefined) ?? {};
        const ver = requestedVer || distTags.latest || '';
        const versions = (data.versions as Record<string, Record<string, unknown>> | undefined) ?? {};
        const verObj = (ver && versions[ver]) || {};
        const desc = typeof (verObj.description ?? data.description) === 'string' ? String(verObj.description ?? data.description).trim() : '';
        const license = typeof (verObj.license ?? data.license) === 'string' ? String(verObj.license ?? data.license) : '';
        const homepage = typeof (verObj.homepage ?? data.homepage) === 'string' ? String(verObj.homepage ?? data.homepage) : '';
        const repoObj = (verObj.repository ?? data.repository) as { url?: string } | string | undefined;
        const repoRaw = typeof repoObj === 'string' ? repoObj : typeof repoObj?.url === 'string' ? repoObj.url : '';
        const repoClean = repoRaw.replace(/^git\+/, '').replace(/\.git$/, '');
        const hasTypes = Boolean(verObj.types || verObj.typings || String(verObj.exports ?? '').includes('types'));
        const deps = verObj.dependencies && typeof verObj.dependencies === 'object' ? Object.keys(verObj.dependencies as object) : [];
        const readme = typeof data.readme === 'string' && data.readme !== 'ERROR: No README data found!' ? data.readme.trim() : '';

        const title = ver ? `${data.name}@${ver}` : data.name;
        const bullets: string[] = [`- **Install**: \`npm install ${data.name}\``];
        if (ver) bullets.push(`- **Latest Version**: \`${ver}\``);
        if (license) bullets.push(`- **License**: ${license}`);
        if (hasTypes) bullets.push(`- **TypeScript**: Bundled declarations included`);
        bullets.push(
          `- **Runtime Dependencies**: ${deps.length}${deps.length > 0 ? ` (${deps.slice(0, 10).join(', ')}${deps.length > 10 ? ', ...' : ''})` : ' (zero dependencies)'}`,
        );
        if (homepage) bullets.push(`- **Homepage**: ${homepage}`);
        if (repoClean.startsWith('http')) bullets.push(`- **Repository**: ${repoClean}`);

        const sections = [`# ${title}`];
        if (desc) sections.push(desc);
        sections.push(bullets.join('\n'));
        if (readme) {
          sections.push(readme.replace(/^#\s+.+\n+/, '').trim() || readme);
        }
        return { title, ...(desc ? { description: desc } : {}), markdown: sections.join('\n\n') };
      },
    };
  },
});
