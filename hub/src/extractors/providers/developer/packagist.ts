import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'packagist',
  name: 'Packagist PHP Composer Registry',
  category: 'developer',
  description: 'Upgrades packagist.org PHP Composer package pages to their official .json metadata feed.',
  domains: ['packagist.org', 'www.packagist.org'],
  exampleUrls: ['https://packagist.org/packages/symfony/console'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'packages' || parts.length !== 3) return null;
    const vendor = parts[1]!;
    const pkg = parts[2]!;
    if (!/^[A-Za-z0-9_.-]+$/.test(vendor) || !/^[A-Za-z0-9_.-]+$/.test(pkg)) return null;
    return {
      id: 'packagist',
      fetchUrl: `https://packagist.org/packages/${vendor}/${pkg}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const pkgObj = data?.package as Record<string, unknown> | undefined;
        if (!pkgObj || typeof pkgObj.name !== 'string') return null;
        const desc = typeof pkgObj.description === 'string' ? pkgObj.description.trim() : '';
        const repo = typeof pkgObj.repository === 'string' ? pkgObj.repository : '';
        const versionsObj = (pkgObj.versions as Record<string, Record<string, unknown>> | undefined) ?? {};
        const stableVer = Object.keys(versionsObj).find((v) => !v.includes('dev')) ?? Object.keys(versionsObj)[0] ?? '';
        const verMeta = (stableVer && versionsObj[stableVer]) || {};
        const license = Array.isArray(verMeta.license) ? verMeta.license.join(', ') : '';
        const title = stableVer ? `${pkgObj.name} ${stableVer} (Composer)` : pkgObj.name;
        const bullets = [`- **Install**: \`composer require ${pkgObj.name}\``];
        if (stableVer) bullets.push(`- **Latest Version**: \`${stableVer}\``);
        if (license) bullets.push(`- **License**: ${license}`);
        if (repo) bullets.push(`- **Repository**: ${repo}`);
        return {
          title,
          ...(desc ? { description: desc } : {}),
          markdown: [`# ${title}`, ...(desc ? [desc] : []), bullets.join('\n')].join('\n\n'),
        };
      },
    };
  },
});
