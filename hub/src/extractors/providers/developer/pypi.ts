import { defineAdapter } from '../../types';
import { extractBalancedDivAt, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'pypi-project',
  name: 'PyPI Python Package Index',
  category: 'developer',
  description: 'Extracts PyPI package install command, summary, and project README from pypi.org/project/<pkg>/ (respecting robots.txt on /json).',
  domains: ['pypi.org', 'www.pypi.org'],
  exampleUrls: ['https://pypi.org/project/httpx/'],
  extractHtml({ path, rawHtml, baseUrl, htmlToMd }) {
    if (!/^\/project\/[^/]+/i.test(path)) return null;
    const clean = stripScriptsAndStyles(rawHtml);
    const headerName = stripTagsInline(/<h1\b[^>]*\bpackage-header__name\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ?? '');
    const pipCmd = stripTagsInline(/<span\b[^>]*\bid=["']pip-command["'][^>]*>([\s\S]*?)<\/span>/i.exec(clean)?.[1] ?? '');
    const summary = stripTagsInline(/<p\b[^>]*\bpackage-description__summary\b[^>]*>([\s\S]*?)<\/p>/i.exec(clean)?.[1] ?? '');
    const descOpen = /<div\b[^>]*\bid=["']description["'][^>]*>/i.exec(clean) ?? /<div\b[^>]*\bproject-description\b[^>]*>/i.exec(clean);
    if (!descOpen || !headerName) return null;
    const inner = extractBalancedDivAt(clean, descOpen.index);
    if (!inner) return null;
    const readmeMd = htmlToMd(inner, baseUrl).markdown.trim();
    if (!readmeMd) return null;

    const sections: string[] = [`# ${headerName}`];
    if (summary) sections.push(summary);
    if (pipCmd) sections.push(`- **Install**: \`${pipCmd}\``);
    sections.push(readmeMd.replace(/^#\s+.+\n+/, '').trim() || readmeMd);
    return {
      extractorId: 'pypi-project',
      title: headerName,
      ...(summary ? { description: summary } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
