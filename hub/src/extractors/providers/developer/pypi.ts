import { attrHasTokenLinear, defineAdapter, findElementInnerLinear, findOpenTagLinear, getAttrValueLinear } from '../../types';
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
    const headerName = stripTagsInline(
      findElementInnerLinear(
        clean,
        'h1',
        (a) => attrHasTokenLinear(a, 'class', 'project-header__name') || attrHasTokenLinear(a, 'class', 'package-header__name'),
      ) ?? '',
    );
    if (!headerName) return null;
    const descOpen =
      findOpenTagLinear(clean, 'div', (a) => getAttrValueLinear(a, 'id') === 'description') ??
      findOpenTagLinear(clean, 'div', (a) => attrHasTokenLinear(a, 'class', 'project-description'));
    if (!descOpen) return null;
    const pipCmd = stripTagsInline(
      findElementInnerLinear(clean, 'span', (a) => getAttrValueLinear(a, 'id') === 'pip-command') ?? '',
    );
    const summary = stripTagsInline(
      findElementInnerLinear(
        clean,
        'p',
        (a) =>
          attrHasTokenLinear(a, 'class', 'project-header__summary') ||
          attrHasTokenLinear(a, 'class', 'package-description__summary'),
      ) ?? '',
    );
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
