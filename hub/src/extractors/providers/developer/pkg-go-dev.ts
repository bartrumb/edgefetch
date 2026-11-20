import { defineAdapter } from '../../types';
import { extractBalancedDivAt, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'pkg-go-dev',
  name: 'Go Packages (pkg.go.dev)',
  category: 'developer',
  description: 'Extracts Go module README and API documentation sections cleanly from pkg.go.dev.',
  domains: ['pkg.go.dev'],
  exampleUrls: ['https://pkg.go.dev/github.com/coder/websocket'],
  extractHtml({ path, rawHtml, baseUrl, htmlToMd }) {
    if (path.length <= 1) return null;
    const clean = stripScriptsAndStyles(rawHtml);
    const title = stripTagsInline(/<title>([\s\S]*?)<\/title>/i.exec(clean)?.[1] ?? '')
      .replace(/\s*-\s*Go Packages\s*$/i, '')
      .trim();

    const sections: string[] = [];
    if (title) sections.push(`# ${title}`);

    const readmeOpen = /<div\b[^>]*\bUnitReadme-content\b[^>]*>/i.exec(clean);
    if (readmeOpen) {
      const inner = extractBalancedDivAt(clean, readmeOpen.index);
      if (inner) {
        const md = htmlToMd(inner, baseUrl).markdown.trim();
        if (md) sections.push(`## Overview / README\n\n${md}`);
      }
    }

    const docOpen = /<div\b[^>]*\bDocumentation-content\b[^>]*>/i.exec(clean);
    if (docOpen) {
      const inner = extractBalancedDivAt(clean, docOpen.index);
      if (inner) {
        const md = htmlToMd(inner, baseUrl).markdown.replace(/\s*¶(\s|$)/g, '$1').trim();
        if (md) sections.push(`## Documentation\n\n${md}`);
      }
    }

    if (sections.length <= 1) return null;
    return { extractorId: 'pkg-go-dev', ...(title ? { title } : {}), markdown: sections.join('\n\n') };
  },
});
