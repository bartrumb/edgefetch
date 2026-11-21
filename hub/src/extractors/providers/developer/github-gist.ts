import {
  attrHasTokenLinear,
  defineAdapter,
  findAllElementInnersLinear,
  findAllOpenTagsLinear,
  findElementInnerLinear,
  getAttrValueLinear,
} from '../../types';
import { decodeBasicEntities, detectFenceLang, extractBalancedDivAt, safeFence, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'github-gist',
  name: 'GitHub Gists',
  category: 'developer',
  description: 'Extracts multi-file GitHub Gist code blocks with fenced language tags and rendered Markdown.',
  domains: ['gist.github.com'],
  exampleUrls: ['https://gist.github.com/octocat/6cad326836d38bd3a7ae'],
  extractHtml({ parts, rawHtml, baseUrl, htmlToMd }) {
    if (parts.length < 2) return null;
    const desc = stripTagsInline(
      findElementInnerLinear(rawHtml, 'div', (a) => getAttrValueLinear(a, 'itemprop') === 'about') ?? '',
    );
    const titleRaw = stripTagsInline(findElementInnerLinear(rawHtml, 'title') ?? '')
      .replace(/\s*·\s*GitHub\s*$/i, '')
      .trim();
    const files: string[] = [];

    const fileBoxes = findAllOpenTagsLinear(rawHtml, 'div', (a) => attrHasTokenLinear(a, 'class', 'file'), 20);
    for (const fm of fileBoxes) {
      const box = extractBalancedDivAt(rawHtml, fm.index);
      if (!box) continue;
      const name = stripTagsInline(
        findElementInnerLinear(box, 'strong', (a) => attrHasTokenLinear(a, 'class', 'gist-blob-name')) ?? '',
      );
      if (!name) continue;
      const mdArticle = findElementInnerLinear(box, 'article', (a) => attrHasTokenLinear(a, 'class', 'markdown-body'));
      if (mdArticle) {
        files.push(`## ${name}\n\n${htmlToMd(mdArticle, baseUrl).markdown.trim()}`);
        continue;
      }
      const codeLines = findAllElementInnersLinear(
        box,
        'td',
        (a) => attrHasTokenLinear(a, 'class', 'blob-code-inner'),
        5000,
      ).map((inner) => decodeBasicEntities(stripTagsInline(inner)));
      if (codeLines.length > 0) {
        const { lang } = detectFenceLang(name);
        files.push(`## ${name}\n\n${safeFence(codeLines.join('\n'), lang)}`);
      }
    }

    if (files.length === 0) return null;
    const title = titleRaw || desc || 'GitHub Gist';
    const sections = [`# ${title}`];
    if (desc && desc !== title) sections.push(desc);
    sections.push(files.join('\n\n'));
    return {
      extractorId: 'github-gist',
      title,
      ...(desc ? { description: desc } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
