import { defineAdapter } from '../../types';
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
      /<div\b[^>]*\bgist-content\b[\s\S]{0,1200}?<div\b[^>]*itemprop=["']about["'][^>]*>([\s\S]*?)<\/div>/i.exec(rawHtml)?.[1] ?? '',
    );
    const titleRaw = stripTagsInline(/<title>([\s\S]*?)<\/title>/i.exec(rawHtml)?.[1] ?? '')
      .replace(/\s*·\s*GitHub\s*$/i, '')
      .trim();
    const files: string[] = [];

    const fileBoxRe = /<div\b[^>]*\bclass=["'][^"']*\bfile\b[^"']*["'][^>]*>/gi;
    let fm: RegExpExecArray | null;
    while ((fm = fileBoxRe.exec(rawHtml)) !== null && files.length < 20) {
      const box = extractBalancedDivAt(rawHtml, fm.index);
      if (!box) continue;
      const name = stripTagsInline(/<strong\b[^>]*\bgist-blob-name\b[^>]*>([\s\S]*?)<\/strong>/i.exec(box)?.[1] ?? '');
      if (!name) continue;
      const mdArticle = /<article\b[^>]*\bmarkdown-body\b[^>]*>([\s\S]*?)<\/article>/i.exec(box);
      if (mdArticle) {
        files.push(`## ${name}\n\n${htmlToMd(mdArticle[1]!, baseUrl).markdown.trim()}`);
        continue;
      }
      const codeLines = [...box.matchAll(/<td\b[^>]*\bblob-code-inner\b[^>]*>([\s\S]*?)<\/td>/gi)].map((m) =>
        decodeBasicEntities(m[1]!.replace(/<[^>]+>/g, '')),
      );
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
