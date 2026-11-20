import { defineAdapter } from '../../types';
import { decodeBasicEntities, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'ietf-rfc',
  name: 'IETF Datatracker & RFC Editor',
  category: 'developer',
  description: 'Strips ASCII RFC running page headers/footers ([Page N]) and promotes numbered section headings to Markdown headings.',
  domains: ['datatracker.ietf.org', 'rfc-editor.org', 'www.rfc-editor.org'],
  exampleUrls: ['https://datatracker.ietf.org/doc/html/rfc9421', 'https://www.rfc-editor.org/rfc/rfc9110'],
  extractHtml({ host, path, rawHtml, currentMd }) {
    const isDatatracker = host === 'datatracker.ietf.org' && /^\/doc\/html\/(?:rfc|draft-)/i.test(path);
    const isRfcEditor = (host === 'www.rfc-editor.org' || host === 'rfc-editor.org') && /^\/rfc\/rfc\d+/i.test(path);
    if (!isDatatracker && !isRfcEditor) return null;

    const preBlocks = [...rawHtml.matchAll(/<pre\b[^>]*\bclass=["'][^"']*\bnewpage\b[^"']*["'][^>]*>([\s\S]*?)<\/pre>/gi)];
    const sourceText =
      preBlocks.length > 0 ? preBlocks.map((m) => decodeBasicEntities(m[1]!.replace(/<[^>]+>/g, ''))).join('\n') : currentMd;
    if (!sourceText || sourceText.trim().length < 80) return null;

    const cleanedLines: string[] = [];
    for (const rawLine of sourceText.replace(/\r\n/g, '\n').replace(/\f/g, '\n').split('\n')) {
      if (/\[Page\s+\d+\]\s*$/i.test(rawLine)) continue;
      if (
        /^RFC\s+\d+\s{2,}.+\s{2,}(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\s*$/i.test(
          rawLine.trim(),
        )
      ) {
        continue;
      }
      const secMatch = /^(\d+(?:\.\d+){0,3})\.\s+([A-Z][^\r\n]{1,90})$/.exec(rawLine.trim());
      if (secMatch && rawLine === rawLine.trim()) {
        const depth = Math.min(4, secMatch[1]!.split('.').length + 1);
        cleanedLines.push(`\n${'#'.repeat(depth)} ${secMatch[1]}. ${secMatch[2]}\n`);
      } else {
        cleanedLines.push(rawLine);
      }
    }

    const md = cleanedLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    const title = stripTagsInline(/<title>([\s\S]*?)<\/title>/i.exec(rawHtml)?.[1] ?? '').trim();
    return {
      extractorId: 'ietf-rfc',
      ...(title ? { title } : {}),
      markdown: title && !md.startsWith('# ') ? `# ${title}\n\n${md}` : md,
    };
  },
});
