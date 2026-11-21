import {
  attrHasTokenLinear,
  defineAdapter,
  findAllElementInnersLinear,
  findElementInnerLinear,
} from '../../types';
import { extractAllMetaContents, extractMetaContent, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'arxiv',
  name: 'arXiv Preprints',
  category: 'research-health',
  description: 'Extracts arXiv preprint title, authors, submission date, subject classifications, PDF/HTML links, and clean abstract from arxiv.org/abs/<id> (strictly respecting robots.txt).',
  domains: ['arxiv.org', 'www.arxiv.org'],
  exampleUrls: ['https://arxiv.org/abs/1706.03762'],
  extractHtml({ path, rawHtml }) {
    const m = /^\/abs\/([A-Za-z0-9._/-]+)$/i.exec(path);
    if (!m?.[1]) return null;
    const arxivId = m[1];

    const clean = stripScriptsAndStyles(rawHtml);
    const title =
      extractMetaContent(rawHtml, 'citation_title') ||
      stripTagsInline(findElementInnerLinear(clean, 'h1', (a) => attrHasTokenLinear(a, 'class', 'title')) ?? '').replace(/^Title:\s*/i, '');
    if (!title) return null;

    const metaAuthors = extractAllMetaContents(rawHtml, 'citation_author');
    const domAuthors = findAllElementInnersLinear(clean, 'div', (a) => attrHasTokenLinear(a, 'class', 'authors'), 5)
      .flatMap((am) => findAllElementInnersLinear(am, 'a', undefined, 50).map((x) => stripTagsInline(x)))
      .filter(Boolean);
    const authors = (metaAuthors.length > 0 ? metaAuthors : domAuthors).slice(0, 20);

    const date = extractMetaContent(rawHtml, 'citation_date') || extractMetaContent(rawHtml, 'citation_online_date');
    const doi = extractMetaContent(rawHtml, 'citation_doi');
    const primarySubject = stripTagsInline(
      findElementInnerLinear(clean, 'span', (a) => attrHasTokenLinear(a, 'class', 'primary-subject')) ?? '',
    );

    const absBlock = findElementInnerLinear(clean, 'blockquote', (a) => attrHasTokenLinear(a, 'class', 'abstract')) ?? '';
    const abstract = stripTagsInline(absBlock).replace(/^Abstract:\s*/i, '').trim() || extractMetaContent(rawHtml, 'citation_abstract');
    if (!abstract) return null;

    const pdfUrl = `https://arxiv.org/pdf/${arxivId}`;
    const htmlPaperUrl = `https://arxiv.org/html/${arxivId}`;

    const bullets: string[] = [`- **arXiv ID**: \`${arxivId}\``];
    if (authors.length > 0) bullets.push(`- **Authors**: ${authors.join(', ')}`);
    if (date) bullets.push(`- **Submitted**: ${date}`);
    if (primarySubject) bullets.push(`- **Primary Subject**: ${primarySubject}`);
    if (doi) bullets.push(`- **DOI**: \`${doi}\``);
    bullets.push(`- **Full Text**: [PDF](${pdfUrl}) · [ar5iv / HTML](${htmlPaperUrl})`);

    return {
      extractorId: 'arxiv',
      title,
      description: abstract.slice(0, 260),
      ...(authors.length > 0 ? { author: authors.slice(0, 4).join(', ') } : {}),
      ...(date ? { publishedTime: date } : {}),
      markdown: [`# ${title}`, bullets.join('\n'), `## Abstract\n\n${abstract}`].join('\n\n'),
      links: [pdfUrl, htmlPaperUrl],
    };
  },
});
