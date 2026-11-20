import { defineAdapter } from '../../types';
import { extractBalancedDivAt, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'pubmed-pmc',
  name: 'PubMed & PubMed Central (NCBI)',
  category: 'research-health',
  description: 'Extracts PubMed abstracts and full-text PMC articles with authors and DOI citations.',
  domains: ['pubmed.ncbi.nlm.nih.gov', 'pmc.ncbi.nlm.nih.gov'],
  exampleUrls: ['https://pubmed.ncbi.nlm.nih.gov/38000001/', 'https://pmc.ncbi.nlm.nih.gov/articles/PMC9000001/'],
  extractHtml({ host, path, rawHtml, baseUrl, htmlToMd }) {
    const isPubmed = host === 'pubmed.ncbi.nlm.nih.gov' && /^\/\d+\/?$/.test(path);
    const isPmc = host === 'pmc.ncbi.nlm.nih.gov' && /^\/articles\/PMC\d+/i.test(path);
    if (!isPubmed && !isPmc) return null;

    const clean = stripScriptsAndStyles(rawHtml);
    const title = stripTagsInline(
      /<h1\b[^>]*\bheading-title\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ??
        /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ??
        '',
    );
    if (!title) return null;

    const authors = [...clean.matchAll(/<a\b[^>]*\bfull-name\b[^>]*>([\s\S]*?)<\/a>/gi)]
      .map((m) => stripTagsInline(m[1]!))
      .filter((a, i, arr) => Boolean(a) && arr.indexOf(a) === i)
      .slice(0, 15);
    const doi = stripTagsInline(/<span\b[^>]*\bcitation-doi\b[^>]*>([\s\S]*?)<\/span>/i.exec(clean)?.[1] ?? '');

    const absOpen =
      /<div\b[^>]*\bid=["'](?:abstract|eng-abstract)["'][^>]*>/i.exec(clean) ??
      /<section\b[^>]*\bclass=["'][^"']*\babstract\b[^"']*["'][^>]*>([\s\S]*?)<\/section>/i.exec(clean);

    let bodyMd = '';
    const pmcArticle = /<article\b[^>]*\barticle\b[^>]*>([\s\S]*?)<\/article>/i.exec(clean);
    if (pmcArticle) {
      bodyMd = htmlToMd(pmcArticle[1]!, baseUrl).markdown.trim();
    } else if (absOpen) {
      const inner = absOpen[0].startsWith('<div') ? extractBalancedDivAt(clean, absOpen.index) : absOpen[1] ?? '';
      if (inner) bodyMd = htmlToMd(inner, baseUrl).markdown.trim();
    }
    if (!bodyMd) return null;

    const meta: string[] = [];
    if (authors.length > 0) meta.push(`- **Authors**: ${authors.join(', ')}`);
    if (doi) meta.push(`- **Citation**: ${doi}`);

    const sections = [`# ${title}`];
    if (meta.length > 0) sections.push(meta.join('\n'));
    sections.push(bodyMd.startsWith('#') ? bodyMd : `## Abstract\n\n${bodyMd}`);
    return {
      extractorId: 'pubmed-pmc',
      title,
      ...(authors.length > 0 ? { author: authors.slice(0, 4).join(', ') } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
