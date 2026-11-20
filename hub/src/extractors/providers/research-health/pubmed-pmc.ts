import { defineAdapter } from '../../types';
import { extractBalancedDivAt, parseJsonObject, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'pubmed-pmc',
  name: 'PubMed & PubMed Central (NCBI / Europe PMC)',
  category: 'research-health',
  description: 'Upgrades PubMed & PMC URLs to robots.txt-allowed Europe PMC REST JSON/JATS XML (with NCBI HTML fallback).',
  domains: ['pubmed.ncbi.nlm.nih.gov', 'pmc.ncbi.nlm.nih.gov'],
  exampleUrls: ['https://pubmed.ncbi.nlm.nih.gov/31452104/', 'https://pmc.ncbi.nlm.nih.gov/articles/PMC7095418/'],
  resolveTwin({ host, path }) {
    const pmidMatch = host === 'pubmed.ncbi.nlm.nih.gov' ? /^\/(\d+)\/?$/.exec(path) : null;
    if (pmidMatch?.[1]) {
      const pmid = pmidMatch[1];
      return {
        id: 'pubmed-europepmc',
        fetchUrl: `https://www.ebi.ac.uk/europepmc/webservices/rest/search?query=EXT_ID:${pmid}%20AND%20SRC:MED&resultType=core&format=json`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const resultList = data?.resultList as Record<string, unknown> | undefined;
          const results = Array.isArray(resultList?.result) ? (resultList.result as Array<Record<string, unknown>>) : null;
          const r = results?.[0];
          if (!r || typeof r.title !== 'string') return null;

          const title = stripTagsInline(r.title).replace(/\.$/, '').trim();
          const authorString = typeof r.authorString === 'string' ? r.authorString.trim() : '';
          const journalInfo = r.journalInfo as Record<string, unknown> | undefined;
          const journalTitle = typeof (journalInfo?.journal as Record<string, unknown> | undefined)?.title === 'string'
            ? String((journalInfo!.journal as Record<string, unknown>).title)
            : '';
          const pubYear = typeof r.pubYear === 'string' ? r.pubYear : '';
          const doi = typeof r.doi === 'string' ? r.doi : '';
          const pmcid = typeof r.pmcid === 'string' ? r.pmcid : '';
          const citedBy = typeof r.citedByCount === 'number' ? r.citedByCount : null;
          const abstractText = typeof r.abstractText === 'string' ? stripTagsInline(r.abstractText) : '';

          const meta: string[] = [`- **PMID**: \`${pmid}\``];
          if (authorString) meta.push(`- **Authors**: ${authorString}`);
          if (journalTitle) meta.push(`- **Journal**: ${journalTitle}${pubYear ? ` (${pubYear})` : ''}`);
          if (doi) meta.push(`- **DOI**: \`${doi}\``);
          if (pmcid) meta.push(`- **Full Text (PMC)**: [${pmcid}](https://pmc.ncbi.nlm.nih.gov/articles/${pmcid}/)`);
          if (citedBy !== null) meta.push(`- **Cited By**: ${citedBy.toLocaleString('en-US')}`);

          const sections = [`# ${title}`, meta.join('\n')];
          if (abstractText) {
            sections.push(`## Abstract\n\n${abstractText}`);
          }
          return {
            title,
            ...(authorString ? { author: authorString } : {}),
            ...(pubYear ? { publishedTime: pubYear } : {}),
            markdown: sections.join('\n\n'),
            links: [
              ...(doi ? [`https://doi.org/${doi}`] : []),
              ...(pmcid ? [`https://pmc.ncbi.nlm.nih.gov/articles/${pmcid}/`] : []),
            ],
          };
        },
      };
    }

    const pmcMatch = host === 'pmc.ncbi.nlm.nih.gov' ? /^\/articles\/(PMC\d+)(?:\/|$)/i.exec(path) : null;
    if (pmcMatch?.[1]) {
      const pmcid = pmcMatch[1].toUpperCase();
      return {
        id: 'pmc-europepmc',
        fetchUrl: `https://www.ebi.ac.uk/europepmc/webservices/rest/${pmcid}/fullTextXML`,
        kind: 'text',
        accept: 'application/xml, text/xml',
        formatTwin: (rawXml) => {
          const title = stripTagsInline(/<article-title\b[^>]*>([\s\S]*?)<\/article-title>/i.exec(rawXml)?.[1] ?? '');
          if (!title) return null;
          const abs = stripTagsInline(/<abstract\b[^>]*>([\s\S]*?)<\/abstract>/i.exec(rawXml)?.[1] ?? '');
          const bodyBlocks: string[] = [];
          const bodyXml = /<body\b[^>]*>([\s\S]*?)<\/body>/i.exec(rawXml)?.[1] ?? '';
          for (const sec of bodyXml.matchAll(/<sec\b[^>]*>([\s\S]*?)<\/sec>/gi)) {
            const secTitle = stripTagsInline(/<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(sec[1]!)?.[1] ?? '');
            const paras = [...sec[1]!.matchAll(/<p\b[^>]*>([\s\S]*?)<\/p>/gi)]
              .map((p) => stripTagsInline(p[1]!))
              .filter(Boolean);
            if (paras.length > 0 && bodyBlocks.length < 30) {
              bodyBlocks.push(secTitle ? `## ${secTitle}\n\n${paras.join('\n\n')}` : paras.join('\n\n'));
            }
          }
          const sections = [`# ${title}`, `- **PMCID**: \`${pmcid}\``];
          if (abs) sections.push(`## Abstract\n\n${abs}`);
          if (bodyBlocks.length > 0) sections.push(...bodyBlocks);
          return {
            title,
            markdown: sections.join('\n\n'),
          };
        },
      };
    }

    return null;
  },
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
