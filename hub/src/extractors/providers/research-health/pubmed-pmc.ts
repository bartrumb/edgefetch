import {
  attrHasTokenLinear,
  defineAdapter,
  findAllElementInnersLinear,
  findElementInnerLinear,
  findOpenTagLinear,
  getAttrValueLinear,
} from '../../types';
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
        accept: 'application/xml',
        formatTwin: (rawXml) => {
          const title = stripTagsInline(findElementInnerLinear(rawXml, 'article-title') ?? '');
          if (!title) return null;
          const abs = stripTagsInline(findElementInnerLinear(rawXml, 'abstract') ?? '');
          const bodyBlocks: string[] = [];
          const bodyXml = findElementInnerLinear(rawXml, 'body') ?? '';
          for (const sec of findAllElementInnersLinear(bodyXml, 'sec', undefined, 60)) {
            const secTitle = stripTagsInline(findElementInnerLinear(sec, 'title') ?? '');
            const paras = findAllElementInnersLinear(sec, 'p', undefined, 100)
              .map((p) => stripTagsInline(p))
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
      findElementInnerLinear(clean, 'h1', (a) => attrHasTokenLinear(a, 'class', 'heading-title')) ??
        findElementInnerLinear(clean, 'h1') ??
        '',
    );
    if (!title) return null;

    const authors = findAllElementInnersLinear(clean, 'a', (a) => attrHasTokenLinear(a, 'class', 'full-name'), 20)
      .map((inner) => stripTagsInline(inner))
      .filter((a, i, arr) => Boolean(a) && arr.indexOf(a) === i)
      .slice(0, 15);
    const doi = stripTagsInline(
      findElementInnerLinear(clean, 'span', (a) => attrHasTokenLinear(a, 'class', 'citation-doi')) ?? '',
    );

    const absDivOpen = findOpenTagLinear(clean, 'div', (a) => {
      const id = getAttrValueLinear(a, 'id');
      return id === 'abstract' || id === 'eng-abstract';
    });
    const absSectionInner = !absDivOpen
      ? findElementInnerLinear(clean, 'section', (a) => attrHasTokenLinear(a, 'class', 'abstract'))
      : null;

    let bodyMd = '';
    const pmcArticle = findElementInnerLinear(clean, 'article', (a) => attrHasTokenLinear(a, 'class', 'article'));
    if (pmcArticle) {
      bodyMd = htmlToMd(pmcArticle, baseUrl).markdown.trim();
    } else if (absDivOpen) {
      const inner = extractBalancedDivAt(clean, absDivOpen.index);
      if (inner) bodyMd = htmlToMd(inner, baseUrl).markdown.trim();
    } else if (absSectionInner) {
      bodyMd = htmlToMd(absSectionInner, baseUrl).markdown.trim();
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
