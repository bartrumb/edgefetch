import {
  attrHasTokenLinear,
  defineAdapter,
  findAllElementInnersLinear,
  findAllOpenTagsLinear,
  findElementInnerLinear,
  findOpenTagLinear,
  getAttrValueLinear,
} from '../../types';
import {
  decodeBasicEntities,
  extractBalancedDivAt,
  parseJsonObject,
  stripScriptsAndStyles,
  stripTagsInline,
} from '../../utils';

function resolveStackExchangeSiteParam(host: string): string | null {
  const h = host.toLowerCase().replace(/^www\./, '');
  if (h === 'stackoverflow.com') return 'stackoverflow';
  if (h === 'serverfault.com') return 'serverfault';
  if (h === 'superuser.com') return 'superuser';
  if (h === 'askubuntu.com') return 'askubuntu';
  if (h === 'mathoverflow.net') return 'mathoverflow';
  if (h === 'stackapps.com') return 'stackapps';
  if (h.endsWith('.stackexchange.com')) {
    return h.slice(0, -'.stackexchange.com'.length);
  }
  return null;
}

// Deterministic Stack Exchange API v2.3 filter including question + answers `body_markdown`, `body`, `score`, `is_accepted`, `tags`, `owner`.
const SE_QUESTION_ANSWERS_FILTER = '!20aKG._8Oscv*6dguVOli';

export default defineAdapter({
  id: 'stackexchange-qa',
  name: 'Stack Overflow & Stack Exchange Q&A',
  category: 'developer',
  description: 'Upgrades Stack Overflow / Stack Exchange URLs to keyless API v2.3 native Markdown (with HTML fallback), sorting the Accepted Answer first.',
  domains: [
    'stackoverflow.com',
    'www.stackoverflow.com',
    'serverfault.com',
    'superuser.com',
    'askubuntu.com',
    'mathoverflow.net',
    'stackapps.com',
    '*.stackexchange.com',
  ],
  exampleUrls: ['https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array'],
  resolveTwin({ host, path }) {
    const qMatch = /^\/(?:questions|q)\/(\d+)(?:\/|$)/i.exec(path);
    if (!qMatch?.[1]) return null;
    const siteParam = resolveStackExchangeSiteParam(host);
    if (!siteParam) return null;
    const qid = qMatch[1];

    return {
      id: 'stackexchange-qa',
      fetchUrl: `https://api.stackexchange.com/2.3/questions/${qid}?site=${encodeURIComponent(siteParam)}&filter=${encodeURIComponent(SE_QUESTION_ANSWERS_FILTER)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const items = Array.isArray(data?.items) ? (data.items as Array<Record<string, unknown>>) : null;
        const q = items?.[0];
        if (!q || typeof q.title !== 'string') return null;

        const title = decodeBasicEntities(q.title).trim();
        const score = typeof q.score === 'number' ? q.score : 0;
        const tags = Array.isArray(q.tags) ? q.tags.map(String).filter(Boolean).slice(0, 8) : [];
        const qMd =
          typeof q.body_markdown === 'string' && q.body_markdown.trim()
            ? decodeBasicEntities(q.body_markdown.replace(/\r\n/g, '\n')).trim()
            : typeof q.body === 'string' && q.body.trim()
              ? htmlToMd(q.body, origUrl).markdown.trim()
              : '';
        if (!qMd) return null;

        const sections: string[] = [`# ${title}`];
        const qMeta: string[] = [`**Votes**: ${score}`];
        if (tags.length > 0) qMeta.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);
        sections.push(qMeta.join(' · '));
        sections.push(`## Question\n\n${qMd}`);

        const rawAnswers = Array.isArray(q.answers) ? (q.answers as Array<Record<string, unknown>>) : [];
        const answers = rawAnswers
          .map((a) => {
            const accepted = Boolean(a.is_accepted);
            const aScore = typeof a.score === 'number' ? a.score : 0;
            const author = decodeBasicEntities(String((a.owner as Record<string, unknown> | undefined)?.display_name ?? '')).trim();
            const md =
              typeof a.body_markdown === 'string' && a.body_markdown.trim()
                ? decodeBasicEntities(a.body_markdown.replace(/\r\n/g, '\n')).trim()
                : typeof a.body === 'string' && a.body.trim()
                  ? htmlToMd(a.body, origUrl).markdown.trim()
                  : '';
            return { accepted, score: aScore, author, md };
          })
          .filter((a) => Boolean(a.md))
          .sort((a, b) => (a.accepted !== b.accepted ? (a.accepted ? -1 : 1) : b.score - a.score));

        for (let i = 0; i < Math.min(answers.length, 8); i++) {
          const a = answers[i]!;
          const bySuffix = a.author ? ` — by ${a.author}` : '';
          const heading = a.accepted
            ? `## ✅ Accepted Answer (Score: ${a.score}${bySuffix})`
            : `## Answer ${i + 1} (Score: ${a.score}${bySuffix})`;
          sections.push(`${heading}\n\n${a.md}`);
        }

        return {
          title,
          markdown: sections.join('\n\n'),
          links: typeof q.link === 'string' && q.link.startsWith('https://') ? [q.link] : undefined,
        };
      },
    };
  },
  extractHtml({ path, rawHtml, baseUrl, htmlToMd }) {
    if (!/^\/questions\/\d+/i.test(path)) return null;
    const cleanHtml = stripScriptsAndStyles(rawHtml);
    const qHeaderOpen = findOpenTagLinear(cleanHtml, 'div', (a) => getAttrValueLinear(a, 'id') === 'question-header');
    const qHeaderInner = qHeaderOpen ? extractBalancedDivAt(cleanHtml, qHeaderOpen.index) : null;
    const h1Inner = findElementInnerLinear(qHeaderInner ?? cleanHtml, 'h1');
    const title = stripTagsInline(h1Inner ?? '').replace(/\s*\[(?:duplicate|closed)\]\s*$/i, '').trim();

    const qOpen = findOpenTagLinear(cleanHtml, 'div', (a) => getAttrValueLinear(a, 'id') === 'question');
    if (!qOpen || !title) return null;
    const qInner = extractBalancedDivAt(cleanHtml, qOpen.index);
    if (!qInner) return null;

    const extractPostBody = (block: string): string => {
      const bodyOpen = findOpenTagLinear(
        block,
        'div',
        (a) =>
          attrHasTokenLinear(a, 'class', 's-prose') ||
          attrHasTokenLinear(a, 'class', 'js-post-body') ||
          attrHasTokenLinear(a, 'class', 'post-text'),
      );
      if (!bodyOpen) return '';
      const inner = extractBalancedDivAt(block, bodyOpen.index);
      return inner ? htmlToMd(inner, baseUrl).markdown.trim() : '';
    };

    const extractComments = (block: string): string[] => {
      const out: string[] = [];
      for (const cm of findAllElementInnersLinear(block, 'span', (a) => attrHasTokenLinear(a, 'class', 'comment-copy'), 6)) {
        const txt = stripTagsInline(cm);
        if (txt && out.length < 6) out.push(`> - *Comment*: ${txt}`);
      }
      return out;
    };

    const qScore =
      getAttrValueLinear(qOpen.attrStr, 'data-score') ??
      stripTagsInline(findElementInnerLinear(qInner, 'div', (a) => attrHasTokenLinear(a, 'class', 'js-vote-count')) ?? '');
    const tags = findAllElementInnersLinear(qInner, 'a', (a) => attrHasTokenLinear(a, 'class', 'post-tag'), 16)
      .map((inner) => stripTagsInline(inner))
      .filter((t, i, a) => Boolean(t) && a.indexOf(t) === i)
      .slice(0, 8);

    const qMd = extractPostBody(qInner);
    if (!qMd) return null;

    const sections: string[] = [`# ${title}`];
    const qMeta: string[] = [];
    if (qScore) qMeta.push(`**Votes**: ${qScore}`);
    if (tags.length > 0) qMeta.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);
    if (qMeta.length > 0) sections.push(qMeta.join(' · '));
    sections.push(`## Question\n\n${qMd}`);
    const qComments = extractComments(qInner);
    if (qComments.length > 0) sections.push(qComments.join('\n'));

    const answers: Array<{ accepted: boolean; score: number; md: string; comments: string[] }> = [];
    const ansOpens = findAllOpenTagsLinear(
      cleanHtml,
      'div',
      (a) => /^answer-\d+$/i.test(getAttrValueLinear(a, 'id') ?? ''),
      12,
    );
    for (const am of ansOpens) {
      const aInner = extractBalancedDivAt(cleanHtml, am.index);
      if (!aInner) continue;
      const accepted =
        attrHasTokenLinear(am.attrStr, 'class', 'accepted-answer') ||
        attrHasTokenLinear(am.attrStr, 'class', 'js-accepted-answer') ||
        /\bjs-accepted-answer-indicator\b/i.test(aInner.slice(0, 2000));
      const scoreRaw =
        getAttrValueLinear(am.attrStr, 'data-score') ??
        stripTagsInline(findElementInnerLinear(aInner, 'div', (a) => attrHasTokenLinear(a, 'class', 'js-vote-count')) ?? '0');
      const score = parseInt(scoreRaw, 10) || 0;
      const md = extractPostBody(aInner);
      if (!md) continue;
      answers.push({ accepted, score, md, comments: extractComments(aInner) });
    }

    answers.sort((a, b) => (a.accepted !== b.accepted ? (a.accepted ? -1 : 1) : b.score - a.score));
    for (let i = 0; i < Math.min(answers.length, 8); i++) {
      const a = answers[i]!;
      const heading = a.accepted ? `## ✅ Accepted Answer (Score: ${a.score})` : `## Answer ${i + 1} (Score: ${a.score})`;
      sections.push(`${heading}\n\n${a.md}`);
      if (a.comments.length > 0) sections.push(a.comments.join('\n'));
    }

    return {
      extractorId: 'stackexchange-qa',
      title,
      markdown: sections.join('\n\n'),
    };
  },
});
