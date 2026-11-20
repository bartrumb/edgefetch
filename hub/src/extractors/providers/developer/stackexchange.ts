import { defineAdapter } from '../../types';
import { extractBalancedDivAt, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'stackexchange-qa',
  name: 'Stack Overflow & Stack Exchange Q&A',
  category: 'developer',
  description: 'Extracts question prose, vote score, tags, and answers sorted with the Accepted Answer first.',
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
  extractHtml({ path, rawHtml, baseUrl, htmlToMd }) {
    if (!/^\/questions\/\d+/i.test(path)) return null;
    const cleanHtml = stripScriptsAndStyles(rawHtml);
    const qHeaderMatch = /<div\b[^>]*\bid=["']question-header["'][^>]*>([\s\S]*?)<\/div>/i.exec(cleanHtml);
    const h1Match = /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(qHeaderMatch?.[1] ?? cleanHtml);
    const title = stripTagsInline(h1Match?.[1] ?? '').replace(/\s*\[(?:duplicate|closed)\]\s*$/i, '').trim();

    const qOpen = /<div\b[^>]*\bid=["']question["'][^>]*>/i.exec(cleanHtml);
    if (!qOpen || !title) return null;
    const qInner = extractBalancedDivAt(cleanHtml, qOpen.index);
    if (!qInner) return null;

    const extractPostBody = (block: string): string => {
      const bodyOpen = /<div\b[^>]*\bclass=["'][^"']*\b(?:s-prose|js-post-body|post-text)\b[^"']*["'][^>]*>/i.exec(block);
      if (!bodyOpen) return '';
      const inner = extractBalancedDivAt(block, bodyOpen.index);
      return inner ? htmlToMd(inner, baseUrl).markdown.trim() : '';
    };

    const extractComments = (block: string): string[] => {
      const out: string[] = [];
      for (const cm of block.matchAll(/<span\b[^>]*\bclass=["'][^"']*\bcomment-copy\b[^"']*["'][^>]*>([\s\S]*?)<\/span>/gi)) {
        const txt = stripTagsInline(cm[1]!);
        if (txt && out.length < 6) out.push(`> - *Comment*: ${txt}`);
      }
      return out;
    };

    const qScore =
      /\bdata-score=["'](-?\d+)["']/i.exec(cleanHtml.slice(qOpen.index, qOpen.index + 500))?.[1] ??
      stripTagsInline(/<div\b[^>]*\bjs-vote-count\b[^>]*>([\s\S]*?)<\/div>/i.exec(qInner)?.[1] ?? '');
    const tags = [...qInner.matchAll(/<a\b[^>]*\bpost-tag\b[^>]*>([\s\S]*?)<\/a>/gi)]
      .map((m) => stripTagsInline(m[1]!))
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
    const ansRe = /<div\b[^>]*\bid=["']answer-\d+["'][^>]*>/gi;
    let am: RegExpExecArray | null;
    while ((am = ansRe.exec(cleanHtml)) !== null && answers.length < 12) {
      const openTag = am[0];
      const aInner = extractBalancedDivAt(cleanHtml, am.index);
      if (!aInner) continue;
      const accepted =
        /\baccepted-answer\b|\bjs-accepted-answer\b/i.test(openTag) || /\bjs-accepted-answer-indicator\b/i.test(aInner.slice(0, 2000));
      const scoreRaw =
        /\bdata-score=["'](-?\d+)["']/i.exec(openTag)?.[1] ??
        stripTagsInline(/<div\b[^>]*\bjs-vote-count\b[^>]*>([\s\S]*?)<\/div>/i.exec(aInner)?.[1] ?? '0');
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
