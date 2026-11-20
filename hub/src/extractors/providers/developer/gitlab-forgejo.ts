import { defineAdapter } from '../../types';
import {
  decodeBasicEntities,
  detectFenceLang,
  extractBalancedDivAt,
  extractMetaContent,
  parseJsonObject,
  safeFence,
} from '../../utils';

const GITLAB_RESERVED_ROOTS = new Set([
  'explore',
  'groups',
  'users',
  'dashboard',
  'help',
  'topics',
  'orgs',
  'admin',
  'search',
  'abuse_reports',
  'oauth',
  'snippets',
  '-',
]);

function extractGitlabBlobPlainSource(rawBody: string): string | null {
  const obj = parseJsonObject(rawBody);
  if (!obj || typeof obj.html !== 'string') return null;
  const codeMatch = /<pre\b[^>]*>\s*<code\b[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/i.exec(obj.html);
  if (!codeMatch?.[1]) return null;
  const plain = decodeBasicEntities(
    codeMatch[1]
      .replace(/<[^>]+>/g, '')
      .replace(/&#x000A;/gi, '\n'),
  )
    .replace(/\r\n/g, '\n')
    .trimEnd();
  return plain.trim() ? plain : null;
}

// Note on `robots.txt` compliance:
// - `gitlab.com/robots.txt` disallows `/api/v*`, `/<path>/raw`, and commit `.patch` paths,
//   while explicitly allowing `/-/blob/...`! Using `/-/blob/...?format=json&viewer=simple` gives 1-hop raw
//   source and repo root `README.md` retrieval with 100% `robots.txt` compliance.
// - `codeberg.org/robots.txt` and `gitea.com/robots.txt` disallow `/api/`, `/raw/`, `/src/`, and
//   `/commit/`, while allowing repository root HTML (`/<owner>/<repo>`), which embeds the rendered README
//   inside `<div class="markup ...">` SSR HTML.
export default defineAdapter({
  id: 'gitlab-forgejo',
  name: 'GitLab, Codeberg & Forgejo Twins',
  category: 'developer',
  description:
    'Upgrades GitLab repo roots and file blobs via robots.txt-allowed ?format=json&viewer=simple endpoints, and extracts clean README content from Codeberg/Gitea SSR repo pages.',
  domains: ['gitlab.com', 'gitlab.*', 'codeberg.org', 'gitea.com'],
  exampleUrls: [
    'https://gitlab.com/gitlab-org/cli',
    'https://gitlab.com/inkscape/inkscape/-/blob/master/CMakeLists.txt',
    'https://codeberg.org/forgejo/forgejo',
  ],
  resolveTwin({ host, parts }) {
    if (host === 'gitlab.com' || host.startsWith('gitlab.')) {
      const dashIdx = parts.indexOf('-');
      if (dashIdx >= 2 && parts[dashIdx + 1] === 'blob' && parts.length >= dashIdx + 4) {
        const nsProj = parts.slice(0, dashIdx).join('/');
        const rawTail = parts.slice(dashIdx + 2).join('/');
        const filePath = parts.slice(dashIdx + 3).join('/');
        const { lang, isMarkdown } = detectFenceLang(filePath);
        return {
          id: 'gitlab-blob-json',
          fetchUrl: `https://${host}/${nsProj}/-/blob/${rawTail}?format=json&viewer=simple`,
          kind: 'json',
          accept: 'application/json',
          formatTwin: (rawBody) => {
            const plain = extractGitlabBlobPlainSource(rawBody);
            if (!plain) return null;
            const title = `${nsProj}/${filePath}`;
            return {
              title,
              markdown: isMarkdown ? plain.trim() : `# ${title}\n\n${safeFence(plain, lang)}`,
            };
          },
        };
      }

      if (
        dashIdx === -1 &&
        parts.length >= 2 &&
        parts.length <= 5 &&
        !GITLAB_RESERVED_ROOTS.has(parts[0]!.toLowerCase()) &&
        parts.every((seg) => /^[A-Za-z0-9_.-]+$/.test(seg) && !seg.endsWith('.git') && !seg.endsWith('.atom'))
      ) {
        const nsProj = parts.join('/');
        return {
          id: 'gitlab-readme-json',
          fetchUrl: `https://${host}/${nsProj}/-/blob/HEAD/README.md?format=json&viewer=simple`,
          kind: 'json',
          accept: 'application/json',
          formatTwin: (rawBody) => {
            const plain = extractGitlabBlobPlainSource(rawBody);
            if (!plain) return null;
            const trimmed = plain.trim();
            return {
              title: nsProj,
              markdown: trimmed.startsWith('# ') ? trimmed : `# ${nsProj}\n\n${trimmed}`,
            };
          },
        };
      }
    }

    return null;
  },
  extractHtml({ host, parts, baseUrl, rawHtml, htmlToMd }) {
    if ((host === 'codeberg.org' || host === 'gitea.com') && parts.length === 2) {
      const slug = `${parts[0]}/${parts[1]}`;
      const desc = extractMetaContent(rawHtml, 'og:description') || extractMetaContent(rawHtml, 'description');
      const markupMatch = /<div\b[^>]*\bclass=["'][^"']*\bmarkup\b[^"']*["'][^>]*>/i.exec(rawHtml);
      if (markupMatch) {
        const inner = extractBalancedDivAt(rawHtml, markupMatch.index);
        if (inner) {
          const converted = htmlToMd(inner, baseUrl);
          const readmeMd = converted.markdown.trim();
          if (readmeMd.length >= 40) {
            const header = `# ${slug}${desc ? `\n\n> ${desc}` : ''}`;
            const md = readmeMd.startsWith('# ')
              ? `${desc ? `> **${slug}** — ${desc}\n\n` : ''}${readmeMd}`
              : `${header}\n\n${readmeMd}`;
            return {
              extractorId: 'gitlab-forgejo',
              title: slug,
              ...(desc ? { description: desc } : {}),
              markdown: md.trim(),
              links: converted.links,
            };
          }
        }
      }
    }
    return null;
  },
});
