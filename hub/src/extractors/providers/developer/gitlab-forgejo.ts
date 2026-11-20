import { defineAdapter } from '../../types';
import { detectFenceLang, safeFence } from '../../utils';

export default defineAdapter({
  id: 'gitlab-forgejo',
  name: 'GitLab, Codeberg & Forgejo Raw/Patch Twins',
  category: 'developer',
  description: 'Upgrades GitLab, Codeberg, and Gitea file blobs and commit pages to raw source and .patch diffs.',
  domains: ['gitlab.com', 'gitlab.*', 'codeberg.org', 'gitea.com'],
  exampleUrls: [
    'https://gitlab.com/inkscape/inkscape/-/blob/master/CMakeLists.txt',
    'https://codeberg.org/forgejo/forgejo/commit/abcdef1234567',
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
          id: 'gitlab-raw',
          fetchUrl: `https://${host}/${nsProj}/-/raw/${rawTail}`,
          kind: 'text',
          accept: 'text/plain',
          formatTwin: (rawBody) => {
            if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
            const title = `${nsProj}/${filePath}`;
            return {
              title,
              markdown: isMarkdown ? rawBody.trim() : `# ${title}\n\n${safeFence(rawBody, lang)}`,
            };
          },
        };
      }
      if (dashIdx >= 2 && parts[dashIdx + 1] === 'commit' && parts[dashIdx + 2] && /^[0-9a-f]{7,40}$/i.test(parts[dashIdx + 2]!)) {
        const nsProj = parts.slice(0, dashIdx).join('/');
        const sha = parts[dashIdx + 2]!;
        return {
          id: 'gitlab-commit-patch',
          fetchUrl: `https://${host}/${nsProj}/-/commit/${sha}.patch`,
          kind: 'text',
          accept: 'text/plain',
          formatTwin: (rawBody) => {
            if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
            const title = `${nsProj}@${sha.slice(0, 10)}`;
            return { title, markdown: `# ${title}\n\n${safeFence(rawBody, 'diff')}` };
          },
        };
      }
    }

    if (host === 'codeberg.org' || host === 'gitea.com') {
      if (parts.length >= 6 && parts[2] === 'src' && (parts[3] === 'branch' || parts[3] === 'tag' || parts[3] === 'commit')) {
        const slug = `${parts[0]}/${parts[1]}`;
        const refType = parts[3]!;
        const refAndPath = parts.slice(4).join('/');
        const filePath = parts.slice(5).join('/');
        const { lang, isMarkdown } = detectFenceLang(filePath);
        return {
          id: 'forgejo-raw',
          fetchUrl: `https://${host}/${slug}/raw/${refType}/${refAndPath}`,
          kind: 'text',
          accept: 'text/plain',
          formatTwin: (rawBody) => {
            if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
            const title = `${slug}/${filePath}`;
            return {
              title,
              markdown: isMarkdown ? rawBody.trim() : `# ${title}\n\n${safeFence(rawBody, lang)}`,
            };
          },
        };
      }
      if (parts.length === 4 && parts[2] === 'commit' && /^[0-9a-f]{7,40}$/i.test(parts[3]!)) {
        const slug = `${parts[0]}/${parts[1]}`;
        const sha = parts[3]!;
        return {
          id: 'forgejo-commit-patch',
          fetchUrl: `https://${host}/${slug}/commit/${sha}.patch`,
          kind: 'text',
          accept: 'text/plain',
          formatTwin: (rawBody) => {
            if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
            const title = `${slug}@${sha.slice(0, 10)}`;
            return { title, markdown: `# ${title}\n\n${safeFence(rawBody, 'diff')}` };
          },
        };
      }
    }

    return null;
  },
});
