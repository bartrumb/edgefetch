import { defineAdapter } from '../../types';
import { detectFenceLang, formatYamlFrontmatterCard, safeFence } from '../../utils';

export default defineAdapter({
  id: 'huggingface',
  name: 'Hugging Face Models, Datasets & Spaces',
  category: 'genai',
  description: 'Upgrades Hugging Face model/dataset/space pages and file blobs to raw README.md with parsed YAML frontmatter tables.',
  domains: ['huggingface.co', 'www.huggingface.co'],
  exampleUrls: ['https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct'],
  resolveTwin({ parts }) {
    const reserved = new Set([
      'models',
      'datasets',
      'spaces',
      'docs',
      'blog',
      'papers',
      'posts',
      'tasks',
      'organizations',
      'settings',
      'login',
      'join',
      'pricing',
    ]);
    const isTyped = (parts[0] === 'datasets' || parts[0] === 'spaces') && parts.length >= 3;
    const prefixCount = isTyped ? 3 : 2;
    if (!(isTyped || (parts.length >= 2 && !reserved.has(parts[0]!.toLowerCase())))) return null;

    const repoPrefix = parts.slice(0, prefixCount).join('/');
    const rest = parts.slice(prefixCount);
    if (rest.length === 0 || (rest.length === 2 && rest[0] === 'tree')) {
      const rev = rest[1] || 'main';
      return {
        id: 'huggingface-card',
        fetchUrl: `https://huggingface.co/${repoPrefix}/raw/${encodeURIComponent(rev)}/README.md`,
        kind: 'text',
        accept: 'text/markdown, text/plain;q=0.9',
        formatTwin: (rawBody) => {
          if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
          return formatYamlFrontmatterCard(rawBody, repoPrefix);
        },
      };
    }
    if (rest.length >= 3 && rest[0] === 'blob') {
      const rev = rest[1]!;
      const filePath = rest.slice(2).join('/');
      const { lang, isMarkdown } = detectFenceLang(filePath);
      return {
        id: 'huggingface-blob',
        fetchUrl: `https://huggingface.co/${repoPrefix}/raw/${encodeURIComponent(rev)}/${filePath}`,
        kind: 'text',
        accept: 'text/plain',
        formatTwin: (rawBody) => {
          if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
          const title = `${repoPrefix}/${filePath}`;
          if (isMarkdown) return formatYamlFrontmatterCard(rawBody, title);
          return { title, markdown: `# ${title}\n\n${safeFence(rawBody, lang)}` };
        },
      };
    }
    return null;
  },
});
