import { defineAdapter } from '../../types';

export default defineAdapter({
  id: 'jsr-io',
  name: 'JSR JavaScript Registry',
  category: 'developer',
  description: 'Strips duplicate version/scorecard navigation chrome from jsr.io/@scope/pkg Markdown.',
  domains: ['jsr.io'],
  exampleUrls: ['https://jsr.io/@std/path'],
  extractHtml({ path, currentMd }) {
    if (!/^\/@[^/]+\/[^/]+/i.test(path) || !currentMd) return null;
    const cleaned = currentMd
      .replace(/^(?:Published\s+[^\n]+\n+|Overview\s+Docs\s+Files\s+Versions\s+Dependencies\s+Dependents\s+Score\s*\n+)/gim, '')
      .trim();
    if (cleaned && cleaned !== currentMd) {
      return { extractorId: 'jsr-io', markdown: cleaned };
    }
    return null;
  },
});
