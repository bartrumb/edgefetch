import { defineAdapter } from '../../types';

export default defineAdapter({
  id: 'jsr-io',
  name: 'JSR JavaScript Registry',
  category: 'developer',
  description: 'Strips top-bar navigation and duplicate version/scorecard tabs from jsr.io/@scope/pkg Markdown.',
  domains: ['jsr.io'],
  exampleUrls: ['https://jsr.io/@std/path'],
  extractHtml({ path, currentMd }) {
    if (!/^\/@[^/]+\/[^/]+/i.test(path) || !currentMd) return null;
    const cleaned = currentMd
      // jsr.io omits `<main>` and `<header>`, causing top-bar nav (`Skip to main content [Packages...]`) to precede `# @scope/pkg`.
      .replace(/(?:^|\n)[ \t]*Skip to main content[\s\S]*?(?=\n#\s+)/i, '')
      .replace(/^(?:Published\s+[^\n]+\s*$)/gim, '')
      .replace(
        /^[ \t]*(?:\[Overview\]\([^)]*\)|Overview)[ \t]*(?:\[(?:Docs|Files|Versions|Dependencies|Dependents|Score)\]\([^)]*\)|(?:Docs|Files|Versions|Dependencies|Dependents|Score))(?:[ \t]*(?:\[(?:Docs|Files|Versions|Dependencies|Dependents|Score)\]\([^)]*\)|(?:Docs|Files|Versions|Dependencies|Dependents|Score)))*[ \t]*$/gim,
        '',
      )
      .replace(/\n{3,}/g, '\n\n')
      .trim();
    if (cleaned && cleaned !== currentMd.trim()) {
      return { extractorId: 'jsr-io', markdown: cleaned };
    }
    return null;
  },
});
