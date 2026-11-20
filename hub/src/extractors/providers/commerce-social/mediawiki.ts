import { defineAdapter } from '../../types';

export default defineAdapter({
  id: 'mediawiki',
  name: 'Wikipedia & MediaWiki Encyclopedias',
  category: 'commerce-social',
  description: 'Strips [edit], [citation needed], reference back-link noise, and trailing MediaWiki navigation menus.',
  domains: ['*.wikipedia.org', 'wiki.archlinux.org'],
  universalEngine: true,
  exampleUrls: ['https://en.wikipedia.org/wiki/HTTP/2'],
  extractHtml({ host, rawHtml, currentMd }) {
    if (!host.endsWith('.wikipedia.org') && host !== 'wiki.archlinux.org' && !/\bcontent=["']MediaWiki\b/i.test(rawHtml.slice(0, 4000))) {
      return null;
    }
    const cleaned = currentMd
      .replace(/\s*\[(?:edit|citation needed|clarification needed|when\?|who\?|dubious\s*[–-]\s*discuss)\]/gi, '')
      .replace(/^\s*\^\s+(?:\[\^[a-z0-9]+\]\s*|(?:[a-z]\s+){2,})/gim, '^ ')
      .replace(/\n+(?:##+\s+)?(?:Navigation menu|Namespaces|Views|Personal tools)\b[\s\S]*$/i, '')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
    if (cleaned && cleaned !== currentMd) {
      return { extractorId: 'mediawiki', markdown: cleaned };
    }
    return null;
  },
});
