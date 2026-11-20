import { defineAdapter } from '../../types';
import { extractJsonLdObjects, extractMetaContent, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'apple-app-store',
  name: 'Apple App Store',
  category: 'developer',
  description: 'Extracts structured iOS/macOS App Store metadata (developer, rating, review count, price, category, version notes, and description).',
  domains: ['apps.apple.com'],
  exampleUrls: ['https://apps.apple.com/us/app/cloudflare-one-agent/id6443476492'],
  extractHtml({ path, rawHtml }) {
    if (!/\/app\//i.test(path)) return null;
    const ldObjects = extractJsonLdObjects(rawHtml);
    const appLd = ldObjects.find((o) => /SoftwareApplication|MobileApplication|WebApplication/i.test(String(o['@type'] ?? '')));

    const clean = stripScriptsAndStyles(rawHtml);
    const title =
      (typeof appLd?.name === 'string' ? appLd.name.trim() : '') ||
      extractMetaContent(rawHtml, 'og:title').replace(/\s+on the App\s*Store$/i, '').trim() ||
      stripTagsInline(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ?? '');
    if (!title) return null;

    const authorObj = appLd?.author as Record<string, unknown> | undefined;
    const developer =
      (typeof authorObj?.name === 'string' ? authorObj.name.trim() : '') ||
      stripTagsInline(/<h2\b[^>]*\bproduct-header__identity\b[^>]*>([\s\S]*?)<\/h2>/i.exec(clean)?.[1] ?? '');

    const aggRating = appLd?.aggregateRating as Record<string, unknown> | undefined;
    const ratingVal = aggRating?.ratingValue !== undefined ? String(aggRating.ratingValue) : '';
    const ratingCount = aggRating?.reviewCount ?? aggRating?.ratingCount;

    const offersObj = (Array.isArray(appLd?.offers) ? appLd?.offers[0] : appLd?.offers) as Record<string, unknown> | undefined;
    const price = offersObj?.price !== undefined ? String(offersObj.price) : '';
    const currency = typeof offersObj?.priceCurrency === 'string' ? offersObj.priceCurrency : 'USD';
    const category = typeof appLd?.applicationCategory === 'string' ? appLd.applicationCategory : '';
    const osSys = typeof appLd?.operatingSystem === 'string' ? appLd.operatingSystem : '';
    const desc =
      (typeof appLd?.description === 'string' ? appLd.description.trim() : '') ||
      extractMetaContent(rawHtml, 'description');

    const versionMatch = /Version\s+([0-9][0-9A-Za-z._-]*)/i.exec(clean);
    const version = versionMatch?.[1] ?? '';

    const bullets: string[] = [];
    if (developer) bullets.push(`- **Developer**: ${developer}`);
    if (category) bullets.push(`- **Category**: ${category}`);
    if (ratingVal) bullets.push(`- **Rating**: ${ratingVal} / 5${ratingCount !== undefined ? ` (${String(ratingCount)} ratings)` : ''}`);
    if (price !== '') bullets.push(`- **Price**: ${Number(price) === 0 ? 'Free' : `${currency} ${price}`}`);
    if (osSys) bullets.push(`- **Platform**: ${osSys}`);
    if (version) bullets.push(`- **Latest Version**: \`${version}\``);

    if (bullets.length === 0 && !desc) return null;

    const sections: string[] = [`# ${title}`];
    if (bullets.length > 0) sections.push(bullets.join('\n'));
    if (desc) sections.push(`## Description\n\n${desc}`);

    return {
      extractorId: 'apple-app-store',
      title,
      ...(desc ? { description: desc.slice(0, 260) } : {}),
      ...(developer ? { author: developer } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
