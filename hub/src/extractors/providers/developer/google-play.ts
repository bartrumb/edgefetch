import { defineAdapter } from '../../types';
import { extractJsonLdObjects, extractMetaContent } from '../../utils';

export default defineAdapter({
  id: 'google-play',
  name: 'Google Play Store',
  category: 'developer',
  description: 'Extracts structured Google Play app metadata (package ID, developer, rating, downloads/reviews, category, price, and full description).',
  domains: ['play.google.com'],
  exampleUrls: ['https://play.google.com/store/apps/details?id=com.cloudflare.onedotonedotonedotone'],
  extractHtml({ url, path, rawHtml }) {
    if (!/^\/store\/apps\/details/i.test(path)) return null;
    const pkgId = url.searchParams.get('id') ?? '';
    const ldObjects = extractJsonLdObjects(rawHtml);
    const appLd = ldObjects.find((o) => /SoftwareApplication|MobileApplication/i.test(String(o['@type'] ?? '')));

    const title =
      (typeof appLd?.name === 'string' ? appLd.name.trim() : '') ||
      extractMetaContent(rawHtml, 'og:title').replace(/\s*-\s*Apps on Google Play$/i, '').trim();
    if (!title) return null;

    const authorObj = appLd?.author as Record<string, unknown> | undefined;
    const developer = typeof authorObj?.name === 'string' ? authorObj.name.trim() : '';
    const aggRating = appLd?.aggregateRating as Record<string, unknown> | undefined;
    const ratingVal = aggRating?.ratingValue !== undefined ? String(aggRating.ratingValue) : '';
    const ratingCount = aggRating?.ratingCount ?? aggRating?.reviewCount;
    const offersObj = (Array.isArray(appLd?.offers) ? appLd?.offers[0] : appLd?.offers) as Record<string, unknown> | undefined;
    const price = offersObj?.price !== undefined ? String(offersObj.price) : '';
    const currency = typeof offersObj?.priceCurrency === 'string' ? offersObj.priceCurrency : 'USD';
    const category = typeof appLd?.applicationCategory === 'string' ? appLd.applicationCategory : '';
    const contentRating = typeof appLd?.contentRating === 'string' ? appLd.contentRating : '';
    const desc =
      (typeof appLd?.description === 'string' ? appLd.description.trim() : '') ||
      extractMetaContent(rawHtml, 'description');

    const bullets: string[] = [];
    if (pkgId) bullets.push(`- **Package ID**: \`${pkgId}\``);
    if (developer) bullets.push(`- **Developer**: ${developer}`);
    if (category) bullets.push(`- **Category**: ${category}`);
    if (ratingVal) bullets.push(`- **Rating**: ${ratingVal} / 5${ratingCount !== undefined ? ` (${String(ratingCount)} reviews)` : ''}`);
    if (price !== '') bullets.push(`- **Price**: ${Number(price) === 0 ? 'Free' : `${currency} ${price}`}`);
    if (contentRating) bullets.push(`- **Content Rating**: ${contentRating}`);

    if (bullets.length === 0 && !desc) return null;

    const sections: string[] = [`# ${title}`];
    if (bullets.length > 0) sections.push(bullets.join('\n'));
    if (desc) sections.push(`## About This App\n\n${desc}`);

    return {
      extractorId: 'google-play',
      title,
      ...(desc ? { description: desc.slice(0, 260) } : {}),
      ...(developer ? { author: developer } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
