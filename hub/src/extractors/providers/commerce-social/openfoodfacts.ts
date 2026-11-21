import { defineAdapter } from '../../types';
import { extractJsonLdObjects, extractMetaContent, parseHtmlDoc } from '../../utils';

export default defineAdapter({
  id: 'openfoodfacts',
  name: 'Open Food Facts Products',
  category: 'commerce-social',
  description:
    'Extracts barcode, brand, Nutri-Score, NOVA group, ingredients, and nutrition facts from world.openfoodfacts.org/product/<barcode> (respecting robots.txt on /api).',
  domains: ['world.openfoodfacts.org', 'openfoodfacts.org', '*.openfoodfacts.org'],
  exampleUrls: ['https://world.openfoodfacts.org/product/3017620422003'],
  extractHtml({ path, rawHtml, currentMd }) {
    const m = /^\/product\/(\d{6,16})/i.exec(path);
    if (!m?.[1]) return null;
    const barcode = m[1];

    const ldObjects = extractJsonLdObjects(rawHtml);
    const prodLd = ldObjects.find((o) => /Product/i.test(String(o['@type'] ?? '')));
    const doc = parseHtmlDoc(rawHtml);

    const title =
      (typeof prodLd?.name === 'string' ? prodLd.name.trim() : '') ||
      extractMetaContent(rawHtml, 'og:title') ||
      doc.text('h1');
    if (!title) return null;

    const brandObj = prodLd?.brand as Record<string, unknown> | string | undefined;
    const brand = typeof brandObj === 'string' ? brandObj : typeof brandObj?.name === 'string' ? brandObj.name : '';
    const imgAlts = doc
      .select('img[alt]', 80)
      .map((img) => img.attr('alt') ?? '')
      .join(' ');
    const scoreCorpus = `${doc.text()} ${imgAlts}`;
    const nutriscore = /Nutri-Score\s*([A-E])\b/i.exec(scoreCorpus)?.[1]?.toUpperCase() ?? '';
    const nova = /NOVA\s*([1-4])\b/i.exec(scoreCorpus)?.[1] ?? '';
    const ingredients =
      doc.text('#panel_ingredients_content') ||
      (typeof prodLd?.description === 'string' ? prodLd.description.trim() : '');

    const bullets: string[] = [`- **Barcode (GTIN)**: \`${barcode}\``];
    if (brand) bullets.push(`- **Brand**: ${brand}`);
    if (nutriscore) bullets.push(`- **Nutri-Score**: **${nutriscore}**`);
    if (nova) bullets.push(`- **NOVA Food Processing Group**: ${nova}`);

    const sections = [`# ${title}`, bullets.join('\n')];
    if (ingredients) sections.push(`## Ingredients & Summary\n\n${ingredients}`);
    if (currentMd && currentMd.length > (ingredients?.length ?? 0) + 120) {
      sections.push(currentMd.replace(/^#\s+.+\n+/, '').trim());
    }

    return {
      extractorId: 'openfoodfacts',
      title,
      ...(ingredients ? { description: ingredients.slice(0, 260) } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
