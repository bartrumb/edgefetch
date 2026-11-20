import { defineAdapter } from '../../types';
import { extractJsonLdObjects, formatGfmTable, parseJsonObject, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'shopify',
  name: 'Shopify Universal Storefront Products',
  category: 'commerce-social',
  description: 'Upgrades *.myshopify.com/products/<handle> to /products/<handle>.json and extracts variants, SKUs, pricing, and stock status on custom-domain Shopify stores.',
  domains: ['*.myshopify.com'],
  universalEngine: true,
  exampleUrls: ['https://allbirds.myshopify.com/products/mens-tree-runners'],
  resolveTwin({ host, parts }) {
    if (!host.endsWith('.myshopify.com')) return null;
    const prodIdx = parts.indexOf('products');
    if (prodIdx < 0 || !parts[prodIdx + 1]) return null;
    const handle = parts[prodIdx + 1]!.replace(/\.json$/i, '');
    if (!/^[A-Za-z0-9_-]{1,160}$/.test(handle)) return null;

    return {
      id: 'shopify',
      fetchUrl: `https://${host}/products/${encodeURIComponent(handle)}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const prod = data?.product as Record<string, unknown> | undefined;
        if (!prod || typeof prod.title !== 'string') return null;

        const title = prod.title.trim();
        const vendor = typeof prod.vendor === 'string' ? prod.vendor : '';
        const pType = typeof prod.product_type === 'string' ? prod.product_type : '';
        const tags = typeof prod.tags === 'string' ? prod.tags : Array.isArray(prod.tags) ? prod.tags.join(', ') : '';
        const bodyHtml = typeof prod.body_html === 'string' ? prod.body_html : '';
        const bodyMd = bodyHtml ? htmlToMd(bodyHtml, origUrl).markdown.trim() : '';

        const variants = Array.isArray(prod.variants) ? (prod.variants as Array<Record<string, unknown>>) : [];
        const rows = variants.slice(0, 30).map((v) => [
          String(v.title ?? 'Default'),
          `\`${String(v.sku || '-')}\``,
          v.price !== undefined ? `$${String(v.price)}` : '-',
          v.compare_at_price ? `$${String(v.compare_at_price)}` : '-',
          v.available === false ? 'Out of Stock' : 'Available',
        ]);

        const bullets: string[] = [];
        if (vendor) bullets.push(`- **Brand / Vendor**: ${vendor}`);
        if (pType) bullets.push(`- **Product Type**: ${pType}`);
        if (tags) bullets.push(`- **Tags**: ${tags}`);

        const sections = [`# ${title}`];
        if (bullets.length > 0) sections.push(bullets.join('\n'));
        if (rows.length > 0) {
          sections.push(`## Variants & Pricing\n\n${formatGfmTable(['Variant', 'SKU', 'Price', 'Compare At', 'Availability'], rows)}`);
        }
        if (bodyMd) sections.push(`## Product Details\n\n${bodyMd}`);

        return {
          title,
          ...(bodyMd ? { description: stripTagsInline(bodyHtml).slice(0, 260) } : {}),
          ...(vendor ? { author: vendor } : {}),
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
  extractHtml({ path, rawHtml }) {
    if (!/\/products\/[^/]+/i.test(path)) return null;
    if (!/cdn\.shopify\.com|Shopify\.shop\s*=|shopify-digital-wallet/i.test(rawHtml.slice(0, 60000))) {
      return null;
    }
    const ldObjects = extractJsonLdObjects(rawHtml);
    const prodLd = ldObjects.find((o) => /Product|ProductGroup/i.test(String(o['@type'] ?? '')));
    if (!prodLd || typeof prodLd.name !== 'string') return null;

    const title = prodLd.name.trim();
    const brandObj = prodLd.brand as Record<string, unknown> | string | undefined;
    const brand = typeof brandObj === 'string' ? brandObj : typeof brandObj?.name === 'string' ? brandObj.name : '';
    const desc = typeof prodLd.description === 'string' ? stripTagsInline(prodLd.description) : '';
    const rawOffers = prodLd.offers ?? prodLd.hasVariant;
    const offersList = Array.isArray(rawOffers)
      ? (rawOffers as Array<Record<string, unknown>>)
      : rawOffers && typeof rawOffers === 'object'
        ? [rawOffers as Record<string, unknown>]
        : [];

    const rows: Array<Array<string>> = [];
    for (const off of offersList.slice(0, 30)) {
      const subOffer = (off.offers as Record<string, unknown> | undefined) ?? off;
      const vName = String(off.name ?? title);
      const sku = String(off.sku ?? subOffer.sku ?? '-');
      const price = subOffer.price ?? subOffer.lowPrice;
      const currency = String(subOffer.priceCurrency ?? 'USD');
      const availRaw = String(subOffer.availability ?? '');
      const avail = /InStock/i.test(availRaw) ? 'In Stock' : /OutOfStock/i.test(availRaw) ? 'Out of Stock' : availRaw.split('/').pop() || '-';
      rows.push([vName, sku !== '-' ? `\`${sku}\`` : '-', price !== undefined ? `${currency} ${String(price)}` : '-', avail]);
    }

    const bullets: string[] = [];
    if (brand) bullets.push(`- **Brand**: ${brand}`);
    if (typeof prodLd.sku === 'string' && prodLd.sku) bullets.push(`- **SKU**: \`${prodLd.sku}\``);

    const sections = [`# ${title}`];
    if (bullets.length > 0) sections.push(bullets.join('\n'));
    if (rows.length > 0) {
      sections.push(`## Pricing & Availability\n\n${formatGfmTable(['Variant', 'SKU', 'Price', 'Status'], rows)}`);
    }
    if (desc) sections.push(`## Description\n\n${desc}`);

    return {
      extractorId: 'shopify',
      title,
      ...(desc ? { description: desc.slice(0, 260) } : {}),
      ...(brand ? { author: brand } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
