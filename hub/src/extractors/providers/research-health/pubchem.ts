import { defineAdapter } from '../../types';
import { extractJsonLdObjects, extractMetaContent, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'pubchem',
  name: 'PubChem Chemical Compounds (NCBI)',
  category: 'research-health',
  description: 'Upgrades pubchem.ncbi.nlm.nih.gov/compound/<cid|name> to NCBI PUG-REST compound properties + pharmacological descriptions (with HTML JSON-LD fallback).',
  domains: ['pubchem.ncbi.nlm.nih.gov'],
  exampleUrls: ['https://pubchem.ncbi.nlm.nih.gov/compound/2244'],
  resolveTwin({ parts }) {
    if (parts[0]?.toLowerCase() !== 'compound' || !parts[1]) return null;
    const rawId = decodeURIComponent(parts[1]).trim();
    if (!/^\d{1,12}$/.test(rawId)) return null;
    // Note: PubChem robots.txt explicitly keeps `/rest/pug_view` crawlable ("Keep /rest/pug/ scoped so /rest/pug_view remains crawlable").
    return {
      id: 'pubchem',
      fetchUrl: `https://pubchem.ncbi.nlm.nih.gov/rest/pug_view/data/compound/${rawId}/JSON/?heading=Names+and+Identifiers`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const rec = data?.Record as Record<string, unknown> | undefined;
        if (!rec || typeof rec.RecordTitle !== 'string') return null;

        const cid = rec.RecordNumber !== undefined ? String(rec.RecordNumber) : rawId;
        const title = rec.RecordTitle.trim() || `Compound ${cid}`;
        const fields = new Map<string, string>();
        const walk = (secs: unknown) => {
          if (!Array.isArray(secs)) return;
          for (const rawS of secs) {
            if (!rawS || typeof rawS !== 'object') continue;
            const s = rawS as Record<string, unknown>;
            const heading = typeof s.TOCHeading === 'string' ? s.TOCHeading : '';
            const infoArr = Array.isArray(s.Information) ? (s.Information as Array<Record<string, unknown>>) : [];
            const valObj = infoArr[0]?.Value as Record<string, unknown> | undefined;
            const strArr = Array.isArray(valObj?.StringWithMarkup)
              ? (valObj.StringWithMarkup as Array<Record<string, unknown>>)
              : [];
            const firstStr = typeof strArr[0]?.String === 'string' ? strArr[0].String.trim() : '';
            if (heading && firstStr && !fields.has(heading)) {
              fields.set(heading, firstStr);
            }
            if (s.Section) walk(s.Section);
          }
        };
        walk(rec.Section);

        const formula = fields.get('Molecular Formula') ?? '';
        const iupac = fields.get('IUPAC Name') ?? '';
        const inchiKey = fields.get('InChIKey') ?? '';
        const smiles = fields.get('SMILES') ?? fields.get('Canonical SMILES') ?? '';
        const cas = fields.get('CAS') ?? '';
        const desc = fields.get('Record Description') ?? '';

        const bullets: string[] = [`- **PubChem CID**: \`${cid}\``];
        if (formula) bullets.push(`- **Molecular Formula**: \`${formula}\``);
        if (cas) bullets.push(`- **CAS Number**: \`${cas}\``);
        if (iupac) bullets.push(`- **IUPAC Name**: \`${iupac}\``);
        if (inchiKey) bullets.push(`- **InChIKey**: \`${inchiKey}\``);
        if (smiles) bullets.push(`- **SMILES**: \`${smiles}\``);

        const sections = [`# ${title} (PubChem CID ${cid})`, bullets.join('\n')];
        if (desc) sections.push(`## Summary\n\n${desc}`);

        return {
          title: `${title} (PubChem CID ${cid})`,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          markdown: sections.join('\n\n'),
          links: [`https://pubchem.ncbi.nlm.nih.gov/compound/${cid}`],
        };
      },
    };
  },
  extractHtml({ path, rawHtml, currentMd }) {
    if (!/^\/compound\/[^/]+/i.test(path)) return null;
    const ldObjects = extractJsonLdObjects(rawHtml);
    const molLd = ldObjects.find((o) => /MolecularEntity|ChemicalSubstance/i.test(String(o['@type'] ?? '')));

    const title =
      (typeof molLd?.name === 'string' ? molLd.name.trim() : '') ||
      extractMetaContent(rawHtml, 'og:title').replace(/\s*\|\s*C\d+.*?\s*-\s*PubChem$/i, '').trim();
    if (!title) return null;

    const formula = typeof molLd?.molecularFormula === 'string' ? molLd.molecularFormula : '';
    const weight =
      typeof molLd?.molecularWeight === 'string' || typeof molLd?.molecularWeight === 'number'
        ? String(molLd.molecularWeight)
        : typeof (molLd?.molecularWeight as Record<string, unknown> | undefined)?.value !== 'undefined'
          ? `${String((molLd!.molecularWeight as Record<string, unknown>).value)} g/mol`
          : '';
    const iupac = typeof molLd?.iupacName === 'string' ? molLd.iupacName : '';
    const inchiKey = typeof molLd?.inChIKey === 'string' ? molLd.inChIKey : '';
    const smiles = typeof molLd?.smiles === 'string' ? molLd.smiles : Array.isArray(molLd?.smiles) ? String(molLd.smiles[0] ?? '') : '';
    const desc = extractMetaContent(rawHtml, 'description');

    const bullets: string[] = [];
    if (formula) bullets.push(`- **Molecular Formula**: \`${formula}\``);
    if (weight) bullets.push(`- **Molecular Weight**: ${weight}`);
    if (iupac) bullets.push(`- **IUPAC Name**: \`${iupac}\``);
    if (inchiKey) bullets.push(`- **InChIKey**: \`${inchiKey}\``);
    if (smiles) bullets.push(`- **SMILES**: \`${smiles}\``);

    if (bullets.length === 0 && !desc) return null;

    const sections: string[] = [`# ${title} (PubChem)`];
    if (bullets.length > 0) sections.push(bullets.join('\n'));
    if (desc) sections.push(`## Summary\n\n${desc}`);
    if (currentMd && currentMd.length > 200) {
      sections.push(currentMd.replace(/^#\s+.+\n+/, '').trim());
    }

    return {
      extractorId: 'pubchem',
      title: `${title} (PubChem)`,
      ...(desc ? { description: desc.slice(0, 260) } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
