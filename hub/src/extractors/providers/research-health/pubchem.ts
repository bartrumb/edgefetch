import { defineAdapter } from '../../types';
import { extractJsonLdObjects, extractMetaContent } from '../../utils';

export default defineAdapter({
  id: 'pubchem',
  name: 'PubChem Chemical Compounds (NCBI)',
  category: 'research-health',
  description: 'Extracts PubChem compound formula, molecular weight, IUPAC name, InChIKey, SMILES, and summary from pubchem.ncbi.nlm.nih.gov/compound/... (strictly respecting robots.txt).',
  domains: ['pubchem.ncbi.nlm.nih.gov'],
  exampleUrls: ['https://pubchem.ncbi.nlm.nih.gov/compound/2244'],
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
