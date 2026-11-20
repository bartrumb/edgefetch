import { defineAdapter } from '../../types';
import { extractJsonLdObjects, extractMetaContent, parseJsonObject } from '../../utils';

function extractBalancedJsonObjectAfter(src: string, keyMarker: RegExp): Record<string, unknown> | null {
  const m = keyMarker.exec(src);
  if (!m) return null;
  const openIdx = src.indexOf('{', m.index + m[0].length - 1);
  if (openIdx < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = openIdx; i < Math.min(src.length, openIdx + 120000); i++) {
    const ch = src[i]!;
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        return parseJsonObject(src.slice(openIdx, i + 1));
      }
    }
  }
  return null;
}

export default defineAdapter({
  id: 'clinicaltrials',
  name: 'ClinicalTrials.gov Studies',
  category: 'research-health',
  description: 'Extracts clinical trial NCT ID, recruitment status, phase, conditions, interventions, sponsor, and summary from rendered clinicaltrials.gov/study/NCT... pages (strictly respecting robots.txt).',
  domains: ['clinicaltrials.gov', 'www.clinicaltrials.gov'],
  exampleUrls: ['https://clinicaltrials.gov/study/NCT04280705'],
  extractHtml({ path, rawHtml, currentMd }) {
    const nctMatch = /\b(NCT\d{8})\b/i.exec(path);
    if (!nctMatch?.[1]) return null;
    const nctId = nctMatch[1].toUpperCase();

    // Check embedded JSON study state or Schema.org `MedicalTrial` / `MedicalStudy` JSON-LD
    const ldObjects = extractJsonLdObjects(rawHtml);
    const studyLd = ldObjects.find((o) => /MedicalStudy|MedicalTrial|ClinicalTrial/i.test(String(o['@type'] ?? '')));

    // Also support raw ClinicalTrials v2 protocolSection JSON if embedded in SSR state
    const proto = extractBalancedJsonObjectAfter(rawHtml, /"protocolSection"\s*:\s*\{/i);
    const idMod = proto?.identificationModule as Record<string, unknown> | undefined;
    const statusMod = proto?.statusModule as Record<string, unknown> | undefined;
    const descMod = proto?.descriptionModule as Record<string, unknown> | undefined;
    const condMod = proto?.conditionsModule as Record<string, unknown> | undefined;
    const designMod = proto?.designModule as Record<string, unknown> | undefined;
    const sponsorMod = proto?.sponsorCollaboratorsModule as Record<string, unknown> | undefined;

    const title =
      (typeof idMod?.briefTitle === 'string' ? idMod.briefTitle.trim() : '') ||
      (typeof studyLd?.name === 'string' ? studyLd.name.trim() : '') ||
      extractMetaContent(rawHtml, 'og:title');
    if (!title) return null;

    const overallStatus =
      (typeof statusMod?.overallStatus === 'string' ? statusMod.overallStatus : '') ||
      (typeof studyLd?.status === 'string' ? studyLd.status : '');
    const phases = Array.isArray(designMod?.phases) ? designMod.phases.map(String).join(', ') : '';
    const conditions = Array.isArray(condMod?.conditions)
      ? condMod.conditions.map(String)
      : Array.isArray(studyLd?.healthCondition)
        ? (studyLd.healthCondition as Array<Record<string, unknown>>).map((c) => String(c.name ?? '')).filter(Boolean)
        : [];
    const leadSponsor = (sponsorMod?.leadSponsor as Record<string, unknown> | undefined)?.name ??
      (studyLd?.sponsor as Record<string, unknown> | undefined)?.name;
    const summary =
      (typeof descMod?.briefSummary === 'string' ? descMod.briefSummary.trim() : '') ||
      (typeof studyLd?.description === 'string' ? studyLd.description.trim() : '') ||
      extractMetaContent(rawHtml, 'description');

    const bullets: string[] = [`- **NCT Number**: \`${nctId}\``];
    if (overallStatus) bullets.push(`- **Status**: ${overallStatus}`);
    if (phases) bullets.push(`- **Phase**: ${phases}`);
    if (typeof leadSponsor === 'string' && leadSponsor) bullets.push(`- **Lead Sponsor**: ${leadSponsor}`);
    if (conditions.length > 0) bullets.push(`- **Conditions**: ${conditions.slice(0, 10).join(', ')}`);

    if (bullets.length <= 1 && !summary) return null;

    const sections: string[] = [`# ${title} (${nctId})`, bullets.join('\n')];
    if (summary) sections.push(`## Brief Summary\n\n${summary}`);
    if (currentMd && currentMd.length > (summary?.length ?? 0) + 120) {
      sections.push(currentMd.replace(/^#\s+.+\n+/, '').trim());
    }

    return {
      extractorId: 'clinicaltrials',
      title: `${title} (${nctId})`,
      ...(summary ? { description: summary.slice(0, 260) } : {}),
      markdown: sections.join('\n\n'),
    };
  },
});
