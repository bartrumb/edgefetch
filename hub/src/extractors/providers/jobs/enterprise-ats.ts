import { defineAdapter } from '../../types';
import { extractBalancedDivAt, extractJsonLdObjects, formatGfmTable, parseJsonObject, stripScriptsAndStyles, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'enterprise-ats',
  name: 'SmartRecruiters, Oracle HCM Cloud & Jobvite',
  category: 'jobs',
  description: 'Keyless Oracle HCM Cloud recruitingCEJobRequisitions REST twin + robots.txt-safe SmartRecruiters and Jobvite HTML posting extractors.',
  domains: ['jobs.smartrecruiters.com', '*.oraclecloud.com', 'jobs.jobvite.com'],
  exampleUrls: [
    'https://jobs.smartrecruiters.com/Visa/744000012345678-senior-software-engineer',
    'https://acme.fa.us2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1/requisitions',
    'https://jobs.jobvite.com/acme/job/oABCdef1',
  ],
  resolveTwin({ host, path }) {
    // Oracle HCM Cloud (`<tenant>.fa.<pod>.oraclecloud.com/hcmUI/CandidateExperience/<lang>/sites/<site>/...`)
    if (/^[a-z0-9-]+\.fa\.[a-z0-9.-]*oraclecloud\.com$/i.test(host)) {
      const siteMatch = /\/sites\/([A-Za-z0-9_-]+)/i.exec(path);
      if (!siteMatch?.[1]) return null;
      const siteNumber = siteMatch[1];
      const reqMatch = /\/(?:job|requisitions\/preview)\/([A-Za-z0-9_-]+)/i.exec(path);

      if (reqMatch?.[1]) {
        const reqId = reqMatch[1];
        return {
          id: 'oracle-hcm-job',
          fetchUrl: `https://${host}/hcmRestApi/resources/latest/recruitingCEJobRequisitionDetails?onlyData=true&expand=all&finder=ById;Id=%22${encodeURIComponent(reqId)}%22,siteNumber=${encodeURIComponent(siteNumber)}`,
          kind: 'json',
          accept: 'application/json',
          formatTwin: (rawBody, origUrl, htmlToMd) => {
            const data = parseJsonObject(rawBody);
            const item = Array.isArray(data?.items) ? (data.items[0] as Record<string, unknown> | undefined) : undefined;
            if (!item || typeof item.Title !== 'string') return null;
            const title = item.Title.trim();
            const loc = String(item.PrimaryLocation ?? '');
            const wp = String(item.WorkplaceType ?? '');
            const posted = String(item.ExternalPostedStartDate ?? '').slice(0, 10);
            const extDesc = typeof item.ExternalDescriptionStr === 'string' ? htmlToMd(item.ExternalDescriptionStr, origUrl).markdown.trim() : '';
            const extResp = typeof item.ExternalResponsibilitiesStr === 'string' ? htmlToMd(item.ExternalResponsibilitiesStr, origUrl).markdown.trim() : '';
            const extQual = typeof item.ExternalQualificationsStr === 'string' ? htmlToMd(item.ExternalQualificationsStr, origUrl).markdown.trim() : '';
            const bullets: string[] = [`- **Requisition ID**: \`${reqId}\``];
            if (loc) bullets.push(`- **Primary Location**: ${loc}`);
            if (wp) bullets.push(`- **Workplace**: ${wp}`);
            if (posted) bullets.push(`- **Posted**: ${posted}`);
            return {
              title,
              ...(posted ? { publishedTime: posted } : {}),
              markdown: [
                `# ${title}`,
                bullets.join('\n'),
                extDesc,
                extResp ? `## Responsibilities\n\n${extResp}` : '',
                extQual ? `## Qualifications\n\n${extQual}` : '',
              ]
                .filter(Boolean)
                .join('\n\n'),
            };
          },
        };
      }

      if (/\/requisitions\/?$/i.test(path) || /\/sites\/[A-Za-z0-9_-]+\/?$/i.test(path)) {
        return {
          id: 'oracle-hcm-board',
          fetchUrl: `https://${host}/hcmRestApi/resources/latest/recruitingCEJobRequisitions?onlyData=true&expand=requisitionList.secondaryLocations&finder=findReqs;siteNumber=${encodeURIComponent(siteNumber)},limit=25`,
          kind: 'json',
          accept: 'application/json',
          formatTwin: (rawBody) => {
            const data = parseJsonObject(rawBody);
            const outer = Array.isArray(data?.items) ? (data.items[0] as Record<string, unknown> | undefined) : undefined;
            const reqs = Array.isArray(outer?.requisitionList) ? (outer.requisitionList as Array<Record<string, unknown>>) : null;
            if (!reqs) return null;
            const total = typeof outer?.TotalJobsCount === 'number' ? outer.TotalJobsCount : reqs.length;
            const title = `Oracle HCM (${siteNumber}) — Open Requisitions (${total})`;
            if (reqs.length === 0) return { title, markdown: `# ${title}\n\nNo open requisitions currently listed.` };
            const links: string[] = [];
            const rows = reqs.slice(0, 50).map((r) => {
              const id = String(r.Id ?? '');
              const rTitle = String(r.Title ?? 'Requisition').trim();
              const rUrl = `https://${host}/hcmUI/CandidateExperience/en/sites/${siteNumber}/job/${id}`;
              links.push(rUrl);
              return [
                `[${rTitle}](${rUrl})`,
                String(r.PrimaryLocation ?? '-'),
                String(r.WorkplaceType ?? '-'),
                String(r.PostedDate ?? '').slice(0, 10) || '-',
              ];
            });
            return {
              title,
              markdown: `# ${title}\n\n${formatGfmTable(['Requisition', 'Location', 'Workplace', 'Posted'], rows)}`,
              links,
            };
          },
        };
      }
    }
    return null;
  },
  extractHtml({ host, parts, rawHtml, baseUrl, htmlToMd }) {
    const clean = stripScriptsAndStyles(rawHtml);

    // SmartRecruiters (`jobs.smartrecruiters.com/<Company>/<JobId>` — strictly HTML, never hitting disallowed api.smartrecruiters.com!)
    if (host === 'jobs.smartrecruiters.com' && parts.length >= 2) {
      const ldObjects = extractJsonLdObjects(rawHtml);
      const jobLd = ldObjects.find((o) => String(o['@type'] ?? '') === 'JobPosting');
      const title =
        (typeof jobLd?.title === 'string' ? jobLd.title.trim() : '') ||
        stripTagsInline(/<h1\b[^>]*\bjob-title\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ?? '');
      const company =
        (typeof (jobLd?.hiringOrganization as Record<string, unknown> | undefined)?.name === 'string'
          ? String((jobLd!.hiringOrganization as Record<string, unknown>).name).trim()
          : '') || parts[0]!;
      const descSec =
        /<div\b[^>]*itemprop=["']description["'][^>]*>([\s\S]*?)<\/div>/i.exec(clean)?.[1] ??
        /<section\b[^>]*id=["']st-jobDescription["'][^>]*>([\s\S]*?)<\/section>/i.exec(clean)?.[1] ??
        (typeof jobLd?.description === 'string' ? jobLd.description : '');
      if (!title || !descSec) return null;
      const bodyMd = htmlToMd(descSec, baseUrl).markdown.trim();
      return {
        extractorId: 'smartrecruiters',
        title: `${title} @ ${company}`,
        markdown: `# ${title} @ ${company}\n\n${bodyMd}`,
      };
    }

    // Jobvite (`jobs.jobvite.com/<org>/job/<id>` fallback when JSON-LD is absent)
    if (host === 'jobs.jobvite.com' && parts.length >= 3 && parts[1] === 'job') {
      const descOpen = /<div\b[^>]*\bjv-job-detail-description\b[^>]*>/i.exec(clean);
      if (!descOpen) return null;
      const inner = extractBalancedDivAt(clean, descOpen.index);
      const title = stripTagsInline(/<h2\b[^>]*\bjv-header\b[^>]*>([\s\S]*?)<\/h2>/i.exec(clean)?.[1] ?? '');
      if (!inner || !title) return null;
      const meta = stripTagsInline(/<p\b[^>]*\bjv-job-detail-meta\b[^>]*>([\s\S]*?)<\/p>/i.exec(clean)?.[1] ?? '');
      const bodyMd = htmlToMd(inner, baseUrl).markdown.trim();
      return {
        extractorId: 'jobvite',
        title: `${title} @ ${parts[0]}`,
        markdown: [`# ${title} @ ${parts[0]}`, meta ? `*${meta}*` : '', bodyMd].filter(Boolean).join('\n\n'),
      };
    }

    return null;
  },
});
