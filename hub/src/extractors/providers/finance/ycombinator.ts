import { defineAdapter } from '../../types';
import { decodeBasicEntities, formatGfmTable, parseJsonObject, stripTagsInline } from '../../utils';

function parseYcInertiaDataPage(rawHtml: string): Record<string, unknown> | null {
  const m = /\bdata-page=["']([^"']+)["']/i.exec(rawHtml);
  if (!m?.[1]) return null;
  const decoded = decodeBasicEntities(m[1]);
  return parseJsonObject(decoded);
}

function formatYcCompanyProps(props: Record<string, unknown>, slugFallback: string): {
  title: string;
  description?: string;
  markdown: string;
  links: string[];
} | null {
  const company = (props.company as Record<string, unknown> | undefined) ?? null;
  if (!company || typeof company.name !== 'string') return null;

  const name = company.name.trim();
  const oneLiner = typeof company.one_liner === 'string' ? company.one_liner.trim() : '';
  const longDesc = typeof company.long_description === 'string' ? company.long_description.trim() : '';
  const batch = typeof company.batch_name === 'string' ? company.batch_name : typeof company.batch === 'string' ? company.batch : '';
  const status = typeof company.ycdc_status === 'string' ? company.ycdc_status : typeof company.status === 'string' ? company.status : '';
  const teamSize = company.team_size !== undefined && company.team_size !== null ? String(company.team_size) : '';
  const location = typeof company.location === 'string' ? company.location : typeof company.city === 'string' ? company.city : '';
  const website = typeof company.website === 'string' ? company.website : '';
  const yearFounded = company.year_founded !== undefined && company.year_founded !== null ? String(company.year_founded) : '';
  const tags = Array.isArray(company.tags) ? company.tags.map(String).filter(Boolean) : [];

  const title = batch ? `${name} (YC ${batch})` : `${name} (Y Combinator)`;
  const bullets: string[] = [];
  if (batch) bullets.push(`- **YC Batch**: ${batch}`);
  if (status) bullets.push(`- **Status**: ${status}`);
  if (yearFounded) bullets.push(`- **Founded**: ${yearFounded}`);
  if (teamSize) bullets.push(`- **Team Size**: ${teamSize}`);
  if (location) bullets.push(`- **Location**: ${location}`);
  if (website) bullets.push(`- **Website**: ${website}`);
  if (tags.length > 0) bullets.push(`- **Tags**: ${tags.join(', ')}`);

  const links: string[] = [];
  if (website.startsWith('https://')) links.push(website);

  const founders = Array.isArray(company.founders) ? (company.founders as Array<Record<string, unknown>>) : [];
  const founderLines: string[] = [];
  for (const f of founders) {
    const fName = typeof f.full_name === 'string' ? f.full_name.trim() : '';
    if (!fName) continue;
    const fTitle = typeof f.title === 'string' ? f.title.trim() : 'Founder';
    const fBio = typeof f.founder_bio === 'string' ? stripTagsInline(f.founder_bio) : '';
    const li = typeof f.linkedin_url === 'string' && f.linkedin_url.startsWith('https://') ? f.linkedin_url : '';
    if (li) links.push(li);
    founderLines.push(`- **${li ? `[${fName}](${li})` : fName}** (${fTitle})${fBio ? ` — ${fBio}` : ''}`);
  }

  const jobPostings = Array.isArray(props.jobPostings)
    ? (props.jobPostings as Array<Record<string, unknown>>)
    : Array.isArray(company.jobPostings)
      ? (company.jobPostings as Array<Record<string, unknown>>)
      : [];
  const jobRows: Array<Array<string>> = [];
  for (const jp of jobPostings.slice(0, 30)) {
    const jTitle = String(jp.title ?? '').trim();
    if (!jTitle) continue;
    const jUrlRaw = typeof jp.url === 'string' ? jp.url : '';
    const jUrl = jUrlRaw.startsWith('http')
      ? jUrlRaw
      : jUrlRaw.startsWith('/')
        ? `https://www.ycombinator.com${jUrlRaw}`
        : `https://www.ycombinator.com/companies/${slugFallback}/jobs`;
    links.push(jUrl);
    const jLoc = String(jp.location ?? jp.pretty_location ?? '-');
    const jSalary = String(jp.salary_range ?? jp.pretty_salary_range ?? '-');
    const jRole = String(jp.role ?? jp.type ?? '-');
    jobRows.push([`[${jTitle}](${jUrl})`, jLoc, jSalary, jRole]);
  }

  const sections: string[] = [`# ${title}`];
  if (oneLiner) sections.push(`> ${oneLiner}`);
  if (bullets.length > 0) sections.push(bullets.join('\n'));
  if (longDesc) sections.push(`## About ${name}\n\n${longDesc}`);
  if (founderLines.length > 0) sections.push(`## Founders\n\n${founderLines.join('\n')}`);
  if (jobRows.length > 0) {
    sections.push(`## Open Roles (${jobPostings.length})\n\n${formatGfmTable(['Role', 'Location', 'Salary', 'Type'], jobRows)}`);
  }

  return {
    title,
    ...(oneLiner ? { description: oneLiner } : {}),
    markdown: sections.join('\n\n'),
    links,
  };
}

export default defineAdapter({
  id: 'ycombinator',
  name: 'Y Combinator Directory & Work at a Startup',
  category: 'finance',
  description: 'Extracts YC company profiles, founders, batches, and open roles from ycombinator.com/companies/<slug> (and upgrades login-gated workatastartup.com company pages to their public YC mirror).',
  domains: ['www.ycombinator.com', 'ycombinator.com', 'www.workatastartup.com', 'workatastartup.com'],
  exampleUrls: [
    'https://www.ycombinator.com/companies/supabase',
    'https://www.workatastartup.com/companies/supabase',
  ],
  resolveTwin({ host, parts }) {
    // `workatastartup.com/companies/<slug>` gates job bodies behind login; `ycombinator.com/companies/<slug>/jobs` is public!
    if ((host === 'www.workatastartup.com' || host === 'workatastartup.com') && parts[0] === 'companies' && parts[1]) {
      const slug = parts[1];
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(slug)) return null;
      return {
        id: 'workatastartup-yc-mirror',
        fetchUrl: `https://www.ycombinator.com/companies/${encodeURIComponent(slug)}/jobs`,
        kind: 'text',
        accept: 'text/html',
        formatTwin: (rawBody) => {
          const page = parseYcInertiaDataPage(rawBody);
          const props = page?.props as Record<string, unknown> | undefined;
          if (!props) return null;
          return formatYcCompanyProps(props, slug);
        },
      };
    }
    return null;
  },
  extractHtml({ host, parts, rawHtml }) {
    if ((host !== 'www.ycombinator.com' && host !== 'ycombinator.com') || parts[0] !== 'companies' || !parts[1]) {
      return null;
    }
    const page = parseYcInertiaDataPage(rawHtml);
    const props = page?.props as Record<string, unknown> | undefined;
    if (!props) return null;
    const formatted = formatYcCompanyProps(props, parts[1]);
    if (!formatted) return null;
    return {
      extractorId: 'ycombinator',
      title: formatted.title,
      ...(formatted.description ? { description: formatted.description } : {}),
      markdown: formatted.markdown,
      links: formatted.links,
    };
  },
});
