import { defineAdapter } from '../../types';
import { formatUsdCompact, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'usaspending',
  name: 'USAspending.gov Federal Awards',
  category: 'public-records',
  description: 'Upgrades usaspending.gov/award/<id> pages to api.usaspending.gov/api/v2/awards/<id>/ JSON details.',
  domains: ['www.usaspending.gov', 'usaspending.gov'],
  exampleUrls: ['https://www.usaspending.gov/award/CONT_AWD_NNK17MA01B_8000_-NONE-_-NONE-'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'award' || !parts[1]) return null;
    const awardId = decodeURIComponent(parts[1]);
    if (!/^[A-Za-z0-9_.-]{4,140}$/.test(awardId)) return null;

    return {
      id: 'usaspending',
      fetchUrl: `https://api.usaspending.gov/api/v2/awards/${encodeURIComponent(awardId)}/`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || (!data.generated_unique_award_id && !data.piid && !data.fain)) return null;

        const idLabel = String(data.piid || data.fain || data.uri || awardId);
        const category = typeof data.category === 'string' ? data.category : 'Federal Award';
        const recipientObj = data.recipient as Record<string, unknown> | undefined;
        const recipient = typeof recipientObj?.recipient_name === 'string' ? recipientObj.recipient_name : '';
        const awardingAgency = (data.awarding_agency as Record<string, unknown> | undefined)?.toptier_agency as Record<string, unknown> | undefined;
        const fundingAgency = (data.funding_agency as Record<string, unknown> | undefined)?.toptier_agency as Record<string, unknown> | undefined;
        const obligation = formatUsdCompact(data.total_obligation);
        const desc = typeof data.description === 'string' ? data.description.trim() : '';
        const pop = data.period_of_performance as Record<string, unknown> | undefined;
        const startDate = typeof pop?.start_date === 'string' ? pop.start_date : '';
        const endDate = typeof pop?.end_date === 'string' ? pop.end_date : '';

        const title = recipient ? `${idLabel} — ${recipient} (USAspending)` : `${idLabel} (USAspending)`;
        const bullets: string[] = [`- **Award ID**: \`${idLabel}\` (${category})`];
        if (recipient) bullets.push(`- **Recipient**: ${recipient}`);
        if (obligation) bullets.push(`- **Total Obligation**: ${obligation}`);
        if (typeof awardingAgency?.name === 'string') bullets.push(`- **Awarding Agency**: ${awardingAgency.name}`);
        if (typeof fundingAgency?.name === 'string') bullets.push(`- **Funding Agency**: ${fundingAgency.name}`);
        if (startDate || endDate) bullets.push(`- **Period of Performance**: ${startDate || '?'} → ${endDate || '?'}`);

        const sections = [`# ${title}`, bullets.join('\n')];
        if (desc) sections.push(`## Award Description\n\n${desc}`);

        return {
          title,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          ...(startDate ? { publishedTime: startDate } : {}),
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
});
