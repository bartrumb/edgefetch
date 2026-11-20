import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'sec-edgar',
  name: 'SEC EDGAR Company Submissions & Filings',
  category: 'finance',
  description: 'Upgrades sec.gov EDGAR company browse pages and CIK URLs to keyless data.sec.gov JSON submissions (10-K, 10-Q, 8-K, DEF 14A, Form 4, 13F).',
  domains: ['www.sec.gov', 'sec.gov', 'data.sec.gov'],
  exampleUrls: ['https://www.sec.gov/edgar/browse/?CIK=0001477333', 'https://data.sec.gov/submissions/CIK0000320193.json'],
  resolveTwin({ url, host, parts }) {
    let rawCik = '';
    if ((host === 'www.sec.gov' || host === 'sec.gov') && parts[0] === 'edgar' && parts[1] === 'browse') {
      rawCik = url.searchParams.get('CIK') ?? url.searchParams.get('cik') ?? '';
    } else if ((host === 'www.sec.gov' || host === 'sec.gov') && url.pathname === '/cgi-bin/browse-edgar') {
      rawCik = url.searchParams.get('CIK') ?? url.searchParams.get('cik') ?? '';
    } else if (host === 'data.sec.gov' && parts[0] === 'submissions' && parts[1]) {
      const m = /^CIK(\d+)\.json$/i.exec(parts[1]);
      if (m?.[1]) rawCik = m[1];
    }

    if (!/^\d{1,10}$/.test(rawCik.trim())) return null;
    const paddedCik = rawCik.trim().padStart(10, '0');
    const numericCik = String(parseInt(paddedCik, 10));

    return {
      id: 'sec-edgar',
      fetchUrl: `https://data.sec.gov/submissions/CIK${paddedCik}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.name !== 'string') return null;

        const name = data.name.trim();
        const tickers = Array.isArray(data.tickers) ? data.tickers.map(String).filter(Boolean) : [];
        const exchanges = Array.isArray(data.exchanges) ? data.exchanges.map(String).filter(Boolean) : [];
        const sic = typeof data.sic === 'string' ? data.sic : '';
        const sicDesc = typeof data.sicDescription === 'string' ? data.sicDescription : '';
        const stateInc = typeof data.stateOfIncorporation === 'string' ? data.stateOfIncorporation : '';
        const fye = typeof data.fiscalYearEnd === 'string' && data.fiscalYearEnd.length === 4
          ? `${data.fiscalYearEnd.slice(0, 2)}/${data.fiscalYearEnd.slice(2)}`
          : '';
        const category = typeof data.category === 'string' ? data.category : '';

        const title = tickers.length > 0 ? `${name} (${tickers.join(', ')}) — SEC EDGAR` : `${name} (CIK ${paddedCik}) — SEC EDGAR`;
        const bullets: string[] = [`- **CIK**: \`${paddedCik}\``];
        if (tickers.length > 0) bullets.push(`- **Tickers**: ${tickers.map((t) => `\`${t}\``).join(', ')}${exchanges.length > 0 ? ` (${exchanges.join(', ')})` : ''}`);
        if (sic || sicDesc) bullets.push(`- **SIC Industry**: ${[sic, sicDesc].filter(Boolean).join(' — ')}`);
        if (category) bullets.push(`- **Filer Category**: ${category}`);
        if (stateInc) bullets.push(`- **Incorporation**: ${stateInc}`);
        if (fye) bullets.push(`- **Fiscal Year End**: ${fye}`);

        const filings = (data.filings as Record<string, unknown> | undefined)?.recent as Record<string, unknown> | undefined;
        const forms = Array.isArray(filings?.form) ? (filings.form as string[]) : [];
        const dates = Array.isArray(filings?.filingDate) ? (filings.filingDate as string[]) : [];
        const reportDates = Array.isArray(filings?.reportDate) ? (filings.reportDate as string[]) : [];
        const accessions = Array.isArray(filings?.accessionNumber) ? (filings.accessionNumber as string[]) : [];
        const primaryDocs = Array.isArray(filings?.primaryDocument) ? (filings.primaryDocument as string[]) : [];
        const itemsArr = Array.isArray(filings?.items) ? (filings.items as string[]) : [];

        const priorityForms = new Set(['10-K', '10-K/A', '10-Q', '10-Q/A', '8-K', 'DEF 14A', '20-F', 'S-1', '13F-HR', '4']);
        const rows: Array<Array<string>> = [];
        const links: string[] = [];

        for (let i = 0; i < forms.length && rows.length < 25; i++) {
          const form = String(forms[i] ?? '');
          if (rows.length >= 12 && !priorityForms.has(form)) continue;
          const accRaw = String(accessions[i] ?? '');
          const accNoDash = accRaw.replace(/-/g, '');
          const primDoc = String(primaryDocs[i] ?? '');
          const filingDate = String(dates[i] ?? '-');
          const repDate = String(reportDates[i] ?? '') || '-';
          const items = String(itemsArr[i] ?? '') || '-';
          const docUrl =
            accNoDash && primDoc
              ? `https://www.sec.gov/Archives/edgar/data/${numericCik}/${accNoDash}/${primDoc}`
              : accRaw
                ? `https://www.sec.gov/Archives/edgar/data/${numericCik}/${accNoDash}/${accRaw}-index.htm`
                : '';
          if (docUrl) links.push(docUrl);
          rows.push([
            docUrl ? `[**${form}**](${docUrl})` : `**${form}**`,
            filingDate,
            repDate,
            items,
          ]);
        }

        const sections = [`# ${title}`, bullets.join('\n')];
        if (rows.length > 0) {
          sections.push(`## Recent SEC Filings\n\n${formatGfmTable(['Form', 'Filed', 'Period', '8-K Items'], rows)}`);
        }

        return {
          title,
          description: `${name} SEC EDGAR filings (${tickers.join(', ') || `CIK ${paddedCik}`})`,
          markdown: sections.join('\n\n'),
          links,
        };
      },
    };
  },
});
