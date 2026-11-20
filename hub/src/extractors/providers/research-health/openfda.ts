import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'openfda',
  name: 'openFDA Recalls, Labels & Adverse Events API',
  category: 'research-health',
  description: 'Formats keyless api.fda.gov JSON endpoints (drug/food/device enforcement recalls, drug labels, and adverse events) into clean Markdown tables.',
  domains: ['api.fda.gov'],
  exampleUrls: ['https://api.fda.gov/food/enforcement.json?limit=5'],
  resolveTwin({ url, urlStr }) {
    if (!url.pathname.endsWith('.json')) return null;
    return {
      id: 'openfda',
      fetchUrl: urlStr,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const results = Array.isArray(data?.results) ? (data.results as Array<Record<string, unknown>>) : [];
        if (results.length === 0) return null;
        const metaResults = (data?.meta as Record<string, unknown> | undefined)?.results as Record<string, unknown> | undefined;
        const total = typeof metaResults?.total === 'number' ? metaResults.total.toLocaleString('en-US') : String(results.length);
        const endpointLabel = url.pathname.replace(/^\//, '').replace(/\.json$/, '');
        const title = `openFDA ${endpointLabel} (${results.length} of ${total} records)`;

        // Enforcement recall records (`recall_number`, `recalling_firm`, `classification`, `reason_for_recall`)
        if (results[0]?.recall_number || results[0]?.reason_for_recall) {
          const rows = results.slice(0, 25).map((r) => [
            `\`${String(r.recall_number ?? '-')}\``,
            String(r.classification ?? '-'),
            String(r.status ?? '-'),
            String(r.recalling_firm ?? '-'),
            String(r.reason_for_recall ?? '-'),
          ]);
          return {
            title,
            markdown: `# ${title}\n\n${formatGfmTable(['Recall #', 'Class', 'Status', 'Firm', 'Reason'], rows)}`,
          };
        }

        // Drug label or generic openFDA JSON records
        const sections: string[] = [`# ${title}`];
        for (let i = 0; i < Math.min(results.length, 10); i++) {
          const r = results[i]!;
          const openfda = (r.openfda as Record<string, unknown> | undefined) ?? {};
          const brand = Array.isArray(openfda.brand_name) ? String(openfda.brand_name[0] ?? '') : '';
          const generic = Array.isArray(openfda.generic_name) ? String(openfda.generic_name[0] ?? '') : '';
          const heading = [brand, generic ? `(${generic})` : ''].filter(Boolean).join(' ') || `Record #${i + 1}`;
          const lines: string[] = [`## ${heading}`];
          for (const key of ['indications_and_usage', 'warnings', 'boxed_warning', 'dosage_and_administration', 'adverse_reactions']) {
            const val = r[key];
            const text = Array.isArray(val) ? String(val[0] ?? '').trim() : typeof val === 'string' ? val.trim() : '';
            if (text) lines.push(`### ${key.replace(/_/g, ' ')}\n\n${text.slice(0, 1200)}`);
          }
          sections.push(lines.join('\n\n'));
        }

        return {
          title,
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
});
