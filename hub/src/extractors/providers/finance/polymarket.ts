import { defineAdapter } from '../../types';
import { formatGfmTable, formatUsdCompact, parseJsonValue } from '../../utils';

export default defineAdapter({
  id: 'polymarket',
  name: 'Polymarket Prediction Markets',
  category: 'finance',
  description: 'Upgrades polymarket.com/event/<slug> pages to gamma-api.polymarket.com JSON with live outcome probabilities, volume, and liquidity.',
  domains: ['polymarket.com', 'www.polymarket.com'],
  exampleUrls: ['https://polymarket.com/event/fed-decision-in-december'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'event' || !parts[1]) return null;
    const slug = decodeURIComponent(parts[1]);
    if (!/^[A-Za-z0-9_-]{2,140}$/.test(slug)) return null;

    return {
      id: 'polymarket',
      fetchUrl: `https://gamma-api.polymarket.com/events?slug=${encodeURIComponent(slug)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const parsed = parseJsonValue(rawBody);
        const ev = Array.isArray(parsed) ? (parsed[0] as Record<string, unknown> | undefined) : (parsed as Record<string, unknown> | undefined);
        if (!ev || typeof ev.title !== 'string') return null;

        const title = ev.title.trim();
        const desc = typeof ev.description === 'string' ? ev.description.trim() : '';
        const vol = formatUsdCompact(ev.volume);
        const liq = formatUsdCompact(ev.liquidity);
        const endDate = typeof ev.endDate === 'string' ? ev.endDate.slice(0, 10) : '';
        const closed = Boolean(ev.closed);

        const bullets: string[] = [`- **Status**: ${closed ? 'Closed / Resolved' : 'Active'}`];
        if (vol) bullets.push(`- **Total Volume**: ${vol}`);
        if (liq) bullets.push(`- **Liquidity**: ${liq}`);
        if (endDate) bullets.push(`- **End Date**: ${endDate}`);

        const markets = Array.isArray(ev.markets) ? (ev.markets as Array<Record<string, unknown>>) : [];
        const rows: Array<Array<string>> = [];
        for (const m of markets.slice(0, 25)) {
          const q = String(m.groupItemTitle || m.question || title).trim();
          const outcomesRaw = typeof m.outcomes === 'string' ? parseJsonValue(m.outcomes) : m.outcomes;
          const pricesRaw = typeof m.outcomePrices === 'string' ? parseJsonValue(m.outcomePrices) : m.outcomePrices;
          const outcomes = Array.isArray(outcomesRaw) ? outcomesRaw.map(String) : ['Yes', 'No'];
          const prices = Array.isArray(pricesRaw) ? pricesRaw.map((p) => Number(p)) : [];
          const probSummary = outcomes
            .map((o, idx) => {
              const pr = prices[idx];
              return Number.isFinite(pr) ? `${o}: ${(pr! * 100).toFixed(1)}%` : o;
            })
            .join(' · ');
          const mVol = formatUsdCompact(m.volume) || '-';
          rows.push([q, probSummary || '-', mVol]);
        }

        const sections: string[] = [`# ${title}`, bullets.join('\n')];
        if (rows.length > 0) {
          sections.push(`## Market Odds\n\n${formatGfmTable(['Market / Outcome', 'Implied Probability', 'Volume'], rows)}`);
        }
        if (desc) sections.push(`## Resolution Rules\n\n${desc}`);

        return {
          title,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
});
