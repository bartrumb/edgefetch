import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'nist-nvd',
  name: 'NIST National Vulnerability Database (NVD)',
  category: 'developer',
  description: 'Upgrades nvd.nist.gov CVE pages to the keyless NVD REST v2 JSON API with CVSS scores, CWEs, and vendor advisories.',
  domains: ['nvd.nist.gov', 'www.nvd.nist.gov'],
  exampleUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094'],
  resolveTwin({ parts }) {
    // Matches `/vuln/detail/CVE-YYYY-NNNN...`
    if (parts[0] !== 'vuln' || parts[1] !== 'detail' || !parts[2]) return null;
    const cveId = parts[2].toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return null;

    return {
      id: 'nist-nvd',
      fetchUrl: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const vulns = Array.isArray(data?.vulnerabilities) ? (data.vulnerabilities as Array<Record<string, unknown>>) : [];
        const cve = vulns[0]?.cve as Record<string, unknown> | undefined;
        if (!cve || typeof cve.id !== 'string') return null;

        const descriptions = Array.isArray(cve.descriptions) ? (cve.descriptions as Array<Record<string, unknown>>) : [];
        const enDesc =
          descriptions.find((d) => d.lang === 'en' && typeof d.value === 'string')?.value ??
          descriptions.find((d) => typeof d.value === 'string')?.value ??
          '';
        const descStr = String(enDesc).trim();

        const metrics = (cve.metrics as Record<string, unknown> | undefined) ?? {};
        const v31 = Array.isArray(metrics.cvssMetricV31) ? (metrics.cvssMetricV31[0] as Record<string, unknown> | undefined) : undefined;
        const v40 = Array.isArray(metrics.cvssMetricV40) ? (metrics.cvssMetricV40[0] as Record<string, unknown> | undefined) : undefined;
        const v30 = Array.isArray(metrics.cvssMetricV30) ? (metrics.cvssMetricV30[0] as Record<string, unknown> | undefined) : undefined;
        const activeMetric = v40 ?? v31 ?? v30;
        const cvssData = activeMetric?.cvssData as Record<string, unknown> | undefined;

        const baseScore = cvssData?.baseScore !== undefined ? String(cvssData.baseScore) : '';
        const severity = typeof (cvssData?.baseSeverity ?? activeMetric?.baseSeverity) === 'string'
          ? String(cvssData?.baseSeverity ?? activeMetric?.baseSeverity)
          : '';
        const vector = typeof cvssData?.vectorString === 'string' ? cvssData.vectorString : '';

        const weaknesses = Array.isArray(cve.weaknesses) ? (cve.weaknesses as Array<Record<string, unknown>>) : [];
        const cwes: string[] = [];
        for (const w of weaknesses) {
          const wDescs = Array.isArray(w.description) ? (w.description as Array<Record<string, unknown>>) : [];
          for (const wd of wDescs) {
            const v = typeof wd.value === 'string' ? wd.value.trim() : '';
            if (v && v !== 'NVD-CWE-noinfo' && !cwes.includes(v)) cwes.push(v);
          }
        }

        const published = typeof cve.published === 'string' ? cve.published : '';
        const vulnStatus = typeof cve.vulnStatus === 'string' ? cve.vulnStatus : '';
        const cisaExploit = typeof cve.cisaExploitAdd === 'string' ? cve.cisaExploitAdd : '';

        const bullets: string[] = [];
        if (baseScore) bullets.push(`- **CVSS Score**: **${baseScore}**${severity ? ` (${severity})` : ''}${vector ? ` — \`${vector}\`` : ''}`);
        if (vulnStatus) bullets.push(`- **Status**: ${vulnStatus}`);
        if (published) bullets.push(`- **Published**: ${published.slice(0, 10)}`);
        if (cwes.length > 0) bullets.push(`- **Weaknesses (CWE)**: ${cwes.join(', ')}`);
        if (cisaExploit) bullets.push(`- **CISA KEV (Known Exploited)**: Added ${cisaExploit}`);

        const refs = Array.isArray(cve.references) ? (cve.references as Array<Record<string, unknown>>) : [];
        const refRows: Array<Array<string>> = [];
        const links: string[] = [];
        for (const r of refs.slice(0, 15)) {
          const rUrl = typeof r.url === 'string' ? r.url : '';
          if (!rUrl.startsWith('https://')) continue;
          links.push(rUrl);
          const rTags = Array.isArray(r.tags) ? r.tags.map(String).join(', ') : '-';
          refRows.push([rUrl, rTags]);
        }

        const title = severity ? `${cve.id} (${severity}${baseScore ? ` ${baseScore}` : ''})` : cve.id;
        const sections: string[] = [`# ${title}`];
        if (bullets.length > 0) sections.push(bullets.join('\n'));
        if (descStr) sections.push(`## Summary\n\n${descStr}`);
        if (refRows.length > 0) {
          sections.push(`## References & Advisories\n\n${formatGfmTable(['URL', 'Tags'], refRows)}`);
        }

        return {
          title,
          ...(descStr ? { description: descStr.slice(0, 260) } : {}),
          ...(published ? { publishedTime: published } : {}),
          markdown: sections.join('\n\n'),
          links,
        };
      },
    };
  },
});
