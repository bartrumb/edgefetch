import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'crates-io',
  name: 'Rust Crates.io',
  category: 'developer',
  description: 'Upgrades crates.io pages to the v1 JSON API with Cargo install command, MSRV, Cargo features, downloads, and release history.',
  domains: ['crates.io', 'www.crates.io'],
  exampleUrls: ['https://crates.io/crates/serde'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'crates' || parts.length < 2) return null;
    const crateName = decodeURIComponent(parts[1]!);
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(crateName)) return null;
    return {
      id: 'crates-io',
      fetchUrl: `https://crates.io/api/v1/crates/${encodeURIComponent(crateName)}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const crate = data?.crate as Record<string, unknown> | undefined;
        if (!crate || typeof crate.name !== 'string') return null;
        const versions = Array.isArray(data?.versions) ? (data.versions as Array<Record<string, unknown>>) : [];
        const latestVerObj = versions[0] ?? {};
        const ver = String(crate.max_stable_version || crate.max_version || latestVerObj.num || '');
        const desc = typeof crate.description === 'string' ? crate.description.trim() : '';
        const license = typeof latestVerObj.license === 'string' ? latestVerObj.license : '';
        const msrv = typeof latestVerObj.rust_version === 'string' ? latestVerObj.rust_version : '';
        const repo = typeof crate.repository === 'string' ? crate.repository : '';
        const docs = typeof crate.documentation === 'string' && crate.documentation ? crate.documentation : `https://docs.rs/${crate.name}`;
        const downloads = typeof crate.downloads === 'number' ? crate.downloads.toLocaleString('en-US') : '';
        const featuresObj = latestVerObj.features && typeof latestVerObj.features === 'object' ? Object.keys(latestVerObj.features as object) : [];
        const categories = Array.isArray(data?.categories)
          ? (data.categories as Array<Record<string, unknown>>).map((c) => String(c.category ?? '')).filter(Boolean)
          : [];
        const keywords = Array.isArray(data?.keywords)
          ? (data.keywords as Array<Record<string, unknown>>).map((k) => String(k.keyword ?? '')).filter(Boolean)
          : [];

        const title = ver ? `${crate.name} v${ver} (Rust Crate)` : `${crate.name} (Rust Crate)`;
        const bullets: string[] = [`- **Cargo**: \`cargo add ${crate.name}\``];
        if (ver) bullets.push(`- **Version**: \`${ver}\``);
        if (msrv) bullets.push(`- **MSRV**: Rust \`${msrv}\``);
        if (license) bullets.push(`- **License**: ${license}`);
        if (downloads) bullets.push(`- **Downloads**: ${downloads}`);
        bullets.push(`- **API Docs**: ${docs}`);
        if (repo) bullets.push(`- **Repository**: ${repo}`);
        if (featuresObj.length > 0) bullets.push(`- **Cargo Features**: \`${featuresObj.slice(0, 14).join('`, `')}\``);
        if (categories.length > 0) bullets.push(`- **Categories**: ${categories.join(', ')}`);
        if (keywords.length > 0) bullets.push(`- **Keywords**: ${keywords.join(', ')}`);

        const links = [docs, ...(repo.startsWith('https://') ? [repo] : [])];
        const sections = [`# ${title}`];
        if (desc) sections.push(desc);
        sections.push(bullets.join('\n'));
        if (versions.length > 1) {
          const recent = versions
            .slice(0, 6)
            .map((v) => `| \`${String(v.num ?? '')}\` | ${String(v.created_at ?? '').slice(0, 10)} | ${String(v.rust_version ?? '-')} |`)
            .join('\n');
          sections.push(`## Recent Releases\n\n| Version | Published | MSRV |\n| --- | --- | --- |\n${recent}`);
        }
        return { title, ...(desc ? { description: desc } : {}), markdown: sections.join('\n\n'), links };
      },
    };
  },
});
