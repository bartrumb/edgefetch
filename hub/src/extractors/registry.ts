/**
 * Modular Site Extractor Registry (`SCRAPE_PIPELINE_VERSION = 20`).
 *
 * Architecture (inspired by `kepano/defuddle`, `postlight/parser`, and `idosal/git-mcp`):
 *  1. `resolveSiteExtractorTwin(url)`: Pre-fetch 1-hop upgrades to official public JSON / raw Markdown / patch twins
 *     (`npmjs.com` -> `registry.npmjs.org`, `crates.io` -> `/api/v1/crates`, `huggingface.co` -> `/raw/.../README.md`,
 *     `gitlab.com` / `codeberg.org` -> raw & `.patch`, Discourse `/t/<slug>/<id>.json`, `lobste.rs` `.json`,
 *     Bluesky ATProto `public.api.bsky.app`, Mastodon `/api/v1/statuses/<id>`, `dev.to/api/articles`,
 *     `rubygems.org`, `packagist.org`, `hex.pm`). Every twin request still flows through `executeHubFetch`, so
 *     `robots.txt`, dial-time SSRF protection, per-host politeness, and OTLP tracing remain strictly enforced.
 *  2. `applyPostFetchSiteExtractor(...)`: Targeted DOM / post-Markdown extractors for structured HTML platforms
 *     (Stack Overflow & Stack Exchange Q&A, `pkg.go.dev`, `pypi.org`, `jsr.io`, `gist.github.com`, `reddit.com` /
 *     `old.reddit.com`, Wikipedia / MediaWiki, IETF RFCs on `datatracker.ietf.org` & `rfc-editor.org`, and PubMed / PMC).
 */

export interface TwinFormattedDoc {
  title: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
}

export interface HtmlFragmentConverter {
  (htmlFragment: string, baseUrl?: string): {
    markdown: string;
    links: string[];
  };
}

export interface SiteExtractorTwin {
  id: string;
  fetchUrl: string;
  kind: 'json' | 'text';
  accept: string;
  formatTwin: (rawBody: string, originalUrl: string, htmlToMd: HtmlFragmentConverter) => TwinFormattedDoc | null;
}

export interface PostFetchSiteResult {
  extractorId: string;
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
}

const CODE_EXT_FENCE_MAP: Record<string, string> = {
  ts: 'ts',
  tsx: 'tsx',
  js: 'js',
  jsx: 'jsx',
  mjs: 'js',
  cjs: 'js',
  py: 'python',
  go: 'go',
  rs: 'rust',
  rb: 'ruby',
  java: 'java',
  kt: 'kotlin',
  swift: 'swift',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  hpp: 'cpp',
  cs: 'csharp',
  php: 'php',
  sh: 'bash',
  bash: 'bash',
  zsh: 'zsh',
  ps1: 'powershell',
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'toml',
  json: 'json',
  sql: 'sql',
  graphql: 'graphql',
  proto: 'protobuf',
  tf: 'hcl',
  hcl: 'hcl',
  nix: 'nix',
  zig: 'zig',
  lua: 'lua',
  ex: 'elixir',
  exs: 'elixir',
  erl: 'erlang',
  css: 'css',
  scss: 'scss',
  html: 'html',
  xml: 'xml',
};

function safeFence(code: string, lang = ''): string {
  let maxTicks = 2;
  for (const m of code.matchAll(/`{3,}/g)) {
    if (m[0].length > maxTicks) maxTicks = m[0].length;
  }
  const fence = '`'.repeat(maxTicks + 1);
  return `${fence}${lang}\n${code.replace(/\r\n/g, '\n').trimEnd()}\n${fence}`;
}

function decodeBasicEntities(s: string): string {
  return s
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex: string) => {
      const cp = parseInt(hex, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : _m;
    })
    .replace(/&#(\d+);/g, (_m, dec: string) => {
      const cp = parseInt(dec, 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : _m;
    });
}

function stripTagsInline(html: string): string {
  return decodeBasicEntities(html.replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

function detectFenceLang(filePath: string): { lang: string; isMarkdown: boolean } {
  const base = (filePath.split('/').pop() ?? filePath).toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.')) return { lang: 'dockerfile', isMarkdown: false };
  if (base === 'makefile' || base === 'gnumakefile') return { lang: 'makefile', isMarkdown: false };
  const ext = /\.([a-z0-9]+)$/i.exec(base)?.[1] ?? '';
  if (ext === 'md' || ext === 'mdx' || ext === 'markdown') return { lang: 'markdown', isMarkdown: true };
  return { lang: CODE_EXT_FENCE_MAP[ext] ?? ext, isMarkdown: false };
}

function parseJsonObject(raw: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(raw.replace(/^\ufeff/, ''));
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Parses YAML model/dataset card frontmatter (e.g. Hugging Face `README.md`) into a GFM metadata table + clean Markdown body. */
export function formatYamlFrontmatterCard(rawMd: string, fallbackTitle: string): {
  title: string;
  description?: string;
  markdown: string;
} {
  const normalized = rawMd.replace(/\r\n/g, '\n');
  const fmMatch = /^---\n([\s\S]{1,8000}?)\n---\n+([\s\S]*)$/.exec(normalized);
  if (!fmMatch) {
    const h1 = /^#\s+(.+)$/m.exec(normalized)?.[1]?.trim();
    const title = h1 || fallbackTitle;
    const md = normalized.trimStart().startsWith('# ') ? normalized.trim() : `# ${title}\n\n${normalized.trim()}`;
    return { title, markdown: md };
  }

  const yamlBlock = fmMatch[1]!;
  const body = fmMatch[2]!.trim();
  const kvPairs: Array<[string, string]> = [];
  let currentKey = '';
  let listItems: string[] = [];

  const flushList = () => {
    if (currentKey && listItems.length > 0) {
      kvPairs.push([currentKey, listItems.slice(0, 12).join(', ')]);
    }
    currentKey = '';
    listItems = [];
  };

  for (const line of yamlBlock.split('\n')) {
    const listMatch = /^\s*-\s+(.+)$/.exec(line);
    if (listMatch && currentKey) {
      const item = listMatch[1]!.replace(/^["']|["']$/g, '').trim();
      if (item && !item.includes(':')) listItems.push(item);
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (kv) {
      flushList();
      const k = kv[1]!;
      const v = kv[2]!.replace(/^["']|["']$/g, '').trim();
      if (!v) {
        currentKey = k;
      } else if (v.length <= 140 && !v.startsWith('{')) {
        kvPairs.push([k, v]);
      }
    }
  }
  flushList();

  const h1 = /^#\s+(.+)$/m.exec(body)?.[1]?.trim();
  const fmTitle = kvPairs.find(([k]) => k === 'pretty_name' || k === 'title')?.[1];
  const title = h1 || fmTitle || fallbackTitle;
  const keepKeys = new Set([
    'license',
    'pipeline_tag',
    'library_name',
    'base_model',
    'language',
    'tags',
    'datasets',
    'sdk',
    ' task_categories',
    'task_categories',
    'size_categories',
  ]);
  const selected = kvPairs.filter(([k]) => keepKeys.has(k)).slice(0, 10);
  const tableLines =
    selected.length > 0
      ? [
          '| Property | Value |',
          '| --- | --- |',
          ...selected.map(([k, v]) => `| **${k}** | ${v.replace(/\|/g, '\\|')} |`),
        ].join('\n')
      : '';

  const parts: string[] = [];
  if (!body.startsWith('# ')) parts.push(`# ${title}`);
  if (tableLines) parts.push(tableLines);
  if (body) parts.push(body);

  const desc = kvPairs.find(([k]) => k === 'description' || k === 'summary')?.[1];
  return {
    title,
    ...(desc ? { description: desc } : {}),
    markdown: parts.join('\n\n').trim(),
  };
}

/**
 * Resolves a pre-fetch 1-hop JSON / raw / patch twin endpoint when a URL belongs to a supported registry, forge,
 * forum, or social protocol. Returns `null` when standard HTML fetching should proceed.
 */
export function resolveSiteExtractorTwin(urlStr: string): SiteExtractorTwin | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  const parts = u.pathname.split('/').filter(Boolean);

  // 1. npm (`npmjs.com/package/<pkg>` or `/package/@scope/<pkg>[/v/<ver>]`) -> `registry.npmjs.org/<pkg>`
  if ((host === 'www.npmjs.com' || host === 'npmjs.com') && parts[0] === 'package' && parts.length >= 2) {
    let pkgName = '';
    let requestedVer = '';
    if (parts[1]!.startsWith('@') && parts.length >= 3) {
      pkgName = `${decodeURIComponent(parts[1]!)}/${decodeURIComponent(parts[2]!)}`;
      if (parts[3] === 'v' && parts[4]) requestedVer = decodeURIComponent(parts[4]);
    } else {
      pkgName = decodeURIComponent(parts[1]!);
      if (parts[2] === 'v' && parts[3]) requestedVer = decodeURIComponent(parts[3]);
    }
    if (/^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i.test(pkgName)) {
      const encodedPkg = pkgName.startsWith('@')
        ? `@${encodeURIComponent(pkgName.slice(1).split('/')[0]!)}%2F${encodeURIComponent(pkgName.split('/')[1]!)}`
        : encodeURIComponent(pkgName);
      return {
        id: 'npm-registry',
        fetchUrl: `https://registry.npmjs.org/${encodedPkg}`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          if (!data || typeof data.name !== 'string') return null;
          const distTags = (data['dist-tags'] as Record<string, string> | undefined) ?? {};
          const ver = requestedVer || distTags.latest || '';
          const versions = (data.versions as Record<string, Record<string, unknown>> | undefined) ?? {};
          const verObj = (ver && versions[ver]) || {};
          const desc = typeof (verObj.description ?? data.description) === 'string' ? String(verObj.description ?? data.description).trim() : '';
          const license = typeof (verObj.license ?? data.license) === 'string' ? String(verObj.license ?? data.license) : '';
          const homepage = typeof (verObj.homepage ?? data.homepage) === 'string' ? String(verObj.homepage ?? data.homepage) : '';
          const repoObj = (verObj.repository ?? data.repository) as { url?: string } | string | undefined;
          const repoRaw = typeof repoObj === 'string' ? repoObj : typeof repoObj?.url === 'string' ? repoObj.url : '';
          const repoClean = repoRaw.replace(/^git\+/, '').replace(/\.git$/, '');
          const hasTypes = Boolean(verObj.types || verObj.typings || String(verObj.exports ?? '').includes('types'));
          const deps = verObj.dependencies && typeof verObj.dependencies === 'object' ? Object.keys(verObj.dependencies as object) : [];
          const readme = typeof data.readme === 'string' && data.readme !== 'ERROR: No README data found!' ? data.readme.trim() : '';

          const title = ver ? `${data.name}@${ver}` : data.name;
          const bullets: string[] = [`- **Install**: \`npm install ${data.name}\``];
          if (ver) bullets.push(`- **Latest Version**: \`${ver}\``);
          if (license) bullets.push(`- **License**: ${license}`);
          if (hasTypes) bullets.push(`- **TypeScript**: Bundled declarations included`);
          if (deps.length >= 0) bullets.push(`- **Runtime Dependencies**: ${deps.length}${deps.length > 0 ? ` (${deps.slice(0, 10).join(', ')}${deps.length > 10 ? ', ...' : ''})` : ' (zero dependencies)'}`);
          if (homepage) bullets.push(`- **Homepage**: ${homepage}`);
          if (repoClean.startsWith('http')) bullets.push(`- **Repository**: ${repoClean}`);

          const sections = [`# ${title}`];
          if (desc) sections.push(desc);
          sections.push(bullets.join('\n'));
          if (readme) {
            sections.push(readme.replace(/^#\s+.+\n+/, '').trim() || readme);
          }
          return { title, ...(desc ? { description: desc } : {}), markdown: sections.join('\n\n') };
        },
      };
    }
  }

  // 2. Rust Crates (`crates.io/crates/<crate>[/<ver>]`) -> `crates.io/api/v1/crates/<crate>`
  if ((host === 'crates.io' || host === 'www.crates.io') && parts[0] === 'crates' && parts.length >= 2) {
    const crateName = decodeURIComponent(parts[1]!);
    if (/^[A-Za-z0-9_-]{1,64}$/.test(crateName)) {
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
    }
  }

  // 3. RubyGems (`rubygems.org/gems/<gem>`) -> `rubygems.org/api/v1/gems/<gem>.json`
  if ((host === 'rubygems.org' || host === 'www.rubygems.org') && parts[0] === 'gems' && parts.length >= 2) {
    const gem = decodeURIComponent(parts[1]!);
    if (/^[A-Za-z0-9_.-]{1,80}$/.test(gem)) {
      return {
        id: 'rubygems',
        fetchUrl: `https://rubygems.org/api/v1/gems/${encodeURIComponent(gem)}.json`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          if (!data || typeof data.name !== 'string') return null;
          const ver = typeof data.version === 'string' ? data.version : '';
          const info = typeof data.info === 'string' ? data.info.trim() : '';
          const licenses = Array.isArray(data.licenses) ? data.licenses.join(', ') : '';
          const authors = typeof data.authors === 'string' ? data.authors : '';
          const repo = typeof data.source_code_uri === 'string' ? data.source_code_uri : typeof data.homepage_uri === 'string' ? data.homepage_uri : '';
          const docs = typeof data.documentation_uri === 'string' ? data.documentation_uri : '';
          const title = ver ? `${data.name} ${ver} (RubyGem)` : `${data.name} (RubyGem)`;
          const bullets = [`- **Install**: \`gem install ${data.name}\``];
          if (ver) bullets.push(`- **Version**: \`${ver}\``);
          if (licenses) bullets.push(`- **License**: ${licenses}`);
          if (authors) bullets.push(`- **Authors**: ${authors}`);
          if (docs) bullets.push(`- **Documentation**: ${docs}`);
          if (repo) bullets.push(`- **Repository**: ${repo}`);
          return {
            title,
            ...(info ? { description: info.slice(0, 260) } : {}),
            ...(authors ? { author: authors } : {}),
            markdown: [`# ${title}`, ...(info ? [info] : []), bullets.join('\n')].join('\n\n'),
          };
        },
      };
    }
  }

  // 4. Packagist (`packagist.org/packages/<vendor>/<pkg>`) -> `packagist.org/packages/<vendor>/<pkg>.json`
  if ((host === 'packagist.org' || host === 'www.packagist.org') && parts[0] === 'packages' && parts.length === 3) {
    const vendor = parts[1]!;
    const pkg = parts[2]!;
    if (/^[A-Za-z0-9_.-]+$/.test(vendor) && /^[A-Za-z0-9_.-]+$/.test(pkg)) {
      return {
        id: 'packagist',
        fetchUrl: `https://packagist.org/packages/${vendor}/${pkg}.json`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const pkgObj = data?.package as Record<string, unknown> | undefined;
          if (!pkgObj || typeof pkgObj.name !== 'string') return null;
          const desc = typeof pkgObj.description === 'string' ? pkgObj.description.trim() : '';
          const repo = typeof pkgObj.repository === 'string' ? pkgObj.repository : '';
          const versionsObj = (pkgObj.versions as Record<string, Record<string, unknown>> | undefined) ?? {};
          const stableVer = Object.keys(versionsObj).find((v) => !v.includes('dev')) ?? Object.keys(versionsObj)[0] ?? '';
          const verMeta = (stableVer && versionsObj[stableVer]) || {};
          const license = Array.isArray(verMeta.license) ? verMeta.license.join(', ') : '';
          const title = stableVer ? `${pkgObj.name} ${stableVer} (Composer)` : pkgObj.name;
          const bullets = [`- **Install**: \`composer require ${pkgObj.name}\``];
          if (stableVer) bullets.push(`- **Latest Version**: \`${stableVer}\``);
          if (license) bullets.push(`- **License**: ${license}`);
          if (repo) bullets.push(`- **Repository**: ${repo}`);
          return {
            title,
            ...(desc ? { description: desc } : {}),
            markdown: [`# ${title}`, ...(desc ? [desc] : []), bullets.join('\n')].join('\n\n'),
          };
        },
      };
    }
  }

  // 5. Hex.pm (`hex.pm/packages/<pkg>`) -> `hex.pm/api/packages/<pkg>`
  if ((host === 'hex.pm' || host === 'www.hex.pm') && parts[0] === 'packages' && parts.length === 2) {
    const pkg = parts[1]!;
    if (/^[A-Za-z0-9_-]+$/.test(pkg)) {
      return {
        id: 'hex-pm',
        fetchUrl: `https://hex.pm/api/packages/${encodeURIComponent(pkg)}`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          if (!data || typeof data.name !== 'string') return null;
          const meta = (data.meta as Record<string, unknown> | undefined) ?? {};
          const desc = typeof meta.description === 'string' ? meta.description.trim() : '';
          const licenses = Array.isArray(meta.licenses) ? meta.licenses.join(', ') : '';
          const linksObj = (meta.links as Record<string, string> | undefined) ?? {};
          const releases = Array.isArray(data.releases) ? (data.releases as Array<Record<string, unknown>>) : [];
          const ver = typeof releases[0]?.version === 'string' ? String(releases[0].version) : '';
          const docsUrl = typeof data.docs_html_url === 'string' ? data.docs_html_url : `https://hexdocs.pm/${data.name}`;
          const title = ver ? `${data.name} ${ver} (Hex)` : `${data.name} (Hex)`;
          const bullets = [`- **Mix**: \`{:${data.name}, "~> ${ver || '0.1'}"}\``, `- **HexDocs**: ${docsUrl}`];
          if (licenses) bullets.push(`- **License**: ${licenses}`);
          for (const [label, href] of Object.entries(linksObj)) {
            if (typeof href === 'string' && href.startsWith('https://')) bullets.push(`- **${label}**: ${href}`);
          }
          return {
            title,
            ...(desc ? { description: desc } : {}),
            markdown: [`# ${title}`, ...(desc ? [desc] : []), bullets.join('\n')].join('\n\n'),
          };
        },
      };
    }
  }

  // 6. Hugging Face (`huggingface.co/[datasets|spaces/]<org>/<repo>[/blob/<rev>/<path>]`) -> `/raw/...`
  if (host === 'huggingface.co' || host === 'www.huggingface.co') {
    const reserved = new Set(['models', 'datasets', 'spaces', 'docs', 'blog', 'papers', 'posts', 'tasks', 'organizations', 'settings', 'login', 'join', 'pricing']);
    const isTyped = (parts[0] === 'datasets' || parts[0] === 'spaces') && parts.length >= 3;
    const prefixCount = isTyped ? 3 : 2;
    if ((isTyped || (parts.length >= 2 && !reserved.has(parts[0]!.toLowerCase())))) {
      const repoPrefix = parts.slice(0, prefixCount).join('/');
      const rest = parts.slice(prefixCount);
      if (rest.length === 0 || (rest.length === 2 && rest[0] === 'tree')) {
        const rev = rest[1] || 'main';
        return {
          id: 'huggingface-card',
          fetchUrl: `https://huggingface.co/${repoPrefix}/raw/${encodeURIComponent(rev)}/README.md`,
          kind: 'text',
          accept: 'text/markdown, text/plain;q=0.9',
          formatTwin: (rawBody) => {
            if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
            return formatYamlFrontmatterCard(rawBody, repoPrefix);
          },
        };
      }
      if (rest.length >= 3 && rest[0] === 'blob') {
        const rev = rest[1]!;
        const filePath = rest.slice(2).join('/');
        const { lang, isMarkdown } = detectFenceLang(filePath);
        return {
          id: 'huggingface-blob',
          fetchUrl: `https://huggingface.co/${repoPrefix}/raw/${encodeURIComponent(rev)}/${filePath}`,
          kind: 'text',
          accept: 'text/plain',
          formatTwin: (rawBody) => {
            if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
            const title = `${repoPrefix}/${filePath}`;
            if (isMarkdown) return formatYamlFrontmatterCard(rawBody, title);
            return { title, markdown: `# ${title}\n\n${safeFence(rawBody, lang)}` };
          },
        };
      }
    }
  }

  // 7. GitLab (`gitlab.com/<group>/<project>/-/blob/<ref>/<path>` & `/-/commit/<sha>`)
  if (host === 'gitlab.com' || host.startsWith('gitlab.')) {
    const dashIdx = parts.indexOf('-');
    if (dashIdx >= 2 && parts[dashIdx + 1] === 'blob' && parts.length >= dashIdx + 4) {
      const nsProj = parts.slice(0, dashIdx).join('/');
      const rawTail = parts.slice(dashIdx + 2).join('/');
      const filePath = parts.slice(dashIdx + 3).join('/');
      const { lang, isMarkdown } = detectFenceLang(filePath);
      return {
        id: 'gitlab-raw',
        fetchUrl: `https://${host}/${nsProj}/-/raw/${rawTail}`,
        kind: 'text',
        accept: 'text/plain',
        formatTwin: (rawBody) => {
          if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
          const title = `${nsProj}/${filePath}`;
          return {
            title,
            markdown: isMarkdown ? rawBody.trim() : `# ${title}\n\n${safeFence(rawBody, lang)}`,
          };
        },
      };
    }
    if (dashIdx >= 2 && parts[dashIdx + 1] === 'commit' && parts[dashIdx + 2] && /^[0-9a-f]{7,40}$/i.test(parts[dashIdx + 2]!)) {
      const nsProj = parts.slice(0, dashIdx).join('/');
      const sha = parts[dashIdx + 2]!;
      return {
        id: 'gitlab-commit-patch',
        fetchUrl: `https://${host}/${nsProj}/-/commit/${sha}.patch`,
        kind: 'text',
        accept: 'text/plain',
        formatTwin: (rawBody) => {
          if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
          const title = `${nsProj}@${sha.slice(0, 10)}`;
          return { title, markdown: `# ${title}\n\n${safeFence(rawBody, 'diff')}` };
        },
      };
    }
  }

  // 8. Codeberg / Forgejo / Gitea (`codeberg.org/<owner>/<repo>/src/branch/<ref>/<path>` & `/commit/<sha>`)
  if (host === 'codeberg.org' || host === 'gitea.com') {
    if (parts.length >= 6 && parts[2] === 'src' && (parts[3] === 'branch' || parts[3] === 'tag' || parts[3] === 'commit')) {
      const slug = `${parts[0]}/${parts[1]}`;
      const refType = parts[3]!;
      const refAndPath = parts.slice(4).join('/');
      const filePath = parts.slice(5).join('/');
      const { lang, isMarkdown } = detectFenceLang(filePath);
      return {
        id: 'forgejo-raw',
        fetchUrl: `https://${host}/${slug}/raw/${refType}/${refAndPath}`,
        kind: 'text',
        accept: 'text/plain',
        formatTwin: (rawBody) => {
          if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
          const title = `${slug}/${filePath}`;
          return {
            title,
            markdown: isMarkdown ? rawBody.trim() : `# ${title}\n\n${safeFence(rawBody, lang)}`,
          };
        },
      };
    }
    if (parts.length === 4 && parts[2] === 'commit' && /^[0-9a-f]{7,40}$/i.test(parts[3]!)) {
      const slug = `${parts[0]}/${parts[1]}`;
      const sha = parts[3]!;
      return {
        id: 'forgejo-commit-patch',
        fetchUrl: `https://${host}/${slug}/commit/${sha}.patch`,
        kind: 'text',
        accept: 'text/plain',
        formatTwin: (rawBody) => {
          if (!rawBody.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(rawBody)) return null;
          const title = `${slug}@${sha.slice(0, 10)}`;
          return { title, markdown: `# ${title}\n\n${safeFence(rawBody, 'diff')}` };
        },
      };
    }
  }

  // 9. Universal Discourse Topic JSON (`/t/<slug>/<topicId>[/<postNum>]`)
  // Matches `discuss.*`, `forum.*`, `community.*`, `users.rust-lang.org`, `meta.discourse.org`, etc.
  if (parts[0] === 't' && parts.length >= 3 && /^\d+$/.test(parts[2]!)) {
    const slug = parts[1]!;
    const topicId = parts[2]!;
    return {
      id: 'discourse-topic',
      fetchUrl: `https://${host}/t/${slug}/${topicId}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, _origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const postStream = data?.post_stream as { posts?: Array<Record<string, unknown>> } | undefined;
        const posts = Array.isArray(postStream?.posts) ? postStream.posts : [];
        if (posts.length === 0 || typeof data?.title !== 'string') return null;

        const title = data.title.trim();
        const tags = Array.isArray(data.tags) ? data.tags.map(String).filter(Boolean) : [];
        const acceptedObj = data.accepted_answer as { post_number?: number; username?: string; excerpt?: string } | undefined;
        const acceptedPostNum = typeof acceptedObj?.post_number === 'number' ? acceptedObj.post_number : -1;

        const sections: string[] = [`# ${title}`];
        if (tags.length > 0) sections.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);

        const allLinks: string[] = [];
        for (const p of posts.slice(0, 20)) {
          const postNum = typeof p.post_number === 'number' ? p.post_number : 0;
          const user = typeof p.username === 'string' ? `@${p.username}` : 'user';
          const created = typeof p.created_at === 'string' ? p.created_at.slice(0, 10) : '';
          const cooked = typeof p.cooked === 'string' ? p.cooked : '';
          if (!cooked.trim()) continue;
          const converted = htmlToMd(cooked, `https://${host}/t/${slug}/${topicId}`);
          for (const l of converted.links) {
            if (!allLinks.includes(l) && allLinks.length < 100) allLinks.push(l);
          }
          const badge = postNum === 1 ? 'Original Post' : postNum === acceptedPostNum ? '✅ Accepted Solution' : `Reply #${postNum}`;
          sections.push(`## ${badge} — ${user}${created ? ` (${created})` : ''}\n\n${converted.markdown.trim()}`);
        }
        const firstAuthor = typeof posts[0]?.username === 'string' ? String(posts[0].username) : undefined;
        const firstCreated = typeof posts[0]?.created_at === 'string' ? String(posts[0].created_at) : undefined;
        return {
          title,
          ...(firstAuthor ? { author: firstAuthor } : {}),
          ...(firstCreated ? { publishedTime: firstCreated } : {}),
          markdown: sections.join('\n\n'),
          links: allLinks,
        };
      },
    };
  }

  // 10. Lobsters (`lobste.rs/s/<id>[/<slug>]`) -> `lobste.rs/s/<id>.json`
  if (host === 'lobste.rs' && parts[0] === 's' && parts[1] && /^[A-Za-z0-9]{4,12}$/.test(parts[1])) {
    const shortId = parts[1];
    return {
      id: 'lobsters',
      fetchUrl: `https://lobste.rs/s/${shortId}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.title !== 'string') return null;
        const title = data.title.trim();
        const storyUrl = typeof data.url === 'string' && data.url ? data.url : '';
        const score = typeof data.score === 'number' ? data.score : 0;
        const user = typeof data.submitter_user === 'string' ? data.submitter_user : '';
        const created = typeof data.created_at === 'string' ? data.created_at : '';
        const tags = Array.isArray(data.tags) ? data.tags.map(String) : [];
        const descPlain = typeof data.description_plain === 'string' ? data.description_plain.trim() : '';
        const comments = Array.isArray(data.comments) ? (data.comments as Array<Record<string, unknown>>) : [];

        const metaParts = [`**Score**: ${score}`];
        if (user) metaParts.push(`**By**: @${user}`);
        if (tags.length > 0) metaParts.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);
        if (storyUrl) metaParts.push(`**Link**: ${storyUrl}`);

        const sections: string[] = [`# ${title}`, metaParts.join(' · ')];
        if (descPlain) sections.push(descPlain);

        if (comments.length > 0) {
          const commentLines: string[] = ['## Comments'];
          for (const c of comments.slice(0, 40)) {
            const cUser = typeof c.commenting_user === 'string' ? c.commenting_user : 'user';
            const cScore = typeof c.score === 'number' ? c.score : 0;
            const depth = typeof c.indent_level === 'number' ? Math.max(0, Math.min(6, c.indent_level - 1)) : 0;
            const indent = '  '.repeat(depth);
            const body = typeof c.comment_plain === 'string' ? c.comment_plain.trim().replace(/\n+/g, `\n${indent}  `) : '';
            if (body) commentLines.push(`${indent}- **@${cUser}** (${cScore} pts): ${body}`);
          }
          sections.push(commentLines.join('\n'));
        }

        return {
          title,
          ...(user ? { author: user } : {}),
          ...(created ? { publishedTime: created } : {}),
          markdown: sections.join('\n\n'),
          ...(storyUrl.startsWith('https://') ? { links: [storyUrl] } : {}),
        };
      },
    };
  }

  // 11. Bluesky (`bsky.app/profile/<actor>/post/<rkey>`) -> ATProto `public.api.bsky.app`
  if ((host === 'bsky.app' || host === 'staging.bsky.app') && parts[0] === 'profile' && parts[2] === 'post' && parts.length >= 4) {
    const actor = decodeURIComponent(parts[1]!);
    const rkey = decodeURIComponent(parts[3]!);
    if (/^[A-Za-z0-9._:-]+$/.test(actor) && /^[A-Za-z0-9._-]+$/.test(rkey)) {
      const atUri = `at://${actor}/app.bsky.feed.post/${rkey}`;
      return {
        id: 'bluesky-thread',
        fetchUrl: `https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(atUri)}&depth=6`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          const thread = data?.thread as Record<string, unknown> | undefined;
          const post = thread?.post as Record<string, unknown> | undefined;
          const record = post?.record as Record<string, unknown> | undefined;
          const authorObj = post?.author as Record<string, unknown> | undefined;
          if (!post || !record || typeof record.text !== 'string') return null;

          const handle = typeof authorObj?.handle === 'string' ? authorObj.handle : actor;
          const displayName = typeof authorObj?.displayName === 'string' && authorObj.displayName ? authorObj.displayName : handle;
          const createdAt = typeof record.createdAt === 'string' ? record.createdAt : '';
          const likes = typeof post.likeCount === 'number' ? post.likeCount : 0;
          const reposts = typeof post.repostCount === 'number' ? post.repostCount : 0;
          const title = `${displayName} (@${handle}) on Bluesky`;

          const embed = post.embed as Record<string, unknown> | undefined;
          const ext = embed?.external as Record<string, unknown> | undefined;
          const images = Array.isArray(embed?.images) ? (embed.images as Array<Record<string, unknown>>) : [];

          const sections: string[] = [
            `# ${title}`,
            record.text.trim(),
            `*Posted ${createdAt ? createdAt.slice(0, 16).replace('T', ' ') + ' UTC · ' : ''}${likes} likes · ${reposts} reposts*`,
          ];
          if (ext && typeof ext.uri === 'string') {
            sections.push(`> **Linked**: [${String(ext.title || ext.uri)}](${ext.uri})${ext.description ? ` — ${String(ext.description)}` : ''}`);
          }
          for (const img of images) {
            if (typeof img.alt === 'string' && img.alt.trim()) {
              sections.push(`- *Image alt*: ${img.alt.trim()}`);
            }
          }

          const replies = Array.isArray(thread?.replies) ? (thread.replies as Array<Record<string, unknown>>) : [];
          const replyLines: string[] = [];
          for (const rep of replies.slice(0, 15)) {
            const rp = rep.post as Record<string, unknown> | undefined;
            const rr = rp?.record as Record<string, unknown> | undefined;
            const ra = rp?.author as Record<string, unknown> | undefined;
            if (rr && typeof rr.text === 'string' && rr.text.trim()) {
              const rHandle = typeof ra?.handle === 'string' ? ra.handle : 'user';
              replyLines.push(`- **@${rHandle}**: ${rr.text.trim().replace(/\n+/g, ' ')}`);
            }
          }
          if (replyLines.length > 0) sections.push(`## Replies\n\n${replyLines.join('\n')}`);

          return {
            title,
            description: record.text.trim().slice(0, 220),
            author: `@${handle}`,
            ...(createdAt ? { publishedTime: createdAt } : {}),
            markdown: sections.join('\n\n'),
          };
        },
      };
    }
  }

  // 12. DEV.to (`dev.to/<user>/<slug>`) -> `dev.to/api/articles/<user>/<slug>` (`body_markdown`)
  if ((host === 'dev.to' || host === 'www.dev.to') && parts.length === 2) {
    const reservedDev = new Set(['t', 'top', 'latest', 'pod', 'videos', 'tags', 'search', 'settings', 'enter', 'new', 'about', 'privacy', 'terms']);
    if (!reservedDev.has(parts[0]!.toLowerCase()) && /^[A-Za-z0-9_-]+$/.test(parts[0]!) && /^[A-Za-z0-9_-]+$/.test(parts[1]!)) {
      return {
        id: 'dev-to',
        fetchUrl: `https://dev.to/api/articles/${parts[0]}/${parts[1]}`,
        kind: 'json',
        accept: 'application/json',
        formatTwin: (rawBody) => {
          const data = parseJsonObject(rawBody);
          if (!data || typeof data.title !== 'string' || typeof data.body_markdown !== 'string') return null;
          const title = data.title.trim();
          const desc = typeof data.description === 'string' ? data.description.trim() : undefined;
          const userObj = data.user as Record<string, unknown> | undefined;
          const author = typeof userObj?.name === 'string' ? userObj.name : undefined;
          const publishedTime = typeof data.published_timestamp === 'string' ? data.published_timestamp : undefined;
          const cleanBody = data.body_markdown.replace(/^---[\s\S]{0,1500}?---\n+/, '').trim();
          const md = cleanBody.startsWith('# ') ? cleanBody : `# ${title}\n\n${cleanBody}`;
          return {
            title,
            ...(desc ? { description: desc } : {}),
            ...(author ? { author } : {}),
            ...(publishedTime ? { publishedTime } : {}),
            markdown: md,
          };
        },
      };
    }
  }

  // 13. Mastodon / Fediverse Status Permalinks (`https://<instance>/@<user>/<numericStatusId>`) -> `/api/v1/statuses/<id>`
  if (
    parts.length === 2 &&
    parts[0]!.startsWith('@') &&
    parts[0]!.length >= 2 &&
    /^\d{15,24}$/.test(parts[1]!) &&
    host !== 'medium.com' &&
    !host.endsWith('.medium.com') &&
    host !== 'tiktok.com' &&
    !host.endsWith('.tiktok.com') &&
    host !== 'threads.net' &&
    !host.endsWith('.threads.net')
  ) {
    const statusId = parts[1]!;
    return {
      id: 'mastodon-status',
      fetchUrl: `https://${host}/api/v1/statuses/${statusId}`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody, _origUrl, htmlToMd) => {
        const data = parseJsonObject(rawBody);
        const acctObj = data?.account as Record<string, unknown> | undefined;
        if (!data || typeof data.content !== 'string' || !acctObj || typeof acctObj.acct !== 'string') return null;
        const displayName = typeof acctObj.display_name === 'string' && acctObj.display_name ? acctObj.display_name : acctObj.acct;
        const createdAt = typeof data.created_at === 'string' ? data.created_at : '';
        const spoiler = typeof data.spoiler_text === 'string' ? data.spoiler_text.trim() : '';
        const converted = htmlToMd(data.content, `https://${host}`);
        const media = Array.isArray(data.media_attachments) ? (data.media_attachments as Array<Record<string, unknown>>) : [];
        const title = `${displayName} (@${acctObj.acct}@${host})`;

        const sections: string[] = [`# ${title}`];
        if (spoiler) sections.push(`> [!NOTE]\n> **Content Note**: ${spoiler}`);
        if (converted.markdown.trim()) sections.push(converted.markdown.trim());
        for (const m of media) {
          if (typeof m.description === 'string' && m.description.trim()) {
            sections.push(`- *Media description*: ${m.description.trim()}`);
          }
        }
        return {
          title,
          author: `@${acctObj.acct}@${host}`,
          ...(createdAt ? { publishedTime: createdAt } : {}),
          markdown: sections.join('\n\n'),
          links: converted.links,
        };
      },
    };
  }

  return null;
}

function isStackExchangeHost(host: string): boolean {
  return (
    host === 'stackoverflow.com' ||
    host === 'www.stackoverflow.com' ||
    host === 'serverfault.com' ||
    host === 'superuser.com' ||
    host === 'askubuntu.com' ||
    host === 'mathoverflow.net' ||
    host === 'stackapps.com' ||
    host.endsWith('.stackexchange.com')
  );
}

/** Extracts balanced `<div ...>...</div>` inner HTML starting right at the matched opening `<div ...>` index. */
function extractBalancedDivAt(html: string, openTagIndex: number): string | null {
  const openTagEnd = html.indexOf('>', openTagIndex);
  if (openTagEnd < 0) return null;
  if (html[openTagEnd - 1] === '/') return '';
  let depth = 1;
  const tagRe = /<\/?div\b(?:"[^"]*"|'[^']*'|[^>"'])*>/gi;
  tagRe.lastIndex = openTagEnd + 1;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const tok = m[0];
    if (tok.startsWith('</')) {
      depth--;
      if (depth === 0) {
        return html.slice(openTagEnd + 1, m.index);
      }
    } else if (!tok.endsWith('/>')) {
      depth++;
    }
  }
  return null;
}

function extractStackExchangeQa(rawHtml: string, baseUrl: string, htmlToMd: HtmlFragmentConverter): PostFetchSiteResult | null {
  const cleanHtml = rawHtml
    .replace(/<(script|style|svg)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
  const qHeaderMatch = /<div\b[^>]*\bid=["']question-header["'][^>]*>([\s\S]*?)<\/div>/i.exec(cleanHtml);
  const h1Match = /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(qHeaderMatch?.[1] ?? cleanHtml);
  const title = stripTagsInline(h1Match?.[1] ?? '').replace(/\s*\[(?:duplicate|closed)\]\s*$/i, '').trim();

  const qOpen = /<div\b[^>]*\bid=["']question["'][^>]*>/i.exec(cleanHtml);
  if (!qOpen || !title) return null;
  const qInner = extractBalancedDivAt(cleanHtml, qOpen.index);
  if (!qInner) return null;

  const extractPostBody = (block: string): string => {
    const bodyOpen = /<div\b[^>]*\bclass=["'][^"']*\b(?:s-prose|js-post-body|post-text)\b[^"']*["'][^>]*>/i.exec(block);
    if (!bodyOpen) return '';
    const inner = extractBalancedDivAt(block, bodyOpen.index);
    return inner ? htmlToMd(inner, baseUrl).markdown.trim() : '';
  };

  const extractComments = (block: string): string[] => {
    const out: string[] = [];
    for (const cm of block.matchAll(/<span\b[^>]*\bclass=["'][^"']*\bcomment-copy\b[^"']*["'][^>]*>([\s\S]*?)<\/span>/gi)) {
      const txt = stripTagsInline(cm[1]!);
      if (txt && out.length < 6) out.push(`> - *Comment*: ${txt}`);
    }
    return out;
  };

  const qScore =
    /\bdata-score=["'](-?\d+)["']/i.exec(cleanHtml.slice(qOpen.index, qOpen.index + 500))?.[1] ??
    stripTagsInline(/<div\b[^>]*\bjs-vote-count\b[^>]*>([\s\S]*?)<\/div>/i.exec(qInner)?.[1] ?? '');
  const tags = [...qInner.matchAll(/<a\b[^>]*\bpost-tag\b[^>]*>([\s\S]*?)<\/a>/gi)]
    .map((m) => stripTagsInline(m[1]!))
    .filter((t, i, a) => Boolean(t) && a.indexOf(t) === i)
    .slice(0, 8);

  const qMd = extractPostBody(qInner);
  if (!qMd) return null;

  const sections: string[] = [`# ${title}`];
  const qMeta: string[] = [];
  if (qScore) qMeta.push(`**Votes**: ${qScore}`);
  if (tags.length > 0) qMeta.push(`**Tags**: ${tags.map((t) => `\`${t}\``).join(', ')}`);
  if (qMeta.length > 0) sections.push(qMeta.join(' · '));
  sections.push(`## Question\n\n${qMd}`);
  const qComments = extractComments(qInner);
  if (qComments.length > 0) sections.push(qComments.join('\n'));

  // Extract answers sorted with Accepted Answer first, then highest score.
  const answers: Array<{ accepted: boolean; score: number; md: string; comments: string[] }> = [];
  const ansRe = /<div\b[^>]*\bid=["']answer-\d+["'][^>]*>/gi;
  let am: RegExpExecArray | null;
  while ((am = ansRe.exec(cleanHtml)) !== null && answers.length < 12) {
    const openTag = am[0];
    const aInner = extractBalancedDivAt(cleanHtml, am.index);
    if (!aInner) continue;
    const accepted = /\baccepted-answer\b|\bjs-accepted-answer\b/i.test(openTag) || /\bjs-accepted-answer-indicator\b/i.test(aInner.slice(0, 2000));
    const scoreRaw =
      /\bdata-score=["'](-?\d+)["']/i.exec(openTag)?.[1] ??
      stripTagsInline(/<div\b[^>]*\bjs-vote-count\b[^>]*>([\s\S]*?)<\/div>/i.exec(aInner)?.[1] ?? '0');
    const score = parseInt(scoreRaw, 10) || 0;
    const md = extractPostBody(aInner);
    if (!md) continue;
    answers.push({ accepted, score, md, comments: extractComments(aInner) });
  }

  answers.sort((a, b) => (a.accepted !== b.accepted ? (a.accepted ? -1 : 1) : b.score - a.score));
  for (let i = 0; i < Math.min(answers.length, 8); i++) {
    const a = answers[i]!;
    const heading = a.accepted
      ? `## ✅ Accepted Answer (Score: ${a.score})`
      : `## Answer ${i + 1} (Score: ${a.score})`;
    sections.push(`${heading}\n\n${a.md}`);
    if (a.comments.length > 0) sections.push(a.comments.join('\n'));
  }

  return {
    extractorId: 'stackexchange-qa',
    title,
    markdown: sections.join('\n\n'),
  };
}

function extractGistHtml(rawHtml: string, baseUrl: string, htmlToMd: HtmlFragmentConverter): PostFetchSiteResult | null {
  const desc = stripTagsInline(/<div\b[^>]*\bgist-content\b[\s\S]{0,1200}?<div\b[^>]*itemprop=["']about["'][^>]*>([\s\S]*?)<\/div>/i.exec(rawHtml)?.[1] ?? '');
  const titleRaw = stripTagsInline(/<title>([\s\S]*?)<\/title>/i.exec(rawHtml)?.[1] ?? '').replace(/\s*·\s*GitHub\s*$/i, '').trim();
  const files: string[] = [];

  const fileBoxRe = /<div\b[^>]*\bclass=["'][^"']*\bfile\b[^"']*["'][^>]*>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = fileBoxRe.exec(rawHtml)) !== null && files.length < 20) {
    const box = extractBalancedDivAt(rawHtml, fm.index);
    if (!box) continue;
    const name = stripTagsInline(/<strong\b[^>]*\bgist-blob-name\b[^>]*>([\s\S]*?)<\/strong>/i.exec(box)?.[1] ?? '');
    if (!name) continue;
    const mdArticle = /<article\b[^>]*\bmarkdown-body\b[^>]*>([\s\S]*?)<\/article>/i.exec(box);
    if (mdArticle) {
      files.push(`## ${name}\n\n${htmlToMd(mdArticle[1]!, baseUrl).markdown.trim()}`);
      continue;
    }
    const codeLines = [...box.matchAll(/<td\b[^>]*\bblob-code-inner\b[^>]*>([\s\S]*?)<\/td>/gi)].map((m) =>
      decodeBasicEntities(m[1]!.replace(/<[^>]+>/g, '')),
    );
    if (codeLines.length > 0) {
      const { lang } = detectFenceLang(name);
      files.push(`## ${name}\n\n${safeFence(codeLines.join('\n'), lang)}`);
    }
  }

  if (files.length === 0) return null;
  const title = titleRaw || desc || 'GitHub Gist';
  const sections = [`# ${title}`];
  if (desc && desc !== title) sections.push(desc);
  sections.push(files.join('\n\n'));
  return {
    extractorId: 'github-gist',
    title,
    ...(desc ? { description: desc } : {}),
    markdown: sections.join('\n\n'),
  };
}

function cleanIetfRfcHtmlOrMarkdown(rawHtml: string, currentMd: string): PostFetchSiteResult | null {
  // ASCII RFCs wrap pages in `<pre class="newpage">` with running headers/footers like `RFC 9110 ... [Page 12]`.
  const preBlocks = [...rawHtml.matchAll(/<pre\b[^>]*\bclass=["'][^"']*\bnewpage\b[^"']*["'][^>]*>([\s\S]*?)<\/pre>/gi)];
  const sourceText =
    preBlocks.length > 0
      ? preBlocks.map((m) => decodeBasicEntities(m[1]!.replace(/<[^>]+>/g, ''))).join('\n')
      : currentMd;
  if (!sourceText || sourceText.trim().length < 80) return null;

  const cleanedLines: string[] = [];
  for (const rawLine of sourceText.replace(/\r\n/g, '\n').replace(/\f/g, '\n').split('\n')) {
    // Drop running page footers (`... [Page 42]`) and running page headers (`RFC 9110   HTTP Semantics   June 2022`).
    if (/\[Page\s+\d+\]\s*$/i.test(rawLine)) continue;
    if (/^RFC\s+\d+\s{2,}.+\s{2,}(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\s*$/i.test(rawLine.trim())) {
      continue;
    }
    const secMatch = /^(\d+(?:\.\d+){0,3})\.\s+([A-Z][^\r\n]{1,90})$/.exec(rawLine.trim());
    if (secMatch && rawLine === rawLine.trim()) {
      const depth = Math.min(4, secMatch[1]!.split('.').length + 1);
      cleanedLines.push(`\n${'#'.repeat(depth)} ${secMatch[1]}. ${secMatch[2]}\n`);
    } else {
      cleanedLines.push(rawLine);
    }
  }

  const md = cleanedLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
  const title = stripTagsInline(/<title>([\s\S]*?)<\/title>/i.exec(rawHtml)?.[1] ?? '').trim();
  return {
    extractorId: 'ietf-rfc',
    ...(title ? { title } : {}),
    markdown: title && !md.startsWith('# ') ? `# ${title}\n\n${md}` : md,
  };
}

function cleanWikipediaMarkdown(md: string): string {
  return md
    .replace(/\s*\[(?:edit|citation needed|clarification needed|when\?|who\?|dubious\s*[–-]\s*discuss)\]/gi, '')
    .replace(/^\s*\^\s+(?:\[\^[a-z0-9]+\]\s*|(?:[a-z]\s+){2,})/gim, '^ ')
    .replace(/\n+(?:##+\s+)?(?:Navigation menu|Namespaces|Views|Personal tools)\b[\s\S]*$/i, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function extractPkgGoDev(rawHtml: string, baseUrl: string, htmlToMd: HtmlFragmentConverter): PostFetchSiteResult | null {
  const clean = rawHtml.replace(/<(script|style|svg)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
  const title = stripTagsInline(/<title>([\s\S]*?)<\/title>/i.exec(clean)?.[1] ?? '')
    .replace(/\s*-\s*Go Packages\s*$/i, '')
    .trim();

  const sections: string[] = [];
  if (title) sections.push(`# ${title}`);

  const readmeOpen = /<div\b[^>]*\bUnitReadme-content\b[^>]*>/i.exec(clean);
  if (readmeOpen) {
    const inner = extractBalancedDivAt(clean, readmeOpen.index);
    if (inner) {
      const md = htmlToMd(inner, baseUrl).markdown.trim();
      if (md) sections.push(`## Overview / README\n\n${md}`);
    }
  }

  const docOpen = /<div\b[^>]*\bDocumentation-content\b[^>]*>/i.exec(clean);
  if (docOpen) {
    const inner = extractBalancedDivAt(clean, docOpen.index);
    if (inner) {
      const md = htmlToMd(inner, baseUrl).markdown.replace(/\s*¶(\s|$)/g, '$1').trim();
      if (md) sections.push(`## Documentation\n\n${md}`);
    }
  }

  if (sections.length <= 1) return null;
  return { extractorId: 'pkg-go-dev', ...(title ? { title } : {}), markdown: sections.join('\n\n') };
}

function extractPypiProject(rawHtml: string, baseUrl: string, htmlToMd: HtmlFragmentConverter): PostFetchSiteResult | null {
  const clean = rawHtml.replace(/<(script|style|svg)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
  const headerName = stripTagsInline(/<h1\b[^>]*\bpackage-header__name\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ?? '');
  const pipCmd = stripTagsInline(/<span\b[^>]*\bid=["']pip-command["'][^>]*>([\s\S]*?)<\/span>/i.exec(clean)?.[1] ?? '');
  const summary = stripTagsInline(/<p\b[^>]*\bpackage-description__summary\b[^>]*>([\s\S]*?)<\/p>/i.exec(clean)?.[1] ?? '');
  const descOpen = /<div\b[^>]*\bid=["']description["'][^>]*>/i.exec(clean) ?? /<div\b[^>]*\bproject-description\b[^>]*>/i.exec(clean);
  if (!descOpen || !headerName) return null;
  const inner = extractBalancedDivAt(clean, descOpen.index);
  if (!inner) return null;
  const readmeMd = htmlToMd(inner, baseUrl).markdown.trim();
  if (!readmeMd) return null;

  const sections: string[] = [`# ${headerName}`];
  if (summary) sections.push(summary);
  if (pipCmd) sections.push(`- **Install**: \`${pipCmd}\``);
  sections.push(readmeMd.replace(/^#\s+.+\n+/, '').trim() || readmeMd);
  return {
    extractorId: 'pypi-project',
    title: headerName,
    ...(summary ? { description: summary } : {}),
    markdown: sections.join('\n\n'),
  };
}

function extractPubMedOrPmc(rawHtml: string, baseUrl: string, htmlToMd: HtmlFragmentConverter): PostFetchSiteResult | null {
  const clean = rawHtml.replace(/<(script|style|svg)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
  const title = stripTagsInline(
    /<h1\b[^>]*\bheading-title\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ??
      /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(clean)?.[1] ??
      '',
  );
  if (!title) return null;

  const authors = [...clean.matchAll(/<a\b[^>]*\bfull-name\b[^>]*>([\s\S]*?)<\/a>/gi)]
    .map((m) => stripTagsInline(m[1]!))
    .filter((a, i, arr) => Boolean(a) && arr.indexOf(a) === i)
    .slice(0, 15);
  const doi = stripTagsInline(/<span\b[^>]*\bcitation-doi\b[^>]*>([\s\S]*?)<\/span>/i.exec(clean)?.[1] ?? '');

  const absOpen =
    /<div\b[^>]*\bid=["'](?:abstract|eng-abstract)["'][^>]*>/i.exec(clean) ??
    /<section\b[^>]*\bclass=["'][^"']*\babstract\b[^"']*["'][^>]*>([\s\S]*?)<\/section>/i.exec(clean);

  let bodyMd = '';
  const pmcArticle = /<article\b[^>]*\barticle\b[^>]*>([\s\S]*?)<\/article>/i.exec(clean);
  if (pmcArticle) {
    bodyMd = htmlToMd(pmcArticle[1]!, baseUrl).markdown.trim();
  } else if (absOpen) {
    const inner = absOpen[0].startsWith('<div') ? extractBalancedDivAt(clean, absOpen.index) : absOpen[1] ?? '';
    if (inner) bodyMd = htmlToMd(inner, baseUrl).markdown.trim();
  }
  if (!bodyMd) return null;

  const meta: string[] = [];
  if (authors.length > 0) meta.push(`- **Authors**: ${authors.join(', ')}`);
  if (doi) meta.push(`- **Citation**: ${doi}`);

  const sections = [`# ${title}`];
  if (meta.length > 0) sections.push(meta.join('\n'));
  sections.push(bodyMd.startsWith('#') ? bodyMd : `## Abstract\n\n${bodyMd}`);
  return {
    extractorId: 'pubmed-pmc',
    title,
    ...(authors.length > 0 ? { author: authors.slice(0, 4).join(', ') } : {}),
    markdown: sections.join('\n\n'),
  };
}

function extractRedditThread(rawHtml: string, baseUrl: string, htmlToMd: HtmlFragmentConverter): PostFetchSiteResult | null {
  const clean = rawHtml.replace(/<(script|style|svg)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
  // Modern Reddit (`<shreddit-post ...>`) or Old Reddit (`.top-matter` + `.usertext-body`)
  const shPost = /<shreddit-post\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/shreddit-post>/i.exec(clean);
  if (shPost) {
    const attrs = shPost[1]!;
    const pTitle = decodeBasicEntities(/\bpost-title=["']([^"']+)["']/i.exec(attrs)?.[1] ?? '');
    const author = decodeBasicEntities(/\bauthor=["']([^"']+)["']/i.exec(attrs)?.[1] ?? '');
    const score = /\bscore=["'](-?\d+)["']/i.exec(attrs)?.[1] ?? '';
    const sub = decodeBasicEntities(/\bsubreddit-prefixed-name=["']([^"']+)["']/i.exec(attrs)?.[1] ?? '');
    const bodyMd = htmlToMd(shPost[2]!, baseUrl).markdown.trim();
    if (!pTitle) return null;
    const sections = [`# ${pTitle}`];
    const meta = [sub, author ? `u/${author}` : '', score ? `${score} upvotes` : ''].filter(Boolean);
    if (meta.length > 0) sections.push(`*${meta.join(' · ')}*`);
    if (bodyMd) sections.push(bodyMd);

    const comments: string[] = [];
    for (const cm of clean.matchAll(/<shreddit-comment\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/shreddit-comment>/gi)) {
      if (comments.length >= 25) break;
      const cAuthor = decodeBasicEntities(/\bauthor=["']([^"']+)["']/i.exec(cm[1]!)?.[1] ?? 'user');
      const cScore = /\bscore=["'](-?\d+)["']/i.exec(cm[1]!)?.[1] ?? '';
      const cDepth = Math.min(5, Math.max(0, parseInt(/\bdepth=["'](\d+)["']/i.exec(cm[1]!)?.[1] ?? '0', 10)));
      const cMd = htmlToMd(cm[2]!, baseUrl).markdown.trim().replace(/\n+/g, ' ');
      if (cMd) comments.push(`${'  '.repeat(cDepth)}- **u/${cAuthor}**${cScore ? ` (${cScore})` : ''}: ${cMd}`);
    }
    if (comments.length > 0) sections.push(`## Comments\n\n${comments.join('\n')}`);
    return {
      extractorId: 'reddit-thread',
      title: pTitle,
      ...(author ? { author: `u/${author}` } : {}),
      markdown: sections.join('\n\n'),
    };
  }
  return null;
}

/**
 * Applies platform-specific post-fetch DOM or Markdown extraction when `baseUrl` matches a registered site.
 */
export function applyPostFetchSiteExtractor(
  rawHtml: string,
  baseUrl: string | undefined,
  currentMd: string,
  htmlToMd: HtmlFragmentConverter,
): PostFetchSiteResult | null {
  if (!baseUrl) return null;
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  const path = u.pathname;

  if (isStackExchangeHost(host) && /^\/questions\/\d+/i.test(path)) {
    return extractStackExchangeQa(rawHtml, baseUrl, htmlToMd);
  }

  if (host === 'gist.github.com' && path.split('/').filter(Boolean).length >= 2) {
    return extractGistHtml(rawHtml, baseUrl, htmlToMd);
  }

  if (host === 'pkg.go.dev' && path.length > 1) {
    return extractPkgGoDev(rawHtml, baseUrl, htmlToMd);
  }

  if ((host === 'pypi.org' || host === 'www.pypi.org') && /^\/project\/[^/]+/i.test(path)) {
    return extractPypiProject(rawHtml, baseUrl, htmlToMd);
  }

  if (
    (host === 'datatracker.ietf.org' && /^\/doc\/html\/(?:rfc|draft-)/i.test(path)) ||
    ((host === 'www.rfc-editor.org' || host === 'rfc-editor.org') && /^\/rfc\/rfc\d+/i.test(path))
  ) {
    return cleanIetfRfcHtmlOrMarkdown(rawHtml, currentMd);
  }

  if (
    (host === 'pubmed.ncbi.nlm.nih.gov' && /^\/\d+\/?$/.test(path)) ||
    (host === 'pmc.ncbi.nlm.nih.gov' && /^\/articles\/PMC\d+/i.test(path))
  ) {
    return extractPubMedOrPmc(rawHtml, baseUrl, htmlToMd);
  }

  if ((host === 'reddit.com' || host.endsWith('.reddit.com')) && /\/comments\/[A-Za-z0-9]+/i.test(path)) {
    const r = extractRedditThread(rawHtml, baseUrl, htmlToMd);
    if (r) return r;
  }

  if (host.endsWith('.wikipedia.org') || host === 'wiki.archlinux.org' || /\bcontent=["']MediaWiki\b/i.test(rawHtml.slice(0, 4000))) {
    const cleaned = cleanWikipediaMarkdown(currentMd);
    if (cleaned && cleaned !== currentMd) {
      return { extractorId: 'mediawiki', markdown: cleaned };
    }
  }

  // JSR (`jsr.io/@scope/pkg`): strip duplicate version/scorecard nav noise at top of extracted Markdown.
  if (host === 'jsr.io' && /^\/@[^/]+\/[^/]+/i.test(path) && currentMd) {
    const cleaned = currentMd
      .replace(/^(?:Published\s+[^\n]+\n+|Overview\s+Docs\s+Files\s+Versions\s+Dependencies\s+Dependents\s+Score\s*\n+)/gim, '')
      .trim();
    if (cleaned && cleaned !== currentMd) {
      return { extractorId: 'jsr-io', markdown: cleaned };
    }
  }

  return null;
}
