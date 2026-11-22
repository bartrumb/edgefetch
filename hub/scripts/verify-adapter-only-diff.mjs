#!/usr/bin/env node
// Deterministic Ring 1 Auto-Merge Policy Gate (`hub/scripts/verify-adapter-only-diff.mjs`).
//
//   node scripts/verify-adapter-only-diff.mjs [--base origin/main]
//
// Enforces hard supply-chain and SSRF boundaries on automated or Ring 1 adapter selector/JSON-path repairs:
//  1. `changedFiles` must be non-empty.
//  2. ONLY existing declarative manifests (`M internal/extract/manifests/<slug>.yaml`),
//     `M internal/extract/manifests/compiled.json`, matching `< 256 KiB` valid JSON fixtures
//     (`M|A hub/test/fixtures/adapters/<slug>.json`), and `M docs/adapter-health.json` may be touched.
//     Any touch to `.github/`, `cmd/`, Go sources (`internal/`), `hub/src/`, `keys/`, `package.json`,
//     or adding/deleting/renaming manifests (`A`/`D`/`R`) is immediately rejected for Ring 0 human review.
//  3. Both `<base>` and `<head>` YAML manifests must pass YAML 1.2 Core AST safety (zero anchors, aliases,
//     merge keys, or explicit tags) and preserve `id`, `category`, `universalEngine`, canonical sorted `domains[]`,
//     adapter mode (cannot flip HTML-only into outbound `twin.fetchUrl`), and `https://` `twin.fetchUrl` host/authority!

import { execFileSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isAlias, isMap, isPair, isScalar, isSeq, parseDocument } from 'yaml';

const SAFE_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MANIFEST_PATH_RE = /^internal\/extract\/manifests\/([a-z0-9][a-z0-9_-]{0,63})\.yaml$/;
const FIXTURE_PATH_RE = /^hub\/test\/fixtures\/adapters\/([a-z0-9][a-z0-9_-]{0,63})\.json$/;
const COMPILED_MANIFESTS_PATH = 'internal/extract/manifests/compiled.json';
const ADAPTER_HEALTH_PATH = 'docs/adapter-health.json';
const MAX_FIXTURE_BYTES = 256 * 1024;

function isAsciiPrintable(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

function checkYamlAstSafety(node, ctxPath) {
  if (!node || typeof node !== 'object') return;
  if (isAlias(node)) {
    throw new Error(`${ctxPath}: YAML alias (*alias) is forbidden`);
  }
  if (node.anchor) {
    throw new Error(`${ctxPath}: YAML anchor (&${node.anchor}) is forbidden`);
  }
  if (node.tag) {
    throw new Error(`${ctxPath}: explicit YAML tag (${node.tag}) is forbidden`);
  }
  if (isMap(node)) {
    for (const pair of node.items) {
      if (!isPair(pair)) continue;
      checkYamlAstSafety(pair.key, ctxPath);
      if (isScalar(pair.key)) {
        const k = String(pair.key.value ?? '');
        if (k === '<<') throw new Error(`${ctxPath}: YAML merge key (<<) is forbidden`);
        if (!isAsciiPrintable(k)) throw new Error(`${ctxPath}: non-ASCII YAML key "${k}" is forbidden`);
      }
      const keyLabel = isScalar(pair.key) ? String(pair.key.value ?? '') : '?';
      checkYamlAstSafety(pair.value, `${ctxPath}.${keyLabel}`);
    }
  } else if (isSeq(node)) {
    node.items.forEach((child, i) => checkYamlAstSafety(child, `${ctxPath}[${i}]`));
  }
}

export function parseSafeYamlManifest(rawYaml, label) {
  if (typeof rawYaml !== 'string' || !rawYaml.trim()) {
    throw new Error(`${label}: empty or missing YAML content`);
  }
  const doc = parseDocument(rawYaml, {
    maxAliasCount: 0,
    merge: false,
    uniqueKeys: true,
    schema: 'core',
  });
  if (doc.errors.length > 0) {
    throw new Error(`${label}: YAML syntax error: ${doc.errors[0].message}`);
  }
  checkYamlAstSafety(doc.contents, label);
  const obj = doc.toJS({ maxAliasCount: 0 });
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(`${label}: top-level YAML value must be a mapping`);
  }
  return obj;
}

function canonicalizeDomains(domains, label) {
  if (!Array.isArray(domains) || domains.length === 0) {
    throw new Error(`${label}: domains must be a non-empty string[]`);
  }
  const normalized = domains.map((d) => {
    if (typeof d !== 'string' || !d.trim()) {
      throw new Error(`${label}: invalid empty domain entry`);
    }
    return d.trim().toLowerCase();
  });
  return [...normalized].sort((a, b) => a.localeCompare(b));
}

function collectManifestTwins(manifest) {
  const twins = [];
  if (manifest.twin && typeof manifest.twin === 'object') {
    twins.push({ twin: manifest.twin, label: 'twin' });
  }
  if (Array.isArray(manifest.routes)) {
    manifest.routes.forEach((route, idx) => {
      if (route && typeof route === 'object' && route.twin && typeof route.twin === 'object') {
        twins.push({ twin: route.twin, label: `routes[${idx}].twin` });
      }
    });
  }
  return twins;
}

function isSafeLiteralHostname(host) {
  if (!host || host.length > 253 || !host.includes('.') || /[\s/\\:?#@%]/.test(host)) {
    return false;
  }
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.nip.io') ||
    host.endsWith('.sslip.io') ||
    host.endsWith('.xip.io') ||
    host.endsWith('.')
  ) {
    return false;
  }
  const labels = host.split('.');
  if (labels.some((l) => !l || l.startsWith('-') || l.endsWith('-'))) return false;
  const tld = labels[labels.length - 1];
  if (/^(?:\d+|0x[0-9a-f]+)$/i.test(tld)) return false;
  return true;
}

/**
 * Parses and validates the scheme + authority token of a `twin.fetchUrl` template:
 *  - `{requestUrl}` -> `{ kind: 'requestUrl', token: '{requestUrl}' }`
 *  - `https://{host}/...` -> `{ kind: 'hostPlaceholder', token: '{host}' }`
 *  - `https://api.example.com/...` -> `{ kind: 'literalHost', token: 'api.example.com' }`
 * Rejects `http://`, `{origin}`, ports, credentials, arbitrary `{param}` host interpolation, or IP/rebinding literals.
 */
export function parseTwinFetchUrlAuthority(fetchUrl, ctxLabel) {
  if (typeof fetchUrl !== 'string' || fetchUrl !== fetchUrl.trim() || !fetchUrl || /[\s\\]/.test(fetchUrl)) {
    throw new Error(`${ctxLabel}: fetchUrl must be a non-empty trimmed string without whitespace`);
  }
  if (fetchUrl === '{requestUrl}') {
    return { kind: 'requestUrl', token: '{requestUrl}' };
  }
  if (!fetchUrl.startsWith('https://')) {
    throw new Error(`${ctxLabel}: fetchUrl scheme must be https:// (got "${fetchUrl}")`);
  }
  const afterScheme = fetchUrl.slice('https://'.length);
  const slashIdx = afterScheme.search(/[/?#]/);
  const rawAuthority = slashIdx >= 0 ? afterScheme.slice(0, slashIdx) : afterScheme;
  if (!rawAuthority) {
    throw new Error(`${ctxLabel}: fetchUrl missing authority host ("${fetchUrl}")`);
  }
  if (rawAuthority.includes('@') || rawAuthority.includes(':') || rawAuthority.includes('%') || rawAuthority.includes('..')) {
    throw new Error(`${ctxLabel}: fetchUrl authority may not contain credentials, ports, percent-encoding, or '..' ("${fetchUrl}")`);
  }
  if (rawAuthority.includes('{') || rawAuthority.includes('}')) {
    if (rawAuthority !== '{host}') {
      throw new Error(`${ctxLabel}: fetchUrl authority template placeholder may only be exact 'https://{host}/...' (got "${fetchUrl}")`);
    }
    if (slashIdx < 0 || afterScheme[slashIdx] !== '/') {
      throw new Error(`${ctxLabel}: 'https://{host}' must be followed immediately by '/' (got "${fetchUrl}")`);
    }
    return { kind: 'hostPlaceholder', token: '{host}' };
  }
  const hostLower = rawAuthority.toLowerCase();
  if (!isSafeLiteralHostname(hostLower)) {
    throw new Error(`${ctxLabel}: fetchUrl literal host "${rawAuthority}" failed public hostname check`);
  }
  return { kind: 'literalHost', token: hostLower };
}

/**
 * Pure, deterministic Ring 1 diff policy verifier.
 *
 * @param {object} params
 * @param {Array<{ status: string, path: string }>} params.changedFiles
 * @param {(path: string) => string} params.getBaseContent
 * @param {(path: string) => string} params.getHeadContent
 */
export function verifyRing1Diff({ changedFiles, getBaseContent, getHeadContent }) {
  const violations = [];
  const fail = (msg) => {
    violations.push(msg);
    return { ok: false, violations, reason: violations.join('; ') };
  };

  if (!Array.isArray(changedFiles) || changedFiles.length === 0) {
    return fail('Diff contains no changed files (changedFiles must be non-empty).');
  }
  if (typeof getBaseContent !== 'function' || typeof getHeadContent !== 'function') {
    return fail('getBaseContent and getHeadContent callbacks are required.');
  }

  const seenPaths = new Set();
  const modifiedManifestFiles = [];
  const touchedFixtures = [];
  let touchedCompiledJson = false;
  let touchedHealthJson = false;

  for (const entry of changedFiles) {
    if (!entry || typeof entry.status !== 'string' || typeof entry.path !== 'string') {
      violations.push(`Malformed changedFiles entry: ${JSON.stringify(entry)}`);
      continue;
    }
    const status = entry.status.trim();
    const filePath = entry.path.trim();

    if (!filePath || filePath.includes('\\') || filePath.startsWith('/') || filePath.split('/').includes('..') || /[\0-\x1f]/.test(filePath)) {
      violations.push(`Disallowed or non-canonical file path "${filePath}"`);
      continue;
    }
    if (seenPaths.has(filePath)) {
      violations.push(`Duplicate changedFiles path "${filePath}"`);
      continue;
    }
    seenPaths.add(filePath);

    const manifestMatch = MANIFEST_PATH_RE.exec(filePath);
    if (manifestMatch) {
      if (status !== 'M') {
        violations.push(
          `Manifest "${filePath}" has git status "${status}" — Ring 1 only permits 'M' on existing manifests (adding/deleting/renaming manifests requires Ring 0 human review).`,
        );
        continue;
      }
      modifiedManifestFiles.push({ path: filePath, slug: manifestMatch[1] });
      continue;
    }

    if (filePath === COMPILED_MANIFESTS_PATH) {
      if (status !== 'M') {
        violations.push(`"${COMPILED_MANIFESTS_PATH}" has status "${status}" (must be 'M').`);
        continue;
      }
      touchedCompiledJson = true;
      continue;
    }

    if (filePath === ADAPTER_HEALTH_PATH) {
      if (status !== 'M') {
        violations.push(`"${ADAPTER_HEALTH_PATH}" has status "${status}" (must be 'M').`);
        continue;
      }
      touchedHealthJson = true;
      continue;
    }

    const fixtureMatch = FIXTURE_PATH_RE.exec(filePath);
    if (fixtureMatch) {
      if (status !== 'M' && status !== 'A') {
        violations.push(`Fixture "${filePath}" has status "${status}" (only 'M' or 'A' allowed).`);
        continue;
      }
      touchedFixtures.push({ path: filePath, slug: fixtureMatch[1], status });
      continue;
    }

    violations.push(
      `Forbidden path touched outside Ring 1 adapter boundary: "${status} ${filePath}" (requires Ring 0 human review).`,
    );
  }

  if (violations.length > 0) {
    return { ok: false, violations, reason: violations.join('; ') };
  }

  const allowedFixtureSlugs = new Set();
  const allowedFixtureAdapterIds = new Set();

  for (const mf of modifiedManifestFiles) {
    let baseObj;
    let headObj;
    try {
      baseObj = parseSafeYamlManifest(getBaseContent(mf.path), `base:${mf.path}`);
      headObj = parseSafeYamlManifest(getHeadContent(mf.path), `head:${mf.path}`);
    } catch (err) {
      violations.push(err instanceof Error ? err.message : String(err));
      continue;
    }

    if (typeof baseObj.id !== 'string' || !SAFE_SLUG_RE.test(baseObj.id) || baseObj.id !== headObj.id) {
      violations.push(
        `${mf.path}: manifest id changed or invalid ("${String(baseObj.id)}" -> "${String(headObj.id)}").`,
      );
    }
    if (baseObj.category !== headObj.category) {
      violations.push(
        `${mf.path}: manifest category changed ("${String(baseObj.category)}" -> "${String(headObj.category)}").`,
      );
    }
    if (Boolean(baseObj.universalEngine) !== Boolean(headObj.universalEngine)) {
      violations.push(
        `${mf.path}: universalEngine changed (${Boolean(baseObj.universalEngine)} -> ${Boolean(headObj.universalEngine)}).`,
      );
    }

    let baseDomains = [];
    let headDomains = [];
    try {
      baseDomains = canonicalizeDomains(baseObj.domains, `base:${mf.path}`);
      headDomains = canonicalizeDomains(headObj.domains, `head:${mf.path}`);
    } catch (err) {
      violations.push(err instanceof Error ? err.message : String(err));
      continue;
    }

    if (
      baseDomains.length !== headDomains.length ||
      baseDomains.some((d, idx) => d !== headDomains[idx])
    ) {
      violations.push(
        `${mf.path}: domains[] must remain 100% identical in Ring 1 (base=[${baseDomains.join(', ')}], head=[${headDomains.join(', ')}]).`,
      );
    }

    // Lock `catalog` pagination URL templates so outbound hosts cannot change through `catalog`
    if (JSON.stringify(baseObj.catalog ?? null) !== JSON.stringify(headObj.catalog ?? null)) {
      violations.push(`${mf.path}: catalog spec modifications require Ring 0 human review.`);
    }

    const baseTwins = collectManifestTwins(baseObj);
    const headTwins = collectManifestTwins(headObj);

    if (baseTwins.length === 0 && headTwins.length > 0) {
      violations.push(
        `${mf.path}: cannot flip HTML-only adapter into outbound twin mode without Ring 0 human review.`,
      );
    }

    if (headTwins.length > 0) {
      const baseAuthorities = new Set();
      for (const bt of baseTwins) {
        try {
          const parsedAuth = parseTwinFetchUrlAuthority(bt.twin.fetchUrl, `base:${mf.path}.${bt.label}`);
          baseAuthorities.add(parsedAuth.token);
        } catch (err) {
          violations.push(err instanceof Error ? err.message : String(err));
        }
      }

      // Exact non-wildcard domains owned by `base.domains` (wildcard patterns like `*.socrata.com` are intentionally
      // excluded so a Ring 1 diff can NEVER redirect `https://{host}/...` traffic to a specific attacker tenant!).
      const exactOwnedBaseDomains = new Set(baseDomains.filter((d) => !d.includes('*')));
      const baseHasWildcardDomain = Boolean(baseObj.universalEngine) || baseDomains.some((d) => d.includes('*'));

      for (const ht of headTwins) {
        let headAuth;
        try {
          headAuth = parseTwinFetchUrlAuthority(ht.twin.fetchUrl, `head:${mf.path}.${ht.label}`);
        } catch (err) {
          violations.push(err instanceof Error ? err.message : String(err));
          continue;
        }

        if (headAuth.kind === 'requestUrl') {
          if (!baseAuthorities.has('{requestUrl}')) {
            violations.push(
              `${mf.path}.${ht.label}: fetchUrl "{requestUrl}" was not present in base manifest.`,
            );
          }
        } else if (headAuth.kind === 'hostPlaceholder') {
          if (!baseAuthorities.has('{host}') && baseHasWildcardDomain) {
            violations.push(
              `${mf.path}.${ht.label}: fetchUrl "https://{host}/..." cannot be introduced on a wildcard adapter without Ring 0 review.`,
            );
          }
        } else if (headAuth.kind === 'literalHost') {
          if (!baseAuthorities.has(headAuth.token) && !exactOwnedBaseDomains.has(headAuth.token)) {
            violations.push(
              `${mf.path}.${ht.label}: fetchUrl host "${headAuth.token}" is not in base twin authorities ([${[...baseAuthorities].join(', ')}]) or exact base.domains ([${[...exactOwnedBaseDomains].join(', ')}]).`,
            );
          }
        }
      }
    }

    allowedFixtureSlugs.add(mf.slug);
    if (typeof baseObj.id === 'string') {
      allowedFixtureSlugs.add(baseObj.id);
      allowedFixtureAdapterIds.add(baseObj.id);
    }
    for (const bt of baseTwins) {
      if (typeof bt.twin.id === 'string' && SAFE_SLUG_RE.test(bt.twin.id)) {
        allowedFixtureSlugs.add(bt.twin.id);
        allowedFixtureAdapterIds.add(bt.twin.id);
      }
    }
    for (const hr of headObj.htmlRoutes ?? []) {
      if (hr && typeof hr.id === 'string' && SAFE_SLUG_RE.test(hr.id)) {
        allowedFixtureAdapterIds.add(hr.id);
      }
    }
  }

  for (const fx of touchedFixtures) {
    if (!allowedFixtureSlugs.has(fx.slug)) {
      violations.push(
        `Fixture "${fx.path}" (slug "${fx.slug}") does not match any modified manifest in this diff ([${[...allowedFixtureSlugs].join(', ')}]).`,
      );
      continue;
    }
    let rawFx;
    try {
      rawFx = getHeadContent(fx.path);
    } catch (err) {
      violations.push(`Failed reading head fixture "${fx.path}": ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    if (typeof rawFx !== 'string') {
      violations.push(`Fixture "${fx.path}" head content must be a UTF-8 string.`);
      continue;
    }
    const byteLen = Buffer.byteLength(rawFx, 'utf8');
    if (byteLen >= MAX_FIXTURE_BYTES) {
      violations.push(
        `Fixture "${fx.path}" is ${byteLen} bytes (must be strictly < ${MAX_FIXTURE_BYTES} bytes / 256 KiB).`,
      );
      continue;
    }
    let parsedFx;
    try {
      parsedFx = JSON.parse(rawFx);
    } catch (err) {
      violations.push(`Fixture "${fx.path}" is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    if (!parsedFx || typeof parsedFx !== 'object' || Array.isArray(parsedFx)) {
      violations.push(`Fixture "${fx.path}" must be a JSON object.`);
      continue;
    }
    if (
      typeof parsedFx.adapterId === 'string' &&
      !allowedFixtureAdapterIds.has(parsedFx.adapterId) &&
      ![...allowedFixtureAdapterIds].some((id) => parsedFx.adapterId.startsWith(`${id}-`))
    ) {
      violations.push(
        `Fixture "${fx.path}" adapterId "${parsedFx.adapterId}" does not match modified manifest IDs ([${[...allowedFixtureAdapterIds].join(', ')}]).`,
      );
    }
  }

  if (touchedCompiledJson) {
    try {
      const compiledObj = JSON.parse(getHeadContent(COMPILED_MANIFESTS_PATH));
      if (!compiledObj || typeof compiledObj !== 'object' || !Array.isArray(compiledObj.manifests)) {
        violations.push(`${COMPILED_MANIFESTS_PATH}: invalid compiled manifest structure.`);
      }
    } catch (err) {
      violations.push(
        `${COMPILED_MANIFESTS_PATH}: invalid JSON (${err instanceof Error ? err.message : String(err)}).`,
      );
    }
  }

  if (touchedHealthJson) {
    try {
      const healthObj = JSON.parse(getHeadContent(ADAPTER_HEALTH_PATH));
      if (!healthObj || typeof healthObj !== 'object' || !Array.isArray(healthObj.adapters)) {
        violations.push(`${ADAPTER_HEALTH_PATH}: invalid adapter-health.json structure.`);
      }
    } catch (err) {
      violations.push(`${ADAPTER_HEALTH_PATH}: invalid JSON (${err instanceof Error ? err.message : String(err)}).`);
    }
  }

  if (violations.length > 0) {
    return { ok: false, violations, reason: violations.join('; ') };
  }

  return {
    ok: true,
    modifiedManifests: modifiedManifestFiles.map((m) => m.path),
    summary: `Verified Ring 1 adapter-only diff (${changedFiles.length} file(s), ${modifiedManifestFiles.length} manifest(s) modified).`,
  };
}

export function parseGitNameStatus(rawOutput) {
  const entries = [];
  for (const rawLine of String(rawOutput ?? '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split('\t');
    const status = (parts[0] ?? '').trim();
    // For renames/copies (`R100\told\tnew`), capture `status` (`R100`) and target path so `verifyRing1Diff` rejects it clearly
    const path = (parts.length >= 3 ? parts[2] : parts[1] ?? '').trim();
    entries.push({ status, path });
  }
  return entries;
}

function parseCliArgs(argv) {
  let baseRef = null;
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--base') {
      baseRef = argv[++i] ?? null;
    } else if (arg.startsWith('--base=')) {
      baseRef = arg.slice('--base='.length);
    } else if (arg === '--help' || arg === '-h') {
      help = true;
    } else {
      throw new Error(`Unknown CLI flag: ${arg}`);
    }
  }
  return { baseRef, help };
}

const isMainModule =
  Boolean(process.argv[1]) &&
  resolve(process.argv[1]).replace(/\\/g, '/').endsWith('/verify-adapter-only-diff.mjs') &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule) {
  const { baseRef: explicitBase, help } = parseCliArgs(process.argv.slice(2));
  if (help) {
    console.log('Usage: node scripts/verify-adapter-only-diff.mjs [--base <git-ref>]');
    process.exit(0);
  }

  const scriptsDir = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(scriptsDir, '..', '..');

  let baseRef = explicitBase;
  if (!baseRef) {
    try {
      execFileSync('git', ['rev-parse', '--verify', 'origin/main'], { cwd: repoRoot, stdio: 'ignore' });
      baseRef = 'origin/main';
    } catch {
      baseRef = 'HEAD~1';
    }
  }

  let mergeBase;
  try {
    mergeBase = execFileSync('git', ['merge-base', baseRef, 'HEAD'], {
      cwd: repoRoot,
      encoding: 'utf8',
    }).trim();
  } catch (err) {
    console.error(`Failed to resolve git merge-base for "${baseRef}": ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  const rawDiff = execFileSync('git', ['diff', '--name-status', mergeBase, 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  const changedFiles = parseGitNameStatus(rawDiff);

  const readGitBlob = (rev, relPath) =>
    execFileSync('git', ['show', `${rev}:${relPath}`], {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });

  const verdict = verifyRing1Diff({
    changedFiles,
    getBaseContent: (p) => readGitBlob(mergeBase, p),
    getHeadContent: (p) => readGitBlob('HEAD', p),
  });

  if (!verdict.ok) {
    console.error('✖ Ring 1 Adapter-Only Diff Policy Gate FAILED:');
    for (const v of verdict.violations) {
      console.error(`  - ${v}`);
    }
    process.exit(1);
  }

  console.log(`✔ ${verdict.summary}`);
}
