#!/usr/bin/env node
// Release version tooling: keeps the repository's version lockstep consistent and drafts the changelog.
//
//   node scripts/release-version.mjs check
//       Verifies every lockstep file carries the current version (addon/config.yaml is the source of truth),
//       that server.json pins the matching agent image, and that CHANGELOG.md == addon/CHANGELOG.md with a
//       `## [<version>]` heading. Run by CI on every PR so drift is caught before a `v*` tag is pushed.
//
//   node scripts/release-version.mjs bump <patch|minor|major|X.Y.Z> [--date YYYY-MM-DD] [--dry-run]
//       Rewrites the current version to the next one in every lockstep file and prepends a changelog section
//       drafted from commit subjects since tag `v<current>` (edit it before merging), then syncs
//       addon/CHANGELOG.md. It does not commit, tag, push, or deploy: pushing the `v*` tag stays a manual
//       maintainer step (tags are admin-only and trigger the signed release + production hub deploy).

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

// Files whose version markers move in lockstep (same set as the v2.8.0 / v2.8.1 release bumps).
// Every occurrence of the current version string in these files is a version marker and is rewritten.
export const LOCKSTEP_FILES = [
  'Dockerfile',
  'Dockerfile.agent',
  'Dockerfile.all-in-one',
  'Makefile',
  'addon/Dockerfile',
  'addon/config.yaml',
  'compose.agent.yaml',
  'docs/openapi.json',
  'extensions/browser-clipper/manifest.json',
  'extensions/browser-clipper/offscreen.js',
  'hub/package.json',
  'hub/src/dev-telemetry.ts',
  'hub/src/mcp-federation.ts',
  'hub/src/openapi.ts',
  'hub/src/otel.ts',
  'hub/src/storage.ts',
  'hub/src/update-check.ts',
  'hub/test/hub.test.ts',
  'hub/test/live-mcp-audit.test.ts',
  'hub/test/updates-telemetry.test.ts',
  'internal/agent/agent.go',
  'internal/hub/hubauth/admin_html.go',
  'internal/otel/otlp.go',
  'internal/otel/otlp_test.go',
  'server.json',
];
// Only the root package entries of the lockfile carry the hub version; dependency versions must not be touched.
const PACKAGE_LOCK = 'hub/package-lock.json';
const PACKAGE_LOCK_HEADER_LINES = 12;
const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)$/;

const read = (rel) => readFileSync(join(repoRoot, rel), 'utf8');
const write = (rel, text) => writeFileSync(join(repoRoot, rel), text);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function currentVersion() {
  const m = /^version:\s*"([^"]+)"/m.exec(read('addon/config.yaml'));
  if (!m || !SEMVER_RE.test(m[1])) throw new Error('addon/config.yaml has no semver `version: "X.Y.Z"` line');
  return m[1];
}

export function nextVersion(current, spec) {
  if (SEMVER_RE.test(spec)) return spec;
  const [maj, min, pat] = SEMVER_RE.exec(current).slice(1).map(Number);
  if (spec === 'patch') return `${maj}.${min}.${pat + 1}`;
  if (spec === 'minor') return `${maj}.${min + 1}.0`;
  if (spec === 'major') return `${maj + 1}.0.0`;
  throw new Error(`bump expects patch, minor, major or X.Y.Z (got "${spec}")`);
}

function compareSemver(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

function lockstepProblems(version) {
  const problems = [];
  const re = new RegExp(`(?<![\\d.])${escapeRe(version)}(?![\\d])`);
  for (const rel of LOCKSTEP_FILES) {
    if (!re.test(read(rel))) problems.push(`${rel}: does not contain version ${version}`);
  }
  const agent = /^var\s+Version\s*=\s*"([^"]+)"/m.exec(read('internal/agent/agent.go'))?.[1];
  if (agent !== version) problems.push(`internal/agent/agent.go: Version is ${agent ?? '(missing)'}, expected ${version}`);
  const hubPkg = JSON.parse(read('hub/package.json')).version;
  if (hubPkg !== version) problems.push(`hub/package.json: version is ${hubPkg}, expected ${version}`);
  const lock = JSON.parse(read(PACKAGE_LOCK));
  if (lock.version !== version || lock.packages?.['']?.version !== version) {
    problems.push(`${PACKAGE_LOCK}: root version is ${lock.version}/${lock.packages?.['']?.version}, expected ${version}`);
  }
  const server = JSON.parse(read('server.json'));
  if (server.version !== version) problems.push(`server.json: version is ${server.version}, expected ${version}`);
  const image = server.packages?.[0]?.identifier;
  if (image !== `ghcr.io/bartrumb/edgefetch-agent:${version}`) {
    problems.push(`server.json: packages[0].identifier is ${image}, expected ghcr.io/bartrumb/edgefetch-agent:${version}`);
  }
  const changelog = read('CHANGELOG.md');
  if (changelog !== read('addon/CHANGELOG.md')) problems.push('addon/CHANGELOG.md is out of sync with CHANGELOG.md');
  if (!changelog.includes(`## [${version}]`)) problems.push(`CHANGELOG.md: missing release heading "## [${version}]"`);
  return problems;
}

function gitSubjectsSince(tag) {
  try {
    execFileSync('git', ['rev-parse', '--verify', '--quiet', `refs/tags/${tag}`], { cwd: repoRoot, stdio: 'ignore' });
  } catch {
    return null;
  }
  const out = execFileSync('git', ['log', '--no-merges', '--format=%s', `${tag}..HEAD`], { cwd: repoRoot, encoding: 'utf8' });
  return out.split('\n').map((s) => s.trim()).filter(Boolean);
}

export function draftChangelogSection(version, date, subjects) {
  const groups = { Added: [], Fixed: [], Security: [], Changed: [] };
  for (const subject of subjects ?? []) {
    if (/^chore\(release\)/i.test(subject)) continue;
    const m = /^(\w+)(?:\([^)]*\))?!?:\s*(.+)$/.exec(subject);
    const type = m?.[1]?.toLowerCase() ?? '';
    const text = (m?.[2] ?? subject).trim();
    const group = type === 'feat' ? 'Added' : type === 'fix' ? 'Fixed' : type === 'security' ? 'Security' : 'Changed';
    groups[group].push(`- ${text}`);
  }
  let section = `## [${version}] - ${date}\n`;
  let any = false;
  for (const [name, items] of Object.entries(groups)) {
    if (items.length === 0) continue;
    any = true;
    section += `\n### ${name}\n${items.join('\n')}\n`;
  }
  if (!any) section += '\n### Changed\n- _Describe the changes in this release._\n';
  return `${section}\n`;
}

function bump(spec, { date, dryRun }) {
  const from = currentVersion();
  const to = nextVersion(from, spec);
  if (compareSemver(to, from) <= 0) throw new Error(`new version ${to} must be greater than current ${from}`);
  const before = lockstepProblems(from).filter((p) => !p.startsWith('CHANGELOG.md: missing'));
  if (before.length > 0) {
    throw new Error(`current version ${from} is not in lockstep; fix these first:\n  ${before.join('\n  ')}`);
  }

  const fromRe = new RegExp(`(?<![\\d.])${escapeRe(from)}(?![\\d])`, 'g');
  const changed = [];
  for (const rel of LOCKSTEP_FILES) {
    const text = read(rel);
    const next = text.replace(fromRe, to);
    if (next !== text) {
      changed.push(rel);
      if (!dryRun) write(rel, next);
    }
  }
  const lockLines = read(PACKAGE_LOCK).split('\n');
  for (let i = 0; i < Math.min(PACKAGE_LOCK_HEADER_LINES, lockLines.length); i++) {
    lockLines[i] = lockLines[i].replace(`"version": "${from}"`, `"version": "${to}"`);
  }
  if (!dryRun) write(PACKAGE_LOCK, lockLines.join('\n'));
  changed.push(PACKAGE_LOCK);

  const changelog = read('CHANGELOG.md');
  if (changelog.includes(`## [${to}]`)) throw new Error(`CHANGELOG.md already has a "## [${to}]" section`);
  const firstRelease = changelog.indexOf('\n## [');
  if (firstRelease < 0) throw new Error('CHANGELOG.md has no existing "## [" release heading to insert before');
  const subjects = gitSubjectsSince(`v${from}`);
  const section = draftChangelogSection(to, date, subjects);
  const nextChangelog = `${changelog.slice(0, firstRelease + 1)}${section}${changelog.slice(firstRelease + 1)}`;
  if (!dryRun) {
    write('CHANGELOG.md', nextChangelog);
    write('addon/CHANGELOG.md', nextChangelog);
  }
  changed.push('CHANGELOG.md', 'addon/CHANGELOG.md');

  console.log(`${dryRun ? '[dry-run] ' : ''}Bumped ${from} -> ${to} in ${changed.length} files.`);
  if (subjects === null) console.log(`Tag v${from} not found locally; changelog section is a placeholder (git fetch --tags).`);
  else console.log(`Drafted CHANGELOG.md [${to}] from ${subjects.length} commit subject(s) since v${from}; edit it before merging.`);
  if (!dryRun) {
    const after = lockstepProblems(to);
    if (after.length > 0) throw new Error(`post-bump lockstep check failed:\n  ${after.join('\n  ')}`);
    console.log(`Lockstep check passed for ${to}. After the release PR merges, a maintainer pushes tag v${to}.`);
  }
}

function main(argv) {
  const [cmd, arg, ...rest] = argv;
  if (cmd === 'check') {
    const version = currentVersion();
    const problems = lockstepProblems(version);
    if (problems.length > 0) {
      console.error(`Version lockstep check failed for ${version}:\n  ${problems.join('\n  ')}`);
      process.exit(1);
    }
    console.log(`Version lockstep OK: ${version} across ${LOCKSTEP_FILES.length + 1} files; changelogs in sync.`);
    return;
  }
  if (cmd === 'bump' && arg) {
    const dateIdx = rest.indexOf('--date');
    const date = dateIdx >= 0 ? rest[dateIdx + 1] : new Date().toISOString().slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date ?? '')) throw new Error('--date must be YYYY-MM-DD');
    bump(arg, { date, dryRun: rest.includes('--dry-run') });
    return;
  }
  console.error('usage: node scripts/release-version.mjs check | bump <patch|minor|major|X.Y.Z> [--date YYYY-MM-DD] [--dry-run]');
  process.exit(2);
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
