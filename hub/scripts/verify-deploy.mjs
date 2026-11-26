#!/usr/bin/env node
// Post-deploy verification for the EdgeFetch hub Worker. Run from `hub/` after `wrangler deploy`:
//
//   node scripts/verify-deploy.mjs --version-id <uuid> --url https://<worker>.workers.dev [--tag vX.Y.Z]
//                                  [--expect-version X.Y.Z] [--worker edgefetch-hub] [--env production] [--timeout-ms 120000]
//
// A green deploy step is not proof of what is live (a skipped deploy once passed green). This fails unless:
//   1. the newest Cloudflare deployment routes 100% of traffic to exactly `--version-id` (the version just uploaded),
//   2. that version carries `--tag` when one is given (Cloudflare's `workers/tag` annotation),
//   3. live `GET /openapi.json` reports `--expect-version` (defaults to hub/package.json), and
//   4. live `GET /health` returns `{ ok: true }`.
// Live checks retry (cache-busted) until `--timeout-ms` to allow for edge propagation.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const hubRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) throw new Error(`unexpected argument: ${a}`);
    const key = a.slice(2);
    const val = argv[i + 1];
    if (val === undefined || val.startsWith('--')) throw new Error(`missing value for --${key}`);
    out[key] = val;
    i++;
  }
  return out;
}

function wranglerJson(args) {
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  const raw = execFileSync(npx, ['wrangler', ...args, '--json'], {
    cwd: hubRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  });
  const start = raw.search(/[[{]/);
  if (start < 0) throw new Error(`wrangler ${args.join(' ')} returned no JSON`);
  return JSON.parse(raw.slice(start));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJsonWithRetry(url, accept, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';
  for (;;) {
    try {
      const res = await fetch(`${url}${url.includes('?') ? '&' : '?'}_verify=${Date.now()}`, {
        headers: { accept: 'application/json', 'cache-control': 'no-cache' },
      });
      if (res.ok) {
        const body = await res.json();
        const verdict = accept(body);
        if (verdict === true) return body;
        last = verdict;
      } else {
        last = `HTTP ${res.status}`;
      }
    } catch (err) {
      last = err instanceof Error ? err.message : String(err);
    }
    if (Date.now() >= deadline) throw new Error(`${url}: ${last}`);
    await sleep(5_000);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const versionId = args['version-id'];
  const baseUrl = (args.url ?? '').replace(/\/+$/, '');
  const worker = args.worker ?? 'edgefetch-hub';
  const env = args.env ?? 'production';
  const tag = args.tag;
  const timeoutMs = Number(args['timeout-ms'] ?? 120_000);
  const expectVersion = args['expect-version'] ?? JSON.parse(readFileSync(join(hubRoot, 'package.json'), 'utf8')).version;
  if (!/^[0-9a-f-]{36}$/.test(versionId ?? '')) throw new Error('--version-id must be the Worker Version ID printed by wrangler deploy');
  if (!/^https:\/\/[^/]+$/.test(baseUrl)) throw new Error('--url must be the deployed https:// origin');

  const checks = [];
  const fail = (msg) => {
    checks.push(`FAIL ${msg}`);
  };
  const pass = (msg) => {
    checks.push(`ok   ${msg}`);
  };

  // 1. Newest deployment routes 100% of traffic to the version that was just uploaded.
  const deployments = wranglerJson(['deployments', 'list', '--name', worker, '-e', env]);
  const newest = [...deployments].sort((a, b) => Date.parse(b.created_on) - Date.parse(a.created_on))[0];
  const split = newest?.versions ?? [];
  if (split.length === 1 && split[0].version_id === versionId && split[0].percentage === 100) {
    pass(`newest deployment ${newest.id} (${newest.created_on}) serves ${versionId} at 100%`);
  } else {
    fail(`newest deployment ${newest?.id ?? '(none)'} serves ${JSON.stringify(split)}, expected ${versionId} at 100%`);
  }

  // 2. The version carries the release tag (when given).
  if (tag) {
    const version = wranglerJson(['versions', 'view', versionId, '--name', worker, '-e', env]);
    const actualTag = version?.annotations?.['workers/tag'];
    if (actualTag === tag) pass(`version ${versionId} is tagged ${tag}`);
    else fail(`version ${versionId} tag is ${JSON.stringify(actualTag)}, expected ${tag}`);
  }

  // 3. The live Worker runs code reporting the expected release version.
  try {
    const spec = await fetchJsonWithRetry(
      `${baseUrl}/openapi.json`,
      (body) => (body?.info?.version === expectVersion ? true : `live openapi info.version is ${JSON.stringify(body?.info?.version)}`),
      timeoutMs,
    );
    pass(`live /openapi.json reports version ${spec.info.version}`);
  } catch (err) {
    fail(`live version check: ${err instanceof Error ? err.message : String(err)} (expected ${expectVersion})`);
  }

  // 4. The live Worker is healthy.
  try {
    await fetchJsonWithRetry(`${baseUrl}/health`, (body) => (body?.ok === true ? true : `health body ${JSON.stringify(body)}`), timeoutMs);
    pass('live /health returns ok');
  } catch (err) {
    fail(`live health check: ${err instanceof Error ? err.message : String(err)}`);
  }

  console.log(checks.join('\n'));
  if (checks.some((c) => c.startsWith('FAIL'))) {
    console.error(`::error title=Post-deploy verification failed::${worker} did not verify as ${tag ?? expectVersion} (${versionId}).`);
    process.exit(1);
  }
  console.log(`Verified: ${worker} ${tag ?? expectVersion} (${versionId}) is live.`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
