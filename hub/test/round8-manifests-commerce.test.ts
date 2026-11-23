import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import compiledBundleJson from '../../internal/extract/manifests/compiled.json';
import {
  getRegistrableDomain as compilerGetReg,
  hasPrivateSharedHostingSuffix as compilerHasPriv,
  isPublicOrPrivateSuffix as compilerIsSuffix,
  matchesApprovedWildcard as compilerWildcardMatch,
  validateManifestSet,
} from '../scripts/compile-manifests.mjs';
import {
  buildDeclarativeCatalogSpec,
  VALID_CATALOG_PLATFORMS,
  type DeclarativeCatalogConfig,
} from '../src/extractors/commerce-engine.ts';
import {
  compileDeclarativeAdapter,
  compileValidatedManifestSet,
  DECLARATIVE_SITE_ADAPTERS,
  matchesApprovedWildcard as runtimeWildcardMatch,
  parseDeclarativeManifest,
  type CompiledManifestBundle,
  type DeclarativeAdapterManifest,
} from '../src/extractors/declarative.ts';
import {
  getRegistrableDomain,
  hasPrivateSharedHostingSuffix,
  isPublicOrPrivateSuffix,
} from '../src/psl.ts';
import { PUBLIC_SUFFIX_LIST_DAT } from '../src/psl-data.ts';

const COMPILED_BUNDLE = compiledBundleJson as unknown as CompiledManifestBundle;
const hubRoot = process.env.EDGEFETCH_HUB_ROOT
  ? resolve(process.env.EDGEFETCH_HUB_ROOT)
  : resolve(dirname(fileURLToPath(import.meta.url)), '..');
const datPath = join(hubRoot, '..', 'internal', 'extract', 'manifests', 'public_suffix_list.dat');

test('R8-PSL-1: Vendored public_suffix_list.dat and psl-data.ts are byte-identical and enforce exact, wildcard, exception, IDN, and PRIVATE DOMAINS rules', () => {
  const onDiskDat = readFileSync(datPath, 'utf8').replace(/\r\n/g, '\n');
  assert.equal(PUBLIC_SUFFIX_LIST_DAT, onDiskDat, 'hub/src/psl-data.ts must match public_suffix_list.dat byte-for-byte');
  assert.ok(onDiskDat.includes('// ===BEGIN ICANN DOMAINS==='));
  assert.ok(onDiskDat.includes('// ===BEGIN PRIVATE DOMAINS==='));

  const cases: Array<[string, string | null, boolean, boolean]> = [
    ['en.wikipedia.org', 'wikipedia.org', false, false],
    ['com', null, true, false],
    ['co.uk', null, true, false],
    ['bbc.co.uk', 'bbc.co.uk', false, false],
    ['ck', null, true, false],
    ['foo.ck', null, true, false],
    ['bar.foo.ck', 'bar.foo.ck', false, false],
    ['www.ck', 'www.ck', false, false],
    ['sub.www.ck', 'www.ck', false, false],
    ['other.kobe.jp', null, true, false],
    ['city.kobe.jp', 'city.kobe.jp', false, false],
    ['ward.city.kobe.jp', 'city.kobe.jp', false, false],
    ['supabase.co', null, true, true],
    ['evil.supabase.co', 'evil.supabase.co', false, true],
    ['workers.dev', null, true, true],
    ['foo.workers.dev', 'foo.workers.dev', false, true],
    ['github.io', null, true, true],
    ['bar.github.io', 'bar.github.io', false, true],
    ['s3.amazonaws.com', null, true, true],
    ['bucket.s3.amazonaws.com', 'bucket.s3.amazonaws.com', false, true],
    ['eu.platformsh.site', null, true, true],
    ['app.eu.platformsh.site', 'app.eu.platformsh.site', false, true],
    ['vercel.app', null, true, true],
    ['x.vercel.app', 'x.vercel.app', false, true],
    ['fly.dev', null, true, true],
    ['y.fly.dev', 'y.fly.dev', false, true],
    ['ngrok-free.app', null, true, true],
    ['z.ngrok-free.app', 'z.ngrok-free.app', false, true],
    ['食狮.com.cn', 'xn--85x722f.com.cn', false, false],
    ['食狮.中国', 'xn--85x722f.xn--fiqs8s', false, false],
    ['中国', null, true, false],
  ];

  for (const [host, wantReg, wantSuf, wantPriv] of cases) {
    assert.equal(getRegistrableDomain(host), wantReg, `runtime getRegistrableDomain(${host})`);
    assert.equal(compilerGetReg(host), wantReg, `compiler getRegistrableDomain(${host})`);
    assert.equal(isPublicOrPrivateSuffix(host), wantSuf, `runtime isPublicOrPrivateSuffix(${host})`);
    assert.equal(compilerIsSuffix(host), wantSuf, `compiler isPublicOrPrivateSuffix(${host})`);
    assert.equal(hasPrivateSharedHostingSuffix(host), wantPriv, `runtime hasPrivateSharedHostingSuffix(${host})`);
    assert.equal(compilerHasPriv(host), wantPriv, `compiler hasPrivateSharedHostingSuffix(${host})`);
  }
});

test('R8-H7-1: matchesApprovedWildcard matches identically in compiler and runtime across all 3 allowlisted shapes', () => {
  const mustMatch: Array<[string, string]> = [
    ['*.wikipedia.org', 'en.wikipedia.org'],
    ['*.wikipedia.org', 'a.b.wikipedia.org'],
    ['*.wikipedia.org', '*.sub.wikipedia.org'],
    ['careers.*.com', 'careers.stripe.com'],
    ['jobs.*.com', 'jobs.stripe.com'],
    ['gitlab.*', 'gitlab.company.org'],
    ['gitlab.*', 'gitlab.eu.company.org'],
  ];
  for (const [w, cand] of mustMatch) {
    assert.equal(compilerWildcardMatch(w, cand), true, `compiler expected match for ${w} vs ${cand}`);
    assert.equal(runtimeWildcardMatch(w, cand), true, `runtime expected match for ${w} vs ${cand}`);
  }

  const mustNotMatch: Array<[string, string]> = [
    ['*.wikipedia.org', '*.wikimedia.org'],
    ['*.wikipedia.org', 'wikipedia.org'],
    ['careers.*.com', 'careers.com'],
    ['jobs.*.com', 'jobs.org'],
    ['gitlab.*', 'mygitlab.org'],
    ['api.example.com', 'app.example.com'],
  ];
  for (const [w, cand] of mustNotMatch) {
    assert.equal(compilerWildcardMatch(w, cand), false, `compiler expected NO match for ${w} vs ${cand}`);
    assert.equal(runtimeWildcardMatch(w, cand), false, `runtime expected NO match for ${w} vs ${cand}`);
  }
});

test('R8-H7-2: Compiler & runtime reject exact-subdomain hijack of *.wikipedia.org, careers.*.com, jobs.*.com, and gitlab.*', () => {
  assert.equal(DECLARATIVE_SITE_ADAPTERS.length, 56);
  assert.doesNotThrow(() =>
    validateManifestSet(COMPILED_BUNDLE.manifests.map((obj) => ({ obj, label: `${obj.id}.yaml` }))),
  );

  const makeRogue = (id: string, domain: string, fetchUrl: string): DeclarativeAdapterManifest => ({
    id,
    name: 'Rogue Hijack Adapter',
    category: 'developer',
    description: 'Attempts to hijack an existing wildcard adapter domain.',
    domains: [domain],
    exampleUrls: ['https://example.org/wiki/Bank_account'],
    match: { pathSegments: ['wiki', { param: 'title', charset: 'pkg' }] },
    twin: { id: `${id}-twin`, fetchUrl, kind: 'json', accept: 'application/json' },
    extract: { titleTemplate: 'Hijacked', vars: { b: { paths: ['body'] } }, bodyVar: 'b' },
  });

  const attacks: DeclarativeAdapterManifest[] = [
    makeRogue('evil-wiki', 'en.wikipedia.org', 'https://en.wikipedia.org/api/rest_v1/page/summary/{title}'),
    makeRogue('evil-careers', 'careers.stripe.com', 'https://careers.stripe.com/api/jobs'),
    makeRogue('evil-jobs', 'jobs.stripe.com', 'https://jobs.stripe.com/api/jobs'),
    makeRogue('evil-gitlab', 'gitlab.company.org', 'https://gitlab.company.org/api/v4/projects'),
  ];

  for (const atk of attacks) {
    assert.throws(
      () => compileValidatedManifestSet([...COMPILED_BUNDLE.manifests, atk]),
      /overlap|collides/i,
      `Runtime compileValidatedManifestSet must reject ${atk.id} (${atk.domains[0]})`,
    );
    assert.throws(
      () =>
        validateManifestSet([
          ...COMPILED_BUNDLE.manifests.map((obj) => ({ obj, label: `${obj.id}.yaml` })),
          { obj: atk, label: `${atk.id}.yaml` },
        ]),
      /overlap/i,
      `Compiler validateManifestSet must reject ${atk.id} (${atk.domains[0]})`,
    );
  }

  // Unapproved cross-domain twin.fetchUrl collector host rejected in both compiler and runtime
  const exfil = makeRogue('exfil-collector', 'victim-bank.org', 'https://collector.attacker-host.net/steal');
  assert.throws(() => compileValidatedManifestSet([exfil]), /cross-domain twin host/i);
  assert.throws(() => validateManifestSet([{ obj: exfil, label: 'exfil.yaml' }]), /cross-domain twin host/i);
});

test('R8-H7-3: PSL PRIVATE DOMAINS shared multi-tenant PaaS/BaaS/tunnel suffixes are rejected for both wildcards and exact tenant subdomains', () => {
  const forbiddenDomains = [
    '*.github.io',
    'victim.github.io',
    '*.gitlab.io',
    'docs.gitlab.io',
    '*.bitbucket.io',
    '*.codeberg.page',
    'org.codeberg.page',
    '*.pages.dev',
    'app.pages.dev',
    '*.workers.dev',
    'fn.workers.dev',
    'pub.r2.dev',
    'tun.trycloudflare.com',
    'site.vercel.app',
    'old.now.sh',
    'demo.netlify.app',
    'web.herokuapp.com',
    'api.fly.dev',
    'svc.onrender.com',
    'web.up.railway.app',
    'bot.replit.app',
    'bot.repl.co',
    'edge.deno.dev',
    'db.supabase.co',
    'db.supabase.in',
    'fn.convex.site',
    'fn.convex.cloud',
    'static.surge.sh',
    'ui.web.app',
    'ui.firebaseapp.com',
    'gae.appspot.com',
    'fn.cloudfunctions.net',
    'svc.run.app',
    'svc1.a.run.app',
    'bucket.s3.amazonaws.com',
    'd111.cloudfront.net',
    'app.azurewebsites.net',
    'ui.azurestaticapps.net',
    'tun.ngrok.io',
    'tun.ngrok-free.app',
    'tun.ngrok.app',
    'blog.blogspot.com',
    'app.eu.platformsh.site',
  ];

  for (const dom of forbiddenDomains) {
    const m: DeclarativeAdapterManifest = {
      id: 'bad-shared-host',
      name: 'Bad Shared Host',
      category: 'developer',
      description: 'Attempts to claim a multi-tenant shared-hosting domain.',
      domains: [dom],
      exampleUrls: ['https://example.org/x'],
      match: { pathSegments: ['x'] },
      twin: { fetchUrl: '{requestUrl}', kind: 'json', accept: 'application/json' },
      extract: { titleTemplate: 'T', vars: { x: { paths: ['x'] } }, bodyVar: 'x' },
    };
    assert.throws(() => parseDeclarativeManifest(m), /forbidden/i, `Expected runtime rejection for ${dom}`);
    assert.throws(
      () => validateManifestSet([{ obj: m, label: 'bad.yaml' }]),
      /forbidden/i,
      `Expected compiler rejection for ${dom}`,
    );
  }
});

test('R8-H7-4: Strict catalog.platform allowlist rejects unknown platforms instead of silently falling through to WooCommerce', () => {
  assert.deepEqual([...VALID_CATALOG_PLATFORMS].sort(), ['shopify', 'woocommerce']);

  const shopSpec = buildDeclarativeCatalogSpec({ platform: 'shopify', pauseMs: 1000, pageCap: 5 });
  assert.equal(shopSpec.platform, 'shopify');

  const wooSpec = buildDeclarativeCatalogSpec({ platform: 'woocommerce', pauseMs: 1000, pageCap: 5 });
  assert.equal(wooSpec.platform, 'woocommerce');

  for (const badPlatform of ['magento', 'bigcommerce', 'prestashop', '', undefined, null]) {
    assert.throws(
      () =>
        buildDeclarativeCatalogSpec({
          platform: badPlatform as unknown as DeclarativeCatalogConfig['platform'],
          pauseMs: 1000,
          pageCap: 5,
        }),
      /Unsupported declarative catalog platform/i,
    );

    const badManifest = {
      id: 'bad-commerce',
      name: 'Bad Commerce',
      category: 'commerce-social',
      description: 'Manifest with an unsupported catalog platform.',
      domains: ['shop.example.org'],
      exampleUrls: ['https://shop.example.org/products'],
      catalog: {
        platform: badPlatform as unknown as 'shopify',
        pauseMs: 1000,
        pageCap: 5,
      },
    } satisfies DeclarativeAdapterManifest;

    assert.throws(() => parseDeclarativeManifest(badManifest), /catalog\.platform/i);
    assert.throws(() => compileDeclarativeAdapter(badManifest), /catalog\.platform/i);
    assert.throws(() => compileValidatedManifestSet([badManifest]), /catalog\.platform/i);
    assert.throws(() => validateManifestSet([{ obj: badManifest, label: 'bad-commerce.yaml' }]), /catalog\.platform/i);
  }
});
