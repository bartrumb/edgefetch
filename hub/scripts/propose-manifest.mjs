#!/usr/bin/env node
/**
 * Offline Declarative YAML Site Adapter Proposer (`npm run adapter:propose -- <https-url>`).
 *
 * Inspects a public HTTPS page (or an offline `--html-file <path>` snapshot), detects:
 *  1. Same-origin JSON / RSS / Atom `<link rel="alternate">` twins (e.g. WordPress `/wp-json/wp/v2/...` or feeds)
 *  2. Embedded Schema.org `<script type="application/ld+json">` `@type`s
 *  3. Framework hydration containers (`__NEXT_DATA__`, `__NUXT_DATA__`, `data-page`, `ng-state`, `wix-viewer-model`)
 *  4. Repeating card/list/table CSS selectors (`>= 3` homogeneous item cards with anchor + heading)
 *
 * Emits a schema-valid declarative YAML manifest (`internal/extract/manifests/<id>.yaml`) + test fixture,
 * enforcing `M2` PSL registrable-domain guards, strict SSRF/DNS-pinned public IP checks, and `robots.txt` politeness.
 * Runs in dry-run stdout mode by default; pass `--write` to write files and run `compile-manifests.mjs --check`.
 */

import { execFileSync } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument as parseHtmlDom } from 'htmlparser2';
import { parseDocument as parseYamlDoc, stringify as stringifyYaml } from 'yaml';
import {
  checkAstSafety,
  getRegistrableDomain,
  hasPrivateSharedHostingSuffix,
  isPublicOrPrivateSuffix,
  validateManifest,
} from './compile-manifests.mjs';

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const hubRoot = resolve(scriptsDir, '..');
const repoRoot = resolve(hubRoot, '..');
const manifestsDir = resolve(repoRoot, 'internal', 'extract', 'manifests');
const fixturesDir = resolve(hubRoot, 'test', 'fixtures', 'adapters');

const VALID_CATEGORIES = new Set([
  'developer',
  'genai',
  'jobs',
  'finance',
  'public-records',
  'research-health',
  'commerce-social',
]);

function parseIpv4Octets(v4) {
  const parts = String(v4 ?? '').split('.');
  if (parts.length !== 4) return null;
  const nums = [];
  for (const p of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    nums.push(n);
  }
  return nums;
}

function isPublicGlobalIpv4Octets([a, b, c]) {
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // RFC 6598 CGNAT
  if (a === 169 && b === 254) return false; // Link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC 1918
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false; // IETF protocol / TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return false; // 6to4 relay anycast
  if (a === 192 && b === 168) return false; // RFC 1918
  if (a === 198 && (b === 18 || b === 19)) return false; // Benchmarking
  if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // Multicast / reserved / broadcast
  return true;
}

/**
 * Parses any `net.isIP(ip) === 6` address into eight 16-bit words (`0x0000..0xffff`).
 */
function parseIpv6Words(rawIp) {
  const zoneIdx = rawIp.indexOf('%');
  const clean = (zoneIdx >= 0 ? rawIp.slice(0, zoneIdx) : rawIp).toLowerCase();
  if (!clean) return null;

  let working = clean;
  let embeddedV4Words = null;
  if (working.includes('.')) {
    const lastColon = working.lastIndexOf(':');
    if (lastColon < 0) return null;
    const octets = parseIpv4Octets(working.slice(lastColon + 1));
    if (!octets) return null;
    embeddedV4Words = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    working = `${working.slice(0, lastColon)}:0:0`;
  }

  const dblParts = working.split('::');
  if (dblParts.length > 2) return null;

  const parseSide = (side) => {
    if (!side) return [];
    const tokens = side.split(':');
    const out = [];
    for (const tok of tokens) {
      if (!/^[0-9a-f]{1,4}$/.test(tok)) return null;
      out.push(parseInt(tok, 16));
    }
    return out;
  };

  let words;
  if (dblParts.length === 2) {
    const left = parseSide(dblParts[0]);
    const right = parseSide(dblParts[1]);
    if (!left || !right || left.length + right.length > 7) return null;
    const zeros = new Array(8 - left.length - right.length).fill(0);
    words = [...left, ...zeros, ...right];
  } else {
    words = parseSide(working);
    if (!words || words.length !== 8) return null;
  }

  if (embeddedV4Words) {
    words[6] = embeddedV4Words[0];
    words[7] = embeddedV4Words[1];
  }
  return words;
}

export function isPublicGlobalIp(ip) {
  const ver = isIP(ip);
  if (ver === 4) {
    const octets = parseIpv4Octets(ip);
    return octets ? isPublicGlobalIpv4Octets(octets) : false;
  }
  if (ver === 6) {
    const w = parseIpv6Words(ip);
    if (!w) return false;
    // IPv4-mapped IPv6 `::ffff:0:0/96` (`0:0:0:0:0:ffff:w6:w7`)
    if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0xffff) {
      return isPublicGlobalIpv4Octets([(w[6] >> 8) & 0xff, w[6] & 0xff, (w[7] >> 8) & 0xff, w[7] & 0xff]);
    }
    // Strictly require IANA Global Unicast `2000::/3` (`(w[0] & 0xe000) === 0x2000`), automatically rejecting
    // `::/128`, `::1/128`, IPv4-compatible `::/96`, `64:ff9b::/96` & `64:ff9b:1::/48` NAT64, `100::/64` discard,
    // `fc00::/7` ULA, `fe80::/10` link-local, `fec0::/10` site-local, and `ff00::/8` multicast (`MEDIUM-3`).
    if ((w[0] & 0xe000) !== 0x2000) return false;
    // Reject `2001:0000::/23` (IANA Special-Purpose: Teredo `2001::/32`, Benchmarking `2001:2::/48`, ORCHID/v2 `2001:10::/28`, `2001:20::/28`)
    if (w[0] === 0x2001 && w[1] < 0x0200) return false;
    // Reject `2001:0db8::/32` (RFC 3849 Documentation)
    if (w[0] === 0x2001 && w[1] === 0x0db8) return false;
    // Reject `2002::/16` (RFC 7526 deprecated 6to4 transition space, e.g. `2002:7f00:1::1` -> `127.0.0.1`)
    if (w[0] === 0x2002) return false;
    return true;
  }
  return false;
}

export function validateProposeTargetUrl(rawUrl) {
  const trimmed = String(rawUrl ?? '').trim();
  if (!trimmed || /[\s\\\u0000-\u001f\u007f]/.test(trimmed)) {
    return { ok: false, error: 'URL must be a clean https:// URL without control characters or whitespace.' };
  }
  let u;
  try {
    u = new URL(trimmed);
  } catch {
    return { ok: false, error: 'Malformed URL.' };
  }
  if (u.protocol !== 'https:') {
    return { ok: false, error: 'Only https:// URLs are permitted.' };
  }
  if (u.username || u.password) {
    return { ok: false, error: 'Embedded URL credentials are not permitted.' };
  }
  if (u.port && u.port !== '443') {
    return { ok: false, error: 'Only standard HTTPS port 443 is permitted.' };
  }
  const host = u.hostname.toLowerCase().replace(/\.+$/, '');
  if (
    !host ||
    !host.includes('.') ||
    isIP(host) !== 0 ||
    host.includes(':') ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.nip.io') ||
    host.endsWith('.sslip.io') ||
    host.endsWith('.xip.io')
  ) {
    return { ok: false, error: `Disallowed non-public or IP-literal hostname "${host}".` };
  }
  const reg = getRegistrableDomain(host);
  if (!reg || isPublicOrPrivateSuffix(host)) {
    return { ok: false, error: `Hostname "${host}" is a bare public/private suffix without a registrable label.` };
  }
  if (hasPrivateSharedHostingSuffix(host)) {
    return {
      ok: false,
      error: `Hostname "${host}" uses a shared-hosting PSL private suffix; cross-tenant manifests are disallowed unless scoped to your exact tenant host.`,
    };
  }
  u.hash = '';
  return { ok: true, url: u, host, registrableDomain: reg };
}

async function resolveVerifiedPublicAddress(hostname) {
  const addrs = await lookup(hostname, { all: true, verbatim: true });
  if (!Array.isArray(addrs) || addrs.length === 0) {
    throw new Error(`DNS lookup returned no addresses for ${hostname}`);
  }
  for (const entry of addrs) {
    if (!isPublicGlobalIp(entry.address)) {
      throw new Error(`Blocked by SSRF guard: ${hostname} resolved to a non-public IP address`);
    }
  }
  return addrs[0];
}

function fetchHttpsOncePinned(targetUrl, pinnedAddr, accept, maxBytes = 2 * 1024 * 1024) {
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpsRequest(
      targetUrl,
      {
        method: 'GET',
        servername: targetUrl.hostname,
        timeout: 15_000,
        headers: {
          'User-Agent': 'EdgeFetch/2.7 (+https://edgefetch.dev/bot)',
          Accept: accept,
          'Accept-Encoding': 'identity',
        },
        lookup: (_host, opts, cb) => {
          if (opts && opts.all) {
            cb(null, [{ address: pinnedAddr.address, family: pinnedAddr.family }]);
          } else {
            cb(null, pinnedAddr.address, pinnedAddr.family);
          }
        },
      },
      (res) => {
        const chunks = [];
        let total = 0;
        res.on('data', (chunk) => {
          total += chunk.length;
          if (total > maxBytes) {
            req.destroy(new Error(`Response exceeded ${maxBytes} byte limit`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolvePromise({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
        res.on('error', rejectPromise);
      },
    );
    req.on('timeout', () => req.destroy(new Error('HTTPS request timed out')));
    req.on('error', rejectPromise);
    req.end();
  });
}

async function fetchPolitePublicHttps(initialUrl, accept) {
  let cur = new URL(initialUrl.toString());
  for (let hop = 0; hop <= 4; hop++) {
    const check = validateProposeTargetUrl(cur.toString());
    if (!check.ok) throw new Error(check.error);
    const pinned = await resolveVerifiedPublicAddress(check.host);

    if (hop === 0 || cur.origin !== initialUrl.origin) {
      const robotsUrl = new URL('/robots.txt', cur.origin);
      const robRes = await fetchHttpsOncePinned(robotsUrl, pinned, 'text/plain,*/*;q=0.8', 512 * 1024);
      if (robRes.status === 429 || robRes.status >= 500) {
        throw new Error(`robots.txt returned HTTP ${robRes.status} on ${cur.origin} (assuming disallow per RFC 9309)`);
      }
      if (robRes.status >= 200 && robRes.status < 300 && !isAllowedBySimpleRobots(robRes.body, cur.pathname + cur.search)) {
        throw new Error(`Disallowed by ${cur.origin}/robots.txt for path ${cur.pathname}`);
      }
    }

    const res = await fetchHttpsOncePinned(cur, pinned, accept);
    if ([301, 302, 303, 307, 308].includes(res.status) && typeof res.headers.location === 'string') {
      const next = new URL(res.headers.location, cur);
      cur = next;
      continue;
    }
    return { finalUrl: cur.toString(), status: res.status, headers: res.headers, body: res.body };
  }
  throw new Error('Exceeded maximum redirect hops (4)');
}

function isUnreservedAsciiByte(b) {
  return (
    (b >= 0x41 && b <= 0x5a) ||
    (b >= 0x61 && b <= 0x7a) ||
    (b >= 0x30 && b <= 0x39) ||
    b === 0x2d ||
    b === 0x2e ||
    b === 0x5f ||
    b === 0x7e
  );
}

/** Normalizes percent-encoding in `/robots.txt` rules and target paths per RFC 9309 §2.2.2 (`MEDIUM-3`). */
function normalizeRobotsUri(raw) {
  const bytes = Buffer.from(String(raw ?? ''), 'utf8');
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x25 && i + 2 < bytes.length) {
      const hex = String.fromCharCode(bytes[i + 1], bytes[i + 2]);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        const decoded = parseInt(hex, 16);
        out += isUnreservedAsciiByte(decoded) ? String.fromCharCode(decoded) : `%${hex.toUpperCase()}`;
        i += 2;
        continue;
      }
    }
    out += b >= 0x80 ? `%${b.toString(16).toUpperCase().padStart(2, '0')}` : String.fromCharCode(b);
  }
  return out;
}

function canonicalizeRobotsTargetPath(norm) {
  const qIdx = norm.indexOf('?');
  const pathPart = qIdx >= 0 ? norm.slice(0, qIdx) : norm;
  const queryPart = qIdx >= 0 ? norm.slice(qIdx) : '';
  if (pathPart.startsWith('/') && !pathPart.includes('//') && !pathPart.includes('/.') && !pathPart.includes(';')) {
    return norm;
  }
  const trailingSlash = pathPart.endsWith('/') || pathPart.endsWith('/.') || pathPart.endsWith('/..');
  const segs = [];
  for (let seg of pathPart.split('/')) {
    const semi = seg.indexOf(';');
    if (semi >= 0) seg = seg.slice(0, semi);
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (segs.length > 0) segs.pop();
      continue;
    }
    segs.push(seg);
  }
  return `/${segs.join('/')}${trailingSlash && segs.length > 0 ? '/' : ''}${queryPart}`;
}

export function isAllowedBySimpleRobots(robotsTxt, pathAndQuery) {
  const body = String(robotsTxt ?? '')
    .replace(/^[\uFEFF\u200B\u200C\u200D\u2060]+/, '')
    .replace(/\r\n|\r|\u0085|\u2028|\u2029/g, '\n');
  let sawSpecificEdgeFetch = false;
  let disallowAiInput = false;
  const wildcardRules = [];
  const edgeFetchRules = [];
  let currentGroupAgents = [];
  let seenDirective = false;

  for (const rawLine of body.split('\n')) {
    const clean = rawLine.replace(/#.*$/, '').trim();
    if (!clean) {
      // RFC 9309 §2.2.1: blank lines inside a User-agent group do NOT reset the group.
      continue;
    }
    const colon = clean.indexOf(':');
    if (colon <= 0) continue;
    const field = clean.slice(0, colon).trim().toLowerCase();
    const val = clean.slice(colon + 1).trim();
    if (field === 'user-agent') {
      if (seenDirective && currentGroupAgents.length > 0) {
        currentGroupAgents = [];
        seenDirective = false;
      }
      const uaToken = val.toLowerCase().split(/[\/\s]/)[0] || '';
      if (uaToken) currentGroupAgents.push(uaToken);
    } else if ((field === 'allow' || field === 'disallow') && currentGroupAgents.length > 0) {
      seenDirective = true;
      if (!val) continue;
      const normPat = normalizeRobotsUri(val);
      if (!normPat.startsWith('/') && !normPat.startsWith('*')) continue;
      for (const ua of currentGroupAgents) {
        if (ua.includes('edgefetch')) {
          sawSpecificEdgeFetch = true;
          edgeFetchRules.push({ allow: field === 'allow', pattern: normPat });
        } else if (ua === '*') {
          wildcardRules.push({ allow: field === 'allow', pattern: normPat });
        }
      }
    } else if (field === 'content-signal') {
      seenDirective = currentGroupAgents.length > 0 ? true : seenDirective;
      if (/\bai-input\s*=\s*["']?no["']?\b/i.test(val)) {
        if (currentGroupAgents.length === 0 || currentGroupAgents.some((ua) => ua === '*' || ua.includes('edgefetch'))) {
          disallowAiInput = true;
        }
      }
    }
  }

  if (disallowAiInput) return false;
  const rules = sawSpecificEdgeFetch ? edgeFetchRules : wildcardRules;
  if (rules.length === 0) return true;

  const evalSingleTarget = (target) => {
    let bestLen = -1;
    let bestAllow = true;
    for (const rule of rules) {
      const pat = rule.pattern;
      if (matchesRobotsPathPattern(target, pat)) {
        if (pat.length > bestLen || (pat.length === bestLen && rule.allow)) {
          bestLen = pat.length;
          bestAllow = rule.allow;
        }
      }
    }
    return bestAllow;
  };

  let rawTarget = String(pathAndQuery || '/');
  const hashIdx = rawTarget.indexOf('#');
  if (hashIdx >= 0) rawTarget = rawTarget.slice(0, hashIdx);
  if (!rawTarget) rawTarget = '/';
  const normRaw = normalizeRobotsUri(rawTarget);
  if (!evalSingleTarget(normRaw)) return false;
  const normCanon = canonicalizeRobotsTargetPath(normRaw);
  if (normCanon !== normRaw && !evalSingleTarget(normCanon)) return false;
  return true;
}

function matchesRobotsPathPattern(targetPath, rawPattern) {
  const anchoredEnd = rawPattern.endsWith('$');
  let pattern = anchoredEnd ? rawPattern.slice(0, -1) : rawPattern;
  if (pattern.includes('**')) {
    pattern = pattern.replace(/\*{2,}/g, '*');
  }
  if (!pattern.includes('*')) {
    return anchoredEnd ? targetPath === pattern : targetPath.startsWith(pattern);
  }
  const trailingStar = pattern.endsWith('*');
  const parts = pattern.split('*');
  let minLen = 0;
  let lastNonEmpty = '';
  for (const p of parts) {
    if (p) {
      minLen += p.length;
      lastNonEmpty = p;
    }
  }
  if (targetPath.length < minLen) return false;
  const firstLit = parts[0];
  if (firstLit && !targetPath.startsWith(firstLit)) return false;
  if (anchoredEnd && !trailingStar && lastNonEmpty && !targetPath.endsWith(lastNonEmpty)) {
    return false;
  }
  let pos = firstLit.length;
  let remLit = minLen - pos;
  for (let i = 1; i < parts.length; i++) {
    if (targetPath.length - pos < remLit) return false;
    const seg = parts[i];
    if (!seg) continue;
    const idx = targetPath.indexOf(seg, pos);
    if (idx < 0) return false;
    pos = idx + seg.length;
    remLit -= seg.length;
  }
  return true;
}

function walkDomElements(node, visit, state = { count: 0 }) {
  if (!node || state.count > 12_000) return;
  state.count++;
  if (node.type === 'tag' || node.type === 'script' || node.type === 'style') {
    visit(node);
  }
  if (Array.isArray(node.children)) {
    for (const ch of node.children) {
      walkDomElements(ch, visit, state);
      if (state.count > 12_000) break;
    }
  }
}

function getElementText(node, depth = 0) {
  if (!node || depth > 8) return '';
  if (node.type === 'text') return String(node.data ?? '');
  if (!Array.isArray(node.children)) return '';
  let out = '';
  for (const ch of node.children) {
    if (ch.type === 'script' || ch.type === 'style') continue;
    out += ` ${getElementText(ch, depth + 1)}`;
    if (out.length > 600) break;
  }
  return out.replace(/\s+/g, ' ').trim();
}

function sanitizeCssClassToken(rawClass) {
  const tokens = String(rawClass ?? '')
    .trim()
    .split(/\s+/)
    .filter((t) => /^[A-Za-z][A-Za-z0-9_-]{1,39}$/.test(t) && !/^(?:flex|grid|block|hidden|relative|absolute|w-|h-|p-|m-|px-|py-|text-|bg-|border)/.test(t));
  return tokens[0] ?? '';
}

function findFirstDescendantTag(node, tagSet, depth = 0) {
  if (!node || depth > 6 || !Array.isArray(node.children)) return null;
  for (const ch of node.children) {
    if (ch.type === 'tag' && tagSet.has(ch.name.toLowerCase())) return ch;
    const nested = findFirstDescendantTag(ch, tagSet, depth + 1);
    if (nested) return nested;
  }
  return null;
}

function sanitizeYamlCommentToken(raw, maxLen = 80) {
  const ascii = String(raw ?? '')
    .replace(/[^\x20-\x7e]+/g, '')
    .trim();
  if (!ascii) return '';
  const clean = ascii.replace(/[^A-Za-z0-9+_./:@?=&%-]+/g, '').slice(0, maxLen);
  return clean;
}

export function analyzeHtmlForManifestProposal({ html, urlStr, slugOverride, categoryOverride }) {
  const check = validateProposeTargetUrl(urlStr);
  if (!check.ok) {
    throw new Error(check.error);
  }
  const { url, host, registrableDomain } = check;
  const defaultSlug = registrableDomain
    .split('.')[0]
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'site-adapter';
  const id = (slugOverride ?? defaultSlug).trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{1,48}$/.test(id)) {
    throw new Error(`Invalid manifest id "${id}". Expected lowercase kebab-case.`);
  }
  const category = categoryOverride && VALID_CATEGORIES.has(categoryOverride) ? categoryOverride : inferCategoryFromUrlAndHtml(url, html);
  const titleLabel = id
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');

  const boundedHtml = String(html ?? '').slice(0, 1_500_000);
  const dom = parseHtmlDom(boundedHtml);

  const jsonLdTypes = new Set();
  const alternateFeeds = [];
  let wpRestUrl = '';
  const frameworkSignals = new Set();
  const repeatingCandidates = [];
  let pageH1 = '';
  let pageTitle = '';

  if (boundedHtml.includes('__NEXT_DATA__')) frameworkSignals.add('nextjs');
  if (boundedHtml.includes('__next_f.push')) frameworkSignals.add('nextjs-rsc');
  if (boundedHtml.includes('__NUXT_DATA__')) frameworkSignals.add('nuxt');
  if (boundedHtml.includes('data-page=')) frameworkSignals.add('inertia');
  if (boundedHtml.includes('id="ng-state"')) frameworkSignals.add('angular');
  if (boundedHtml.includes('id="wix-viewer-model"')) frameworkSignals.add('wix');

  walkDomElements(dom, (el) => {
    const tag = el.name.toLowerCase();
    const attrs = el.attribs ?? {};
    if (tag === 'title' && !pageTitle) {
      pageTitle = getElementText(el);
    } else if (tag === 'h1' && !pageH1) {
      pageH1 = getElementText(el);
    } else if (tag === 'link') {
      const rel = String(attrs.rel ?? '').toLowerCase();
      const rawType = String(attrs.type ?? '').toLowerCase().split(';')[0].trim();
      const safeType = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(rawType) ? rawType.slice(0, 64) : '';
      const href = String(attrs.href ?? '').trim();
      if (rel.split(/\s+/).includes('alternate') && href && safeType) {
        try {
          const resolved = new URL(href, url.toString());
          resolved.hash = '';
          if (
            resolved.protocol === 'https:' &&
            !resolved.username &&
            !resolved.password &&
            (!resolved.port || resolved.port === '443') &&
            resolved.hostname.toLowerCase() === host
          ) {
            if (safeType === 'application/json' && /^\/wp-json\/wp\/v2\/(?:posts|pages)\/\d+\/?$/.test(resolved.pathname)) {
              wpRestUrl = resolved.toString();
            } else if (safeType.includes('rss') || safeType.includes('atom') || safeType === 'application/json') {
              alternateFeeds.push({ type: safeType, url: resolved.toString() });
            }
          }
        } catch {
          // ignore invalid link href
        }
      }
    } else if (tag === 'script') {
      const type = String(attrs.type ?? '').toLowerCase();
      if (type.includes('application/ld+json')) {
        const raw = getElementText(el);
        try {
          const parsed = JSON.parse(raw);
          collectJsonLdTypeNames(parsed, jsonLdTypes, 0);
        } catch {
          // ignore malformed JSON-LD
        }
      }
    }

    // Inspect repeating card children under container elements
    if (Array.isArray(el.children) && el.children.length >= 3) {
      const bySig = new Map();
      for (const ch of el.children) {
        if (ch.type !== 'tag') continue;
        const chTag = ch.name.toLowerCase();
        if (!['article', 'li', 'tr', 'div', 'section'].includes(chTag)) continue;
        const cls = sanitizeCssClassToken(ch.attribs?.class);
        const sig = cls ? `${chTag}.${cls}` : chTag;
        if (sig === 'div' || sig === 'section') continue; // Require semantic tag or class token
        const list = bySig.get(sig) ?? [];
        list.push(ch);
        bySig.set(sig, list);
      }
      for (const [sig, items] of bySig.entries()) {
        if (items.length < 3 || items.length > 200) continue;
        let withAnchor = 0;
        let headingSel = '';
        for (const item of items.slice(0, 10)) {
          const a = findFirstDescendantTag(item, new Set(['a']));
          const h = findFirstDescendantTag(item, new Set(['h1', 'h2', 'h3', 'h4']));
          if (a?.attribs?.href) withAnchor++;
          if (!headingSel && h) headingSel = h.name.toLowerCase();
        }
        if (withAnchor >= Math.ceil(Math.min(items.length, 10) * 0.7)) {
          const parentCls = sanitizeCssClassToken(attrs.class);
          const parentRootSel =
            attrs.id && /^[A-Za-z][A-Za-z0-9_-]{1,39}$/.test(attrs.id)
              ? `#${attrs.id}`
              : parentCls
                ? `${tag}.${parentCls}`
                : '';
          const containerSel = parentRootSel ? `${parentRootSel} ${sig}` : sig;
          repeatingCandidates.push({
            parentSelector: parentRootSel,
            itemSelector: containerSel,
            count: items.length,
            titleSelector: headingSel || 'a',
            sampleTitle: getElementText(findFirstDescendantTag(items[0], new Set(['h1', 'h2', 'h3', 'h4', 'a'])) || items[0]).slice(0, 100),
          });
        }
      }
    }
  });

  repeatingCandidates.sort((a, b) => b.count - a.count);
  const topList = repeatingCandidates[0] ?? null;
  const pathSegments = url.pathname.split('/').filter(Boolean);
  const firstSeg = pathSegments[0] && /^[a-z0-9_-]{1,32}$/i.test(pathSegments[0]) ? `/${pathSegments[0]}` : undefined;
  const safeDetectedLd = [...jsonLdTypes].filter((t) => /^[A-Za-z][A-Za-z0-9_-]{1,48}$/.test(t)).slice(0, 6);

  let manifestObj;
  let fixtureObj;

  if (topList) {
    const itemHeadingSel = `${topList.itemSelector} ${topList.titleSelector}`;
    const bodySelectors = [
      ...(topList.parentSelector ? [topList.parentSelector] : []),
      'main',
      'article',
      '[role="main"]',
    ];
    manifestObj = {
      id,
      name: titleLabel,
      category,
      description: `Extracts structured listing cards from ${host} HTML pages using declarative CSS selectors.`,
      domains: [host],
      exampleUrls: [url.toString()],
      htmlRoutes: [
        {
          id: `${id}-list`,
          match: {
            ...(firstSeg ? { pathPrefix: firstSeg } : { minSegments: 0 }),
          },
          mode: 'dom',
          vars: {
            title: {
              cssText: ['h1', 'title'],
              metaKeys: ['og:title'],
              trim: true,
            },
            items: {
              cssAllText: {
                selector: itemHeadingSel,
                limit: 50,
                dedupe: true,
                join: '\n- ',
              },
            },
            body: {
              cssHtmlToMd: bodySelectors,
            },
          },
          requireVars: ['items'],
          titleTemplate: '{title}',
          titleWhenVar: 'title',
          titleFallbackTemplate: `${titleLabel} Listings`,
          sections: [
            {
              heading: 'Listings',
              textVar: 'body',
            },
          ],
        },
      ],
    };
    fixtureObj = {
      adapterId: id,
      mode: 'html',
      inputUrl: url.toString(),
      mockPayload: `<!doctype html><html><head><title>${escapeBasicHtml(titleLabel)} Listings</title></head><body><main><div id="jobs-list"><article class="job-card"><h2><a href="/item-1">Sample ${escapeBasicHtml(titleLabel)} 1</a></h2></article><article class="job-card"><h2><a href="/item-2">Sample ${escapeBasicHtml(titleLabel)} 2</a></h2></article><article class="job-card"><h2><a href="/item-3">Sample ${escapeBasicHtml(titleLabel)} 3</a></h2></article></div></main></body></html>`,
      expectTitleIncludes: `${titleLabel} Listings`,
      expectMarkdownIncludes: [`Sample ${titleLabel} 1`],
    };
  } else {
    manifestObj = {
      id,
      name: titleLabel,
      category,
      description: `Extracts structured content from ${host} pages using declarative CSS selectors and Schema.org JSON-LD.`,
      domains: [host],
      exampleUrls: [url.toString()],
      htmlRoutes: [
        {
          id,
          match: {
            ...(firstSeg ? { pathPrefix: firstSeg } : { minSegments: 1 }),
          },
          mode: 'dom',
          jsonLdTypes: safeDetectedLd.length > 0 ? safeDetectedLd : ['Article', 'WebPage', 'JobPosting', 'Product'],
          vars: {
            title: {
              jsonLdPaths: ['headline', 'name'],
              cssText: ['h1'],
              metaKeys: ['og:title'],
              trim: true,
            },
            summary: {
              jsonLdPaths: ['description'],
              metaKeys: ['description', 'og:description'],
              trim: true,
            },
            body: {
              cssHtmlToMd: ['article', 'main', '[role="main"]'],
            },
          },
          requireVars: ['title'],
          titleTemplate: '{title}',
          descriptionVar: 'summary',
          introVar: 'summary',
          bodyVar: 'body',
        },
      ],
    };
    const sampleHeading = (pageH1 || pageTitle || `Sample ${titleLabel}`).replace(/[\r\n]+/g, ' ').trim().slice(0, 80);
    fixtureObj = {
      adapterId: id,
      mode: 'html',
      inputUrl: url.toString(),
      mockPayload: `<!doctype html><html><head><meta name="description" content="Structured summary for ${escapeBasicHtml(titleLabel)}." /></head><body><h1>${escapeBasicHtml(sampleHeading)}</h1><article><p>Clean extracted body content.</p></article></body></html>`,
      expectTitleIncludes: sampleHeading.slice(0, 24),
      expectMarkdownIncludes: [`# ${sampleHeading}`],
    };
  }

  const safeHostComment = sanitizeYamlCommentToken(host, 120);
  const safeLdComment = safeDetectedLd.join(', ') || 'none';
  const safeFwComment = [...frameworkSignals].map((f) => sanitizeYamlCommentToken(f, 32)).filter(Boolean).join(', ') || 'none';
  const safeWpComment = wpRestUrl ? sanitizeYamlCommentToken(wpRestUrl, 160) : '';
  const safeFeedComments = alternateFeeds
    .slice(0, 3)
    .map((f) => `${sanitizeYamlCommentToken(f.type, 48)}:${sanitizeYamlCommentToken(f.url, 160)}`)
    .filter((s) => s.length > 2);

  const headerComment = [
    `# Proposed Declarative YAML Site Adapter for ${safeHostComment}`,
    `# Signals: jsonLd=[${safeLdComment}], frameworks=[${safeFwComment}]${safeWpComment ? `, wpRest=${safeWpComment}` : ''}`,
    ...(safeFeedComments.length > 0 ? [`# Alternate links: ${safeFeedComments.join(' | ')}`] : []),
  ].join('\n');

  const yamlBody = `${headerComment}\n${stringifyYaml(manifestObj, { lineWidth: 110 })}`;
  // Verify YAML round-trips cleanly under strict YAML 1.2 Core rules AND `compile-manifests.mjs` schema validation (`HIGH-4`).
  const parsedDoc = parseYamlDoc(yamlBody, {
    schema: 'core',
    merge: false,
    maxAliasCount: 0,
    uniqueKeys: true,
    strict: true,
  });
  if (parsedDoc.errors.length > 0) {
    throw new Error(`Generated YAML failed strict validation: ${parsedDoc.errors[0].message}`);
  }
  checkAstSafety(parsedDoc.contents, `${id}.yaml`);
  const roundTrippedObj = parsedDoc.toJS({ maxAliasCount: 0 });
  validateManifest(roundTrippedObj, `${id}.yaml`);

  return {
    id,
    host,
    registrableDomain,
    category,
    signals: {
      jsonLdTypes: safeDetectedLd,
      frameworks: [...frameworkSignals],
      ...(wpRestUrl ? { wpRestUrl } : {}),
      alternateFeeds,
      repeatingList: topList,
    },
    yaml: yamlBody,
    fixture: fixtureObj,
  };
}

function escapeBasicHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function collectJsonLdTypeNames(node, out, depth) {
  if (!node || depth > 10 || out.size >= 20) return;
  if (Array.isArray(node)) {
    for (const item of node) collectJsonLdTypeNames(item, out, depth + 1);
    return;
  }
  if (typeof node === 'object') {
    const pushCleanType = (raw) => {
      if (typeof raw !== 'string') return;
      const stripped = raw.replace(/^https?:\/\/schema\.org\//i, '').trim();
      if (/^[A-Za-z][A-Za-z0-9_-]{1,48}$/.test(stripped)) {
        out.add(stripped);
      }
    };
    const t = node['@type'];
    if (typeof t === 'string') pushCleanType(t);
    else if (Array.isArray(t)) {
      for (const x of t) pushCleanType(x);
    }
    if (Array.isArray(node['@graph'])) collectJsonLdTypeNames(node['@graph'], out, depth + 1);
  }
}

function inferCategoryFromUrlAndHtml(u, html) {
  const hay = `${u.hostname} ${u.pathname} ${String(html ?? '').slice(0, 8192)}`.toLowerCase();
  if (/\b(?:jobs?|careers?|hiring|JobPosting)\b/i.test(hay)) return 'jobs';
  if (/\b(?:product|shop|store|cart|woocommerce|shopify)\b/i.test(hay)) return 'commerce-social';
  if (/\b(?:docs|github|api|package|crate|sdk|developer)\b/i.test(hay)) return 'developer';
  if (/\b(?:pubmed|clinical|doi|arxiv|scholar)\b/i.test(hay)) return 'research-health';
  if (/\b(?:sec\.gov|edgar|ticker|earnings|stock)\b/i.test(hay)) return 'finance';
  return 'developer';
}

async function runCli() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(
      [
        'Usage: npm run adapter:propose -- <https-url> [options]',
        '',
        'Options:',
        '  --id <slug>          Override manifest id (default: registrable domain label)',
        '  --category <cat>     Override category (developer, genai, jobs, finance, public-records, research-health, commerce-social)',
        '  --html-file <path>   Analyze a saved local HTML snapshot instead of fetching over the network',
        '  --write              Write internal/extract/manifests/<id>.yaml + test fixture and run compile-manifests.mjs',
      ].join('\n'),
    );
    process.exit(args.length === 0 ? 1 : 0);
  }

  let targetUrlStr = '';
  let slugOverride;
  let categoryOverride;
  let htmlFilePath;
  let writeMode = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--write') {
      writeMode = true;
    } else if (arg === '--id' && args[i + 1]) {
      slugOverride = args[++i];
    } else if (arg === '--category' && args[i + 1]) {
      categoryOverride = args[++i];
    } else if (arg === '--html-file' && args[i + 1]) {
      htmlFilePath = args[++i];
    } else if (!arg.startsWith('--') && !targetUrlStr) {
      targetUrlStr = arg;
    }
  }

  const urlCheck = validateProposeTargetUrl(targetUrlStr);
  if (!urlCheck.ok) {
    console.error(`Error: ${urlCheck.error}`);
    process.exit(1);
  }

  let html = '';
  let finalUrl = urlCheck.url.toString();
  if (htmlFilePath) {
    html = readFileSync(resolve(htmlFilePath), 'utf8');
  } else {
    const fetched = await fetchPolitePublicHttps(urlCheck.url, 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8');
    if (fetched.status < 200 || fetched.status >= 300) {
      console.error(`Error: Origin returned HTTP ${fetched.status} for ${fetched.finalUrl}`);
      process.exit(1);
    }
    html = fetched.body;
    finalUrl = fetched.finalUrl;
  }

  const proposal = analyzeHtmlForManifestProposal({
    html,
    urlStr: finalUrl,
    slugOverride,
    categoryOverride,
  });

  if (!writeMode) {
    process.stdout.write(proposal.yaml);
    return;
  }

  mkdirSync(manifestsDir, { recursive: true });
  mkdirSync(fixturesDir, { recursive: true });
  const manifestPath = resolve(manifestsDir, `${proposal.id}.yaml`);
  const fixturePath = resolve(fixturesDir, `${proposal.id}.json`);
  if (!manifestPath.startsWith(manifestsDir + sep) || !fixturePath.startsWith(fixturesDir + sep)) {
    console.error('Refusing unsafe output path.');
    process.exit(1);
  }
  if (existsSync(manifestPath) || existsSync(fixturePath)) {
    console.error(`Refusing to overwrite existing manifest or fixture: ${manifestPath} / ${fixturePath}`);
    process.exit(1);
  }

  writeFileSync(manifestPath, proposal.yaml, 'utf8');
  writeFileSync(fixturePath, `${JSON.stringify(proposal.fixture, null, 2)}\n`, 'utf8');
  try {
    execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'inherit' });
  } catch (err) {
    rmSync(manifestPath, { force: true });
    rmSync(fixturePath, { force: true });
    throw err;
  }
  console.log(`\nWrote and compiled ${manifestPath}\nWrote fixture ${fixturePath}`);
}

const isDirectRun =
  Boolean(process.argv[1]) &&
  /(?:^|[\\/])propose-manifest\.mjs$/.test(process.argv[1]) &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  runCli().catch((err) => {
    console.error(`adapter:propose failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
