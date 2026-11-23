/**
 * Zero-dependency Mozilla Public Suffix List (PSL) lookup (`hub/src/psl.ts`).
 *
 * Implements the standard Mozilla PSL specification in O(labels) Map lookups across exact rules,
 * wildcard rules (`*.ck`, `*.run.app`, `*.platformsh.site`), exception rules (`!www.ck`, `!city.kobe.jp`),
 * and the unlisted TLD default `*` rule, distinguishing ICANN vs PRIVATE DOMAINS sections.
 */

import { PUBLIC_SUFFIX_LIST_DAT } from './psl-data';

const exactRules = new Map<string, boolean>();
const wildcardRules = new Map<string, boolean>();
const exceptionRules = new Map<string, boolean>();

let inPrivateSection = false;
for (const line of PUBLIC_SUFFIX_LIST_DAT.split('\n')) {
  if (!line) continue;
  if (line.startsWith('//')) {
    if (line.includes('===BEGIN PRIVATE DOMAINS===')) inPrivateSection = true;
    else if (line.includes('===END PRIVATE DOMAINS===')) inPrivateSection = false;
    continue;
  }
  if (line.startsWith('!')) {
    exceptionRules.set(line.slice(1), inPrivateSection);
  } else if (line.startsWith('*.')) {
    wildcardRules.set(line.slice(2), inPrivateSection);
  } else {
    exactRules.set(line, inPrivateSection);
  }
}

function normalizeHostLabels(rawHost: string): string[] | null {
  let clean = String(rawHost ?? '').trim().toLowerCase();
  if (!clean || clean.startsWith('.')) return null;
  clean = clean.replace(/\.+$/, '');
  if (!clean || /[\s/*\\:?#@[\]]/.test(clean)) return null;
  if (/[^\x20-\x7e]/.test(clean)) {
    try {
      clean = new URL(`http://${clean}`).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  const labels = clean.split('.');
  for (const l of labels) {
    if (!l || l.length > 63 || l.startsWith('-') || l.endsWith('-') || !/^[a-z0-9-]+$/.test(l)) {
      return null;
    }
  }
  const tld = labels[labels.length - 1]!;
  if (tld.charCodeAt(0) >= 48 && tld.charCodeAt(0) <= 57) return null;
  return labels;
}

function matchPsl(labels: string[]): { suffixLen: number; isPrivate: boolean } {
  let suffixLen = 1; // Prevailing default `*` TLD rule
  let isPrivate = false;
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    const rem = labels.length - i;
    const excPriv = exceptionRules.get(cand);
    if (excPriv !== undefined) {
      return { suffixLen: rem - 1, isPrivate: excPriv };
    }
    const exactPriv = exactRules.get(cand);
    if (exactPriv !== undefined && rem > suffixLen) {
      suffixLen = rem;
      isPrivate = exactPriv;
    }
    const wildPriv = i > 0 ? wildcardRules.get(cand) : undefined;
    if (wildPriv !== undefined && rem + 1 > suffixLen) {
      suffixLen = rem + 1;
      isPrivate = wildPriv;
    }
  }
  return { suffixLen, isPrivate };
}

export function getRegistrableDomain(host: string): string | null {
  const labels = normalizeHostLabels(host);
  if (!labels) return null;
  const { suffixLen } = matchPsl(labels);
  if (labels.length <= suffixLen) return null;
  return labels.slice(labels.length - suffixLen - 1).join('.');
}

export function isPublicOrPrivateSuffix(host: string): boolean {
  return getRegistrableDomain(host) === null;
}

export function hasPrivateSharedHostingSuffix(host: string): boolean {
  const labels = normalizeHostLabels(host);
  if (!labels) return false;
  const { isPrivate } = matchPsl(labels);
  return isPrivate || wildcardRules.get(labels.join('.')) === true;
}
