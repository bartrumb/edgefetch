/**
 * Persistent Zero-Dependency WASI Reactor Bridge (`hub/src/wasm-bridge.ts`).
 *
 * Instantiates Go's `edgefetch-core.wasm` (`GOOS=wasip1 GOARCH=wasm -buildmode=c-shared`) lazily once per V8 isolate
 * and dispatches all pure-CPU HTML/Markdown extraction, CommonMark fence hardening, slice paging, 56 declarative YAML
 * adapters, PSL lookups, Schema.org, SSR hydration, CMS auto-twins, Wikipedia URL/cleanup, WAF/content-state
 * classification, and RE2 linear regex evaluation to the single Go implementation.
 */

import coreWasmModule from './edgefetch-core.wasm';

interface CoreReactorExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  _initialize: () => void;
  ef_in_ptr: (size: number) => number;
  ef_out_ptr: () => number;
  ef_out_len: () => number;
  ef_call: (inLen: number) => number;
  ef_call_raw: (metaLen: number, totalLen: number) => number;
  ef_call_raw_str: (metaLen: number, totalLen: number) => number;
  ef_re2_compile: (patLen: number) => number;
  ef_re2_test: (id: number, subjLen: number) => number;
  ef_re2_exec: (id: number, subjLen: number) => number;
}

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

let cachedReactor: CoreReactorExports | null = null;

function createMinimalWasiImports(getMemory: () => WebAssembly.Memory): WebAssembly.Imports {
  const baseWasi: Record<string, (...args: never[]) => number> = {
    args_sizes_get(argcPtr: number, argvBufSizePtr: number): number {
      const dv = new DataView(getMemory().buffer);
      dv.setUint32(argcPtr, 1, true);
      dv.setUint32(argvBufSizePtr, 15, true);
      return 0;
    },
    args_get(argvPtr: number, argvBufPtr: number): number {
      const buf = getMemory().buffer;
      const dv = new DataView(buf);
      dv.setUint32(argvPtr, argvBufPtr, true);
      const name = utf8Encoder.encode('edgefetch-wasm\0');
      new Uint8Array(buf, argvBufPtr, name.byteLength).set(name);
      return 0;
    },
    environ_sizes_get(countPtr: number, bufSizePtr: number): number {
      const dv = new DataView(getMemory().buffer);
      dv.setUint32(countPtr, 0, true);
      dv.setUint32(bufSizePtr, 0, true);
      return 0;
    },
    environ_get(): number {
      return 0;
    },
    clock_time_get(_id: number, _precision: bigint, timePtr: number): number {
      const dv = new DataView(getMemory().buffer);
      const ns = BigInt(Math.max(1, Date.now())) * 1_000_000n;
      dv.setBigUint64(timePtr, ns, true);
      return 0;
    },
    fd_write(_fd: number, iovsPtr: number, iovsLen: number, nwrittenPtr: number): number {
      const dv = new DataView(getMemory().buffer);
      let total = 0;
      for (let i = 0; i < iovsLen; i++) {
        total += dv.getUint32(iovsPtr + i * 8 + 4, true);
      }
      dv.setUint32(nwrittenPtr, total, true);
      return 0;
    },
    fd_read(_fd: number, _iovsPtr: number, _iovsLen: number, nreadPtr: number): number {
      const dv = new DataView(getMemory().buffer);
      dv.setUint32(nreadPtr, 0, true);
      return 0;
    },
    fd_close(): number {
      return 0;
    },
    fd_fdstat_get(fd: number, statPtr: number): number {
      if (fd < 0 || fd > 2) return 8; // EBADF
      const buf = getMemory().buffer;
      new Uint8Array(buf, statPtr, 24).fill(0);
      const dv = new DataView(buf);
      dv.setUint8(statPtr, 2); // FILETYPE_CHARACTER_DEVICE
      return 0;
    },
    fd_fdstat_set_flags(): number {
      return 0;
    },
    fd_prestat_get(): number {
      return 8; // EBADF -> stops Go's preopen directory scan cleanly
    },
    fd_prestat_dir_name(): number {
      return 8; // EBADF
    },
    path_open(): number {
      return 44; // ENOENT (zero host filesystem access)
    },
    path_filestat_get(): number {
      return 44; // ENOENT
    },
    random_get(bufPtr: number, bufLen: number): number {
      const target = new Uint8Array(getMemory().buffer, bufPtr, bufLen);
      let off = 0;
      while (off < bufLen) {
        const chunk = Math.min(65_536, bufLen - off);
        crypto.getRandomValues(target.subarray(off, off + chunk));
        off += chunk;
      }
      return 0;
    },
    sched_yield(): number {
      return 0;
    },
    poll_oneoff(_inPtr: number, _outPtr: number, _nsubscriptions: number, neventsPtr: number): number {
      const dv = new DataView(getMemory().buffer);
      dv.setUint32(neventsPtr, 0, true);
      return 0;
    },
    proc_exit(code: number): never {
      throw new Error(`edgefetch-core.wasm exited unexpectedly with code ${code}`);
    },
  };
  const wasiProxy = new Proxy(baseWasi, {
    get(target, prop: string) {
      if (prop in target) return target[prop];
      return () => 52; // ENOSYS fallback for any unused WASI preview1 import
    },
  });
  return {
    wasi_snapshot_preview1: wasiProxy as unknown as WebAssembly.ModuleImports,
  };
}

function getReactor(): CoreReactorExports {
  if (cachedReactor) return cachedReactor;
  let instanceRef: WebAssembly.Instance | null = null;
  const imports = createMinimalWasiImports(() => (instanceRef!.exports as CoreReactorExports).memory);
  instanceRef = new WebAssembly.Instance(coreWasmModule, imports);
  const exports = instanceRef.exports as CoreReactorExports;
  exports._initialize();
  cachedReactor = exports;
  return exports;
}

// Pre-warm the WASI reactor at module load on Node.js so cold `_initialize()` never inflates per-call timers;
// falls back lazily on Cloudflare Workers (`workerd`), which disallows `Date.now()` / `getRandomValues()` in global scope.
if (
  typeof process !== 'undefined' &&
  process.release?.name === 'node' &&
  (typeof navigator === 'undefined' || !String(navigator.userAgent).includes('Cloudflare-Workers'))
) {
  try {
    getReactor();
  } catch {
    cachedReactor = null;
  }
}

function writeInputBytes(reactor: CoreReactorExports, bytes: Uint8Array): number {
  const ptr = reactor.ef_in_ptr(bytes.byteLength) >>> 0;
  if (ptr === 0 && bytes.byteLength > 0) {
    throw new Error(`WASM input buffer allocation failed (${bytes.byteLength} bytes)`);
  }
  if (bytes.byteLength > 0) {
    new Uint8Array(reactor.memory.buffer, ptr, bytes.byteLength).set(bytes);
  }
  return bytes.byteLength;
}

export function callCoreWasm<T = Record<string, unknown>>(op: string, payload: unknown): T {
  let reactor = getReactor();
  const reqBytes = utf8Encoder.encode(JSON.stringify({ op, payload }));
  let outLen: number;
  try {
    const inLen = writeInputBytes(reactor, reqBytes);
    outLen = reactor.ef_call(inLen) >>> 0;
  } catch (err) {
    // Fault-isolated auto-recovery if the WASI reactor ever traps
    cachedReactor = null;
    reactor = getReactor();
    const inLen = writeInputBytes(reactor, reqBytes);
    outLen = reactor.ef_call(inLen) >>> 0;
    void err;
  }
  const outPtr = reactor.ef_out_ptr() >>> 0;
  const jsonText = outLen > 0 ? utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen)) : '{}';
  const parsed = JSON.parse(jsonText) as T & { error?: string };
  if (parsed && typeof parsed === 'object' && typeof parsed.error === 'string' && !('ok' in parsed)) {
    throw new Error(parsed.error);
  }
  return parsed;
}

function writeMetaAndRawStrings(
  reactor: CoreReactorExports,
  metaBytes: Uint8Array,
  rawA: string,
  rawB = '',
): { metaLen: number; firstRawBytes: number; totalLen: number } {
  const maxRawBytes = (rawA.length + rawB.length) * 3;
  const allocSize = metaBytes.byteLength + maxRawBytes;
  const ptr = reactor.ef_in_ptr(allocSize) >>> 0;
  if (ptr === 0 && allocSize > 0) {
    throw new Error(`WASM input buffer allocation failed (${allocSize} bytes)`);
  }
  const mem = new Uint8Array(reactor.memory.buffer);
  mem.set(metaBytes, ptr);
  let offset = ptr + metaBytes.byteLength;
  let firstRawBytes = 0;
  if (rawA.length > 0) {
    const encA = utf8Encoder.encodeInto(rawA, mem.subarray(offset, offset + rawA.length * 3));
    firstRawBytes = encA.written;
    offset += firstRawBytes;
  }
  if (rawB.length > 0) {
    const encB = utf8Encoder.encodeInto(rawB, mem.subarray(offset, offset + rawB.length * 3));
    offset += encB.written;
  }
  return { metaLen: metaBytes.byteLength, firstRawBytes, totalLen: offset - ptr };
}

/**
 * Zero-JSON-escape WASI RPC for multi-MiB HTML/JSON/Markdown inputs with small metadata.
 * Encodes UTF-8 directly into WASM linear memory via `TextEncoder.encodeInto` (no quote/backslash JSON escaping).
 */
export function callCoreWasmRaw<T = Record<string, unknown>>(op: string, meta: unknown, rawStr: string): T {
  let reactor = getReactor();
  const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta }));
  let outLen: number;
  try {
    const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
    outLen = reactor.ef_call_raw(metaLen, totalLen) >>> 0;
  } catch (err) {
    cachedReactor = null;
    reactor = getReactor();
    const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
    outLen = reactor.ef_call_raw(metaLen, totalLen) >>> 0;
    void err;
  }
  const outPtr = reactor.ef_out_ptr() >>> 0;
  const jsonText = outLen > 0 ? utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen)) : '{}';
  const parsed = JSON.parse(jsonText) as T & { error?: string };
  if (parsed && typeof parsed === 'object' && typeof parsed.error === 'string' && !('ok' in parsed)) {
    throw new Error(parsed.error);
  }
  return parsed;
}

export function callCoreWasmRawMetaPair<T = Record<string, unknown>>(
  op: string,
  metaObj: Record<string, unknown>,
  rawA: string,
  rawB: string,
): T {
  let reactor = getReactor();
  const run = (r: CoreReactorExports): number => {
    const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : new Uint8Array(0);
    const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : new Uint8Array(0);
    const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta: { ...metaObj, htmlByteLen: encA.byteLength } }));
    const totalLen = metaBytes.byteLength + encA.byteLength + encB.byteLength;
    const ptr = r.ef_in_ptr(totalLen) >>> 0;
    if (ptr === 0 && totalLen > 0) {
      throw new Error(`WASM input buffer allocation failed (${totalLen} bytes)`);
    }
    const mem = new Uint8Array(r.memory.buffer, ptr, totalLen);
    mem.set(metaBytes, 0);
    if (encA.byteLength > 0) mem.set(encA, metaBytes.byteLength);
    if (encB.byteLength > 0) mem.set(encB, metaBytes.byteLength + encA.byteLength);
    return r.ef_call_raw(metaBytes.byteLength, totalLen) >>> 0;
  };
  let outLen: number;
  try {
    outLen = run(reactor);
  } catch (err) {
    cachedReactor = null;
    reactor = getReactor();
    outLen = run(reactor);
    void err;
  }
  const outPtr = reactor.ef_out_ptr() >>> 0;
  const jsonText = outLen > 0 ? utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen)) : '{}';
  return JSON.parse(jsonText) as T;
}

export function callCoreWasmRawPair<T = Record<string, unknown>>(op: string, rawA: string, rawB: string): T {
  let reactor = getReactor();
  const run = (r: CoreReactorExports): number => {
    const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : new Uint8Array(0);
    const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : new Uint8Array(0);
    const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta: { mdByteLen: encA.byteLength } }));
    const totalLen = metaBytes.byteLength + encA.byteLength + encB.byteLength;
    const ptr = r.ef_in_ptr(totalLen) >>> 0;
    if (ptr === 0 && totalLen > 0) {
      throw new Error(`WASM input buffer allocation failed (${totalLen} bytes)`);
    }
    const mem = new Uint8Array(r.memory.buffer, ptr, totalLen);
    mem.set(metaBytes, 0);
    if (encA.byteLength > 0) mem.set(encA, metaBytes.byteLength);
    if (encB.byteLength > 0) mem.set(encB, metaBytes.byteLength + encA.byteLength);
    return r.ef_call_raw(metaBytes.byteLength, totalLen) >>> 0;
  };
  let outLen: number;
  try {
    outLen = run(reactor);
  } catch (err) {
    cachedReactor = null;
    reactor = getReactor();
    outLen = run(reactor);
    void err;
  }
  const outPtr = reactor.ef_out_ptr() >>> 0;
  const jsonText = outLen > 0 ? utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen)) : '{}';
  return JSON.parse(jsonText) as T;
}

/**
 * Zero-JSON-escape WASI RPC for string -> string transforms (`sanitize_markdown`, `full_artifact_markdown`).
 * Neither the input nor the output goes through `JSON.stringify` / `JSON.parse`.
 */
export function callCoreWasmRawString(op: string, meta: unknown, rawStr: string): string {
  let reactor = getReactor();
  const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta }));
  let outLen: number;
  try {
    const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
    outLen = reactor.ef_call_raw_str(metaLen, totalLen) >>> 0;
  } catch (err) {
    cachedReactor = null;
    reactor = getReactor();
    const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
    outLen = reactor.ef_call_raw_str(metaLen, totalLen) >>> 0;
    void err;
  }
  if (outLen === 0) return '';
  const outPtr = reactor.ef_out_ptr() >>> 0;
  return utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen));
}

// ── Fast Integer-Handle RE2 Regex Engine (replaces `re2js`) ─────────────────────────────────────

export interface WasmRe2Compiled {
  test: (subject: string) => boolean;
  exec: (subject: string) => RegExpExecArray | null;
}

export function compileWasmRe2(re2Pattern: string): WasmRe2Compiled | null {
  const reactor = getReactor();
  const patBytes = utf8Encoder.encode(re2Pattern);
  const patLen = writeInputBytes(reactor, patBytes);
  let handle = reactor.ef_re2_compile(patLen);
  if (handle <= 0) return null;

  const ensureHandle = (r: CoreReactorExports): number => {
    const len = writeInputBytes(r, patBytes);
    handle = r.ef_re2_compile(len);
    return handle;
  };

  return {
    test(subject: string): boolean {
      const r = getReactor();
      const subjBytes = utf8Encoder.encode(subject);
      const subjLen = writeInputBytes(r, subjBytes);
      let res = r.ef_re2_test(handle, subjLen);
      if (res === -1) {
        if (ensureHandle(r) <= 0) return false;
        const retryLen = writeInputBytes(r, subjBytes);
        res = r.ef_re2_test(handle, retryLen);
      }
      return res === 1;
    },
    exec(subject: string): RegExpExecArray | null {
      const r = getReactor();
      const subjBytes = utf8Encoder.encode(subject);
      const subjLen = writeInputBytes(r, subjBytes);
      let outLen = r.ef_re2_exec(handle, subjLen) >>> 0;
      if (outLen === 0 && r.ef_re2_test(handle, 0) === -1) {
        if (ensureHandle(r) <= 0) return null;
        const retryLen = writeInputBytes(r, subjBytes);
        outLen = r.ef_re2_exec(handle, retryLen) >>> 0;
      }
      if (outLen === 0) return null;
      const outPtr = r.ef_out_ptr() >>> 0;
      const hit = JSON.parse(utf8Decoder.decode(new Uint8Array(r.memory.buffer, outPtr, outLen))) as {
        matched: boolean;
        index: number;
        groups: Array<string | null>;
        namedGroups?: Record<string, string | null>;
      };
      if (!hit.matched) return null;
      const arr = hit.groups.map((g) => (g === null ? undefined : g)) as unknown as RegExpExecArray;
      arr.index = hit.index;
      arr.input = subject;
      if (hit.namedGroups) {
        const ng: Record<string, string> = Object.create(null) as Record<string, string>;
        for (const [k, v] of Object.entries(hit.namedGroups)) {
          ng[k] = v === null ? (undefined as unknown as string) : v;
        }
        arr.groups = ng;
      }
      return arr;
    },
  };
}

// ── Bounded PSL Lookup Cache (delegates rules to Go `internal/extract/psl.go`) ───────────────────

export interface PslLookupInfo {
  registrableDomain: string | null;
  isSuffix: boolean;
  isPrivateShared: boolean;
  knownRegistrable: string | null;
  isKnown: boolean;
}

const pslCache = new Map<string, PslLookupInfo>();

export function wasmLookupPsl(rawHost: string): PslLookupInfo {
  const key = String(rawHost ?? '').trim().toLowerCase();
  if (!key) {
    return { registrableDomain: null, isSuffix: true, isPrivateShared: false, knownRegistrable: null, isKnown: false };
  }
  const hit = pslCache.get(key);
  if (hit) return hit;

  let normalized = key;
  if (/[^\x20-\x7e]/.test(normalized)) {
    try {
      normalized = new URL(`http://${normalized}`).hostname.toLowerCase();
    } catch {
      const invalid: PslLookupInfo = {
        registrableDomain: null,
        isSuffix: true,
        isPrivateShared: false,
        knownRegistrable: null,
        isKnown: false,
      };
      return invalid;
    }
  }

  const raw = callCoreWasm<{
    registrableDomain: string;
    isSuffix: boolean;
    isPrivateShared: boolean;
    knownRegistrable: string;
    isKnown: boolean;
  }>('psl_lookup', { host: normalized });

  const info: PslLookupInfo = {
    registrableDomain: raw.registrableDomain || null,
    isSuffix: raw.isSuffix,
    isPrivateShared: raw.isPrivateShared,
    knownRegistrable: raw.knownRegistrable || null,
    isKnown: raw.isKnown,
  };
  if (pslCache.size >= 2_048) {
    const oldest = pslCache.keys().next().value;
    if (oldest !== undefined) pslCache.delete(oldest);
  }
  pslCache.set(key, info);
  return info;
}
