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
const EMPTY_BYTES = new Uint8Array(0);

// WebAssembly linear memory pages (`64 KiB` each) can never shrink once grown.
// Measured under `debug.SetMemoryLimit(48 << 20)` (`initialMemoryBytes ≈ 50.5–51.0 MiB`):
//   - Ordinary 2 MB documents (`2M` `<` sanitize -> `77.5 MiB` total, `+26.5 MiB`) stabilize below `80 MiB` across
//     repeated calls; an aggressive `+28 MiB` growth cap would rebuild the instance every ~3rd call (`~50 ms` stall +
//     brief `78 + 51 ≈ 129 MiB` old/new instance overlap before V8 GC).
//   - Evict ONLY after multi-MiB calls (`> 8 MiB` in or out) OR when total linear memory exceeds `96 MiB` (`WASM_MAX_TOTAL_MEMORY_BYTES`),
//     and never allocate a second retry instance when the failing input itself exceeded `8 MiB` (`WASM_MAX_RETRY_INPUT_BYTES`).
const WASM_EVICT_IO_BYTES = 8 * 1024 * 1024;
const WASM_MAX_TOTAL_MEMORY_BYTES = 96 * 1024 * 1024;
const WASM_MAX_RETRY_INPUT_BYTES = 8 * 1024 * 1024;
const EXACT_UTF8_ENCODE_THRESHOLD_CHARS = 524_288;

let cachedReactor: CoreReactorExports | null = null;
let cachedReactorInitMemBytes = 0;
let reactorGeneration = 0;

export interface WasmReactorStats {
  active: boolean;
  generation: number;
  memoryBytes: number;
  initialMemoryBytes: number;
}

export function getWasmReactorStats(): WasmReactorStats {
  return {
    active: cachedReactor !== null,
    generation: reactorGeneration,
    memoryBytes: cachedReactor ? cachedReactor.memory.buffer.byteLength : 0,
    initialMemoryBytes: cachedReactorInitMemBytes,
  };
}

export function isWasmReactorGenerationCurrent(generation: number): boolean {
  return cachedReactor !== null && generation > 0 && reactorGeneration === generation;
}

export function resetWasmReactor(): void {
  cachedReactor = null;
  cachedReactorInitMemBytes = 0;
}

function maybeEvictOversizedReactor(
  reactor: CoreReactorExports,
  inBytes: number,
  outBytes: number,
  skipTotalCeiling = false,
): void {
  if (cachedReactor !== reactor) return;
  const memBytes = reactor.memory.buffer.byteLength;
  if (
    inBytes > WASM_EVICT_IO_BYTES ||
    outBytes > WASM_EVICT_IO_BYTES ||
    (!skipTotalCeiling && memBytes > WASM_MAX_TOTAL_MEMORY_BYTES)
  ) {
    cachedReactor = null;
    cachedReactorInitMemBytes = 0;
  }
}

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
  cachedReactorInitMemBytes = exports.memory.buffer.byteLength;
  reactorGeneration++;
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
  let inLen = 0;
  let outLen = 0;
  let jsonText = '{}';
  try {
    try {
      inLen = writeInputBytes(reactor, reqBytes);
      outLen = reactor.ef_call(inLen) >>> 0;
    } catch (err) {
      // Fault-isolated auto-recovery if the WASI reactor ever traps (skip retry on >8 MiB inputs to avoid dual-instance OOM)
      resetWasmReactor();
      if (reqBytes.byteLength > WASM_MAX_RETRY_INPUT_BYTES) throw err;
      reactor = getReactor();
      inLen = writeInputBytes(reactor, reqBytes);
      outLen = reactor.ef_call(inLen) >>> 0;
      void err;
    }
    const outPtr = reactor.ef_out_ptr() >>> 0;
    if (outLen > 0) {
      jsonText = utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen));
    }
  } finally {
    maybeEvictOversizedReactor(reactor, inLen, outLen, op === 'dom_parse');
  }
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
  // For multi-MiB strings (e.g. 10 MiB Greenhouse/Ashby JSON or HTML), pre-encoding with `utf8Encoder.encode`
  // allocates the exact UTF-8 byte length (~1x) in WASM linear memory instead of `length * 3` (~30 MiB),
  // avoiding permanent `WebAssembly.Memory` page growth inside Cloudflare Workers' 128 MiB isolate ceiling.
  const totalChars = rawA.length + rawB.length;
  if (totalChars > EXACT_UTF8_ENCODE_THRESHOLD_CHARS) {
    const slack = Math.min(262_144, (totalChars >>> 4) + 4_096);
    const optimisticSize = metaBytes.byteLength + totalChars + slack;
    if (optimisticSize <= 48 * 1024 * 1024) {
      const optPtr = reactor.ef_in_ptr(optimisticSize) >>> 0;
      if (optPtr !== 0) {
        const mem = new Uint8Array(reactor.memory.buffer);
        mem.set(metaBytes, optPtr);
        let offset = optPtr + metaBytes.byteLength;
        const endPtr = optPtr + optimisticSize;
        let fits = true;
        let firstRawBytes = 0;
        if (rawA.length > 0) {
          const encA = utf8Encoder.encodeInto(rawA, mem.subarray(offset, endPtr));
          if (encA.read !== rawA.length) {
            fits = false;
          } else {
            firstRawBytes = encA.written;
            offset += firstRawBytes;
          }
        }
        if (fits && rawB.length > 0) {
          const encB = utf8Encoder.encodeInto(rawB, mem.subarray(offset, endPtr));
          if (encB.read !== rawB.length) {
            fits = false;
          } else {
            offset += encB.written;
          }
        }
        if (fits) {
          return { metaLen: metaBytes.byteLength, firstRawBytes, totalLen: offset - optPtr };
        }
      }
    }

    const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : null;
    const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : null;
    const lenA = encA ? encA.byteLength : 0;
    const lenB = encB ? encB.byteLength : 0;
    const allocSize = metaBytes.byteLength + lenA + lenB;
    const ptr = reactor.ef_in_ptr(allocSize) >>> 0;
    if (ptr === 0 && allocSize > 0) {
      throw new Error(`WASM input buffer allocation failed (${allocSize} bytes)`);
    }
    const mem = new Uint8Array(reactor.memory.buffer);
    mem.set(metaBytes, ptr);
    let offset = ptr + metaBytes.byteLength;
    if (encA && lenA > 0) {
      mem.set(encA, offset);
      offset += lenA;
    }
    if (encB && lenB > 0) {
      mem.set(encB, offset);
      offset += lenB;
    }
    return { metaLen: metaBytes.byteLength, firstRawBytes: lenA, totalLen: offset - ptr };
  }

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
  let usedTotalLen = 0;
  let outLen = 0;
  let jsonText = '{}';
  try {
    try {
      const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
      usedTotalLen = totalLen;
      outLen = reactor.ef_call_raw(metaLen, totalLen) >>> 0;
    } catch (err) {
      resetWasmReactor();
      if (rawStr.length > WASM_MAX_RETRY_INPUT_BYTES || usedTotalLen > WASM_MAX_RETRY_INPUT_BYTES) throw err;
      reactor = getReactor();
      const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
      usedTotalLen = totalLen;
      outLen = reactor.ef_call_raw(metaLen, totalLen) >>> 0;
      void err;
    }
    const outPtr = reactor.ef_out_ptr() >>> 0;
    if (outLen > 0) {
      jsonText = utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen));
    }
  } finally {
    maybeEvictOversizedReactor(reactor, usedTotalLen, outLen);
  }
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
  const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : EMPTY_BYTES;
  const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : EMPTY_BYTES;
  const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta: { ...metaObj, htmlByteLen: encA.byteLength } }));
  const allocLen = metaBytes.byteLength + encA.byteLength + encB.byteLength;
  const run = (r: CoreReactorExports): number => {
    const ptr = r.ef_in_ptr(allocLen) >>> 0;
    if (ptr === 0 && allocLen > 0) {
      throw new Error(`WASM input buffer allocation failed (${allocLen} bytes)`);
    }
    const mem = new Uint8Array(r.memory.buffer);
    mem.set(metaBytes, ptr);
    let offset = ptr + metaBytes.byteLength;
    if (encA.byteLength > 0) {
      mem.set(encA, offset);
      offset += encA.byteLength;
    }
    if (encB.byteLength > 0) {
      mem.set(encB, offset);
      offset += encB.byteLength;
    }
    return r.ef_call_raw(metaBytes.byteLength, offset - ptr) >>> 0;
  };
  let outLen = 0;
  let jsonText = '{}';
  try {
    try {
      outLen = run(reactor);
    } catch (err) {
      resetWasmReactor();
      if (allocLen > WASM_MAX_RETRY_INPUT_BYTES) throw err;
      reactor = getReactor();
      outLen = run(reactor);
      void err;
    }
    const outPtr = reactor.ef_out_ptr() >>> 0;
    if (outLen > 0) {
      jsonText = utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen));
    }
  } finally {
    maybeEvictOversizedReactor(reactor, allocLen, outLen);
  }
  return JSON.parse(jsonText) as T;
}

export function callCoreWasmRawPair<T = Record<string, unknown>>(op: string, rawA: string, rawB: string): T {
  let reactor = getReactor();
  const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : EMPTY_BYTES;
  const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : EMPTY_BYTES;
  const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta: { mdByteLen: encA.byteLength } }));
  const allocLen = metaBytes.byteLength + encA.byteLength + encB.byteLength;
  const run = (r: CoreReactorExports): number => {
    const ptr = r.ef_in_ptr(allocLen) >>> 0;
    if (ptr === 0 && allocLen > 0) {
      throw new Error(`WASM input buffer allocation failed (${allocLen} bytes)`);
    }
    const mem = new Uint8Array(r.memory.buffer);
    mem.set(metaBytes, ptr);
    let offset = ptr + metaBytes.byteLength;
    if (encA.byteLength > 0) {
      mem.set(encA, offset);
      offset += encA.byteLength;
    }
    if (encB.byteLength > 0) {
      mem.set(encB, offset);
      offset += encB.byteLength;
    }
    return r.ef_call_raw(metaBytes.byteLength, offset - ptr) >>> 0;
  };
  let outLen = 0;
  let jsonText = '{}';
  try {
    try {
      outLen = run(reactor);
    } catch (err) {
      resetWasmReactor();
      if (allocLen > WASM_MAX_RETRY_INPUT_BYTES) throw err;
      reactor = getReactor();
      outLen = run(reactor);
      void err;
    }
    const outPtr = reactor.ef_out_ptr() >>> 0;
    if (outLen > 0) {
      jsonText = utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen));
    }
  } finally {
    maybeEvictOversizedReactor(reactor, allocLen, outLen);
  }
  return JSON.parse(jsonText) as T;
}

/**
 * Zero-JSON-escape WASI RPC for string -> string transforms (`sanitize_markdown`, `full_artifact_markdown`).
 * Neither the input nor the output goes through `JSON.stringify` / `JSON.parse`.
 */
export function callCoreWasmRawString(op: string, meta: unknown, rawStr: string): string {
  let reactor = getReactor();
  const metaBytes = utf8Encoder.encode(JSON.stringify({ op, meta }));
  let usedTotalLen = 0;
  let outLen = 0;
  try {
    try {
      const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
      usedTotalLen = totalLen;
      outLen = reactor.ef_call_raw_str(metaLen, totalLen) >>> 0;
    } catch (err) {
      resetWasmReactor();
      if (rawStr.length > WASM_MAX_RETRY_INPUT_BYTES || usedTotalLen > WASM_MAX_RETRY_INPUT_BYTES) throw err;
      reactor = getReactor();
      const { metaLen, totalLen } = writeMetaAndRawStrings(reactor, metaBytes, rawStr);
      usedTotalLen = totalLen;
      outLen = reactor.ef_call_raw_str(metaLen, totalLen) >>> 0;
      void err;
    }
    if (outLen === 0xffffffff) return rawStr;
    if (outLen === 0) return '';
    const outPtr = reactor.ef_out_ptr() >>> 0;
    return utf8Decoder.decode(new Uint8Array(reactor.memory.buffer, outPtr, outLen));
  } finally {
    const effectiveOutBytes = outLen === 0xffffffff ? 0 : outLen;
    maybeEvictOversizedReactor(reactor, usedTotalLen, effectiveOutBytes);
  }
}

// ── Fast Integer-Handle RE2 Regex Engine (replaces `re2js`) ─────────────────────────────────────

export interface WasmRe2Compiled {
  test: (subject: string) => boolean;
  exec: (subject: string) => RegExpExecArray | null;
}

export function compileWasmRe2(re2Pattern: string): WasmRe2Compiled | null {
  let initReactor = getReactor();
  const patBytes = utf8Encoder.encode(re2Pattern);
  let handle: number;
  try {
    const patLen = writeInputBytes(initReactor, patBytes);
    handle = initReactor.ef_re2_compile(patLen);
  } catch (err) {
    resetWasmReactor();
    initReactor = getReactor();
    const patLen = writeInputBytes(initReactor, patBytes);
    handle = initReactor.ef_re2_compile(patLen);
    void err;
  }
  if (handle <= 0) return null;

  let boundReactor: CoreReactorExports | null = initReactor;

  const ensureHandle = (r: CoreReactorExports): number => {
    const len = writeInputBytes(r, patBytes);
    handle = r.ef_re2_compile(len);
    boundReactor = handle > 0 ? r : null;
    return handle;
  };

  return {
    test(subject: string): boolean {
      let r = getReactor();
      const subjBytes = utf8Encoder.encode(subject);
      let res: number;
      try {
        if (r !== boundReactor && ensureHandle(r) <= 0) return false;
        const subjLen = writeInputBytes(r, subjBytes);
        res = r.ef_re2_test(handle, subjLen);
        if (res === -1) {
          if (ensureHandle(r) <= 0) return false;
          const retryLen = writeInputBytes(r, subjBytes);
          res = r.ef_re2_test(handle, retryLen);
        }
      } catch (err) {
        resetWasmReactor();
        boundReactor = null;
        if (subjBytes.byteLength > WASM_MAX_RETRY_INPUT_BYTES) throw err;
        r = getReactor();
        if (ensureHandle(r) <= 0) return false;
        const retryLen = writeInputBytes(r, subjBytes);
        res = r.ef_re2_test(handle, retryLen);
        void err;
      } finally {
        maybeEvictOversizedReactor(r, subjBytes.byteLength, 0);
      }
      return res === 1;
    },
    exec(subject: string): RegExpExecArray | null {
      let r = getReactor();
      const subjBytes = utf8Encoder.encode(subject);
      let outLen = 0;
      let hitText = '';
      try {
        try {
          if (r !== boundReactor && ensureHandle(r) <= 0) return null;
          const subjLen = writeInputBytes(r, subjBytes);
          outLen = r.ef_re2_exec(handle, subjLen) >>> 0;
          if (outLen === 0 && (r !== boundReactor || r.ef_re2_test(handle, 0) === -1)) {
            if (ensureHandle(r) <= 0) return null;
            const retryLen = writeInputBytes(r, subjBytes);
            outLen = r.ef_re2_exec(handle, retryLen) >>> 0;
          }
        } catch (err) {
          resetWasmReactor();
          boundReactor = null;
          if (subjBytes.byteLength > WASM_MAX_RETRY_INPUT_BYTES) throw err;
          r = getReactor();
          if (ensureHandle(r) <= 0) return null;
          const retryLen = writeInputBytes(r, subjBytes);
          outLen = r.ef_re2_exec(handle, retryLen) >>> 0;
          void err;
        }
        if (outLen === 0) return null;
        const outPtr = r.ef_out_ptr() >>> 0;
        hitText = utf8Decoder.decode(new Uint8Array(r.memory.buffer, outPtr, outLen));
      } finally {
        maybeEvictOversizedReactor(r, subjBytes.byteLength, outLen);
      }
      const hit = JSON.parse(hitText) as {
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
