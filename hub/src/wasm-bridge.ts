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

// Shared edge WASM input & isolate concurrency budgets (`PR #73` + `PR #74`):
//   - Fresh reactor baseline (after build-tagging `crypto/*` out of `wasip1` to eliminate Go 1.26's 32 MiB
//     `fips140/drbg.memory` BSS + lazy-compiling 641 package-level regexes via `sync.Once`):
//     `initialMemoryBytes ≈ 7.25 MiB` (`initial_pages = 92`, `initHeapAlloc ≈ 141 KiB`, down `-43.75 MiB` from `51.00 MiB`).
//   - `MAX_WASM_INPUT_BYTES = 4 MiB` enforced in every shared writer below so all ~30 raw/JSON/RE2 ops are bounded in one place.
//   - `MAX_ISOLATE_IN_FLIGHT_BYTES = 12 MiB` semaphore caps concurrent multi-MiB requests sharing one 128 MiB Worker isolate.
//   - Evict `cachedReactor` only when I/O exceeds `8 MiB` (`WASM_EVICT_IO_BYTES`) or total linear memory exceeds `96 MiB`
//     (`WASM_MAX_TOTAL_MEMORY_BYTES`), keeping `<= 4 MiB` inputs and `2M` `<` (`8.00 MB` out) steady with 0 rebuild stalls.
export const MAX_WASM_INPUT_BYTES = 4 * 1024 * 1024;
export const MAX_ISOLATE_IN_FLIGHT_BYTES = 12 * 1024 * 1024;
export const WASM_EVICT_IN_BYTES = 8 * 1024 * 1024;
export const WASM_EVICT_IO_BYTES = WASM_EVICT_IN_BYTES;
export const WASM_EVICT_OUT_BYTES = 8 * 1024 * 1024;
export const WASM_MAX_TOTAL_MEMORY_BYTES = 96 * 1024 * 1024;
const EXACT_UTF8_ENCODE_THRESHOLD_CHARS = 524_288;

export class WasmInputBudgetExceededError extends Error {
  readonly code = 'wasm_input_budget_exceeded' as const;
  readonly inputBytes: number;
  readonly budgetBytes: number;

  constructor(inputBytes: number, budgetBytes = MAX_WASM_INPUT_BYTES) {
    super(`Document exceeds ${Math.round(budgetBytes / (1024 * 1024))} MiB edge WASM input budget (${inputBytes} bytes)`);
    this.name = 'WasmInputBudgetExceededError';
    this.inputBytes = inputBytes;
    this.budgetBytes = budgetBytes;
  }
}

export function isWasmInputBudgetExceededError(err: unknown): err is WasmInputBudgetExceededError {
  return (
    err instanceof WasmInputBudgetExceededError ||
    (Boolean(err) && typeof err === 'object' && (err as { code?: unknown }).code === 'wasm_input_budget_exceeded')
  );
}

export interface IsolateBudgetLease {
  readonly bytes: number;
  release(): void;
}

interface IsolateBudgetWaiter {
  bytes: number;
  timer: ReturnType<typeof setTimeout>;
  resolve: (lease: IsolateBudgetLease | null) => void;
}

let isolateBytesInFlight = 0;
const isolateWaitQueue: IsolateBudgetWaiter[] = [];

function createLease(cost: number): IsolateBudgetLease {
  let released = false;
  return {
    bytes: cost,
    release(): void {
      if (released) return;
      released = true;
      isolateBytesInFlight = Math.max(0, isolateBytesInFlight - cost);
      drainIsolateWaitQueue();
    },
  };
}

function drainIsolateWaitQueue(): void {
  while (isolateWaitQueue.length > 0) {
    const head = isolateWaitQueue[0]!;
    if (isolateBytesInFlight + head.bytes > MAX_ISOLATE_IN_FLIGHT_BYTES) {
      break;
    }
    isolateWaitQueue.shift();
    clearTimeout(head.timer);
    isolateBytesInFlight += head.bytes;
    head.resolve(createLease(head.bytes));
  }
}

export function acquireIsolateByteBudget(
  requestedBytes: number,
  waitTimeoutMs = 200,
): Promise<IsolateBudgetLease | null> {
  const cost = Math.max(1, Math.min(MAX_ISOLATE_IN_FLIGHT_BYTES, Math.ceil(Number.isFinite(requestedBytes) ? requestedBytes : 1)));
  if (isolateWaitQueue.length === 0 && isolateBytesInFlight + cost <= MAX_ISOLATE_IN_FLIGHT_BYTES) {
    isolateBytesInFlight += cost;
    return Promise.resolve(createLease(cost));
  }
  if (waitTimeoutMs <= 0) {
    return Promise.resolve(null);
  }
  return new Promise<IsolateBudgetLease | null>((resolve) => {
    const waiter: IsolateBudgetWaiter = {
      bytes: cost,
      timer: setTimeout(() => {
        const idx = isolateWaitQueue.indexOf(waiter);
        if (idx >= 0) isolateWaitQueue.splice(idx, 1);
        resolve(null);
        // A timed-out head waiter may have been the only thing blocking smaller waiters that already fit.
        if (idx === 0) drainIsolateWaitQueue();
      }, waitTimeoutMs),
      resolve,
    };
    isolateWaitQueue.push(waiter);
  });
}

export function getIsolateBudgetStats(): { inFlightBytes: number; maxBytes: number; queuedWaiters: number } {
  return {
    inFlightBytes: isolateBytesInFlight,
    maxBytes: MAX_ISOLATE_IN_FLIGHT_BYTES,
    queuedWaiters: isolateWaitQueue.length,
  };
}

export function resetIsolateBudgetForTests(): void {
  while (isolateWaitQueue.length > 0) {
    const w = isolateWaitQueue.shift()!;
    clearTimeout(w.timer);
    w.resolve(null);
  }
  isolateBytesInFlight = 0;
}

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
    inBytes > WASM_EVICT_IN_BYTES ||
    outBytes > WASM_EVICT_OUT_BYTES ||
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
  if (bytes.byteLength > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(bytes.byteLength);
  }
  const ptr = reactor.ef_in_ptr(bytes.byteLength) >>> 0;
  if (ptr === 0 && bytes.byteLength > 0) {
    throw new Error(`WASM input buffer allocation failed (${bytes.byteLength} bytes)`);
  }
  if (bytes.byteLength > 0) {
    new Uint8Array(reactor.memory.buffer, ptr, bytes.byteLength).set(bytes);
  }
  return bytes.byteLength;
}

export interface WasmGoMemStatsSnapshot {
  alloc: number;
  totalAlloc: number;
  sys: number;
  heapAlloc: number;
  heapSys: number;
  heapIdle: number;
  heapInuse: number;
  heapReleased: number;
  heapObjects: number;
  stackInuse: number;
  stackSys: number;
  mSpanSys: number;
  mCacheSys: number;
  buckHashSys: number;
  gcSys: number;
  otherSys: number;
  nextGC: number;
  numGC: number;
}

export function getWasmRuntimeMemStats(): { init: WasmGoMemStatsSnapshot; current: WasmGoMemStatsSnapshot } {
  return callCoreWasm<{ init: WasmGoMemStatsSnapshot; current: WasmGoMemStatsSnapshot }>('wasm_mem_stats', {});
}

export function callCoreWasm<T = Record<string, unknown>>(op: string, payload: unknown): T {
  let reactor = getReactor();
  const reqBytes = utf8Encoder.encode(JSON.stringify({ op, payload }));
  if (reqBytes.byteLength > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(reqBytes.byteLength);
  }
  let inLen = 0;
  let outLen = 0;
  let jsonText = '{}';
  try {
    try {
      inLen = writeInputBytes(reactor, reqBytes);
      outLen = reactor.ef_call(inLen) >>> 0;
    } catch (err) {
      if (isWasmInputBudgetExceededError(err)) throw err;
      // Fault-isolated auto-recovery if the WASI reactor ever traps
      resetWasmReactor();
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
  // Global WASM input byte budget (`MAX_WASM_INPUT_BYTES` = 4 MiB) enforced in the shared writer
  // so every raw/HTML/JSON/XML/CSV/Markdown op is bounded automatically without per-op drift.
  const totalChars = rawA.length + rawB.length;
  if (totalChars > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(totalChars);
  }
  if (totalChars > EXACT_UTF8_ENCODE_THRESHOLD_CHARS) {
    const slack = Math.min(262_144, (totalChars >>> 4) + 4_096);
    const optimisticSize = metaBytes.byteLength + totalChars + slack;
    if (optimisticSize <= metaBytes.byteLength + MAX_WASM_INPUT_BYTES + 262_144) {
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
          const rawBytesWritten = offset - (optPtr + metaBytes.byteLength);
          if (rawBytesWritten > MAX_WASM_INPUT_BYTES) {
            throw new WasmInputBudgetExceededError(rawBytesWritten);
          }
          return { metaLen: metaBytes.byteLength, firstRawBytes, totalLen: offset - optPtr };
        }
      }
    }

    const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : null;
    const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : null;
    const lenA = encA ? encA.byteLength : 0;
    const lenB = encB ? encB.byteLength : 0;
    if (lenA + lenB > MAX_WASM_INPUT_BYTES) {
      throw new WasmInputBudgetExceededError(lenA + lenB);
    }
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

  const maxRawBytes = totalChars * 3;
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
  const rawBytesWritten = offset - (ptr + metaBytes.byteLength);
  if (rawBytesWritten > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(rawBytesWritten);
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
      if (isWasmInputBudgetExceededError(err)) throw err;
      resetWasmReactor();
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
  if (rawA.length + rawB.length > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(rawA.length + rawB.length);
  }
  let reactor = getReactor();
  const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : EMPTY_BYTES;
  const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : EMPTY_BYTES;
  if (encA.byteLength + encB.byteLength > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(encA.byteLength + encB.byteLength);
  }
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
      if (isWasmInputBudgetExceededError(err)) throw err;
      resetWasmReactor();
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
  if (rawA.length + rawB.length > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(rawA.length + rawB.length);
  }
  let reactor = getReactor();
  const encA = rawA.length > 0 ? utf8Encoder.encode(rawA) : EMPTY_BYTES;
  const encB = rawB.length > 0 ? utf8Encoder.encode(rawB) : EMPTY_BYTES;
  if (encA.byteLength + encB.byteLength > MAX_WASM_INPUT_BYTES) {
    throw new WasmInputBudgetExceededError(encA.byteLength + encB.byteLength);
  }
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
      if (isWasmInputBudgetExceededError(err)) throw err;
      resetWasmReactor();
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
      if (isWasmInputBudgetExceededError(err)) throw err;
      resetWasmReactor();
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
    if (isWasmInputBudgetExceededError(err)) throw err;
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
      if (subject.length > MAX_WASM_INPUT_BYTES) {
        throw new WasmInputBudgetExceededError(subject.length);
      }
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
        if (isWasmInputBudgetExceededError(err)) throw err;
        resetWasmReactor();
        boundReactor = null;
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
      if (subject.length > MAX_WASM_INPUT_BYTES) {
        throw new WasmInputBudgetExceededError(subject.length);
      }
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
          if (isWasmInputBudgetExceededError(err)) throw err;
          resetWasmReactor();
          boundReactor = null;
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
