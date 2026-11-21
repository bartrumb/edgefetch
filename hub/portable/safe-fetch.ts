/**
 * Dial-Time SSRF-Safe Outbound Fetch for Portable Node.js Hub (`hub/portable/safe-fetch.ts` — `H5`).
 *
 * Enforces `net.BlockList` + full IPv4/IPv6 public-unicast validation inside Node's `dns.lookup` callback
 * right before `http.request` / `https.request` opens a socket — closing DNS-rebinding and split-horizon
 * internal-DNS (`*.plex.direct`, corporate split-DNS, Home Assistant DuckDNS -> `192.168.x.x`) bypasses on Hub-side
 * overflow fetches, webhooks, SPA-fallback robots checks, and remote LLM calls!
 */
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

const IPV4_BLOCKLIST = (() => {
  const bl = new net.BlockList();
  bl.addSubnet('0.0.0.0', 8, 'ipv4');
  bl.addSubnet('10.0.0.0', 8, 'ipv4');
  bl.addSubnet('100.64.0.0', 10, 'ipv4'); // RFC 6598 CGNAT / Tailscale
  bl.addSubnet('127.0.0.0', 8, 'ipv4');
  bl.addSubnet('169.254.0.0', 16, 'ipv4'); // Link-local & cloud metadata
  bl.addSubnet('172.16.0.0', 12, 'ipv4');
  bl.addSubnet('192.0.0.0', 24, 'ipv4');
  bl.addSubnet('192.0.2.0', 24, 'ipv4');
  bl.addSubnet('192.31.196.0', 24, 'ipv4'); // RFC 7535 AS112-v4
  bl.addSubnet('192.52.193.0', 24, 'ipv4'); // RFC 7450 AMT
  bl.addSubnet('192.88.99.0', 24, 'ipv4'); // 6to4 relay
  bl.addSubnet('192.168.0.0', 16, 'ipv4');
  bl.addSubnet('192.175.48.0', 24, 'ipv4'); // RFC 7534 Direct Delegation AS112
  bl.addSubnet('198.18.0.0', 15, 'ipv4'); // Benchmarking
  bl.addSubnet('198.51.100.0', 24, 'ipv4');
  bl.addSubnet('203.0.113.0', 24, 'ipv4');
  bl.addSubnet('224.0.0.0', 4, 'ipv4'); // Multicast
  bl.addSubnet('240.0.0.0', 4, 'ipv4'); // Reserved / broadcast
  return bl;
})();

const IPV6_BLOCKLIST = (() => {
  const bl = new net.BlockList();
  bl.addAddress('::', 'ipv6');
  bl.addAddress('::1', 'ipv6');
  bl.addSubnet('fc00::', 7, 'ipv6'); // ULA
  bl.addSubnet('fe80::', 10, 'ipv6'); // Link-local
  bl.addSubnet('fec0::', 10, 'ipv6'); // Site-local
  bl.addSubnet('ff00::', 8, 'ipv6'); // Multicast
  bl.addSubnet('2001::', 23, 'ipv6'); // RFC 2928 / IANA IETF Protocol Assignments (Teredo, Benchmarking, AMT, AS112, ORCHID, Drone ID)
  bl.addSubnet('2001:db8::', 32, 'ipv6'); // Documentation
  bl.addSubnet('2002::', 16, 'ipv6'); // 6to4
  bl.addSubnet('2620:4f:8000::', 48, 'ipv6'); // Direct Delegation AS112-v6
  bl.addSubnet('3ffe::', 16, 'ipv6'); // 6bone deprecated
  bl.addSubnet('3fff::', 20, 'ipv6'); // Documentation
  bl.addSubnet('5f00::', 16, 'ipv6'); // SRv6
  bl.addSubnet('64:ff9b::', 96, 'ipv6'); // NAT64 well-known
  bl.addSubnet('64:ff9b:1::', 48, 'ipv6'); // NAT64 local-use
  bl.addSubnet('100::', 64, 'ipv6'); // Discard-only
  return bl;
})();

function expandIpv6ToWords(addr: string): number[] | null {
  const zoneIdx = addr.indexOf('%');
  let clean = (zoneIdx >= 0 ? addr.slice(0, zoneIdx) : addr).toLowerCase();
  // Handle embedded trailing IPv4 (`::ffff:127.0.0.1` or `64:ff9b::10.0.0.1`)
  const lastColon = clean.lastIndexOf(':');
  if (lastColon >= 0 && clean.slice(lastColon + 1).includes('.')) {
    const v4Parts = clean.slice(lastColon + 1).split('.').map(Number);
    if (v4Parts.length !== 4 || v4Parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    const hi = ((v4Parts[0]! << 8) | v4Parts[1]!).toString(16);
    const lo = ((v4Parts[2]! << 8) | v4Parts[3]!).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }
  const halves = clean.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const full = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...right];
  if (full.length !== 8) return null;
  const words: number[] = [];
  for (const h of full) {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    words.push(parseInt(h, 16));
  }
  return words;
}

/**
 * Checks whether a resolved IPv4 or IPv6 literal is a routable public internet unicast address,
 * matching Go `politeness.IsPublicAddr` (`internal/politeness/ssrf.go`).
 */
export function isPublicIpAddress(rawIp: string): boolean {
  if (typeof rawIp !== 'string') return false;
  const clean = rawIp.trim().replace(/^\[|\]$/g, '');
  if (!clean || clean.includes('%')) return false;
  const ver = net.isIP(clean);
  if (ver === 4) {
    return !IPV4_BLOCKLIST.check(clean, 'ipv4');
  }
  if (ver === 6) {
    const words = expandIpv6ToWords(clean);
    if (!words) return false;
    // Permit IPv6 ONLY inside `2000::/3` global unicast (`0x2000..0x3fff` first 16-bit word),
    // automatically rejecting `::/96`, `::ffff:0:0/96`, loopback, ULA, and link-local!
    if ((words[0]! & 0xe000) !== 0x2000) return false;
    const canonical = words.map((w) => w.toString(16)).join(':');
    return !IPV6_BLOCKLIST.check(canonical, 'ipv6');
  }
  return false;
}

export type LookupResolverFn =
  | ((
      hostname: string,
      options: dns.LookupAllOptions,
      callback: (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void,
    ) => void)
  | ((hostname: string, options: dns.LookupAllOptions) => Promise<dns.LookupAddress[]>);

export function createPublicOnlyLookup(resolver: LookupResolverFn = dns.lookup): net.LookupFunction {
  return (hostname, options, callback) => {
    const optsObj = typeof options === 'object' && options !== null ? options : {};
    const wantAll = Boolean((optsObj as { all?: boolean }).all);
    let settled = false;
    const failLookup = (err: Error, family = 4) => {
      if (settled) return;
      settled = true;
      if (wantAll) {
        (callback as unknown as (e: Error | null, addrs: dns.LookupAddress[]) => void)(err, []);
      } else {
        callback(err, '', family);
      }
    };
    const handleResolved = (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => {
      if (settled) return;
      if (err) {
        failLookup(err);
        return;
      }
      if (!Array.isArray(addresses) || addresses.length === 0) {
        failLookup(new Error(`SSRF blocked: DNS lookup returned no addresses for ${hostname}`));
        return;
      }
      // Every resolved A/AAAA record must be a valid public unicast IP string (defeating round-robin `[public, 127.0.0.1]` DNS rebinding!).
      for (const entry of addresses) {
        const addrStr = entry && typeof entry === 'object' && typeof entry.address === 'string' ? entry.address.trim() : '';
        const fam = entry && typeof entry === 'object' && (entry.family === 4 || entry.family === 6) ? entry.family : 4;
        if (!addrStr || !isPublicIpAddress(addrStr)) {
          failLookup(
            new Error(`SSRF blocked: refusing connection to non-public IP ${addrStr || String(entry)} resolved for ${hostname}`),
            fam,
          );
          return;
        }
      }
      settled = true;
      if (wantAll) {
        const normalized = addresses.map((e) => ({ address: e.address.trim(), family: e.family }));
        (callback as unknown as (e: Error | null, addrs: dns.LookupAddress[]) => void)(null, normalized);
      } else {
        callback(null, addresses[0]!.address.trim(), addresses[0]!.family);
      }
    };

    try {
      if (resolver.length <= 2) {
        Promise.resolve((resolver as (h: string, o: dns.LookupAllOptions) => Promise<dns.LookupAddress[]>)(hostname, {
          all: true,
          verbatim: true,
        }))
          .then((addrs) => handleResolved(null, addrs))
          .catch((err) => failLookup(err instanceof Error ? err : new Error(String(err))));
      } else {
        (
          resolver as (
            h: string,
            o: dns.LookupAllOptions,
            cb: (e: NodeJS.ErrnoException | null, a: dns.LookupAddress[]) => void,
          ) => void
        )(hostname, { all: true, verbatim: true }, (err, addrs) => {
          try {
            handleResolved(err, addrs);
          } catch (cbErr) {
            failLookup(cbErr instanceof Error ? cbErr : new Error(String(cbErr)));
          }
        });
      }
    } catch (err) {
      failLookup(err instanceof Error ? err : new Error(String(err)));
    }
  };
}

export interface SafeOutboundFetchOptions {
  /** Custom DNS resolver hook for deterministic unit tests (`H5`). */
  resolver?: LookupResolverFn;
  /** Allow explicit operator-configured loopback HTTP URLs (e.g. local Ollama `http://127.0.0.1:11434`). */
  allowExplicitLoopbackUrls?: boolean;
}

/**
 * Builds a Web-API-compatible `typeof fetch` backed by `node:https` / `node:http` with dial-time
 * `createPublicOnlyLookup` IP filtering and `redirect: 'manual'` enforcement (`H5`).
 */
export function createSafeOutboundFetch(opts: SafeOutboundFetchOptions = {}): typeof fetch {
  const safeLookup = createPublicOnlyLookup(opts.resolver);
  const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 32, lookup: safeLookup });
  const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 16, lookup: safeLookup });
  const loopbackHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });

  const executeSingleRequest = (
    targetUrl: URL,
    init: RequestInit | undefined,
    bodyBytes: Buffer | null,
    allowLoopbackThisHop: boolean,
  ): Promise<Response> =>
    new Promise<Response>((resolve, reject) => {
      if (init?.signal?.aborted) {
        reject(init.signal.reason ?? new DOMException('Aborted', 'AbortError'));
        return;
      }
      const isHttps = targetUrl.protocol === 'https:';
      const isHttp = targetUrl.protocol === 'http:';
      if (!isHttps && !isHttp) {
        reject(new Error(`Unsupported protocol: ${targetUrl.protocol}`));
        return;
      }
      const isExplicitLoopback =
        allowLoopbackThisHop &&
        (targetUrl.hostname === '127.0.0.1' || targetUrl.hostname === 'localhost' || targetUrl.hostname === '[::1]');

      if (!isExplicitLoopback && net.isIP(targetUrl.hostname.replace(/^\[|\]$/g, '')) !== 0) {
        if (!isPublicIpAddress(targetUrl.hostname)) {
          reject(new Error(`SSRF blocked: refusing connection to non-public IP literal ${targetUrl.hostname}`));
          return;
        }
      }

      const hdrObj: Record<string, string> = {};
      if (init?.headers) {
        const h = new Headers(init.headers);
        h.forEach((v, k) => {
          hdrObj[k] = v;
        });
      }
      if (bodyBytes && hdrObj['content-length'] === undefined) {
        hdrObj['content-length'] = String(bodyBytes.byteLength);
      }

      const mod = isHttps ? https : http;
      const agent = isExplicitLoopback && isHttp ? loopbackHttpAgent : isHttps ? httpsAgent : httpAgent;
      const reqMethod = (init?.method ?? 'GET').toUpperCase();

      let settled = false;
      let activeRes: http.IncomingMessage | null = null;
      let onAbort: (() => void) | null = null;

      const detachAbort = () => {
        if (onAbort && init?.signal) {
          init.signal.removeEventListener('abort', onAbort);
          onAbort = null;
        }
      };

      const finishOk = (response: Response) => {
        if (settled) return;
        settled = true;
        resolve(response);
      };

      const finishErr = (err: unknown) => {
        if (settled) return;
        settled = true;
        detachAbort();
        reject(err);
      };

      let req: http.ClientRequest;
      try {
        req = mod.request(
          targetUrl,
          {
            method: reqMethod,
            headers: hdrObj,
            agent,
            ...(isExplicitLoopback ? {} : { lookup: safeLookup }),
          },
          (res) => {
            activeRes = res;
            const status = res.statusCode ?? 502;
            // `R3-M2`: Never permit `101 Switching Protocols` upgrades on outbound HTTP fetches!
            if (status === 101) {
              res.on('error', () => undefined);
              res.socket?.destroy();
              res.destroy();
              finishErr(new Error('HTTP 101 Switching Protocols is not allowed'));
              return;
            }

            const respHeaders = new Headers();
            for (const [k, v] of Object.entries(res.headers)) {
              if (Array.isArray(v)) {
                for (const item of v) respHeaders.append(k, item);
              } else if (typeof v === 'string') {
                respHeaders.set(k, v);
              }
            }

            const nullBodyStatus = status === 204 || status === 205 || status === 304;
            if (nullBodyStatus || reqMethod === 'HEAD') {
              res.on('error', () => undefined);
              detachAbort();
              const hasBogusBodyFraming =
                (status === 204 || status === 205) &&
                Boolean(res.headers['transfer-encoding'] || (res.headers['content-length'] && res.headers['content-length'] !== '0'));
              if (hasBogusBodyFraming) {
                res.destroy();
              } else {
                res.resume();
              }
              const response = new Response(null, { status, statusText: res.statusMessage ?? '', headers: respHeaders });
              Object.defineProperty(response, 'url', { value: targetUrl.toString(), configurable: true });
              finishOk(response);
              return;
            }

            // Wrap `res` in an error-safe Web `ReadableStream` so unread/aborted responses NEVER emit uncaught `'error'` events (`R3-M2`)!
            let streamClosed = false;
            let streamCtrl: ReadableStreamDefaultController<Uint8Array> | null = null;
            let pendingStreamErr: unknown = null;

            const cleanupResListeners = () => {
              detachAbort();
              res.removeListener('data', onResData);
              res.removeListener('end', onResEnd);
              res.removeListener('close', onResClose);
            };

            const failStream = (err: unknown) => {
              if (streamClosed) return;
              streamClosed = true;
              cleanupResListeners();
              if (streamCtrl) {
                try {
                  streamCtrl.error(err);
                } catch {
                  // ignore
                }
              } else {
                pendingStreamErr = err;
              }
            };

            const onResData = (chunk: Buffer | Uint8Array) => {
              if (streamClosed || !streamCtrl) return;
              try {
                streamCtrl.enqueue(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
                if ((streamCtrl.desiredSize ?? 1) <= 0) {
                  res.pause();
                }
              } catch {
                streamClosed = true;
                cleanupResListeners();
              }
            };

            const onResEnd = () => {
              if (streamClosed) return;
              streamClosed = true;
              cleanupResListeners();
              try {
                streamCtrl?.close();
              } catch {
                // ignore
              }
            };

            const onResClose = () => {
              if (streamClosed) return;
              if (!res.complete) {
                failStream(new Error('Premature close: incomplete HTTP response body'));
                return;
              }
              onResEnd();
            };

            res.on('error', (err) => {
              failStream(err);
            });
            res.pause();

            const webStream = new ReadableStream<Uint8Array>({
              start(c) {
                streamCtrl = c;
                if (pendingStreamErr !== null) {
                  c.error(pendingStreamErr);
                  return;
                }
                res.on('data', onResData);
                res.once('end', onResEnd);
                res.once('close', onResClose);
              },
              pull() {
                if (!streamClosed) res.resume();
              },
              cancel() {
                if (streamClosed) return;
                streamClosed = true;
                cleanupResListeners();
                res.destroy();
              },
            });

            const response = new Response(webStream, {
              status,
              statusText: res.statusMessage ?? '',
              headers: respHeaders,
            });
            Object.defineProperty(response, 'url', { value: targetUrl.toString(), configurable: true });
            finishOk(response);
          },
        );
      } catch (syncErr) {
        finishErr(syncErr);
        return;
      }

      req.on('upgrade', (_res, socket) => {
        socket.on('error', () => undefined);
        socket.destroy();
        finishErr(new Error('HTTP 101 Switching Protocols is not allowed'));
      });
      req.on('connect', (_res, socket) => {
        socket.on('error', () => undefined);
        socket.destroy();
        finishErr(new Error('HTTP CONNECT is not allowed'));
      });
      req.on('error', (err) => {
        finishErr(err);
      });
      req.on('close', () => {
        if (!settled) {
          finishErr(new Error('Socket closed before HTTP response completed'));
        }
      });

      if (init?.signal) {
        if (init.signal.aborted) {
          const reason = init.signal.reason ?? new DOMException('Aborted', 'AbortError');
          req.destroy();
          finishErr(reason);
          return;
        }
        onAbort = () => {
          const reason = init.signal?.reason ?? new DOMException('Aborted', 'AbortError');
          const errObj = reason instanceof Error ? reason : new Error(String(reason));
          if (activeRes) {
            activeRes.destroy(errObj);
          }
          req.destroy(errObj);
          finishErr(reason);
        };
        init.signal.addEventListener('abort', onAbort, { once: true });
        req.on('close', () => {
          if (!activeRes) detachAbort();
        });
      }

      if (bodyBytes && bodyBytes.byteLength > 0) {
        req.write(bodyBytes);
      }
      req.end();
    });

  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    if (init?.signal?.aborted) {
      throw init.signal.reason ?? new DOMException('Aborted', 'AbortError');
    }
    const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    let currentUrl = new URL(rawUrl);
    let currentMethod = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    let bodyBytes: Buffer | null = null;
    if (init?.body !== undefined && init.body !== null) {
      if (typeof init.body === 'string') {
        bodyBytes = Buffer.from(init.body, 'utf8');
      } else if (init.body instanceof Uint8Array) {
        bodyBytes = Buffer.from(init.body);
      } else if (init.body instanceof ArrayBuffer) {
        bodyBytes = Buffer.from(init.body);
      } else {
        const ab = await new Response(init.body as BodyInit).arrayBuffer();
        bodyBytes = Buffer.from(ab);
      }
    }

    const redirectMode = init?.redirect ?? 'manual';
    let currentHeaders = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));

    for (let hop = 0; hop <= 5; hop++) {
      const res = await executeSingleRequest(
        currentUrl,
        { ...init, method: currentMethod, headers: currentHeaders },
        bodyBytes,
        hop === 0 && opts.allowExplicitLoopbackUrls === true,
      );
      if (redirectMode !== 'follow' || res.status < 300 || res.status >= 400) {
        if (redirectMode === 'error' && res.status >= 300 && res.status < 400) {
          await res.body?.cancel().catch(() => undefined);
          throw new Error(`Unexpected redirect HTTP ${res.status}`);
        }
        return res;
      }
      const loc = res.headers.get('location');
      await res.body?.cancel().catch(() => undefined);
      if (!loc) return res;
      if (hop === 5) throw new Error('Too many redirects');
      const nextUrl = new URL(loc, currentUrl);
      if (nextUrl.protocol !== 'https:') {
        throw new Error(`Refusing redirect to non-HTTPS URL: ${nextUrl.protocol}`);
      }
      if (nextUrl.origin !== currentUrl.origin) {
        currentHeaders.delete('authorization');
        currentHeaders.delete('cookie');
        currentHeaders.delete('x-api-key');
        currentHeaders.delete('x-goog-api-key');
      }
      if (res.status === 301 || res.status === 302 || res.status === 303) {
        currentMethod = 'GET';
        bodyBytes = null;
        currentHeaders.delete('content-type');
        currentHeaders.delete('content-length');
      }
      currentUrl = nextUrl;
    }
    throw new Error('Too many redirects');
  }) as typeof fetch;
}
