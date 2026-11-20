/**
 * Zero-dependency WebCrypto AWS Signature Version 4 (`AWS4-HMAC-SHA256`) `R2Bucket` adapter (`hub/portable/s3-bucket.ts`).
 *
 * Works across Node.js 22+, Deno Deploy, Bun, and Edge runtimes using only standard `crypto.subtle` and `fetch()` —
 * compatible with AWS S3, Cloudflare R2 S3 API, Fly.io Tigris, MinIO, Backblaze B2, and Garage with zero `@aws-sdk/*` bloat.
 */

export interface S3BucketConfig {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
  forcePathStyle?: boolean;
  fetchImpl?: typeof fetch;
}

const ENC = new TextEncoder();

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? ENC.encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return toHex(digest);
}

async function hmacSha256(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const rawKey = key instanceof Uint8Array ? (key as BufferSource) : key;
  const cryptoKey = await crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', cryptoKey, ENC.encode(message));
}

function encodeRfc3986(str: string): string {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeS3Path(path: string): string {
  return path
    .split('/')
    .map((seg) => encodeRfc3986(seg))
    .join('/');
}

function formatAmzDates(now: Date): { amzDate: string; dateStamp: string } {
  const iso = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return {
    amzDate: iso, // YYYYMMDDTHHMMSSZ
    dateStamp: iso.slice(0, 8), // YYYYMMDD
  };
}

export interface SigV4SignInput {
  method: string;
  url: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  headers?: Record<string, string>;
  payloadSha256?: string;
  now?: Date;
}

export async function buildSigV4Headers(input: SigV4SignInput): Promise<Record<string, string>> {
  const u = new URL(input.url);
  const { amzDate, dateStamp } = formatAmzDates(input.now ?? new Date());
  const payloadHash = input.payloadSha256 ?? 'UNSIGNED-PAYLOAD';

  const lowerHeaders: Record<string, string> = {
    host: u.host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
  };
  for (const [k, v] of Object.entries(input.headers ?? {})) {
    lowerHeaders[k.toLowerCase().trim()] = v.trim().replace(/\s+/g, ' ');
  }

  const sortedHeaderNames = Object.keys(lowerHeaders).sort();
  const canonicalHeaders = sortedHeaderNames.map((k) => `${k}:${lowerHeaders[k]}\n`).join('');
  const signedHeaders = sortedHeaderNames.join(';');

  const sortedQuery = [...u.searchParams.entries()]
    .sort(([a, av], [b, bv]) => (a === b ? av.localeCompare(bv) : a.localeCompare(b)))
    .map(([k, v]) => `${encodeRfc3986(k)}=${encodeRfc3986(v)}`)
    .join('&');

  const canonicalUri = u.pathname
    .split('/')
    .map((seg) => encodeRfc3986(decodeURIComponent(seg)))
    .join('/');

  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri || '/',
    sortedQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${input.region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n');

  const kDate = await hmacSha256(ENC.encode(`AWS4${input.secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, input.region);
  const kService = await hmacSha256(kRegion, 's3');
  const kSigning = await hmacSha256(kService, 'aws4_request');
  const signature = toHex(await hmacSha256(kSigning, stringToSign));

  const out: Record<string, string> = { ...lowerHeaders };
  delete out.host;
  out.authorization = `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return out;
}

async function readValueBytes(
  value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
): Promise<Uint8Array> {
  if (value === null) return new Uint8Array(0);
  if (typeof value === 'string') return ENC.encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (typeof Blob !== 'undefined' && value instanceof Blob) return new Uint8Array(await value.arrayBuffer());
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = (value as ReadableStream<Uint8Array>).getReader();
  while (true) {
    const { done, value: chunk } = await reader.read();
    if (done) break;
    if (chunk) {
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return merged;
}

function parseS3ObjectMeta(key: string, res: Response): R2Object {
  const customMetadata: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    const lower = k.toLowerCase();
    if (lower.startsWith('x-amz-meta-')) {
      customMetadata[lower.slice('x-amz-meta-'.length)] = v;
    }
  });
  const size = Number(res.headers.get('content-length') ?? '0') || 0;
  const lastMod = res.headers.get('last-modified');
  const uploaded = lastMod ? new Date(lastMod) : new Date();
  const etag = (res.headers.get('etag') ?? '').replace(/^"|"$/g, '');
  const ct = res.headers.get('content-type') ?? 'application/octet-stream';

  return {
    key,
    version: etag || '1',
    size,
    etag,
    httpEtag: `"${etag}"`,
    checksums: {} as R2Checksums,
    uploaded,
    httpMetadata: { contentType: ct },
    customMetadata,
    storageClass: 'Standard',
    writeHttpMetadata(headers: Headers): void {
      headers.set('content-type', ct);
    },
  } as unknown as R2Object;
}

export class S3ArtifactBucket {
  private readonly endpoint: URL;
  private readonly bucket: string;
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly region: string;
  private readonly forcePathStyle: boolean;
  private readonly fetchFn: typeof fetch;

  constructor(cfg: S3BucketConfig) {
    this.endpoint = new URL(cfg.endpoint);
    this.bucket = cfg.bucket;
    this.accessKeyId = cfg.accessKeyId;
    this.secretAccessKey = cfg.secretAccessKey;
    this.region = cfg.region || 'auto';
    this.forcePathStyle = cfg.forcePathStyle ?? true;
    this.fetchFn = cfg.fetchImpl ?? fetch;
  }

  private objectUrl(key: string): string {
    const cleanKey = key.replace(/^\/+/, '');
    const encodedKey = encodeS3Path(cleanKey);
    const base = new URL(this.endpoint.toString());
    const prefix = base.pathname.replace(/\/+$/, '');
    if (this.forcePathStyle) {
      base.pathname = `${prefix}/${encodeRfc3986(this.bucket)}/${encodedKey}`;
    } else {
      base.hostname = `${this.bucket}.${base.hostname}`;
      base.pathname = `${prefix}/${encodedKey}`;
    }
    return base.toString();
  }

  async head(key: string): Promise<R2Object | null> {
    const url = this.objectUrl(key);
    const headers = await buildSigV4Headers({
      method: 'HEAD',
      url,
      region: this.region,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.secretAccessKey,
    });
    const res = await this.fetchFn(url, { method: 'HEAD', headers });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`S3 HEAD failed with HTTP ${res.status}`);
    return parseS3ObjectMeta(key, res);
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    const url = this.objectUrl(key);
    const headers = await buildSigV4Headers({
      method: 'GET',
      url,
      region: this.region,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.secretAccessKey,
    });
    const res = await this.fetchFn(url, { method: 'GET', headers });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`S3 GET failed with HTTP ${res.status}`);
    const meta = parseS3ObjectMeta(key, res);
    const buf = await res.arrayBuffer();
    return {
      ...meta,
      body: new ReadableStream<Uint8Array>({
        start(ctrl) {
          ctrl.enqueue(new Uint8Array(buf));
          ctrl.close();
        },
      }),
      bodyUsed: false,
      async arrayBuffer(): Promise<ArrayBuffer> {
        return buf;
      },
      async text(): Promise<string> {
        return new TextDecoder().decode(buf);
      },
      async json<T = unknown>(): Promise<T> {
        return JSON.parse(new TextDecoder().decode(buf)) as T;
      },
      async blob(): Promise<Blob> {
        return new Blob([buf]);
      },
    } as unknown as R2ObjectBody;
  }

  async put(
    key: string,
    value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
    options?: R2PutOptions,
  ): Promise<R2Object | null> {
    const bytes = await readValueBytes(value);
    const payloadSha = await sha256Hex(bytes);
    if (options?.sha256 !== undefined) {
      let wantHex = '';
      if (typeof options.sha256 === 'string') {
        wantHex = options.sha256.trim().toLowerCase();
      } else if (options.sha256 instanceof ArrayBuffer) {
        wantHex = Array.from(new Uint8Array(options.sha256), (b) => b.toString(16).padStart(2, '0')).join('');
      } else if (ArrayBuffer.isView(options.sha256)) {
        const view = new Uint8Array(options.sha256.buffer, options.sha256.byteOffset, options.sha256.byteLength);
        wantHex = Array.from(view, (b) => b.toString(16).padStart(2, '0')).join('');
      }
      if (!wantHex || wantHex !== payloadSha.toLowerCase()) {
        throw new Error('R2 sha256 checksum mismatch');
      }
    }
    const extraHeaders: Record<string, string> = {
      'content-length': String(bytes.byteLength),
    };
    const httpMeta = options?.httpMetadata as { contentType?: string } | undefined;
    if (httpMeta?.contentType) extraHeaders['content-type'] = httpMeta.contentType;
    if (options?.customMetadata) {
      for (const [mk, mv] of Object.entries(options.customMetadata)) {
        extraHeaders[`x-amz-meta-${mk.toLowerCase()}`] = String(mv);
      }
    }
    const onlyIf = options?.onlyIf as Headers | { etagDoesNotMatch?: string } | undefined;
    if (onlyIf instanceof Headers && onlyIf.get('if-none-match') === '*') {
      extraHeaders['if-none-match'] = '*';
    } else if (onlyIf && !(onlyIf instanceof Headers) && onlyIf.etagDoesNotMatch === '*') {
      extraHeaders['if-none-match'] = '*';
    }

    const url = this.objectUrl(key);
    const headers = await buildSigV4Headers({
      method: 'PUT',
      url,
      region: this.region,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.secretAccessKey,
      headers: extraHeaders,
      payloadSha256: payloadSha,
    });
    const res = await this.fetchFn(url, { method: 'PUT', headers, body: bytes as BodyInit });
    if (res.status === 412 || res.status === 409) return null; // Conditional `If-None-Match: *` already exists
    if (!res.ok) throw new Error(`S3 PUT failed with HTTP ${res.status}`);
    return parseS3ObjectMeta(key, res);
  }

  async delete(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const key of list) {
      const url = this.objectUrl(key);
      const headers = await buildSigV4Headers({
        method: 'DELETE',
        url,
        region: this.region,
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
      });
      const res = await this.fetchFn(url, { method: 'DELETE', headers });
      if (!res.ok && res.status !== 404) {
        throw new Error(`S3 DELETE failed with HTTP ${res.status}`);
      }
    }
  }

  asR2Bucket(): R2Bucket {
    return this as unknown as R2Bucket;
  }
}
