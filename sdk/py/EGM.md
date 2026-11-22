# sdk/py

## Overview

`sdk/py` provides the zero-dependency Python standard-library client SDK (`edgefetch_client.py`) for the EdgeFetch Hub HTTP v1 API. It wraps synchronous Bearer-authenticated JSON requests with origin cleartext validation, W3C `traceparent` forwarding and response trace capture (`last_trace_id`, `lastTraceId`, `last_trace_parent`), multi-URL gateway failover (`502`/`503`/`504` and transport errors), and cross-origin redirect `Authorization` header stripping.

## Interface

- `[edgefetch_client.py:EdgeFetchError]` — `class EdgeFetchError(Exception)` carrying `status: int`, `code: str`, and `message: str`.
- `[edgefetch_client.py:EdgeFetchClient]` — Synchronous Hub API client exposing `base_urls: List[str]`, `token: str`, `timeout: float`, `traceparent: Optional[str]`, `last_trace_id: Optional[str]`, `last_trace_parent: Optional[str]`, and property `lastTraceId -> Optional[str]`.
- `[edgefetch_client.py:EdgeFetchClient.__init__]` — `(self, token: str, base_url: Optional[str] = None, base_urls: Optional[Sequence[str]] = None, timeout: float = 45.0, allow_insecure_http: bool = False, opener: Optional[Callable[[urllib.request.Request, float], Any]] = None, traceparent: Optional[str] = None) -> None`.
- `[edgefetch_client.py:EdgeFetchClient.capabilities]` — `(self, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/capabilities`).
- `[edgefetch_client.py:EdgeFetchClient.hosts]` — `(self, limit: int = 100, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/hosts?limit={safe_limit}`).
- `[edgefetch_client.py:EdgeFetchClient.extractors]` — `(self, category: Optional[str] = None, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/extractors[?category=...]`).
- `[edgefetch_client.py:EdgeFetchClient.scrape]` — `(self, url: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/scrape`).
- `[edgefetch_client.py:EdgeFetchClient.extract]` — `(self, urls: Iterable[str], query: Optional[str] = None, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/extract`).
- `[edgefetch_client.py:EdgeFetchClient.map]` — `(self, url: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/map`).
- `[edgefetch_client.py:EdgeFetchClient.crawl]` — `(self, url: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/crawl`).
- `[edgefetch_client.py:EdgeFetchClient.get_crawl]` — `(self, crawl_id: str, offset: int = 0, limit: int = 25, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/crawl/{crawl_id}?offset={offset}&limit={limit}`).
- `[edgefetch_client.py:EdgeFetchClient.search]` — `(self, query: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/search`).
- `[edgefetch_client.py:EdgeFetchClient.jobs]` — `(self, query: Optional[str] = None, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/jobs`).
- `[edgefetch_client.py:EdgeFetchClient.interact]` — `(self, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/interact`).
- `[edgefetch_client.py:EdgeFetchClient.batch_scrape]` — `(self, urls: Iterable[str], *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/batch/scrape`).
- `[edgefetch_client.py:EdgeFetchClient.get_batch_scrape]` — `(self, batch_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/batch/scrape/{batch_id}`).
- `[edgefetch_client.py:EdgeFetchClient.preview_crawl_params]` — `(self, url: str, prompt: str, traceparent: Optional[str] = None) -> Dict[str, Any]` (`POST /v1/crawl/params-preview`).
- `[edgefetch_client.py:EdgeFetchClient.agent]` — `(self, prompt: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]` (`POST /v1/agent`).
- `[edgefetch_client.py:EdgeFetchClient.get_agent]` — `(self, agent_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/agent/{agent_id}`).
- `[edgefetch_client.py:EdgeFetchClient.get_agent_trace]` — `(self, agent_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/agent/{agent_id}/trace`).
- `[edgefetch_client.py:EdgeFetchClient.cancel_agent]` — `(self, agent_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]` (`DELETE /v1/agent/{agent_id}`).
- `[edgefetch_client.py:EdgeFetchClient.read_artifact]` — `(self, blob_sha256: str, offset: int = 0, limit: int = 65536, fmt: Union[str, None] = "raw", traceparent: Optional[str] = None) -> Dict[str, Any]` (`GET /v1/artifacts/{blob_sha256}?format={q_fmt}&offset={offset}&limit={limit}`).

## Invariants

- `[edgefetch_client.py:EdgeFetchClient.__init__]` — Raises `ValueError` unless `base_urls` or `base_url` supplies at least one non-empty URL; strips surrounding whitespace and trailing `/`, and deduplicates `base_url` if already present in `base_urls`.
- `[edgefetch_client.py:_validate_hub_origin]` — Permits `https://` and loopback `http://` (`127.0.0.1`, `localhost`, `::1`) by default; rejects unsupported schemes, missing hosts, and cleartext non-loopback `http://` unless `allow_insecure_http=True`.
- `[edgefetch_client.py:_CrossOriginAuthStripRedirectHandler.redirect_request]` — Strips `Authorization` from both `redirected.headers` and `redirected.unredirected_hdrs` whenever an HTTP redirect changes `(scheme, netloc)`.
- `[edgefetch_client.py:EdgeFetchClient._request_json]` — Sends `Authorization: Bearer {token}`, `Accept: application/json`, and `User-Agent: EdgeFetchPythonSDK/2.1` on all requests, plus `Content-Type: application/json` when `body is not None`; decodes empty 2xx bodies as `{}` and maps `urllib.error.HTTPError` to `EdgeFetchError` (falling back to `{}` when the error body is empty, non-JSON, or non-dict JSON such as `null` or `[]`).
- `[edgefetch_client.py:EdgeFetchClient._request_json]` — Forwards outbound `traceparent` strictly as an HTTP header (keyword-only/named parameter on all methods so it never leaks into JSON request bodies). Trims whitespace, rejects `CR`/`LF`/`NUL`, permits non-W3C probe strings, and allows `traceparent=""` / whitespace to suppress the client default for a single call.
- `[edgefetch_client.py:EdgeFetchClient._request_json]` — Resets `last_trace_id = None` and `last_trace_parent = None` at the start of every `base_urls` attempt so stale trace IDs never leak across failover retries or onto final network errors; captures response `x-trace-id` (case-insensitively across `HTTPMessage`, `dict`, `.get()` objects, or `None`) with valid W3C `traceparent` 32-hex `traceId` fallback (`re.fullmatch`, rejecting all-zero trace/span IDs) immediately on response or `HTTPError` receipt.
- `[edgefetch_client.py:EdgeFetchClient._request_json]` — Fails over across `base_urls` only on HTTP `502`/`503`/`504` or non-`HTTPError` transport exceptions (exhausting naturally to `last_exc` or `RuntimeError` if `base_urls` is empty); raises `EdgeFetchError` immediately without failover on all other HTTP error status codes.
- `[edgefetch_client.py:EdgeFetchClient.hosts]` — Clamps `limit` to `[1, 500]` via `max(1, min(500, int(limit)))`.
- `[edgefetch_client.py:EdgeFetchClient.extractors]`, `[edgefetch_client.py:EdgeFetchClient.get_crawl]`, `[edgefetch_client.py:EdgeFetchClient.get_batch_scrape]`, `[edgefetch_client.py:EdgeFetchClient.get_agent]`, `[edgefetch_client.py:EdgeFetchClient.get_agent_trace]`, `[edgefetch_client.py:EdgeFetchClient.cancel_agent]`, `[edgefetch_client.py:EdgeFetchClient.read_artifact]` — Percent-encodes dynamic path segments and `category` query values with `urllib.parse.quote(..., safe="")`.
- `[edgefetch_client.py:EdgeFetchClient.read_artifact]` — Normalizes the `format` query parameter to `"markdown"` iff `fmt == "markdown"`, and `"json"` otherwise (including default `fmt="raw"` and `None`).

## Side Effects

- `[edgefetch_client.py:_DEFAULT_SAFE_OPENER]` — Instantiates a module-level `urllib.request.OpenerDirector` configured with `_CrossOriginAuthStripRedirectHandler` at import time.
- `[edgefetch_client.py:EdgeFetchClient._request_json]` — Issues synchronous outbound HTTP/HTTPS `GET`, `POST`, and `DELETE` requests to configured `base_urls` using `self._opener` and `self.timeout`, mutating `last_trace_id` and `last_trace_parent`.

## Verification

- Discover from repo root: `python -m unittest discover -s sdk/py -v`
- Direct module run from `sdk/py`: `python test_edgefetch_client.py -v`
