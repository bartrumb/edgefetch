"""Zero-dependency Python 3.9+ client SDK for EdgeFetch v2.1 (`sdk/py/edgefetch_client.py`).

Uses only the Python standard library (`urllib.request`, `json`) and supports automatic
multi-controller High Availability failover (`base_urls=[primary_hub, standby_go_hub]`).

Drop-in compatibility note:
  - Existing Firecrawl Python SDK users can point `FirecrawlApp(api_url="https://<hub>/compat/firecrawl", api_key=TOKEN)`
  - Existing Tavily Python SDK users can POST directly to `https://<hub>/compat/tavily/search`
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union


_TRACEPARENT_RE = re.compile(r"00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-[0-9a-fA-F]{2}")
_ALL_ZERO_32 = "0" * 32
_ALL_ZERO_16 = "0" * 16
_FORBIDDEN_HEADER_CHARS_RE = re.compile(r"[\r\n\x00]")


def _sanitize_traceparent(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    if _FORBIDDEN_HEADER_CHARS_RE.search(raw):
        raise ValueError("Invalid traceparent header: contains forbidden CR, LF, or NUL character")
    cleaned = raw.strip()
    return cleaned or None


def _extract_header(headers: Any, name: str) -> Optional[str]:
    if headers is None:
        return None
    val: Any = headers.get(name) if hasattr(headers, "get") else None
    if val is None and hasattr(headers, "items"):
        target = name.lower()
        for k, v in headers.items():
            if str(k).lower() == target:
                val = v
                break
    if val is None:
        return None
    cleaned = str(val).strip()
    return cleaned or None


def _extract_trace_id_from_traceparent(traceparent: Optional[str]) -> Optional[str]:
    if not traceparent:
        return None
    match = _TRACEPARENT_RE.fullmatch(traceparent.strip())
    if not match:
        return None
    trace_id = match.group(1).lower()
    span_id = match.group(2).lower()
    if trace_id == _ALL_ZERO_32 or span_id == _ALL_ZERO_16:
        return None
    return trace_id


class EdgeFetchError(Exception):
    """Typed HTTP error raised when an EdgeFetch Hub returns a non-2xx status."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"[{status} {code}] {message}")
        self.status = status
        self.code = code
        self.message = message


class _CrossOriginAuthStripRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Strips Authorization headers whenever an HTTP redirect crosses origins (`Low`)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        orig = urllib.parse.urlsplit(req.full_url)
        dest = urllib.parse.urlsplit(newurl)
        if (orig.scheme, orig.netloc) != (dest.scheme, dest.netloc):
            redirected.headers.pop("Authorization", None)
            redirected.unredirected_hdrs.pop("Authorization", None)
        return redirected


_DEFAULT_SAFE_OPENER = urllib.request.build_opener(_CrossOriginAuthStripRedirectHandler())


def _validate_hub_origin(raw: str, allow_insecure_http: bool) -> str:
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").strip().lower().strip("[]")
    if scheme not in ("https", "http") or not host:
        raise ValueError(f"Invalid EdgeFetch Hub base URL {raw!r}: expected https:// origin")
    if scheme == "http" and not allow_insecure_http and host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"Refusing cleartext http:// Hub URL {raw!r} for non-loopback host {host!r} "
            "(use https:// or pass allow_insecure_http=True)"
        )
    return raw


class EdgeFetchClient:
    """Minimal, zero-dependency Python client for EdgeFetch v2.1."""

    def __init__(
        self,
        token: str,
        base_url: Optional[str] = None,
        base_urls: Optional[Sequence[str]] = None,
        timeout: float = 45.0,
        allow_insecure_http: bool = False,
        opener: Optional[Callable[[urllib.request.Request, float], Any]] = None,
        traceparent: Optional[str] = None,
    ) -> None:
        urls: List[str] = []
        if base_urls:
            urls.extend(u.strip().rstrip("/") for u in base_urls if u and u.strip())
        if base_url and base_url.strip():
            clean = base_url.strip().rstrip("/")
            if clean not in urls:
                urls.append(clean)
        if not urls:
            raise ValueError("EdgeFetchClient requires base_url or non-empty base_urls")
        self.base_urls = [_validate_hub_origin(u, allow_insecure_http) for u in urls]
        self.token = token
        self.timeout = timeout
        self._opener = opener or (lambda req, t: _DEFAULT_SAFE_OPENER.open(req, timeout=t))
        self.traceparent: Optional[str] = _sanitize_traceparent(traceparent)
        self.last_trace_id: Optional[str] = None
        self.last_trace_parent: Optional[str] = None

    @property
    def lastTraceId(self) -> Optional[str]:
        return self.last_trace_id

    def _capture_trace_headers(self, resp: Any) -> None:
        headers = getattr(resp, "headers", None)
        trace_parent = _extract_header(headers, "traceparent")
        trace_id = _extract_header(headers, "x-trace-id") or _extract_trace_id_from_traceparent(trace_parent)
        self.last_trace_parent = trace_parent
        self.last_trace_id = trace_id

    def _request_json(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        traceparent: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        active_tp = self.traceparent if traceparent is None else _sanitize_traceparent(traceparent)
        last_exc: Optional[Exception] = None

        for origin in self.base_urls:
            self.last_trace_id = None
            self.last_trace_parent = None
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": "EdgeFetchPythonSDK/2.1",
            }
            if active_tp:
                headers["traceparent"] = active_tp
            if payload_bytes is not None:
                headers["Content-Type"] = "application/json"

            req = urllib.request.Request(f"{origin}{path}", data=payload_bytes, headers=headers, method=method)
            try:
                with self._opener(req, self.timeout) as resp:
                    self._capture_trace_headers(resp)
                    raw = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as http_err:
                self._capture_trace_headers(http_err)
                raw_err = ""
                try:
                    raw_err = http_err.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                parsed: Dict[str, Any] = {}
                try:
                    loaded = json.loads(raw_err) if raw_err.strip() else {}
                    parsed = loaded if isinstance(loaded, dict) else {}
                except Exception:
                    parsed = {}
                ef_err = EdgeFetchError(
                    http_err.code,
                    str(parsed.get("error") or f"http_{http_err.code}"),
                    str(parsed.get("message") or f"EdgeFetch HTTP {http_err.code}"),
                )
                if http_err.code in (502, 503, 504):
                    last_exc = ef_err
                    continue
                raise ef_err from None
            except Exception as net_err:
                last_exc = net_err
                continue

        if last_exc is not None:
            raise last_exc
        raise RuntimeError("All EdgeFetch Hub endpoints failed")

    def capabilities(self, traceparent: Optional[str] = None) -> Dict[str, Any]:
        return self._request_json("GET", "/v1/capabilities", traceparent=traceparent)

    def hosts(self, limit: int = 100, traceparent: Optional[str] = None) -> Dict[str, Any]:
        safe_limit = max(1, min(500, int(limit)))
        return self._request_json("GET", f"/v1/hosts?limit={safe_limit}", traceparent=traceparent)

    def extractors(self, category: Optional[str] = None, traceparent: Optional[str] = None) -> Dict[str, Any]:
        qs = f"?category={urllib.parse.quote(category, safe='')}" if category else ""
        return self._request_json("GET", f"/v1/extractors{qs}", traceparent=traceparent)

    def scrape(self, url: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/scrape", {"url": url, **options}, traceparent=traceparent)

    def extract(
        self,
        urls: Iterable[str],
        query: Optional[str] = None,
        *,
        traceparent: Optional[str] = None,
        **options: Any,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"urls": list(urls), **options}
        if query is not None:
            body["query"] = query
        return self._request_json("POST", "/v1/extract", body, traceparent=traceparent)

    def map(self, url: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/map", {"url": url, **options}, traceparent=traceparent)

    def crawl(self, url: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/crawl", {"url": url, **options}, traceparent=traceparent)

    def get_crawl(
        self,
        crawl_id: str,
        offset: int = 0,
        limit: int = 25,
        traceparent: Optional[str] = None,
    ) -> Dict[str, Any]:
        cid = urllib.parse.quote(crawl_id, safe="")
        return self._request_json("GET", f"/v1/crawl/{cid}?offset={offset}&limit={limit}", traceparent=traceparent)

    def search(self, query: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/search", {"query": query, **options}, traceparent=traceparent)

    def jobs(
        self,
        query: Optional[str] = None,
        *,
        traceparent: Optional[str] = None,
        **options: Any,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = dict(options)
        if query is not None:
            body["query"] = query
        return self._request_json("POST", "/v1/jobs", body, traceparent=traceparent)

    def interact(self, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/interact", dict(options), traceparent=traceparent)

    def batch_scrape(self, urls: Iterable[str], *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/batch/scrape", {"urls": list(urls), **options}, traceparent=traceparent)

    def get_batch_scrape(self, batch_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]:
        bid = urllib.parse.quote(batch_id, safe="")
        return self._request_json("GET", f"/v1/batch/scrape/{bid}", traceparent=traceparent)

    def preview_crawl_params(self, url: str, prompt: str, traceparent: Optional[str] = None) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/crawl/params-preview", {"url": url, "prompt": prompt}, traceparent=traceparent)

    def agent(self, prompt: str, *, traceparent: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/agent", {"prompt": prompt, **options}, traceparent=traceparent)

    def get_agent(self, agent_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]:
        aid = urllib.parse.quote(agent_id, safe="")
        return self._request_json("GET", f"/v1/agent/{aid}", traceparent=traceparent)

    def get_agent_trace(self, agent_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]:
        aid = urllib.parse.quote(agent_id, safe="")
        return self._request_json("GET", f"/v1/agent/{aid}/trace", traceparent=traceparent)

    def cancel_agent(self, agent_id: str, traceparent: Optional[str] = None) -> Dict[str, Any]:
        aid = urllib.parse.quote(agent_id, safe="")
        return self._request_json("DELETE", f"/v1/agent/{aid}", traceparent=traceparent)

    def read_artifact(
        self,
        blob_sha256: str,
        offset: int = 0,
        limit: int = 65536,
        fmt: Union[str, None] = "raw",
        traceparent: Optional[str] = None,
    ) -> Dict[str, Any]:
        sha = urllib.parse.quote(blob_sha256, safe="")
        q_fmt = "markdown" if fmt == "markdown" else "json"
        return self._request_json(
            "GET",
            f"/v1/artifacts/{sha}?format={q_fmt}&offset={offset}&limit={limit}",
            traceparent=traceparent,
        )
