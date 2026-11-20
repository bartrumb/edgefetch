"""Zero-dependency Python 3.9+ client SDK for EdgeFetch v2.1 (`sdk/py/edgefetch_client.py`).

Uses only the Python standard library (`urllib.request`, `json`) and supports automatic
multi-controller High Availability failover (`base_urls=[primary_hub, standby_go_hub]`).

Drop-in compatibility note:
  - Existing Firecrawl Python SDK users can point `FirecrawlApp(api_url="https://<hub>/compat/firecrawl", api_key=TOKEN)`
  - Existing Tavily Python SDK users can POST directly to `https://<hub>/compat/tavily/search`
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union


class EdgeFetchError(Exception):
    """Typed HTTP error raised when an EdgeFetch Hub returns a non-2xx status."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"[{status} {code}] {message}")
        self.status = status
        self.code = code
        self.message = message


class EdgeFetchClient:
    """Minimal, zero-dependency Python client for EdgeFetch v2.1."""

    def __init__(
        self,
        token: str,
        base_url: Optional[str] = None,
        base_urls: Optional[Sequence[str]] = None,
        timeout: float = 45.0,
        opener: Optional[Callable[[urllib.request.Request, float], Any]] = None,
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
        self.base_urls = urls
        self.token = token
        self.timeout = timeout
        self._opener = opener or (lambda req, t: urllib.request.urlopen(req, timeout=t))

    def _request_json(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        last_exc: Optional[Exception] = None

        for idx, origin in enumerate(self.base_urls):
            has_more = idx + 1 < len(self.base_urls)
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": "EdgeFetchPythonSDK/2.1",
            }
            if payload_bytes is not None:
                headers["Content-Type"] = "application/json"

            req = urllib.request.Request(f"{origin}{path}", data=payload_bytes, headers=headers, method=method)
            try:
                with self._opener(req, self.timeout) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as http_err:
                raw_err = ""
                try:
                    raw_err = http_err.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                parsed: Dict[str, Any] = {}
                try:
                    parsed = json.loads(raw_err) if raw_err.strip() else {}
                except Exception:
                    parsed = {}
                ef_err = EdgeFetchError(
                    http_err.code,
                    str(parsed.get("error") or f"http_{http_err.code}"),
                    str(parsed.get("message") or f"EdgeFetch HTTP {http_err.code}"),
                )
                if has_more and http_err.code in (502, 503, 504):
                    last_exc = ef_err
                    continue
                raise ef_err from None
            except Exception as net_err:
                last_exc = net_err
                if has_more:
                    continue
                raise

        if last_exc is not None:
            raise last_exc
        raise RuntimeError("All EdgeFetch Hub endpoints failed")

    def capabilities(self) -> Dict[str, Any]:
        return self._request_json("GET", "/v1/capabilities")

    def scrape(self, url: str, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/scrape", {"url": url, **options})

    def extract(self, urls: Iterable[str], query: Optional[str] = None, **options: Any) -> Dict[str, Any]:
        body: Dict[str, Any] = {"urls": list(urls), **options}
        if query is not None:
            body["query"] = query
        return self._request_json("POST", "/v1/extract", body)

    def map(self, url: str, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/map", {"url": url, **options})

    def crawl(self, url: str, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/crawl", {"url": url, **options})

    def get_crawl(self, crawl_id: str, offset: int = 0, limit: int = 25) -> Dict[str, Any]:
        cid = urllib.parse.quote(crawl_id, safe="")
        return self._request_json("GET", f"/v1/crawl/{cid}?offset={offset}&limit={limit}")

    def search(self, query: str, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/search", {"query": query, **options})

    def interact(self, **options: Any) -> Dict[str, Any]:
        return self._request_json("POST", "/v1/interact", dict(options))

    def read_artifact(
        self,
        blob_sha256: str,
        offset: int = 0,
        limit: int = 65536,
        fmt: Union[str, None] = "raw",
    ) -> Dict[str, Any]:
        sha = urllib.parse.quote(blob_sha256, safe="")
        q_fmt = "markdown" if fmt == "markdown" else "json"
        return self._request_json("GET", f"/v1/artifacts/{sha}?format={q_fmt}&offset={offset}&limit={limit}")
