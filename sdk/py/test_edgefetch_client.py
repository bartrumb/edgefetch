import email.parser
import http.client
import io
import json
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from unittest import mock

import edgefetch_client
from edgefetch_client import EdgeFetchClient, EdgeFetchError, _CrossOriginAuthStripRedirectHandler


TRACE_A = "00-0123456789abcdef0123456789abcdef-1111111111111111-01"
TRACE_A_ID = "0123456789abcdef0123456789abcdef"
TRACE_B = "00-FEDCBA9876543210FEDCBA9876543210-2222222222222222-00"
TRACE_B_ID = "fedcba9876543210fedcba9876543210"


def _make_http_message(raw_headers: str) -> http.client.HTTPMessage:
    return email.parser.Parser(http.client.HTTPMessage).parsestr(raw_headers)


class _FakeResp:
    def __init__(self, payload: Any, headers: Any = None, raw_bytes: Optional[bytes] = None) -> None:
        self._buf = raw_bytes if raw_bytes is not None else json.dumps(payload).encode("utf-8")
        if headers is not None:
            self.headers = headers

    def read(self) -> bytes:
        return self._buf

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _GetOnlyHeaders:
    def __init__(self, values: Dict[str, str]) -> None:
        self._values = values

    def get(self, key: str) -> Optional[str]:
        return self._values.get(key)


class _BrokenReadErrorStream:
    def read(self) -> bytes:
        raise OSError("stream broken")

    def close(self) -> None:
        return None


class TestEdgeFetchPythonSDK(unittest.TestCase):
    def test_ha_failover_and_scrape(self) -> None:
        visited = []

        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            visited.append(req.full_url)
            if req.full_url.startswith("https://primary.example.com"):
                raise urllib.error.HTTPError(
                    req.full_url,
                    503,
                    "Service Unavailable",
                    hdrs=_make_http_message(f"X-Trace-Id: {TRACE_A_ID}\nTraceparent: {TRACE_A}\n"),
                    fp=io.BytesIO(b'{"error":"hub_unavailable","message":"evicting"}'),
                )
            return _FakeResp(
                {"ok": True, "via": "standby-go-hub", "markdown": "# OK"},
                headers=_make_http_message(f"X-Trace-Id: {TRACE_B_ID}\nTraceparent: {TRACE_B}\n"),
            )

        client = EdgeFetchClient(
            token="0123456789abcdef0123456789abcdef",
            base_urls=["https://primary.example.com", "https://standby.example.com"],
            opener=fake_opener,
        )
        res = client.scrape("https://example.com", maxChars=5000)
        self.assertEqual(res["via"], "standby-go-hub")
        self.assertEqual(len(visited), 2)
        self.assertEqual(client.last_trace_id, TRACE_B_ID)
        self.assertEqual(client.lastTraceId, TRACE_B_ID)
        self.assertEqual(client.last_trace_parent, TRACE_B)

    def test_non_retryable_401_raises_typed_error_and_captures_trace_headers(self) -> None:
        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            raise urllib.error.HTTPError(
                req.full_url,
                401,
                "Unauthorized",
                hdrs=_make_http_message(f"X-Trace-Id: {TRACE_A_ID}\nTraceparent: {TRACE_A}\n"),
                fp=io.BytesIO(b'{"error":"unauthorized","message":"bad token"}'),
            )

        client = EdgeFetchClient(
            token="bad",
            base_urls=["https://primary.example.com", "https://standby.example.com"],
            opener=fake_opener,
        )
        with self.assertRaises(EdgeFetchError) as ctx:
            client.capabilities()
        self.assertEqual(ctx.exception.status, 401)
        self.assertEqual(ctx.exception.code, "unauthorized")
        self.assertEqual(ctx.exception.message, "bad token")
        self.assertEqual(client.last_trace_id, TRACE_A_ID)
        self.assertEqual(client.lastTraceId, TRACE_A_ID)
        self.assertEqual(client.last_trace_parent, TRACE_A)

    def test_constructor_validation_dedup_and_default_opener(self) -> None:
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok")
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok", base_url="   ", base_urls=["", "   "])
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok", base_url="ftp://hub.example.com")
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok", base_url="https:///nohost")
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok", base_url="not-a-url")
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok", base_url="https://hub.example.com", traceparent="00-bad\r\n")
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok", base_url="https://hub.example.com", traceparent="00-bad\x00")

        dedup = EdgeFetchClient(
            token="tok",
            base_urls=["", "   ", "https://a.example.com/"],
            base_url="https://a.example.com///",
            traceparent="   ",
        )
        self.assertEqual(dedup.base_urls, ["https://a.example.com"])
        self.assertIsNone(dedup.traceparent)

        both = EdgeFetchClient(
            token="tok",
            base_urls=["https://a.example.com"],
            base_url="https://b.example.com/",
        )
        self.assertEqual(both.base_urls, ["https://a.example.com", "https://b.example.com"])

        with mock.patch.object(
            edgefetch_client._DEFAULT_SAFE_OPENER,
            "open",
            return_value=_FakeResp({"ok": True, "default": True}),
        ) as mock_open:
            out = dedup.capabilities()
            self.assertEqual(out["default"], True)
            mock_open.assert_called_once()

    def test_cross_origin_redirect_strips_authorization_header(self) -> None:
        handler = _CrossOriginAuthStripRedirectHandler()
        orig = urllib.request.Request(
            "https://hub.example.com/v1/scrape",
            headers={"Authorization": "Bearer super-secret-token", "Accept": "application/json"},
        )
        same_origin = handler.redirect_request(
            orig, None, 307, "Temporary Redirect", {}, "https://hub.example.com/v2/scrape"  # type: ignore[arg-type]
        )
        self.assertIsNotNone(same_origin)
        assert same_origin is not None
        self.assertEqual(same_origin.get_header("Authorization"), "Bearer super-secret-token")

        cross_origin = handler.redirect_request(
            orig, None, 302, "Found", {}, "https://evil.example.org/collect"  # type: ignore[arg-type]
        )
        self.assertIsNotNone(cross_origin)
        assert cross_origin is not None
        self.assertIsNone(cross_origin.get_header("Authorization"))

        with mock.patch.object(urllib.request.HTTPRedirectHandler, "redirect_request", return_value=None):
            self.assertIsNone(
                handler.redirect_request(
                    orig, None, 302, "Found", {}, "https://evil.example.org/collect"  # type: ignore[arg-type]
                )
            )

    def test_cleartext_http_rejected_unless_loopback_or_explicit_opt_in(self) -> None:
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok-123", base_url="http://remote-hub.example.com")
        with self.assertRaises(ValueError):
            EdgeFetchClient(token="tok-123", base_urls=["https://ok.example.com", "http://192.168.1.50:8787"])

        for loopback in ("http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787"):
            c = EdgeFetchClient(token="tok-123", base_url=loopback)
            self.assertEqual(c.base_urls, [loopback])

        opted_in = EdgeFetchClient(token="tok-123", base_url="http://hub.internal:8787", allow_insecure_http=True)
        self.assertEqual(opted_in.base_urls, ["http://hub.internal:8787"])

    def test_traceparent_forwarding_override_suppression_probe_and_body_isolation(self) -> None:
        captured: list[tuple[Optional[str], Optional[Dict[str, Any]]]] = []

        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            body = json.loads(req.data.decode("utf-8")) if req.data else None
            captured.append((req.get_header("Traceparent"), body))
            return _FakeResp({"ok": True}, headers=_make_http_message(f"X-Trace-Id: {TRACE_A_ID}\n"))

        client = EdgeFetchClient(
            token="tok-tp",
            base_url="https://hub.example.com",
            traceparent=f"  {TRACE_A}  ",
            opener=fake_opener,
        )
        self.assertIsNone(client.last_trace_id)
        self.assertIsNone(client.lastTraceId)
        self.assertIsNone(client.last_trace_parent)

        client.scrape("https://example.com", maxChars=100)
        client.scrape("https://example.com/2", traceparent=f"  {TRACE_B}  ", maxChars=200)
        client.scrape("https://example.com/3", **{"traceparent": TRACE_B, "maxChars": 300})
        client.scrape("https://example.com/4", traceparent="")
        client.capabilities(traceparent="non-w3c-probe")

        self.assertEqual(captured[0], (TRACE_A, {"url": "https://example.com", "maxChars": 100}))
        self.assertEqual(captured[1], (TRACE_B, {"url": "https://example.com/2", "maxChars": 200}))
        self.assertEqual(captured[2], (TRACE_B, {"url": "https://example.com/3", "maxChars": 300}))
        self.assertEqual(captured[3], (None, {"url": "https://example.com/4"}))
        self.assertEqual(captured[4], ("non-w3c-probe", None))

        with self.assertRaises(ValueError):
            client.capabilities(traceparent="bad\nheader")

    def test_response_header_extraction_variants_and_traceparent_fallback(self) -> None:
        responses = [
            # 0: no .headers attribute
            _FakeResp({"ok": True}),
            # 1: headers is None
            _FakeResp({"ok": True}, headers=None),
            # 2: plain dict with mixed-case keys
            _FakeResp({"ok": True}, headers={"Other": "x", "X-Trace-Id": f" {TRACE_A_ID} ", "Traceparent": TRACE_A}),
            # 3: plain dict without matching keys
            _FakeResp({"ok": True}, headers={"Content-Type": "application/json"}),
            # 4: .get()-only object with whitespace-only value & missing key
            _FakeResp({"ok": True}, headers=_GetOnlyHeaders({"x-trace-id": "   ", "traceparent": TRACE_B})),
            # 5: .get()-only object returning None for both
            _FakeResp({"ok": True}, headers=_GetOnlyHeaders({})),
            # 6: object with neither .get nor .items
            _FakeResp({"ok": True}, headers=object()),
            # 7: HTTPMessage with uppercase traceparent fallback only
            _FakeResp({"ok": True}, headers=_make_http_message(f"Traceparent:  {TRACE_B} \n")),
            # 8: malformed traceparent
            _FakeResp({"ok": True}, headers={"traceparent": "invalid"}),
            # 9: all-zero traceId
            _FakeResp({"ok": True}, headers={"traceparent": "00-00000000000000000000000000000000-1111111111111111-01"}),
            # 10: all-zero spanId
            _FakeResp({"ok": True}, headers={"traceparent": f"00-{TRACE_A_ID}-0000000000000000-01"}),
            # 11: empty whitespace 2xx body -> {}
            _FakeResp(None, headers={"x-trace-id": TRACE_A_ID}, raw_bytes=b"   "),
        ]
        # Force explicit None .headers on entry 1 (since _FakeResp skips setting if None)
        responses[1].headers = None  # type: ignore[attr-defined]

        idx = 0

        def fake_opener(_req: urllib.request.Request, _timeout: float) -> _FakeResp:
            nonlocal idx
            resp = responses[idx]
            idx += 1
            return resp

        client = EdgeFetchClient(token="tok", base_url="https://hub.example.com", opener=fake_opener)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)
        self.assertIsNone(client.last_trace_parent)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)

        client.capabilities()
        self.assertEqual(client.last_trace_id, TRACE_A_ID)
        self.assertEqual(client.last_trace_parent, TRACE_A)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)

        client.capabilities()
        self.assertEqual(client.last_trace_id, TRACE_B_ID)
        self.assertEqual(client.last_trace_parent, TRACE_B)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)
        self.assertIsNone(client.last_trace_parent)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)

        client.capabilities()
        self.assertEqual(client.last_trace_id, TRACE_B_ID)
        self.assertEqual(client.last_trace_parent, TRACE_B)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)
        self.assertEqual(client.last_trace_parent, "invalid")

        client.capabilities()
        self.assertIsNone(client.last_trace_id)

        client.capabilities()
        self.assertIsNone(client.last_trace_id)

        empty_out = client.capabilities()
        self.assertEqual(empty_out, {})
        self.assertEqual(client.last_trace_id, TRACE_A_ID)

    def test_error_bodies_failover_exhaustion_network_errors_and_reset(self) -> None:
        # 1. HTTPError with broken .read(), empty body, and non-JSON body
        def opener_broken_err(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            raise urllib.error.HTTPError(
                req.full_url,
                500,
                "Internal",
                hdrs=None,  # type: ignore[arg-type]
                fp=_BrokenReadErrorStream(),  # type: ignore[arg-type]
            )

        c1 = EdgeFetchClient(token="tok", base_url="https://hub.example.com", opener=opener_broken_err)
        with self.assertRaises(EdgeFetchError) as ctx1:
            c1.capabilities()
        self.assertEqual(ctx1.exception.status, 500)
        self.assertEqual(ctx1.exception.code, "http_500")
        self.assertEqual(ctx1.exception.message, "EdgeFetch HTTP 500")

        def opener_html_err(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            raise urllib.error.HTTPError(
                req.full_url,
                502,
                "Bad Gateway",
                hdrs={"x-trace-id": TRACE_A_ID},  # type: ignore[arg-type]
                fp=io.BytesIO(b"<html>502</html>"),
            )

        c2 = EdgeFetchClient(
            token="tok",
            base_urls=["https://a.example.com", "https://b.example.com"],
            opener=opener_html_err,
        )
        with self.assertRaises(EdgeFetchError) as ctx2:
            c2.capabilities()
        self.assertEqual(ctx2.exception.status, 502)
        self.assertEqual(ctx2.exception.code, "http_502")
        self.assertEqual(c2.last_trace_id, TRACE_A_ID)

        # 2. Empty error body on 404
        def opener_empty_err(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            raise urllib.error.HTTPError(
                req.full_url,
                404,
                "Not Found",
                hdrs=None,  # type: ignore[arg-type]
                fp=io.BytesIO(b"   "),
            )

        c3 = EdgeFetchClient(token="tok", base_url="https://hub.example.com", opener=opener_empty_err)
        with self.assertRaises(EdgeFetchError) as ctx3:
            c3.capabilities()
        self.assertEqual(ctx3.exception.status, 404)

        # 3. Network OSError failover -> 200
        attempts = 0

        def opener_net_failover(_req: urllib.request.Request, _timeout: float) -> _FakeResp:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("temporary reset")
            return _FakeResp({"ok": True})

        c4 = EdgeFetchClient(
            token="tok",
            base_urls=["https://a.example.com", "https://b.example.com"],
            opener=opener_net_failover,
        )
        self.assertEqual(c4.capabilities(), {"ok": True})

        # 4. 503 with trace-A on primary followed by network OSError on standby -> clears trace headers & raises OSError
        step = 0

        def opener_503_then_net(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            nonlocal step
            step += 1
            if step == 1:
                raise urllib.error.HTTPError(
                    req.full_url,
                    503,
                    "Unavailable",
                    hdrs={"x-trace-id": TRACE_A_ID, "traceparent": TRACE_A},  # type: ignore[arg-type]
                    fp=io.BytesIO(b"{}"),
                )
            raise OSError("standby unreachable")

        c5 = EdgeFetchClient(
            token="tok",
            base_urls=["https://a.example.com", "https://b.example.com"],
            opener=opener_503_then_net,
        )
        with self.assertRaises(OSError):
            c5.capabilities()
        self.assertIsNone(c5.last_trace_id)
        self.assertIsNone(c5.last_trace_parent)

        # 5. Mutated empty base_urls -> RuntimeError
        c6 = EdgeFetchClient(token="tok", base_url="https://hub.example.com", opener=opener_net_failover)
        c6.base_urls = []
        with self.assertRaises(RuntimeError):
            c6.capabilities()

        # 6. Non-dict JSON error bodies (b"null", b"[]") fail over cleanly on 503 and raise EdgeFetchError on 401
        null_failover_calls = []

        def opener_503_null_then_200(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            null_failover_calls.append(req.full_url)
            if len(null_failover_calls) == 1:
                raise urllib.error.HTTPError(
                    req.full_url,
                    503,
                    "Unavailable",
                    hdrs={"x-trace-id": TRACE_A_ID},  # type: ignore[arg-type]
                    fp=io.BytesIO(b"null"),
                )
            return _FakeResp({"ok": True, "recovered": True}, headers={"x-trace-id": TRACE_B_ID})

        c7 = EdgeFetchClient(
            token="tok",
            base_urls=["https://a.example.com", "https://b.example.com"],
            opener=opener_503_null_then_200,
        )
        self.assertEqual(c7.capabilities(), {"ok": True, "recovered": True})
        self.assertEqual(len(null_failover_calls), 2)
        self.assertEqual(c7.last_trace_id, TRACE_B_ID)

        for raw_non_dict in (b"null", b"[]"):
            def opener_401_non_dict(
                req: urllib.request.Request, _timeout: float, body: bytes = raw_non_dict
            ) -> _FakeResp:
                raise urllib.error.HTTPError(
                    req.full_url,
                    401,
                    "Unauthorized",
                    hdrs={"x-trace-id": TRACE_A_ID, "traceparent": TRACE_A},  # type: ignore[arg-type]
                    fp=io.BytesIO(body),
                )

            c_non_dict = EdgeFetchClient(
                token="tok",
                base_url="https://hub.example.com",
                opener=opener_401_non_dict,
            )
            with self.assertRaises(EdgeFetchError) as ctx_nd:
                c_non_dict.capabilities()
            self.assertEqual(ctx_nd.exception.status, 401)
            self.assertEqual(ctx_nd.exception.code, "http_401")
            self.assertEqual(ctx_nd.exception.message, "EdgeFetch HTTP 401")
            self.assertEqual(c_non_dict.last_trace_id, TRACE_A_ID)
            self.assertEqual(c_non_dict.last_trace_parent, TRACE_A)

    def test_all_19_public_methods_routes_params_and_traceparent(self) -> None:
        calls: list[tuple[str, str, Optional[str], Optional[Dict[str, Any]]]] = []

        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            body = json.loads(req.data.decode("utf-8")) if req.data else None
            calls.append((req.get_method(), req.full_url, req.get_header("Traceparent"), body))
            return _FakeResp({"ok": True})

        client = EdgeFetchClient(token="tok-123", base_url="https://hub.example.com", opener=fake_opener)

        client.capabilities(traceparent=TRACE_B)
        client.hosts(limit=0, traceparent=TRACE_B)
        client.hosts(limit=9999, traceparent=TRACE_B)
        client.extractors(traceparent=TRACE_B)
        client.extractors("jobs/ats", traceparent=TRACE_B)
        client.scrape("https://example.com", traceparent=TRACE_B, formats=["markdown"])
        client.extract(["https://example.com"], query=None, traceparent=TRACE_B, mode="full")
        client.extract(["https://example.com"], query="jobs", traceparent=TRACE_B)
        client.map("https://example.com", traceparent=TRACE_B, limit=10)
        client.crawl("https://example.com", traceparent=TRACE_B, maxDepth=2)
        client.get_crawl("crawl/1", offset=5, limit=10, traceparent=TRACE_B)
        client.search("edgefetch", traceparent=TRACE_B, max_results=5)
        client.jobs(query=None, traceparent=TRACE_B, remote=True)
        client.jobs("Forward Deployed Engineer", traceparent=TRACE_B, minBase=200000)
        client.interact(traceparent=TRACE_B, url="https://example.com", keepSession=True)
        client.batch_scrape(["https://example.com/1"], traceparent=TRACE_B, sync=True)
        client.get_batch_scrape("batch/1", traceparent=TRACE_B)
        client.preview_crawl_params("https://example.com", "docs only", traceparent=TRACE_B)
        client.agent("Summarize", traceparent=TRACE_B, effort="low")
        client.get_agent("agt/1", traceparent=TRACE_B)
        client.get_agent_trace("agt/1", traceparent=TRACE_B)
        client.cancel_agent("agt/1", traceparent=TRACE_B)
        client.read_artifact("sha/1", traceparent=TRACE_B)
        client.read_artifact("sha/1", offset=10, limit=20, fmt="markdown", traceparent=TRACE_B)

        expected = [
            ("GET", "https://hub.example.com/v1/capabilities", None),
            ("GET", "https://hub.example.com/v1/hosts?limit=1", None),
            ("GET", "https://hub.example.com/v1/hosts?limit=500", None),
            ("GET", "https://hub.example.com/v1/extractors", None),
            ("GET", "https://hub.example.com/v1/extractors?category=jobs%2Fats", None),
            ("POST", "https://hub.example.com/v1/scrape", {"url": "https://example.com", "formats": ["markdown"]}),
            ("POST", "https://hub.example.com/v1/extract", {"urls": ["https://example.com"], "mode": "full"}),
            ("POST", "https://hub.example.com/v1/extract", {"urls": ["https://example.com"], "query": "jobs"}),
            ("POST", "https://hub.example.com/v1/map", {"url": "https://example.com", "limit": 10}),
            ("POST", "https://hub.example.com/v1/crawl", {"url": "https://example.com", "maxDepth": 2}),
            ("GET", "https://hub.example.com/v1/crawl/crawl%2F1?offset=5&limit=10", None),
            ("POST", "https://hub.example.com/v1/search", {"query": "edgefetch", "max_results": 5}),
            ("POST", "https://hub.example.com/v1/jobs", {"remote": True}),
            ("POST", "https://hub.example.com/v1/jobs", {"query": "Forward Deployed Engineer", "minBase": 200000}),
            ("POST", "https://hub.example.com/v1/interact", {"url": "https://example.com", "keepSession": True}),
            ("POST", "https://hub.example.com/v1/batch/scrape", {"urls": ["https://example.com/1"], "sync": True}),
            ("GET", "https://hub.example.com/v1/batch/scrape/batch%2F1", None),
            ("POST", "https://hub.example.com/v1/crawl/params-preview", {"url": "https://example.com", "prompt": "docs only"}),
            ("POST", "https://hub.example.com/v1/agent", {"prompt": "Summarize", "effort": "low"}),
            ("GET", "https://hub.example.com/v1/agent/agt%2F1", None),
            ("GET", "https://hub.example.com/v1/agent/agt%2F1/trace", None),
            ("DELETE", "https://hub.example.com/v1/agent/agt%2F1", None),
            ("GET", "https://hub.example.com/v1/artifacts/sha%2F1?format=json&offset=0&limit=65536", None),
            ("GET", "https://hub.example.com/v1/artifacts/sha%2F1?format=markdown&offset=10&limit=20", None),
        ]

        self.assertEqual(len(calls), len(expected))
        for (method, url, tp, body), (exp_method, exp_url, exp_body) in zip(calls, expected):
            self.assertEqual(method, exp_method)
            self.assertEqual(url, exp_url)
            self.assertEqual(tp, TRACE_B)
            self.assertEqual(body, exp_body)


if __name__ == "__main__":
    unittest.main()
