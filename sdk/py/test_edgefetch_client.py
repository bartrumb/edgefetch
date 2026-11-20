import io
import json
import unittest
import urllib.error
import urllib.request

from edgefetch_client import EdgeFetchClient, EdgeFetchError


class _FakeResp:
    def __init__(self, payload: dict) -> None:
        self._buf = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._buf

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *args: object) -> None:
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
                    hdrs=None,  # type: ignore[arg-type]
                    fp=io.BytesIO(b'{"error":"hub_unavailable","message":"evicting"}'),
                )
            return _FakeResp({"ok": True, "via": "standby-go-hub", "markdown": "# OK"})

        client = EdgeFetchClient(
            token="0123456789abcdef0123456789abcdef",
            base_urls=["https://primary.example.com", "https://standby.example.com"],
            opener=fake_opener,
        )
        res = client.scrape("https://example.com", maxChars=5000)
        self.assertEqual(res["via"], "standby-go-hub")
        self.assertEqual(len(visited), 2)

    def test_non_retryable_401_raises_typed_error(self) -> None:
        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            raise urllib.error.HTTPError(
                req.full_url,
                401,
                "Unauthorized",
                hdrs=None,  # type: ignore[arg-type]
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

    def test_jobs_endpoint(self) -> None:
        captured = {}

        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8")) if req.data else {}
            return _FakeResp({"ok": True, "count": 1, "jobs": [{"title": "Forward Deployed Engineer"}]})

        client = EdgeFetchClient(token="tok-123", base_url="https://hub.example.com", opener=fake_opener)
        out = client.jobs("Forward Deployed Engineer", remote=True, minBase=200000)
        self.assertEqual(captured["url"], "https://hub.example.com/v1/jobs")
        self.assertEqual(captured["body"], {"query": "Forward Deployed Engineer", "remote": True, "minBase": 200000})
        self.assertEqual(out["count"], 1)

    def test_hosts_endpoint(self) -> None:
        captured = {}

        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            captured["url"] = req.full_url
            return _FakeResp({"ok": True, "hosts": [{"host": "example.com", "recommendedPauseMs": 0}]})

        client = EdgeFetchClient(token="tok-123", base_url="https://hub.example.com", opener=fake_opener)
        out = client.hosts(limit=25)
        self.assertEqual(captured["url"], "https://hub.example.com/v1/hosts?limit=25")
        self.assertEqual(out["hosts"][0]["host"], "example.com")

    def test_agent_and_batch_scrape_endpoints(self) -> None:
        calls = []

        def fake_opener(req: urllib.request.Request, _timeout: float) -> _FakeResp:
            calls.append((req.get_method(), req.full_url, json.loads(req.data.decode("utf-8")) if req.data else None))
            return _FakeResp({"ok": True, "id": "agt_123", "status": "completed", "creditsUsed": 0})

        client = EdgeFetchClient(token="tok-123", base_url="https://hub.example.com", opener=fake_opener)
        res = client.agent("Find open roles and SEC filings", zeroDataRetention=True, llm={"provider": "ollama"})
        self.assertEqual(res["id"], "agt_123")
        _ = client.get_agent_trace("agt_123")
        _ = client.batch_scrape(["https://example.com/1", "https://example.com/2"], sync=True)
        self.assertEqual(calls[0][1], "https://hub.example.com/v1/agent")
        self.assertEqual(calls[0][2]["zeroDataRetention"], True)
        self.assertEqual(calls[1][1], "https://hub.example.com/v1/agent/agt_123/trace")
        self.assertEqual(calls[2][1], "https://hub.example.com/v1/batch/scrape")


if __name__ == "__main__":
    unittest.main()
