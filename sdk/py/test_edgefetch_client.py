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


if __name__ == "__main__":
    unittest.main()
