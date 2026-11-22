## Summary

<!-- Briefly describe what this PR adds or fixes, and link any related issue. -->

## Contributor Rules Checklist

- [ ] **Politeness & Ethics:** Verified `https://<domain>/robots.txt` allows any new adapter/twin URL; zero CAPTCHA solvers, stealth spoofers, or anti-bot bypasses.
- [ ] **Keyless MIT Adapters:** New built-in adapters (`internal/extract/manifests/` or `hub/src/extractors/`) use public, keyless endpoints or HTML (no paid B2B API keys).
- [ ] **Minimal Supply Chain:** Kept `go.mod` at 1 external dependency (`github.com/coder/websocket`, `CGO_ENABLED=0`) and added no unapproved npm dependencies in `hub/`.
- [ ] **Workflow & Key Hygiene:** Does not touch `keys/release-signing-pub.pem` or release-signing workflows without maintainer coordination.
- [ ] **Tests & Formatting:** Added/updated deterministic unit tests or `hub/test/fixtures/adapters/<slug>.json` fixture (`gofmt -s`, `go test -race ./...`, and `cd hub && npm test` pass).
- [ ] **Inbound = MIT + DCO (`git commit -s`):** I have signed off my commits (`Signed-off-by:`) and license this contribution inbound under the [MIT License](../LICENSE).
