## Summary

<!-- Briefly describe what this PR adds or fixes, and link any related issue. -->

## Contributor Rules Checklist

- [ ] **Politeness & Ethics:** Verified `https://<domain>/robots.txt` allows any new adapter/twin URL; zero CAPTCHA solvers, stealth spoofers, or anti-bot bypasses.
- [ ] **Keyless Open Source:** New built-in adapters use public, keyless endpoints or HTML (no paid B2B API keys).
- [ ] **Minimal Supply Chain:** Kept `go.mod` at 1 external dependency (`github.com/coder/websocket`, `CGO_ENABLED=0`) and `hub/` at 0 runtime npm dependencies.
- [ ] **Workflow & Key Hygiene:** Does not touch `keys/release-signing-pub.pem` or release-signing workflows without maintainer coordination.
- [ ] **Tests & Formatting:** Added/updated deterministic unit tests or `hub/test/fixtures/adapters/<slug>.json` fixture (`gofmt -s`, `go test -race ./...`, and `cd hub && npm test` pass).
- [ ] **MIT License:** I have the right to submit these changes under the project's [MIT License](../LICENSE).
