## Summary

<!-- Briefly describe what this PR adds or fixes. -->

## Checklist

- [ ] **Politeness & Ethics:** Verified `/robots.txt` allows any new adapter/twin URL; zero CAPTCHA solvers, stealth spoofers, or anti-bot bypasses.
- [ ] **Keyless Open Source:** New built-in adapters use public, keyless endpoints or HTML (no paid B2B API keys).
- [ ] **Supply Chain:** Kept `go.mod` at 1 external dependency (`github.com/coder/websocket`) and `hub/` at 0 runtime npm dependencies.
- [ ] **Tests:** Added/updated deterministic unit tests or `hub/test/fixtures/adapters/<slug>.json` fixture (`npm test` & `go test -race ./...` pass).
