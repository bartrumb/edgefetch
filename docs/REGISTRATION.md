# Official Registration, Certification & Release Verification Guide

EdgeFetch participates in two trust ecosystems:

1. **Bot & WAF Verification Registries** — proving your self-hosted Hub and edge fleet are polite, user-triggered retrieval agents (`robots.txt`-compliant, non-training, cryptographically signed via IETF RFC 9421).
2. **MCP, Supply-Chain & Open-Source Trust Registries** — verifying official release binaries/containers and listing EdgeFetch in Model Context Protocol (MCP) directories.

---

## Important Rule: Project Identity vs. Operator Signing Keys

A public binary **must never** ship a shared bot-signing key inside the repository — anyone could abuse it and get the key revoked globally. Instead, registration separates cleanly into two layers:

| Layer | Who Registers It | What Gets Registered |
| --- | --- | --- |
| **1. Public Project Identity** | Project Maintainer (`@bartrumb`) | Public `EdgeFetch` User-Agent documentation, MCP Registry (`io.github.bartrumb/edgefetch`), Glama (`glama.json`), OpenSSF Best Practices, and official release signing (`keys/release-signing-pub.pem` + SLSA provenance). |
| **2. Deployed Fleet Identity (Web Bot Auth)** | Each Self-Hosted Operator (including your own Hub domain) | Your own Ed25519 keypair minted via `edgefetch keygen-bot-auth`, served with self-signed RFC 9421 headers at `https://<your-hub>/.well-known/http-message-signatures-directory`, submitted to **Cloudflare Verified Bots**. |

---

## Part 1: Registering Your Deployed Fleet with WAF & Bot Authorities

### 1. Cloudflare Verified Bots (IETF RFC 9421 Web Bot Auth)

EdgeFetch (`v2.5.2+`) natively implements **100% of Cloudflare's Web Bot Auth specification** (`RFC 9421` + `draft-meunier-http-message-signatures-directory`), including:
- Outbound `Signature-Input`, `Signature`, and `Signature-Agent` headers (`alg="ed25519"`, `tag="web-bot-auth"`).
- `GET /.well-known/http-message-signatures-directory` returning `application/http-message-signatures-directory+json` with RFC 7638 `kid` thumbprints, `"nbf"` validity timestamps, `Content-Digest: sha-256=:...:`, and RFC 9421 self-signature headers (`Signature-Input: directory=("@authority";req "content-digest");...;tag="http-message-signatures-directory"`).
- `GET /.well-known/edgefetch-bot.json` declaring `category: "user-triggered-agent-retrieval"`, `robotsTxt: "strict-rfc9309"`, `contentSignals: "honored (ai-input)"`, and `aiModelTraining: false`.

#### Step-by-Step Setup (< 3 Minutes)

1. **Mint your fleet's Ed25519 keypair locally:**
   ```bash
   edgefetch keygen-bot-auth
   ```
2. **Configure your Hub secret** (Cloudflare Workers Hub or self-hosted Go/Portable Hub):
   ```bash
   cd hub
   npx wrangler secret put BOT_SIGNING_PRIVATE_KEY
   # Paste the `privateKeySeed` value printed by keygen-bot-auth
   ```
   *(Optional)* Set `BOT_CONTACT_URL` in `wrangler.jsonc` (e.g., `https://github.com/bartrumb/edgefetch` or `mailto:ops@yourdomain.com`).
3. **Configure your Go Edge Nodes** (optional if your nodes fetch directly; Cloudflare overflow already signs automatically when `BOT_SIGNING_PRIVATE_KEY` is set on the Hub):
   - Set `EDGEFETCH_BOT_SIGNING_KEY=<privateKeySeed>` and `EDGEFETCH_BOT_DIRECTORY_URL=https://<your-hub-domain>/.well-known/http-message-signatures-directory`.
4. **Verify your live directory endpoint before submitting:**
   ```bash
   curl -i https://<your-hub-domain>/.well-known/http-message-signatures-directory
   ```
   Confirm you see:
   - `HTTP/2 200`
   - `content-type: application/http-message-signatures-directory+json; charset=utf-8`
   - `content-digest: sha-256=:...:`
   - `signature-input: directory=("@authority";req "content-digest");...;tag="http-message-signatures-directory"`
   - `signature: directory=:...:`
   - JSON body with `"keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "...", "x": "...", "nbf": ... }]`
5. **Submit to Cloudflare Verified Bots:**
   - Open **Cloudflare Dashboard -> Configurations -> Lists / Bot Management -> Verified Bots Submission** (or <https://radar.cloudflare.com/traffic/verified-bots>).
   - Select **Category:** *AI Assistant / User-Triggered Fetcher* (not training crawler).
   - Select **Verification Method:** *Web Bot Auth (HTTP Message Signatures)* and enter `https://<your-hub-domain>/.well-known/http-message-signatures-directory`.

---

### 2. Known Agents (`knownagents.com` / Dark Visitors) & Community Bot Lists

Public `robots.txt` governance platforms track open-source agent `User-Agent` tokens so site owners distinguish polite user-triggered retrieval tools from bulk AI training scrapers:

- **Known Agents (<https://knownagents.com>):** Submit `EdgeFetch` under **Agent Type: User-Triggered Agent / Assistant Fetcher**, linking `https://github.com/bartrumb/edgefetch` and [SECURITY.md](../SECURITY.md) (`strict-rfc9309`, halts on challenges, zero model training).
- **Well-Known Bot Manifest:** Every EdgeFetch Hub automatically serves `https://<your-hub-domain>/.well-known/edgefetch-bot.json` for automated origin inspection.

---

### 3. Public Research & Government "Polite Pool" Identification

EdgeFetch's keyless open-data adapters (`sec-edgar`, `openalex`, `crossref-doi`, `pubmed-pmc`, `clinicaltrials`, `europe-pmc`, `semantic-scholar`) automatically benefit from polite-pool routing when your `USER_AGENT` includes a real contact email or URL:

- **SEC EDGAR (`data.sec.gov` / `www.sec.gov`):** Requires a descriptive `CompanyOrProjectName/Version (contact@yourdomain.com)` `User-Agent` (no registration form needed; EdgeFetch paces requests politely and includes contact metadata automatically).
- **OpenAlex, Crossref & NCBI E-utilities:** Setting `USER_AGENT="EdgeFetch/2.5 (mailto:you@yourdomain.com)"` places your Hub/nodes into their prioritized "Polite Pool" without API keys.

---

## Part 2: Registering in Official MCP & Open-Source Directories

### 1. Official MCP Registry (`registry.modelcontextprotocol.io`)

EdgeFetch includes a validated [`server.json`](../server.json) manifest at the repository root (`io.github.bartrumb/edgefetch`, schema `2025-12-11`) pinned to `ghcr.io/bartrumb/edgefetch-agent:2.7.0` with the required `LABEL io.modelcontextprotocol.server.name="io.github.bartrumb/edgefetch"` OCI image label.

To validate and publish `io.github.bartrumb/edgefetch` in the Official MCP Registry:

```bash
# 1. Install mcp-publisher (macOS/Linux/Windows)
brew install mcp-publisher   # or download from https://github.com/modelcontextprotocol/registry/releases

# 2. Validate server.json locally before publishing
mcp-publisher validate

# 3. Authenticate via GitHub OIDC / device login (verifies ownership of github.com/bartrumb)
mcp-publisher login github

# 4. Publish server.json from the repo root
mcp-publisher publish
```

### 2. Glama MCP Directory (`glama.ai/mcp`) & Smithery

- [`glama.json`](../glama.json) is committed at the repository root with `"maintainers": ["bartrumb"]`, allowing instant ownership claim at <https://glama.ai/mcp/servers>.

### 3. OpenSSF Best Practices Badge (`bestpractices.dev`)

EdgeFetch satisfies the OpenSSF Passing criteria out of the box:
- Public vulnerability reporting ([SECURITY.md](../SECURITY.md) + GitHub Security Advisories)
- Contributor rules & DCO/MIT inbound=outbound ([CONTRIBUTING.md](../CONTRIBUTING.md), [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md))
- Automated CI with `-race` ThreadSanitizer, `staticcheck`, `govulncheck`, native fuzzers, Dependabot ([`.github/dependabot.yml`](../.github/dependabot.yml)), SLSA provenance, and Ed25519 signed releases.
- Claim your project badge in ~10 minutes at <https://www.bestpractices.dev/en>.

---

## Part 3: Verifying Official EdgeFetch Releases (Ed25519 + SLSA Provenance)

Every official `v*` release of EdgeFetch is protected by **two independent cryptographic guarantees**:

1. **Owner-Only Ed25519 Signature (`checksums.txt.sig`):** Signed inside GitHub Actions on protected, immutable `v*` tags (`can_admins_bypass: false`) using `RELEASE_SIGNING_PRIVATE_KEY` (sealed exclusively in the tag-gated `release` GitHub Actions environment; never accessible to forks, pull requests, or branch workflows) and verified against [`keys/release-signing-pub.pem`](../keys/release-signing-pub.pem) (`SPKI SHA-256: 2ed9e6f815d727738d51bc48c176f2b63d5176c92975f52943fefcf0afe03272`).
2. **GitHub OIDC SLSA Build Provenance Attestations:** Proves the exact GitHub Actions workflow and commit SHA that built the binary archive or GHCR container image.

### Verify a Release Archive (`openssl` + `sha256sum` + `gh attestation`)

```bash
# 1. Verify SLSA Build Provenance via GitHub CLI
gh attestation verify edgefetch_2.7.0_linux_amd64.tar.gz --owner bartrumb

# 2. Verify the Owner Ed25519 Signature on checksums.txt
openssl pkeyutl -verify -pubin \
  -inkey keys/release-signing-pub.pem \
  -rawin -in checksums.txt \
  -sigfile checksums.txt.sig

# 3. Verify the SHA-256 archive digest against the signed checksums.txt
sha256sum -c --ignore-missing checksums.txt
```

### Verify a GHCR Container Image (`gh attestation`)

```bash
gh attestation verify oci://ghcr.io/bartrumb/edgefetch-agent:latest --owner bartrumb
```
