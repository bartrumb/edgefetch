package crawl

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/coder/websocket"
)

type heldOutRenderPage struct {
	name string
	url  string
	html string
}

// 20 held-out pages drawn directly from EdgeFetch's existing render and HTML extraction tests
// (`bench/run-bench.mjs`, `internal/extract/extract_test.go`, `internal/browser/browser_test.go`,
// `internal/browser/renderer_test.go`, and `internal/browser/universal_harvest_test.go`), each rendered
// with third-party tracking subresources alongside legitimate first-party scripts/styles.
func twentyHeldOutRenderPages() []heldOutRenderPage {
	return []heldOutRenderPage{
		{
			name: "01-stackoverflow-generics",
			url:  "https://stackoverflow.com/questions/424242/preserving-typescript-generics",
			html: `<!doctype html><html><head><title>Preserving TypeScript Generics - Stack Overflow</title><script src="https://www.googletagmanager.com/gtm.js"></script></head><body><main><h1>How to preserve Promise&lt;Result&lt;T, Error&gt;&gt; in streaming parsers?</h1><p>Stash <code>&lt;pre&gt;&lt;code&gt;</code> and inline <code>&lt;code&gt;</code> blocks first:</p><pre><code class="language-ts">export async function parseStream&lt;T&gt;(src: ReadableStream&lt;Uint8Array&gt;): Promise&lt;Result&lt;T, Error&gt;&gt; { return ok(src); }</code></pre></main></body></html>`,
		},
		{
			name: "02-vitepress-politeness-docs",
			url:  "https://docs.example.com/guide/politeness",
			html: `<!doctype html><html><head><title>Politeness &amp; Rate Limiting</title><script src="https://www.google-analytics.com/analytics.js"></script></head><body><main><h1>Politeness &amp; Rate Limiting</h1><p>Always honor RFC 9110 <code>Retry-After</code> headers before retrying.</p><table><thead><tr><th>Outcome</th><th>Cooldown</th></tr></thead><tbody><tr><td>429 Retry-After</td><td>Exact header seconds</td></tr></tbody></table></main></body></html>`,
		},
		{
			name: "03-wikipedia-rrf-katex",
			url:  "https://en.wikipedia.org/wiki/Reciprocal_rank_fusion",
			html: `<!doctype html><html><head><title>Reciprocal rank fusion - Wikipedia</title></head><body><main><h1>Reciprocal rank fusion</h1><p><b>Reciprocal rank fusion</b> (<b>RRF</b>) combines ranked lists from multiple retrieval engines.</p><p>Score: <span class="katex"><math><semantics><annotation encoding="application/x-tex">\text{RRF}(d) = \sum_{r \in R} \frac{1}{60 + r(d)}</annotation></semantics></math></span></p></main></body></html>`,
		},
		{
			name: "04-ietf-rfc9309",
			url:  "https://www.rfc-editor.org/rfc/rfc9309",
			html: `<!doctype html><html><head><title>RFC 9309: Robots Exclusion Protocol</title></head><body><main><h2>2.2.2. The Allow and Disallow Lines</h2><p>Crawlers MUST use longest-match path precedence when evaluating rules and process at least 500 KiB of UTF-8 rules per host.</p></main></body></html>`,
		},
		{
			name: "05-hackernews-thread",
			url:  "https://news.ycombinator.com/item?id=41000001",
			html: `<!doctype html><html><head><title>Single-binary Go WebSocket crawlers | Hacker News</title></head><body><main><h1>Single-binary Go WebSocket crawlers</h1><p>Enforcing SSRF inside <code>net.Dialer.Control</code> eliminates DNS rebinding TOCTOU completely.</p></main></body></html>`,
		},
		{
			name: "06-edgefetch-docs-intro-table",
			url:  "https://example.com/docs/intro",
			html: `<!DOCTYPE html><html><head><title>EdgeFetch Documentation</title><link rel="canonical" href="https://example.com/docs/intro"></head><body><nav><a href="/login">Nav Login</a></nav><main><h1>Getting Started</h1><p>EdgeFetch connects outbound from <strong>Home Assistant OS</strong> to Cloudflare Durable Objects.</p><table><tr><th>Variant</th><th>Footprint</th></tr><tr><td>Lite</td><td>9 MB distroless</td></tr><tr><td>Fat</td><td>Chromium + Poppler PDF</td></tr></table><h2>Torque Specifications</h2><p>Tighten the rear axle nut to 35 Nm.</p><pre><code>go test -race ./...</code></pre></main><footer>Copyright 2026</footer></body></html>`,
		},
		{
			name: "07-code-stash-c-and-multi-backticks",
			url:  "https://example.com/docs/types",
			html: "<html><body><main><h1>Type Signatures</h1><p>Async hook returns <code>Promise&lt;Array&lt;string&gt;&gt;</code> and supports <code>use `tick` literals</code>.</p><pre><code class=\"language-c\">#include &lt;stdio.h&gt;\nint main(void) { return 0; }</code></pre></main></body></html>",
		},
		{
			name: "08-example-domain-no-main",
			url:  "https://example.com/",
			html: `<!doctype html><html><head><title>Example Domain</title></head><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without prior coordination.</p></div></body></html>`,
		},
		{
			name: "09-query-params-link-preservation",
			url:  "https://example.com/watch-guide",
			html: `<html><body><main><h1>Video Reference</h1><p>Watch <a href="https://example.com/watch?v=1&amp;currentTime=45&section=2&region=us">Session Recording</a> for details.</p></main></body></html>`,
		},
		{
			name: "10-clinicaltrials-print-dup-link",
			url:  "https://clinicaltrials.gov/study/NCT0001",
			html: `<html><body><main><h1>Study NCT0001</h1><p>Read our <a href="https://clinicaltrials.gov/about-site/disclaimer">disclaimer</a>(https://clinicaltrials.gov/about-site/disclaimer) before continuing.</p></main></body></html>`,
		},
		{
			name: "11-og-article-fallback",
			url:  "https://blog.example.com/post",
			html: `<html><head><title>Article Title</title><meta property="og:description" content="OG Desc"></head><body><nav><a href="/x">X</a></nav><article><h1>Article Title</h1><p>This article contains more than thirty-two characters of real body text explaining browser isolation.</p></article></body></html>`,
		},
		{
			name: "12-starlight-ec-lines-and-nested-fence",
			url:  "https://starlight.example.com/reference",
			html: "<html><body><main><h1>Expressive Code</h1><pre><code><div class=\"ec-line\">const a = 1;</div><div class=\"ec-line\">const b = 2;</div></code></pre><pre><code>```nested```</code></pre><blockquote cite=\"https://starlight.example.com\"><p>Quoted callout text.</p></blockquote></main></body></html>",
		},
		{
			name: "13-details-disclosure-preserved",
			url:  "https://hardware.example.com/manual",
			html: `<!doctype html><html><head><title>Hardware Spec</title></head><body><main><h1>Visible Primary Heading</h1><p>Visible article paragraph with clean prose.</p><details><summary>Specifications</summary><p>CLOSED_DETAILS_CONTENT_MUST_SURVIVE</p></details></main></body></html>`,
		},
		{
			name: "14-spa-pricing-plans",
			url:  "https://spa.example.com/pricing",
			html: `<html><head><title>Pricing</title><script src="https://static.hotjar.com/c/hotjar-123.js"></script></head><body><main><h1>Rendered Plans</h1><ul><li>Starter — $0/mo</li><li>Team — $19/mo</li></ul></main></body></html>`,
		},
		{
			name: "15-app-dashboard-hydrated",
			url:  "https://app.example.com/dashboard",
			html: `<html><head><title>Dashboard</title><script src="https://cdn.segment.com/analytics.js/v1/key/analytics.min.js"></script></head><body><main><h1>Dashboard Ready</h1><p>Active worker nodes: 4 online across 3 regions.</p></main></body></html>`,
		},
		{
			name: "16-faq-Accordion-article",
			url:  "https://support.example.com/faq",
			html: `<!doctype html><html><head><title>Support FAQ</title></head><body><main><h1>Frequently Asked Questions</h1><h2>How often are tracker rules updated?</h2><p>Once per day on the Hub using conditional ETag requests.</p><h2>Do workers fetch filter lists?</h2><p>Never; workers receive validated host sets over the Hub WebSocket.</p></main></body></html>`,
		},
		{
			name: "17-careers-job-posting",
			url:  "https://careers.example.com/jobs/systems-engineer",
			html: `<!doctype html><html><head><title>Staff Systems Engineer</title><script src="https://bat.bing.com/bat.js"></script></head><body><main><h1>Staff Systems Engineer</h1><p>Location: Austin, TX (Hybrid). Build low-allocation Go network services and sandboxed browser workers.</p></main></body></html>`,
		},
		{
			name: "18-changelog-release-notes",
			url:  "https://changelog.example.com/2026-11",
			html: `<!doctype html><html><head><title>November Changelog</title><script src="https://connect.facebook.net/en_US/fbevents.js"></script></head><body><main><h1>November 2026 Release</h1><p>Improved streaming PDF extraction and reduced p95 render latency by aborting third-party session-replay scripts.</p></main></body></html>`,
		},
		{
			name: "19-ecommerce-product-spec",
			url:  "https://store.example.com/products/torque-wrench",
			html: `<!doctype html><html><head><title>Digital Torque Wrench</title><script src="https://sc-static.net/scevent.min.js"></script></head><body><main><h1>Digital Torque Wrench (2–60 Nm)</h1><p>Calibrated to +/- 1.5% clockwise accuracy with audible target alert.</p></main></body></html>`,
		},
		{
			name: "20-security-advisory-cve",
			url:  "https://security.example.com/advisories/EF-2026-01",
			html: `<!doctype html><html><head><title>Advisory EF-2026-01</title><script src="https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js"></script></head><body><main><h1>Advisory EF-2026-01</h1><p>All 32-bit seccomp architectures remain disabled on x86_64 and aarch64 containers.</p></main></body></html>`,
		},
	}
}

func TestAcceptance8_TwentyHeldOutRenderPagesMarkdownUnchangedAndBlockedCountReported(t *testing.T) {
	pages := twentyHeldOutRenderPages()
	if len(pages) != 20 {
		t.Fatalf("expected exactly 20 held-out pages, got %d", len(pages))
	}

	htmlByURL := make(map[string]string, len(pages))
	for _, p := range pages {
		htmlByURL[p.url] = p.html
	}

	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		var writeMu sync.Mutex
		send := func(v any) {
			b, _ := json.Marshal(v)
			writeMu.Lock()
			_ = conn.Write(req.Context(), websocket.MessageText, b)
			writeMu.Unlock()
		}

		var (
			stateMu      sync.Mutex
			fetchEnabled bool
			curURL       string
		)

		for {
			_, raw, err := conn.Read(req.Context())
			if err != nil {
				return
			}
			var rpc struct {
				ID        int64           `json:"id"`
				SessionID string          `json:"sessionId"`
				Method    string          `json:"method"`
				Params    json.RawMessage `json:"params"`
			}
			if json.Unmarshal(raw, &rpc) != nil {
				continue
			}

			switch rpc.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"browserContextId": "bc-reg"}})
			case "Target.createTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"targetId": "tgt-reg"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": rpc.ID, "result": map[string]any{"sessionId": "sess-reg"}})
			case "Fetch.enable":
				stateMu.Lock()
				fetchEnabled = true
				stateMu.Unlock()
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			case "Fetch.continueRequest", "Fetch.failRequest":
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			case "Page.navigate":
				var navP struct {
					URL string `json:"url"`
				}
				_ = json.Unmarshal(rpc.Params, &navP)
				stateMu.Lock()
				curURL = navP.URL
				fe := fetchEnabled
				stateMu.Unlock()

				navID := rpc.ID
				navSID := rpc.SessionID
				parsedNav, _ := url.Parse(navP.URL)
				firstPartyScript := "https://" + parsedNav.Host + "/assets/main.js"

				go func() {
					if fe {
						send(map[string]any{
							"sessionId": navSID,
							"method":    "Fetch.requestPaused",
							"params": map[string]any{
								"requestId":    "doc-1",
								"frameId":      "f-1",
								"resourceType": "Document",
								"request":      map[string]any{"url": navP.URL, "method": "GET"},
							},
						})
					}
					send(map[string]any{"id": navID, "sessionId": navSID, "result": map[string]any{"frameId": "f-1", "loaderId": "l-1"}})
					send(map[string]any{
						"sessionId": navSID,
						"method":    "Page.frameNavigated",
						"params":    map[string]any{"frame": map[string]any{"id": "f-1", "loaderId": "l-1", "url": navP.URL}},
					})
					if fe {
						// 1 first-party script (must continue) + 2 third-party trackers (must abort when blocking active)
						for _, sr := range []struct {
							id  string
							url string
						}{
							{id: "fp-js", url: firstPartyScript},
							{id: "tp-ga", url: "https://www.google-analytics.com/analytics.js"},
							{id: "tp-hj", url: "https://static.hotjar.com/c/hotjar-123.js"},
						} {
							send(map[string]any{
								"sessionId": navSID,
								"method":    "Fetch.requestPaused",
								"params": map[string]any{
									"requestId":    sr.id,
									"frameId":      "f-1",
									"resourceType": "Script",
									"request":      map[string]any{"url": sr.url, "method": "GET"},
								},
							})
						}
					}
					send(map[string]any{"sessionId": navSID, "method": "Page.loadEventFired", "params": map[string]any{}})
				}()
			case "Runtime.evaluate":
				stateMu.Lock()
				u := curURL
				stateMu.Unlock()
				docJSON, _ := json.Marshal(map[string]string{
					"url":  u,
					"html": htmlByURL[u],
				})
				send(map[string]any{
					"id":        rpc.ID,
					"sessionId": rpc.SessionID,
					"result":    map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}},
				})
			default:
				send(map[string]any{"id": rpc.ID, "sessionId": rpc.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	wsURL := "ws://" + strings.TrimPrefix(cdpSrv.URL, "http://")
	allowAll := func(*url.URL) error { return nil }

	newTestCrawler := func(r *browser.Renderer) *Crawler {
		tr := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/robots.txt" {
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Type": []string{"text/plain"}},
					Body:       http.NoBody,
				}, nil
			}
			return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
		})
		silentLog := slog.New(slog.NewTextHandler(io.Discard, nil))
		c := NewCrawler(tr, allowAll, "EdgeFetch/2.7", silentLog)
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		c.SetRenderer(r)
		return c
	}

	// 1. Baseline renders with NO tracker list loaded
	rBaseline := browser.NewMockRenderer(wsURL, allowAll, "EdgeFetch/2.7")
	defer rBaseline.Close()
	cBaseline := newTestCrawler(rBaseline)

	// 2. Active tracker blocking renders with EasyPrivacy tracker hosts loaded
	rBlocked := browser.NewMockRenderer(wsURL, allowAll, "EdgeFetch/2.7")
	defer rBlocked.Close()
	rBlocked.SetTrackerList("2026112401", []string{
		"google-analytics.com",
		"googletagmanager.com",
		"hotjar.com",
		"segment.com",
		"bing.com",
		"facebook.net",
		"sc-static.net",
		"mxpnl.com",
	})
	cBlocked := newTestCrawler(rBlocked)

	opts := Options{
		PauseMs:       1,
		Concurrency:   2,
		IncludeBody:   true,
		DiscoverLlms:  Bool(false),
		RespectRobots: Bool(false),
	}

	var changedPages []string
	for _, p := range pages {
		baseRes := cBaseline.Run(context.Background(), []Request{{
			ID:         p.name,
			URL:        p.url,
			Kind:       classify.KindRender,
			RenderMode: "always",
			Formats:    []string{"markdown"},
			WaitForMs:  5,
		}}, opts)[0]
		if baseRes.Outcome != classify.OutcomeOK || strings.TrimSpace(baseRes.Markdown) == "" {
			t.Fatalf("baseline render failed for %s: outcome=%s problem=%s", p.name, baseRes.Outcome, baseRes.Problem)
		}
		if baseRes.BlockedTrackers == nil || *baseRes.BlockedTrackers != 0 {
			t.Fatalf("expected baseline BlockedTrackers=0 on %s, got %v", p.name, baseRes.BlockedTrackers)
		}

		blkRes := cBlocked.Run(context.Background(), []Request{{
			ID:         p.name,
			URL:        p.url,
			Kind:       classify.KindRender,
			RenderMode: "always",
			Formats:    []string{"markdown"},
			WaitForMs:  5,
		}}, opts)[0]
		if blkRes.Outcome != classify.OutcomeOK {
			t.Fatalf("tracker-blocked render failed for %s: outcome=%s problem=%s", p.name, blkRes.Outcome, blkRes.Problem)
		}
		if blkRes.BlockedTrackers == nil || *blkRes.BlockedTrackers != 2 {
			t.Fatalf("expected BlockedTrackers=2 on rendered page %s, got %v", p.name, blkRes.BlockedTrackers)
		}
		if blkRes.Markdown != baseRes.Markdown {
			changedPages = append(changedPages, p.name)
		}
	}

	if len(changedPages) > 0 {
		t.Fatalf("extracted Markdown changed on %d/20 held-out pages: %v", len(changedPages), changedPages)
	}

	// Verify per-request `BlockTrackers: Bool(false)` on crawl.Request disables blocking for that call only
	optOutRes := cBlocked.Run(context.Background(), []Request{{
		ID:            "opt-out-check",
		URL:           pages[0].url,
		Kind:          classify.KindRender,
		RenderMode:    "always",
		BlockTrackers: Bool(false),
		Formats:       []string{"markdown"},
		WaitForMs:     5,
	}}, opts)[0]
	if optOutRes.BlockedTrackers == nil || *optOutRes.BlockedTrackers != 0 {
		t.Fatalf("expected Request.BlockTrackers=false to report 0 blocked trackers, got %v", optOutRes.BlockedTrackers)
	}
}
