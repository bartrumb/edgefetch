package hubstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

func TestStoreDiskPersistenceReloadAndMemoryRing(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir, 0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	blobSHA, contentSHA, cBytes, sBytes, err := s1.PutRawBlob("crawl", []byte("hello edgefetch gzip world"))
	if err != nil || cBytes != 26 || sBytes <= 0 {
		t.Fatalf("PutRawBlob failed: err=%v cBytes=%d sBytes=%d", err, cBytes, sBytes)
	}
	gz, ok, err := s1.GetGzipBlob("crawl", blobSHA)
	if err != nil || !ok {
		t.Fatalf("GetGzipBlob: ok=%v err=%v", ok, err)
	}
	if err := s1.PutGzipBlob("crawl_copy", blobSHA, contentSHA, gz); err != nil {
		t.Fatalf("PutGzipBlob: %v", err)
	}

	etag := s1.PutScrapeCache("k1", map[string]any{"markdown": "# Cached", "status": 200})
	if etag == "" {
		t.Fatal("expected non-empty etag")
	}

	s1.RecordHostTelemetry("docs.example.com", "blocked", 403, "cloudflare", "waf_challenge", "", 120)
	s1.RecordHostTelemetry("docs.example.com", "ok", 200, "", "article", "", 80)
	s1.RecordHostTelemetry("adapted.example.com", "ok", 200, "", "article", "github-repo", 40)

	s1.PutJob("crawl", "job-1", "alice", map[string]any{"status": "running", "pages": 3})
	s1.SetSetting("tracker_list", "on")
	s1.AppendEvent(map[string]any{"type": "scrape_ok", "host": "docs.example.com"})
	s1.AppendEvent(map[string]any{"type": "waf_block", "host": "docs.example.com"})

	s2, err := NewStore(dir, 0)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}
	dec, ok, err := s2.GetDecodedBlob("crawl_copy", blobSHA, 1024)
	if err != nil || !ok || string(dec) != "hello edgefetch gzip world" {
		t.Fatalf("GetDecodedBlob after reload: ok=%v err=%v got=%q", ok, err, string(dec))
	}
	if _, _, err := s2.GetDecodedBlob("crawl_copy", blobSHA, 5); err != ErrBlobTooLarge {
		t.Fatalf("expected ErrBlobTooLarge, got %v", err)
	}

	payload, gotETag, notMod, hit := s2.GetScrapeCache("k1", 60_000, "")
	if !hit || notMod || gotETag != etag || payload["markdown"] != "# Cached" {
		t.Fatalf("unexpected cache hit result: hit=%v notMod=%v etag=%q payload=%v", hit, notMod, gotETag, payload)
	}
	payload304, gotETag304, notMod304, hit304 := s2.GetScrapeCache("k1", 60_000, `W/`+etag)
	if !hit304 || !notMod304 || payload304 != nil || gotETag304 != etag {
		t.Fatalf("expected 304 Not Modified: hit=%v notMod=%v payload=%v", hit304, notMod304, payload304)
	}

	hosts := s2.ListHosts(10)
	if len(hosts) != 2 || hosts[0]["host"] != "docs.example.com" || hosts[0]["blockedCount"] != 1 {
		t.Fatalf("unexpected ListHosts: %+v", hosts)
	}
	gaps := s2.ListHostGaps(10)
	if len(gaps) != 1 || gaps[0]["host"] != "docs.example.com" {
		t.Fatalf("unexpected ListHostGaps (adapted host must be excluded): %+v", gaps)
	}

	if _, ok := s2.GetJob("crawl", "job-1", "bob", false); ok {
		t.Fatal("bob must not read alice's job")
	}
	if j, ok := s2.GetJob("crawl", "job-1", "alice", false); !ok || j["status"] != "running" {
		t.Fatalf("alice failed to read own job: ok=%v j=%v", ok, j)
	}
	if _, ok := s2.DeleteOrCancelJob("crawl", "job-1", "bob", false); ok {
		t.Fatal("bob must not cancel alice's job")
	}
	cancelled, ok := s2.DeleteOrCancelJob("crawl", "job-1", "alice", false)
	if !ok || cancelled["status"] != "cancelled" || cancelled["cancelled"] != true {
		t.Fatalf("cancel failed: ok=%v data=%v", ok, cancelled)
	}
	if v, ok := s2.GetSetting("tracker_list"); !ok || v != "on" {
		t.Fatalf("GetSetting after reload: ok=%v v=%q", ok, v)
	}
	evs := s2.ListEvents(10)
	if len(evs) != 2 || evs[0]["type"] != "waf_block" {
		t.Fatalf("unexpected ListEvents: %+v", evs)
	}
	s2.ClearEvents()
	if len(s2.ListEvents(10)) != 0 {
		t.Fatal("expected empty events after ClearEvents")
	}

	memStore, err := NewStore("", 256)
	if err != nil {
		t.Fatalf("NewStore mem: %v", err)
	}
	shaA, _, _, _, err := memStore.PutRawBlob("ns", bytes.Repeat([]byte("a"), 120))
	if err != nil {
		t.Fatalf("PutRawBlob A: %v", err)
	}
	for i := 0; i < 12; i++ {
		_, _, _, _, _ = memStore.PutRawBlob("ns", fmt.Appendf(nil, "distinct-payload-%d-%s", i, strings.Repeat("z", 80)))
	}
	if _, ok, _ := memStore.GetGzipBlob("ns", shaA); ok {
		t.Fatal("expected oldest in-memory blob to be evicted by ring cap")
	}
}

func TestMarkdownArtifactTenantIsolationAndSlicePaging(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("# Architecture Guide\n\n")
	sb.WriteString(strings.Repeat("Safe introductory prose paragraph with emoji 🚀 and CJK 日本語テキスト.\n\n", 300))
	sb.WriteString("```go\nfunc secretCode() string {\n\treturn \"<raw-inside-fence>\"\n}\n```\n\n")
	sb.WriteString("Trailing prose with <script>evil()</script> neutralized.\n")
	doc := sb.String()

	privID, totalChars, cps, err := s.PersistMarkdownArtifact("alice", "https://example.com/guide", "Guide <tag>", doc, true)
	if err != nil {
		t.Fatalf("PersistMarkdownArtifact: %v", err)
	}
	if len(privID) != 64 || totalChars < 18000 || len(cps) == 0 {
		t.Fatalf("unexpected artifact metadata: id=%q total=%d cps=%v", privID, totalChars, cps)
	}

	if _, status, code := s.ReadArtifactPage("alice", false, "not-a-sha", 0, 500); status != 404 || code != "not_found" {
		t.Fatalf("expected 404 on invalid ID, got %d %q", status, code)
	}
	if _, status, code := s.ReadArtifactPage("bob", false, privID, 0, 500); status != 404 || code != "not_found" {
		t.Fatalf("bob must get 404 on alice private artifact, got %d %q", status, code)
	}
	if _, status, _ := s.ReadArtifactPage("", false, privID, 0, 500); status != 404 {
		t.Fatalf("anonymous non-owner must get 404 on private artifact, got %d", status)
	}
	if p, status, _ := s.ReadArtifactPage("owner", true, privID, 0, 200); status != 200 || p["ok"] != true {
		t.Fatalf("hub owner should access artifact, got status=%d", status)
	}

	offset, pages := 0, 0
	var combined strings.Builder
	for {
		page, status, errCode := s.ReadArtifactPage("alice", false, privID, offset, 4096)
		if status != 200 || errCode != "" {
			t.Fatalf("ReadArtifactPage at %d failed: status=%d code=%q", offset, status, errCode)
		}
		chunk := page["markdown"].(string)
		if strings.Contains(chunk, "<script>") {
			t.Fatalf("unsanitized <script> leaked in page %d", pages)
		}
		combined.WriteString(chunk)
		pages++
		if !page["hasMore"].(bool) {
			if page["nextOffset"] != nil {
				t.Fatalf("expected nil nextOffset on final page, got %v", page["nextOffset"])
			}
			break
		}
		offset = page["nextOffset"].(int)
		if pages > 20 {
			t.Fatal("pagination did not terminate")
		}
	}
	if pages < 4 || !strings.Contains(combined.String(), "<raw-inside-fence>") {
		t.Fatalf("expected multi-page traversal preserving code fence content, pages=%d", pages)
	}
}

func TestCollectionIndexBM25PrefixAndTenantIsolation(t *testing.T) {
	dir := t.TempDir()
	ownerKey, ownerDisp := ResolveCollectionKey("owner", true, "docs")
	aliceKey, aliceDisp := ResolveCollectionKey("alice", false, "docs")
	bobKey, _ := ResolveCollectionKey("bob", false, "docs")
	if ownerKey != "docs" || aliceKey != "u:alice:docs" || bobKey != "u:bob:docs" || ownerDisp != "docs" || aliceDisp != "docs" {
		t.Fatalf("unexpected collection keys: owner=%q alice=%q bob=%q", ownerKey, aliceKey, bobKey)
	}

	idx, err := NewCollectionIndex(dir)
	if err != nil {
		t.Fatalf("NewCollectionIndex: %v", err)
	}
	chunks, pageID := idx.ReplacePageChunks(
		aliceKey,
		aliceDisp,
		"https://docs.cloudflare.com/workers/wrangler",
		"Wrangler CLI Deployment",
		"# Wrangler Deployment\n\nDeploy serverless Cloudflare Workers globally with durable routing.\n\n"+strings.Repeat("Additional paragraph detailing configuration bindings and observability.\n\n", 25),
	)
	if chunks < 2 || len(pageID) != 64 {
		t.Fatalf("expected >=2 chunks and 64-hex pageID, got chunks=%d pageID=%q", chunks, pageID)
	}
	idx.ReplacePageChunks(aliceKey, aliceDisp, "https://go.dev/doc/effective_go", "Effective Go", "# Concurrency\n\nGoroutines and channels make concurrent programming clean.")
	idx.ReplacePageChunks(ownerKey, ownerDisp, "https://example.org/p1", "Old Legacy Title", "obsoletekeywordalpha unique token")
	idx.ReplacePageChunks(ownerKey, ownerDisp, "https://example.org/p1", "Updated Modern Title", "freshkeywordbeta replacement body")

	idx2, err := NewCollectionIndex(dir)
	if err != nil {
		t.Fatalf("NewCollectionIndex reload: %v", err)
	}
	if got := idx2.Search(ownerKey, "obsoletekeywordalpha", 5, ""); len(got) != 0 {
		t.Fatalf("expected stale chunk removal on ReplacePageChunks, got %+v", got)
	}
	if got := idx2.Search(ownerKey, "freshkeywordbeta", 5, ""); len(got) != 1 {
		t.Fatalf("expected replaced chunk hit after reload, got %+v", got)
	}
	if got := idx2.Search(bobKey, "wrangler", 5, ""); len(got) != 0 {
		t.Fatalf("tenant leak to bob: %+v", got)
	}
	if got := idx2.Search(ownerKey, "wrangler", 5, ""); len(got) != 0 {
		t.Fatalf("tenant leak to owner default key: %+v", got)
	}

	hits := idx2.Search(aliceKey, "serverless rout", 5, "docs.cloudflare.com")
	if len(hits) == 0 || hits[0].URL != "https://docs.cloudflare.com/workers/wrangler" || hits[0].Collection != "docs" {
		t.Fatalf("expected Cloudflare Wrangler BM25 + prefix hit, got %+v", hits)
	}
	if filteredOut := idx2.Search(aliceKey, "goroutines", 5, "docs.cloudflare.com"); len(filteredOut) != 0 {
		t.Fatalf("expected hostFilter to exclude go.dev hit, got %+v", filteredOut)
	}
}

type mockSearchRoundTripper struct {
	serperKey string
	braveKey  string
	tavilyKey string
	t         *testing.T
}

func (m *mockSearchRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	jsonResp := func(body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
	switch req.Host {
	case "google.serper.dev":
		if got := req.Header.Get("X-API-Key"); got != m.serperKey {
			m.t.Errorf("serper missing X-API-Key: %q", got)
		}
		return jsonResp(`{"organic":[{"link":"https://rust-lang.org/learn?utm_source=serper#top","title":"Learn <b>Rust</b> <script>bad()</script>","snippet":"Official Rust guide"},{"link":"https://shared.example.com/article?fbclid=123","title":"Shared Article","snippet":"Found by Serper"}]}`)
	case "api.search.brave.com":
		if got := req.Header.Get("X-Subscription-Token"); got != m.braveKey {
			m.t.Errorf("brave missing X-Subscription-Token: %q", got)
		}
		return jsonResp(`{"web":{"results":[{"url":"https://shared.example.com/article","title":"Shared Article","description":"Found by Brave"}]}}`)
	case "api.tavily.com":
		if got := req.Header.Get("Authorization"); got != "Bearer "+m.tavilyKey {
			m.t.Errorf("tavily missing Authorization: %q", got)
		}
		return jsonResp(`{"results":[{"url":"https://tavily-only.example.com/post","title":"Tavily Hit","content":"Tavily snippet"}]}`)
	default:
		return http.DefaultTransport.RoundTrip(req)
	}
}

func TestExecuteWebSearchRRFAndOTLPSecretStripping(t *testing.T) {
	var otlpMu sync.Mutex
	var otlpPayloads []string
	otlpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		otlpMu.Lock()
		otlpPayloads = append(otlpPayloads, string(b))
		otlpMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer otlpSrv.Close()

	searxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" || r.URL.Query().Get("format") != "json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"results":[{"url":"https://shared.example.com/article/?utm_medium=web","title":"Shared Article","content":"Found by SearXNG"},{"url":"https://searx-only.example.com/doc","title":"SearXNG Doc","content":"Self-hosted result"}]}`)
	}))
	defer searxSrv.Close()

	const (
		secretSerper = "serper-secret-999"
		secretBrave  = "brave-secret-888"
		secretTavily = "tavily-secret-777"
		secretQuery  = "confidential-search-token-xyz"
	)

	exp := otel.NewExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return otlpSrv.URL
		}
		return ""
	}, "edgefetch-hub-test", "2.8.0", nil)
	if exp == nil {
		t.Fatal("expected live OTLP exporter")
	}

	collIdx, _ := NewCollectionIndex("")
	collIdx.ReplacePageChunks("default", "default", "https://shared.example.com/article", "Shared Article", "confidential-search-token-xyz local indexed knowledge")

	client := &http.Client{
		Transport: &mockSearchRoundTripper{serperKey: secretSerper, braveKey: secretBrave, tavilyKey: secretTavily, t: t},
		Timeout:   5 * time.Second,
	}

	rootCtx := otel.WithTraceContext(context.Background(), otel.ExtractOrNew(nil))
	out, err := ExecuteWebSearch(rootCtx, SearchConfig{
		SearxngURL:           searxSrv.URL + "?api_key=searx-secret-123",
		SerperAPIKey:         secretSerper,
		BraveAPIKey:          secretBrave,
		TavilyAPIKey:         secretTavily,
		CollectionIndex:      collIdx,
		CollectionStorageKey: "default",
		OperatorClient:       client,
		OtelExporter:         exp,
	}, SearchParams{Query: secretQuery, Limit: 10, TimeRange: "week"})
	if err != nil {
		t.Fatalf("ExecuteWebSearch: %v", err)
	}
	_ = exp.Close()

	results := out["results"].([]map[string]any)
	if len(results) != 4 {
		t.Fatalf("expected 4 deduplicated RRF results, got %d: %+v", len(results), results)
	}
	top := results[0]
	if top["url"] != "https://shared.example.com/article" || len(top["providers"].([]string)) != 4 {
		t.Fatalf("expected shared canonical URL ranked #1 with 4 fused providers, got %+v", top)
	}
	for _, r := range results {
		if strings.Contains(r["title"].(string), "<script>") {
			t.Fatalf("raw <script> leaked in search title: %q", r["title"])
		}
	}

	otlpMu.Lock()
	joinedOTLP := strings.Join(otlpPayloads, "\n")
	otlpMu.Unlock()
	for _, spanName := range []string{"edgefetch.search.searxng", "edgefetch.search.serper", "edgefetch.search.brave", "edgefetch.search.tavily"} {
		if !strings.Contains(joinedOTLP, spanName) {
			t.Fatalf("missing expected span %q in OTLP export", spanName)
		}
	}
	for _, forbidden := range []string{secretSerper, secretBrave, secretTavily, "searx-secret-123", secretQuery, "format=json"} {
		if strings.Contains(joinedOTLP, forbidden) {
			t.Fatalf("OTLP span leaked secret or query string %q: %s", forbidden, joinedOTLP)
		}
	}
}

func buildValidEasyPrivacyFixture(version string, count int) string {
	var sb strings.Builder
	sb.WriteString("[Adblock Plus 2.0]\n! Version: " + version + "\n! Title: EasyPrivacy\n! Last modified: 25 Nov 2026 00:00 UTC\n")
	sb.WriteString("||challenges.cloudflare.com^\n||launchdarkly.com^\n||evil.example.com^$important\n||192.168.1.1^\n||co.uk^\n||wild*.tracker.com^\n||path.tracker.com/pixel.js^\n")
	for i := 0; i < count; i++ {
		sb.WriteString(fmt.Sprintf("||trk-%05d-analytics-telemetry-pixel.example.com^\n", i))
	}
	for sb.Len() < MinTrackerListBytes+4096 {
		sb.WriteString("! padding comment line for realistic EasyPrivacy minimum byte floor validation\n")
	}
	return sb.String()
}

func TestTrackerManagerZeroStartupFetchValidationAndDelayedRefresh(t *testing.T) {
	var hits atomic.Int32
	currentBody := buildValidEasyPrivacyFixture("2026112501", 5500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"ep-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("ETag", `"ep-v1"`)
		_, _ = io.WriteString(w, currentBody)
	}))
	defer srv.Close()

	dir := t.TempDir()
	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Verify EDGEFETCH_TRACKER_LIST=off disables fetches completely.
	offTM, _ := NewTrackerManager(TrackerConfig{
		Store: store, SourceURL: srv.URL,
		Getenv: func(k string) string {
			if k == "EDGEFETCH_TRACKER_LIST" {
				return "off"
			}
			return ""
		},
	})
	if offTM.IsEnabled() || offTM.Status()["enabled"] != false {
		t.Fatal("expected tracker manager disabled when EDGEFETCH_TRACKER_LIST=off")
	}

	t.Setenv("EDGEFETCH_TRACKER_INITIAL_DELAY_MS", "35")
	var updateCount atomic.Int32
	var updatedVer atomic.Value

	tm, err := NewTrackerManager(TrackerConfig{
		Store:     store,
		SourceURL: srv.URL,
		OnUpdate: func(ver string, hosts []string) {
			updatedVer.Store(ver)
			updateCount.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("NewTrackerManager: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("expected 0 startup network requests, got %d", hits.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tm.StartBackground(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && updateCount.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	tm.Stop()

	if hits.Load() != 1 || updateCount.Load() != 1 || updatedVer.Load() != "2026112501" {
		t.Fatalf("expected 1 delayed background fetch, got hits=%d updates=%d ver=%v", hits.Load(), updateCount.Load(), updatedVer.Load())
	}
	// Conditional 304 check makes zero updates.
	if updated, err := tm.RefreshNow(ctx); err != nil || updated {
		t.Fatalf("expected 304 no-op, got updated=%v err=%v", updated, err)
	}

	ver, hosts := tm.CurrentList()
	if ver != "2026112501" || len(hosts) != 5500 {
		t.Fatalf("expected 5500 validated hosts, got ver=%q len=%d", ver, len(hosts))
	}
	if _, _, _, _, err := ValidateEasyPrivacyList([]byte(buildValidEasyPrivacyFixture("2026112502", 4000)), 5500, nil); err == nil {
		t.Fatal("expected >20% count-drop guard to reject 5500 -> 4000 drop")
	}

	// Reload from disk in new Store + TrackerManager with ZERO network requests.
	hitsBeforeReload := hits.Load()
	store2, _ := NewStore(dir, 0)
	tm2, _ := NewTrackerManager(TrackerConfig{Store: store2, SourceURL: srv.URL})
	if hits.Load() != hitsBeforeReload || tm2.Status()["available"] != true || tm2.Status()["hostCount"] != 5500 {
		t.Fatalf("reload failed or made network call: hits=%d status=%+v", hits.Load(), tm2.Status())
	}

	if single := BuildTrackerListFrames(ver, hosts); len(single) != 1 || !strings.Contains(string(single[0]), `"type":"tracker_list"`) {
		t.Fatalf("expected single tracker_list frame, got %d", len(single))
	}
	bigHosts := make([]string, 36000)
	for i := range bigHosts {
		h := sha256Hex(fmt.Appendf(nil, "entropy-host-%d", i))
		bigHosts[i] = fmt.Sprintf("%s.%s.trk.example.com", h[:28], h[28:56])
	}
	chunkFrames := BuildTrackerListFrames("2026112599", bigHosts)
	if len(chunkFrames) < 2 {
		t.Fatalf("expected chunked tracker_list_chunk frames when >768 KiB, got %d", len(chunkFrames))
	}
	var joinedB64 strings.Builder
	for i, cf := range chunkFrames {
		var m map[string]any
		_ = json.Unmarshal(cf, &m)
		if m["type"] != "tracker_list_chunk" || int(m["chunkIndex"].(float64)) != i {
			t.Fatalf("bad chunk %d metadata: %+v", i, m)
		}
		joinedB64.WriteString(m["data"].(string))
	}
	gzRaw, _ := base64.StdEncoding.DecodeString(joinedB64.String())
	zr, err := gzip.NewReader(bytes.NewReader(gzRaw))
	if err != nil {
		t.Fatalf("gzip open reassembled chunks: %v", err)
	}
	gunzipped, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil || strings.Count(string(gunzipped), "\n") != len(bigHosts)-1 {
		t.Fatalf("reassembled gunzip line count mismatch: err=%v", err)
	}
}
