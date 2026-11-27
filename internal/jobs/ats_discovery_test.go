package jobs

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestATSPreFetchSpecsAndFormatters(t *testing.T) {
	refNow := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// 1. Ashby truncated salvage + empty board + single job
	truncAshby := `{"organizationName":"TruncCo","jobs":[{"id":"j1","title":"Platform Engineer","location":"Remote","isRemote":true},{"id":"partial"`
	salv := SalvageAshbyBoardFromTruncatedJSON(truncAshby)
	if salv == nil || salv.OrganizationName != "TruncCo" || len(salv.Jobs) != 1 {
		t.Fatalf("unexpected Ashby salvage: %+v", salv)
	}
	ashbySpec := ResolveATSPreFetchSpec("https://jobs.ashbyhq.com/Hippocratic%20AI")
	if ashbySpec == nil || ashbySpec.ID != "ashby-board" || !strings.Contains(ashbySpec.FetchURL, "Hippocratic%20AI") {
		t.Fatalf("expected space-bearing Ashby spec, got %+v", ashbySpec)
	}
	if fmtSalv := FormatATSResponse("https://jobs.ashbyhq.com/acme", truncAshby, "https://jobs.ashbyhq.com/acme", nil, refNow); fmtSalv == nil || fmtSalv.Truncated == nil || !*fmtSalv.Truncated {
		t.Fatalf("expected salvaged Ashby board formatted with truncated=true, got %+v", fmtSalv)
	}
	if fmtEmpty := FormatATSResponse("https://jobs.ashbyhq.com/acme", `{"organizationName":"EmptyCo","jobs":[]}`, "https://jobs.ashbyhq.com/acme", nil, refNow); fmtEmpty == nil || *fmtEmpty.Total != 0 {
		t.Fatalf("expected empty Ashby board total=0, got %+v", fmtEmpty)
	}

	// 2. Greenhouse US & EU + `?error=true` guard + HIGH-1 location XSS/link sanitization
	if ResolveATSPreFetchSpec("https://job-boards.greenhouse.io/vercel?error=true") != nil {
		t.Fatal("Greenhouse ?error=true must return nil spec")
	}
	ghEUSpec := ResolveATSPreFetchSpec("https://eu-boards.greenhouse.io/celonis")
	if ghEUSpec == nil || ghEUSpec.FetchURL != "https://boards-api.eu.greenhouse.io/v1/boards/celonis/jobs?content=true" {
		t.Fatalf("unexpected Greenhouse EU spec: %+v", ghEUSpec)
	}
	ghHostileJSON, _ := json.Marshal(map[string]any{
		"jobs": []any{
			map[string]any{
				"id":           99,
				"title":        "Security Engineer",
				"absolute_url": "https://boards.greenhouse.io/sec-test/jobs/99",
				"location":     map[string]any{"name": "Distributed"},
				"offices":      []any{map[string]any{"name": "&amp;lt;img src=x onerror=1&amp;gt; Austin"}},
				"metadata":     []any{map[string]any{"name": "Job Posting Location", "value": []any{"United States", "[Remote - Apply](javascript:void(0))"}}},
				"updated_at":   "2026-11-23",
			},
		},
	})
	ghFmt := FormatATSResponse("https://boards.greenhouse.io/sec-test", string(ghHostileJSON), "https://boards.greenhouse.io/sec-test", nil, refNow)
	if ghFmt == nil || len(ghFmt.Jobs) != 1 {
		t.Fatalf("expected 1 Greenhouse job, got %+v", ghFmt)
	}
	for _, loc := range ghFmt.Jobs[0].Locations {
		if strings.Contains(loc, "<img") || strings.Contains(loc, "javascript:") {
			t.Fatalf("HIGH-1: hostile Greenhouse location leaked: %q", loc)
		}
	}

	// 3. Workday CXS board POST (including offset >= 20 where total == 0) & single job
	wdBoardSpec := ResolveATSPreFetchSpec("https://nvidia.wd5.myworkdayjobs.com/en-US/NVIDIAExternalCareerSite?q=Rust&offset=20")
	if wdBoardSpec == nil || wdBoardSpec.Method != "POST" || !strings.Contains(wdBoardSpec.RequestBody, `"offset":20`) {
		t.Fatalf("unexpected Workday board spec: %+v", wdBoardSpec)
	}
	wdPage2Body, _ := json.Marshal(map[string]any{
		"total": 0,
		"jobPostings": []any{
			map[string]any{
				"title":         "Staff Rust Engineer",
				"externalPath":  "/job/Santa-Clara/Staff-Rust-Engineer_JR12345",
				"locationsText": "Santa Clara, CA",
				"postedOn":      "Posted 30+ Days Ago",
			},
		},
	})
	wdFmt := wdBoardSpec.formatWithNow(string(wdPage2Body), "https://nvidia.wd5.myworkdayjobs.com/NVIDIAExternalCareerSite?offset=20", nil, refNow)
	if wdFmt == nil || wdFmt.Total == nil || *wdFmt.Total != 21 || *wdFmt.Truncated {
		t.Fatalf("expected final <20 Workday page at offset=20 to compute total=21 & truncated=false, got %+v", wdFmt)
	}
	if wdFmt.Jobs[0].PostedAt != nil || wdFmt.Jobs[0].PostedLabel != "30+ days ago" {
		t.Fatalf("expected Workday 30+ days ago bucket label, got %+v", wdFmt.Jobs[0])
	}

	// 4. Lever EU, Workable shortcode merge, Gem, Rippling UUID multi-location merge, Public Feeds, SmartRecruiters
	levEU := ResolveATSPreFetchSpec("https://jobs.eu.lever.co/spotify")
	if levEU == nil || levEU.FetchURL != "https://api.eu.lever.co/v0/postings/spotify?mode=json&skip=0&limit=100" {
		t.Fatalf("unexpected Lever EU spec: %+v", levEU)
	}

	ripFmt := FormatATSResponse(
		"https://ats.rippling.com/en-GB/acme/jobs",
		`[{"uuid":"u-1","name":"Principal Engineer","workLocation":{"label":"San Francisco, CA"}},{"uuid":"u-1","name":"Principal Engineer","workLocation":{"label":"Remote (US)"}},{"uuid":"u-2","name":"Security Engineer","workLocation":{"label":"London, UK"}}]`,
		"https://ats.rippling.com/en-GB/acme/jobs",
		nil,
		refNow,
	)
	if ripFmt == nil || len(ripFmt.Jobs) != 2 || ripFmt.Jobs[0].WorkplaceType != WorkplaceRemote || len(ripFmt.Jobs[0].Locations) != 2 {
		t.Fatalf("expected Rippling uuid merge, got %+v", ripFmt)
	}

	wwrRecs := ParsePublicJobFeedRecords("weworkremotely", `<rss><channel><item><title>Acme: Go Dev</title><link>https://weworkremotely.com/remote-jobs/1</link><region>Anywhere</region><pubDate>Mon, 01 Jan 2026 00:00:00 +0000</pubDate><description>$170k - $210k</description></item></channel></rss>`)
	if len(wwrRecs) != 1 || wwrRecs[0].Company != "Acme" || wwrRecs[0].Title != "Go Dev" || wwrRecs[0].Pay == nil {
		t.Fatalf("unexpected WWR records: %+v", wwrRecs)
	}

	srRecs := ParseSmartRecruitersBoardScrape(
		"https://jobs.smartrecruiters.com/Visa",
		"# Visa Careers\n\n- [Staff Software Engineer](https://jobs.smartrecruiters.com/Visa/744000099988877-staff-software-engineer) — Austin, TX\n",
		"",
		[]string{"https://jobs.smartrecruiters.com/Visa/744000099988877-staff-software-engineer"},
	)
	if len(srRecs) != 1 || srRecs[0].Title != "Staff Software Engineer" || srRecs[0].Locations[0] != "Austin, TX" {
		t.Fatalf("unexpected SmartRecruiters records: %+v", srRecs)
	}
}

func TestBoardDiscoveryStatusAndIdentity(t *testing.T) {
	if got := ClassifyATSBoardStatus(ClassifyBoardStatusParams{HTTPStatus: 200, RequestedURL: "https://jobs.ashbyhq.com/acme", JobCount: 5}); got != BoardStatusOK {
		t.Fatalf("expected ok, got %q", got)
	}
	if got := ClassifyATSBoardStatus(ClassifyBoardStatusParams{HTTPStatus: 200, RequestedURL: "https://jobs.ashbyhq.com/acme", JobCount: 0}); got != BoardStatusEmptyBoard {
		t.Fatalf("expected empty_board, got %q", got)
	}
	if got := ClassifyATSBoardStatus(ClassifyBoardStatusParams{HTTPStatus: 200, RequestedURL: "https://bad.bamboohr.com/careers", FinalURL: "https://www.bamboohr.com/"}); got != BoardStatusWrongSlug {
		t.Fatalf("expected BambooHR vendor redirect classified as wrong_slug, got %q", got)
	}
	if got := ClassifyATSBoardStatus(ClassifyBoardStatusParams{HTTPStatus: 403, RequestedURL: "https://jobs.ashbyhq.com/acme"}); got != BoardStatusBlockedOrDown {
		t.Fatalf("expected 403 classified as blocked_or_down, got %q", got)
	}

	careersHTML := strings.Join([]string{
		`<script src="https://boards.greenhouse.io/embed/job_board/js?for=ffive"></script>`,
		`<a href="https://boards.greenhouse.io/embed/job_board?for=embed">Ignored Junk</a>`,
		`<a href="https://resources.bamboohr.com/careers">Ignored Marketing</a>`,
		`<a href="https://jobs.ashbyhq.com/Hippocratic%20AI">Ashby Space</a>`,
		`<a href="https:\/\/panw.wd5.myworkdayjobs.com\/en-US\/panwexternalcareers\/job\/123">Workday</a>`,
		`<a href="https://ats.rippling.com/en-GB/ripplingco/jobs">Rippling</a>`,
	}, "\n")
	boards := DiscoverATSBoardsFromHTML(DiscoverBoardsParams{
		SourceURL: "https://f5.com/careers",
		RawHTML:   careersHTML,
	})
	if len(boards) != 4 {
		t.Fatalf("expected 4 discovered boards (excluding embed & resources junk), got %+v", boards)
	}
	if boards[0].BoardURL != "https://job-boards.greenhouse.io/ffive" || boards[1].Slug != "Hippocratic AI" {
		t.Fatalf("unexpected discovered boards: %+v", boards)
	}

	for _, u := range []string{
		"https://job-boards.greenhouse.io/acme/jobs/12345",
		"https://acme.com/careers?gh_jid=99999",
		"https://jobs.ashbyhq.com/Hippocratic%20AI/abcdef",
		"https://jobs.lever.co/acme/111-222",
		"https://acme.wd5.myworkdayjobs.com/en-US/External/job/NYC/Staff_123",
		"https://apply.workable.com/acme/j/ABCD1234",
		"https://jobs.gem.com/acme/g1",
		"https://ats.rippling.com/en-US/acme/jobs/r1",
		"https://acme.pinpointhq.com/postings/senior-systems-engineer-99",
		"https://acme.bamboohr.com/careers/42",
		"https://acme.recruitee.com/o/senior-systems-engineer",
		"https://acme.icims.com/jobs/12345/staff-eng/job",
	} {
		if id := ParseATSPostingIdentity(u); id == nil {
			t.Fatalf("expected non-nil ParseATSPostingIdentity for %q", u)
		}
	}

	sim := FindSimilarRoles([]SimilarRole{
		{Title: "Senior Distributed Systems Engineer", URL: "https://simco.recruitee.com/o/1"},
		{Title: "Product Manager", URL: "https://simco.recruitee.com/o/2"},
	}, []string{"systems", "engineer"})
	if len(sim) != 1 || sim[0].URL != "https://simco.recruitee.com/o/1" {
		t.Fatalf("unexpected similar roles: %+v", sim)
	}
}

func TestLargeGreenhouseAndAshbyStreamingBoundedHeap(t *testing.T) {
	refNow := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// Build a realistic ~9.5 MiB 600-posting Greenhouse `?content=true` payload (matching Cloudflare/Anthropic scale),
	// placing `"meta"` AFTER `"jobs"` to verify key-order-independent streaming.
	htmlChunk := strings.Repeat("&lt;p&gt;Build distributed systems in Go and Rust across global edge PoPs. Base salary $185,000 - $240,000 USD.&lt;/p&gt;", 120)
	var sb strings.Builder
	sb.Grow(10 << 20)
	sb.WriteString(`{"jobs":[`)
	for i := 0; i < 600; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"id":%d,"title":"Systems Engineer %d","absolute_url":"https://boards.greenhouse.io/bigco/jobs/%d","location":{"name":"Distributed, United States"},"updated_at":"2026-11-24T10:00:00Z","content":"%s"}`, 10000+i, i, 10000+i, htmlChunk)
	}
	sb.WriteString(`],"meta":{"total":625}}`)
	bigGH := sb.String()
	if len(bigGH) < 8<<20 {
		t.Fatalf("expected >=8 MiB Greenhouse payload, got %d bytes", len(bigGH))
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	res := FormatATSResponse("https://boards.greenhouse.io/bigco", bigGH, "https://boards.greenhouse.io/bigco", nil, refNow)
	if res == nil || res.Total == nil || *res.Total != 625 || res.Returned == nil || *res.Returned != 600 || res.Truncated == nil || !*res.Truncated {
		t.Fatalf("unexpected streaming Greenhouse result: total=%v returned=%v truncated=%v", res.Total, res.Returned, res.Truncated)
	}
	if len(res.Jobs) != 600 || len(res.Links) != 600 || res.Jobs[0].WorkplaceType != WorkplaceRemote || res.Jobs[0].Pay == nil {
		t.Fatalf("unexpected first Greenhouse job: %+v", res.Jobs[0])
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	var liveDelta int64
	if after.HeapAlloc > before.HeapAlloc {
		liveDelta = int64(after.HeapAlloc - before.HeapAlloc)
	}
	// Retained result for 600 compact StructuredJobRecord structs + links + 120-bullet markdown must stay well under 4 MiB.
	if liveDelta > 4<<20 {
		t.Fatalf("retained heap delta too high after streaming 600-job Greenhouse board: %d bytes", liveDelta)
	}

	// Verify Ashby streaming when `"jobs"` precedes `"organizationName"` so `records[i].Company` still resolves to `organizationName`.
	ashbyTrailingOrg := `{"jobs":[{"id":"lin-1","title":"Product Engineer","location":"Remote","isRemote":true,"descriptionPlain":"$190k - $230k base"}],"organizationName":"Linear"}`
	ashbyRes := FormatATSResponse("https://jobs.ashbyhq.com/linear", ashbyTrailingOrg, "https://jobs.ashbyhq.com/linear", nil, refNow)
	if ashbyRes == nil || len(ashbyRes.Jobs) != 1 || ashbyRes.Jobs[0].Company != "Linear" {
		t.Fatalf("expected Ashby streaming to backfill trailing organizationName='Linear', got %+v", ashbyRes)
	}

	// Verify lite Greenhouse board (`?content=false` for `verify` mode & slug-existence probes) and single posting omit `?content=true` upstream.
	liteSpec := ResolveATSPreFetchSpec("https://job-boards.greenhouse.io/anthropic?content=false")
	if liteSpec == nil || liteSpec.FetchURL != "https://boards-api.greenhouse.io/v1/boards/anthropic/jobs" {
		t.Fatalf("expected lite Greenhouse board FetchURL without ?content=true, got %+v", liteSpec)
	}
	liteJobSpec := ResolveATSPreFetchSpec("https://job-boards.greenhouse.io/anthropic/jobs/5462972008?content=false")
	if liteJobSpec == nil || liteJobSpec.FetchURL != "https://boards-api.greenhouse.io/v1/boards/anthropic/jobs/5462972008" {
		t.Fatalf("expected lite Greenhouse job FetchURL without ?content=true, got %+v", liteJobSpec)
	}
	liteGH := `{"jobs":[{"id":5462972008,"title":"Member of Technical Staff","absolute_url":"https://job-boards.greenhouse.io/anthropic/jobs/5462972008","location":{"name":"San Francisco, CA"},"company_name":"Anthropic","updated_at":"2026-11-24T12:00:00Z"}],"meta":{"total":1}}`
	liteRes := FormatATSResponse("https://job-boards.greenhouse.io/anthropic?content=false", liteGH, "https://job-boards.greenhouse.io/anthropic", nil, refNow)
	if liteRes == nil || len(liteRes.Jobs) != 1 || len(liteRes.Links) != 1 || liteRes.Jobs[0].URL != "https://job-boards.greenhouse.io/anthropic/jobs/5462972008" {
		t.Fatalf("unexpected lite Greenhouse board result: %+v", liteRes)
	}
}
