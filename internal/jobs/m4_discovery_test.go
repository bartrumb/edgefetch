package jobs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestM4DiscoverUkgPaylocityDoverAndInferCompany(t *testing.T) {
	html := `<!doctype html><html><body>
		<a href="https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/">UKG Board</a>
		<a href="https://recruiting.ultipro.com/UKG1001/JobBoardView/123">Blocked View</a>
		<a href="https://recruiting.paylocity.com/recruiting/jobs/all/aa11bb22-cc33-44dd-ee55-ff6677889900">Paylocity Board</a>
		<a href="https://app.dover.com/jobs/acme-robotics">Dover App Board</a>
		<a href="https://jobs.dover.com/volt-motors">Dover Custom Board</a>
	</body></html>`

	boards := DiscoverATSBoardsFromHTML(DiscoverBoardsParams{
		SourceURL: "https://example.com/careers",
		RawHTML:   html,
	})
	seen := make(map[string]DiscoveredATSBoard)
	for _, b := range boards {
		seen[b.Platform+":"+b.Slug] = b
	}

	if _, ok := seen["ukg:UKG1001/JobBoard/11111111-2222-3333-4444-555555555555"]; !ok {
		t.Fatalf("expected UKG JobBoard to be discovered, got %+v", boards)
	}
	if _, ok := seen["paylocity:aa11bb22-cc33-44dd-ee55-ff6677889900"]; !ok {
		t.Fatalf("expected Paylocity board to be discovered, got %+v", boards)
	}
	if _, ok := seen["dover:acme-robotics"]; !ok {
		t.Fatalf("expected app.dover.com board to be discovered, got %+v", boards)
	}
	if _, ok := seen["dover:volt-motors"]; !ok {
		t.Fatalf("expected jobs.dover.com board to be discovered, got %+v", boards)
	}

	if got := InferCompanyFromATSURL("https://jobs.dover.com/volt-motors"); got == "" {
		t.Fatal("expected InferCompanyFromATSURL non-empty for jobs.dover.com")
	}
	if got := InferCompanyFromATSURL("https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/"); got != "Ukg1001" && got == "" {
		t.Fatal("expected InferCompanyFromATSURL non-empty for ultipro.com")
	}

	// Explicit Workday cluster spec preserves wd5 host
	wdSpec := ResolveATSPreFetchSpec("https://temporal.wd5.myworkdayjobs.com/en-US/Temporal")
	if wdSpec == nil || wdSpec.ID != "workday-board" || wdSpec.FetchURL != "https://temporal.wd5.myworkdayjobs.com/wday/cxs/temporal/Temporal/jobs" {
		t.Fatalf("unexpected Workday board spec: %+v", wdSpec)
	}
}

func TestWorkdayATSRejectsPathTraversalGO2(t *testing.T) {
	malicious := []string{
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/../admin",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/./admin",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/%2e%2e/admin",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/%2E%2E/admin",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/slug%2fextra",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/slug%5cextra",
		"https://acme.wd1.myworkdayjobs.com/en-US/%2e%2e/jobs",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/..",
		"https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/Boston/Role%2e%2eName",
		"https://..wd1.myworkdayjobs.com/en-US/Careers",
	}
	for _, rawURL := range malicious {
		if spec := ResolveATSPreFetchSpec(rawURL); spec != nil {
			t.Fatalf("expected ResolveATSPreFetchSpec(%q) to reject path traversal and return nil, got %+v", rawURL, spec)
		}
	}

	validJob := ResolveATSPreFetchSpec("https://acme.wd1.myworkdayjobs.com/en-US/Careers/job/Boston/Senior-Engineer_R-1001")
	if validJob == nil || validJob.ID != "workday-job" || validJob.FetchURL != "https://acme.wd1.myworkdayjobs.com/wday/cxs/acme/Careers/job/Boston/Senior-Engineer_R-1001" {
		t.Fatalf("expected valid Workday job spec, got %+v", validJob)
	}
	validBoard := ResolveATSPreFetchSpec("https://acme.wd1.myworkdayjobs.com/en-US/Careers")
	if validBoard == nil || validBoard.ID != "workday-board" {
		t.Fatalf("expected valid Workday board spec, got %+v", validBoard)
	}
}

func TestWorkdayATSRejectsDoubleEncodedTraversalR2GO2(t *testing.T) {
	doubleEncoded := []string{
		"https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Remote/Eng_%252e%252e_admin",
		"https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/%252e%252e/secret",
		"https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Remote/%252f..%252fadmin",
		"https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Remote/%255c..%255cadmin",
		"https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Remote/Role%25252e%25252eName",
	}
	for _, rawURL := range doubleEncoded {
		if spec := ResolveATSPreFetchSpec(rawURL); spec != nil {
			t.Fatalf("R2-GO-2: expected ResolveATSPreFetchSpec(%q) to reject double-encoded traversal, got %+v", rawURL, spec)
		}
	}

	// Also verify formatWorkdayBoard rejects double-encoded externalPath
	wdBoardSpec := ResolveATSPreFetchSpec("https://acme.wd5.myworkdayjobs.com/en-US/Careers")
	if wdBoardSpec == nil {
		t.Fatal("expected valid workday board spec")
	}
	boardJSON, _ := json.Marshal(map[string]any{
		"total": 1,
		"jobPostings": []map[string]any{
			{
				"title":         "Engineer",
				"externalPath":  "/job/Remote/Eng_%252e%252e_admin",
				"locationsText": "Remote",
			},
		},
	})
	res := FormatATSResponse("https://acme.wd5.myworkdayjobs.com/en-US/Careers", string(boardJSON), "https://acme.wd5.myworkdayjobs.com/en-US/Careers", nil, time.Unix(1700000000, 0).UTC())
	if res == nil || len(res.Jobs) != 1 || strings.Contains(res.Jobs[0].URL, "%252e") {
		t.Fatalf("expected double-encoded externalPath rejected in formatWorkdayBoard, got %+v", res)
	}
}

func TestATSFleetAndFeedsSanitizeMarkdownAndHTMLR2GO1(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	assertSafeATSOutput := func(label string, res *ATSFormattedResult) {
		t.Helper()
		if res == nil {
			t.Fatalf("%s: expected non-nil ATSFormattedResult", label)
		}
		for _, bad := range []string{
			"](https://evil.com/phish)",
			"<script",
			"<img ",
			"onerror=",
		} {
			if strings.Contains(res.Markdown, bad) {
				t.Fatalf("%s: unescaped injection %q in Markdown:\n%s", label, bad, res.Markdown)
			}
			for _, j := range res.Jobs {
				if strings.Contains(j.Title, "<script") || strings.Contains(j.Title, "<img ") || strings.Contains(j.Company, "<script") {
					t.Fatalf("%s: raw HTML leaked into StructuredJobRecord: %+v", label, j)
				}
			}
		}
	}

	// 1. Lever board & single job
	leverPayload, _ := json.Marshal([]map[string]any{{
		"id":        "1)<script>",
		"text":      "Eng](https://evil.com/phish) [x <script>alert(1)</script>",
		"hostedUrl": "https://jobs.lever.co/acme/1)evil",
		"applyUrl":  "https://jobs.lever.co/acme/1/apply)bad",
		"categories": map[string]any{
			"location": "NYC](https://evil.com/phish)",
		},
	}})
	leverRes := FormatATSResponse("https://jobs.lever.co/acme", string(leverPayload), "https://jobs.lever.co/acme", nil, now)
	assertSafeATSOutput("lever-board", leverRes)
	if strings.Contains(leverRes.Markdown, ")evil)") {
		t.Fatalf("lever-board: unencoded ) in URL broke link: %s", leverRes.Markdown)
	}
	leverJobPayload, _ := json.Marshal(map[string]any{
		"text":  "Eng](https://evil.com/phish) <script>alert(1)</script>",
		"lists": []map[string]any{{"text": "Reqs <script>alert(1)</script>", "content": "<li>Go</li>"}},
	})
	leverJobURL := "https://jobs.lever.co/acme/11111111-2222-3333-4444-555555555555"
	assertSafeATSOutput("lever-job", FormatATSResponse(leverJobURL, string(leverJobPayload), leverJobURL, nil, now))

	// 2. Greenhouse board & single job
	ghPayload, _ := json.Marshal(map[string]any{
		"jobs": []map[string]any{{
			"id":           101,
			"title":        "Dev](https://evil.com/phish) [x <img src=x onerror=alert(1)>",
			"absolute_url": "https://boards.greenhouse.io/acme/jobs/101",
			"location":     map[string]any{"name": "NYC"},
		}},
	})
	assertSafeATSOutput("greenhouse-board", FormatATSResponse("https://boards.greenhouse.io/acme", string(ghPayload), "https://boards.greenhouse.io/acme", nil, now))
	ghJobPayload, _ := json.Marshal(map[string]any{
		"title":        "Dev](https://evil.com/phish) <script>alert(1)</script>",
		"company_name": "Evil <script>Co</script>",
		"absolute_url": "https://boards.greenhouse.io/acme/jobs/101",
	})
	assertSafeATSOutput("greenhouse-job", FormatATSResponse("https://boards.greenhouse.io/acme/jobs/101", string(ghJobPayload), "https://boards.greenhouse.io/acme/jobs/101", nil, now))

	// 3. Ashby board & single job
	ashbyPayload, _ := json.Marshal(map[string]any{
		"organizationName": "Evil <script>Org</script>",
		"jobs": []map[string]any{{
			"id":       "a1",
			"title":    "PM](https://evil.com/phish) [x <script>alert(1)</script>",
			"jobUrl":   "https://jobs.ashbyhq.com/acme/a1",
			"location": "Remote [phish](https://evil.com/phish)",
		}},
	})
	assertSafeATSOutput("ashby-board", FormatATSResponse("https://jobs.ashbyhq.com/acme", string(ashbyPayload), "https://jobs.ashbyhq.com/acme", nil, now))
	assertSafeATSOutput("ashby-job", FormatATSResponse("https://jobs.ashbyhq.com/acme/a1", string(ashbyPayload), "https://jobs.ashbyhq.com/acme/a1", nil, now))

	// 4. Workable board & single job
	workablePayload, _ := json.Marshal(map[string]any{
		"name": "Evil <script>Co</script>",
		"jobs": []map[string]any{{
			"shortcode": "ABCD1234",
			"title":     "SRE](https://evil.com/phish) <img src=x onerror=alert(1)>",
			"city":      "NYC",
			"url":       "https://apply.workable.com/acme/j/ABCD1234/",
		}},
	})
	assertSafeATSOutput("workable-board", FormatATSResponse("https://apply.workable.com/acme", string(workablePayload), "https://apply.workable.com/acme", nil, now))
	workableJobPayload, _ := json.Marshal(map[string]any{
		"title":       "SRE](https://evil.com/phish) <script>alert(1)</script>",
		"description": "<p>Clean</p>",
	})
	assertSafeATSOutput("workable-job", FormatATSResponse("https://apply.workable.com/acme/j/ABCD1234", string(workableJobPayload), "https://apply.workable.com/acme/j/ABCD1234", nil, now))

	// 5. Gem board
	gemPayload, _ := json.Marshal([]map[string]any{{
		"id":           "g1",
		"title":        "Staff](https://evil.com/phish) <script>alert(1)</script>",
		"absolute_url": "https://jobs.gem.com/acme/g1",
		"location":     map[string]any{"name": "SF [phish](https://evil.com/phish)"},
	}})
	assertSafeATSOutput("gem-board", FormatATSResponse("https://jobs.gem.com/acme", string(gemPayload), "https://jobs.gem.com/acme", nil, now))

	// 6. Rippling board & single job
	ripplingPayload, _ := json.Marshal([]map[string]any{{
		"uuid":         "11111111-2222-3333-4444-555555555555",
		"name":         "Sec](https://evil.com/phish) <img src=x onerror=alert(1)>",
		"companyName":  "Co <script>alert(1)</script>",
		"workLocation": map[string]any{"label": "Remote [phish](https://evil.com/phish)"},
		"url":          "https://ats.rippling.com/acme/jobs/11111111-2222-3333-4444-555555555555",
	}})
	assertSafeATSOutput("rippling-board", FormatATSResponse("https://ats.rippling.com/acme/jobs", string(ripplingPayload), "https://ats.rippling.com/acme/jobs", nil, now))
	assertSafeATSOutput("rippling-job", FormatATSResponse("https://ats.rippling.com/acme/jobs/11111111-2222-3333-4444-555555555555", string(ripplingPayload), "https://ats.rippling.com/acme/jobs/11111111-2222-3333-4444-555555555555", nil, now))

	// 7. Public job feeds: WeWorkRemotely, Himalayas, WorkingNomads
	wwrXML := `<rss><channel><item><title>Evil [Co](https://evil.com/phish) &lt;script&gt;: Go](https://evil.com/phish) &lt;img src=x onerror=alert(1)&gt;</title><link>https://weworkremotely.com/remote-jobs/1</link><region>Anywhere [phish](https://evil.com/phish)</region></item></channel></rss>`
	assertSafeATSOutput("wwr-feed", FormatATSResponse("https://weworkremotely.com/remote-jobs.rss", wwrXML, "https://weworkremotely.com/remote-jobs.rss", nil, now))

	himPayload, _ := json.Marshal(map[string]any{
		"totalCount": 1,
		"jobs": []map[string]any{{
			"title":           "SRE](https://evil.com/phish) <script>alert(1)</script>",
			"companyName":     "Evil <script>Co</script> [x](https://evil.com/phish)",
			"applicationLink": "https://himalayas.app/jobs/1",
		}},
	})
	assertSafeATSOutput("himalayas-feed", FormatATSResponse("https://himalayas.app/jobs/api?limit=50", string(himPayload), "https://himalayas.app/jobs/api?limit=50", nil, now))

	wnPayload, _ := json.Marshal([]map[string]any{{
		"title":        "Backend](https://evil.com/phish) <script>alert(1)</script>",
		"company_name": "Evil <img src=x onerror=alert(1)> [x](https://evil.com/phish)",
		"url":          "https://workingnomads.com/jobs/1",
	}})
	assertSafeATSOutput("workingnomads-feed", FormatATSResponse("https://www.workingnomads.com/api/exposed_jobs/", string(wnPayload), "https://www.workingnomads.com/api/exposed_jobs/", nil, now))
}

func TestTier5R3GO1to3_ATSSanitizationAndWorkdayGuards(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

	// R3-GO-1: Ashby jobUrl & applyUrl must route through sanitizeATSHttpsURL
	ashbyBoard, _ := json.Marshal(map[string]any{
		"jobs": []map[string]any{
			{
				"id":          "j1",
				"title":       "Eng",
				"jobUrl":      "https://evil.com/x)[phish](https://evil.com/p)",
				"applyUrl":    "https://sub.localhost.localdomain/apply",
				"isRemote":    true,
				"location":    "Remote",
			},
			{
				"id":       "j2",
				"title":    "Role 2",
				"jobUrl":   "https://localhost.localdomain./jobs/2",
				"applyUrl": "https://user:pass@jobs.ashbyhq.com/acme/j2/application",
				"location": "NYC",
			},
		},
	})
	ashRes := FormatATSResponse("https://jobs.ashbyhq.com/acme", string(ashbyBoard), "https://jobs.ashbyhq.com/acme", nil, now)
	if ashRes == nil {
		t.Fatal("R3-GO-1: expected Ashby board result")
	}
	if strings.Contains(ashRes.Markdown, ")[phish](") {
		t.Fatalf("R3-GO-1: Ashby board leaked Markdown link breakout:\n%s", ashRes.Markdown)
	}
	if strings.Contains(ashRes.Markdown, "localhost.localdomain") {
		t.Fatalf("R3-GO-1: Ashby board leaked localhost.localdomain:\n%s", ashRes.Markdown)
	}
	for _, lk := range ashRes.Links {
		if strings.Contains(lk, "localhost.localdomain") || strings.Contains(lk, "user:pass") || strings.Contains(lk, ")") {
			t.Fatalf("R3-GO-1: unsafe Ashby link leaked into Links[]: %q", lk)
		}
	}

	ashJob, _ := json.Marshal(map[string]any{
		"jobs": []map[string]any{{
			"id":          "j9",
			"title":       "Staff Eng",
			"jobUrl":      "https://evil.com/x)[phish](https://evil.com/p)",
			"applyUrl":    "https://sub.localhost.localdomain/apply",
			"descriptionPlain": "Build systems.",
		}},
	})
	ashJobRes := FormatATSResponse("https://jobs.ashbyhq.com/acme/j9", string(ashJob), "https://jobs.ashbyhq.com/acme/j9", nil, now)
	if ashJobRes == nil || strings.Contains(ashJobRes.Markdown, "sub.localhost.localdomain") || strings.Contains(ashJobRes.Markdown, ")[phish](") {
		t.Fatalf("R3-GO-1: Ashby single job leaked unsafe URL:\n%+v", ashJobRes)
	}

	// R3-GO-2: sanitizeATSHttpsURL parity with IsSafePublicHostname + port 443
	for _, bad := range []string{
		"https://sub.localhost.localdomain/jobs/1",
		"https://localhost.localdomain./jobs/1",
		"https://127.0.0.1/jobs/1",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]/jobs/1",
		"https://evil.nip.io/jobs/1",
		"https://evil.sslip.io/jobs/1",
		"https://evil.com:8443/jobs/1",
		"https://user:pass@evil.com/jobs/1",
	} {
		if got := sanitizeATSHttpsURL(bad, ""); got != "" {
			t.Fatalf("R3-GO-2: sanitizeATSHttpsURL(%q) = %q, want empty", bad, got)
		}
	}
	if got := sanitizeATSHttpsURL("https://jobs.lever.co/acme/1", ""); got != "https://jobs.lever.co/acme/1" {
		t.Fatalf("R3-GO-2: valid URL altered: %q", got)
	}

	// R3-GO-3: Workday title/heading/locationsText/bullets Markdown sanitization & %00 segment guard
	wdJobJSON, _ := json.Marshal(map[string]any{
		"jobPostingInfo": map[string]any{
			"title":          "Eng](https://evil.com/phish) [x\n\n## Injected",
			"location":       "Austin",
			"jobDescription": "<p>Workday job body.</p>",
		},
	})
	wdJobRes := FormatATSResponse("https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Austin/Eng_1", string(wdJobJSON), "https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Austin/Eng_1", nil, now)
	if wdJobRes == nil || strings.Contains(wdJobRes.Markdown, "](https://evil.com/phish)") || strings.Contains(wdJobRes.Markdown, "\n## Injected") {
		t.Fatalf("R3-GO-3: Workday job failed Markdown sanitization:\n%+v", wdJobRes)
	}

	wdBoardJSON, _ := json.Marshal(map[string]any{
		"total": 1,
		"jobPostings": []map[string]any{{
			"title":         "Dev [x](https://evil.com/phish)",
			"externalPath":  "/job/Remote/Dev_1",
			"locationsText": "NYC [phish](https://evil.com/loc)\n## Fake",
			"bulletFields":  []string{"Full time", "bad\n## Evil"},
		}},
	})
	wdBoardRes := FormatATSResponse("https://acme.wd5.myworkdayjobs.com/en-US/Careers", string(wdBoardJSON), "https://acme.wd5.myworkdayjobs.com/en-US/Careers", nil, now)
	if wdBoardRes == nil || strings.Contains(wdBoardRes.Markdown, "](https://evil.com/") || strings.Contains(wdBoardRes.Markdown, "\n## Fake") || strings.Contains(wdBoardRes.Markdown, "\n## Evil") {
		t.Fatalf("R3-GO-3: Workday board failed Markdown sanitization:\n%+v", wdBoardRes)
	}

	for _, badSeg := range []string{"%00admin", "Eng_%00", "%1Ftest", "%7Fdel", "%2500"} {
		if isSafeWorkdayPathSegment(badSeg) {
			t.Fatalf("R3-GO-3: isSafeWorkdayPathSegment(%q) = true, want false", badSeg)
		}
		if spec := ResolveATSPreFetchSpec("https://acme.wd5.myworkdayjobs.com/en-US/Careers/job/Remote/" + badSeg); spec != nil {
			t.Fatalf("R3-GO-3: ResolveATSPreFetchSpec accepted control byte segment %q: %+v", badSeg, spec)
		}
	}
}

func TestTier5R4GO2_R4GO3a_R4GO4_JSONLDApplyURLAshbyTitleWorkdayExtPath(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

	// R4-GO-2: ExtractJobPostingJSONLD rejects unsafe/SSRF/http/userinfo jp["url"] into ApplyURL
	baseURL := "https://careers.acme.com/jobs/1"
	for _, badURL := range []string{
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://127.0.0.1/apply",
		"https://169.254.169.254/latest/meta-data/",
		"https://user:pass@evil.com/apply",
		"http://evil.com/apply",
		"https://127.0.0.1.nip.io/apply",
	} {
		payload, _ := json.Marshal(map[string]any{
			"@context": "https://schema.org",
			"@type":    "JobPosting",
			"title":    "Staff Engineer",
			"url":      badURL,
		})
		jp := ExtractJobPostingJSONLD(`<script type="application/ld+json">`+string(payload)+`</script>`, baseURL, "")
		if jp == nil {
			t.Fatalf("R4-GO-2: expected JobPosting for %q", badURL)
		}
		if jp.ApplyURL != baseURL {
			t.Fatalf("R4-GO-2: unsafe jp[url]=%q leaked into ApplyURL=%q, want fallback %q", badURL, jp.ApplyURL, baseURL)
		}
	}
	bracketedPayload, _ := json.Marshal(map[string]any{
		"@context": "https://schema.org",
		"@type":    "JobPosting",
		"title":    "Staff Engineer",
		"url":      "https://evil.com/a[b]c",
	})
	jpBr := ExtractJobPostingJSONLD(`<script type="application/ld+json">`+string(bracketedPayload)+`</script>`, baseURL, "")
	if jpBr == nil || strings.ContainsAny(jpBr.ApplyURL, "[]") {
		t.Fatalf("R4-GO-2: expected brackets in ApplyURL to be percent-encoded, got %+v", jpBr)
	}

	// R4-GO-3a: formatAshby ATSFormattedResult.Title uses cleanOrgTitle
	ashBoard, _ := json.Marshal(map[string]any{
		"organization": map[string]any{"name": "Acme <script>alert(1)</script>\n## Hack"},
		"jobs": []map[string]any{{
			"id":       "a1",
			"title":    "Engineer",
			"jobUrl":   "https://jobs.ashbyhq.com/acme/a1",
			"location": "Remote",
		}},
	})
	ashRes := FormatATSResponse("https://jobs.ashbyhq.com/acme", string(ashBoard), "https://jobs.ashbyhq.com/acme", nil, now)
	if ashRes == nil {
		t.Fatal("R4-GO-3a: expected Ashby board result")
	}
	if strings.Contains(ashRes.Title, "\n") || strings.Contains(ashRes.Title, "<script") {
		t.Fatalf("R4-GO-3a: Ashby Title leaked newline or HTML tag: %q", ashRes.Title)
	}

	// R4-GO-4: Workday board externalPath rejects percent-encoded control characters (%00..%1F, %7F)
	wdCtrlBoard, _ := json.Marshal(map[string]any{
		"total": 2,
		"jobPostings": []map[string]any{
			{
				"title":        "Control Path Job",
				"externalPath": "/job/Remote/Dev_%00_1%0A2",
			},
			{
				"title":        "Safe Path Job",
				"externalPath": "/job/Remote/Dev_Safe_2",
			},
		},
	})
	wdCtrlRes := FormatATSResponse("https://acme.wd5.myworkdayjobs.com/en-US/Careers", string(wdCtrlBoard), "https://acme.wd5.myworkdayjobs.com/en-US/Careers", nil, now)
	if wdCtrlRes == nil {
		t.Fatal("R4-GO-4: expected Workday board result")
	}
	if strings.Contains(wdCtrlRes.Markdown, "%00") || strings.Contains(wdCtrlRes.Markdown, "%0A") {
		t.Fatalf("R4-GO-4: Workday board leaked control-char externalPath in Markdown:\n%s", wdCtrlRes.Markdown)
	}
	for _, lk := range wdCtrlRes.Links {
		if strings.Contains(lk, "%00") || strings.Contains(lk, "%0A") {
			t.Fatalf("R4-GO-4: Workday board leaked control-char externalPath in Links[]: %q", lk)
		}
	}
	if !strings.Contains(wdCtrlRes.Markdown, "https://acme.wd5.myworkdayjobs.com/Careers/job/Remote/Dev_Safe_2") {
		t.Fatalf("R4-GO-4: expected valid Workday externalPath to remain intact:\n%s", wdCtrlRes.Markdown)
	}
}
