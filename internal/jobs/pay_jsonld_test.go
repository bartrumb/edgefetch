package jobs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPayAndWorkplaceNormalization(t *testing.T) {
	if got := InferPayBasis("Base salary range"); got != PayBasisBase {
		t.Fatalf("expected base, got %q", got)
	}
	if got := InferPayBasis("OTE on-target earnings"); got != PayBasisOTE {
		t.Fatalf("expected ote, got %q", got)
	}
	if got := InferPayBasis("Annual Total Target Cash: $180k - $220k"); got != PayBasisTotal {
		t.Fatalf("expected total, got %q", got)
	}

	for raw, want := range map[string]PayPeriod{
		"HOUR":    PayPeriodHour,
		"per hr":  PayPeriodHour,
		"DAY":     PayPeriodDay,
		"wk":      PayPeriodWeek,
		"mo":      PayPeriodMonth,
		"annual":  PayPeriodYear,
		"unknown": PayPeriodYear,
	} {
		if got := NormalizePeriod(raw); got != want {
			t.Fatalf("NormalizePeriod(%q) = %q, want %q", raw, got, want)
		}
	}

	p1 := ParsePayFromText("$160k - $210k/year base")
	if p1 == nil || *p1.Min != 160_000 || *p1.Max != 210_000 || p1.Currency != "USD" || p1.Period != PayPeriodYear || p1.Basis != PayBasisBase {
		t.Fatalf("unexpected p1: %+v", p1)
	}
	if got := FormatNormalizedPay(p1); got != "$160,000–$210,000 USD/year (base)" {
		t.Fatalf("unexpected formatted pay: %q", got)
	}

	// Ashby shorthand ($230 - $350 -> 230,000 - 350,000)
	pAshby := ParsePayFromText("Compensation: $230 – $350")
	if pAshby == nil || *pAshby.Min != 230_000 || *pAshby.Max != 350_000 {
		t.Fatalf("expected Ashby shorthand scaling, got %+v", pAshby)
	}

	// Symbol-less Workday enterprise range
	pWorkday := ParsePayFromText("Compensation offered for this role is 85,000.00 - 145,075.00 annually.")
	if pWorkday == nil || *pWorkday.Min != 85_000 || *pWorkday.Max != 145_075 || pWorkday.Currency != "USD" {
		t.Fatalf("expected symbol-less Workday pay, got %+v", pWorkday)
	}

	// Lookaround recovery after decimal version token (`v1.20 - $180,000 - $220,000`)
	pAfterVer := ParsePayFromText("Release v1.20 - $180,000 - $220,000 base salary")
	if pAfterVer == nil || *pAfterVer.Min != 180_000 || *pAfterVer.Max != 220_000 {
		t.Fatalf("expected recovery after v1.20, got %+v", pAfterVer)
	}

	// Foreign currencies, non-monetary ranges, and funding/ARR must be rejected
	for _, nonSalary := range []string{
		"Salary: ₹1,500,000 - 2,500,000 per annum",
		"Compensation: INR 1,200,000 - 1,800,000 annually",
		"ZIP CODE: 94105 - 94107",
		"Company of 10,000 - 50,000 employees globally",
		"We raised $150,000 - $250,000 in angel funding and grew ARR",
	} {
		if got := ParsePayFromText(nonSalary); got != nil {
			t.Fatalf("expected nil pay for %q, got %+v", nonSalary, got)
		}
	}

	if got := InferWorkplaceType("Remote - US"); got != WorkplaceRemote {
		t.Fatalf("expected remote, got %q", got)
	}
	if got := InferWorkplaceType("Hybrid (NYC)"); got != WorkplaceHybrid {
		t.Fatalf("expected hybrid, got %q", got)
	}
	if got := InferWorkplaceType("On-site London"); got != WorkplaceOnsite {
		t.Fatalf("expected onsite, got %q", got)
	}
	if got := InferWorkdayWorkplaceType("", "Austin, TX", "Software Engineer"); got != WorkplaceOnsite {
		t.Fatalf("expected concrete Workday location to infer onsite, got %q", got)
	}
	if got := InferWorkdayWorkplaceType("", "3 Locations", "Software Engineer"); got != WorkplaceUnknown {
		t.Fatalf("expected vague Workday location to stay unknown, got %q", got)
	}

	refNow := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	if at, lbl := ParseWorkdayPostedField("2026-11-20", refNow); at == nil || *at != "2026-11-20" || lbl != "" {
		t.Fatalf("unexpected ISO postedAt: %v, %q", at, lbl)
	}
	if at, _ := ParseWorkdayPostedField("2026-02-31", refNow); at != nil {
		t.Fatalf("expected invalid calendar date 2026-02-31 rejected, got %v", *at)
	}
	if at, lbl := ParseWorkdayPostedField("Posted 30+ Days Ago", refNow); at != nil || lbl != "30+ days ago" {
		t.Fatalf("expected bucket label 30+ days ago without fake ISO date, got %v %q", at, lbl)
	}
	if at, _ := ParseWorkdayPostedField("Posted 5 Days Ago", refNow); at == nil || *at != "2026-11-20" {
		t.Fatalf("expected exact 5 days ago ISO date, got %v", at)
	}
}

func TestJobPostingJSONLDAndBoilerplate(t *testing.T) {
	rawObj := map[string]any{
		"@graph": []any{
			map[string]any{
				"@type":                         []any{"Thing", "JobPosting"},
				"title":                         "Staff Engineer [Click](javascript:alert(1))",
				"hiringOrganization":            "Acme Corp",
				"jobLocation":                   []any{"Seattle, WA", map[string]any{"address": "New York, NY"}, map[string]any{"address": map[string]any{"addressLocality": map[string]any{"name": "San Jose"}, "addressRegion": "CA", "addressCountry": map[string]any{"name": "US"}}}},
				"jobLocationType":               "TELECOMMUTE",
				"applicantLocationRequirements": map[string]any{"name": "United States"},
				"baseSalary":                    map[string]any{"currency": "USD", "value": map[string]any{"minValue": 180000, "maxValue": 220000, "unitText": "YEAR"}},
				"description":                   "<p>Total Target Cash: $180,000 - $220,000 per year.</p><p>Location Type: Hybrid</p>",
				"datePosted":                    "2026-11-10T08:00:00Z",
				"employmentType":                []any{"FULL_TIME", "CONTRACTOR"},
			},
		},
	}
	jb, _ := json.Marshal(rawObj)
	htmlDoc := `<html><head><script type="application/ld+json">` + string(jb) + `</script></head><body><script>window.__DATA__ = {"workplaceType":"Hybrid"};</script></body></html>`

	jp := ExtractJobPostingJSONLD(htmlDoc, "https://example.com/jobs/1", "Location Type: Hybrid")
	if jp == nil {
		t.Fatal("expected non-nil StructuredJobPosting")
	}
	if strings.Contains(jp.Title, "javascript:") {
		t.Fatalf("unsafe javascript link survived in title: %q", jp.Title)
	}
	if jp.WorkplaceType != WorkplaceHybrid {
		t.Fatalf("expected workplaceType=hybrid overriding TELECOMMUTE, got %q", jp.WorkplaceType)
	}
	if jp.Pay == nil || jp.Pay.Basis != PayBasisTotal {
		t.Fatalf("expected prose Total Target Cash to upgrade basis=total, got %+v", jp.Pay)
	}
	hdr := FormatJobPostingHeaderMarkdown(*jp)
	if !strings.Contains(hdr, "Acme Corp") || !strings.Contains(hdr, "2026-11-10") {
		t.Fatalf("unexpected header markdown: %q", hdr)
	}

	// TELECOMMUTE + applicantLocationRequirements when jobLocation is omitted
	teleJSON, _ := json.Marshal(map[string]any{
		"@type":                         "JobPosting",
		"title":                         "Remote Engineer",
		"hiringOrganization":            map[string]any{"name": "CloudCo"},
		"jobLocationType":               "TELECOMMUTE",
		"applicantLocationRequirements": map[string]any{"name": "Canada"},
		"baseSalary":                    map[string]any{"currency": "USD", "value": 150000},
	})
	jpTele := ExtractJobPostingJSONLD(`<script type="application/ld+json">`+string(teleJSON)+`</script>`, "", "")
	if jpTele == nil || len(jpTele.JobLocation) != 1 || jpTele.JobLocation[0] != "Remote (Canada)" || *jpTele.Pay.Min != 150000 {
		t.Fatalf("unexpected TELECOMMUTE JobPosting: %+v", jpTele)
	}

	// Unicode Tag smuggling inspection in JSON-LD
	smuggledHTML := `<script type="application/ld+json">{"@type":"JobPosting","title":"Eng","description":"&#xE0069;hidden"}</script>`
	inspected := InspectRawJobPostingJSONLDLinear(smuggledHTML)
	if !strings.ContainsRune(inspected.RawDecodedStringsForPICheck, '\U000E0069') {
		t.Fatalf("expected Unicode Tag sentinel preserved for PI check, got %q", inspected.RawDecodedStringsForPICheck)
	}

	if !IsJobLegalBoilerplateChunk("We are an equal opportunity employer and value diversity.", "Equal Opportunity") {
		t.Fatal("expected EEO boilerplate detected")
	}
	if !IsJobLegalBoilerplateChunk("Artificial intelligence may be used in hiring. Automated employment decision tool under NYC Local Law 144.", "Notice") {
		t.Fatal("expected AI NYC Local Law 144 boilerplate detected")
	}
	if IsJobLegalBoilerplateChunk("Design distributed consensus systems in Go and Rust.", "Responsibilities") {
		t.Fatal("expected technical responsibilities NOT flagged as boilerplate")
	}
}

func TestStubThinScriptAndChunkJSONRecords(t *testing.T) {
	redir, ok := DetectWorkdayRedirectStub(`{"widget":"redirect","url":"/Workday","externalSpa":true}`, "https://acme.wd5.myworkdayjobs.com/en-US/Ext")
	if !ok || redir != "https://acme.wd5.myworkdayjobs.com/Workday" {
		t.Fatalf("unexpected Workday redirect stub: ok=%v redir=%q", ok, redir)
	}

	if HasExecutableScriptTag(`<html><head><script type="application/ld+json">{"@type":"JobPosting"}</script></head></html>`) {
		t.Fatal("JSON-LD script must not count as executable script")
	}
	if !IsThinScriptedPage(`<html><body><script src="/app.js"></script><div id="root"></div></body></html>`, "Loading...") {
		t.Fatal("expected thin scripted SPA shell detected")
	}

	rawChunkBody, _ := json.Marshal(map[string]any{
		"organizationName": "ChunkCo",
		"jobs": []any{
			map[string]any{
				"id":               "c1",
				"title":            "Senior Go Engineer",
				"categories":       map[string]any{"team": "Core"},
				"salaryRange":      map[string]any{"min": 180000, "max": 210000, "interval": "year", "currency": "USD"},
				"descriptionPlain": "Plain fallback",
				"lists":            []any{map[string]any{"text": "Stack", "content": "<li>Go</li>"}},
			},
			map[string]any{
				"id":               "c2",
				"title":            "Intern",
				"categories":       map[string]any{"team": "Core"},
				"descriptionPlain": "Plain intern",
			},
		},
	})
	chunked := ChunkJSONRecords(ChunkJSONRecordsParams{
		RawBody:     string(rawChunkBody),
		ContentType: "application/json",
		JSONFilter:  "categories.team=Core && title!=Intern && descriptionPlain~=Plain",
	})
	if chunked == nil || chunked.MatchedRecords != 1 || !strings.Contains(chunked.Markdown, "$180,000–$210,000 USD/year") {
		t.Fatalf("unexpected chunked result: %+v", chunked)
	}

	// Unsafe nested-quantifier regex `(a*aaa*)?$` and malformed `[bad(` in jsonFilter MUST fail closed!
	for _, unsafeFilter := range []string{"title~=(a*aaa*)?$", "title~=[bad("} {
		res := ChunkJSONRecords(ChunkJSONRecordsParams{
			RawBody:     `[{"id":"1","title":"aaaa"},{"id":"2","title":"Senior Engineer"}]`,
			ContentType: "application/json",
			JSONFilter:  unsafeFilter,
		})
		if res == nil || res.MatchedRecords != 0 {
			t.Fatalf("expected 0 matchedRecords for unsafe filter %q, got %+v", unsafeFilter, res)
		}
	}

	// 2048-char subject cap in jsonFilter
	longRecs, _ := json.Marshal([]any{
		map[string]any{"id": "1", "title": strings.Repeat("x", 2100) + "LATE_TOKEN"},
		map[string]any{"id": "2", "title": "early LATE_TOKEN match"},
	})
	cappedRes := ChunkJSONRecords(ChunkJSONRecordsParams{
		RawBody:     string(longRecs),
		ContentType: "application/json",
		JSONFilter:  "title~=LATE_TOKEN",
	})
	if cappedRes == nil || cappedRes.MatchedRecords != 1 || cappedRes.Chunks[0].RecordID != "2" {
		t.Fatalf("expected 2048-char cap on jsonFilter subject, got %+v", cappedRes)
	}
}
