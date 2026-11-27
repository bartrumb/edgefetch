package jobs

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func fp(v float64) *float64 { return &v }

func TestNormalizeTitleFamily(t *testing.T) {
	cases := []struct {
		title, family, seniority string
	}{
		{"Sr. Software Engineer II, Backend (Remote)", "software engineer", "senior"},
		{"Solutions Engineer, Splunk", "solutions engineer", SeniorityUnspecified},
		{"Software Engineer", "software engineer", SeniorityUnspecified},
		{"Software Engineer I", "software engineer", "junior"},
		{"Software Engineer II", "software engineer", "mid"},
		{"Software Engineer III", "software engineer", "senior"},
		{"Software Engineer 2", "software engineer", "mid"},
		{"Staff Software Engineer", "software engineer", "staff"},
		{"Senior Staff Software Engineer, Infrastructure", "software engineer", "staff"},
		{"Principal Software Engineer - Platform", "software engineer", "principal"},
		{"Software Engineer, Senior", "software engineer", "senior"},
		{"Software Engineer (Senior)", "software engineer", "senior"},
		{"Jr. Software Developer", "software engineer", "junior"},
		{"Associate Software Engineer", "software engineer", "junior"},
		{"Software Engineering Intern (Summer 2026)", "software engineer", "intern"},
		{"New Grad Software Engineer", "software engineer", "junior"},
		{"SWE", "software engineer", SeniorityUnspecified},
		{"Senior SWE", "software engineer", "senior"},
		{"Staff Engineer", "software engineer", "staff"},
		{"Tech Lead", "software engineer", "lead"},
		{"Lead Software Engineer", "software engineer", "lead"},
		{"Senior Backend Developer", "backend engineer", "senior"},
		{"Full-Stack Engineer", "full stack engineer", SeniorityUnspecified},
		{"Front End Software Engineer", "frontend engineer", SeniorityUnspecified},
		{"Senior Site Reliability Engineer", "site reliability engineer", "senior"},
		{"SRE", "site reliability engineer", SeniorityUnspecified},
		{"Senior Product Manager", "product manager", "senior"},
		{"PM", "product manager", SeniorityUnspecified},
		{"Product Manager, Payments", "product manager", SeniorityUnspecified},
		{"Associate Product Manager", "product manager", "junior"},
		{"Engineering Manager", "engineering manager", "manager"},
		{"Senior Engineering Manager, Payments", "engineering manager", "senior manager"},
		{"Manager, Software Engineering", "engineering manager", "manager"},
		{"Senior Manager, Product Marketing", "product marketing manager", "senior manager"},
		{"Director of Engineering", "engineering", "director"},
		{"Director, Engineering", "engineering", "director"},
		{"Associate Director, Engineering", "engineering", "director"},
		{"Head of Product", "product", "head"},
		{"VP of Sales, North America", "sales", "vp"},
		{"Vice President, Engineering", "engineering", "vp"},
		{"Machine Learning Engineer", "machine learning engineer", SeniorityUnspecified},
		{"Senior ML Engineer", "machine learning engineer", "senior"},
		{"UI/UX Designer", "ux designer", SeniorityUnspecified},
		{"Account Executive, Mid-Market", "account executive", SeniorityUnspecified},
		{"Member of Technical Staff", "member of technical staff", SeniorityUnspecified},
		{"Senior Data Scientist - US Remote", "data scientist", "senior"},
		{"Data Engineer (m/f/d)", "data engineer", SeniorityUnspecified},
		{"Software Engineer [REQ-123456]", "software engineer", SeniorityUnspecified},
		{"JR12345 Senior Software Engineer", "software engineer", "senior"},
		{"Software Engineer &amp; Team Player", "software engineer team player", SeniorityUnspecified},
		{"Ingénieur Logiciel Senior", "ingenieur logiciel", "senior"},
		{"Customer Success Manager", "customer success manager", SeniorityUnspecified},
		{"Sales Development Representative (SDR)", "sales development representative", SeniorityUnspecified},
		{"(Remote)", "", SeniorityUnspecified},
		{"", "", SeniorityUnspecified},
	}
	for _, c := range cases {
		f, s := NormalizeTitleFamily(c.title)
		if f != c.family || s != c.seniority {
			t.Errorf("NormalizeTitleFamily(%q) = (%q, %q), want (%q, %q)", c.title, f, s, c.family, c.seniority)
		}
		if f != "" {
			if f2, _ := NormalizeTitleFamily(f); f2 != f {
				t.Errorf("family %q is not idempotent: re-normalized to %q", f, f2)
			}
		}
	}
}

func TestMatchTitleQuery(t *testing.T) {
	cases := []struct{ q, family, seniority string }{
		{"senior swe salary", "software engineer", "senior"},
		{"software engineer salaries in London", "software engineer", ""},
		{"pm", "product manager", ""},
		{"Staff engineer at Acme", "software engineer", "staff"},
		{"how much does a senior product manager make", "product manager", "senior"},
		{"software engineer in test", "software engineer in test", ""},
		{"director of engineering", "engineering", "director"},
	}
	for _, c := range cases {
		f, s := MatchTitleQuery(c.q)
		if f != c.family || s != c.seniority {
			t.Errorf("MatchTitleQuery(%q) = (%q, %q), want (%q, %q)", c.q, f, s, c.family, c.seniority)
		}
	}
}

func TestNormalizeLocationBucket(t *testing.T) {
	cases := []struct{ loc, bucket, country string }{
		{"New York, NY", "metro:new-york", "US"},
		{"New York, New York, United States", "metro:new-york", "US"},
		{"San Francisco, CA, United States", "metro:san-francisco", "US"},
		{"Palo Alto, CA", "metro:san-francisco", "US"},
		{"London, United Kingdom", "metro:london", "GB"},
		{"London, England, UK", "metro:london", "GB"},
		{"London, ON", "country:CA", "CA"},
		{"London", "metro:london", "GB"},
		{"Remote - US", "remote", "US"},
		{"Remote (Canada)", "remote", "CA"},
		{"US-Remote", "remote", "US"},
		{"Remote", "remote", ""},
		{"Anywhere in the world", "remote", ""},
		{"Austin, TX", "metro:austin", "US"},
		{"Boise, ID", "country:US", "US"},
		{"Fresno, CA", "country:US", "US"},
		{"Toronto, ON, Canada", "metro:toronto", "CA"},
		{"Vancouver, WA", "country:US", "US"},
		{"Berlin, Germany", "metro:berlin", "DE"},
		{"München, Bayern, Deutschland", "metro:munich", "DE"},
		{"Bengaluru, Karnataka, India", "metro:bangalore", "IN"},
		{"Washington, D.C.", "metro:washington-dc", "US"},
		{"New York, NY (Hybrid)", "metro:new-york", "US"},
		{"New York, NY; San Francisco, CA", "metro:new-york", "US"},
		{"United States", "country:US", "US"},
		{"Germany", "country:DE", "DE"},
		{"Springfield", "unknown", ""},
		{"", "unknown", ""},
	}
	for _, c := range cases {
		b, co := NormalizeLocationBucket(c.loc)
		if b != c.bucket || co != c.country {
			t.Errorf("NormalizeLocationBucket(%q) = (%q, %q), want (%q, %q)", c.loc, b, co, c.bucket, c.country)
		}
	}
	q := []struct{ in, want string }{
		{"", ""}, {"remote", "remote"}, {"country:us", "country:US"}, {"metro:New York", "metro:new-york"},
		{"Bay Area", "metro:san-francisco"}, {"USA", "country:US"}, {"Atlantis", "unknown"},
	}
	for _, c := range q {
		if got := NormalizeLocationQuery(c.in); got != c.want {
			t.Errorf("NormalizeLocationQuery(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func payJob(url, title string, lo, hi *float64, cur string, period PayPeriod) StructuredJobRecord {
	return StructuredJobRecord{
		Title: title, Company: "Acme, Inc.", URL: url, Locations: []string{"New York, NY"},
		WorkplaceType: WorkplaceOnsite, Source: "greenhouse",
		Pay: &NormalizedPay{Min: lo, Max: hi, Currency: cur, Period: period, Basis: PayBasisBase},
	}
}

func TestSalaryObservationAnnualizationAndPlausibility(t *testing.T) {
	cases := []struct {
		name         string
		lo, hi       *float64
		cur          string
		period       PayPeriod
		ok           bool
		minA, maxA   float64
		wantMin, max float64
	}{
		{"year", fp(150000), fp(200000), "USD", PayPeriodYear, true, 150000, 200000, 150000, 200000},
		{"hour", fp(50), fp(60), "USD", PayPeriodHour, true, 104000, 124800, 50, 60},
		{"day", fp(500), fp(600), "GBP", PayPeriodDay, true, 130000, 156000, 500, 600},
		{"week", fp(2000), fp(2500), "EUR", PayPeriodWeek, true, 104000, 130000, 2000, 2500},
		{"month", fp(8000), fp(10000), "EUR", PayPeriodMonth, true, 96000, 120000, 8000, 10000},
		{"swapped", fp(200000), fp(150000), "USD", PayPeriodYear, true, 150000, 200000, 150000, 200000},
		{"single min", fp(120000), nil, "usd", PayPeriodYear, true, 120000, 120000, 120000, 120000},
		{"single max", nil, fp(90000), "CAD", PayPeriodYear, true, 90000, 90000, 90000, 90000},
		{"jpy scaled", fp(8000000), fp(12000000), "JPY", PayPeriodYear, true, 8000000, 12000000, 8000000, 12000000},
		{"no bounds", nil, nil, "USD", PayPeriodYear, false, 0, 0, 0, 0},
		{"zero", fp(0), fp(0), "USD", PayPeriodYear, false, 0, 0, 0, 0},
		{"negative", fp(-5), fp(-1), "USD", PayPeriodYear, false, 0, 0, 0, 0},
		{"nan", fp(math.NaN()), nil, "USD", PayPeriodYear, false, 0, 0, 0, 0},
		{"too small annual", fp(200), fp(500), "USD", PayPeriodYear, false, 0, 0, 0, 0},
		{"too large annual", fp(4000000), fp(9000000), "USD", PayPeriodYear, false, 0, 0, 0, 0},
		{"hourly below 1", fp(0.5), fp(2), "USD", PayPeriodHour, false, 0, 0, 0, 0},
		{"bad currency", fp(100000), fp(120000), "US$", PayPeriodYear, false, 0, 0, 0, 0},
		{"empty currency", fp(100000), fp(120000), "", PayPeriodYear, false, 0, 0, 0, 0},
		{"unknown period", fp(100000), fp(120000), "USD", PayPeriod("fortnight"), false, 0, 0, 0, 0},
	}
	for _, c := range cases {
		o, ok := SalaryObservationFromJob(payJob("https://boards.example.com/acme/jobs/1#apply", "Senior Software Engineer", c.lo, c.hi, c.cur, c.period), 1000)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if o.MinAnnual != c.minA || o.MaxAnnual != c.maxA || o.Min != c.wantMin || o.Max != c.max {
			t.Errorf("%s: got min=%v max=%v minA=%v maxA=%v", c.name, o.Min, o.Max, o.MinAnnual, o.MaxAnnual)
		}
	}
	o, ok := SalaryObservationFromJob(payJob("https://Boards.Example.com/acme/jobs/1/#x", "Senior Software Engineer", fp(1), fp(2), "USD", PayPeriodHour), 42)
	if !ok {
		t.Fatalf("hourly 1..2 annualizes to 2080..4160 which is plausible; expected accept")
	}
	_ = o
	o, ok = SalaryObservationFromJob(payJob("https://Boards.Example.com/acme/jobs/1/#x", "Senior Software Engineer", fp(150000), fp(180000), "usd", PayPeriodYear), 42)
	if !ok || o.URL != "https://boards.example.com/acme/jobs/1" || o.CompanyKey != "acme" || o.Company != "Acme, Inc." ||
		o.TitleFamily != "software engineer" || o.Seniority != "senior" || o.LocationBucket != "metro:new-york" ||
		o.Country != "US" || o.Currency != "USD" || o.SeenAt != 42 || o.Source != "greenhouse" || o.Basis != PayBasisBase {
		t.Fatalf("unexpected observation: %+v", o)
	}
	if _, ok := SalaryObservationFromJob(payJob("", "Engineer", fp(1e5), fp(2e5), "USD", PayPeriodYear), 1); ok {
		t.Fatal("expected rejection without URL")
	}
	rec := payJob("https://x.example/1", "Engineer", fp(1e5), fp(2e5), "USD", PayPeriodYear)
	rec.Pay = nil
	if _, ok := SalaryObservationFromJob(rec, 1); ok {
		t.Fatal("expected rejection without pay")
	}
	rec = payJob("https://x.example/2", "Engineer", fp(1e5), fp(2e5), "USD", PayPeriodYear)
	rec.WorkplaceType = WorkplaceRemote
	rec.Locations = []string{"Remote - US"}
	if o, ok := SalaryObservationFromJob(rec, 1); !ok || o.LocationBucket != "remote" || o.Country != "US" {
		t.Fatalf("remote bucket: %+v", o)
	}
}

func TestSalaryPercentileType7(t *testing.T) {
	x := []float64{10, 20, 30, 40, 50}
	cases := []struct{ p, want float64 }{
		{0, 10}, {0.1, 14}, {0.25, 20}, {0.5, 30}, {0.75, 40}, {0.9, 46}, {1, 50},
	}
	for _, c := range cases {
		if got := SalaryPercentile(x, c.p); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("p=%v got %v want %v", c.p, got, c.want)
		}
	}
	y := []float64{1, 2, 3, 4}
	if got := SalaryPercentile(y, 0.5); got != 2.5 {
		t.Errorf("even median = %v", got)
	}
	if got := SalaryPercentile(y, 0.1); math.Abs(got-1.3) > 1e-9 {
		t.Errorf("p10 = %v", got)
	}
	if SalaryPercentile(nil, 0.5) != 0 || SalaryPercentile([]float64{7}, 0.9) != 7 {
		t.Error("degenerate percentile")
	}
	s := ComputeSalaryStats([]float64{100000, 120000, 140000, 160000, 180000})
	if s.Count != 5 || s.P10 != 108000 || s.P25 != 120000 || s.Median != 140000 || s.P75 != 160000 || s.P90 != 172000 || s.Mean != 140000 {
		t.Errorf("stats = %+v", s)
	}
}

func obsFixture(url, company, family, seniority, bucket, country, cur string, minA, maxA float64, seen int64) SalaryObservation {
	return SalaryObservation{
		URL: url, TitleRaw: family, TitleFamily: family, Seniority: seniority, CompanyKey: NormalizeCompanyKey(company),
		Company: company, LocationBucket: bucket, Country: country, Currency: cur, Period: PayPeriodYear,
		Basis: PayBasisBase, Min: minA, Max: maxA, MinAnnual: minA, MaxAnnual: maxA, Source: "lever", SeenAt: seen,
	}
}

const dayMs = 86_400_000

func TestAggregateSalariesCurrencySeparation(t *testing.T) {
	now := int64(1000 * dayMs)
	obs := []SalaryObservation{
		obsFixture("https://a.example/1", "Alpha", "software engineer", "senior", "metro:new-york", "US", "USD", 150000, 200000, now),
		obsFixture("https://b.example/1", "Beta", "software engineer", "senior", "metro:san-francisco", "US", "USD", 160000, 220000, now),
		obsFixture("https://c.example/1", "Gamma", "software engineer", "senior", "remote", "US", "USD", 140000, 180000, now),
		obsFixture("https://d.example/1", "Delta", "software engineer", "senior", "metro:london", "GB", "GBP", 80000, 100000, now),
		obsFixture("https://e.example/1", "Epsilon", "software engineer", "senior", "metro:london", "GB", "GBP", 90000, 110000, now),
	}
	rep := AggregateSalaries(obs, SalaryQuery{TitleFamily: "Software Engineer", NowMs: now})
	if rep.Currency != "USD" || rep.Matched != 3 || rep.Currencies["GBP"] != 2 || rep.Currencies["USD"] != 3 {
		t.Fatalf("currency selection: %+v", rep)
	}
	if rep.Midpoint.Median != 175000 || rep.Min.Median != 150000 || rep.Max.Median != 200000 {
		t.Fatalf("USD stats mixed: mid=%+v min=%+v max=%+v", rep.Midpoint, rep.Min, rep.Max)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "GBP 2") {
		t.Fatalf("expected other-currency note: %v", rep.Notes)
	}
	gbp := AggregateSalaries(obs, SalaryQuery{TitleFamily: "software engineer", Currency: "gbp", NowMs: now})
	if gbp.Currency != "GBP" || gbp.Matched != 2 || gbp.Midpoint.Median != 95000 {
		t.Fatalf("gbp: %+v", gbp)
	}
	us := AggregateSalaries(obs, SalaryQuery{TitleFamily: "software engineer", LocationBucket: "country:US", NowMs: now})
	if us.Matched != 3 || us.Currency != "USD" {
		t.Fatalf("country:US should include metros and remote-US: %+v", us)
	}
	rem := AggregateSalaries(obs, SalaryQuery{TitleFamily: "software engineer", LocationBucket: "remote", NowMs: now})
	if rem.Matched != 1 {
		t.Fatalf("remote: %+v", rem)
	}
	ny := AggregateSalaries(obs, SalaryQuery{TitleFamily: "software engineer", LocationBucket: "New York, NY", NowMs: now})
	if ny.Matched != 1 || ny.Sample[0].Company != "Alpha" {
		t.Fatalf("metro: %+v", ny)
	}
}

func TestAggregateSalariesDedupeWeighting(t *testing.T) {
	now := int64(1000 * dayMs)
	var obs []SalaryObservation
	// One employer posts the same band in 20 cities: must count as one observation.
	cities := []string{"metro:new-york", "metro:san-francisco", "metro:seattle", "metro:austin", "metro:boston"}
	for i := 0; i < 20; i++ {
		o := obsFixture("https://big.example/job/"+string(rune('a'+i)), "BigCo", "software engineer", "senior", cities[i%len(cities)], "US", "USD", 100000, 120000, now-int64(i))
		obs = append(obs, o)
	}
	// Same URL seen twice (older copy must lose).
	obs = append(obs, obsFixture("https://small.example/1", "SmallCo", "software engineer", "senior", "metro:new-york", "US", "USD", 1, 2, now-5*dayMs))
	obs = append(obs, obsFixture("https://small.example/1/", "SmallCo", "software engineer", "senior", "metro:new-york", "US", "USD", 200000, 240000, now))
	obs = append(obs, obsFixture("https://mid.example/1", "MidCo", "software engineer", "senior", "metro:boston", "US", "USD", 150000, 170000, now))
	rep := AggregateSalaries(obs, SalaryQuery{TitleFamily: "software engineer", NowMs: now})
	if rep.Postings != 22 || rep.Matched != 3 {
		t.Fatalf("postings=%d matched=%d", rep.Postings, rep.Matched)
	}
	// Midpoints: 110000, 160000, 220000 -> median 160000 (not dominated by BigCo's 20 postings).
	if rep.Midpoint.Median != 160000 || rep.Midpoint.Mean != 163333 {
		t.Fatalf("weighted midpoint: %+v", rep.Midpoint)
	}
	if len(rep.TopCompanies) != 3 || rep.TopCompanies[0].Count != 1 {
		t.Fatalf("companies: %+v", rep.TopCompanies)
	}
	if rep.Sources["lever"] != 22 {
		t.Fatalf("sources: %v", rep.Sources)
	}
	bostonCount := 0
	for _, b := range rep.ByLocation {
		if b.Key == "metro:boston" {
			bostonCount = b.Count
		}
	}
	if bostonCount != 2 {
		t.Fatalf("boston should count BigCo cluster once plus MidCo: %+v", rep.ByLocation)
	}
	var bigPostings int
	for _, s := range rep.Sample {
		if s.Company == "BigCo" {
			bigPostings = s.Postings
		}
	}
	if bigPostings != 20 {
		t.Fatalf("sample postings for cluster = %d", bigPostings)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "collapsed 22 postings into 3") || !strings.Contains(rep.Notes[0], "only 3 observations") {
		t.Fatalf("notes: %v", rep.Notes)
	}
}

func TestAggregateSalariesFiltersAndBasis(t *testing.T) {
	now := int64(1000 * dayMs)
	mk := func(url string, basis PayBasis, sen string, minA float64, seen int64) SalaryObservation {
		o := obsFixture(url, "Co "+url, "account executive", sen, "metro:new-york", "US", "USD", minA, minA+20000, seen)
		o.Basis = basis
		return o
	}
	obs := []SalaryObservation{
		mk("https://x.example/1", PayBasisOTE, "senior", 200000, now),
		mk("https://x.example/2", PayBasisOTE, "senior", 220000, now),
		mk("https://x.example/3", PayBasisBase, "senior", 100000, now),
		mk("https://x.example/4", PayBasisBase, "mid", 90000, now-200*dayMs), // stale
	}
	rep := AggregateSalaries(obs, SalaryQuery{TitleFamily: "AE", NowMs: now})
	if rep.Basis != "all" || rep.Matched != 3 {
		t.Fatalf("basis fallback: basis=%s matched=%d notes=%v", rep.Basis, rep.Matched, rep.Notes)
	}
	if rep2 := AggregateSalaries(obs, SalaryQuery{TitleFamily: "account executive", Basis: "ote", NowMs: now}); rep2.Matched != 2 {
		t.Fatalf("ote filter: %d", rep2.Matched)
	}
	if rep3 := AggregateSalaries(obs, SalaryQuery{TitleFamily: "account executive", MaxAgeDays: -1, NowMs: now}); rep3.Matched != 4 {
		t.Fatalf("age disabled: %d", rep3.Matched)
	}
	if rep4 := AggregateSalaries(obs, SalaryQuery{TitleFamily: "account executive", Seniority: "Sr", NowMs: now}); rep4.Matched != 3 || rep4.Query.Seniority != "senior" {
		t.Fatalf("seniority: %+v", rep4.Query)
	}
	if rep5 := AggregateSalaries(obs, SalaryQuery{Company: "co https x example 1", NowMs: now}); rep5.Matched != 1 {
		t.Fatalf("company filter: %d", rep5.Matched)
	}
	empty := AggregateSalaries(nil, SalaryQuery{TitleFamily: "astronaut"})
	if empty.Matched != 0 || empty.Sample == nil || empty.BySeniority == nil || !strings.Contains(empty.Markdown, "No employer-posted") {
		t.Fatalf("empty report: %+v", empty)
	}
}

func TestSalaryMarkdownEscapesUntrustedText(t *testing.T) {
	now := int64(1000 * dayMs)
	o := obsFixture("javascript:alert(1)", "Evil | Co [x](https://evil.example)", "software engineer", "senior", "metro:new-york", "US", "USD", 100000, 120000, now)
	o.TitleRaw = "<script>alert(1)</script> Engineer"
	o2 := obsFixture("https://ok.example/a(b)", "Good", "software engineer", "senior", "metro:new-york", "US", "USD", 110000, 130000, now)
	rep := AggregateSalaries([]SalaryObservation{o, o2}, SalaryQuery{TitleFamily: "software engineer", NowMs: now})
	md := rep.Markdown
	if strings.Contains(md, "<script") || strings.Contains(md, "](javascript:") || strings.Contains(md, "[x](") || !strings.Contains(md, `\[x\]`) {
		t.Fatalf("unsafe markdown: %s", md)
	}
	if !strings.Contains(md, "(https://ok.example/a%28b%29)") || !strings.Contains(md, "| Midpoint |") {
		t.Fatalf("expected safe link and table: %s", md)
	}
}

func TestSalaryJSONShape(t *testing.T) {
	o, ok := SalaryObservationFromJob(payJob("https://x.example/1", "Senior Software Engineer", fp(1e5), fp(2e5), "USD", PayPeriodYear), 7)
	if !ok {
		t.Fatal("expected observation")
	}
	b, _ := json.Marshal(o)
	for _, k := range []string{`"url"`, `"titleRaw"`, `"titleFamily"`, `"seniority"`, `"companyKey"`, `"company"`, `"locationBucket"`,
		`"workplaceType"`, `"currency"`, `"period"`, `"basis"`, `"minAnnual"`, `"maxAnnual"`, `"source"`, `"seenAt"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
}
