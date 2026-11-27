package company

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ---- synthetic Wikidata fixture helpers ----

func wdStr(v string, rank string) string {
	return `{"rank":"` + rank + `","mainsnak":{"snaktype":"value","datavalue":{"type":"string","value":` + jsonQuote(v) + `}}}`
}

func wdItem(qid, rank string, quals string) string {
	q := ""
	if quals != "" {
		q = `,"qualifiers":` + quals
	}
	return `{"rank":"` + rank + `","mainsnak":{"snaktype":"value","datavalue":{"type":"wikibase-entityid","value":{"id":"` + qid + `"}}}` + q + `}`
}

func wdQty(amount, rank, pit string) string {
	q := ""
	if pit != "" {
		q = `,"qualifiers":{"P585":[{"snaktype":"value","datavalue":{"type":"time","value":{"time":"` + pit + `","precision":11}}}]}`
	}
	return `{"rank":"` + rank + `","mainsnak":{"snaktype":"value","datavalue":{"type":"quantity","value":{"amount":"` + amount + `","unit":"1"}}}` + q + `}`
}

func wdTime(t string) string {
	return `{"rank":"normal","mainsnak":{"snaktype":"value","datavalue":{"type":"time","value":{"time":"` + t + `","precision":11}}}}`
}

func wdEntityJSON(qid, label, desc string, claims map[string][]string) string {
	var parts []string
	for k, v := range claims {
		parts = append(parts, `"`+k+`":[`+strings.Join(v, ",")+`]`)
	}
	return `{"id":"` + qid + `","labels":{"en":{"language":"en","value":` + jsonQuote(label) + `}},"descriptions":{"en":{"language":"en","value":` + jsonQuote(desc) + `}},"claims":{` + strings.Join(parts, ",") + `}}`
}

func wdEntities(ents ...string) string {
	var parts []string
	for _, e := range ents {
		var probe struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(e), &probe)
		parts = append(parts, `"`+probe.ID+`":`+e)
	}
	return `{"entities":{` + strings.Join(parts, ",") + `}}`
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

const searchAcme = `{"searchinfo":{"search":"Acme Widgets"},"search":[
 {"id":"Q900001","label":"Acme Widgets","description":"fictional band"},
 {"id":"Q900002","label":"Acme Widgets","description":"American widget manufacturing company"},
 {"id":"bogus","label":"x"},
 {"id":"Q900003","label":"Acme Widgets (disambiguation)","description":"Wikimedia disambiguation page"}
]}`

func decoyEntity() string {
	return wdEntityJSON("Q900001", "Acme Widgets", "fictional band", map[string][]string{
		"P856": {wdStr("https://acmewidgets.net/", "normal")},
	})
}

func acmeEntity() string {
	return wdEntityJSON("Q900002", "Acme Widgets", "American widget manufacturing company", map[string][]string{
		"P856":  {wdStr("https://www.acmewidgets.com/", "normal")},
		"P5531": {wdStr("0000123456", "normal")},
		"P571":  {wdTime("+1987-03-01T00:00:00Z")},
		"P159":  {wdItem("Q910001", "normal", "")},
		"P17":   {wdItem("Q910002", "normal", "")},
		"P452":  {wdItem("Q910003", "normal", ""), wdItem("Q910004", "normal", "")},
		"P414":  {wdItem("Q910005", "normal", `{"P249":[{"snaktype":"value","datavalue":{"type":"string","value":"ACMW"}}]}`)},
		"P1128": {
			wdQty("+900", "normal", "+2019-12-31T00:00:00Z"),
			wdQty("+1500", "preferred", "+2022-12-31T00:00:00Z"),
			wdQty("+1700", "normal", "+2023-12-31T00:00:00Z"),
			wdQty("+99999", "deprecated", "+2024-12-31T00:00:00Z"),
		},
		"P2002": {wdStr("acmewidgets", "normal")},
		"P2037": {wdStr("acmewidgets", "normal")},
		"P4264": {wdStr("acme-widgets-inc", "normal")},
	})
}

func labelsJSON() string {
	return wdEntities(
		wdEntityJSON("Q910001", "Springfield", "", nil),
		wdEntityJSON("Q910002", "United States", "", nil),
		wdEntityJSON("Q910003", "manufacturing", "", nil),
		wdEntityJSON("Q910004", "industrial <b>machinery</b>", "", nil),
		wdEntityJSON("Q910005", "Nasdaq", "", nil),
	)
}

const secSubmissionsAcme = `{"cik":"123456","name":"ACME WIDGETS HOLDINGS, INC.","sic":"3560","sicDescription":"General Industrial Machinery & Equipment",
"tickers":["ACMW",null,"acmw.b"],"exchanges":["Nasdaq",null,"NYSE"],
"addresses":{"business":{"street1":"1 Main St","city":"SPRINGFIELD","stateOrCountry":"IL","stateOrCountryDescription":"IL"}}}`

const secFactsAcme = `{"cik":123456,"entityName":"ACME WIDGETS HOLDINGS, INC.","facts":{"us-gaap":{
 "Revenues":{"units":{"USD":[
  {"start":"2021-01-01","end":"2021-12-31","val":1000000,"fy":2021,"fp":"FY","form":"10-K","filed":"2022-02-20"},
  {"start":"2022-01-01","end":"2022-12-31","val":2000000,"fy":2022,"fp":"FY","form":"10-K","filed":"2023-02-20"},
  {"start":"2022-01-01","end":"2022-12-31","val":2000000,"fy":2023,"fp":"FY","form":"10-K","filed":"2024-02-20"},
  {"start":"2024-01-01","end":"2024-03-31","val":900000,"fy":2024,"fp":"Q1","form":"10-Q","filed":"2024-05-01"}
 ]}},
 "RevenueFromContractWithCustomerExcludingAssessedTax":{"units":{"USD":[
  {"start":"2023-01-01","end":"2023-12-31","val":3000000,"fy":2023,"fp":"FY","form":"10-K","filed":"2024-02-20"},
  {"start":"2024-01-01","end":"2024-06-30","val":5000000,"fy":2024,"fp":"Q2","form":"10-K","filed":"2024-08-20"},
  {"start":"2023-01-01","end":"2023-12-31","val":3000000,"fy":2025,"fp":"FY","form":"10-K","filed":"2026-02-20"}
 ],"EUR":[
  {"start":"2025-01-01","end":"2025-12-31","val":9000000,"fy":2025,"fp":"FY","form":"10-K","filed":"2026-02-20"}
 ]}}
}}}`

const homepageHTML = `<!doctype html><html><head><title>Acme Widgets | Industrial widgets</title>
<script type="application/ld+json">{"@context":"https://schema.org","@graph":[
 {"@type":"WebSite","url":"https://www.acmewidgets.com/","publisher":{"@type":"Organization","name":"Partner Co","url":"https://partner.example.org/"}},
 {"@type":"Organization","name":"Acme Widgets","url":"https://www.acmewidgets.com/","description":"We build \u003cscript\u003ealert(1)\u003c/script\u003e widgets.",
  "logo":{"@type":"ImageObject","url":"/static/logo.png"},
  "foundingDate":"1990-01-01",
  "sameAs":["https://www.linkedin.com/company/acme-widgets/","http://twitter.com/insecure","javascript:alert(1)","https://instagram.com/acmewidgets?hl=en"]}
]}</script></head><body>
<a href="https://twitter.com/intent/tweet?text=hi">share</a>
<a href='https://twitter.com/partnerco'>partner</a>
<a href="https://x.com/AcmeWidgets">x</a>
<a href=https://www.facebook.com/sharer/sharer.php?u=1>fb share</a>
<a href="https://www.facebook.com/acmewidgets">fb</a>
<a href="https://www.youtube.com/@acmewidgets">yt</a>
<a href="https://github.com/acmewidgets">gh</a>
<a href="https://www.linkedin.com/in/some-person">person</a>
</body></html>`

const githubAcme = `{"login":"acmewidgets","name":"Acme Widgets","html_url":"https://github.com/acmewidgets","blog":"acmewidgets.com","public_repos":42,"followers":1234,"avatar_url":"https://avatars.githubusercontent.com/u/1?v=4","description":"Open source widgets"}`

// ---- tests ----

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"acmewidgets.com", "acmewidgets.com", true},
		{"https://WWW.AcmeWidgets.com/about?x=1#y", "acmewidgets.com", true},
		{"http://careers.acmewidgets.co.uk:443/", "careers.acmewidgets.co.uk", true},
		{"//acmewidgets.com", "acmewidgets.com", true},
		{"acmewidgets.com.", "acmewidgets.com", true},
		{"ftp://acmewidgets.com", "", false},
		{"user@acmewidgets.com", "", false},
		{"localhost", "", false},
		{"127.0.0.1", "", false},
		{"intranet.local", "", false},
		{"co.uk", "", false},
		{"acme widgets.com", "", false},
		{"acmewidgets.com:abc", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeDomain(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}

func TestPlan(t *testing.T) {
	out, err := Plan(PlanInput{Name: "Acme Widgets, Inc.", Domain: "https://www.acmewidgets.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]FetchRequest{}
	for _, r := range out.Requests {
		ids[r.ID] = r
		if r.Method != "GET" {
			t.Errorf("method %q", r.Method)
		}
	}
	if ids["homepage"].URL != "https://acmewidgets.com/" || ids["homepage"].Kind != "html" {
		t.Errorf("homepage %+v", ids["homepage"])
	}
	if !ids["about"].Optional || ids["about"].URL != "https://acmewidgets.com/about" {
		t.Errorf("about %+v", ids["about"])
	}
	if want := "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&language=en&type=item&limit=5&search=Acme+Widgets%2C+Inc."; ids["wikidata_search"].URL != want {
		t.Errorf("search url %q", ids["wikidata_search"].URL)
	}
	if ids["github_org"].URL != "https://api.github.com/orgs/acmewidgets" || out.GitHubSlug != "acmewidgets" {
		t.Errorf("github %+v", ids["github_org"])
	}

	nameOnly, err := Plan(PlanInput{Name: "Acme Widgets Inc"})
	if err != nil || len(nameOnly.Requests) != 2 || nameOnly.GitHubSlug != "acmewidgets" || nameOnly.Domain != "" {
		t.Errorf("name-only plan: %+v %v", nameOnly, err)
	}
	domOnly, _ := Plan(PlanInput{Domain: "acmewidgets.co.uk"})
	if domOnly.SearchTerm != "acmewidgets" {
		t.Errorf("domain-only search term %q", domOnly.SearchTerm)
	}
	if _, err := Plan(PlanInput{}); !errors.Is(err, ErrNoInput) {
		t.Errorf("empty input err %v", err)
	}
	if _, err := Plan(PlanInput{Name: "x", Domain: "localhost"}); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("invalid domain err %v", err)
	}
	if out, _ := Plan(PlanInput{Name: "!!"}); out.GitHubSlug != "" {
		t.Errorf("implausible slug %q", out.GitHubSlug)
	}
}

func TestURLBuilders(t *testing.T) {
	if p, ok := PadCIK("320193"); !ok || p != "0000320193" {
		t.Errorf("pad %q", p)
	}
	for _, bad := range []string{"", "0", "12345678901", "12a", "-1"} {
		if _, ok := PadCIK(bad); ok {
			t.Errorf("PadCIK(%q) accepted", bad)
		}
	}
	if SECSubmissionsURL("CIK320193") != "https://data.sec.gov/submissions/CIK0000320193.json" {
		t.Error(SECSubmissionsURL("320193"))
	}
	if SECCompanyFactsURL("0000320193") != "https://data.sec.gov/api/xbrl/companyfacts/CIK0000320193.json" {
		t.Error(SECCompanyFactsURL("0000320193"))
	}
	if WikidataEntityURL("Q95") != "https://www.wikidata.org/wiki/Special:EntityData/Q95.json" || WikidataEntityURL("Q0") != "" || WikidataEntityURL("../x") != "" {
		t.Error("entity url")
	}
	if got := WikidataEntitiesURL([]string{"Q1", "bad", "Q2"}, true); got != "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&languages=en&props=labels&ids=Q1%7CQ2" {
		t.Error(got)
	}
}

func TestFollowups(t *testing.T) {
	f := Followups(FollowupsInput{WikidataSearchJSON: searchAcme})
	if len(f.Candidates) != 3 || len(f.WikidataEntityURLs) != 3 || f.Candidates[1].ID != "Q900002" {
		t.Fatalf("followups %+v", f)
	}
	if !strings.Contains(f.WikidataBatchURL, "ids=Q900001%7CQ900002%7CQ900003") {
		t.Errorf("batch %q", f.WikidataBatchURL)
	}
	if e := Followups(FollowupsInput{WikidataSearchJSON: "not json"}); len(e.Candidates) != 0 || e.WikidataEntityURLs == nil {
		t.Errorf("bad json %+v", e)
	}
}

func TestPickWikidataEntity(t *testing.T) {
	batch := wdEntities(decoyEntity(), acmeEntity())
	cases := []struct {
		name   string
		in     PickInput
		qid    string
		ok     bool
		reason string
	}{
		{"domain corroborated beats same-name decoy", PickInput{WikidataSearchJSON: searchAcme, EntityJSONs: []string{batch}, Domain: "acmewidgets.com"}, "Q900002", true, "website_match"},
		{"registrable domain match", PickInput{WikidataSearchJSON: searchAcme, EntityJSONs: []string{wdEntities(acmeEntity())}, Domain: "shop.acmewidgets.com"}, "Q900002", true, "website_match"},
		{"decoy domain picks decoy", PickInput{WikidataSearchJSON: searchAcme, EntityJSONs: []string{batch}, Domain: "acmewidgets.net"}, "Q900001", true, "website_match"},
		{"no corroboration never picks", PickInput{WikidataSearchJSON: searchAcme, EntityJSONs: []string{batch}, Domain: "other-company.com"}, "", false, "no_corroborated_candidate"},
		{"domain but no entities", PickInput{WikidataSearchJSON: searchAcme, Domain: "acmewidgets.com"}, "", false, "no_corroborated_candidate"},
		{"no domain uses description", PickInput{WikidataSearchJSON: searchAcme, Name: "Acme Widgets"}, "Q900002", true, "description_match"},
		{"empty", PickInput{}, "", false, "no_candidates"},
		{"invalid domain", PickInput{WikidataSearchJSON: searchAcme, Domain: "localhost"}, "", false, "invalid_domain"},
	}
	for _, c := range cases {
		got := PickWikidataEntity(c.in)
		if got.QID != c.qid || got.OK != c.ok || got.Reason != c.reason {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
	got := PickWikidataEntity(PickInput{WikidataSearchJSON: searchAcme, EntityJSONs: []string{batch}, Domain: "acmewidgets.com"})
	if got.Followups == nil || got.Followups.CIK != "0000123456" || got.Followups.SECSubmissionsURL != "https://data.sec.gov/submissions/CIK0000123456.json" {
		t.Fatalf("followups %+v", got.Followups)
	}
	if got.Followups.HomepageURL != "" || got.Followups.GitHubOrgURL != "https://api.github.com/orgs/acmewidgets" {
		t.Errorf("followups homepage/github %+v", got.Followups)
	}
	if len(got.Followups.LabelIDs) != 5 || !strings.Contains(got.Followups.LabelsURL, "props=labels") {
		t.Errorf("label ids %+v", got.Followups)
	}
}

func TestEntityFollowupsNoDomain(t *testing.T) {
	f := EntityFollowupsFor(EntityFollowupsInput{EntityJSON: wdEntities(acmeEntity())})
	if f.QID != "Q900002" || f.HomepageURL != "https://www.acmewidgets.com/" || f.SECCompanyFactsURL == "" {
		t.Errorf("%+v", f)
	}
	if e := EntityFollowupsFor(EntityFollowupsInput{EntityJSON: wdEntities(acmeEntity(), decoyEntity())}); e.QID != "" {
		t.Errorf("ambiguous entity without qid should yield nothing: %+v", e)
	}
}

func TestSelectClaim(t *testing.T) {
	parse := func(claims ...string) []wdClaim {
		var out []wdClaim
		if err := json.Unmarshal([]byte("["+strings.Join(claims, ",")+"]"), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	amount := func(c *wdClaim) float64 {
		if c == nil {
			return -1
		}
		f, _ := snakQuantity(c.Mainsnak)
		return f
	}
	cases := []struct {
		name   string
		claims []wdClaim
		want   float64
	}{
		{"preferred wins over later normal", parse(wdQty("+1", "normal", "+2024-01-01T00:00:00Z"), wdQty("+2", "preferred", "+2020-01-01T00:00:00Z")), 2},
		{"latest normal by P585", parse(wdQty("+1", "normal", "+2020-01-01T00:00:00Z"), wdQty("+3", "normal", "+2023-06-30T00:00:00Z"), wdQty("+2", "normal", "+2021-01-01T00:00:00Z")), 3},
		{"first normal without P585", parse(wdQty("+5", "normal", ""), wdQty("+6", "normal", "")), 5},
		{"deprecated never selected", parse(wdQty("+9", "deprecated", "+2025-01-01T00:00:00Z")), -1},
		{"latest among several preferred", parse(wdQty("+7", "preferred", "+2019-01-01T00:00:00Z"), wdQty("+8", "preferred", "+2022-01-01T00:00:00Z")), 8},
	}
	for _, c := range cases {
		if got := amount(selectClaim(c.claims)); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestLatestAnnualRevenue(t *testing.T) {
	cf := parseCompanyFacts(secFactsAcme)
	rev := latestAnnualRevenue(cf)
	if rev == nil {
		t.Fatal("nil revenue")
	}
	if rev.Value != 3000000 || rev.FiscalYear != 2023 || rev.PeriodEnd != "2023-12-31" || rev.Filed != "2024-02-20" ||
		rev.Concept != "RevenueFromContractWithCustomerExcludingAssessedTax" || rev.Currency != "USD" {
		t.Errorf("revenue %+v", rev)
	}
	// Comparative duplicate of FY2022 in a later filing keeps the original fy.
	only2022 := `{"cik":1,"facts":{"us-gaap":{"Revenues":{"units":{"USD":[
	 {"start":"2022-01-01","end":"2022-12-31","val":2,"fy":2023,"form":"10-K","filed":"2024-02-20"},
	 {"start":"2022-01-01","end":"2022-12-31","val":2,"fy":2022,"form":"10-K","filed":"2023-02-20"}]}}}}}`
	if r := latestAnnualRevenue(parseCompanyFacts(only2022)); r == nil || r.FiscalYear != 2022 || r.Filed != "2023-02-20" {
		t.Errorf("comparative %+v", r)
	}
	if latestAnnualRevenue(parseCompanyFacts(`{"facts":{}}`)) != nil || latestAnnualRevenue(nil) != nil {
		t.Error("expected nil revenue")
	}
}

func TestNormalizeSocialURL(t *testing.T) {
	cases := []struct {
		in, net, want string
	}{
		{"https://www.linkedin.com/company/Acme-Widgets/about/", NetLinkedIn, "https://www.linkedin.com/company/acme-widgets"},
		{"https://linkedin.com/in/some-person", "", ""},
		{"https://twitter.com/AcmeWidgets?lang=en", NetX, "https://x.com/AcmeWidgets"},
		{"https://mobile.x.com/acme_w", NetX, "https://x.com/acme_w"},
		{"https://twitter.com/intent/tweet?text=x", "", ""},
		{"https://x.com/this_handle_is_way_too_long", "", ""},
		{"http://twitter.com/acme", "", ""},
		{"javascript:alert(1)", "", ""},
		{"JAVASCRIPT://x.com/acme", "", ""},
		{"data:text/html,x", "", ""},
		{"https://github.com/acmewidgets/repo", NetGitHub, "https://github.com/acmewidgets"},
		{"https://github.com/orgs/acmewidgets/people", NetGitHub, "https://github.com/acmewidgets"},
		{"https://github.com/features", "", ""},
		{"https://m.facebook.com/acmewidgets/", NetFacebook, "https://www.facebook.com/acmewidgets"},
		{"https://www.facebook.com/sharer/sharer.php?u=x", "", ""},
		{"https://instagram.com/acmewidgets", NetInstagram, "https://www.instagram.com/acmewidgets"},
		{"https://www.instagram.com/p/abc123", "", ""},
		{"https://www.youtube.com/@acmewidgets/videos", NetYouTube, "https://www.youtube.com/@acmewidgets"},
		{"https://youtube.com/channel/UC123abc", NetYouTube, "https://www.youtube.com/channel/UC123abc"},
		{"https://www.youtube.com/watch?v=abc", "", ""},
		{"https://user:pw@github.com/acme", "", ""},
		{"https://github.com:8443/acme", "", ""},
		{"https://evil.example.org/github.com/acme", "", ""},
	}
	for _, c := range cases {
		net, got, ok := NormalizeSocialURL(c.in)
		if ok != (c.want != "") || net != c.net || got != c.want {
			t.Errorf("NormalizeSocialURL(%q) = %q %q %v; want %q %q", c.in, net, got, ok, c.net, c.want)
		}
	}
}

func TestScanHrefsLinearAndBounded(t *testing.T) {
	got := scanHrefs(`<a HREF = "https://x.com/a">x</a><a href='https://github.com/b'><a href=https://facebook.com/c>`+
		`<a href="https://unrelated.example.org/">`+`<a href="unterminated`, 100)
	if len(got) != 3 || got[0] != "https://x.com/a" || got[2] != "https://facebook.com/c" {
		t.Errorf("hrefs %q", got)
	}
	big := strings.Repeat(`href="`, 200000)
	if out := scanHrefs(big, 10); len(out) != 0 {
		t.Errorf("pathological input produced %d", len(out))
	}
}

func fullMergeInput() MergeInput {
	return MergeInput{
		Name:   "Acme Widgets",
		Domain: "acmewidgets.com",
		Homepage: &HomepageInput{
			URL: "https://acmewidgets.com/", FinalURL: "https://www.acmewidgets.com/",
			Title: "Acme Widgets | Industrial widgets", Description: "Meta description", SiteName: "Acme",
			HTML: homepageHTML,
		},
		WikidataID:          "Q900002",
		WikidataEntityJSON:  wdEntities(acmeEntity()),
		WikidataLabelsJSON:  labelsJSON(),
		SECSubmissionsJSON:  secSubmissionsAcme,
		SECCompanyFactsJSON: secFactsAcme,
		GitHubOrgJSON:       githubAcme,
		ATS: &ATSSummary{
			BoardURLs: []string{"https://boards.example-ats.com/acme", "http://insecure.example.com/x", "javascript:alert(1)"},
			Platform:  "greenhouse", OpenRoles: 37,
			Departments: []string{"Engineering", "Sales", "engineering", "<img src=x onerror=alert(1)>Ops"},
			Locations:   []string{"Remote", "Springfield, IL"},
			SampleRoles: []string{"Senior Widget Engineer"},
		},
	}
}

func TestMergePrecedence(t *testing.T) {
	p := Merge(fullMergeInput())
	check := func(field, got, want, src string) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
		if src != "" && p.FieldSources[field] != src {
			t.Errorf("%s source = %q, want %q", field, p.FieldSources[field], src)
		}
	}
	check("name", p.Name, "Acme Widgets", SourceWikidata)
	check("legalName", p.LegalName, "ACME WIDGETS HOLDINGS, INC.", SourceSECSubmissions)
	check("domain", p.Domain, "acmewidgets.com", SourceInput)
	check("website", p.Website, "https://acmewidgets.com/", SourceInput)
	check("logo", p.Logo, "https://www.acmewidgets.com/static/logo.png", SourceHomepageJSONLD)
	check("cik", p.CIK, "0000123456", SourceSECSubmissions)
	check("ticker", p.Ticker, "ACMW", SourceSECSubmissions)
	check("exchange", p.Exchange, "Nasdaq", SourceSECSubmissions)
	check("wikidataId", p.WikidataID, "Q900002", SourceWikidata)
	if p.FieldSources["description"] != SourceHomepageJSONLD || strings.Contains(p.Description, "<script") || !strings.Contains(p.Description, "widgets") {
		t.Errorf("description %q (%s)", p.Description, p.FieldSources["description"])
	}
	if p.Founded != 1987 || p.FieldSources["founded"] != SourceWikidata {
		t.Errorf("founded %d from %s (wikidata must beat JSON-LD 1990)", p.Founded, p.FieldSources["founded"])
	}
	if hq := p.Headquarters; hq == nil || hq.City != "Springfield" || hq.Region != "IL" || hq.Country != "United States" || p.FieldSources["headquarters"] != SourceSECSubmissions {
		t.Errorf("hq %+v", p.Headquarters)
	}
	if ind := p.Industry; ind == nil || ind.SICCode != "3560" || len(ind.Labels) != 2 || strings.Contains(ind.Labels[1], "<") {
		t.Errorf("industry %+v", p.Industry)
	}
	if e := p.Employees; e == nil || e.Count != 1500 || e.AsOf != "2022-12-31" {
		t.Errorf("employees %+v (preferred rank must win)", p.Employees)
	}
	if len(p.Listings) != 2 || p.Listings[1].Ticker != "ACMW.B" || p.Listings[1].Exchange != "NYSE" {
		t.Errorf("listings %+v", p.Listings)
	}
	if p.Revenue == nil || p.Revenue.Value != 3000000 || p.FieldSources["revenue"] != SourceSECCompanyFacts {
		t.Errorf("revenue %+v", p.Revenue)
	}
	s := p.Socials
	if s == nil {
		t.Fatal("no socials")
	}
	check("socials.linkedin", s.LinkedIn, "https://www.linkedin.com/company/acme-widgets", SourceHomepageJSONLD)
	check("socials.instagram", s.Instagram, "https://www.instagram.com/acmewidgets", SourceHomepageJSONLD)
	check("socials.x", s.X, "https://x.com/AcmeWidgets", SourceHomepageLinks)
	check("socials.facebook", s.Facebook, "https://www.facebook.com/acmewidgets", SourceHomepageLinks)
	check("socials.youtube", s.YouTube, "https://www.youtube.com/@acmewidgets", SourceHomepageLinks)
	check("socials.github", s.GitHub, "https://github.com/acmewidgets", SourceHomepageLinks)
	if g := p.GitHub; g == nil || g.PublicRepos != 42 || g.Followers != 1234 || g.URL != "https://github.com/acmewidgets" {
		t.Errorf("github %+v", p.GitHub)
	}
	h := p.Hiring
	if h == nil || h.OpenRoles != 37 || len(h.BoardURLs) != 1 || len(h.Departments) != 3 || strings.Contains(strings.Join(h.Departments, ""), "<img") {
		t.Errorf("hiring %+v", p.Hiring)
	}
	for _, src := range []string{SourceSECSubmissions, SourceSECCompanyFacts, SourceWikidata, SourceHomepageJSONLD, SourceHomepageLinks, SourceGitHub, SourceATS, SourceInput} {
		if !containsFold(p.Sources, src) {
			t.Errorf("sources missing %s: %v", src, p.Sources)
		}
	}
	md := p.Markdown
	for _, want := range []string{"# Acme Widgets", "**Revenue**: $3,000,000 USD (FY2023", "**Employees**: 1,500 (as of 2022-12-31)", "Nasdaq: ACMW", "**Hiring**: 37 open roles on greenhouse"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "<script") || strings.Contains(md, "<img") || strings.Contains(md, "javascript:") {
		t.Errorf("markdown leaked raw html:\n%s", md)
	}
}

func TestMergeFallbacksAndCorroboration(t *testing.T) {
	// Homepage meta only.
	p := Merge(MergeInput{Domain: "acmewidgets.com", Homepage: &HomepageInput{Title: "Acme Widgets - Home", Description: "Meta <b>desc</b>"}})
	if p.Name != "Acme Widgets" || p.FieldSources["name"] != SourceHomepageMeta || p.Description != "Meta desc" || p.FieldSources["description"] != SourceHomepageMeta {
		t.Errorf("meta fallback %+v", p)
	}

	// Missing everything: only input.
	p = Merge(MergeInput{Name: "Acme Widgets"})
	if p.Name != "Acme Widgets" || p.FieldSources["name"] != SourceInput || len(p.Sources) != 1 || p.Socials != nil || p.Hiring != nil {
		t.Errorf("empty merge %+v", p)
	}
	if !strings.HasPrefix(p.Markdown, "# Acme Widgets") {
		t.Errorf("md %q", p.Markdown)
	}

	// Decoy Wikidata entity with mismatched website is dropped, and SEC is then uncorroborated.
	in := fullMergeInput()
	in.WikidataID = "Q900001"
	in.WikidataEntityJSON = wdEntities(decoyEntity())
	p = Merge(in)
	if p.WikidataID != "" || p.CIK != "" || p.Revenue != nil || !containsFold(p.Warnings, "wikidata_uncorroborated") || !containsFold(p.Warnings, "sec_uncorroborated") {
		t.Errorf("decoy merge %+v warnings=%v", p.FieldSources, p.Warnings)
	}
	if p.Founded != 1990 || p.FieldSources["founded"] != SourceHomepageJSONLD {
		t.Errorf("founded fallback %d %s", p.Founded, p.FieldSources["founded"])
	}

	// GitHub org without any corroboration is dropped.
	p = Merge(MergeInput{Name: "Acme Widgets", GitHubOrgJSON: `{"login":"acmewidgets","blog":"https://someone-else.example.org","public_repos":1}`})
	if p.GitHub != nil || !containsFold(p.Warnings, "github_uncorroborated") {
		t.Errorf("github should be dropped: %+v %v", p.GitHub, p.Warnings)
	}
	// GitHub corroborated by blog domain; also supplies the github social.
	p = Merge(MergeInput{Domain: "acmewidgets.com", GitHubOrgJSON: githubAcme})
	if p.GitHub == nil || p.Socials == nil || p.Socials.GitHub != "https://github.com/acmewidgets" || p.FieldSources["logo"] != SourceGitHub {
		t.Errorf("github blog corroboration %+v", p)
	}

	// Wikidata HQ / listings / socials fill in when SEC and homepage are absent.
	p = Merge(MergeInput{Domain: "acmewidgets.com", WikidataEntityJSON: wdEntities(acmeEntity()), WikidataLabelsJSON: labelsJSON()})
	if hq := p.Headquarters; hq == nil || hq.City != "Springfield" || hq.Country != "United States" || p.FieldSources["headquarters"] != SourceWikidata {
		t.Errorf("wikidata hq %+v", p.Headquarters)
	}
	if p.Ticker != "ACMW" || p.Exchange != "Nasdaq" || p.FieldSources["listings"] != SourceWikidata || p.CIK != "0000123456" || p.FieldSources["cik"] != SourceWikidata {
		t.Errorf("wikidata listing %+v", p)
	}
	if p.Socials == nil || p.Socials.X != "https://x.com/acmewidgets" || p.Socials.LinkedIn != "https://www.linkedin.com/company/acme-widgets-inc" || p.FieldSources["socials.x"] != SourceWikidata {
		t.Errorf("wikidata socials %+v", p.Socials)
	}

	// Garbage bodies never panic and produce warnings.
	p = Merge(MergeInput{Name: "X Co", WikidataEntityJSON: "{", SECSubmissionsJSON: "[", SECCompanyFactsJSON: "nope", GitHubOrgJSON: "{}", PlacesJSON: "]"})
	if len(p.Warnings) < 4 {
		t.Errorf("warnings %v", p.Warnings)
	}
}

const placesObjectShape = `{"places":[
 {"displayName":{"text":"Acme Widgets Outlet"},"formattedAddress":"9 Mall Rd","websiteUri":"https://acmewidgets-outlet.example.org/","rating":4.9},
 {"displayName":{"text":"Acme Widgets HQ"},"formattedAddress":"1 Main St, Springfield, IL 62701, USA","location":{"latitude":39.8,"longitude":-89.6},
  "googleMapsUri":"https://maps.google.com/?cid=1","internationalPhoneNumber":"+1 217-555-0100","rating":4.3,"userRatingCount":210,"websiteUri":"https://www.acmewidgets.com/"}
]}`

const placesArrayShape = `[
 {"name":"Acme Widgets","address":"77 Decoy Ave","websiteUri":"https://not-acme.example.org/","mapsUri":"http://maps.example.org/insecure"},
 {"name":"ACME WIDGETS, INC.","address":"2 Side St","url":"javascript:alert(1)","phone":"555-0101","rating":"bad"}
]`

func TestPlaces(t *testing.T) {
	pl := PickPlace(placesObjectShape, "acmewidgets.com", []string{"Acme Widgets"})
	if pl == nil || pl.Name != "Acme Widgets HQ" || pl.MatchedBy != "website" || pl.MapsURL != "https://maps.google.com/?cid=1" ||
		pl.RatingCount != 210 || pl.Latitude == nil || *pl.Latitude != 39.8 || pl.Phone != "+1 217-555-0100" {
		t.Fatalf("object shape %+v", pl)
	}
	// Array shape: name-matching decoy with a foreign website is rejected; the name match without a website wins.
	pl = PickPlace(placesArrayShape, "acmewidgets.com", []string{"Acme Widgets"})
	if pl == nil || pl.Address != "2 Side St" || pl.MatchedBy != "name" || pl.MapsURL != "" || pl.Rating != 0 {
		t.Fatalf("array shape %+v", pl)
	}
	// MCP wrapper shape.
	wrapped := `{"content":[{"type":"text","text":` + jsonQuote(placesObjectShape) + `}]}`
	if pl := PickPlace(wrapped, "acmewidgets.com", nil); pl == nil || pl.Name != "Acme Widgets HQ" {
		t.Errorf("wrapped %+v", pl)
	}
	if pl := PickPlace(placesObjectShape, "", []string{"Unrelated Corp"}); pl != nil {
		t.Errorf("non-matching should be nil: %+v", pl)
	}

	// Merge: place is always attached; HQ only from Maps when SEC/Wikidata absent.
	in := fullMergeInput()
	in.PlacesJSON = placesObjectShape
	p := Merge(in)
	if p.Place == nil || p.FieldSources["place"] != SourceGoogleMaps || p.FieldSources["headquarters"] != SourceSECSubmissions {
		t.Errorf("place with SEC hq %+v %v", p.Place, p.FieldSources)
	}
	p = Merge(MergeInput{Name: "Acme Widgets", Domain: "acmewidgets.com", PlacesJSON: placesObjectShape})
	if hq := p.Headquarters; hq == nil || hq.Address == "" || hq.Latitude == nil || p.FieldSources["headquarters"] != SourceGoogleMaps {
		t.Errorf("maps hq %+v", p.Headquarters)
	}
	if !strings.Contains(p.Markdown, "**Map**: Acme Widgets HQ") {
		t.Errorf("md %s", p.Markdown)
	}
}

func TestPlacesQuery(t *testing.T) {
	cases := []struct {
		in   PlacesQueryInput
		want string
	}{
		{PlacesQueryInput{Name: "Acme Widgets", HQHint: "Springfield, IL"}, "Acme Widgets headquarters Springfield, IL"},
		{PlacesQueryInput{Name: "  Acme\n<b>Widgets</b> "}, "Acme bWidgets/b headquarters"},
		{PlacesQueryInput{Domain: "https://www.acmewidgets.com"}, "acmewidgets headquarters"},
		{PlacesQueryInput{}, ""},
	}
	for _, c := range cases {
		if got := PlacesQuery(c.in); got != c.want {
			t.Errorf("PlacesQuery(%+v) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestHostMatchesDomain(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"www.acmewidgets.com", "acmewidgets.com", true},
		{"shop.acmewidgets.com", "acmewidgets.com", true},
		{"acmewidgets.com.evil.org", "acmewidgets.com", false},
		{"acme.github.io", "other.github.io", false},
		{"", "acmewidgets.com", false},
	}
	for _, c := range cases {
		if got := HostMatchesDomain(c.host, c.domain); got != c.want {
			t.Errorf("HostMatchesDomain(%q,%q)=%v", c.host, c.domain, got)
		}
	}
}
