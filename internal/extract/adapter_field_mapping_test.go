package extract

import (
	"slices"
	"strings"
	"testing"
)

func TestIsNuGetPrerelease(t *testing.T) {
	cases := map[string]bool{
		"13.0.3":               false,
		"1.0.0+sha.abc":        false,
		"10.0.0-preview.1":     true,
		"2.0.0-rc.1+build.5":   true,
		" 3.1.0-beta ":         true,
		"":                     false,
		"-":                    false,
		"1.0.0-":               false,
		"4.0.0+meta-with-dash": false,
	}
	for in, want := range cases {
		if got := isNuGetPrerelease(in); got != want {
			t.Errorf("isNuGetPrerelease(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNuGetLatestPrefersStableAndSurfacesNewerPrerelease(t *testing.T) {
	raw := `{"count":1,"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/demo/index.json#page/1.0.0/2.0.0-preview.2","count":4,"lower":"1.0.0","upper":"2.0.0-preview.2","items":[
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.0.0","listed":true,"published":"2024-01-01T00:00:00Z"}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.5.0","listed":true,"published":"2024-06-01T00:00:00Z","description":"Stable line"}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"2.0.0-preview.1","listed":true,"published":"2024-09-01T00:00:00Z"}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"2.0.0-preview.2","listed":true,"published":"2024-10-01T00:00:00Z"}}
	]}]}`
	doc, ok := formatNuGetRegistrationJSONGo([]byte(raw), map[string]string{"pkgId": "Demo.Pkg"}, "https://www.nuget.org/packages/Demo.Pkg")
	if !ok || doc == nil {
		t.Fatal("expected NuGet registration to format")
	}
	if doc.Title != "Demo.Pkg v1.5.0 (NuGet)" {
		t.Fatalf("expected newest stable 1.5.0 as latest, got title %q", doc.Title)
	}
	if !strings.Contains(doc.Markdown, "- **Version**: `1.5.0`") ||
		!strings.Contains(doc.Markdown, "- **Latest Prerelease**: `2.0.0-preview.2`") {
		t.Fatalf("expected stable version plus Latest Prerelease bullet, got:\n%s", doc.Markdown)
	}

	// No prerelease newer than the stable pick: no Latest Prerelease bullet.
	stableOnly := `{"items":[{"count":2,"items":[
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.0.0-beta","listed":true}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.0.0","listed":true}}
	]}]}`
	doc, ok = formatNuGetRegistrationJSONGo([]byte(stableOnly), map[string]string{"pkgId": "Demo.Pkg"}, "https://www.nuget.org/packages/Demo.Pkg")
	if !ok || doc == nil || doc.Title != "Demo.Pkg v1.0.0 (NuGet)" || strings.Contains(doc.Markdown, "Latest Prerelease") {
		t.Fatalf("expected 1.0.0 without Latest Prerelease, got: %+v", doc)
	}

	// Only prereleases exist: fall back to the newest listed prerelease without a duplicate bullet.
	preOnly := `{"items":[{"count":2,"items":[
		{"catalogEntry":{"id":"Demo.Pkg","version":"0.1.0-alpha","listed":true}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"0.2.0-alpha","listed":true}}
	]}]}`
	doc, ok = formatNuGetRegistrationJSONGo([]byte(preOnly), map[string]string{"pkgId": "Demo.Pkg"}, "https://www.nuget.org/packages/Demo.Pkg")
	if !ok || doc == nil || doc.Title != "Demo.Pkg v0.2.0-alpha (NuGet)" || strings.Contains(doc.Markdown, "Latest Prerelease") {
		t.Fatalf("expected prerelease-only package to select 0.2.0-alpha, got: %+v", doc)
	}

	// Unlisted stable releases are still skipped in favour of a listed one.
	unlisted := `{"items":[{"count":3,"items":[
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.0.0","listed":true}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.1.0","listed":false}},
		{"catalogEntry":{"id":"Demo.Pkg","version":"1.2.0-rc.1","listed":true}}
	]}]}`
	doc, ok = formatNuGetRegistrationJSONGo([]byte(unlisted), map[string]string{"pkgId": "Demo.Pkg"}, "https://www.nuget.org/packages/Demo.Pkg")
	if !ok || doc == nil || doc.Title != "Demo.Pkg v1.0.0 (NuGet)" || !strings.Contains(doc.Markdown, "- **Latest Prerelease**: `1.2.0-rc.1`") {
		t.Fatalf("expected listed stable 1.0.0 plus 1.2.0-rc.1 prerelease, got: %+v", doc)
	}

	// An explicitly requested version is honoured even when it is a prerelease.
	doc, ok = formatNuGetRegistrationJSONGo([]byte(raw), map[string]string{"pkgId": "Demo.Pkg", "ver": "2.0.0-preview.1"}, "https://www.nuget.org/packages/Demo.Pkg/2.0.0-preview.1")
	if !ok || doc == nil || doc.Title != "Demo.Pkg v2.0.0-preview.1 (NuGet)" || strings.Contains(doc.Markdown, "Latest Prerelease") {
		t.Fatalf("expected requested prerelease version, got: %+v", doc)
	}

	// Branch 2 (un-inlined pages): a prerelease upper bound is labelled as such.
	stubs := `{"count":1,"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/demo/page/1.0.0/3.0.0-rc.1.json","lower":"1.0.0","upper":"3.0.0-rc.1","count":40}]}`
	doc, ok = formatNuGetRegistrationJSONGo([]byte(stubs), map[string]string{"pkgId": "Demo.Pkg"}, "https://www.nuget.org/packages/Demo.Pkg")
	if !ok || doc == nil || !strings.Contains(doc.Markdown, "- **Latest Prerelease**: `3.0.0-rc.1`") || strings.Contains(doc.Markdown, "- **Latest Version**:") {
		t.Fatalf("expected Branch 2 prerelease upper bound labelled Latest Prerelease, got: %+v", doc)
	}
}

func TestMavenCentralVersionedRouteUsesSonatypeSolr(t *testing.T) {
	twin, ok := ResolveDeclarativeTwin("https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/2.18.2")
	if !ok || twin.FetchURL != "https://central.sonatype.com/solrsearch/select?q=g:com.fasterxml.jackson.core+AND+a:jackson-databind+AND+v:2.18.2&core=gav&rows=20&wt=json" {
		t.Fatalf("unexpected versioned maven-central twin: ok=%v twin=%+v", ok, twin)
	}
	// Live central.sonatype.com gav docs report versionCount 0 and an empty ec list.
	doc, ok := twin.Format(`{"responseHeader":{"status":0},"response":{"numFound":1,"start":0,"docs":[{"id":"com.fasterxml.jackson.core:jackson-databind:2.18.2","g":"com.fasterxml.jackson.core","a":"jackson-databind","v":"2.18.2","repositoryId":"central","p":"jar","timestamp":1732756357347,"versionCount":0,"ec":[]}]}}`)
	if !ok || doc == nil {
		t.Fatal("expected maven-central versioned doc to format")
	}
	if doc.Title != "com.fasterxml.jackson.core:jackson-databind:2.18.2 (Maven Central)" ||
		!strings.Contains(doc.Markdown, "- **Published**: 2024-11-28") ||
		!strings.Contains(doc.Markdown, "- **Packaging**: jar") {
		t.Fatalf("unexpected maven-central versioned markdown: %+v", doc)
	}
	if strings.Contains(doc.Markdown, "**Versions**") || strings.Contains(doc.Markdown, "Classifiers / Files") {
		t.Fatalf("expected no Versions / empty Classifiers bullets from gav docs, got:\n%s", doc.Markdown)
	}

	// The unversioned artifact-summary route is unchanged.
	summary, ok := ResolveDeclarativeTwin("https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind")
	if !ok || summary.FetchURL != "https://search.maven.org/solrsearch/select?q=g:com.fasterxml.jackson.core+AND+a:jackson-databind&rows=20&wt=json" {
		t.Fatalf("unexpected unversioned maven-central twin: ok=%v twin=%+v", ok, summary)
	}
}

func TestWikidataCuratedClaims(t *testing.T) {
	twin, ok := ResolveDeclarativeTwin("https://www.wikidata.org/wiki/Q64")
	if !ok {
		t.Fatal("expected wikidata twin")
	}
	city := `{"entities":{"Q64":{"id":"Q64","labels":{"en":{"language":"en","value":"Berlin"}},"descriptions":{"en":{"language":"en","value":"capital of Germany"}},"claims":{
		"P31":[{"mainsnak":{"datavalue":{"value":{"entity-type":"item","id":"Q1901835"},"type":"wikibase-entityid"}},"rank":"normal"},{"mainsnak":{"datavalue":{"value":{"entity-type":"item","id":"Q515"},"type":"wikibase-entityid"}},"rank":"normal"}],
		"P571":[{"mainsnak":{"datavalue":{"value":{"time":"+1100-00-00T00:00:00Z","precision":9},"type":"time"}},"rank":"deprecated"},{"mainsnak":{"datavalue":{"value":{"time":"+1244-00-00T00:00:00Z","precision":9},"type":"time"}},"rank":"normal"}],
		"P1082":[{"mainsnak":{"datavalue":{"value":{"amount":"+1200","unit":"1"},"type":"quantity"}},"rank":"normal"},{"mainsnak":{"datavalue":{"value":{"amount":"+3400000","unit":"1"},"type":"quantity"}},"rank":"normal"},{"mainsnak":{"datavalue":{"value":{"amount":"+3755251","unit":"1"},"type":"quantity"}},"rank":"preferred"},{"mainsnak":{"datavalue":{"value":{"amount":"+3600000","unit":"1"},"type":"quantity"}},"rank":"normal"}],
		"P856":[{"mainsnak":{"datavalue":{"value":"https://www.berlin.de/","type":"string"}},"rank":"normal"}]
	}}}}`
	doc, ok := twin.Format(city)
	if !ok || doc == nil {
		t.Fatal("expected wikidata city doc to format")
	}
	for _, want := range []string{
		"- **Instance Of**: `Q1901835`, `Q515`",
		"- **Inception**: 1244",
		"- **Population**: 3,755,251",
		"- **Official Website**: https://www.berlin.de/",
	} {
		if !strings.Contains(doc.Markdown, want) {
			t.Fatalf("expected %q in wikidata markdown, got:\n%s", want, doc.Markdown)
		}
	}
	// The preferred-rank population wins over the historic-first and later normal-rank claims,
	// and a deprecated-rank inception is never emitted.
	for _, absent := range []string{"1,200", "3,400,000", "3,600,000", "1100"} {
		if strings.Contains(doc.Markdown, absent) {
			t.Fatalf("expected non-preferred claim value %q to be omitted, got:\n%s", absent, doc.Markdown)
		}
	}
	for _, absent := range []string{"Sex or Gender", "Country of Citizenship", "Occupation", "Date of Birth", "Date of Death"} {
		if strings.Contains(doc.Markdown, absent) {
			t.Fatalf("expected absent claim %q to be omitted, got:\n%s", absent, doc.Markdown)
		}
	}
	if !slices.Contains(doc.Links, "https://www.berlin.de/") {
		t.Fatalf("expected official website in links, got %v", doc.Links)
	}

	personTwin, ok := ResolveDeclarativeTwin("https://www.wikidata.org/wiki/Q42")
	if !ok {
		t.Fatal("expected wikidata twin for Q42")
	}
	person := `{"entities":{"Q42":{"id":"Q42","labels":{"en":{"language":"en","value":"Douglas Adams"}},"claims":{
		"P31":[{"mainsnak":{"datavalue":{"value":{"id":"Q5"}}},"rank":"normal"}],
		"P21":[{"mainsnak":{"datavalue":{"value":{"id":"Q6581097"}}},"rank":"normal"}],
		"P27":[{"mainsnak":{"datavalue":{"value":{"id":"Q145"}}},"rank":"normal"}],
		"P106":[{"mainsnak":{"datavalue":{"value":{"id":"Q214917"}}},"rank":"normal"},{"mainsnak":{"snaktype":"somevalue"},"rank":"normal"},{"mainsnak":{"datavalue":{"value":{"id":"Q28389"}}},"rank":"normal"}],
		"P569":[{"mainsnak":{"datavalue":{"value":{"time":"+1952-03-11T00:00:00Z","precision":11}}},"rank":"normal"}],
		"P570":[{"mainsnak":{"datavalue":{"value":{"time":"+2001-05-11T00:00:00Z","precision":11}}},"rank":"normal"}],
		"P856":[{"mainsnak":{"datavalue":{"value":"javascript:alert(1)"}},"rank":"normal"}]
	}}}}`
	doc, ok = personTwin.Format(person)
	if !ok || doc == nil {
		t.Fatal("expected wikidata person doc to format")
	}
	for _, want := range []string{
		"- **Instance Of**: `Q5`",
		"- **Sex or Gender**: `Q6581097`",
		"- **Country of Citizenship**: `Q145`",
		"- **Occupation**: `Q214917`, `Q28389`",
		"- **Date of Birth**: 1952-03-11",
		"- **Date of Death**: 2001-05-11",
	} {
		if !strings.Contains(doc.Markdown, want) {
			t.Fatalf("expected %q in wikidata person markdown, got:\n%s", want, doc.Markdown)
		}
	}
	if strings.Contains(doc.Markdown, "javascript:") || strings.Contains(doc.Markdown, "Official Website") {
		t.Fatalf("expected non-http official website to be dropped, got:\n%s", doc.Markdown)
	}
}

func TestOpenLibraryByStatementAuthorFallback(t *testing.T) {
	twin, ok := ResolveDeclarativeTwin("https://openlibrary.org/isbn/9780743273565")
	if !ok {
		t.Fatal("expected open library twin")
	}
	doc, ok := twin.Format(`{"title":"The Great Gatsby","by_statement":"F. Scott Fitzgerald","publishers":["Scribner"],"key":"/books/OL1M"}`)
	if !ok || doc == nil || doc.Author != "F. Scott Fitzgerald" || !strings.Contains(doc.Markdown, "- **By**: F. Scott Fitzgerald") {
		t.Fatalf("expected by_statement author fallback, got: %+v", doc)
	}
	doc, ok = twin.Format(`{"title":"Fantastic Mr. Fox","contributions":["Tony Ross (Illustrator)"],"by_statement":"Roald Dahl","key":"/books/OL2M"}`)
	if !ok || doc == nil || doc.Author != "Roald Dahl" {
		t.Fatalf("expected by_statement to win over an illustrator-first contributions list, got: %+v", doc)
	}
	doc, ok = twin.Format(`{"title":"Matilda","contributions":["Quentin Blake (Illustrator)"],"key":"/books/OL4M"}`)
	if !ok || doc == nil || doc.Author != "Quentin Blake (Illustrator)" {
		t.Fatalf("expected contributions as the fallback author source, got: %+v", doc)
	}
	doc, ok = twin.Format(`{"title":"1984","key":"/books/OL3M"}`)
	if !ok || doc == nil || doc.Author != "" || strings.Contains(doc.Markdown, "**By**") {
		t.Fatalf("expected no author when neither field is present, got: %+v", doc)
	}
}

func TestFederalRegisterURLDateMismatchWarning(t *testing.T) {
	payload := `{"title":"Agency Forms Undergoing Paperwork Reduction Act Review","document_number":"2024-09145","type":"Notice","publication_date":"2024-04-29"}`
	mismatch, ok := ResolveDeclarativeTwin("https://www.federalregister.gov/documents/2024/05/07/2024-09145/non-compete-clause-rule")
	if !ok {
		t.Fatal("expected federal-register twin")
	}
	doc, ok := mismatch.Format(payload)
	if !ok || doc == nil || !strings.Contains(doc.Markdown, "- **Warning**: Publication date 2024-04-29 does not match the URL date 2024-05-07") {
		t.Fatalf("expected URL date mismatch warning, got: %+v", doc)
	}

	match, ok := ResolveDeclarativeTwin("https://www.federalregister.gov/documents/2024/04/29/2024-09145/agency-forms")
	if !ok {
		t.Fatal("expected federal-register twin")
	}
	doc, ok = match.Format(payload)
	if !ok || doc == nil || strings.Contains(doc.Markdown, "**Warning**") {
		t.Fatalf("expected no warning when publication date matches the URL, got: %+v", doc)
	}

	doc, ok = mismatch.Format(`{"title":"Undated","document_number":"2024-09145"}`)
	if !ok || doc == nil || strings.Contains(doc.Markdown, "**Warning**") {
		t.Fatalf("expected no warning without a publication date, got: %+v", doc)
	}
}

func TestIcimsGenericHeadingAndCompanyFallback(t *testing.T) {
	for _, generic := range []string{"Job Details", "Careers", "Search Jobs", " careers home ", "Job Search Results", "Jobs:"} {
		if !isIcimsGenericHeadingDeclHTML(generic) {
			t.Errorf("expected %q to be treated as a generic iCIMS heading", generic)
		}
	}
	for _, specific := range []string{"Senior FPGA Engineer", "Acme Corp", "Careers at Acme", "Job Details Analyst"} {
		if isIcimsGenericHeadingDeclHTML(specific) {
			t.Errorf("expected %q NOT to be treated as a generic iCIMS heading", specific)
		}
	}

	// Single job without JSON-LD: generic h1.iCIMS_Header skipped, real h1 used; company from og:site_name.
	single := `<!doctype html><html><head><meta property="og:site_name" content="Acme Robotics"><title>Job Details | Careers</title></head><body>
		<h1 class="iCIMS_Header">Job Details</h1><h1>Senior Robotics Engineer</h1>
		<div class="iCIMS_JobContent"><p>Build robots.</p></div></body></html>`
	doc, ok := ApplyDeclarativeHTMLExtractor(single, "https://careers-acme.icims.com/jobs/4242/senior-robotics-engineer/job", "", nil)
	if !ok || doc == nil || doc.Title != "Senior Robotics Engineer @ Acme Robotics" {
		t.Fatalf("expected generic heading skipped and og:site_name company, got: %+v", doc)
	}

	// Company from "<...> at <Company>" in <title> when og:site_name is absent.
	titled := `<!doctype html><html><head><title>Senior Robotics Engineer at Initech Systems | iCIMS</title></head><body>
		<h1 class="iCIMS_Header">Senior Robotics Engineer</h1><div class="iCIMS_JobContent"><p>Build robots.</p></div></body></html>`
	doc, ok = ApplyDeclarativeHTMLExtractor(titled, "https://careers-initech.icims.com/jobs/77/senior-robotics-engineer/job", "", nil)
	if !ok || doc == nil || doc.Title != "Senior Robotics Engineer @ Initech Systems" {
		t.Fatalf("expected company from title 'at' segment, got: %+v", doc)
	}

	// No usable metadata: subdomain slug remains the final fallback.
	bare := `<!doctype html><html><head><title>Careers</title></head><body><h1>Data Analyst</h1><div class="iCIMS_JobContent"><p>Analyze.</p></div></body></html>`
	doc, ok = ApplyDeclarativeHTMLExtractor(bare, "https://careers-globex.icims.com/jobs/88/data-analyst/job", "", nil)
	if !ok || doc == nil || doc.Title != "Data Analyst @ careers-globex" {
		t.Fatalf("expected subdomain slug company fallback, got: %+v", doc)
	}

	// Only generic headings and no JSON-LD title: no job title can be derived.
	onlyGeneric := `<!doctype html><html><body><h1 class="iCIMS_Header">Job Details</h1><div class="iCIMS_JobContent"><p>Text.</p></div></body></html>`
	if doc, ok = ApplyDeclarativeHTMLExtractor(onlyGeneric, "https://careers-globex.icims.com/jobs/89/x/job", "", nil); ok && doc != nil && strings.HasPrefix(doc.Title, "Job Details") {
		t.Fatalf("expected generic heading never used as job title, got: %+v", doc)
	}

	// Portal listing with a generic header: company label from og:site_name, not "Search Jobs".
	board := `<!doctype html><html><head><meta property="og:site_name" content="Acme Robotics"></head><body><h1 class="iCIMS_Header">Search Jobs</h1>
		<div class="iCIMS_JobsTable"><div class="row"><a class="iCIMS_Anchor" href="/jobs/4242/senior-robotics-engineer/job"><h3>Senior Robotics Engineer</h3></a></div></div></body></html>`
	doc, ok = ApplyDeclarativeHTMLExtractor(board, "https://careers-acme.icims.com/jobs/search?in_iframe=1", "", nil)
	if !ok || doc == nil || !strings.HasPrefix(doc.Title, "Acme Robotics — iCIMS Career Portal") {
		t.Fatalf("expected og:site_name portal company label, got: %+v", doc)
	}
	if len(doc.Records) != 1 || doc.Records[0]["company"] != "Acme Robotics" {
		t.Fatalf("expected record company Acme Robotics, got: %+v", doc.Records)
	}
}

func TestSelectPreferWhereElement(t *testing.T) {
	arr := []any{
		map[string]any{"rank": "normal", "v": "a"},
		map[string]any{"rank": "deprecated", "v": "b"},
		map[string]any{"rank": "normal", "v": "c"},
		map[string]any{"rank": "preferred", "v": "d"},
		map[string]any{"rank": "normal", "v": "e"},
	}
	pick := func(arr []any, pw *DeclarativePreferWhereSpec) string {
		el := selectPreferWhereElement(arr, pw)
		if el == nil {
			return ""
		}
		return jsonScalarToString(getByDotPath(el, "v"))
	}
	if got := pick(arr, &DeclarativePreferWhereSpec{Path: "rank", Equals: "preferred"}); got != "d" {
		t.Fatalf("preferred match: got %q", got)
	}
	noPref := []any{arr[0], arr[1], arr[2], arr[4]}
	if got := pick(noPref, &DeclarativePreferWhereSpec{Path: "rank", Equals: "preferred", FallbackEquals: "normal"}); got != "a" {
		t.Fatalf("first normal fallback: got %q", got)
	}
	if got := pick(noPref, &DeclarativePreferWhereSpec{Path: "rank", Equals: "preferred", FallbackEquals: "normal", FallbackLast: true}); got != "e" {
		t.Fatalf("last normal fallback: got %q", got)
	}
	if got := pick(noPref, &DeclarativePreferWhereSpec{Path: "rank", Equals: "preferred"}); got != "" {
		t.Fatalf("no fallback configured should resolve empty, got %q", got)
	}
	if got := pick([]any{arr[1], "scalar", nil}, &DeclarativePreferWhereSpec{Path: "rank", Equals: "preferred", FallbackEquals: "normal"}); got != "" {
		t.Fatalf("deprecated-only should resolve empty, got %q", got)
	}

	// Through formatExtractedJSONValue: subField resolves on the picked element, then format applies.
	spec := DeclarativeVarSpec{
		PreferWhere: &DeclarativePreferWhereSpec{Path: "rank", Equals: "preferred"},
		SubField:    "amount",
		Format:      "int_comma",
	}
	raw := []any{map[string]any{"rank": "normal", "amount": "+1200"}, map[string]any{"rank": "preferred", "amount": "+3755251"}}
	if got := formatExtractedJSONValue(raw, spec, ""); got != "3,755,251" {
		t.Fatalf("formatExtractedJSONValue preferWhere: got %q", got)
	}
	if got := formatExtractedJSONValue(map[string]any{"rank": "preferred"}, spec, ""); got != "" {
		t.Fatalf("non-array input should resolve empty, got %q", got)
	}
}

func TestWikidataPreferredRankFallbacks(t *testing.T) {
	twin, ok := ResolveDeclarativeTwin("https://www.wikidata.org/wiki/Q1")
	if !ok {
		t.Fatal("expected wikidata twin")
	}
	payload := `{"entities":{"Q1":{"id":"Q1","labels":{"en":{"language":"en","value":"Sample Town"}},"claims":{
		"P1082":[{"mainsnak":{"datavalue":{"value":{"amount":"+900","unit":"1"}}},"rank":"normal"},{"mainsnak":{"datavalue":{"value":{"amount":"+5000","unit":"1"}}},"rank":"deprecated"},{"mainsnak":{"datavalue":{"value":{"amount":"+12345","unit":"1"}}},"rank":"normal"}],
		"P569":[{"mainsnak":{"datavalue":{"value":{"time":"+1950-01-01T00:00:00Z"}}},"rank":"normal"},{"mainsnak":{"datavalue":{"value":{"time":"+1952-03-11T00:00:00Z"}}},"rank":"preferred"}],
		"P570":[{"mainsnak":{"datavalue":{"value":{"time":"+2000-01-01T00:00:00Z"}}},"rank":"deprecated"}]
	}}}}`
	doc, ok := twin.Format(payload)
	if !ok || doc == nil {
		t.Fatal("expected wikidata doc to format")
	}
	for _, want := range []string{"- **Population**: 12,345", "- **Date of Birth**: 1952-03-11"} {
		if !strings.Contains(doc.Markdown, want) {
			t.Fatalf("expected %q, got:\n%s", want, doc.Markdown)
		}
	}
	for _, absent := range []string{"5,000", "1950-01-01", "Date of Death"} {
		if strings.Contains(doc.Markdown, absent) {
			t.Fatalf("expected %q to be omitted, got:\n%s", absent, doc.Markdown)
		}
	}
}
