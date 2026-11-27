package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestM2AllTwelveManifestsRegisteredAndValid(t *testing.T) {
	rawCompiled, err := embeddedManifestFS.ReadFile("manifests/compiled.json")
	if err != nil {
		t.Fatalf("ReadFile(manifests/compiled.json): %v", err)
	}
	var bundle compiledManifestBundle
	dec := json.NewDecoder(bytes.NewReader(rawCompiled))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		t.Fatalf("Decode compiled.json: %v", err)
	}
	if err := ValidateDeclarativeManifests(bundle.Manifests); err != nil {
		t.Fatalf("ValidateDeclarativeManifests failed: %v", err)
	}

	expectedIDs := []string{
		"zendesk-hc",
		"federal-register",
		"cpsc-recalls",
		"us-cfr-govinfo",
		"eur-lex",
		"terraform-registry",
		"docker-hub",
		"maven-central",
		"nuget-gallery",
		"homebrew-formulae",
		"osv-ghsa",
		"wikidata-openlibrary",
	}
	byID := make(map[string]DeclarativeAdapterManifest, len(bundle.Manifests))
	for _, m := range bundle.Manifests {
		byID[m.ID] = m
	}
	for _, id := range expectedIDs {
		m, ok := byID[id]
		if !ok {
			t.Fatalf("missing M2 manifest %q in compiled.json", id)
		}
		for i, r := range m.Routes {
			if r.Twin.ID != "" && r.Twin.ID != m.ID {
				t.Fatalf("manifest %q route %d sets custom twin.id %q (must omit or equal manifest.id for redirect trust)", id, i, r.Twin.ID)
			}
			if r.Twin.MaxBytes <= 0 || r.Twin.MaxBytes > 4*1024*1024 {
				t.Fatalf("manifest %q route %d invalid maxBytes %d", id, i, r.Twin.MaxBytes)
			}
		}
	}
}

func TestM2Tier1AdaptersResolutionAndFormatting(t *testing.T) {
	// 1. zendesk-hc: article, section, category + draft fail-open
	zdArt, ok := ResolveDeclarativeTwin("https://acme.zendesk.com/hc/EN-US/articles/4408886858138-Getting-Started")
	if !ok || zdArt.ID != "zendesk-hc" {
		t.Fatalf("expected zendesk-hc article match, got ok=%v twin=%+v", ok, zdArt)
	}
	if zdArt.FetchURL != "https://acme.zendesk.com/api/v2/help_center/en-us/articles/4408886858138.json?include=sections,categories" {
		t.Fatalf("unexpected zendesk article fetchUrl: %s", zdArt.FetchURL)
	}
	zdPayload := `{"article":{"title":"<b>Getting Started</b>","body":"<p>Install via <a href=\"https://acme.zendesk.com/hc/article_attachments/99/manual.pdf\">Manual PDF</a>.</p>","updated_at":"2026-02-01T12:00:00Z","html_url":"https://acme.zendesk.com/hc/en-us/articles/4408886858138","label_names":["setup","guide"],"draft":false},"sections":[{"name":"Setup","html_url":"https://acme.zendesk.com/hc/en-us/sections/10"}],"categories":[{"name":"Docs","html_url":"https://acme.zendesk.com/hc/en-us/categories/1"}]}`
	zdDoc, ok := zdArt.Format(zdPayload)
	if !ok || zdDoc == nil {
		t.Fatalf("expected zendesk article Format to succeed")
	}
	if zdDoc.Title != "Getting Started" || !strings.Contains(zdDoc.Markdown, "Docs › Setup") || !strings.Contains(zdDoc.Markdown, "manual.pdf") {
		t.Fatalf("unexpected zendesk article output: title=%q md=%s", zdDoc.Title, zdDoc.Markdown)
	}
	zdDraftPayload := strings.Replace(zdPayload, `"draft":false`, `"draft":true`, 1)
	if _, ok := zdArt.Format(zdDraftPayload); ok {
		t.Fatalf("expected draft:true zendesk article to fail open")
	}

	zdSec, ok := ResolveDeclarativeTwin("https://acme.zendesk.com/hc/en-us/sections/10-Setup")
	if !ok || !strings.Contains(zdSec.FetchURL, "/sections/10/articles.json") {
		t.Fatalf("expected zendesk section match, got ok=%v twin=%+v", ok, zdSec)
	}
	zdSecDoc, ok := zdSec.Format(`{"sections":[{"name":"Setup"}],"categories":[{"name":"Docs"}],"articles":[{"title":"Install","html_url":"https://acme.zendesk.com/hc/en-us/articles/440","updated_at":"2026-02-01T00:00:00Z","label_names":["setup"]}]}`)
	if !ok || !strings.Contains(zdSecDoc.Markdown, "[Install](https://acme.zendesk.com/hc/en-us/articles/440)") {
		t.Fatalf("unexpected zendesk section markdown: %+v", zdSecDoc)
	}

	zdCat, ok := ResolveDeclarativeTwin("https://acme.zendesk.com/hc/en-us/categories/1-Docs")
	if !ok || !strings.Contains(zdCat.FetchURL, "/categories/1/sections.json") {
		t.Fatalf("expected zendesk category match, got ok=%v twin=%+v", ok, zdCat)
	}
	zdCatDoc, ok := zdCat.Format(`{"categories":[{"name":"Docs"}],"sections":[{"name":"Setup","html_url":"https://acme.zendesk.com/hc/en-us/sections/10","description":"Start here","updated_at":"2026-02-01T00:00:00Z"}]}`)
	if !ok || !strings.Contains(zdCatDoc.Markdown, "[Setup](https://acme.zendesk.com/hc/en-us/sections/10)") {
		t.Fatalf("unexpected zendesk category markdown: %+v", zdCatDoc)
	}

	// 2. federal-register: numeric subFieldsJoin (title: 16, part: 1500) + /documents/current exclusion
	if _, ok := ResolveDeclarativeTwin("https://www.federalregister.gov/documents/current"); ok {
		t.Fatalf("expected disallowed /documents/current NOT to match federal-register")
	}
	frTwin, ok := ResolveDeclarativeTwin("https://www.federalregister.gov/documents/2024/05/07/2024-09145/non-compete-clause-rule")
	if !ok || frTwin.FetchURL != "https://www.federalregister.gov/api/v1/documents/2024-09145.json" {
		t.Fatalf("unexpected federal-register match: ok=%v twin=%+v", ok, frTwin)
	}
	frPayload := `{"title":"Non-Compete Clause Rule","document_number":"2024-09145","type":"Rule","citation":"89 FR 38342","publication_date":"2024-05-07","effective_on":"2024-09-04","agencies":[{"name":"Federal Trade Commission"}],"cfr_references":[{"title":16,"part":910,"chapter":"I"},{"title":16,"part":1500}],"abstract":"Final rule banning non-compete clauses.","pdf_url":"https://www.govinfo.gov/content/pkg/FR-2024-05-07/pdf/2024-09145.pdf","html_url":"https://www.federalregister.gov/documents/2024/05/07/2024-09145/non-compete-clause-rule"}`
	frDoc, ok := frTwin.Format(frPayload)
	if !ok || !strings.Contains(frDoc.Markdown, "16 CFR Part 910; 16 CFR Part 1500") {
		t.Fatalf("expected numeric subFieldsJoin '16 CFR Part 910; 16 CFR Part 1500' in federal-register markdown, got: %+v", frDoc)
	}

	// 3. cpsc-recalls: bounded saferproducts + unfiltered rejection + cpsc.gov DOM htmlRoutes
	if _, ok := ResolveDeclarativeTwin("https://www.saferproducts.gov/RestWebServices/Recall?format=json"); ok {
		t.Fatalf("expected unfiltered saferproducts.gov URL without RecallNumber NOT to match twin")
	}
	cpscTwin, ok := ResolveDeclarativeTwin("https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=24-123")
	if !ok || cpscTwin.FetchURL != "https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123" {
		t.Fatalf("unexpected cpsc-recalls twin: ok=%v twin=%+v", ok, cpscTwin)
	}
	cpscDoc, ok := cpscTwin.Format(`[{"RecallNumber":"24123","Title":"Acme Bike Helmet Recall","RecallDate":"2024-03-14","Description":"Chin strap can fail.","URL":"https://www.cpsc.gov/Recalls/2024/Acme-Helmet","Products":[{"Name":"Helmet","Model":"H-1","NumberOfUnits":"5,000","Type":"Sports"}],"Hazards":[{"Name":"Impact hazard"}],"Remedies":[{"Name":"Refund"}]}]`)
	if !ok || !strings.Contains(cpscDoc.Markdown, "24123") || !strings.Contains(cpscDoc.Markdown, "Impact hazard") {
		t.Fatalf("unexpected cpsc-recalls markdown: %+v", cpscDoc)
	}
	cpscHTML := `<!doctype html><html><head><title>Acme Helmet Recall</title></head><body><main><h1>Acme Bike Helmet Recall</h1><p>Recall Number: 24-123</p><p>Consumers should stop using the helmet immediately.</p></main></body></html>`
	cpscDom, ok := ApplyDeclarativeHTMLExtractor(cpscHTML, "https://www.cpsc.gov/recalls/2024/acme-helmet", "", nil)
	if !ok || cpscDom.ExtractorID != "cpsc-recalls" || !strings.Contains(cpscDom.Markdown, "24-123") {
		t.Fatalf("expected cpsc-recalls DOM htmlRoutes match on lowercase /recalls/, got ok=%v res=%+v", ok, cpscDom)
	}

	// 4. us-cfr-govinfo: textMode html_document + summary JSON
	govGran, ok := ResolveDeclarativeTwin("https://www.govinfo.gov/app/details/CFR-2023-title16-vol2/CFR-2023-title16-vol2-part1500")
	if !ok || govGran.FetchURL != "https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/html/CFR-2023-title16-vol2-part1500.htm" {
		t.Fatalf("unexpected govinfo granule match: ok=%v twin=%+v", ok, govGran)
	}
	govDoc, ok := govGran.Format(`<!doctype html><html><head><title>16 CFR Part 1500</title></head><body><main><h1>Part 1500 Hazardous Substances</h1><p>Regulatory text for part 1500.</p></main></body></html>`)
	if !ok || !strings.Contains(govDoc.Markdown, "Hazardous Substances") {
		t.Fatalf("expected textMode html_document to extract govinfo HTML, got ok=%v doc=%+v", ok, govDoc)
	}
	govSum, ok := ResolveDeclarativeTwin("https://www.govinfo.gov/wssearch/getContentDetail?packageId=CFR-2023-title16-vol2")
	if !ok {
		t.Fatalf("expected govinfo wssearch summary match")
	}
	govSumDoc, ok := govSum.Format(`{"title":"Title 16 Commercial Practices","packageId":"CFR-2023-title16-vol2","collectionName":"Code of Federal Regulations","dateIssued":"2023-01-01","download":{"pdfLink":"https://www.govinfo.gov/content/pkg/CFR-2023-title16-vol2/pdf/CFR-2023-title16-vol2.pdf"}}`)
	if !ok || !strings.Contains(govSumDoc.Markdown, "CFR-2023-title16-vol2.pdf") {
		t.Fatalf("unexpected govinfo summary markdown: %+v", govSumDoc)
	}

	// 5. eur-lex: textMode html_document + never /TXT/DOC/
	if _, ok := ResolveDeclarativeTwin("https://eur-lex.europa.eu/legal-content/EN/TXT/DOC/?uri=CELEX:32016R0679"); ok {
		t.Fatalf("expected /TXT/DOC/ NOT to match eur-lex")
	}
	if _, ok := ResolveDeclarativeTwin("https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679"); ok {
		t.Fatalf("expected /TXT/HTML/ NOT to match eur-lex twin route")
	}
	eurTwin, ok := ResolveDeclarativeTwin("https://eur-lex.europa.eu/legal-content/en/TXT/?uri=CELEX:32016R0679")
	if !ok || eurTwin.FetchURL != "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX%3A32016R0679" {
		t.Fatalf("unexpected eur-lex match: ok=%v twin=%+v", ok, eurTwin)
	}
	eurDoc, ok := eurTwin.Format(`<!doctype html><html><head><title>GDPR Regulation (EU) 2016/679</title></head><body><main><h1>Article 1 Subject-matter</h1><p>This Regulation lays down rules relating to the protection of natural persons.</p></main></body></html>`)
	if !ok || !strings.Contains(eurDoc.Markdown, "protection of natural persons") {
		t.Fatalf("expected eur-lex html_document extraction, got ok=%v doc=%+v", ok, eurDoc)
	}
}

func TestM2Tier3AndTier4AdaptersResolutionAndFormatting(t *testing.T) {
	// 6. terraform-registry
	tfMod, ok := ResolveDeclarativeTwin("https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/5.1.0")
	if !ok || tfMod.FetchURL != "https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/5.1.0" {
		t.Fatalf("unexpected terraform module match: ok=%v twin=%+v", ok, tfMod)
	}
	tfDoc, ok := tfMod.Format(`{"namespace":"terraform-aws-modules","name":"vpc","provider":"aws","version":"5.1.0","verified":true,"downloads":1234567,"description":"AWS VPC Terraform module","root":{"readme":"# VPC Module\n\nCreates a VPC.","inputs":[{"name":"cidr","type":"string","required":true,"description":"VPC CIDR"}]}}`)
	if !ok || !strings.Contains(tfDoc.Markdown, "1,234,567") || !strings.Contains(tfDoc.Markdown, "`cidr`") {
		t.Fatalf("unexpected terraform markdown: %+v", tfDoc)
	}

	// 7. docker-hub: _/<repo> -> library/<repo> + /tags
	dhRoot, ok := ResolveDeclarativeTwin("https://hub.docker.com/_/alpine")
	if !ok || dhRoot.FetchURL != "https://hub.docker.com/v2/repositories/library/alpine/" {
		t.Fatalf("unexpected docker-hub official repo match: ok=%v twin=%+v", ok, dhRoot)
	}
	dhRootDoc, ok := dhRoot.Format(`{"namespace":"library","name":"alpine","description":"Minimal Docker image","pull_count":9000000,"star_count":10500,"full_description":"# Alpine\n\nLightweight Linux."}`)
	if !ok || !strings.Contains(dhRootDoc.Markdown, "9,000,000") || !strings.Contains(dhRootDoc.Markdown, "Lightweight Linux.") {
		t.Fatalf("unexpected docker-hub root markdown: %+v", dhRootDoc)
	}
	dhTags, ok := ResolveDeclarativeTwin("https://hub.docker.com/_/alpine/tags")
	if !ok || dhTags.FetchURL != "https://hub.docker.com/v2/repositories/library/alpine/tags?page_size=25" {
		t.Fatalf("unexpected docker-hub tags match: ok=%v twin=%+v", ok, dhTags)
	}
	dhTagsDoc, ok := dhTags.Format(`{"count":500,"results":[{"name":"3.20","full_size":3670016,"last_updated":"2026-01-01T00:00:00Z","images":[{"os":"linux","architecture":"amd64"},{"os":"linux","architecture":"arm64"}]}]}`)
	if !ok || !strings.Contains(dhTagsDoc.Markdown, "`3.20`") || !strings.Contains(dhTagsDoc.Markdown, "linux/amd64") {
		t.Fatalf("unexpected docker-hub tags markdown: %+v", dhTagsDoc)
	}

	// 8. maven-central: epoch_ms_date + Solr injection blocking
	if _, ok := ResolveDeclarativeTwin("https://central.sonatype.com/artifact/com.foo%20OR%20*/bar"); ok {
		t.Fatalf("expected Solr query injection attempt NOT to match maven-central")
	}
	mvTwin, ok := ResolveDeclarativeTwin("https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/2.18.2")
	if !ok || mvTwin.FetchURL != "https://search.maven.org/solrsearch/select?q=g:com.fasterxml.jackson.core+AND+a:jackson-databind+AND+v:2.18.2&core=gav&rows=20&wt=json" {
		t.Fatalf("unexpected maven-central match: ok=%v twin=%+v", ok, mvTwin)
	}
	mvDoc, ok := mvTwin.Format(`{"response":{"numFound":1,"docs":[{"id":"com.fasterxml.jackson.core:jackson-databind:2.18.2","g":"com.fasterxml.jackson.core","a":"jackson-databind","v":"2.18.2","p":"jar","timestamp":1744651522422,"ec":[".jar","-sources.jar"]}]}}`)
	if !ok || !strings.Contains(mvDoc.Markdown, "2025-04-14") || !strings.Contains(mvDoc.Markdown, "com.fasterxml.jackson.core:jackson-databind:2.18.2") {
		t.Fatalf("unexpected maven-central markdown (check epoch_ms_date): %+v", mvDoc)
	}

	// 9. nuget-gallery: inlined multi-page & un-inlined CatalogPage stubs
	ngTwin, ok := ResolveDeclarativeTwin("https://www.nuget.org/packages/Newtonsoft.Json")
	if !ok || ngTwin.FetchURL != "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json" {
		t.Fatalf("unexpected nuget-gallery match: ok=%v twin=%+v", ok, ngTwin)
	}
	ngInlined := `{"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page/1.json","count":1,"lower":"12.0.1","upper":"12.0.1","items":[{"catalogEntry":{"id":"Newtonsoft.Json","version":"12.0.1","description":"Old","listed":true}}]},{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/page/2.json","count":1,"lower":"13.0.3","upper":"13.0.3","items":[{"catalogEntry":{"id":"Newtonsoft.Json","version":"13.0.3","description":"Popular high-performance JSON framework for .NET","authors":"James Newton-King","licenseExpression":"MIT","projectUrl":"https://www.newtonsoft.com/json","published":"2023-03-08T07:42:00Z","listed":true,"dependencyGroups":[{"targetFramework":"net6.0","dependencies":[{"id":"System.Runtime","range":"[4.3.0, )"}]}]}}]}]}`
	ngInlinedDoc, ok := ngTwin.Format(ngInlined)
	if !ok || !strings.Contains(ngInlinedDoc.Title, "13.0.3") || !strings.Contains(ngInlinedDoc.Markdown, "James Newton-King") || !strings.Contains(ngInlinedDoc.Markdown, "System.Runtime") {
		t.Fatalf("unexpected nuget inlined output: %+v", ngInlinedDoc)
	}
	ngUninlined := `{"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/0.1.0/2.0.0.json","@type":"catalog:CatalogPage","count":64,"lower":"0.1.0","upper":"2.0.0"},{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/2.0.1/4.2.0.json","@type":"catalog:CatalogPage","count":64,"lower":"2.0.1","upper":"4.2.0"}]}`
	ngUninlinedDoc, ok := ngTwin.Format(ngUninlined)
	if !ok || !strings.Contains(ngUninlinedDoc.Markdown, "4.2.0") || !strings.Contains(ngUninlinedDoc.Markdown, "Registration Pages") {
		t.Fatalf("unexpected nuget un-inlined output: %+v", ngUninlinedDoc)
	}

	// 10. homebrew-formulae: brew_id (python@3.12, gtk+3), deprecated notice, analytics, .json exclusion
	if _, ok := ResolveDeclarativeTwin("https://formulae.brew.sh/formula/jq.json"); ok {
		t.Fatalf("expected .json suffix NOT to match homebrew-formulae")
	}
	hbPy, ok := ResolveDeclarativeTwin("https://formulae.brew.sh/formula/python@3.12")
	if !ok || hbPy.FetchURL != "https://formulae.brew.sh/api/formula/python@3.12.json" {
		t.Fatalf("expected brew_id to accept python@3.12, got ok=%v twin=%+v", ok, hbPy)
	}
	if hbGtk, ok := ResolveDeclarativeTwin("https://formulae.brew.sh/formula/gtk+3"); !ok || hbGtk.FetchURL != "https://formulae.brew.sh/api/formula/gtk+3.json" {
		t.Fatalf("expected brew_id to accept gtk+3, got ok=%v twin=%+v", ok, hbGtk)
	}
	hbDoc, ok := hbPy.Format(`{"name":"python@3.12","full_name":"python@3.12","desc":"Interpreted, interactive, object-oriented programming language","versions":{"stable":"3.12.9"},"license":"Python-2.0","homepage":"https://www.python.org/","deprecated":true,"deprecation_date":"2026-10-01","deprecation_reason":"versioned_formula","deprecation_replacement_formula":"python@3.13","analytics":{"install":{"30d":{"python@3.12":42100}}}}`)
	if !ok || !strings.Contains(hbDoc.Markdown, "Deprecated") || !strings.Contains(hbDoc.Markdown, "42,100") || !strings.Contains(hbDoc.Markdown, "python@3.13") {
		t.Fatalf("unexpected homebrew-formulae markdown: %+v", hbDoc)
	}

	// 11. osv-ghsa: GHSA uppercase -> lowercase suffix + oversized versions[] slicing
	ghsaTwin, ok := ResolveDeclarativeTwin("https://github.com/advisories/GHSA-JFH8-C2JP-5V3Q")
	if !ok || ghsaTwin.FetchURL != "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q" {
		t.Fatalf("expected lowercase GHSA suffix for api.osv.dev, got ok=%v twin=%+v", ok, ghsaTwin)
	}
	var vers []string
	for i := 0; i < 40; i++ {
		vers = append(vers, fmt.Sprintf(`"1.0.%d"`, i))
	}
	osvPayload := fmt.Sprintf(`{"id":"GHSA-jfh8-c2jp-5v3q","summary":"Log4j2 JNDI RCE","details":"Remote code execution via JNDI.","aliases":["CVE-2021-44228"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],"published":"2021-12-10T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"versions":[%s]}],"references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}]}`, strings.Join(vers, ","))
	osvDoc, ok := ghsaTwin.Format(osvPayload)
	if !ok || !strings.Contains(osvDoc.Markdown, "CVE-2021-44228") || !strings.Contains(osvDoc.Markdown, "1.0.11") || strings.Contains(osvDoc.Markdown, "1.0.39") {
		t.Fatalf("expected osv-ghsa to slice versions[] to 12, got: %+v", osvDoc)
	}

	// 12. wikidata-openlibrary: Q42 labels.mul fallback + openlibrary /isbn/*.json (never /api/*)
	wdTwin, ok := ResolveDeclarativeTwin("https://www.wikidata.org/wiki/Q42")
	if !ok || wdTwin.FetchURL != "https://www.wikidata.org/wiki/Special:EntityData/Q42.json" {
		t.Fatalf("unexpected wikidata match: ok=%v twin=%+v", ok, wdTwin)
	}
	wdMulPayload := `{"entities":{"Q42":{"id":"Q42","labels":{"mul":{"language":"mul","value":"Douglas Adams"}},"descriptions":{"en":{"language":"en","value":"English writer and humorist"}},"claims":{"P31":[],"P106":[]},"sitelinks":{"enwiki":{"site":"enwiki","title":"Douglas Adams"}}}}}`
	wdDoc, ok := wdTwin.Format(wdMulPayload)
	if !ok || wdDoc.Title != "Douglas Adams (Q42)" || !strings.Contains(wdDoc.Markdown, "English writer and humorist") || !strings.Contains(wdDoc.Markdown, "https://en.wikipedia.org/wiki/Douglas_Adams") {
		t.Fatalf("expected Q42 labels.mul fallback to produce 'Douglas Adams (Q42)', got ok=%v doc=%+v", ok, wdDoc)
	}
	olTwin, ok := ResolveDeclarativeTwin("https://openlibrary.org/isbn/9780140328721")
	if !ok || olTwin.FetchURL != "https://openlibrary.org/isbn/9780140328721.json" || strings.Contains(olTwin.FetchURL, "/api/") {
		t.Fatalf("unexpected openlibrary match: ok=%v twin=%+v", ok, olTwin)
	}
	olDoc, ok := olTwin.Format(`{"title":"Fantastic Mr Fox","isbn_13":["9780140328721"],"publishers":["Puffin"],"publish_date":"1988","number_of_pages":96,"key":"/books/OL7353617M"}`)
	if !ok || olDoc.Title != "Fantastic Mr Fox" || !strings.Contains(olDoc.Markdown, "9780140328721") {
		t.Fatalf("unexpected openlibrary markdown: %+v", olDoc)
	}
}

func TestM2RegressionFixesChallengerRound1(t *testing.T) {
	// 1. cpsc-recalls: reject dashes-only, single-alnum-after-strip, underscore, and duplicate/mixed-case RecallNumber
	for _, badCpsc := range []string{
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=--",
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=---",
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=-1",
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=2-",
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=24_123",
		"https://www.saferproducts.gov/RestWebServices/Recall?recallnumber=24123&RecallNumber=bad!",
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=&recallnumber=24123",
		"https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=24123&ReCaLlNuMbEr=bad!",
	} {
		if twin, ok := ResolveDeclarativeTwin(badCpsc); ok {
			t.Fatalf("expected invalid cpsc-recalls URL %q NOT to match, got %+v", badCpsc, twin)
		}
	}
	if twin, ok := ResolveDeclarativeTwin("https://www.saferproducts.gov/RestWebServices/Recall?recallnumber=24-123"); !ok || twin.FetchURL != "https://www.saferproducts.gov/RestWebServices/Recall?format=json&RecallNumber=24123" {
		t.Fatalf("expected lowercase recallnumber=24-123 to match and strip dashes, got ok=%v twin=%+v", ok, twin)
	}

	// 2. zendesk-hc: html_to_md must strip <script>/<style>/<noscript> before fallback instead of leaking JS/CSS
	zdArt, ok := ResolveDeclarativeTwin("https://acme.zendesk.com/hc/en-us/articles/440-Manual")
	if !ok {
		t.Fatalf("expected zendesk-hc article match")
	}
	for _, body := range []string{
		"<script>alert(1)</script><style>body{}</style>",
		"<style>.secret{display:none}</style>",
		"<noscript>Enable JavaScript</noscript>",
	} {
		payload := fmt.Sprintf(`{"article":{"title":"Test","body":%q,"draft":false}}`, body)
		if doc, ok := zdArt.Format(payload); ok {
			t.Fatalf("expected script/style/noscript-only zendesk body %q to fail open, got doc=%+v", body, doc)
		}
	}
	if doc, ok := zdArt.Format(`{"article":{"title":"Inline","body":"<b>Hello</b>","draft":false}}`); !ok || !strings.Contains(doc.Markdown, "Hello") {
		t.Fatalf("expected inline HTML snippet <b>Hello</b> to remain supported, got ok=%v doc=%+v", ok, doc)
	}

	// 3. us-cfr-govinfo: /summary subpath must not match Route 1
	if twin, ok := ResolveDeclarativeTwin("https://www.govinfo.gov/app/details/CFR-2023-title16-vol2/CFR-2023-title16-vol2-part1500/summary"); ok {
		t.Fatalf("expected govinfo /summary subpath NOT to match Route 1, got %+v", twin)
	}

	// 4. terraform-registry: exactSegments + /latest alias
	for _, badTf := range []string{
		"https://registry.terraform.io/providers/hashicorp/random/docs",
		"https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/string",
		"https://registry.terraform.io/providers/hashicorp/random/3.8.1/docs/resources/string",
		"https://registry.terraform.io/providers/hashicorp/random/3.8.1%20OR%201",
		"https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/submodules/vpc-endpoints",
		"https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/examples/simple",
		"https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/5.1.0/submodules/vpc-endpoints",
		"https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/5.1.0/examples/simple",
	} {
		if twin, ok := ResolveDeclarativeTwin(badTf); ok {
			t.Fatalf("expected terraform-registry URL %q NOT to match, got %+v", badTf, twin)
		}
	}
	if twin, ok := ResolveDeclarativeTwin("https://registry.terraform.io/providers/hashicorp/random/latest"); !ok || twin.FetchURL != "https://registry.terraform.io/v1/providers/hashicorp/random" {
		t.Fatalf("expected terraform provider /latest to match unversioned v1 endpoint, got ok=%v twin=%+v", ok, twin)
	}
	if twin, ok := ResolveDeclarativeTwin("https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest"); !ok || twin.FetchURL != "https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws" {
		t.Fatalf("expected terraform module /latest to match unversioned v1 endpoint, got ok=%v twin=%+v", ok, twin)
	}

	// 5. maven-central: reject ':' / '%3A' Solr injection in v, plus reserved & extra segments on Route 2
	for _, badMv := range []string{
		"https://central.sonatype.com/artifact/com.foo/bar/1.0:OR:a:evil",
		"https://central.sonatype.com/artifact/com.foo/bar/1.0%3AOR%3Aa%3Aevil",
		"https://central.sonatype.com/artifact/com.foo/bar/1.0%20OR%20*",
		"https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/versions",
		"https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/overview",
		"https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/dependencies",
		"https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/dependents",
		"https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/jar",
	} {
		if twin, ok := ResolveDeclarativeTwin(badMv); ok {
			t.Fatalf("expected maven-central URL %q NOT to match, got %+v", badMv, twin)
		}
	}

	// 6. nuget-gallery: exactSegments on Routes 1 & 2 prevents ReportAbuse/ContactOwners/versions fallthrough
	for _, badNg := range []string{
		"https://www.nuget.org/packages/Newtonsoft.Json/ReportAbuse",
		"https://www.nuget.org/packages/Newtonsoft.Json/ContactOwners",
		"https://www.nuget.org/packages/Newtonsoft.Json/versions",
		"https://www.nuget.org/packages/Newtonsoft.Json/13.0.3/extra",
	} {
		if twin, ok := ResolveDeclarativeTwin(badNg); ok {
			t.Fatalf("expected nuget-gallery URL %q NOT to match, got %+v", badNg, twin)
		}
	}

	// 7. homebrew-formulae: fullName falls back to name when full_name is absent
	hbJq, ok := ResolveDeclarativeTwin("https://formulae.brew.sh/formula/jq")
	if !ok {
		t.Fatalf("expected homebrew-formulae match for jq")
	}
	hbJqDoc, ok := hbJq.Format(`{"name":"jq","desc":"Lightweight and flexible command-line JSON processor"}`)
	if !ok || hbJqDoc.Title != "jq (Homebrew Formula)" {
		t.Fatalf("expected fullName fallback to name -> 'jq (Homebrew Formula)', got ok=%v doc=%+v", ok, hbJqDoc)
	}
}
