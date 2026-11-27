package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestM4AllTenAdaptersRegisteredAndMatch(t *testing.T) {
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

	byID := make(map[string]DeclarativeAdapterManifest, len(bundle.Manifests))
	for _, m := range bundle.Manifests {
		byID[m.ID] = m
	}

	expectedM4 := []string{
		"ukg-paylocity-dover",
		"nhtsa-vpic-recalls",
		"fcc-id",
		"nfpa",
		"giant-liv-bikes",
		"bumm-de",
		"bicycleretailer",
		"cornell-lii",
		"sram-models",
		"tq-ebike",
	}
	for _, id := range expectedM4 {
		m, ok := byID[id]
		if !ok {
			t.Fatalf("missing M4 manifest %q in compiled.json", id)
		}
		if len(m.Domains) == 0 || (len(m.Routes) == 0 && len(m.HTMLRoutes) == 0) {
			t.Fatalf("manifest %q has empty domains or routes", id)
		}
	}
}

func TestIcimsSingleJobNoSS1AndExplicitZeroText(t *testing.T) {
	jobTwin, ok := ResolveDeclarativeTwin("https://careers-acme.icims.com/jobs/4123/firmware-engineer/job")
	if !ok || jobTwin == nil {
		t.Fatal("expected iCIMS single-job route to match")
	}
	if strings.Contains(jobTwin.FetchURL, "ss=1") {
		t.Fatalf("single-job iCIMS fetchUrl must NOT inject ss=1, got %q", jobTwin.FetchURL)
	}
	if !strings.Contains(jobTwin.FetchURL, "in_iframe=1") {
		t.Fatalf("single-job iCIMS fetchUrl must include in_iframe=1, got %q", jobTwin.FetchURL)
	}

	searchTwin, ok := ResolveDeclarativeTwin("https://careers-acme.icims.com/jobs/search?ss=1")
	if !ok || searchTwin == nil {
		t.Fatal("expected iCIMS search route to match")
	}
	if !strings.Contains(searchTwin.FetchURL, "ss=1") || !strings.Contains(searchTwin.FetchURL, "in_iframe=1") {
		t.Fatalf("search iCIMS fetchUrl expected ss=1 & in_iframe=1, got %q", searchTwin.FetchURL)
	}

	zeroHTML := `<!doctype html><html><head><title>Search | Acme</title></head><body><div class="iCIMS_ErrorMsg">No jobs match your search criteria.</div></body></html>`
	doc, ok := searchTwin.Format(zeroHTML)
	if !ok || doc == nil {
		t.Fatal("expected zero-result iCIMS search HTML to format cleanly")
	}
	if !strings.Contains(doc.Markdown, "No jobs match your search criteria") {
		t.Fatalf("expected iCIMS zero-result message retained in markdown, got:\n%s", doc.Markdown)
	}
	if strings.Contains(doc.Title, "(0 open roles)") {
		t.Fatalf("empty iCIMS title must omit (0 open roles), got %q", doc.Title)
	}
}

func TestM4UkgPaylocityDoverExtractors(t *testing.T) {
	// Paylocity JSON feed
	plcTwin, ok := ResolveDeclarativeTwin("https://recruiting.paylocity.com/recruiting/jobs/all/aa11bb22-cc33-44dd-ee55-ff6677889900")
	if !ok || plcTwin == nil || plcTwin.ID != "ukg-paylocity-dover" {
		t.Fatalf("expected ukg-paylocity-dover match for Paylocity board, got ok=%v twin=%+v", ok, plcTwin)
	}
	plcJSON := `{"Jobs":[{"JobId":901,"Title":"Staff Controls Engineer","LocationName":"Remote, US","PublishedDate":"2026-11-01T00:00:00Z","JobUrl":"https://recruiting.paylocity.com/Recruiting/Jobs/Details/901"}]}`
	plcDoc, ok := plcTwin.Format(plcJSON)
	if !ok || plcDoc == nil || len(plcDoc.Records) != 1 {
		t.Fatalf("expected 1 Paylocity record, got ok=%v doc=%+v", ok, plcDoc)
	}
	if plcDoc.Records[0]["title"] != "Staff Controls Engineer" {
		t.Fatalf("unexpected Paylocity record: %+v", plcDoc.Records[0])
	}

	// UKG Pro HTML with unquoted JS keys
	ukgHTML := `<!doctype html><html><head><title>Careers | UKG Pro</title></head><body><main><h1>Open Roles</h1><script>window.__PRELOADED_STATE__ = { opportunities: [{ Id: "ukg-1", Title: "Principal Firmware Engineer", Location: "Remote", Compensation: "$170,000 - $195,000", ApplyUrl: "https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/OpportunityDetail?opportunityId=ukg-1" }] };</script></main></body></html>`
	ukgDoc := ExtractHTMLDocumentFull(ukgHTML, FullExtractOptions{
		BaseURL:         "https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555/",
		OnlyMainContent: true,
	})
	if ukgDoc.ExtractorID != "ukg-paylocity-dover" || len(ukgDoc.Records) != 1 {
		t.Fatalf("expected ukg-paylocity-dover 1 record, got id=%q records=%+v", ukgDoc.ExtractorID, ukgDoc.Records)
	}
	if !strings.Contains(ukgDoc.Markdown, "Principal Firmware Engineer") {
		t.Fatalf("expected role in UKG markdown, got:\n%s", ukgDoc.Markdown)
	}

	// UKG JobBoardView disallowed path must NOT match HTML extractor
	ukgViewDoc := ExtractHTMLDocumentFull(ukgHTML, FullExtractOptions{
		BaseURL:         "https://recruiting.ultipro.com/UKG1001/JobBoardView/123",
		OnlyMainContent: true,
	})
	if ukgViewDoc.ExtractorID == "ukg-paylocity-dover" {
		t.Fatal("UKG JobBoardView must not extract as ukg-paylocity-dover")
	}

	// Dover SSR __NEXT_DATA__
	doverHTML := `<!doctype html><html><head><title>Acme Jobs | Dover</title></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"company":{"name":"Acme Robotics"},"jobs":[{"id":"dov-1","title":"Senior Battery Engineer","locations":[{"name":"Remote"}],"compensation_min":150000,"compensation_max":180000,"slug":"senior-battery-engineer"}]}}}</script></body></html>`
	doverDoc := ExtractHTMLDocumentFull(doverHTML, FullExtractOptions{
		BaseURL:         "https://app.dover.com/jobs/acme",
		OnlyMainContent: true,
	})
	if doverDoc.ExtractorID != "ukg-paylocity-dover" || len(doverDoc.Records) != 1 {
		t.Fatalf("expected dover_html 1 record, got id=%q records=%+v", doverDoc.ExtractorID, doverDoc.Records)
	}
}

func TestM4NhtsaCamelCaseJsonSchemaAndFccId(t *testing.T) {
	vinTwin, ok := ResolveDeclarativeTwin("https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/1HGCM82633A004352?format=json")
	if !ok || vinTwin == nil || vinTwin.ID != "nhtsa-vpic-recalls" {
		t.Fatalf("expected nhtsa-vpic-recalls twin, got ok=%v twin=%+v", ok, vinTwin)
	}
	vinJSON := `{"Message":"Results returned successfully","Results":[{"VIN":"1HGCM82633A004352","Make":"HONDA","Model":"Accord","ModelYear":"2003","BodyClass":"Sedan"}]}`
	doc, ok := vinTwin.Format(vinJSON)
	if !ok || doc == nil {
		t.Fatal("expected vPIC decode formatting to succeed")
	}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"Make":      map[string]any{"type": "string"},
			"ModelYear": map[string]any{"type": "string"},
		},
	}
	extracted, _, _ := ExtractStructuredJSONFromPageWithDiagnostics(vinJSON, ExtractedDocumentFull{
		Title:    doc.Title,
		Markdown: doc.Markdown,
	}, schema, "")
	if extracted["Make"] != "HONDA" || extracted["ModelYear"] != "2003" {
		t.Fatalf("expected Make=HONDA and ModelYear=2003 (camelCase heuristic), got %+v", extracted)
	}
}

func TestM4LocaleAnyOfBummAndTqAndGiantWildcardAndNfpa(t *testing.T) {
	// bumm-de both /en/product-detail/* and /de/products/detail/*
	bumm1 := ExtractHTMLDocumentFull(`<html><body><main><h1>IQ-X</h1><table class="attributes-table"><tr><th>Illuminance</th><td>100 Lux</td></tr></table><a href="https://bumm.de/fileadmin/user_upload/Anleitung_IQ-X.pdf">PDF</a></main></body></html>`, FullExtractOptions{
		BaseURL:         "https://bumm.de/en/product-detail/iq-x.html",
		OnlyMainContent: true,
	})
	if bumm1.ExtractorID != "bumm-de" || !strings.Contains(bumm1.Markdown, "100 Lux") {
		t.Fatalf("expected bumm-de /en/product-detail/* extraction, got id=%q md=%q", bumm1.ExtractorID, bumm1.Markdown)
	}
	bumm2 := ExtractHTMLDocumentFull(`<html><body><main><h1>IQ-X</h1><table class="attributes-table"><tr><th>Leuchtkraft</th><td>100 Lux</td></tr></table></main></body></html>`, FullExtractOptions{
		BaseURL:         "https://www.bumm.de/products/detail/iq-x.html",
		OnlyMainContent: true,
	})
	if bumm2.ExtractorID != "bumm-de" || !strings.Contains(bumm2.Markdown, "100 Lux") {
		t.Fatalf("expected bumm-de /products/detail/* extraction, got id=%q", bumm2.ExtractorID)
	}

	// tq-ebike /en/products/hpr50
	tqDoc := ExtractHTMLDocumentFull(`<html><body><main><h1>HPR50 Drive Unit</h1><table><tr><th>Torque</th><td>50 Nm</td></tr></table></main></body></html>`, FullExtractOptions{
		BaseURL:         "https://www.tq-ebike.com/en/products/hpr50",
		OnlyMainContent: true,
	})
	if tqDoc.ExtractorID != "tq-ebike" || !strings.Contains(tqDoc.Markdown, "50 Nm") {
		t.Fatalf("expected tq-ebike extraction, got id=%q md=%q", tqDoc.ExtractorID, tqDoc.Markdown)
	}

	// giant-liv-bikes wildcard + /shop/ exclusion
	giantDoc := ExtractHTMLDocumentFull(`<html><body><main><h1>Defy Advanced Pro 0</h1><section id="specifications"><ul><li class="datarow"><span class="label">Frame</span><span class="value">Carbon</span></li></ul></section></main></body></html>`, FullExtractOptions{
		BaseURL:         "https://www.liv-cycling.com/au/langma-advanced",
		OnlyMainContent: true,
	})
	if giantDoc.ExtractorID != "giant-liv-bikes" || !strings.Contains(giantDoc.Markdown, "Carbon") {
		t.Fatalf("expected giant-liv-bikes wildcard match, got id=%q", giantDoc.ExtractorID)
	}
	giantShop := ExtractHTMLDocumentFull(`<html><body><main><h1>Cart</h1></main></body></html>`, FullExtractOptions{
		BaseURL:         "https://www.giant-bicycles.com/us/shop/cart",
		OnlyMainContent: true,
	})
	if giantShop.ExtractorID == "giant-liv-bikes" {
		t.Fatal("giant /shop/* must not match giant-liv-bikes")
	}

	// nfpa Sitecore JSS __NEXT_DATA__
	nfpaHTML := `<!doctype html><html><head><title>NFPA 70</title></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"name":"nfpa-70","placeholders":{"jss-main":[{"componentName":"PageTitle","fields":{"Title":{"value":"NFPA 70 National Electrical Code"}}},{"componentName":"ContentBlock","fields":{"Content":{"value":"<p>Overcurrent protection rules.</p>"}}}]}}}}}}}</script></body></html>`
	nfpaDoc := ExtractHTMLDocumentFull(nfpaHTML, FullExtractOptions{
		BaseURL:         "https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70",
		OnlyMainContent: true,
	})
	if nfpaDoc.ExtractorID != "nfpa" || !strings.Contains(nfpaDoc.Markdown, "Overcurrent protection rules.") {
		t.Fatalf("expected nfpa Sitecore JSS extraction, got id=%q md=%q", nfpaDoc.ExtractorID, nfpaDoc.Markdown)
	}
}

func TestM4YouTubeAndShimanoRSCAndM2ContractFixes(t *testing.T) {
	// YouTube malformed nested trailing JSON
	ytHTML := `<html><head><title>Bike Motor Review - YouTube</title></head><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"abc123XYZ00","title":"Bosch CX Gen5 Review","author":"E-Bike Lab","lengthSeconds":"420","shortDescription":"85 Nm torque test."},"extra":{{broken;</script></body></html>`
	ytMeta := ExtractYouTubeWatchMetadataFromHTML(ytHTML, "https://www.youtube.com/watch?v=abc123XYZ00")
	if ytMeta == nil || ytMeta.Title != "Bosch CX Gen5 Review" || ytMeta.Author != "E-Bike Lab" {
		t.Fatalf("expected ExtractYouTubeWatchMetadataFromHTML balanced extraction despite trailing syntax noise, got %+v", ytMeta)
	}

	// Shimano RSC with nested unescaped quote inside string payload (fixtures.mjs F35 shape)
	rscHTML := `<!doctype html><html><body><div id="__next"><div>Loading...</div></div><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"spec\":\"{\"TableSpecContents\":[{\"categoryName\":\"Drive Unit Specifications\",\"specs\":[{\"specName\":\"Maximum Torque\",\"specValue\":\"85 Nm\"}]}]}\"}]\n"])</script></body></html>`
	hyd := RecoverSSRHydrationContent(rscHTML, "https://productinfo.shimano.com/en/product/DU-EP801", nil)
	if hyd == nil || !strings.Contains(hyd.Markdown, "85 Nm") {
		t.Fatalf("expected Shimano RSC TableSpecContents hydration, got %+v", hyd)
	}

	// M2 F06.2: leading § preserved in CFR headings
	cfrHTML := `<html><body><main><h1>16 CFR Part 1500</h1><h2>§ 1500.3 Definitions</h2><p>Hazardous substance definition.</p></main></body></html>`
	cfrDoc := ExtractHTMLDocumentFull(cfrHTML, FullExtractOptions{
		BaseURL:         "https://www.law.cornell.edu/cfr/text/16/1500.3",
		OnlyMainContent: true,
	})
	if !strings.Contains(cfrDoc.Markdown, "§ 1500.3") {
		t.Fatalf("F06.2: expected leading § preserved in markdown heading, got:\n%s", cfrDoc.Markdown)
	}

	// M2 F01.3 / F05.1: RecordFields emitted on Zendesk & CPSC
	zdTwin, ok := ResolveDeclarativeTwin("https://acme.zendesk.com/hc/en-us/sections/123-billing")
	if !ok || zdTwin == nil {
		t.Fatal("expected zendesk section twin")
	}
	zdDoc, ok := zdTwin.Format(`{"articles":[{"id":1,"title":"Invoice FAQ","html_url":"https://acme.zendesk.com/hc/en-us/articles/1","updated_at":"2026-10-01T00:00:00Z"}]}`)
	if !ok || zdDoc == nil || len(zdDoc.Records) != 1 || zdDoc.Records[0]["updatedAt"] != "2026-10-01" {
		t.Fatalf("expected zendesk RecordFields updatedAt, got %+v", zdDoc)
	}

	// M2 F20.2: osv-ghsa surfaces fixedVersions via nestedSubValues
	osvTwin, ok := ResolveDeclarativeTwin("https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q")
	if !ok || osvTwin == nil {
		t.Fatal("expected osv-ghsa twin")
	}
	osvDoc, ok := osvTwin.Format(`{"id":"GHSA-jfh8-c2jp-5v3q","summary":"Demo vuln","affected":[{"package":{"ecosystem":"Maven","name":"com.google.guava:guava"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"32.0.0-jre"}]}]}]}`)
	if !ok || osvDoc == nil || !strings.Contains(osvDoc.Markdown, "32.0.0-jre") {
		t.Fatalf("expected osv-ghsa fixed version 32.0.0-jre, got %+v", osvDoc)
	}

	// Microdata itemprop="url" on spec-table Product resolves relative href against finalURL
	specHTML := `<!doctype html><html><body><main itemscope itemtype="https://schema.org/Product"><h1 itemprop="name">Bafang M600</h1><a itemprop="url" href="/parts/bafang-m600">Spec</a><table class="spec-table"><tr><th>SKU</th><td>BF-M600-85</td></tr><tr><th>Brand</th><td>Bafang</td></tr><tr><th>Price</th><td>$899.00</td></tr></table></main></body></html>`
	specProd := ExtractStructuredProduct(specHTML, "https://bikeschematics.example.com/specs/bafang-m600", "Bafang M600", "")
	if specProd == nil || specProd["url"] != "https://bikeschematics.example.com/parts/bafang-m600" || specProd["sku"] != "BF-M600-85" {
		t.Fatalf("expected microdata itemprop=url resolved to /parts/bafang-m600, got %+v", specProd)
	}
}

func TestM4Iteration2RemediationsGo(t *testing.T) {
	// 1. Dover __NEXT_DATA__ locations[], compensation_min/max, slug URL, and sap-rmk-jibe exclusion
	doverHTML := `<!doctype html><html><head><title>Acme Jobs | Dover</title></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"company":{"name":"Acme Robotics","slug":"acme"},"jobs":[{"id":"dov-1","title":"Senior Battery Engineer","locations":[{"name":"Remote"}],"compensation_min":150000,"compensation_max":180000,"slug":"senior-battery-engineer"}]}}}</script></body></html>`
	doverDoc := ExtractHTMLDocumentFull(doverHTML, FullExtractOptions{
		BaseURL:         "https://app.dover.com/jobs/acme",
		OnlyMainContent: true,
	})
	if doverDoc.ExtractorID != "ukg-paylocity-dover" || len(doverDoc.Records) != 1 {
		t.Fatalf("expected dover_html 1 record, got id=%q records=%+v", doverDoc.ExtractorID, doverDoc.Records)
	}
	rec := doverDoc.Records[0]
	if rec["location"] != "Remote" {
		t.Fatalf("expected Dover location=Remote, got %+v", rec["location"])
	}
	if rec["compensation"] != "150000 - 180000" {
		t.Fatalf("expected Dover compensation=150000 - 180000, got %+v", rec["compensation"])
	}
	if recURL, _ := rec["url"].(string); !strings.Contains(recURL, "senior-battery-engineer") {
		t.Fatalf("expected Dover URL to contain slug senior-battery-engineer, got %q", recURL)
	}

	// sap-rmk-jibe must NOT collide with jobs.dover.com or app.dover.com
	if twin, ok := ResolveDeclarativeTwin("https://jobs.dover.com/api/jobs"); ok && twin != nil && twin.ID == "sap-rmk-jibe" {
		t.Fatalf("sap-rmk-jibe must not match jobs.dover.com/api/jobs")
	}
	if twin, ok := ResolveDeclarativeTwin("https://app.dover.com/api/jobs"); ok && twin != nil && twin.ID == "sap-rmk-jibe" {
		t.Fatalf("sap-rmk-jibe must not match app.dover.com/api/jobs")
	}
	sitemapXML := `<rss xmlns:g="http://base.google.com/ns/1.0"><channel><item><title>Eng</title><link>https://jobs.dover.com/1</link><g:location>Remote</g:location><g:employer>Dover</g:employer></item></channel></rss>`
	doverSitemap := ExtractHTMLDocumentFull(sitemapXML, FullExtractOptions{
		BaseURL:         "https://jobs.dover.com/sitemap.xml",
		OnlyMainContent: true,
	})
	if doverSitemap.ExtractorID == "sap-rmk-jibe" || doverSitemap.ExtractorID == "sap-rmk" {
		t.Fatalf("sap-rmk must not match jobs.dover.com/sitemap.xml, got %q", doverSitemap.ExtractorID)
	}

	// 2. SanitizeScrapedMeta across UKG, Paylocity (HTML + Feed), and Dover records[]
	ukgXSS := `<!doctype html><html><body><main><h1><script>alert(1)</script>Jobs</h1><script>window.__PRELOADED_STATE__ = { opportunities: [{ Id: "u1", Title: "<script>alert(1)</script>Firmware Eng", Location: "<img src=x onerror=alert(1)>Austin", Compensation: "<script>1</script>$150k", ApplyUrl: "https://recruiting.ultipro.com/U1/JobBoard/11111111-2222-3333-4444-555555555555/OpportunityDetail?opportunityId=u1" }] };</script></main></body></html>`
	ukgXSSDoc := ExtractHTMLDocumentFull(ukgXSS, FullExtractOptions{
		BaseURL:         "https://recruiting.ultipro.com/U1/JobBoard/11111111-2222-3333-4444-555555555555/",
		OnlyMainContent: true,
	})
	if len(ukgXSSDoc.Records) != 1 {
		t.Fatalf("expected 1 UKG record, got %+v", ukgXSSDoc.Records)
	}
	for _, field := range []string{"title", "location", "compensation"} {
		val, _ := ukgXSSDoc.Records[0][field].(string)
		if strings.Contains(val, "<script") || strings.Contains(val, "<img") {
			t.Fatalf("UKG record %s contains unsanitized HTML tag: %q", field, val)
		}
	}

	plcXSS := `<!doctype html><html><body><script>window.pageData = { Jobs: [{ JobId: 7, Title: "<img src=x onerror=alert(1)>Controls", LocationName: "<script>x</script>Remote", JobUrl: "https://recruiting.paylocity.com/Recruiting/Jobs/Details/7" }] };</script></body></html>`
	plcXSSDoc := ExtractHTMLDocumentFull(plcXSS, FullExtractOptions{
		BaseURL:         "https://recruiting.paylocity.com/Recruiting/Jobs/All/11111111-2222-3333-4444-555555555555",
		OnlyMainContent: true,
	})
	if len(plcXSSDoc.Records) != 1 {
		t.Fatalf("expected 1 Paylocity HTML record, got %+v", plcXSSDoc.Records)
	}
	if strings.Contains(plcXSSDoc.Records[0]["title"].(string), "<img") || strings.Contains(plcXSSDoc.Records[0]["location"].(string), "<script") {
		t.Fatalf("Paylocity HTML record unsanitized: %+v", plcXSSDoc.Records[0])
	}

	// 3. decodeJSOrJSONObjectM4 / normalizeJSObjectLiteralToJSONM4 with trailing commas & large object
	var bigItems strings.Builder
	bigItems.WriteString(`{ opportunities: [`)
	for i := 0; i < 400; i++ {
		if i > 0 {
			bigItems.WriteByte(',')
		}
		bigItems.WriteString(`{ Title: "Role \"Quoted\"", Location: 'Austin, TX', }`)
	}
	bigItems.WriteString(`], }`)
	decodedObj := decodeJSOrJSONObjectM4(bigItems.String())
	if decodedObj == nil {
		t.Fatal("expected decodeJSOrJSONObjectM4 to parse large JS object literal with trailing commas")
	}

	// 4. Shimano RSC sibling object before TableSpecContents + "}" inside sibling string
	rscSibling := `<!doctype html><html><body><div id="__next"><div>Loading...</div></div><script>self.__next_f.push([1,"1:[\"$\",\"$L1\",null,{\"meta\":{\"foo\":1,\"brace\":\"}\"},\"TableSpecContents\":[{\"categoryName\":\"Drive Unit\",\"specs\":[{\"specName\":\"Peak Power\",\"specValue\":\"600 W\"}]}]},BROKEN_TAIL\n"])</script></body></html>`
	hydSib := RecoverSSRHydrationContent(rscSibling, "https://productinfo.shimano.com/en/product/DU-EP801", nil)
	if hydSib == nil || !strings.Contains(hydSib.Markdown, "600 W") {
		t.Fatalf("expected Shimano RSC sibling object recovery with 600 W, got %+v", hydSib)
	}

	// 5. giant-liv-bikes link replacement, nested <p> without nav/footer chrome, and 3-letter /int/ / /global/ handling
	giantNestedHTML := `<!doctype html><html><body><main><h1>Defy</h1><div><p>Nested overview paragraph for endurance road geometry.</p></div><nav><p>Nav menu item</p><a href="https://uk.giant-bicycles.com/us/shop/checkout">Cart</a></nav><a href="https://uk.giant-bicycles.com/manuals/defy.pdf">Manual PDF</a></main></body></html>`
	giantNested := ExtractHTMLDocumentFull(giantNestedHTML, FullExtractOptions{
		BaseURL:         "https://uk.giant-bicycles.com/us/defy",
		OnlyMainContent: true,
	})
	if giantNested.ExtractorID != "giant-liv-bikes" {
		t.Fatalf("expected giant-liv-bikes, got %q", giantNested.ExtractorID)
	}
	if !strings.Contains(giantNested.Markdown, "Nested overview paragraph") || strings.Contains(giantNested.Markdown, "Nav menu item") {
		t.Fatalf("expected nested main p included and nav p excluded, got:\n%s", giantNested.Markdown)
	}
	for _, l := range giantNested.Links {
		if strings.Contains(l, "/shop/checkout") {
			t.Fatalf("giant-liv-bikes leaked disallowed /shop/ link: %q", l)
		}
	}

	giantOnlyShopHTML := `<!doctype html><html><body><main><h1>Defy</h1><section id="specifications"><ul><li class="datarow"><span class="label">Frame</span><span class="value">Carbon</span></li></ul></section><a href="/us/shop/checkout">Buy Now</a></main></body></html>`
	giantOnlyShop := ExtractHTMLDocumentFull(giantOnlyShopHTML, FullExtractOptions{
		BaseURL:         "https://uk.giant-bicycles.com/us/defy",
		OnlyMainContent: true,
	})
	if len(giantOnlyShop.Links) != 0 {
		t.Fatalf("expected empty Links when only /shop/ links present, got %+v", giantOnlyShop.Links)
	}

	giantIntShop := ExtractHTMLDocumentFull(`<html><body><main><h1>Shop</h1></main></body></html>`, FullExtractOptions{
		BaseURL:         "https://www.giant-bicycles.com/int/shop/cart",
		OnlyMainContent: true,
	})
	if giantIntShop.ExtractorID == "giant-liv-bikes" {
		t.Fatal("giant /int/shop/cart must not match giant-liv-bikes")
	}
	reg := loadRegistry()
	var giantMatchSpec DeclarativeMatchSpec
	for _, a := range reg.byHost["www.giant-bicycles.com"] {
		if a.ID == "giant-liv-bikes" && len(a.HTMLRoutes) > 0 {
			giantMatchSpec = a.HTMLRoutes[0].Match
			break
		}
	}
	if _, okMatch := MatchDeclarativeRouteURL(giantMatchSpec, "https://www.giant-bicycles.com/int/shop/cart"); okMatch {
		t.Fatal("MatchDeclarativeRouteURL must reject /int/shop/cart for giant-liv-bikes")
	}
	if _, okMatch := MatchDeclarativeRouteURL(giantMatchSpec, "https://www.giant-bicycles.com/int/defy-advanced-pro-0"); !okMatch {
		t.Fatal("MatchDeclarativeRouteURL must match /int/defy-advanced-pro-0 for giant-liv-bikes")
	}

	// 6. NFPA capitalized Sitecore JSS keys + relative ctaLink/link Markdown bullets
	nfpaCapHTML := `<!doctype html><html><head><title>NFPA 70</title></head><body><script id="__NEXT_DATA__" type="application/json">{"Props":{"PageProps":{"LayoutData":{"Sitecore":{"Route":{"Placeholders":{"Storefront-Main":[{"ComponentName":"PageTitle","Fields":{"Title":{"Value":"NFPA 70"}}},{"ComponentName":"Callout","Fields":{"Heading":{"Value":"Resources"},"CtaLink":{"Value":{"Href":"/codes-and-standards/nfpa-70","Text":"Read NFPA 70"}}}}]}}}}}}}</script></body></html>`
	nfpaCapDoc := ExtractHTMLDocumentFull(nfpaCapHTML, FullExtractOptions{
		BaseURL:         "https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70",
		OnlyMainContent: true,
	})
	if nfpaCapDoc.ExtractorID != "nfpa" {
		t.Fatalf("expected nfpa extractor, got %q", nfpaCapDoc.ExtractorID)
	}
	if !strings.Contains(nfpaCapDoc.Markdown, "- [Read NFPA 70](https://www.nfpa.org/codes-and-standards/nfpa-70)") {
		t.Fatalf("expected resolved relative ctaLink bullet in NFPA markdown, got:\n%s", nfpaCapDoc.Markdown)
	}
	foundNfpaLink := false
	for _, l := range nfpaCapDoc.Links {
		if l == "https://www.nfpa.org/codes-and-standards/nfpa-70" {
			foundNfpaLink = true
		}
	}
	if !foundNfpaLink {
		t.Fatalf("expected resolved NFPA link in doc.Links, got %+v", nfpaCapDoc.Links)
	}
}

func TestM4Iteration3RemediationsGo(t *testing.T) {
	// 1. giant-liv-bikes no-PDF <main> fallback must strip <nav>/<footer>/<header>/<aside> and /shop/ links from both Markdown and Links
	giantNoPdfHTML := `<!doctype html><html><body><main><h1>Bike</h1><div><p>Nested overview.</p></div><nav><p>Nav noise</p></nav><footer><p>Footer noise</p></footer><aside><p>Aside noise</p></aside><a href="/us/shop/checkout">Shop</a><a href="/us/defy-specs">Geometry</a></main></body></html>`
	giantNoPdfDoc := ExtractHTMLDocumentFull(giantNoPdfHTML, FullExtractOptions{
		BaseURL:         "https://uk.giant-bicycles.com/us/bike",
		OnlyMainContent: true,
	})
	if giantNoPdfDoc.ExtractorID != "giant-liv-bikes" {
		t.Fatalf("expected giant-liv-bikes, got %q", giantNoPdfDoc.ExtractorID)
	}
	if !strings.Contains(giantNoPdfDoc.Markdown, "Nested overview.") {
		t.Fatalf("expected main content preserved in markdown, got:\n%s", giantNoPdfDoc.Markdown)
	}
	for _, banned := range []string{"Nav noise", "Footer noise", "Aside noise", "/shop/checkout", "[Shop]"} {
		if strings.Contains(giantNoPdfDoc.Markdown, banned) {
			t.Fatalf("no-PDF giant-liv-bikes markdown leaked %q:\n%s", banned, giantNoPdfDoc.Markdown)
		}
	}
	if !strings.Contains(giantNoPdfDoc.Markdown, "https://uk.giant-bicycles.com/us/defy-specs") {
		t.Fatalf("expected legitimate non-shop link retained in markdown, got:\n%s", giantNoPdfDoc.Markdown)
	}
	for _, l := range giantNoPdfDoc.Links {
		if strings.Contains(l, "/shop/checkout") {
			t.Fatalf("no-PDF giant-liv-bikes Links leaked /shop/ link: %q", l)
		}
	}

	// 2. NFPA runSitecoreJSSHTMLExtractorDeclHTML applies SanitizeScrapedMeta to docTitle (PageTitle and <title> fallback)
	nfpaCtrlTitleHTML := `<!doctype html><html><head><title>Ignored</title></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"placeholders":{"storefront-main":[{"componentName":"PageTitle","fields":{"title":{"value":"NFPA 70\u0000\u0007\n   Code"}}},{"componentName":"ContentBlock","fields":{"body":{"value":"<p>Safe body.</p>"}}}]}}}}}}}</script></body></html>`
	nfpaCtrlDoc := ExtractHTMLDocumentFull(nfpaCtrlTitleHTML, FullExtractOptions{
		BaseURL:         "https://www.nfpa.org/codes-and-standards/nfpa-70",
		OnlyMainContent: true,
	})
	if nfpaCtrlDoc.ExtractorID != "nfpa" {
		t.Fatalf("expected nfpa extractor, got %q", nfpaCtrlDoc.ExtractorID)
	}
	if strings.ContainsAny(nfpaCtrlDoc.Title, "\x00\x07\n") || nfpaCtrlDoc.Title != "NFPA 70 Code" {
		t.Fatalf("expected SanitizeScrapedMeta on NFPA PageTitle, got %q", nfpaCtrlDoc.Title)
	}
	if !strings.HasPrefix(nfpaCtrlDoc.Markdown, "# NFPA 70 Code\n\n") {
		t.Fatalf("expected sanitized H1 heading in NFPA markdown, got:\n%s", nfpaCtrlDoc.Markdown)
	}

	nfpaFallbackTitleHTML := `<!doctype html><html><head><title>NFPA   72&#10;&#9;Standard</title></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"placeholders":{"storefront-main":[{"componentName":"ContentBlock","fields":{"body":{"value":"<p>Fire alarm code.</p>"}}}]}}}}}}}</script></body></html>`
	nfpaFallbackDoc := ExtractHTMLDocumentFull(nfpaFallbackTitleHTML, FullExtractOptions{
		BaseURL:         "https://www.nfpa.org/codes-and-standards/nfpa-72",
		OnlyMainContent: true,
	})
	if strings.ContainsAny(nfpaFallbackDoc.Title, "\t\n\r") || nfpaFallbackDoc.Title != "NFPA 72 Standard" {
		t.Fatalf("expected SanitizeScrapedMeta on NFPA <title> fallback, got %q", nfpaFallbackDoc.Title)
	}
}

func TestM4Iteration5UkgPaylocityDoverSanitizationGo(t *testing.T) {
	assertNoRawHTMLTags := func(ctx string, rec map[string]any, fields ...string) {
		t.Helper()
		for _, field := range fields {
			val, _ := rec[field].(string)
			low := strings.ToLower(val)
			if strings.Contains(low, "<script") || strings.Contains(low, "</script") || strings.Contains(low, "<img") {
				t.Fatalf("%s record[%q] contains unsanitized HTML tag: %q", ctx, field, val)
			}
		}
	}

	// 1. paylocity_feed: id, postedAt, description (entity-encoded &lt;script&gt; and raw <img ...>)
	plcTwin, ok := ResolveDeclarativeTwin("https://recruiting.paylocity.com/recruiting/jobs/all/aa11bb22-cc33-44dd-ee55-ff6677889900")
	if !ok || plcTwin == nil {
		t.Fatal("expected paylocity_feed twin")
	}
	plcFeedJSON := `{"Jobs":[{"JobId":"<script>alert(1)</script>99","Title":"PLC Engineer","PublishedDate":"<img src=x onerror=alert(3)>2026-11-26","Description":"&lt;script&gt;alert(3)&lt;/script&gt; <img src=x onerror=alert(2)>PLC firmware","JobUrl":"https://recruiting.paylocity.com/Recruiting/Jobs/Details/99"}]}`
	plcFeedDoc, ok := plcTwin.Format(plcFeedJSON)
	if !ok || plcFeedDoc == nil || len(plcFeedDoc.Records) != 1 {
		t.Fatalf("expected 1 paylocity_feed record, got ok=%v doc=%+v", ok, plcFeedDoc)
	}
	assertNoRawHTMLTags("paylocity_feed", plcFeedDoc.Records[0], "id", "postedAt", "description", "title")
	if desc, _ := plcFeedDoc.Records[0]["description"].(string); !strings.Contains(desc, "PLC firmware") {
		t.Fatalf("expected description text preserved after sanitization, got %q", desc)
	}

	// 2. ukg_pro_html: id, postedAt
	ukgHTML := `<!doctype html><html><body><main><h1>Open Roles</h1><script>window.__PRELOADED_STATE__ = { opportunities: [{ Id: "\u003cscript\u003ealert(1)\u003c/script\u003eu1", Title: "Firmware Eng", PostedDate: "<img src=x onerror=alert(3)>2026-11-26", ApplyUrl: "https://recruiting.ultipro.com/U1/JobBoard/11111111-2222-3333-4444-555555555555/OpportunityDetail?opportunityId=u1" }] };</script></main></body></html>`
	ukgDoc := ExtractHTMLDocumentFull(ukgHTML, FullExtractOptions{
		BaseURL:         "https://recruiting.ultipro.com/U1/JobBoard/11111111-2222-3333-4444-555555555555/",
		OnlyMainContent: true,
	})
	if len(ukgDoc.Records) != 1 {
		t.Fatalf("expected 1 UKG record, got %+v", ukgDoc.Records)
	}
	assertNoRawHTMLTags("ukg_pro_html", ukgDoc.Records[0], "id", "postedAt", "title")

	// 3. paylocity_html: id, postedAt
	plcHTML := `<!doctype html><html><body><script>window.pageData = { Jobs: [{ JobId: "\u003cscript\u003ealert(1)\u003c/script\u003e7", Title: "Controls Eng", PublishedDate: "<img src=x onerror=alert(3)>2026-11-26", JobUrl: "https://recruiting.paylocity.com/Recruiting/Jobs/Details/7" }] };</script></body></html>`
	plcDoc := ExtractHTMLDocumentFull(plcHTML, FullExtractOptions{
		BaseURL:         "https://recruiting.paylocity.com/Recruiting/Jobs/All/11111111-2222-3333-4444-555555555555",
		OnlyMainContent: true,
	})
	if len(plcDoc.Records) != 1 {
		t.Fatalf("expected 1 paylocity_html record, got %+v", plcDoc.Records)
	}
	assertNoRawHTMLTags("paylocity_html", plcDoc.Records[0], "id", "postedAt", "title")

	// 4. dover_html: id, postedAt, description (&lt;script&gt; + <img ...>)
	doverHTML := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"company":{"name":"Acme &lt;script\u003ealert(1)&lt;/script\u003e"},"jobs":[{"id":"\u003cscript\u003ealert(1)\u003c/script\u003edov-1","title":"Battery Eng","postedAt":"\u003cimg src=x onerror=alert(3)\u003e2026-11-26","description":"&lt;script&gt;alert(4)&lt;/script&gt; \u003cimg src=x onerror=alert(5)\u003eBuild batteries","slug":"battery-eng"}]}}}</script></body></html>`
	doverDoc := ExtractHTMLDocumentFull(doverHTML, FullExtractOptions{
		BaseURL:         "https://app.dover.com/jobs/acme",
		OnlyMainContent: true,
	})
	if len(doverDoc.Records) != 1 {
		t.Fatalf("expected 1 dover_html record, got %+v", doverDoc.Records)
	}
	assertNoRawHTMLTags("dover_html", doverDoc.Records[0], "id", "postedAt", "description", "company", "title")
	if desc, _ := doverDoc.Records[0]["description"].(string); !strings.Contains(desc, "Build batteries") {
		t.Fatalf("expected Dover description text preserved after sanitization, got %q", desc)
	}
}

func TestM4Iteration6DotSegmentURLHygieneGo(t *testing.T) {
	assertNoDotSegments := func(ctx string, rec map[string]any) {
		t.Helper()
		for _, field := range []string{"url", "applyUrl"} {
			if u, ok := rec[field].(string); ok && u != "" {
				if strings.HasSuffix(u, "/.") || strings.HasSuffix(u, "/..") || strings.Contains(u, "/./") || strings.Contains(u, "/../") {
					t.Fatalf("%s record[%q] contains unnormalized dot-segment URL: %q", ctx, field, u)
				}
			}
		}
	}

	// 1. paylocity_feed: "." / ".." JobId must not synthesize /Details/. or /Details/..
	plcTwin, ok := ResolveDeclarativeTwin("https://recruiting.paylocity.com/recruiting/jobs/all/aa11bb22-cc33-44dd-ee55-ff6677889900")
	if !ok || plcTwin == nil {
		t.Fatal("expected paylocity_feed twin")
	}
	plcFeedDoc, ok := plcTwin.Format(`{"Jobs":[{"JobId":"..","Title":"DotDot Role"},{"JobId":".","Title":"Dot Role"}]}`)
	if !ok || plcFeedDoc == nil || len(plcFeedDoc.Records) != 2 {
		t.Fatalf("expected 2 paylocity_feed records, got ok=%v doc=%+v", ok, plcFeedDoc)
	}
	for i, rec := range plcFeedDoc.Records {
		assertNoDotSegments(fmt.Sprintf("paylocity_feed[%d]", i), rec)
		if _, hasURL := rec["url"]; hasURL {
			t.Fatalf("expected paylocity_feed[%d] url omitted for dot-segment JobId, got %v", i, rec["url"])
		}
	}

	// 2. paylocity_html: "." / ".." JobId must not synthesize /Details/. or /Details/..
	plcHTML := `<!doctype html><html><body><script>window.pageData = { Jobs: [{ JobId: "..", Title: "DotDot HTML Role" }, { JobId: ".", Title: "Dot HTML Role" }] };</script></body></html>`
	plcDoc := ExtractHTMLDocumentFull(plcHTML, FullExtractOptions{
		BaseURL:         "https://recruiting.paylocity.com/Recruiting/Jobs/All/11111111-2222-3333-4444-555555555555",
		OnlyMainContent: true,
	})
	if len(plcDoc.Records) != 2 {
		t.Fatalf("expected 2 paylocity_html records, got %+v", plcDoc.Records)
	}
	for i, rec := range plcDoc.Records {
		assertNoDotSegments(fmt.Sprintf("paylocity_html[%d]", i), rec)
		if _, hasURL := rec["url"]; hasURL {
			t.Fatalf("expected paylocity_html[%d] url omitted for dot-segment JobId, got %v", i, rec["url"])
		}
	}

	// 3. dover_html: "." / ".." companySlug or slug must fall back cleanly to baseURL without /apply/../..
	doverHTML := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"company":{"name":"Acme","slug":".."},"jobs":[{"id":"d1","title":"DotDot Role","slug":".."},{"id":"d2","title":"Valid Slug With Bad Company","slug":"eng"}]}}}</script></body></html>`
	doverDoc := ExtractHTMLDocumentFull(doverHTML, FullExtractOptions{
		BaseURL:         "https://app.dover.com/jobs/acme",
		OnlyMainContent: true,
	})
	if len(doverDoc.Records) != 2 {
		t.Fatalf("expected 2 dover_html records, got %+v", doverDoc.Records)
	}
	for i, rec := range doverDoc.Records {
		assertNoDotSegments(fmt.Sprintf("dover_html[%d]", i), rec)
		if rec["url"] != "https://app.dover.com/jobs/acme" {
			t.Fatalf("expected dover_html[%d] fallback to baseURL, got %q", i, rec["url"])
		}
	}

	doverDotSlugHTML := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"company":{"name":"Acme","slug":"acme"},"jobs":[{"id":"d3","title":"Dot Slug","slug":"."}]}}}</script></body></html>`
	doverDotSlugDoc := ExtractHTMLDocumentFull(doverDotSlugHTML, FullExtractOptions{
		BaseURL:         "https://app.dover.com/jobs/acme",
		OnlyMainContent: true,
	})
	if len(doverDotSlugDoc.Records) != 1 {
		t.Fatalf("expected 1 dover_html dot-slug record, got %+v", doverDotSlugDoc.Records)
	}
	assertNoDotSegments("dover_html_dot_slug", doverDotSlugDoc.Records[0])
	if doverDotSlugDoc.Records[0]["url"] != "https://app.dover.com/jobs/acme" {
		t.Fatalf("expected dover_html_dot_slug fallback to baseURL, got %q", doverDotSlugDoc.Records[0]["url"])
	}
}

func TestM4YouTubeAndShimanoXSSSanitization(t *testing.T) {
	ytXSSHTML := `<!doctype html><html><head><title>YouTube</title></head><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"xss123XYZ00","title":"<script>alert(1)</script>Cool Video","author":"<img src=x onerror=alert(1)>Channel","lengthSeconds":"90","shortDescription":"<svg onload=alert(1)>Desc [bad](javascript:alert(1))"}};</script></body></html>`
	assertNoRawXSS := func(label, s string) {
		t.Helper()
		low := strings.ToLower(s)
		for _, bad := range []string{"<script", "<img", "<svg", "javascript:"} {
			if strings.Contains(low, bad) {
				t.Fatalf("%s leaked unsafe payload %q: %q", label, bad, s)
			}
		}
	}

	ytMeta := ExtractYouTubeWatchMetadataFromHTML(ytXSSHTML, "https://www.youtube.com/watch?v=xss123XYZ00")
	if ytMeta == nil {
		t.Fatal("expected ExtractYouTubeWatchMetadataFromHTML to return metadata")
	}
	assertNoRawXSS("ytMeta.Title", ytMeta.Title)
	assertNoRawXSS("ytMeta.Author", ytMeta.Author)
	assertNoRawXSS("ytMeta.Description", ytMeta.Description)
	assertNoRawXSS("ytMeta.Markdown", ytMeta.Markdown)
	if !strings.Contains(ytMeta.Title, "Cool Video") || !strings.Contains(ytMeta.Author, "Channel") || !strings.Contains(ytMeta.Description, "Desc") {
		t.Fatalf("expected legitimate text preserved in ytMeta, got %+v", ytMeta)
	}

	ytDoc := ExtractHTMLDocumentFull(ytXSSHTML, FullExtractOptions{
		BaseURL:         "https://www.youtube.com/watch?v=xss123XYZ00",
		OnlyMainContent: true,
	})
	assertNoRawXSS("ytDoc.Title", ytDoc.Title)
	assertNoRawXSS("ytDoc.Description", ytDoc.Description)
	assertNoRawXSS("ytDoc.Markdown", ytDoc.Markdown)
	assertNoRawXSS("ytDoc.Text", ytDoc.Text)
	if !strings.Contains(ytDoc.Text, "Cool Video") || !strings.Contains(ytDoc.Text, "Desc") {
		t.Fatalf("expected sanitized content in ytDoc.Text, got %q", ytDoc.Text)
	}

	// Shimano RSC TableSpecContents XSS in records[] and markdown
	rscXSS := `<!doctype html><html><body><div id="__next"><div>Loading...</div></div><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"spec\":\"{\\\"TableSpecContents\\\":[{\\\"categoryName\\\":\\\"<script>alert(1)</script>Drive\\\",\\\"specs\\\":[{\\\"specName\\\":\\\"<img src=x onerror=alert(1)>Torque\\\",\\\"specValue\\\":\\\"<svg onload=alert(1)>85 Nm [bad](javascript:alert(1))\\\"}]}]}\"}]\n"])</script></body></html>`
	// Also test unescaped nested JSON shape (as used by F35 fixture)
	rscXSSUnescaped := `<!doctype html><html><body><div id="__next"><div>Loading...</div></div><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"spec\":\"{\"TableSpecContents\":[{\"categoryName\":\"<script>alert(1)</script>Drive\",\"specs\":[{\"specName\":\"<img src=x onerror=alert(1)>Torque\",\"specValue\":\"<svg onload=alert(1)>85 Nm [bad](javascript:alert(1))\"}]}]}\"}]\n"])</script></body></html>`
	_ = rscXSS
	hyd := RecoverSSRHydrationContent(rscXSSUnescaped, "https://productinfo.shimano.com/en/product/DU-EP801", nil)
	if hyd == nil || len(hyd.Records) != 1 {
		t.Fatalf("expected 1 Shimano RSC record, got %+v", hyd)
	}
	assertNoRawXSS("shimano.Markdown", hyd.Markdown)
	for _, field := range []string{"category", "name", "value"} {
		val, _ := hyd.Records[0][field].(string)
		assertNoRawXSS("shimano.Records[0]."+field, val)
	}
	if !strings.Contains(hyd.Records[0]["value"].(string), "85 Nm") {
		t.Fatalf("expected 85 Nm preserved in sanitized Shimano record, got %+v", hyd.Records[0])
	}
}

func TestM4YouTubeAndShimanoAdversarialXSSBypasses(t *testing.T) {
	assertNoRawXSS := func(label, s string) {
		t.Helper()
		low := strings.ToLower(s)
		for _, bad := range []string{"<script", "</script", "<img", "<svg", "<iframe", "javascript:"} {
			if strings.Contains(low, bad) {
				t.Fatalf("%s leaked unsafe payload %q: %q", label, bad, s)
			}
		}
	}

	// 1. YouTube Watch untrusted fenced code block breakout in shortDescription (with ADAPTER-18 newline check)
	ytFenceHTML := `<!doctype html><html><head><title>Watch</title></head><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"fence123456","title":"Test\nVid","author":"Safe Chan","lengthSeconds":"90","shortDescription":"Intro\n\n` + "```" + `html\n<script>alert(\"yt-fence-bypass\")</script>\n` + "```" + `\n\n~~~html\n<img src=x onerror=alert(1)\n~~~\n\nEnd"}};</script></body></html>`
	ytFenceMeta := ExtractYouTubeWatchMetadataFromHTML(ytFenceHTML, "https://www.youtube.com/watch?v=fence123456")
	if ytFenceMeta == nil {
		t.Fatal("expected ExtractYouTubeWatchMetadataFromHTML to return metadata")
	}
	if ytFenceMeta.Title != "Test\nVid" {
		t.Fatalf("expected ADAPTER-18 newline title preserved, got %q", ytFenceMeta.Title)
	}
	assertNoRawXSS("ytFenceMeta.Description", ytFenceMeta.Description)
	assertNoRawXSS("ytFenceMeta.Markdown", ytFenceMeta.Markdown)

	ytFenceDoc := ExtractHTMLDocumentFull(ytFenceHTML, FullExtractOptions{
		BaseURL:         "https://www.youtube.com/watch?v=fence123456",
		OnlyMainContent: true,
	})
	assertNoRawXSS("ytFenceDoc.Description", ytFenceDoc.Description)
	assertNoRawXSS("ytFenceDoc.Markdown", ytFenceDoc.Markdown)
	assertNoRawXSS("ytFenceDoc.Text", ytFenceDoc.Text)

	// 2. Entity-free split-tag reassembly (<scr<script>ipt> and <im<img src=x>g>) + unclosed tags
	ytSplitHTML := `<!doctype html><html><head><title>Watch</title></head><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"split123456","title":"Safe <scr<script>ipt>alert(1)</scr</script>ipt>","author":"<im<img src=x>g onerror=alert(1)>Chan","lengthSeconds":"90","shortDescription":"<svg onload=alert(1)Body"}};</script></body></html>`
	ytSplitMeta := ExtractYouTubeWatchMetadataFromHTML(ytSplitHTML, "https://www.youtube.com/watch?v=split123456")
	if ytSplitMeta == nil {
		t.Fatal("expected ytSplitMeta to return metadata")
	}
	assertNoRawXSS("ytSplitMeta.Title", ytSplitMeta.Title)
	assertNoRawXSS("ytSplitMeta.Author", ytSplitMeta.Author)
	assertNoRawXSS("ytSplitMeta.Description", ytSplitMeta.Description)
	assertNoRawXSS("ytSplitMeta.Markdown", ytSplitMeta.Markdown)

	ytSplitDoc := ExtractHTMLDocumentFull(ytSplitHTML, FullExtractOptions{
		BaseURL:         "https://www.youtube.com/watch?v=split123456",
		OnlyMainContent: true,
	})
	assertNoRawXSS("ytSplitDoc.Markdown", ytSplitDoc.Markdown)
	assertNoRawXSS("ytSplitDoc.Text", ytSplitDoc.Text)

	// Direct SanitizeMarkdownWithOptions check for split-tag reassembly
	splitSan := SanitizeScrapedMarkdown("Before <scr<script>ipt>alert(1)</scr</script>ipt> After")
	assertNoRawXSS("splitSan", splitSan)

	// 3. Shimano RSC unclosed tags, split tags, entity-encoded & double-encoded inputs
	rscAdversarial := `<!doctype html><html><body><div id="__next"><div>Loading...</div></div><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"spec\":\"{\"TableSpecContents\":[{\"categoryName\":\"&lt;script&gt;alert(1)&lt;/script&gt;<scr<script>ipt>x</scr</script>ipt>Drive\",\"specs\":[{\"specName\":\"<img src=x onerror=alert(1)Torque\",\"specValue\":\"<svg onload=alert(1)85 Nm\"},{\"specName\":\"&#x3C;img src=x onerror=alert(1)&#x3E;Power\",\"specValue\":\"&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;250 W\"}]}]}\"}]\n"])</script></body></html>`
	hydAdv := RecoverSSRHydrationContent(rscAdversarial, "https://productinfo.shimano.com/en/product/DU-EP801", nil)
	if hydAdv == nil || len(hydAdv.Records) != 2 {
		t.Fatalf("expected 2 Shimano RSC records, got %+v", hydAdv)
	}
	assertNoRawXSS("shimanoAdv.Markdown", hydAdv.Markdown)
	for i, rec := range hydAdv.Records {
		for _, field := range []string{"category", "name", "value"} {
			val, _ := rec[field].(string)
			assertNoRawXSS(fmt.Sprintf("shimanoAdv.Records[%d].%s", i, field), val)
		}
	}
}

func TestM4GenericHTMLDocumentTextSanitization(t *testing.T) {
	assertNoRawXSS := func(label, s string) {
		t.Helper()
		low := strings.ToLower(s)
		for _, bad := range []string{"<script", "</script", "<img", "<svg", "<iframe", "<scr", "](vbscript:", "](javascript:", "<vbscript:", "<javascript:", "< vbscript:"} {
			if strings.Contains(low, bad) {
				t.Fatalf("%s leaked unsafe payload %q: %q", label, bad, s)
			}
		}
	}

	nestedOpen := strings.Repeat("<scr", 10) + "<script>" + strings.Repeat("ipt>", 10)
	nestedClose := strings.Repeat("</scr", 10) + "</script>" + strings.Repeat("ipt>", 10)
	rawHTML := `<!doctype html><html><head><title>Generic Page</title></head><body><main><article>` +
		`<p>Gen ` + nestedOpen + `Hello` + nestedClose + ` ` +
		`<script>alert(1)</script> ` +
		`<scr<script>ipt>alert(2)</scr</script>ipt> ` +
		`<scr<wbr>ipt>alert(3)</scr<wbr>ipt> ` +
		`<img src=x onerror=alert(1)> ` +
		`&lt;script&gt;alert(4)&lt;/script&gt; ` +
		`&#0000060;img src=x onerror=alert(1)&#0000062; ` +
		`[md](vbscript:alert(1)) ` +
		`[ent](&#106;avascript:alert(1)) ` +
		`&lt;  vbscript:alert(1) ` +
		`5 < 10</p></article></main></body></html>`

	doc := ExtractHTMLDocumentFull(rawHTML, FullExtractOptions{
		BaseURL:         "https://generic.example.com/page",
		OnlyMainContent: true,
	})
	assertNoRawXSS("generic.Markdown", doc.Markdown)
	assertNoRawXSS("generic.Text", doc.Text)
	if !strings.Contains(doc.Text, "5 < 10") {
		t.Fatalf("expected benign prose '5 < 10' preserved in doc.Text, got %q", doc.Text)
	}
	if !strings.Contains(doc.Markdown, "5 < 10") && !strings.Contains(doc.Markdown, "5 &lt; 10") {
		t.Fatalf("expected benign math prose preserved in doc.Markdown, got %q", doc.Markdown)
	}
}

func TestTier5AdversarialM4AndHydrationGO3ToGO6(t *testing.T) {
	t.Parallel()

	// GO-3: Escape `[` and `]` + odd trailing `\` in escapeTableCellM4 & nfpa & giant-liv-bikes & YouTube watch metadata.
	gotEscaped := escapeTableCellM4(`Role](https://evil.com)[x\`)
	if gotEscaped != `Role\](https://evil.com)\[x\\` {
		t.Fatalf("unexpected escapeTableCellM4 output: got %q", gotEscaped)
	}

	nfpaHTML := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{
		"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"placeholders":{"storefront-main":[
			{"componentName":"PageTitle","fields":{"title":{"value":"NFPA 70"}}},
			{"componentName":"ContentBlock","fields":{"ctaLink":{"value":{"href":"/codes-and-standards/70","text":"NFPA 70](https://evil.test)[x"}}}}
		]}}}}}}
	}</script></body></html>`
	nfpaRes, okNfpa := ExtractHTMLOnValidatedManifest(LookupBuiltInManifest("nfpa"), nfpaHTML, "https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70", "", nil)
	if !okNfpa || nfpaRes == nil {
		t.Fatal("expected nfpa extractor to match")
	}
	if !strings.Contains(nfpaRes.Markdown, `\](https://evil.test)\[x`) {
		t.Fatalf("expected nfpa markdown link injection escaped with backslash, got:\n%s", nfpaRes.Markdown)
	}

	giantHTML := `<!doctype html><html><body>
		<main>
			<h1>Defy Advanced</h1>
			<p class="price">$2,999.00</p>
			<table class="geometry">
				<tr><th>Size</th><th>Stack</th><th>Link</th></tr>
				<tr><td>M</td><td>567 mm</td><td><a href="/us/shop/add-to-cart?id=1">Buy Now</a> <a href="/us/cart/checkout">Checkout</a> <a href="/us/sizing-guide">Sizing](https://evil.test)</a></td></tr>
			</table>
			<a href="/us/spec-sheet">Spec Sheet](https://evil.test)</a>
		</main>
	</body></html>`
	giantRes, okGiant := ExtractHTMLOnValidatedManifest(LookupBuiltInManifest("giant-liv-bikes"), giantHTML, "https://www.giant-bicycles.com/us/defy-advanced", "", nil)
	if !okGiant || giantRes == nil {
		t.Fatal("expected giant-liv-bikes extractor to match")
	}
	if strings.Contains(giantRes.Markdown, "/shop/") || strings.Contains(giantRes.Markdown, "/cart/") {
		t.Fatalf("expected /shop/ and /cart/ links stripped in giant-liv-bikes geometry table, got:\n%s", giantRes.Markdown)
	}
	if !strings.Contains(giantRes.Markdown, `\](https://evil.test)`) {
		t.Fatalf("expected bracket injection escaped in giant-liv-bikes, got:\n%s", giantRes.Markdown)
	}

	// GO-3 & GO-6: YouTube videoId validation, bracket escaping, and optional whitespace before `{` in "videoDetails" : {
	ytAdversarialHTML := `<!doctype html><html><body><script>var ytInitialPlayerResponse = {"videoDetails"  :  {"videoId":"dQw4w9WgXcQ","title":"Song ](https://evil.test) [Live]","author":"Artist ](https://evil.test)","lengthSeconds":"212"}};</script></body></html>`
	ytMeta := ExtractYouTubeWatchMetadataFromHTML(ytAdversarialHTML, "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if ytMeta == nil {
		t.Fatal("expected YouTube metadata with whitespace in videoDetails : {")
	}
	if !strings.Contains(ytMeta.Markdown, `\](https://evil.test)`) || !strings.Contains(ytMeta.Markdown, `\[Live\]`) {
		t.Fatalf("expected YouTube title/author brackets escaped in Markdown, got:\n%s", ytMeta.Markdown)
	}

	ytBadIDHTML := `<!doctype html><html><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"bad/../../id?x=1","title":"Bad Video","author":"Attacker","lengthSeconds":"10"}};</script></body></html>`
	ytBadMeta := ExtractYouTubeWatchMetadataFromHTML(ytBadIDHTML, "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if ytBadMeta != nil && strings.Contains(ytBadMeta.Markdown, "bad/../../id") {
		t.Fatalf("expected invalid YouTube videoId rejected, got:\n%s", ytBadMeta.Markdown)
	}

	// GO-4: JS object literal comments & bare undefined (preserving '//' inside single-quoted string)
	rawJSObj := `{
		// leading comment
		title: 'https://jobs.example.com/1', /* inline block comment */
		remote: undefined,
		nested: { /* c */ count: 3, empty: undefined, tags: [undefined, 'a//b'] },
		undefinedKey: 'kept'
	}`
	normJSON := normalizeJSObjectLiteralToJSONM4(rawJSObj)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(normJSON), &decoded); err != nil {
		t.Fatalf("expected valid JSON from normalizeJSObjectLiteralToJSONM4, err=%v\njson=%s", err, normJSON)
	}
	if decoded["title"] != "https://jobs.example.com/1" || decoded["remote"] != nil || decoded["undefinedKey"] != "kept" {
		t.Fatalf("unexpected decoded JS object literal: %#v", decoded)
	}
	nested := decoded["nested"].(map[string]any)
	if nested["empty"] != nil {
		t.Fatalf("expected nested undefined converted to null, got %#v", nested)
	}

	// GO-5: Shimano RSC distinct anonymous spec tables of equal length must NOT dedupe onto each other
	rscDistinct := `<!doctype html><html><body><div id="__next">Loading</div><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"spec\":\"{\\\"TableSpecContents\\\":[{\\\"categoryName\\\":\\\"\\\",\\\"specs\\\":[{\\\"specName\\\":\\\"Weight\\\",\\\"specValue\\\":\\\"210g\\\"},{\\\"specName\\\":\\\"Speeds\\\",\\\"specValue\\\":\\\"12\\\"}]},{\\\"categoryName\\\":\\\"\\\",\\\"specs\\\":[{\\\"specName\\\":\\\"Clamp\\\",\\\"specValue\\\":\\\"22.2mm\\\"},{\\\"specName\\\":\\\"Color\\\",\\\"specValue\\\":\\\"Black\\\"}]}]}\"}]\n"])</script></body></html>`
	hydDistinct := RecoverSSRHydrationContent(rscDistinct, "https://productinfo.shimano.com/en/product/RD-M8100", nil)
	if hydDistinct == nil || len(hydDistinct.Records) != 4 {
		t.Fatalf("expected 4 Shimano RSC specs from 2 distinct equal-length anonymous tables, got %+v", hydDistinct)
	}

	// Duplicate anonymous tables MUST still dedupe
	rscDup := `<!doctype html><html><body><div id="__next">Loading</div><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"spec\":\"{\\\"TableSpecContents\\\":[{\\\"categoryName\\\":\\\"\\\",\\\"specs\\\":[{\\\"specName\\\":\\\"Weight\\\",\\\"specValue\\\":\\\"210g\\\"}]},{\\\"categoryName\\\":\\\"\\\",\\\"specs\\\":[{\\\"specName\\\":\\\"Weight\\\",\\\"specValue\\\":\\\"210g\\\"}]}]}\"}]\n"])</script></body></html>`
	hydDup := RecoverSSRHydrationContent(rscDup, "https://productinfo.shimano.com/en/product/RD-M8100", nil)
	if hydDup == nil || len(hydDup.Records) != 1 {
		t.Fatalf("expected duplicate anonymous Shimano RSC table deduped to 1 record, got %+v", hydDup)
	}

	// GO-6: NuGet count=1e20 overflow clamp & backtick escaping in inline code cells
	nugetRaw := []byte(`{
		"count": 1e20,
		"items": [{
			"@id": "https://api.nuget.org/v3/registration5-gz-semver2/evil` + "`" + `pkg/index.json#page/1.0.0/2.0.0",
			"lower": "1.0.0` + "`" + `bad",
			"upper": "2.0.0",
			"count": 1e20,
			"items": [{
				"catalogEntry": {
					"id": "Evil` + "`" + `Pkg",
					"version": "1.0.0` + "`" + `[x]",
					"listed": true,
					"summary": "Test summary"
				}
			}]
		}]
	}`)
	nugetDoc, okNuGet := formatNuGetRegistrationJSONGo(nugetRaw, map[string]string{"pkg": "evilpkg"}, "https://www.nuget.org/packages/evilpkg")
	if !okNuGet || nugetDoc == nil {
		t.Fatal("expected formatNuGetRegistrationJSONGo to succeed")
	}
	if strings.Contains(nugetDoc.Markdown, "-9223372036854775808") {
		t.Fatalf("expected NuGet count overflow clamped instead of wrapping negative, got:\n%s", nugetDoc.Markdown)
	}
	if !strings.Contains(nugetDoc.Markdown, "`dotnet add package Evil'Pkg --version 1.0.0'[x]`") ||
		!strings.Contains(nugetDoc.Markdown, "- **Version**: `1.0.0'[x]`") ||
		!strings.Contains(nugetDoc.Markdown, "| `1.0.0'[x]` |") {
		t.Fatalf("expected NuGet inline-code backticks escaped, got:\n%s", nugetDoc.Markdown)
	}
}

func TestTier5R2GO3AndR2GO4AdversarialBoundaries(t *testing.T) {
	// R2-GO-3: normalizeJSObjectLiteralToJSONM4 handles JS regex literals containing // and /* */
	regexJS := `{ regex: /https?:\/\//i, re2: /\/\*comment\*\//g, Title: 'Engineer', Department: undefined }`
	normRegex := normalizeJSObjectLiteralToJSONM4(regexJS)
	var regexDecoded map[string]any
	if err := json.Unmarshal([]byte(normRegex), &regexDecoded); err != nil {
		t.Fatalf("R2-GO-3: expected valid JSON with regex literals, err=%v\njson=%s", err, normRegex)
	}
	if regexDecoded["Title"] != "Engineer" || regexDecoded["Department"] != nil {
		t.Fatalf("R2-GO-3: unexpected decoded fields: %#v", regexDecoded)
	}

	// R2-GO-3: End-to-end Paylocity & UKG Pro extraction with single-quoted '{'/'}', '//' & '/*' comments, and regex literals
	paylocityHTML := `<!doctype html><html><head><title>Careers</title></head><body><script>
	window.pageData = {
		// comment with } brace
		UrlPattern: /https?:\/\//i,
		/* block comment } with { braces */
		Jobs: [{ JobId: 101, Title: 'Senior {Go} Dev } Lead', Department: undefined }]
	};
	</script></body></html>`
	payRes, okPay := ApplyDeclarativeHTMLExtractor(paylocityHTML, "https://recruiting.paylocity.com/Recruiting/Jobs/All/aaaa-bbbb", "", nil)
	if !okPay || payRes == nil || len(payRes.Records) != 1 || payRes.Records[0]["title"] != "Senior {Go} Dev } Lead" {
		t.Fatalf("R2-GO-3: expected Paylocity JS-aware extraction to succeed, got ok=%v res=%+v", okPay, payRes)
	}

	ukgHTML := `<!doctype html><html><head><title>UKG Careers</title></head><body><script>
	window.__PRELOADED_STATE__ = {
		/* } comment */
		Matcher: /\/\*abc\*\//g,
		// another } comment
		opportunities: [{ Id: 'u1', Title: 'Role } 1', Extra: undefined }]
	};
	</script></body></html>`
	ukgRes, okUkg := ApplyDeclarativeHTMLExtractor(ukgHTML, "https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555", "", nil)
	if !okUkg || ukgRes == nil || len(ukgRes.Records) != 1 || ukgRes.Records[0]["title"] != "Role } 1" {
		t.Fatalf("R2-GO-3: expected UKG Pro JS-aware extraction to succeed, got ok=%v res=%+v", okUkg, ukgRes)
	}

	// R2-GO-4 (a): Shimano RSC >8-spec anonymous tables differing only at spec >= 9 must NOT collide
	makeNineSpecs := func(val9 string) map[string]any {
		specs := make([]map[string]string, 0, 9)
		for i := 1; i <= 8; i++ {
			specs = append(specs, map[string]string{
				"specName":  "Spec" + string(rune('0'+i)),
				"specValue": "Shared",
			})
		}
		specs = append(specs, map[string]string{"specName": "Spec9", "specValue": val9})
		return map[string]any{"categoryName": "", "specs": specs}
	}
	innerRSC, _ := json.Marshal(map[string]any{
		"TableSpecContents": []any{makeNineSpecs("ValA"), makeNineSpecs("ValB")},
	})
	rscPayloadLine, _ := json.Marshal([]any{"$", "div", nil, map[string]any{"spec": string(innerRSC)}})
	rscChunk, _ := json.Marshal([]any{1, "5:" + string(rscPayloadLine) + "\n"})
	rscNineHTML := `<!doctype html><html><body><div id="__next">Loading</div><script>self.__next_f.push(` + string(rscChunk) + `)</script></body></html>`
	hydNine := RecoverSSRHydrationContent(rscNineHTML, "https://productinfo.shimano.com/en/product/RD-M8100", nil)
	if hydNine == nil || len(hydNine.Records) != 18 {
		t.Fatalf("R2-GO-4(a): expected 18 specs from two distinct 9-spec Shimano RSC tables, got %+v", hydNine)
	}

	// R2-GO-4 (b): mode: dom inline-code `{sku}` neutralizes backticks, newlines, and pipes
	for _, tc := range []struct {
		urlStr string
		html   string
	}{
		{
			urlStr: "https://bumm.de/en/product-detail/iq-x.html",
			html:   `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"IQ-X","sku":"SKU` + "`" + `|inj\n## Phish|[x](https://evil.example)"}</script></head><body><main><h1>IQ-X</h1><p>Headlight</p></main></body></html>`,
		},
		{
			urlStr: "https://www.sram.com/en/sram/models/rd-xx-e-b1",
			html:   `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"XX Eagle","sku":"SKU` + "`" + `|inj|[x](https://evil.example)"}</script></head><body><main class="product-detail"><h1>XX Eagle</h1><p>Derailleur</p></main></body></html>`,
		},
		{
			urlStr: "https://www.tq-ebike.com/en/products/hpr50",
			html:   `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"HPR50","sku":"SKU` + "`" + `|inj|[x](https://evil.example)"}</script></head><body><main><h1>HPR50</h1><p>Drive</p></main></body></html>`,
		},
	} {
		domRes, okDom := ApplyDeclarativeHTMLExtractor(tc.html, tc.urlStr, "", nil)
		if !okDom || domRes == nil {
			t.Fatalf("R2-GO-4(b): expected %s extraction to succeed", tc.urlStr)
		}
		if strings.Contains(domRes.Markdown, "\n## Phish") {
			t.Fatalf("R2-GO-4(b): SKU newline breakout in %s:\n%s", tc.urlStr, domRes.Markdown)
		}
		if !strings.Contains(domRes.Markdown, "`SKU'&#124;") {
			t.Fatalf("R2-GO-4(b): expected neutralized inline code SKU in %s, got:\n%s", tc.urlStr, domRes.Markdown)
		}
		for _, ln := range strings.Split(domRes.Markdown, "\n") {
			if strings.HasPrefix(ln, "- **SKU**:") && strings.Count(ln, "`") != 2 {
				t.Fatalf("R2-GO-4(b): expected exactly 2 backticks on SKU line in %s, got %q", tc.urlStr, ln)
			}
		}
	}

	// R2-GO-4 (c): YouTube videoDetails title/author newlines must not inject headings or break bullets
	ytNewlineHTML := `<!doctype html><html><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"nl123456789","title":"Cool Video\n\n## Phish","author":"Channel\\\n## Evil","lengthSeconds":"120"}};</script></body></html>`
	ytNL := ExtractYouTubeWatchMetadataFromHTML(ytNewlineHTML, "https://www.youtube.com/watch?v=nl123456789")
	if ytNL == nil {
		t.Fatal("R2-GO-4(c): expected YouTube metadata")
	}
	if strings.Contains(ytNL.Markdown, "\n## Phish") || strings.Contains(ytNL.Markdown, "\n## Evil") {
		t.Fatalf("R2-GO-4(c): YouTube title/author newline injected heading:\n%s", ytNL.Markdown)
	}
	if !strings.Contains(ytNL.Markdown, "# Cool Video ## Phish") || !strings.Contains(ytNL.Markdown, "- **Channel**: Channel") {
		t.Fatalf("R2-GO-4(c): expected single-line H1 and Channel bullet, got:\n%s", ytNL.Markdown)
	}

	// R2-GO-4 (d): Bosch eBike Help split-bracket breadcrumbs escaped per anchor
	boschSplitHTML := `<!doctype html><html><body><nav aria-label="Breadcrumb"><a href="/a">A [b</a><a href="/c">c](https://evil.example)</a></nav><main><h1>Help</h1><p>Battery charging steps.</p></main></body></html>`
	boschRes, okBosch := ApplyDeclarativeHTMLExtractor(boschSplitHTML, "https://help.bosch-ebike.com/en/help-center/ebike-battery-charging", "", nil)
	if !okBosch || boschRes == nil {
		t.Fatal("R2-GO-4(d): expected bosch-ebike-help extraction")
	}
	if hasUnescapedClickableEvilLinkR10(boschRes.Markdown) {
		t.Fatalf("R2-GO-4(d): split-bracket breadcrumb formed clickable link:\n%s", boschRes.Markdown)
	}
	if !strings.Contains(boschRes.Markdown, `A \[b › c\]`) {
		t.Fatalf("R2-GO-4(d): expected escaped brackets on breadcrumbs, got:\n%s", boschRes.Markdown)
	}

	// R2-GO-4 (e): localhost.localdomain blocked in declarative SSRF check
	if IsSafeDeclarativeTwinURL("https://localhost.localdomain/items/1") {
		t.Fatal("R2-GO-4(e): expected IsSafeDeclarativeTwinURL to reject localhost.localdomain")
	}
}

func TestTier5R3GO4and5_JSParserAndMarkdownEscaping(t *testing.T) {
	// R3-GO-4: extractBalancedJSObjectAtM4 & normalizeJSObjectLiteralToJSONM4 with return /}/, !/a/*b/, backticks, ${...}, \xHH, and 10 / 2
	advPaylocity := `<!doctype html><html><head><title>Careers</title></head><body><script>
	window.pageData = {
		helper: function() { return /}/; },
		ok: !/a/*b/.test("x"),
		ratio: 10 / 2,
		tpl: ` + "`hi ${fn(\"`\")}`" + `,
		note: ` + "`hello world`" + `,
		hex: '\x41\x42',
		Jobs: [{ JobId: 701, Title: ` + "`Staff \\x47o Dev`" + `, Department: undefined }]
	};
	</script></body></html>`
	advPayRes, okAdvPay := ApplyDeclarativeHTMLExtractor(advPaylocity, "https://recruiting.paylocity.com/Recruiting/Jobs/All/1111-2222", "", nil)
	if !okAdvPay || advPayRes == nil || len(advPayRes.Records) != 1 || advPayRes.Records[0]["title"] != "Staff Go Dev" {
		t.Fatalf("R3-GO-4: expected Paylocity extraction with return /}/, !/a/*b/, template literals, and \\xHH, got ok=%v res=%+v", okAdvPay, advPayRes)
	}

	rawObj := `{ fn: function() { return /}/; }, ok: !/a/*b/.test("x"), ratio: 10 / 2, tpl: ` + "`hi ${fn(\"`\")}`" + `, note: ` + "`hello`" + `, hex: '\x41', Jobs: [{ Title: 'OK' }] }`
	norm := normalizeJSObjectLiteralToJSONM4(rawObj)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(norm), &parsed); err != nil {
		t.Fatalf("R3-GO-4: json.Unmarshal failed on normalized JS object: %v\nnorm=%s", err, norm)
	}
	if parsed["note"] != "hello" || parsed["hex"] != "A" {
		t.Fatalf("R3-GO-4: unexpected normalized values: %#v", parsed)
	}

	// R3-GO-5 (a): bumm-de non-backtick bullet metadata value escaping
	bummHostile := `<!doctype html><html><head><script type="application/ld+json">{"@type":"Product","name":"IQ-X","brand":{"name":"Bumm [phish](https://evil.com/b)"},"sku":"S1"}</script></head><body><main><h1>IQ-X</h1><p>Light</p></main></body></html>`
	bummDoc, okBumm := ApplyDeclarativeHTMLExtractor(bummHostile, "https://bumm.de/en/product-detail/iq-x.html", "", nil)
	if !okBumm || bummDoc == nil || hasUnescapedClickableEvilLinkR10(bummDoc.Markdown) {
		t.Fatalf("R3-GO-5: bumm-de brand injected clickable Markdown link:\n%+v", bummDoc)
	}

	// R3-GO-5 (b): giant-liv-bikes spec label/value & title escaping
	giantHostile := `<!doctype html><html><body><main><h1>Defy [x](https://evil.com/t)</h1><section id="specifications"><ul><li class="datarow"><span class="label">Frame [x](https://evil.com/l)</span><span class="value">Carbon [v](https://evil.com/v)</span></li></ul></section></main></body></html>`
	giantDoc, okGiant := ApplyDeclarativeHTMLExtractor(giantHostile, "https://www.giant-bicycles.com/us/defy-advanced", "", nil)
	if !okGiant || giantDoc == nil || hasUnescapedClickableEvilLinkR10(giantDoc.Markdown) {
		t.Fatalf("R3-GO-5: giant-liv-bikes leaked clickable Markdown link:\n%+v", giantDoc)
	}

	// R3-GO-5 (c): nfpa Sitecore JSS title/heading escaping
	nfpaHostile := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"placeholders":{"storefront-main":[{"componentName":"PageTitle","fields":{"Title":{"value":"NFPA 70 [phish](https://evil.com/t)"}}},{"componentName":"ContentBlock","fields":{"Heading":{"value":"Sec 1 [phish](https://evil.com/h)"},"Content":{"value":"<p>Safe text.</p>"}}}]}}}}}}}</script></body></html>`
	nfpaDoc, okNfpa := ApplyDeclarativeHTMLExtractor(nfpaHostile, "https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70", "", nil)
	if !okNfpa || nfpaDoc == nil || hasUnescapedClickableEvilLinkR10(nfpaDoc.Markdown) {
		t.Fatalf("R3-GO-5: nfpa leaked clickable Markdown link:\n%+v", nfpaDoc)
	}

	// R3-GO-5 (d): sap-rmk-jibe JSON & XML table backtick, bracket, and URL paren escaping
	jibeTwin, okJibe := ResolveDeclarativeTwin("https://careers.rivian.com/api/jobs?page=1&limit=25")
	if !okJibe || jibeTwin == nil {
		t.Fatal("expected sap-rmk-jibe twin")
	}
	jibePayload, _ := json.Marshal(map[string]any{
		"totalCount": 1,
		"jobs": []map[string]any{{
			"data": map[string]any{
				"title":         "Role [x](https://evil.com/r)",
				"req_id":        "R1`|x",
				"category":      "Eng [c](https://evil.com/c)",
				"full_location": "NY [l](https://evil.com/l)",
				"apply_url":     "https://careers.rivian.com/jobs/1)bad",
			},
		}},
	})
	jibeDoc, okJibeFmt := jibeTwin.Format(string(jibePayload))
	if !okJibeFmt || jibeDoc == nil {
		t.Fatal("expected sap-rmk-jibe format to succeed")
	}
	if hasUnescapedClickableEvilLinkR10(jibeDoc.Markdown) || strings.Contains(jibeDoc.Markdown, "/jobs/1)bad)") || !strings.Contains(jibeDoc.Markdown, "`R1'&#124;x`") || !strings.Contains(jibeDoc.Markdown, "1%29bad") {
		t.Fatalf("R3-GO-5: sap-rmk-jibe failed cell/link escaping:\n%s", jibeDoc.Markdown)
	}

	rmkXML := `<rss xmlns:g="http://base.google.com/ns/1.0"><channel><item><title>Eng [x](https://evil.com/r)</title><link>https://jobs.sap.com/job/1)bad</link><g:id>S1` + "`" + `|y</g:id><g:location>Remote [l](https://evil.com/l)</g:location><g:employer>SAP</g:employer></item></channel></rss>`
	rmkDoc, okRmk := ApplyDeclarativeHTMLExtractor(rmkXML, "https://jobs.sap.com/sitemap.xml", "", nil)
	if !okRmk || rmkDoc == nil || hasUnescapedClickableEvilLinkR10(rmkDoc.Markdown) || strings.Contains(rmkDoc.Markdown, "1)bad") || len(rmkDoc.Links) != 0 {
		t.Fatalf("R3-GO-5: sap-rmk XML table failed escaping:\n%+v", rmkDoc)
	}
}

func TestTier5R4GO3AndR4GO5_SitecoreGiantEscapingAndJSContinuationsShorthand(t *testing.T) {
	// R4-GO-3d: sitecore_jss_html plain-text Subtitle / Content / Items.Body escaping
	nfpaPlain := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">` +
		`{"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"placeholders":{"storefront-main":[` +
		`{"componentName":"PageTitle","fields":{"Title":{"value":"NFPA 70"},"Subtitle":{"value":"Sub [Phish](https://evil.com/sub)\n\n## FakeSub"}}},` +
		`{"componentName":"ContentBlock","fields":{"Heading":{"value":"Section 1"},"Content":{"value":"Plain body [Click](https://evil.com/body)\n\n## FakeBody"},"Items":[{"heading":{"value":"Item 1"},"body":{"value":"Item plain [Link](https://evil.com/item)"}}]}}` +
		`]}}}}}}}</script></body></html>`
	nfpaDoc, okNfpa := ApplyDeclarativeHTMLExtractor(nfpaPlain, "https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70", "", nil)
	if !okNfpa || nfpaDoc == nil {
		t.Fatal("R4-GO-3d: expected nfpa sitecore_jss_html extraction")
	}
	if hasUnescapedClickableEvilLinkR10(nfpaDoc.Markdown) ||
		strings.Contains(nfpaDoc.Markdown, "\n## FakeSub") ||
		strings.Contains(nfpaDoc.Markdown, "\n## FakeBody") {
		t.Fatalf("R4-GO-3d: sitecore_jss_html leaked clickable link or heading:\n%s", nfpaDoc.Markdown)
	}
	if !strings.Contains(nfpaDoc.Markdown, `Sub \[Phish\]`) || !strings.Contains(nfpaDoc.Markdown, `Plain body \[Click\]`) || !strings.Contains(nfpaDoc.Markdown, `Item plain \[Link\]`) {
		t.Fatalf("R4-GO-3d: expected escaped brackets in plain-text Sitecore JSS fields, got:\n%s", nfpaDoc.Markdown)
	}

	// R4-GO-3e: giant_liv_html <main> p fallback when manualLinks present and no specs/geometry
	giantFallbackHTML := `<!doctype html><html><body><main><h1>Defy Advanced</h1>` +
		`<a href="https://static.giant-bicycles.com/Manuals/Defy.pdf">Owner Manual</a>` +
		`<p>Read notice [Phish](https://evil.com/giant) immediately.` + "\n## FakeGiant" + `</p>` +
		`</main></body></html>`
	giantDoc, okGiant := ApplyDeclarativeHTMLExtractor(giantFallbackHTML, "https://www.giant-bicycles.com/us/defy-advanced", "", nil)
	if !okGiant || giantDoc == nil {
		t.Fatal("R4-GO-3e: expected giant-liv-bikes extraction")
	}
	if hasUnescapedClickableEvilLinkR10(giantDoc.Markdown) || strings.Contains(giantDoc.Markdown, "\n## FakeGiant") {
		t.Fatalf("R4-GO-3e: giant_liv_html <main> p fallback leaked link or heading:\n%s", giantDoc.Markdown)
	}
	if !strings.Contains(giantDoc.Markdown, `Read notice \[Phish\]`) {
		t.Fatalf("R4-GO-3e: expected escaped brackets in <main> p fallback, got:\n%s", giantDoc.Markdown)
	}

	// R4-GO-5 (a): JS string line continuations (\+\n, \+\r\n, \+\r) and raw control bytes (< 0x20)
	jsLineCont := "{\n\tTitle: \"Staff \\\nGo \\\r\nDev \\\rLead\",\n\tCtrl: \"A\\\x07B\",\n\tTpl: `Line \\\nJoined`\n}"
	normCont := normalizeJSObjectLiteralToJSONM4(jsLineCont)
	var contDecoded map[string]any
	if err := json.Unmarshal([]byte(normCont), &contDecoded); err != nil {
		t.Fatalf("R4-GO-5: json.Unmarshal failed on line-continuation JS object: %v\nnorm=%s", err, normCont)
	}
	if contDecoded["Title"] != "Staff Go Dev Lead" || contDecoded["Ctrl"] != "A\x07B" || contDecoded["Tpl"] != "Line Joined" {
		t.Fatalf("R4-GO-5: unexpected line-continuation decoded values: %#v", contDecoded)
	}

	// R4-GO-5 (b): ES6 shorthand methods & async/get/set/quoted shorthand methods in object literals
	jsShorthand := `{
		helper() { return /}/; },
		async fetchItems(a = { nested: 1 }) { const re = /[{}\n]/; return a; },
		get count() { return 1; },
		'quotedMethod'(x) { return x; },
		Jobs: [{ JobId: 901, Title: "Staff \\\nGo Dev", Department: undefined }]
	}`
	normShort := normalizeJSObjectLiteralToJSONM4(jsShorthand)
	var shortDecoded map[string]any
	if err := json.Unmarshal([]byte(normShort), &shortDecoded); err != nil {
		t.Fatalf("R4-GO-5: json.Unmarshal failed on ES6 shorthand object: %v\nnorm=%s", err, normShort)
	}

	// End-to-end Paylocity (line continuation) & UKG (ES6 shorthand method with return /}/;)
	plcContHTML := "<!doctype html><html><body><script>window.pageData = { Jobs: [{ JobId: 12, Title: \"Staff \\\nGo Dev\" }] };</script></body></html>"
	plcDoc, okPlc := ApplyDeclarativeHTMLExtractor(plcContHTML, "https://recruiting.paylocity.com/Recruiting/Jobs/All/1111-2222", "", nil)
	if !okPlc || plcDoc == nil || len(plcDoc.Records) != 1 || plcDoc.Records[0]["title"] != "Staff Go Dev" {
		t.Fatalf("R4-GO-5: Paylocity line continuation failed: ok=%v doc=%+v", okPlc, plcDoc)
	}

	ukgShortHTML := `<!doctype html><html><body><script>window.__PRELOADED_STATE__ = { helper() { return /}/; }, opportunities: [{ Id: 'u9', Title: 'Method Safe Role' }] };</script></body></html>`
	ukgDoc, okUkg := ApplyDeclarativeHTMLExtractor(ukgShortHTML, "https://recruiting.ultipro.com/UKG1001/JobBoard/11111111-2222-3333-4444-555555555555", "", nil)
	if !okUkg || ukgDoc == nil || len(ukgDoc.Records) != 1 || ukgDoc.Records[0]["title"] != "Method Safe Role" {
		t.Fatalf("R4-GO-5: UKG ES6 shorthand method failed: ok=%v doc=%+v", okUkg, ukgDoc)
	}
}

func TestTier5R5GO1ThroughR5GO5(t *testing.T) {
	// R5-GO-1: formatJSONTwin BlockquoteTemplate, FooterItalicTemplate, IntroVar, non-Markdown sec.TextVar escaping
	// while preserving Markdown-formatted vars (se_markdown / html_to_md / composed linkedEmbed).
	mastodonTwin, okMast := ResolveDeclarativeTwin("https://mastodon.social/@alice/113456789012345678")
	if !okMast || mastodonTwin == nil {
		t.Fatal("expected mastodon twin")
	}
	mastDoc, okMastFmt := mastodonTwin.Format(`{"content":"<p>Hello world</p>","spoiler_text":"[Phish](https://evil.com/m)\n## Injected Mastodon","account":{"acct":"alice","display_name":"Alice"},"created_at":"2026-11-26T00:00:00Z"}`)
	if !okMastFmt || mastDoc == nil {
		t.Fatal("expected mastodon format to succeed")
	}
	if hasUnescapedClickableEvilLinkR10(mastDoc.Markdown) || strings.Contains(mastDoc.Markdown, "\n## Injected Mastodon") {
		t.Fatalf("R5-GO-1: mastodon spoiler_text leaked link or broke blockquote:\n%s", mastDoc.Markdown)
	}

	wdTwin, okWd := ResolveDeclarativeTwin("https://www.wikidata.org/wiki/Q42")
	if !okWd || wdTwin == nil {
		t.Fatal("expected wikidata twin")
	}
	wdDoc, okWdFmt := wdTwin.Format(`{"entities":{"Q42":{"labels":{"en":{"value":"Douglas Adams"}},"descriptions":{"en":{"value":"[EvilWD](https://evil.com/wd)\n## Fake WD Section"}}}}}`)
	if !okWdFmt || wdDoc == nil {
		t.Fatal("expected wikidata format to succeed")
	}
	if hasUnescapedClickableEvilLinkR10(wdDoc.Markdown) || strings.Contains(wdDoc.Markdown, "\n## Fake WD Section") {
		t.Fatalf("R5-GO-1: wikidata IntroVar leaked link or heading:\n%s", wdDoc.Markdown)
	}

	cpscTwin, okCpsc := ResolveDeclarativeTwin("https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=24-123")
	if !okCpsc || cpscTwin == nil {
		t.Fatal("expected cpsc-recalls twin")
	}
	cpscDoc, okCpscFmt := cpscTwin.Format(`[{"RecallNumber":"24123","Title":"Helmet Recall","RecallDate":"2024-03-14","Description":"[PhishCPSC](https://evil.com/cpsc)\n## Fake Recall Section","URL":"https://www.cpsc.gov/Recalls/2024/Helmet"}]`)
	if !okCpscFmt || cpscDoc == nil {
		t.Fatal("expected cpsc format to succeed")
	}
	if hasUnescapedClickableEvilLinkR10(cpscDoc.Markdown) || strings.Contains(cpscDoc.Markdown, "\n## Fake Recall Section") {
		t.Fatalf("R5-GO-1: cpsc TextVar leaked link or heading:\n%s", cpscDoc.Markdown)
	}

	bskyTwin, okBsky := ResolveDeclarativeTwin("https://bsky.app/profile/alice.bsky.social/post/3kabcdef123")
	if !okBsky || bskyTwin == nil {
		t.Fatal("expected bluesky twin")
	}
	bskyDoc, okBskyFmt := bskyTwin.Format(`{"thread":{"post":{"author":{"handle":"alice.bsky.social","displayName":"Alice"},"record":{"text":"Main post","createdAt":"2026-11-26T00:00:00Z"},"likeCount":5,"repostCount":1,"embed":{"external":{"uri":"https://example.org/article","title":"Legit Article","description":"[Bad](https://evil.com/bsky)\n## Fake"}}}}} `)
	if !okBskyFmt || bskyDoc == nil {
		t.Fatal("expected bluesky format to succeed")
	}
	if !strings.Contains(bskyDoc.Markdown, "[Legit Article](https://example.org/article)") || hasUnescapedClickableEvilLinkR10(bskyDoc.Markdown) {
		t.Fatalf("R5-GO-1: bluesky must preserve composed linkedEmbed while escaping inner extDesc:\n%s", bskyDoc.Markdown)
	}

	seTwin, okSe := ResolveDeclarativeTwin("https://stackoverflow.com/questions/123456/how-to-test")
	if !okSe || seTwin == nil {
		t.Fatal("expected stackexchange twin")
	}
	seDoc, okSeFmt := seTwin.Format(`{"items":[{"title":"How to test","score":10,"tags":["go"],"body_markdown":"See [Go docs](https://go.dev/doc/) for details.","link":"https://stackoverflow.com/questions/123456/how-to-test"}]}`)
	if !okSeFmt || seDoc == nil || !strings.Contains(seDoc.Markdown, "[Go docs](https://go.dev/doc/)") {
		t.Fatalf("R5-GO-1: stackexchange se_markdown link must be preserved, got:\n%+v", seDoc)
	}

	// R5-GO-2: runDomRouteDeclHTML (arxiv plain text vs pkg.go.dev cssHtmlToMd), icims_portal, nuget.go, dover_html
	arxivHTML := `<!doctype html><html><head><title>[2501.00001] Paper</title><meta name="citation_title" content="Safe Paper"></head><body><blockquote class="abstract">Abstract: [Click Evil](https://evil.com/arxiv)` + "\n## Fake Arxiv" + `</blockquote></body></html>`
	arxivDoc, okArxiv := ApplyDeclarativeHTMLExtractor(arxivHTML, "https://arxiv.org/abs/2501.00001", "", nil)
	if !okArxiv || arxivDoc == nil || hasUnescapedClickableEvilLinkR10(arxivDoc.Markdown) || strings.Contains(arxivDoc.Markdown, "\n## Fake Arxiv") {
		t.Fatalf("R5-GO-2: arxiv TextVar leaked link or heading:\n%+v", arxivDoc)
	}

	pkgGoHTML := `<!doctype html><html><head><title>ws - Go Packages</title></head><body><div class="UnitReadme-content"><p>Read <a href="https://go.dev/doc/">the docs</a>.</p></div></body></html>`
	pkgGoDoc, okPkgGo := ApplyDeclarativeHTMLExtractor(pkgGoHTML, "https://pkg.go.dev/github.com/coder/websocket", "", nil)
	if !okPkgGo || pkgGoDoc == nil || !strings.Contains(pkgGoDoc.Markdown, "[the docs](https://go.dev/doc/)") {
		t.Fatalf("R5-GO-2: pkg.go.dev cssHtmlToMd must preserve Markdown links, got:\n%+v", pkgGoDoc)
	}

	icimsSingleHTML := `<!doctype html><html><head><script type="application/ld+json">{"@type":"JobPosting","title":"Software Engineer","hiringOrganization":{"name":"[EvilCorp](https://evil.com/icims)"},"jobLocation":{"address":{"addressLocality":"[PhishLoc](https://evil.com/loc)","addressRegion":"CA","addressCountry":"US"}},"employmentType":"[EvilType](https://evil.com/emp)","description":"<p>Build reliable services.</p>"}</script></head><body></body></html>`
	icimsSingleDoc, okIcimsS := ApplyDeclarativeHTMLExtractor(icimsSingleHTML, "https://careers-acme.icims.com/jobs/101/swe/job?in_iframe=1", "", nil)
	if !okIcimsS || icimsSingleDoc == nil || hasUnescapedClickableEvilLinkR10(icimsSingleDoc.Markdown) {
		t.Fatalf("R5-GO-2: icims single job leaked clickable link:\n%+v", icimsSingleDoc)
	}

	icimsBoardHTML := `<!doctype html><html><body><h1 class="iCIMS_Header">[EvilCo](https://evil.com/hdr) Careers</h1><div class="iCIMS_JobsTable"><div class="row"><a class="iCIMS_Anchor" href="/jobs/999/swe/job"><h3>[Fake Link](https://evil.com/job)</h3></a><dl><dt>Location</dt><dd>[LocPhish](https://evil.com/l)</dd><dt>Pay</dt><dd>[PayPhish](https://evil.com/p)</dd></dl></div></div></body></html>`
	icimsBoardDoc, okIcimsB := ApplyDeclarativeHTMLExtractor(icimsBoardHTML, "https://careers-acme.icims.com/jobs/search?in_iframe=1", "", nil)
	if !okIcimsB || icimsBoardDoc == nil || hasUnescapedClickableEvilLinkR10(icimsBoardDoc.Markdown) {
		t.Fatalf("R5-GO-2: icims board leaked clickable link:\n%+v", icimsBoardDoc)
	}

	nugetHostile := `{"count":1,"items":[{"lower":"1.0.0","upper":"1.0.0","items":[{"catalogEntry":{"id":"EvilPkg","version":"1.0.0","listed":true,"description":"[Phish NuGet](https://evil.com/nuget)\n## Injected NuGet Heading"}}]}]}`
	nugetHostileDoc, okNuGetH := formatNuGetRegistrationJSONGo([]byte(nugetHostile), map[string]string{"pkg": "evilpkg"}, "https://www.nuget.org/packages/evilpkg")
	if !okNuGetH || nugetHostileDoc == nil || hasUnescapedClickableEvilLinkR10(nugetHostileDoc.Markdown) || strings.Contains(nugetHostileDoc.Markdown, "\n## Injected NuGet Heading") {
		t.Fatalf("R5-GO-2: nuget desc leaked link or heading:\n%+v", nugetHostileDoc)
	}

	doverHostileHTML := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"company":{"name":"[EvilDoverCo](https://evil.com/dover)","slug":"acme"},"jobs":[{"id":"d1","title":"Eng","slug":"eng"}]}}}</script></body></html>`
	doverHostileDoc, okDoverH := ApplyDeclarativeHTMLExtractor(doverHostileHTML, "https://app.dover.com/jobs/acme", "", nil)
	if !okDoverH || doverHostileDoc == nil || hasUnescapedClickableEvilLinkR10(doverHostileDoc.Markdown) {
		t.Fatalf("R5-GO-2: dover_html boardTitle leaked clickable link:\n%+v", doverHostileDoc)
	}

	// R5-GO-3: formatters.go (vCard, iCalendar, FeedXML, OpenAPI)
	vcardDoc := FormatVCardToMarkdown("BEGIN:VCARD\nVERSION:3.0\nFN:[EvilVC](https://evil.com/vc)\nORG:[EvilOrg](https://evil.com/org)\nNOTE:[EvilNote](https://evil.com/n)\nEND:VCARD")
	if vcardDoc == nil || hasUnescapedClickableEvilLinkR10(vcardDoc.Markdown) {
		t.Fatalf("R5-GO-3: vCard leaked clickable link:\n%+v", vcardDoc)
	}

	icsDoc := FormatICalendarToMarkdown("BEGIN:VCALENDAR\nVERSION:2.0\nX-WR-CALNAME:[EvilCal](https://evil.com/cal)\nBEGIN:VEVENT\nSUMMARY:[EvilEv](https://evil.com/ev)\nLOCATION:[EvilLoc](https://evil.com/loc)\nDESCRIPTION:[EvilDesc](https://evil.com/d)\nEND:VEVENT\nEND:VCALENDAR")
	if icsDoc == nil || hasUnescapedClickableEvilLinkR10(icsDoc.Markdown) {
		t.Fatalf("R5-GO-3: iCalendar leaked clickable link:\n%+v", icsDoc)
	}

	feedDoc, _ := FormatFeedXMLToMarkdown(`<?xml version="1.0"?><rss version="2.0"><channel><title>[EvilFeed](https://evil.com/f)</title><description>[EvilFeedDesc](https://evil.com/fd)</description><item><title>[EvilItem](https://evil.com/it)</title><link>https://example.org/post/1</link><description>[EvilBody](https://evil.com/ib)</description></item></channel></rss>`, "https://example.org/feed.xml")
	if feedDoc == nil || hasUnescapedClickableEvilLinkR10(feedDoc.Markdown) || !strings.Contains(feedDoc.Markdown, `## [\[EvilItem\]\(https://evil.com/it)](https://example.org/post/1)`) {
		t.Fatalf("R5-GO-3: FeedXML failed escaping or link-wrapper preservation:\n%+v", feedDoc)
	}

	openAPIDoc := FormatOpenAPISpecToMarkdown(`{"openapi":"3.0.0","info":{"title":"[EvilAPI](https://evil.com/api)","version":"1.0","description":"[EvilDesc](https://evil.com/desc)\n## Fake OA Heading"},"paths":{"/users":{"get":{"summary":"[EvilSum](https://evil.com/sum)","responses":{"200":{"description":"[EvilResp](https://evil.com/resp)"}}}}}}`, "https://example.org/openapi.json")
	if openAPIDoc == nil || hasUnescapedClickableEvilLinkR10(openAPIDoc.Markdown) || strings.Contains(openAPIDoc.Markdown, "\n## Fake OA Heading") {
		t.Fatalf("R5-GO-3: OpenAPI leaked clickable link or heading:\n%+v", openAPIDoc)
	}

	// R5-GO-4: JS object literal edge cases (*gen, async *agen, [computed], numeric keys, shorthand props, regex after if(...), \0, \u{...})
	jsEdge := `{
		*gen() { yield 1; },
		async *agen() { if (a) /}/.test(x); yield 2; },
		[symKey]: 1,
		[symMethod]() { return 2; },
		0: "first",
		extraFlag,
		nulStr: "a\x00\0b",
		uniStr: "hi \u{1F600} \u{41}",
		tplStr: ` + "`tpl \\0 \\u{1F600}`" + `,
		"opportunities": [{"id":"1","title":"OK"}]
	}`
	normEdge := normalizeJSObjectLiteralToJSONM4(jsEdge)
	var edgeDecoded map[string]any
	if err := json.Unmarshal([]byte(normEdge), &edgeDecoded); err != nil {
		t.Fatalf("R5-GO-4: expected valid JSON for JS edge cases, err=%v\nnorm=%s", err, normEdge)
	}
	if edgeDecoded["0"] != "first" || edgeDecoded["nulStr"] != "a\x00\x00b" || edgeDecoded["uniStr"] != "hi 😀 A" || edgeDecoded["tplStr"] != "tpl \x00 😀" {
		t.Fatalf("R5-GO-4: unexpected decoded edge values: %#v", edgeDecoded)
	}

	ukgEdgeHTML := `<!doctype html><html><body><script>window.__PRELOADED_STATE__ = { *gen() { if (a) /}/.test(x); }, [dynKey]: 1, 0: "zero", extraFlag, opportunities: [{ Id: 'u55', Title: 'R5 JS Lexer Role' }] };</script></body></html>`
	ukgEdgeDoc, okUkgEdge := ApplyDeclarativeHTMLExtractor(ukgEdgeHTML, "https://recruiting.ultipro.com/R5CO/JobBoard/11111111-2222-3333-4444-555555555555", "", nil)
	if !okUkgEdge || ukgEdgeDoc == nil || len(ukgEdgeDoc.Records) != 1 || ukgEdgeDoc.Records[0]["title"] != "R5 JS Lexer Role" {
		t.Fatalf("R5-GO-4: UKG Pro end-to-end JS edge case failed: ok=%v doc=%+v", okUkgEdge, ukgEdgeDoc)
	}

	// R5-GO-5: ExtractStructuredProduct rejects bare public suffixes (co.uk, github.io) in product.url & product.images
	prodBareSuffixHTML := `<!doctype html><html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Widget","url":"https://co.uk/evil","image":"https://github.io/evil.png"}</script></head><body><h1>Widget</h1></body></html>`
	prodBare := ExtractStructuredProduct(prodBareSuffixHTML, "https://shop.example.com/widget", "Widget", "")
	if prodBare == nil {
		t.Fatal("expected structured product")
	}
	if prodBare["url"] == "https://co.uk/evil" {
		t.Fatalf("R5-GO-5: ExtractStructuredProduct emitted bare public suffix URL: %+v", prodBare)
	}
	if imgs, ok := prodBare["images"].([]string); ok {
		for _, img := range imgs {
			if strings.Contains(img, "github.io") {
				t.Fatalf("R5-GO-5: ExtractStructuredProduct emitted bare public suffix image URL: %+v", imgs)
			}
		}
	}
}

func TestR6AdversarialHardening(t *testing.T) {
	// R6-GO-1: formatters.go (ipynb, source_code, delimited, git_patch)
	nbJSON := `{
		"nbformat": 4,
		"metadata": {
			"title": "[EvilNB](https://evil.com/nb)\n## FakeNB",
			"kernelspec": {"language": "python"}
		},
		"cells": [
			{"cell_type": "code", "source": ["print(1)"], "outputs": [
				{"output_type": "execute_result", "data": {"text/markdown": "Out [XSS](javascript:alert(2)) <img src=x onerror=alert(1)>"}}
			]},
			{"cell_type": "markdown", "source": ["Hello [Click](javascript:alert(1)) and [Safe](https://example.org/ok) <script>alert(1)</script>"]}
		]
	}`
	nbDoc := FormatJupyterNotebookToMarkdown(nbJSON, "https://example.org/nb.ipynb")
	if nbDoc == nil {
		t.Fatal("expected ipynb doc")
	}
	if hasUnescapedClickableEvilLinkR10(nbDoc.Markdown) ||
		strings.Contains(nbDoc.Markdown, "javascript:alert") ||
		strings.Contains(nbDoc.Markdown, "<script>") ||
		strings.Contains(nbDoc.Markdown, "<img ") ||
		strings.Contains(nbDoc.Markdown, "\n## FakeNB") ||
		!strings.Contains(nbDoc.Markdown, "[Safe](https://example.org/ok)") {
		t.Fatalf("R6-GO-1: ipynb failed sanitization:\n%s", nbDoc.Markdown)
	}
	nbURLFallback := FormatJupyterNotebookToMarkdown(`{"nbformat":4,"cells":[{"cell_type":"code","source":["x = 1"]}]}`, "https://example.org/dir/%5BEvilNB%5D(https%3A%2F%2Fevil.com)%0a%23%23%20FakeURL.ipynb")
	if nbURLFallback == nil || hasUnescapedClickableEvilLinkR10(nbURLFallback.Markdown) || strings.Contains(nbURLFallback.Markdown, "\n## FakeURL") {
		t.Fatalf("R6-GO-1: ipynb URL fallback leaked link/heading:\n%+v", nbURLFallback)
	}

	srcDoc := FormatSourceCodeURLToMarkdown("print('ok')\n", "https://example.org/%5BEvilSrc%5D(https%3A%2F%2Fevil.com)%0a%23%23%20Injected/app.py", "text/plain")
	if srcDoc == nil || hasUnescapedClickableEvilLinkR10(srcDoc.Markdown) || strings.Contains(srcDoc.Markdown, "\n## Injected") {
		t.Fatalf("R6-GO-1: source_code URL title leaked link or heading:\n%+v", srcDoc)
	}
	tomlDoc := FormatSourceCodeURLToMarkdown("[package]\nname = \"pkg<script>alert(1)</script>\"\nversion = \"1.0.0\"\ndescription = \"[Evil](https://evil.com)\"\n", "https://example.org/Cargo.toml", "text/plain")
	if tomlDoc == nil || strings.Contains(tomlDoc.Description, "<script>") || hasUnescapedClickableEvilLinkR10(tomlDoc.Description) {
		t.Fatalf("R6-GO-1: Cargo.toml Description unsanitized:\n%+v", tomlDoc)
	}

	csvDoc := FormatDelimitedTableToMarkdown("col`[EvilHdr](https://evil.com)`x,val\n[EvilCell](https://evil.com),123\n", ",", "[EvilCSV](https://evil.com)\n## FakeCSV")
	if csvDoc == nil ||
		hasUnescapedClickableEvilLinkR10(csvDoc.Markdown) ||
		hasUnescapedClickableEvilLinkR10(csvDoc.Description) ||
		strings.Contains(csvDoc.Markdown, "\n## FakeCSV") {
		t.Fatalf("R6-GO-1: delimited table leaked link/heading:\n%+v", csvDoc)
	}

	patchRaw := "From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001\n" +
		"From: [EvilAuth](https://evil.com/a)\n" +
		"Date: [EvilDate](https://evil.com/d)\n" +
		"Subject: [PATCH] [EvilSubj](https://evil.com/s)\n\n" +
		"Commit body [XSS](javascript:alert(1)) <script>alert(1)</script>\n\n" +
		"diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-a\n+b\n"
	patchDoc := FormatGitPatchToMarkdown(patchRaw, "https://example.org/x.patch")
	if patchDoc == nil ||
		hasUnescapedClickableEvilLinkR10(patchDoc.Markdown) ||
		strings.Contains(patchDoc.Markdown, "javascript:alert") ||
		strings.Contains(patchDoc.Markdown, "<script>") ||
		strings.Contains(patchDoc.Description, "<script>") {
		t.Fatalf("R6-GO-1: git_patch leaked injection:\n%+v", patchDoc)
	}

	// R6-GO-2: OpenAPI spec badge + backtick spans
	oaJSON := `{
		"openapi": "3.0.0\n## FakeOAVer [EvilVer](https://evil.com/v)",
		"info": {"title": "API", "version": "1.0"},
		"servers": [{"url": "https://api.example.com\n\n## FakeSrv [EvilSrv](https://evil.com/s)"}],
		"components": {
			"securitySchemes": {"apiKey": {"type": "apiKey\n\n## FakeSec [EvilSec](https://evil.com/sec)", "in": "header", "name": "X-Key"}},
			"schemas": {"User` + "` [EvilSchema](https://evil.com/sch) `" + `": {"type": "object", "properties": {"id` + "` [EvilProp](https://evil.com/p) `" + `": {"type": "string"}}}}
		},
		"paths": {
			"/users\n## FakePath ` + "` [EvilPath](https://evil.com/path) `" + `": {
				"get": {
					"operationId": "op` + "` [EvilOp](https://evil.com/op) `" + `",
					"parameters": [{"name": "q\n## FakeParam", "in": "query", "schema": {"type": "string"}}],
					"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/In` + "` [EvilRB](https://evil.com/rb) `" + `"}}}},
					"responses": {"200` + "` [EvilCode](https://evil.com/c) `" + `": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Out` + "` [EvilResp](https://evil.com/r) `" + `"}}}}}
				}
			}
		}
	}`
	oaDoc := FormatOpenAPISpecToMarkdown(oaJSON, "https://example.org/openapi.json")
	if oaDoc == nil ||
		hasUnescapedClickableEvilLinkR10(oaDoc.Markdown) ||
		strings.Contains(oaDoc.Markdown, "\n## Fake") {
		t.Fatalf("R6-GO-2: OpenAPI leaked clickable link or heading:\n%s", oaDoc.Markdown)
	}

	// R6-GO-3: huggingface card, jats_article (pubmed-pmc), TreeComments (ycombinator), github-gist
	hfTwin, okHf := ResolveDeclarativeTwin("https://huggingface.co/acme/evil-model")
	if !okHf || hfTwin == nil {
		t.Fatal("expected huggingface twin")
	}
	hfCardDoc, okHfFmt := hfTwin.Format("---\npretty_name: \"[EvilHF](https://evil.com/hf)\"\nlicense: \"[EvilLic](https://evil.com/lic)\"\n---\n\nSee [Docs](https://huggingface.co/docs) for usage.")
	if !okHfFmt || hfCardDoc == nil || hasUnescapedClickableEvilLinkR10(hfCardDoc.Markdown) || !strings.Contains(hfCardDoc.Markdown, "[Docs](https://huggingface.co/docs)") {
		t.Fatalf("R6-GO-3: huggingface card escaping failed:\n%+v", hfCardDoc)
	}

	pmcTwin, okPmc := ResolveDeclarativeTwin("https://pmc.ncbi.nlm.nih.gov/articles/PMC123456/")
	if !okPmc || pmcTwin == nil {
		t.Fatal("expected pubmed-pmc twin")
	}
	pmcXML := `<article><front><article-meta><title-group><article-title>[EvilPMC](https://evil.com/t)</article-title></title-group><abstract><p>[EvilAbs](https://evil.com/a)</p></abstract></article-meta></front><body><sec><title>[EvilSec](https://evil.com/s)</title><p>[EvilPara](https://evil.com/p)</p></sec></body></article>`
	pmcDoc, okPmcFmt := pmcTwin.Format(pmcXML)
	if !okPmcFmt || pmcDoc == nil || hasUnescapedClickableEvilLinkR10(pmcDoc.Markdown) {
		t.Fatalf("R6-GO-3: jats_article leaked clickable link:\n%+v", pmcDoc)
	}

	hnTwin, okHn := ResolveDeclarativeTwin("https://news.ycombinator.com/item?id=12345")
	if !okHn || hnTwin == nil {
		t.Fatal("expected ycombinator twin")
	}
	hnJSON := `{"id":12345,"title":"Show HN","text":"Body","author":"alice","points":10,"children":[{"id":1,"author":"[EvilAuth](https://evil.com/u)","text":"Comment [EvilCmt](https://evil.com/c)\n## FakeHN","children":[]}]}`
	hnDoc, okHnFmt := hnTwin.Format(hnJSON)
	if !okHnFmt || hnDoc == nil || hasUnescapedClickableEvilLinkR10(hnDoc.Markdown) || strings.Contains(hnDoc.Markdown, "\n## FakeHN") || !strings.Contains(hnDoc.Markdown, "EvilAuth") {
		t.Fatalf("R6-GO-3: TreeComments leaked clickable link or heading:\n%+v", hnDoc)
	}

	gistHTML := `<!doctype html><html><head><title>[EvilGist](https://evil.com/gt) · GitHub</title></head><body><div itemprop="about">[EvilDesc](https://evil.com/gd)</div><div class="file"><strong class="gist-blob-name">[EvilFile](https://evil.com/gf).py</strong><table><tr><td class="blob-code-inner">print(1)</td></tr></table></div><div class="file"><strong class="gist-blob-name">notes.md</strong><article class="markdown-body"><p>Read <a href="https://example.org/ok">legit</a>.</p></article></div></body></html>`
	gistDoc, okGist := ApplyDeclarativeHTMLExtractor(gistHTML, "https://gist.github.com/alice/abcdef123456", "", nil)
	if !okGist || gistDoc == nil || hasUnescapedClickableEvilLinkR10(gistDoc.Markdown) || !strings.Contains(gistDoc.Markdown, "[legit](https://example.org/ok)") {
		t.Fatalf("R6-GO-3: gist extractor failed:\n%+v", gistDoc)
	}

	// R6-GO-4: JS spread properties & chained member/method access on array/object literals
	jsSpreadAndMember := `{
		...defaults,
		...fn({ nested: [1, 2] }),
		items: [1, 2].map(x => ({ v: x })),
		val: { k: 1 }.k,
		sum: [1, 2] + [3],
		opt: { a: 1 }?.a ?? 2,
		opportunities: [{"id": "u99", "title": "Staff Engineer"}],
		...trailingSpread
	}`
	normSpread := normalizeJSObjectLiteralToJSONM4(jsSpreadAndMember)
	var spreadDecoded map[string]any
	if err := json.Unmarshal([]byte(normSpread), &spreadDecoded); err != nil {
		t.Fatalf("R6-GO-4: expected valid JSON for spread & literal-member JS, err=%v\nnorm=%s", err, normSpread)
	}
	if spreadDecoded["val"] != nil || spreadDecoded["items"] != nil {
		t.Fatalf("R6-GO-4: expected chained literal expressions to normalize to null, got: %#v", spreadDecoded)
	}

	ukgSpreadHTML := `<!doctype html><html><body><script>window.__PRELOADED_STATE__ = { ...defaults, items: [1, 2].map(x => x + 1), val: { k: 1 }.k, opportunities: [{ Id: 'u99', Title: 'R6 Spread Role' }] };</script></body></html>`
	ukgSpreadDoc, okUkgSpread := ApplyDeclarativeHTMLExtractor(ukgSpreadHTML, "https://recruiting.ultipro.com/R6CO/JobBoard/11111111-2222-3333-4444-555555555555", "", nil)
	if !okUkgSpread || ukgSpreadDoc == nil || len(ukgSpreadDoc.Records) != 1 || ukgSpreadDoc.Records[0]["title"] != "R6 Spread Role" {
		t.Fatalf("R6-GO-4: UKG Pro end-to-end spread/chained literal failed: ok=%v doc=%+v", okUkgSpread, ukgSpreadDoc)
	}
}

func TestR7AdversarialHardening(t *testing.T) {
	// R7-GO-1: Declarative XML (items_table), JSON (title, resolveHeading, subH, ObjectLinksPath), NuGet Branch 2
	rmkXML := `<?xml version="1.0"?><rss><channel><item><title>Engineer</title><link>https://jobs.sap.com/job/1</link><g:employer>Acme [Phish](https://evil.com/rmk)</g:employer><g:location>Remote</g:location></item></channel></rss>`
	rmkDoc, okRmk := ApplyDeclarativeHTMLExtractor(rmkXML, "https://jobs.sap.com/sitemap.xml", "", nil)
	if !okRmk || rmkDoc == nil || hasUnescapedClickableEvilLinkR10(rmkDoc.Markdown) || !strings.Contains(rmkDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-1: sap-rmk XML title leaked clickable link:\n%+v", rmkDoc)
	}

	ttTwin, okTt := ResolveDeclarativeTwin("https://acme.teamtailor.com/")
	if !okTt || ttTwin == nil {
		t.Fatal("expected teamtailor twin")
	}
	ttDoc, okTtFmt := ttTwin.Format(`<?xml version="1.0"?><rss><channel><title>Careers [Phish](https://evil.com/tt)</title><item><title>Engineer</title><link>https://acme.teamtailor.com/jobs/1</link></item></channel></rss>`)
	if !okTtFmt || ttDoc == nil || hasUnescapedClickableEvilLinkR10(ttDoc.Markdown) || !strings.Contains(ttDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-1: teamtailor XML title leaked clickable link:\n%+v", ttDoc)
	}

	npmTwin, okNpm := ResolveDeclarativeTwin("https://www.npmjs.com/package/left-pad")
	if !okNpm || npmTwin == nil {
		t.Fatal("expected npm twin")
	}
	npmDoc, okNpmFmt := npmTwin.Format(`{"name":"left-pad [Phish](https://evil.com/npm)","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"description":"Safe"}}}`)
	if !okNpmFmt || npmDoc == nil || hasUnescapedClickableEvilLinkR10(npmDoc.Markdown) || !strings.Contains(npmDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-1: npm JSON title leaked clickable link:\n%+v", npmDoc)
	}

	ycHTML := `<!doctype html><html><body><div id="app" data-page='{"component":"Companies/Show","props":{"company":{"name":"Acme [Phish](https://evil.com/yc)","one_liner":"Safe","long_description":"Long desc"}}}'></div></body></html>`
	ycDoc, okYc := ApplyDeclarativeHTMLExtractor(ycHTML, "https://www.ycombinator.com/companies/acme", "", nil)
	if !okYc || ycDoc == nil || hasUnescapedClickableEvilLinkR10(ycDoc.Markdown) || !strings.Contains(ycDoc.Markdown, `## About Acme \[Phish\]`) {
		t.Fatalf("R7-GO-1: ycombinator resolveHeading leaked clickable link:\n%+v", ycDoc)
	}

	discTwin, okDisc := ResolveDeclarativeTwin("https://meta.discourse.org/t/safe-topic/123")
	if !okDisc || discTwin == nil {
		t.Fatal("expected discourse twin")
	}
	discDoc, okDiscFmt := discTwin.Format(`{"title":"SubTest","post_stream":{"posts":[{"post_number":1,"username":"bob [Phish](https://evil.com/subh)","cooked":"<p>hi</p>"}]}}`)
	if !okDiscFmt || discDoc == nil || hasUnescapedClickableEvilLinkR10(discDoc.Markdown) || !strings.Contains(discDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-1: discourse subH leaked clickable link:\n%+v", discDoc)
	}

	hexTwin, okHex := ResolveDeclarativeTwin("https://hex.pm/packages/phoenix")
	if !okHex || hexTwin == nil {
		t.Fatal("expected hex-pm twin")
	}
	hexDoc, okHexFmt := hexTwin.Format(`{"name":"phoenix","releases":[{"version":"1.7.0"}],"meta":{"description":"web","links":{"[Phish](https://evil.com/hex)":"https://hex.pm/docs","Bad":"javascript:alert(1)"}}}`)
	if !okHexFmt || hexDoc == nil || hasUnescapedClickableEvilLinkR10(hexDoc.Markdown) || strings.Contains(hexDoc.Markdown, "javascript:alert") || !strings.Contains(hexDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-1: hex ObjectLinksPath leaked clickable link or unsafe href:\n%+v", hexDoc)
	}

	nugetTwin, okNu := ResolveDeclarativeTwin("https://www.nuget.org/packages/serilog")
	if !okNu || nugetTwin == nil {
		t.Fatal("expected nuget-gallery twin")
	}
	nugetB2, okNuB2 := nugetTwin.Format(`{"count":1,"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/1.0.0/2.0.0.json","lower":"1.0.0","upper":"2.0.0 [Phish](https://evil.com/nuget)","count":5}]}`)
	if !okNuB2 || nugetB2 == nil || hasUnescapedClickableEvilLinkR10(nugetB2.Markdown) || !strings.Contains(nugetB2.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-1: nuget Branch 2 title leaked clickable link:\n%+v", nugetB2)
	}

	// R7-GO-2: Declarative HTML routes (dom, stackexchange_html, reddit_shreddit, ietf_rfc)
	fccHTML := `<!doctype html><html><head><title>FCC [Phish](https://evil.com/dom)</title></head><body><h1>FCC [Phish](https://evil.com/dom)</h1><main><p>Grant details for device.</p></main></body></html>`
	fccDoc, okFcc := ApplyDeclarativeHTMLExtractor(fccHTML, "https://fccid.io/BCG-E3542A", "", nil)
	if !okFcc || fccDoc == nil || hasUnescapedClickableEvilLinkR10(fccDoc.Markdown) || !strings.Contains(fccDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-2: dom H1 title leaked clickable link:\n%+v", fccDoc)
	}

	seHTML := `<!doctype html><html><body><div id="question-header"><h1>SE Title [Phish](https://evil.com/se)</h1></div><div id="question" data-score="5"><a class="post-tag">go` + "`bad`" + `</a><div class="s-prose"><p>See <a href="https://example.org/docs">SE Docs</a> for details.</p></div><span class="comment-copy">Comment [Phish](https://evil.com/sec)</span></div></body></html>`
	seDoc, okSe := ApplyDeclarativeHTMLExtractor(seHTML, "https://stackoverflow.com/questions/123/test", "", nil)
	if !okSe || seDoc == nil || hasUnescapedClickableEvilLinkR10(seDoc.Markdown) || !strings.Contains(seDoc.Markdown, "[SE Docs](https://example.org/docs)") || !strings.Contains(seDoc.Markdown, "`go'bad'`") {
		t.Fatalf("R7-GO-2: stackexchange_html failed escaping or broke legit link:\n%+v", seDoc)
	}

	rdHTML := `<!doctype html><html><body><shreddit-post post-title="Reddit [Phish](https://evil.com/rd)" subreddit-prefixed-name="r/golang*evil*" author="bob [Phish](https://evil.com/ra)" score="[Phish](https://evil.com/rs)"><p>Body text</p></shreddit-post><shreddit-comment author="alice [Phish](https://evil.com/rc)" score="[Phish](https://evil.com/rcs)" depth="0"><p>Nice</p></shreddit-comment></body></html>`
	rdDoc, okRd := ApplyDeclarativeHTMLExtractor(rdHTML, "https://www.reddit.com/r/golang/comments/1abc123/test/", "", nil)
	if !okRd || rdDoc == nil || hasUnescapedClickableEvilLinkR10(rdDoc.Markdown) || !strings.Contains(rdDoc.Markdown, `r/golang\*evil\*`) {
		t.Fatalf("R7-GO-2: reddit_shreddit leaked clickable link or unescaped italic:\n%+v", rdDoc)
	}

	rfcBody := "1. Introduction\n\nThis document defines HTTP Message Signatures and provides detailed specification text exceeding eighty characters."
	rfcDoc, okRfc := ApplyDeclarativeHTMLExtractor(`<!doctype html><html><head><title>RFC 9999 [Phish](https://evil.com/rfc)</title></head><body><pre class="newpage">`+rfcBody+`</pre></body></html>`, "https://datatracker.ietf.org/doc/html/rfc9999", rfcBody, nil)
	if !okRfc || rfcDoc == nil || hasUnescapedClickableEvilLinkR10(rfcDoc.Markdown) || !strings.Contains(rfcDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-2: ietf_rfc H1 title leaked clickable link:\n%+v", rfcDoc)
	}

	// R7-GO-3: json_scrape, Inertia (formatters & hydration), WordPress REST, RSC, state tree
	jsonDoc := TryParseJSONPayloadForScrape(`{"title":"JSON [Phish](https://evil.com/json)","ok":true}`, "https://example.org/api.json")
	if jsonDoc == nil || hasUnescapedClickableEvilLinkR10(jsonDoc.Markdown) || !strings.Contains(jsonDoc.Markdown, `\[Phish\]`) || !strings.Contains(jsonDoc.Title, "[Phish]") {
		t.Fatalf("R7-GO-3: json_scrape H1 leaked link or corrupted Title:\n%+v", jsonDoc)
	}
	hugeJSON := `{"title":"Huge [Phish](https://evil.com/hugejson)","blob":"` + strings.Repeat("a", 530*1024) + `"}`
	hugeJsonDoc := TryParseJSONPayloadForScrape(hugeJSON, "https://example.org/huge.json")
	if hugeJsonDoc == nil || hasUnescapedClickableEvilLinkR10(hugeJsonDoc.Markdown) || !strings.Contains(hugeJsonDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-3: huge json_scrape H1 leaked link:\n%+v", hugeJsonDoc)
	}

	inertiaDoc := FormatInertiaPagePropsToMarkdown(map[string]any{
		"component": "Pages/Home",
		"props": map[string]any{
			"title": "Inertia [Phish](https://evil.com/ititle)",
			"items": []any{
				map[string]any{"name": "Row [Phish](https://evil.com/irow)", "ok": true},
			},
		},
	}, "https://example.org/")
	if inertiaDoc == nil || hasUnescapedClickableEvilLinkR10(inertiaDoc.Markdown) || !strings.Contains(inertiaDoc.Markdown, `\[Phish\]`) || !strings.Contains(inertiaDoc.Title, "[Phish]") {
		t.Fatalf("R7-GO-3: FormatInertiaPagePropsToMarkdown leaked link or corrupted Title:\n%+v", inertiaDoc)
	}

	inertiaHydHTML := `<!doctype html><html><body><div id="app" data-page='{"component":"Pages/Home","props":{"title":"Inertia [Phish](https://evil.com/ihyd)","items":[{"name":"HydRow [Phish](https://evil.com/ihrow)","ok":true}]}}'></div></body></html>`
	inertiaHyd := RecoverSSRHydrationContent(inertiaHydHTML, "https://example.org/", nil)
	if inertiaHyd == nil || hasUnescapedClickableEvilLinkR10(inertiaHyd.Markdown) || !strings.Contains(inertiaHyd.Markdown, `\[Phish\]`) || !strings.Contains(inertiaHyd.Title, "[Phish]") {
		t.Fatalf("R7-GO-3: hydration Inertia leaked link or corrupted Title:\n%+v", inertiaHyd)
	}

	wpWords := strings.Repeat("word ", 30)
	wpDoc := FormatWordPressRestPostJSON(fmt.Sprintf(`{"title":{"rendered":"WP [Phish](https://evil.com/wp)"},"content":{"rendered":"<p>%s</p>"},"excerpt":{"rendered":"<p>Excerpt</p>"},"slug":"test","type":"post"}`, wpWords), "https://example.org/wp-json/wp/v2/posts/1", nil)
	if wpDoc == nil || hasUnescapedClickableEvilLinkR10(wpDoc.Markdown) || !strings.Contains(wpDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-3: FormatWordPressRestPostJSON H1 leaked clickable link:\n%+v", wpDoc)
	}

	rscHTML := fmt.Sprintf(`<!doctype html><html><head><title>RSC [Phish](https://evil.com/rsc)</title></head><body><script>self.__next_f.push([1,"1:[\"$\",\"div\",null,{\"children\":\"%s\"}]\n"])</script></body></html>`, strings.Repeat("flight ", 30))
	rscDoc := ExtractNextRSCFlight(rscHTML, "https://example.org/rsc", nil)
	if rscDoc == nil || hasUnescapedClickableEvilLinkR10(rscDoc.Markdown) || !strings.Contains(rscDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-3: ExtractNextRSCFlight H1 leaked clickable link:\n%+v", rscDoc)
	}

	stateHTML := fmt.Sprintf(`<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"title":"State [Phish](https://evil.com/state)","body":"%s"}}}</script></body></html>`, strings.Repeat("content ", 40))
	stateHyd := RecoverSSRHydrationContent(stateHTML, "https://example.org/post", nil)
	if stateHyd == nil || hasUnescapedClickableEvilLinkR10(stateHyd.Markdown) || !strings.Contains(stateHyd.Markdown, `\[Phish\]`) {
		t.Fatalf("R7-GO-3: ExtractFromParsedStateTree H1 leaked clickable link:\n%+v", stateHyd)
	}

	// R7-GO-4: Raw HTML tags stripped/escaped in direct Go calls to vCard, iCalendar, and OpenAPI
	vcardRaw := FormatVCardToMarkdown("BEGIN:VCARD\nVERSION:3.0\nFN:Bob <script>alert(1)</script>\nNOTE:Hi <img src=x onerror=alert(1)>\nEND:VCARD")
	if vcardRaw == nil || strings.Contains(vcardRaw.Markdown, "<script>") || strings.Contains(vcardRaw.Markdown, "<img ") || strings.Contains(vcardRaw.Title, "<script>") {
		t.Fatalf("R7-GO-4: FormatVCardToMarkdown leaked raw HTML:\n%+v", vcardRaw)
	}

	icsRaw := FormatICalendarToMarkdown("BEGIN:VCALENDAR\nVERSION:2.0\nX-WR-CALNAME:Cal <script>alert(1)</script>\nX-WR-CALDESC:CalDesc <img src=x onerror=alert(1)>\nBEGIN:VEVENT\nSUMMARY:Meet <script>alert(1)</script>\nDESCRIPTION:Desc <img src=x onerror=alert(1)>\nEND:VEVENT\nEND:VCALENDAR")
	if icsRaw == nil || strings.Contains(icsRaw.Markdown, "<script>") || strings.Contains(icsRaw.Markdown, "<img ") || strings.Contains(icsRaw.Title, "<script>") || strings.Contains(icsRaw.Description, "<img ") {
		t.Fatalf("R7-GO-4: FormatICalendarToMarkdown leaked raw HTML:\n%+v", icsRaw)
	}

	oaRaw := FormatOpenAPISpecToMarkdown(`{"openapi":"3.0.0","info":{"title":"API <script>alert(1)</script>","version":"1.0","description":"Desc <img src=x onerror=alert(1)>"},"paths":{"/items/{id}":{"get":{"summary":"List <script>alert(1)</script>","responses":{"200":{"description":"OK <img src=x onerror=alert(1)>"}}}}}}`, "https://example.org/openapi.json")
	if oaRaw == nil || strings.Contains(oaRaw.Markdown, "<script>") || strings.Contains(oaRaw.Markdown, "<img ") || strings.Contains(oaRaw.Title, "<script>") || strings.Contains(oaRaw.Description, "<img ") || !strings.Contains(oaRaw.Markdown, "`GET /items/{id}`") {
		t.Fatalf("R7-GO-4: FormatOpenAPISpecToMarkdown leaked raw HTML or broke code span:\n%+v", oaRaw)
	}
}

func TestR8AdversarialHardening(t *testing.T) {
	// R8-GO-1: polymarket paired_percent escapes outcomes
	polyDoc, okPoly := FormatDeclarativeTwinByURL(
		"https://polymarket.com/event/test-market",
		`[{"title":"Market Event","markets":[{"question":"Q1","outcomes":"[\"[Phish](https://evil.com/poly)\",\"Yes | Evil\\n# FakeHeading\"]","outcomePrices":"[\"0.6\",\"0.4\"]","volumeNum":1000}]}]`,
		"",
	)
	if !okPoly || polyDoc == nil || hasUnescapedClickableEvilLinkR10(polyDoc.Markdown) || !strings.Contains(polyDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R8-GO-1: polymarket paired_percent leaked unescaped outcome link:\n%+v", polyDoc)
	}

	// R8-GO-2: bluesky plain_text bodyVar escapes links/headings/HTML while preserving newlines and Markdown bodyVar adapters
	bskyDoc, okBsky := FormatDeclarativeTwinByURL(
		"https://bsky.app/profile/alice.bsky.social/post/3lbxyz123",
		`{"thread":{"post":{"author":{"handle":"alice.bsky.social","displayName":"Alice"},"record":{"text":"[Phish](https://evil.com/bsky)\n# FakeHeading\n<img onerror=1>\nSecond line","createdAt":"2025-01-01T00:00:00Z"},"likeCount":5,"repostCount":1,"embed":{"external":{"uri":"https://example.org/post","title":"Safe Link","description":"Clean"}}}}}`,
		"",
	)
	if !okBsky || bskyDoc == nil || hasUnescapedClickableEvilLinkR10(bskyDoc.Markdown) ||
		strings.Contains(bskyDoc.Markdown, "\n# FakeHeading") ||
		!strings.Contains(bskyDoc.Markdown, `\# FakeHeading`) ||
		strings.Contains(bskyDoc.Markdown, "<img ") ||
		!strings.Contains(bskyDoc.Markdown, "\nSecond line") ||
		!strings.Contains(bskyDoc.Markdown, "[Safe Link](https://example.org/post)") {
		t.Fatalf("R8-GO-2: bluesky plain_text escaping failed:\n%+v", bskyDoc)
	}
	osvDoc, okOsv := FormatDeclarativeTwinByURL(
		"https://osv.dev/vulnerability/GHSA-1234-5678-9012",
		`{"id":"GHSA-1234-5678-9012","summary":"Test Advisory","details":"See [OSV Advisory](https://osv.dev/docs) for details."}`,
		"",
	)
	if !okOsv || osvDoc == nil || !strings.Contains(osvDoc.Markdown, "[OSV Advisory](https://osv.dev/docs)") {
		t.Fatalf("R8-GO-2: Markdown bodyVar adapter osv-ghsa must retain legitimate links:\n%+v", osvDoc)
	}

	// R8-GO-3: xenforo-thread, sram-docs, and bosch-ebike-help escape literal brackets in H1, author, breadcrumbs, and models
	xfHTML := `<!doctype html><html><body>
		<h1 class="p-title-value">[Phish](https://evil.com/xfh1)</h1>
		<article class="message--post"><div class="message-main"><header><a class="message-name">[Phish](https://evil.com/xfauth)</a></header><div class="bbWrapper"><p>Valid forum reply body text.</p></div></div></article>
	</body></html>`
	xfDoc, okXf := ApplyDeclarativeHTMLExtractor(xfHTML, "https://forums.electricbikereview.com/threads/test-topic.123/", "", nil)
	if !okXf || xfDoc == nil || hasUnescapedClickableEvilLinkR10(xfDoc.Markdown) || !strings.Contains(xfDoc.Markdown, `# \[Phish\]`) || strings.Contains(xfDoc.Markdown, `\\[`) {
		t.Fatalf("R8-GO-3: xenforo-thread H1/author escaping failed:\n%+v", xfDoc)
	}

	sramHTML := `<!doctype html><html><body>
		<nav aria-label="breadcrumb"><a href="/en">Crumb [Phish](https://evil.com/sc)</a></nav>
		<main><h1 class="ft-topic-title">[Phish](https://evil.com/sh1)</h1><div class="ft-topic-content"><p>Torque to 12 Nm safely.</p></div></main>
	</body></html>`
	sramDoc, okSram := ApplyDeclarativeHTMLExtractor(sramHTML, "https://docs.sram.com/en-US/publications/abc?models=[Phish](https://evil.com/sm)", "", nil)
	if !okSram || sramDoc == nil || hasUnescapedClickableEvilLinkR10(sramDoc.Markdown) || !strings.Contains(sramDoc.Markdown, `# \[Phish\]`) || strings.Contains(sramDoc.Markdown, `\\[`) {
		t.Fatalf("R8-GO-3: sram-docs escaping failed:\n%+v", sramDoc)
	}

	boschHTML := `<!doctype html><html><body>
		<nav aria-label="Breadcrumb"><a href="/help">Crumb [Phish](https://evil.com/bc)</a></nav>
		<main><h1>[Phish](https://evil.com/bh1)</h1><article><p>Check Bosch battery terminals carefully before charging.</p></article></main>
	</body></html>`
	boschDoc, okBosch := ApplyDeclarativeHTMLExtractor(boschHTML, "https://help.bosch-ebike.com/us/help-center/test-guide?models=[Phish](https://evil.com/bm)", "", nil)
	if !okBosch || boschDoc == nil || hasUnescapedClickableEvilLinkR10(boschDoc.Markdown) || !strings.Contains(boschDoc.Markdown, `# \[Phish\]`) || strings.Contains(boschDoc.Markdown, `\\[`) {
		t.Fatalf("R8-GO-3: bosch-ebike-help escaping failed:\n%+v", boschDoc)
	}

	// R8-GO-4: ExtractUniversalSchemaOrg escapes brackets across Article, FAQPage, QAPage, HowTo, ItemList, Event
	artHTML := `<!doctype html><html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"[Phish](https://evil.com/art)","author":{"name":"[Phish](https://evil.com/auth)"},"publisher":{"name":"[Phish](https://evil.com/pub)"},"articleBody":"` + strings.Repeat("word ", 35) + `"}</script></head><body></body></html>`
	artSchema := ExtractUniversalSchemaOrg(artHTML, "https://example.com/art", nil)
	if artSchema == nil || hasUnescapedClickableEvilLinkR10(artSchema.Markdown) || hasUnescapedClickableEvilLinkR10(artSchema.HeaderMarkdown) || !strings.Contains(artSchema.Markdown, `# \[Phish\]`) {
		t.Fatalf("R8-GO-4: schema.org Article leaked clickable link:\n%+v", artSchema)
	}

	faqHTML := `<!doctype html><html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","name":"[Phish](https://evil.com/faq)","mainEntity":[{"@type":"Question","name":"What is [Phish](https://evil.com/q)?","acceptedAnswer":{"@type":"Answer","text":"Safe answer text."}}]}</script></head><body></body></html>`
	faqSchema := ExtractUniversalSchemaOrg(faqHTML, "https://example.com/faq", nil)
	if faqSchema == nil || hasUnescapedClickableEvilLinkR10(faqSchema.Markdown) || !strings.Contains(faqSchema.Markdown, `# \[Phish\]`) {
		t.Fatalf("R8-GO-4: schema.org FAQPage leaked clickable link:\n%+v", faqSchema)
	}

	evtHTML := `<!doctype html><html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"Event","name":"[Phish](https://evil.com/evt)","startDate":"2026-12-01","location":{"name":"[Phish](https://evil.com/loc)"},"description":"# FakeHeading [Phish](https://evil.com/desc)"}</script></head><body></body></html>`
	evtSchema := ExtractUniversalSchemaOrg(evtHTML, "https://example.com/evt", nil)
	if evtSchema == nil || hasUnescapedClickableEvilLinkR10(evtSchema.Markdown) || hasUnescapedClickableEvilLinkR10(evtSchema.HeaderMarkdown) || strings.Contains(evtSchema.Markdown, "\n# FakeHeading") {
		t.Fatalf("R8-GO-4: schema.org Event leaked clickable link or heading:\n%+v", evtSchema)
	}

	// R8-GO-5: ietf_rfc <pre class="newpage"> escapes brackets, HTML tags, and non-promoted # headings
	rfcRaw := "1. [Phish](https://evil.com/rfc1) &lt;script&gt;alert(1)&lt;/script&gt;\n# FakeRFCHeading\n1.1. Section [Phish](https://evil.com/rfcsec)\nThis specification defines protocol requirements with sufficient detail and length."
	rfcDoc, okRfc := ApplyDeclarativeHTMLExtractor(
		`<!doctype html><html><head><title>RFC 9110</title></head><body><pre class="newpage">`+rfcRaw+`</pre></body></html>`,
		"https://datatracker.ietf.org/doc/html/rfc9110",
		"",
		nil,
	)
	if !okRfc || rfcDoc == nil || hasUnescapedClickableEvilLinkR10(rfcDoc.Markdown) || strings.Contains(rfcDoc.Markdown, "<script>") || strings.Contains(rfcDoc.Markdown, "\n# FakeRFCHeading") {
		t.Fatalf("R8-GO-5: ietf_rfc <pre class=\"newpage\"> leaked link, tag, or heading:\n%+v", rfcDoc)
	}

	// R8-GO-6: formatTextTwin code_or_markdown_by_path and default sanitize title & body
	hfBlobDoc, okHfBlob := FormatDeclarativeTwinByURL(
		"https://huggingface.co/acme/demo/blob/main/dir/[Phish](https://evil.com/hf).py",
		"print('hello')\n",
		"",
	)
	if !okHfBlob || hfBlobDoc == nil || hasUnescapedClickableEvilLinkR10(hfBlobDoc.Markdown) || !strings.Contains(hfBlobDoc.Markdown, `\[Phish\]`) {
		t.Fatalf("R8-GO-6: huggingface blob H1 leaked unescaped bracket link:\n%+v", hfBlobDoc)
	}

	defMatch := &DeclarativeTwinMatch{
		ID:     "r8-default-text",
		route:  DeclarativeRouteSpec{Extract: DeclarativeExtractSpec{TitleTemplate: "{name}"}},
		params: map[string]string{"name": "File [Phish](https://evil.com/title).py"},
	}
	defDoc, okDef := defMatch.formatTextTwin("Body [Ok](https://example.org) <script>alert(1)</script>")
	if !okDef || defDoc == nil || !strings.Contains(defDoc.Markdown, `\[Phish\]`) || strings.Contains(defDoc.Markdown, "<script>") {
		t.Fatalf("R8-GO-6: formatTextTwin default failed title escaping or body sanitization:\n%+v", defDoc)
	}
}

func TestR9AdversarialHardening(t *testing.T) {
	// R9-GO-1: gem-ats plain-text fallback (content_plain) escapes links, headings, and HTML while HTML content preserves legitimate links
	gemPlainDoc, okGemPlain := FormatDeclarativeTwinByURL(
		"https://jobs.gem.com/acme/job-123",
		`[{"id":"job-123","title":"Backend Engineer","content":"","content_plain":"[GemPhish](https://evil.com/gem)\n# FakeGemHeading\n<img src=x onerror=1>\nPlain job description."}]`,
		"",
	)
	if !okGemPlain || gemPlainDoc == nil ||
		hasUnescapedClickableEvilLinkR10(gemPlainDoc.Markdown) ||
		!strings.Contains(gemPlainDoc.Markdown, `\[GemPhish\]`) ||
		strings.Contains(gemPlainDoc.Markdown, "\n# FakeGemHeading") ||
		!strings.Contains(gemPlainDoc.Markdown, `\# FakeGemHeading`) ||
		strings.Contains(gemPlainDoc.Markdown, "<img ") ||
		!strings.Contains(gemPlainDoc.Markdown, "Plain job description.") {
		t.Fatalf("R9-GO-1: gem-ats bodyPlain fallback leaked unescaped link/heading/HTML:\n%+v", gemPlainDoc)
	}

	gemHTMLDoc, okGemHTML := FormatDeclarativeTwinByURL(
		"https://jobs.gem.com/acme/job-456",
		`[{"id":"job-456","title":"Systems Engineer","content":"<p>Explore <a href=\"https://acme.com/benefits\">Benefits</a> today.</p>","content_plain":"[Ignored](https://evil.com/ignored)"}]`,
		"",
	)
	if !okGemHTML || gemHTMLDoc == nil ||
		!strings.Contains(gemHTMLDoc.Markdown, "[Benefits](https://acme.com/benefits)") ||
		strings.Contains(gemHTMLDoc.Markdown, "evil.com/ignored") {
		t.Fatalf("R9-GO-1: gem-ats HTML branch must preserve legitimate Markdown links:\n%+v", gemHTMLDoc)
	}

	// R9-GO-2: XenForo quoteTitle escapes literal [ and ] without double-escaping
	xfQuoteHTML := `<!doctype html><html><body>
		<h1 class="p-title-value">Topic Title</h1>
		<article class="message--post"><div class="message-main"><header><a class="message-name">Bob</a></header><div class="bbWrapper">
			<blockquote class="bbCodeBlock bbCodeBlock--quote">
				<div class="bbCodeBlock-title">[QuotePhish](https://evil.com/q) said:</div>
				<div class="bbCodeBlock-content"><p>Quoted text here.</p></div>
			</blockquote>
			<p>Reply body text.</p>
		</div></div></article>
	</body></html>`
	xfQuoteDoc, okXfQuote := ApplyDeclarativeHTMLExtractor(xfQuoteHTML, "https://www.mtbr.com/threads/test-topic.123/", "", nil)
	if !okXfQuote || xfQuoteDoc == nil ||
		hasUnescapedClickableEvilLinkR10(xfQuoteDoc.Markdown) ||
		!strings.Contains(xfQuoteDoc.Markdown, `> **\[QuotePhish\]`) ||
		strings.Contains(xfQuoteDoc.Markdown, `\\[`) {
		t.Fatalf("R9-GO-2: xenforo quoteTitle leaked unescaped link or double-escaped:\n%+v", xfQuoteDoc)
	}

	// R9-GO-3: giant-liv-bikes <main> p fallback and nfpa plain-text toBodyMD escape leading # headings
	giantHTML := `<!doctype html><html><body><main>
		<h1>Defy Advanced</h1>
		<a href="https://static.giant-bicycles.com/Manuals/defy.pdf">Owner Manual</a>
		<p>  # FakeGiantHeading [Phish](https://evil.com/g)</p>
	</main></body></html>`
	giantDoc, okGiant := ApplyDeclarativeHTMLExtractor(giantHTML, "https://www.giant-bicycles.com/us/defy-advanced-pro-0", "", nil)
	if !okGiant || giantDoc == nil ||
		hasUnescapedClickableEvilLinkR10(giantDoc.Markdown) ||
		strings.Contains(giantDoc.Markdown, "\n# FakeGiantHeading") ||
		!strings.Contains(giantDoc.Markdown, `\# FakeGiantHeading`) {
		t.Fatalf("R9-GO-3: giant-liv-bikes <main> p fallback leaked leading # heading or link:\n%+v", giantDoc)
	}

	nfpaHTML := `<!doctype html><html><body><script id="__NEXT_DATA__" type="application/json">{
		"props":{"pageProps":{"layoutData":{"sitecore":{"route":{"placeholders":{"storefront-main":[
			{"componentName":"PageTitle","fields":{"Title":{"value":"NFPA 70"}}},
			{"componentName":"ContentBlock","fields":{
				"Heading":{"value":"Section"},
				"Content":{"value":"# FakeContentHeading\n[RawContentPhish](https://evil.com/rc)"},
				"Items":[{"heading":{"value":"Item"},"body":{"value":"# FakeItemH1\nDetails here"}}]
			}}
		]}}}}}}
	}</script></body></html>`
	nfpaDoc, okNfpa := ApplyDeclarativeHTMLExtractor(nfpaHTML, "https://www.nfpa.org/codes-and-standards/nfpa-70-standard-development/70", "", nil)
	if !okNfpa || nfpaDoc == nil ||
		hasUnescapedClickableEvilLinkR10(nfpaDoc.Markdown) ||
		strings.Contains(nfpaDoc.Markdown, "\n# FakeContentHeading") ||
		!strings.Contains(nfpaDoc.Markdown, `\# FakeContentHeading`) ||
		strings.Contains(nfpaDoc.Markdown, "\n# FakeItemH1") ||
		!strings.Contains(nfpaDoc.Markdown, `\# FakeItemH1`) {
		t.Fatalf("R9-GO-3: nfpa plain-text toBodyMD leaked leading # heading or link:\n%+v", nfpaDoc)
	}
}
