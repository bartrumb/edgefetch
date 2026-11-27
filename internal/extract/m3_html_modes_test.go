package extract

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestM3XenForoExtractorAndPathExclusions(t *testing.T) {
	xfHTML := `<!doctype html><html><body>
		<h1 class="p-title-value">Bosch Gen4 Noise Fix</h1>
		<div class="p-body">
			<div class="p-body-main">
				<article class="message message--post" data-author="Alice" data-content="post-101">
					<div class="message-main">
						<header><a class="message-name">Alice</a><time class="u-dt" datetime="2026-03-10T14:22:00Z">Mar 10, 2026</time></header>
						<div class="bbWrapper"><p>Check motor mounting bolt torque at 20 Nm.</p></div>
						<aside class="message-signature">Sent from my noisy signature block</aside>
					</div>
				</article>
				<article class="message message--post" data-author="Bob" data-content="post-102">
					<div class="message-main">
						<header><a class="message-name">Bob</a><time class="u-dt" data-time="1773187200">Mar 11, 2026</time></header>
						<div class="bbWrapper">
							<blockquote class="bbCodeBlock bbCodeBlock--expandable bbCodeBlock--quote">
								<div class="bbCodeBlock-title">Alice said:</div>
								<div class="bbCodeBlock-content">
									<div class="bbCodeBlock-expandContent"><p>Check motor mounting bolt torque at 20 Nm.</p></div>
									<div class="bbCodeBlock-expandLink">Click to expand...</div>
								</div>
							</blockquote>
							<p>Confirmed, Loctite 243 solved the creak.</p>
						</div>
						<aside class="message-signature">My signature <a href="https://spam.example">Buy now</a></aside>
					</div>
				</article>
			</div>
			<aside class="p-body-sidebar"><div>Latest posts sidebar noise</div></aside>
		</div>
	</body></html>`

	res, ok := ApplyDeclarativeHTMLExtractor(xfHTML, "https://forums.electricbikereview.com/threads/bosch-gen4-noise.9912/", "", nil)
	if !ok || res == nil || res.ExtractorID != "xenforo-thread" {
		t.Fatalf("expected xenforo-thread extraction, got ok=%v res=%+v", ok, res)
	}
	if !strings.Contains(res.Markdown, "## Original Post — Alice (2026-03-10T14:22:00Z)") {
		t.Fatalf("missing OP heading in markdown:\n%s", res.Markdown)
	}
	if !strings.Contains(res.Markdown, "## Reply #1 — Bob (2026-03-11T00:00:00Z)") {
		t.Fatalf("missing reply heading in markdown:\n%s", res.Markdown)
	}
	if !strings.Contains(res.Markdown, "> **Alice said:**") || !strings.Contains(res.Markdown, "> Check motor mounting bolt torque at 20 Nm.") {
		t.Fatalf("missing formatted quote block in markdown:\n%s", res.Markdown)
	}
	if strings.Contains(res.Markdown, "Click to expand...") {
		t.Fatalf("quote expand link should be stripped:\n%s", res.Markdown)
	}
	if strings.Contains(res.Markdown, "noisy signature") || strings.Contains(res.Markdown, "spam.example") || strings.Contains(res.Markdown, "sidebar noise") {
		t.Fatalf("signature or sidebar chrome leaked into markdown:\n%s", res.Markdown)
	}
	if len(res.Records) != 2 || res.Records[0]["author"] != "Alice" {
		t.Fatalf("unexpected xenforo records: %+v", res.Records)
	}

	// Verify /sphere/threads/ works (endless-sphere) while /forums/ and /sphere/search/ fail open (return false).
	esRes, esOk := ApplyDeclarativeHTMLExtractor(xfHTML, "https://endless-sphere.com/sphere/threads/bosch-gen4.54321/", "", nil)
	if !esOk || esRes == nil || esRes.ExtractorID != "xenforo-thread" {
		t.Fatalf("expected endless-sphere /sphere/threads/ match, got ok=%v", esOk)
	}
	if _, badOk := ApplyDeclarativeHTMLExtractor(xfHTML, "https://endless-sphere.com/forums/threads/bad.1/", "", nil); badOk {
		t.Fatal("expected /forums/ path to be excluded")
	}
	if _, searchOk := ApplyDeclarativeHTMLExtractor(xfHTML, "https://endless-sphere.com/sphere/search/threads/", "", nil); searchOk {
		t.Fatal("expected /sphere/search/ path to be excluded")
	}
	if _, nonXFOk := ApplyDeclarativeHTMLExtractor(`<html><body><h1>Not a forum</h1><p>Just a thread article</p></body></html>`, "https://example.com/threads/123", "", nil); nonXFOk {
		t.Fatal("expected non-XenForo HTML to fail open")
	}
}

func TestM3SramDocsAndBoschHelpOver2MiBAndSuspense(t *testing.T) {
	// Build a > 2.2 MiB HTML payload (within 4 MiB HardMaxHTMLDocChars) with a huge data:image/png;base64 blob BEFORE main content.
	bigBase64 := strings.Repeat("A", 2_250_000)
	sramHTML := `<!doctype html><html><body>
		<nav aria-label="breadcrumb"><a href="/en-US">SRAM</a><a href="/en-US/drivetrain">Drivetrain</a></nav>
		<img src="data:image/png;base64,` + bigBase64 + `" alt="inline blob" />
		<div class="dodo-service-include__error" aria-hidden="true">Service include failed</div>
		<main>
			<h1 class="ft-topic-title">RED AXS Crankset Installation</h1>
			<div class="ft-topic-content">
				<p>Tighten the crank arm bolt to 54 Nm using an 8mm hex bit.</p>
				<p>Download <a href="/manuals/red-axs-manual.pdf">User Manual PDF</a>.</p>
			</div>
		</main>
	</body></html>`

	doc := ExtractHTMLDocumentFull(sramHTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/abc123?models=fc-red-d1,rd-red-e1",
		OnlyMainContent: true,
		IncludeImages:   true,
	})
	if doc.ExtractorID != "sram-docs" {
		t.Fatalf("expected extractorId sram-docs even above 2 MiB, got %q", doc.ExtractorID)
	}
	if !strings.Contains(doc.Markdown, "54 Nm") || !strings.Contains(doc.Markdown, "SRAM › Drivetrain") || !strings.Contains(doc.Markdown, "fc-red-d1, rd-red-e1") {
		t.Fatalf("missing expected sram-docs content/breadcrumbs/models:\n%s", doc.Markdown)
	}
	if !strings.Contains(doc.Markdown, "https://docs.sram.com/manuals/red-axs-manual.pdf") {
		t.Fatalf("missing resolved https PDF link:\n%s", doc.Markdown)
	}
	if strings.Contains(doc.Markdown, "data:image/") || strings.Contains(doc.Markdown, "Service include failed") {
		t.Fatalf("data:image or dodo error leaked:\n%s", doc.Markdown)
	}

	// Bosch Help Center with React Suspense $RC slot + dodo-service-include__error + data:image blob.
	boschHTML := `<!doctype html><html><head><title>Error 503 - Bosch eBike Systems</title></head><body>
		<nav aria-label="Breadcrumb"><a href="/us/help-center">Help Center</a><span>Error Codes</span></nav>
		<div class="dodo-service-include__error" aria-hidden="true">Include Error Banner</div>
		<template id="B:0">Loading...</template>
		<div hidden id="S:0">
			<h1>Error Code 503</h1>
			<p>Check the speed sensor magnet alignment on the rear wheel spoke.</p>
			<a href="https://help.bosch-ebike.com/files/speed-sensor-guide.pdf">Sensor Guide</a>
		</div>
		<script>$RC("B:0","S:0");$RV("x");</script>
	</body></html>`
	bDoc := ExtractHTMLDocumentFull(boschHTML, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes?models=bdu37yy",
		OnlyMainContent: true,
	})
	if bDoc.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("expected extractorId bosch-ebike-help, got %q", bDoc.ExtractorID)
	}
	if !strings.Contains(bDoc.Markdown, "speed sensor magnet alignment") || !strings.Contains(bDoc.Markdown, "bdu37yy") || !strings.Contains(bDoc.Markdown, "speed-sensor-guide.pdf") {
		t.Fatalf("missing rescued Suspense content / models / PDF:\n%s", bDoc.Markdown)
	}
	if strings.Contains(bDoc.Markdown, "Include Error Banner") || strings.Contains(bDoc.Markdown, "$RC(") {
		t.Fatalf("dodo error or $RC script leaked:\n%s", bDoc.Markdown)
	}
	// www.bosch-ebike.com MUST NOT match bosch-ebike-help.
	wwwDoc := ExtractHTMLDocumentFull(boschHTML, FullExtractOptions{
		BaseURL:         "https://www.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if wwwDoc.ExtractorID == "bosch-ebike-help" {
		t.Fatal("www.bosch-ebike.com must NOT match bosch-ebike-help manifest")
	}
}

func TestM3BoschHelpReact18SuspenseInsideMain(t *testing.T) {
	// Case A: <main> has >= 20 chars shell + <template id="B:0"></template>, <div hidden id="S:0"> outside </main>.
	caseA := `<!doctype html><html><body>
		<main><h1>Bosch eBike Help Center</h1><p>Please wait while loading article details...</p><!--$?--><template id="B:0"></template><!--/$--></main>
		<div class="dodo-service-include__error">Error loading</div>
		<div hidden id="S:0"><h2>Error Code 503 Troubleshooting</h2><p>Real Bosch content: Inspect the speed sensor magnet on the rear wheel spoke.</p></div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docA := ExtractHTMLDocumentFull(caseA, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if docA.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("Case A: expected bosch-ebike-help, got %q", docA.ExtractorID)
	}
	if !strings.Contains(docA.Markdown, "Real Bosch content") || !strings.Contains(docA.Markdown, "Error Code 503 Troubleshooting") {
		t.Fatalf("Case A: missing S:0 content:\n%s", docA.Markdown)
	}
	if strings.Contains(docA.Markdown, "Error loading") || strings.Contains(docA.Markdown, "$RC(") {
		t.Fatalf("Case A: leaked error banner or $RC:\n%s", docA.Markdown)
	}
	if strings.Count(docA.Markdown, "Real Bosch content") != 1 {
		t.Fatalf("Case A: expected S:0 content exactly once, got:\n%s", docA.Markdown)
	}

	// Case B: <main> contains .dodo-service-include__error + >= 20 chars + <template id="B:0">Loading...</template>, nested <div> in S:0.
	caseB := `<!doctype html><html><body>
		<main><div class="dodo-service-include__error">Error loading</div><p>Shell wrapper text exceeding twenty characters.</p><template id="B:0">Loading...</template></main>
		<div hidden id="S:0"><div class="outer"><div class="inner"><p>Nested div troubleshooting steps.</p></div></div></div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docB := ExtractHTMLDocumentFull(caseB, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/case-b",
		OnlyMainContent: true,
	})
	if !strings.Contains(docB.Markdown, "Nested div troubleshooting steps.") || strings.Contains(docB.Markdown, "Loading...") || strings.Contains(docB.Markdown, "Error loading") {
		t.Fatalf("Case B: unexpected markdown:\n%s", docB.Markdown)
	}

	// Case C: Multi-slot + out-of-order + nested Suspense.
	caseC := `<!doctype html><html><body>
		<main><h1>Guide</h1><template id="B:0"></template><p>Middle static paragraph.</p><template id="B:1"></template></main>
		<div hidden id="S:1"><div>Second slot <template id="B:2"></template></div></div>
		<div hidden id="S:0"><div>First slot</div></div>
		<div hidden id="S:2"><p>Nested slot</p></div>
		<script>$RC("B:0","S:0");$RC("B:1","S:1");$RC("B:2","S:2")</script>
	</body></html>`
	docC := ExtractHTMLDocumentFull(caseC, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/case-c",
		OnlyMainContent: true,
	})
	iFirst := strings.Index(docC.Markdown, "First slot")
	iMid := strings.Index(docC.Markdown, "Middle static paragraph.")
	iSec := strings.Index(docC.Markdown, "Second slot")
	iNest := strings.Index(docC.Markdown, "Nested slot")
	if !(iFirst >= 0 && iFirst < iMid && iMid < iSec && iSec < iNest) {
		t.Fatalf("Case C: expected order First < Middle < Second < Nested, got:\n%s", docC.Markdown)
	}

	// Case D: Missing <template id="B:0"> fallback.
	caseD := `<!doctype html><html><body>
		<main><h1>Bosch Help</h1><p>Shell text exceeding twenty chars.</p></main>
		<div hidden id="S:0"><p>Fallback out-of-band slot</p></div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docD := ExtractHTMLDocumentFull(caseD, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/case-d",
		OnlyMainContent: true,
	})
	if !strings.Contains(docD.Markdown, "Fallback out-of-band slot") {
		t.Fatalf("Case D: missing fallback out-of-band slot:\n%s", docD.Markdown)
	}

	// Case E: 3.5 MiB data:image/ before <main> + React 18 <template id="B:0"> inside <main> + S:0 outside </main>.
	bigDataImg := `<img src="data:image/png;base64,` + strings.Repeat("C", 3_500_000) + `" alt="huge" />`
	caseE := `<!doctype html><html><body>` + bigDataImg + `
		<main><h1>Bosch Large Doc</h1><p>Loading placeholder text that is over twenty characters.</p><template id="B:0"></template></main>
		<div hidden id="S:0"><p>Rescued after 3.5 MiB image strip.</p></div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docE := ExtractHTMLDocumentFull(caseE, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/case-e",
		OnlyMainContent: true,
	})
	if docE.ExtractorID != "bosch-ebike-help" || !strings.Contains(docE.Markdown, "Rescued after 3.5 MiB image strip.") || strings.Contains(docE.Markdown, "data:image/") {
		t.Fatalf("Case E: unexpected result extractorId=%q:\n%s", docE.ExtractorID, docE.Markdown)
	}
}

func TestM3BoschHelpOrphanS0NestedS2Once(t *testing.T) {
	// With <main> (>= 20 chars) and missing <template id="B:0">, S:0 wraps nested B:2 -> S:2.
	withMain := `<!doctype html><html><body>
		<main><h1>Missing Template Nested</h1><p>Main shell text over twenty characters.</p></main>
		<div hidden id="S:0"><p>OrphanOuter</p><template id="B:2"></template><p>OrphanAfter</p></div>
		<div hidden id="S:2"><p>OrphanInnerS2 Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p></div>
		<script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
	</body></html>`
	docWithMain := ExtractHTMLDocumentFull(withMain, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if docWithMain.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("expected bosch-ebike-help, got %q", docWithMain.ExtractorID)
	}
	if cnt := strings.Count(docWithMain.Markdown, "OrphanInnerS2"); cnt != 1 {
		t.Fatalf("with <main>: expected OrphanInnerS2 count=1, got %d:\n%s", cnt, docWithMain.Markdown)
	}
	if cnt := strings.Count(docWithMain.Markdown, "OrphanOuter"); cnt != 1 {
		t.Fatalf("with <main>: expected OrphanOuter count=1, got %d:\n%s", cnt, docWithMain.Markdown)
	}

	// Without <main> (else branch when bodyEl == nil or small slots): S:0 wraps nested B:2 -> S:2.
	withoutMain := `<!doctype html><html><body>
		<div hidden id="S:0"><p>A</p><template id="B:2"></template></div>
		<div hidden id="S:2"><p>OrphanInnerS2</p></div>
		<script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
	</body></html>`
	docNoMain := ExtractHTMLDocumentFull(withoutMain, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if docNoMain.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("without <main>: expected bosch-ebike-help, got %q", docNoMain.ExtractorID)
	}
	if cnt := strings.Count(docNoMain.Markdown, "OrphanInnerS2"); cnt != 1 {
		t.Fatalf("without <main>: expected OrphanInnerS2 count=1, got %d:\n%s", cnt, docNoMain.Markdown)
	}
}

func TestM3BodyMarkdownLinkInjectionAndBalancedParens(t *testing.T) {
	reUnescapedInjected := regexp.MustCompile(`(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?://evil\.com`)
	assertNoInjectedLink := func(t *testing.T, label, md, baseURL string, links []string) {
		t.Helper()
		if reUnescapedInjected.MatchString(md) {
			t.Fatalf("%s: unescaped injected markdown link found in:\n%s", label, md)
		}
		mdLinks, _ := ExtractMarkdownLinksAndImages(md, baseURL)
		for _, ml := range mdLinks {
			if u, err := url.Parse(ml); err == nil && strings.EqualFold(u.Hostname(), "evil.com") {
				t.Fatalf("%s: markdown parsed an injected evil.com link %q in:\n%s", label, ml, md)
			}
		}
		for _, l := range links {
			if strings.Contains(l, ")[xss](") || strings.Contains(l, "[xss]") {
				t.Fatalf("%s: unescaped breakout chars in links[]: %q", label, l)
			}
			if u, err := url.Parse(l); err == nil && strings.EqualFold(u.Hostname(), "evil.com") {
				t.Fatalf("%s: evil.com leaked into links[]: %q", label, l)
			}
		}
	}

	// 1. sram-docs body link injection (both without and with trailing ')') + label injection + backslash
	sramHTML := `<!doctype html><html><body><main><h1>Tech Doc</h1>
		<p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
		<p><a href="https://docs.sram.com/a)[xss](https://evil.com/doc.pdf">Manual PDF</a></p>
		<p><a href="https://docs.sram.com/a)[xss](https://evil.com/doc.pdf)">Manual PDF Balanced</a></p>
		<p><a href="https://docs.sram.com/a\)[xss](https://evil.com/doc.pdf">Backslash PDF</a></p>
		<p><a href="https://docs.sram.com/doc">Label ](https://evil.com/doc.pdf)</a></p>
		<p><a href="https://docs.sram.com/doc2">Label [xss](https://evil.com/doc.pdf)</a></p>
	</main></body></html>`
	sramDoc := ExtractHTMLDocumentFull(sramHTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/7E6x3h",
		OnlyMainContent: true,
	})
	if sramDoc.ExtractorID != "sram-docs" {
		t.Fatalf("expected sram-docs, got %q", sramDoc.ExtractorID)
	}
	assertNoInjectedLink(t, "sram-docs", sramDoc.Markdown, "https://docs.sram.com/en-US/publications/7E6x3h", sramDoc.Links)
	if !strings.Contains(sramDoc.Markdown, "[Manual PDF](https://docs.sram.com/a%29%5Bxss%5D%28https://evil.com/doc.pdf)") {
		t.Fatalf("sram-docs: expected percent-encoded destination, got:\n%s", sramDoc.Markdown)
	}

	// 2. bosch-ebike-help body link injection
	boschHTML := `<!doctype html><html><body><main><h1>Tech Doc</h1>
		<p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
		<p><a href="https://help.bosch-ebike.com/a)[xss](https://evil.com/doc.pdf">Manual PDF</a></p>
	</main></body></html>`
	boschDoc := ExtractHTMLDocumentFull(boschHTML, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if boschDoc.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("expected bosch-ebike-help, got %q", boschDoc.ExtractorID)
	}
	assertNoInjectedLink(t, "bosch-ebike-help", boschDoc.Markdown, "https://help.bosch-ebike.com/us/help-center/ebw-error-codes", boschDoc.Links)
	if !strings.Contains(boschDoc.Markdown, "[Manual PDF](https://help.bosch-ebike.com/a%29%5Bxss%5D%28https://evil.com/doc.pdf)") {
		t.Fatalf("bosch-ebike-help: expected percent-encoded destination, got:\n%s", boschDoc.Markdown)
	}

	// 3. xenforo-thread body link injection
	xfHTML := `<!doctype html><html><body><div class="p-body-main">
		<article class="message message--post" data-author="Alice">
			<div class="message-main"><div class="bbWrapper">
				<p>Check <a href="https://example.com/a)[xss](https://evil.com/x)">Click</a> and <a href="https://example.com/ok">Bad ](https://evil.com/x)</a>.</p>
			</div></div>
		</article>
	</div></body></html>`
	xfDoc := ExtractHTMLDocumentFull(xfHTML, FullExtractOptions{
		BaseURL:         "https://forums.electricbikereview.com/threads/test.123/",
		OnlyMainContent: true,
	})
	if xfDoc.ExtractorID != "xenforo-thread" {
		t.Fatalf("expected xenforo-thread, got %q", xfDoc.ExtractorID)
	}
	assertNoInjectedLink(t, "xenforo-thread", xfDoc.Markdown, "https://forums.electricbikereview.com/threads/test.123/", xfDoc.Links)

	// 4. General ExtractHTMLDocumentFull: balanced-paren URLs like Wikipedia Foo_(bar) preserved while breakout payloads encoded
	genHTML := `<!doctype html><html><body><main><h1>Links</h1>
		<p><a href="https://en.wikipedia.org/wiki/Foo_(bar)">Foo</a> and <a href="https://example.com/a)[xss](https://evil.com/x)">Click</a>.</p>
	</main></body></html>`
	genDoc := ExtractHTMLDocumentFull(genHTML, FullExtractOptions{
		BaseURL:         "https://example.com/article",
		OnlyMainContent: true,
	})
	assertNoInjectedLink(t, "general", genDoc.Markdown, "https://example.com/article", genDoc.Links)
	if !strings.Contains(genDoc.Markdown, "[Foo](https://en.wikipedia.org/wiki/Foo_(bar))") {
		t.Fatalf("expected balanced paren URL preserved in markdown:\n%s", genDoc.Markdown)
	}
	foundBalanced := false
	for _, l := range genDoc.Links {
		if l == "https://en.wikipedia.org/wiki/Foo_(bar)" {
			foundBalanced = true
		}
	}
	if !foundBalanced {
		t.Fatalf("expected balanced paren URL preserved in links[], got %+v", genDoc.Links)
	}
}

func TestM3MultiPassEntityLinkInjectionAndBadgeHardening(t *testing.T) {
	reUnescapedInjected := regexp.MustCompile(`(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?://evil\.com`)
	assertCleanDoc := func(t *testing.T, label string, doc ExtractedDocumentFull, baseURL string) {
		t.Helper()
		if reUnescapedInjected.MatchString(doc.Markdown) {
			t.Fatalf("%s: unescaped injected markdown link found in:\n%s", label, doc.Markdown)
		}
		mdLinks, _ := ExtractMarkdownLinksAndImages(doc.Markdown, baseURL)
		for _, ml := range mdLinks {
			if u, err := url.Parse(ml); err == nil && strings.EqualFold(u.Hostname(), "evil.com") {
				t.Fatalf("%s: markdown parsed an injected evil.com link %q in:\n%s", label, ml, doc.Markdown)
			}
		}
		for _, l := range doc.Links {
			if strings.Contains(l, "&rpar;") || strings.Contains(l, "&lsqb;") || strings.Contains(l, ")[xss](") {
				t.Fatalf("%s: entity/breakout chars leaked into links[]: %q", label, l)
			}
			if u, err := url.Parse(l); err == nil && strings.EqualFold(u.Hostname(), "evil.com") {
				t.Fatalf("%s: evil.com leaked into links[]: %q", label, l)
			}
		}
	}

	// 1. Bypass #1: multi-encoded entities in <a> labels, <td><a>, <a><h2>, and <img alt>
	bypass1HTML := `<!doctype html><html><body><main>
		<h1>Tech Manual</h1>
		<p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
		<p><a href="https://docs.sram.com/ok">Manual &amp;#93;(https://evil.com/doc.pdf)</a></p>
		<p><a href="https://docs.sram.com/ok2">Hex &amp;#x5D;(https://evil.com/doc.pdf)</a></p>
		<p><a href="https://docs.sram.com/ok3">Named &amp;rsqb;(https://evil.com/doc.pdf)</a></p>
		<p><a href="https://docs.sram.com/ok4">Triple &amp;amp;#93;(https://evil.com/doc.pdf)</a></p>
		<p><a href="https://docs.sram.com/ok5">Backslash &amp;bsol;&amp;#93;(https://evil.com/doc.pdf)</a></p>
		<table><tr><th>Doc</th><th>Ref</th></tr><tr><td><a href="https://docs.sram.com/cell">Cell &amp;#93;(https://evil.com/cell.pdf)</a></td><td>v1</td></tr></table>
		<a href="https://docs.sram.com/head"><h2>Head &amp;#93;(https://evil.com/h.pdf)</h2></a>
		<p><img src="https://docs.sram.com/a.png" alt="Img &amp;amp;#93;(https://evil.com/img.png)"></p>
	</main></body></html>`
	b1Doc := ExtractHTMLDocumentFull(bypass1HTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/7E6x3h",
		OnlyMainContent: true,
		IncludeImages:   true,
	})
	assertCleanDoc(t, "bypass1-sram", b1Doc, "https://docs.sram.com/en-US/publications/7E6x3h")

	// 2. Bypass #2: double- and triple-encoded entities in PDF and body links on sram-docs & bosch-ebike-help
	sramBypass2HTML := `<!doctype html><html><body><main><h1>Tech Doc</h1>
		<p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
		<p><a href="https://docs.sram.com/a&amp;rpar;&amp;lsqb;xss&amp;rsqb;&amp;lpar;https://evil.com/doc.pdf">Manual PDF</a></p>
		<p><a href="https://docs.sram.com/b&amp;amp;rpar;&amp;amp;lsqb;xss&amp;amp;rsqb;&amp;amp;lpar;https://evil.com/doc2.pdf">Triple PDF</a></p>
	</main></body></html>`
	sramB2 := ExtractHTMLDocumentFull(sramBypass2HTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/7E6x3h",
		OnlyMainContent: true,
	})
	assertCleanDoc(t, "bypass2-sram", sramB2, "https://docs.sram.com/en-US/publications/7E6x3h")
	if strings.Contains(sramB2.Markdown, "## PDF Manuals") {
		t.Fatalf("bypass2-sram: unsafe entity PDF link should be rejected from ## PDF Manuals:\n%s", sramB2.Markdown)
	}
	if !strings.Contains(sramB2.Markdown, "https://docs.sram.com/a%29%5Bxss%5D%28https://evil.com/doc.pdf") ||
		!strings.Contains(sramB2.Markdown, "https://docs.sram.com/b%29%5Bxss%5D%28https://evil.com/doc2.pdf") {
		t.Fatalf("bypass2-sram: expected percent-encoded body links in markdown:\n%s", sramB2.Markdown)
	}

	boschBypass2HTML := `<!doctype html><html><body><main><h1>Bosch Doc</h1>
		<p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p>
		<p><a href="https://help.bosch-ebike.com/a&amp;rpar;&amp;lsqb;xss&amp;rsqb;&amp;lpar;https://evil.com/doc.pdf">Manual PDF</a></p>
	</main></body></html>`
	boschB2 := ExtractHTMLDocumentFull(boschBypass2HTML, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	assertCleanDoc(t, "bypass2-bosch", boschB2, "https://help.bosch-ebike.com/us/help-center/ebw-error-codes")
	if strings.Contains(boschB2.Markdown, "## PDF Manuals") {
		t.Fatalf("bypass2-bosch: unsafe entity PDF link should be rejected from ## PDF Manuals:\n%s", boschB2.Markdown)
	}

	// 3. isSafePublicHTTPSFeedURL entity checks & formatSafeMarkdownLinkSchemaGo
	for _, badURL := range []string{
		"https://docs.sram.com/a&rpar;&lsqb;xss&rsqb;&lpar;https://evil.com/doc.pdf",
		"https://docs.sram.com/a&#41;&#91;xss&#93;&#40;https://evil.com/doc.pdf",
		"https://docs.sram.com&#x3a;8080/doc.pdf",
		"https://user&commat;docs.sram.com/doc.pdf",
	} {
		if isSafePublicHTTPSFeedURL(badURL) {
			t.Fatalf("isSafePublicHTTPSFeedURL unexpectedly accepted %q", badURL)
		}
	}
	if !isSafePublicHTTPSFeedURL("https://example.com/watch?v=1&currentTime=45&section=2&region=us") {
		t.Fatal("expected semicolonless query URL to remain safe in isSafePublicHTTPSFeedURL")
	}
	schemaLink := formatSafeMarkdownLinkSchemaGo("Label &amp;#93;(https://evil.com)", "https://docs.sram.com/a&rpar;&lsqb;xss&rsqb;&lpar;https://evil.com")
	if reUnescapedInjected.MatchString(schemaLink) || !strings.Contains(schemaLink, `\]`) {
		t.Fatalf("formatSafeMarkdownLinkSchemaGo failed to neutralize entity injection: %q", schemaLink)
	}

	// 4. Literal ![fake](...) inside <a> produces zero phantom images[], while real <a><img></a> badge is preserved
	fakeImgHTML := `<!doctype html><html><body><main><h1>Fake Img</h1>
		<p><a href="https://docs.sram.com/ok">![fake](https://evil.com/x.png)</a></p>
	</main></body></html>`
	fakeImgDoc := ExtractHTMLDocumentFull(fakeImgHTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/page",
		OnlyMainContent: true,
		IncludeImages:   true,
	})
	if len(fakeImgDoc.Images) != 0 {
		t.Fatalf("expected 0 phantom images for literal ![fake](...) text inside <a>, got %+v", fakeImgDoc.Images)
	}

	badgeHTML := `<!doctype html><html><body><main><h1>Badge</h1>
		<p><a href="https://docs.sram.com/ok"><img src="https://img.shields.io/a.svg" alt="ok"> Docs &amp;#93;(https://evil.com)</a></p>
	</main></body></html>`
	badgeDoc := ExtractHTMLDocumentFull(badgeHTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/page",
		OnlyMainContent: true,
		IncludeImages:   true,
	})
	assertCleanDoc(t, "badge-link", badgeDoc, "https://docs.sram.com/page")
	if len(badgeDoc.Images) != 1 || badgeDoc.Images[0].URL != "https://img.shields.io/a.svg" {
		t.Fatalf("expected real badge image preserved in images[], got %+v (md=%s)", badgeDoc.Images, badgeDoc.Markdown)
	}

	// 5. Compatibility: Wikipedia Foo_(bar), MediaWiki [edit]/[1] stripping, and semicolonless &section query
	compatHTML := `<!doctype html><html><body><main>
		<h1>Title <span class="mw-editsection"><a href="https://en.wikipedia.org/w/index.php?title=Foo&amp;action=edit">edit</a></span></h1>
		<p>See <a href="https://en.wikipedia.org/wiki/Foo_(bar)">Foo</a><sup class="reference"><a href="#cite_note-1">[1]</a></sup> and <a href="https://example.com/watch?v=1&amp;currentTime=45&section=2&region=us">Video</a>.</p>
	</main></body></html>`
	compatDoc := ExtractHTMLDocumentFull(compatHTML, FullExtractOptions{
		BaseURL:         "https://en.wikipedia.org/wiki/Test",
		OnlyMainContent: true,
	})
	if !strings.Contains(compatDoc.Markdown, "[Foo](https://en.wikipedia.org/wiki/Foo_(bar))") {
		t.Fatalf("expected Wikipedia Foo_(bar) preserved:\n%s", compatDoc.Markdown)
	}
	if !strings.Contains(compatDoc.Markdown, "https://example.com/watch?v=1&currentTime=45&section=2&region=us") {
		t.Fatalf("expected semicolonless &currentTime=45&section=2&region=us preserved:\n%s", compatDoc.Markdown)
	}
	if strings.Contains(compatDoc.Markdown, "[1]") || strings.Contains(compatDoc.Markdown, "[edit]") {
		t.Fatalf("expected MediaWiki [edit]/[1] stripped:\n%s", compatDoc.Markdown)
	}

	// 6. Full-doc HTML-to-MD single-encoded bracket entities across tables, headings, lists, inline tags & frontmatter
	entityHTML := `<!doctype html><html><body><main>
		<h2><span>Head</span> &#93;(https://evil.com)</h2>
		<table><tr><th>Col &#91;xss&#93;(https://evil.com)</th></tr><tr><td>[Click &#93;(https://evil.com)</td></tr></table>
		<ul><li>Item &lsqb;xss&rsqb;(https://evil.com)</li></ul>
		<p><strong>Bold &amp;#93;(https://evil.com)</strong> and <em>Ital &#93;(https://evil.com)</em></p>
		<p>See <a href="https://en.wikipedia.org/wiki/Foo_(bar)">Foo</a> and <a href="https://example.com/watch?v=1&amp;currentTime=45&section=2&region=us">Video</a>.</p>
	</main></body></html>`
	reEvilLink := regexp.MustCompile(`(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?://evil\.com`)
	for _, docBase := range []string{"https://docs.sram.com/page", "https://example.com/page"} {
		entityDoc := ExtractHTMLDocumentFull(entityHTML, FullExtractOptions{
			BaseURL:         docBase,
			OnlyMainContent: true,
		})
		if reEvilLink.MatchString(entityDoc.Markdown) {
			t.Fatalf("[%s] expected entity-encoded evil.com links escaped in full-doc Markdown:\n%s", docBase, entityDoc.Markdown)
		}
		if !strings.Contains(entityDoc.Markdown, "[Foo](https://en.wikipedia.org/wiki/Foo_(bar))") ||
			!strings.Contains(entityDoc.Markdown, "https://example.com/watch?v=1&currentTime=45&section=2&region=us") {
			t.Fatalf("[%s] expected Foo_(bar) and &currentTime=45&section=2&region=us preserved:\n%s", docBase, entityDoc.Markdown)
		}
		if idem := SanitizeMarkdown(entityDoc.Markdown, docBase); idem != entityDoc.Markdown {
			t.Fatalf("[%s] expected ExtractHTMLDocumentFull Markdown idempotent under SanitizeMarkdown:\n  got1=%q\n  got2=%q", docBase, entityDoc.Markdown, idem)
		}
	}
	fmTitle, _, _ := ParseMarkdownFrontmatter("---\ntitle: \"Guide &amp;#93;(https://evil.com)\"\n---\nBody")
	if reEvilLink.MatchString(fmTitle) {
		t.Fatalf("expected frontmatter title to escape bracket entities, got %q", fmTitle)
	}
}

func TestM3Iteration6VerifierHardening(t *testing.T) {
	reEvilLink := regexp.MustCompile(`(?:^|[^\\])(?:\[xss\]|\])\s*\(\s*https?://evil\.com`)
	assertNoEvil := func(t *testing.T, label, md, baseURL string) {
		t.Helper()
		if reEvilLink.MatchString(md) {
			t.Fatalf("[%s] unescaped evil.com link found in:\n%s", label, md)
		}
		mdLinks, _ := ExtractMarkdownLinksAndImages(md, baseURL)
		for _, ml := range mdLinks {
			if u, err := url.Parse(ml); err == nil && strings.EqualFold(u.Hostname(), "evil.com") {
				t.Fatalf("[%s] ExtractMarkdownLinksAndImages parsed evil.com link %q in:\n%s", label, ml, md)
			}
		}
		if idem := SanitizeMarkdown(md, baseURL); idem != md {
			t.Fatalf("[%s] markdown not idempotent under SanitizeMarkdown:\n  1=%q\n  2=%q", label, md, idem)
		}
	}

	// 1. Empty / disallowed href <a> in ExtractHTMLDocumentFull (prose, <td>, badge <img>) & hnFragmentToMarkdownFullDocGo
	anchorHTML := `<!doctype html><html><body><main>
		<h1>Anchor Hardening</h1>
		<p><a>&#91;xss&#93;</a>(https://evil.com)</p>
		<p><a href="javascript:alert(1)">&lsqb;xss&rsqb;(https://evil.com)</a></p>
		<p><a name="sec"><img src="https://docs.sram.com/a.png" alt="ok"> [Click &#93;(https://evil.com)</a></p>
		<table><tr><th>Col</th></tr><tr><td><a href="javascript:alert(1)">&#91;xss&#93;</a>(https://evil.com)</td></tr></table>
	</main></body></html>`
	for _, base := range []string{"https://example.com/page", "https://docs.sram.com/en-US/publications/abc"} {
		d := ExtractHTMLDocumentFull(anchorHTML, FullExtractOptions{
			BaseURL:         base,
			OnlyMainContent: true,
			IncludeImages:   true,
		})
		assertNoEvil(t, "anchor-"+base, d.Markdown, base)
	}
	hnMD := hnFragmentToMarkdownFullDocGo(`<a href="javascript:alert(1)">&#91;xss&#93;</a>(https://evil.com)`, "https://news.ycombinator.com/item?id=1")
	assertNoEvil(t, "hn-fragment", hnMD, "https://news.ycombinator.com/item?id=1")

	// 2. SRAM title/breadcrumbs + HTML comment inside .ft-topic-content + meta description multi-&amp; idempotence
	sramHTML := `<!doctype html><html><head>
		<meta name="description" content="[Manual &amp;amp;amp;#93;(https://evil.com)](https://docs.sram.com/ok)">
	</head><body>
		<nav aria-label="breadcrumb"><a href="/en">Crumb &#91;xss&#93;(https://evil.com)</a></nav>
		<main>
			<h1 class="ft-topic-title">Title &#91;xss&#93;(https://evil.com)</h1>
			<div class="ft-topic-content">
				<p>Before comment.</p>
				<!-- </div> fake close tag inside comment -->
				<p>IMPORTANT_AFTER_COMMENT content must not be truncated!</p>
			</div>
		</main>
	</body></html>`
	sramDoc := ExtractHTMLDocumentFull(sramHTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/7E6x3h",
		OnlyMainContent: true,
	})
	assertNoEvil(t, "sram-comment-title-crumb", sramDoc.Markdown, "https://docs.sram.com/en-US/publications/7E6x3h")
	if !strings.Contains(sramDoc.Markdown, "IMPORTANT_AFTER_COMMENT") || !strings.Contains(sramDoc.Markdown, "Crumb") {
		t.Fatalf("sram-docs truncated on comment or dropped breadcrumbs:\n%s", sramDoc.Markdown)
	}
	if SanitizeScrapedMeta(sramDoc.Description) != sramDoc.Description {
		t.Fatalf("sramDoc.Description not idempotent under SanitizeScrapedMeta: %q", sramDoc.Description)
	}

	// 3. Bosch Suspense S:0 / S:2 across HTML comments + void tag guard (<input class="article-body">) + title/breadcrumbs
	boschHTML := `<!doctype html><html><body>
		<nav aria-label="Breadcrumb"><a href="/us/help-center">Crumb &#91;xss&#93;(https://evil.com)</a></nav>
		<input class="article-body" type="hidden" value="ignore">
		<main><p>Shell loading placeholder exceeding twenty chars.</p><template id="B:0"></template></main>
		<div hidden id="S:0" data-x="a>b">
			<h1>Bosch &#91;xss&#93;(https://evil.com)</h1>
			<p>S0 start</p>
			<!-- </div> -->
			<template id="B:2"></template>
			<p>S0_TAIL_AFTER_COMMENT</p>
		</div>
		<div hidden id="S:2"><p>S2_INNER_CONTENT over twenty chars for bosch help.</p></div>
		<script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
	</body></html>`
	boschDoc := ExtractHTMLDocumentFull(boschHTML, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	assertNoEvil(t, "bosch-comment-void-title", boschDoc.Markdown, "https://help.bosch-ebike.com/us/help-center/ebw-error-codes")
	if !strings.Contains(boschDoc.Markdown, "S0_TAIL_AFTER_COMMENT") || !strings.Contains(boschDoc.Markdown, "S2_INNER_CONTENT") {
		t.Fatalf("bosch-ebike-help lost S:0 tail or S:2 on comment/void-tag:\n%s", boschDoc.Markdown)
	}

	// 4. XenForo thread title + quote title + HTML-commented <article> + <blockquote data-x="a>b">
	xfHTML := `<!doctype html><html><body>
		<h1 class="p-title-value">Thread &#91;xss&#93;(https://evil.com)</h1>
		<div class="p-body-main">
			<!-- <article class="message message--post" data-author="Ghost"><div class="bbWrapper"><p>Commented out</p></div></article> -->
			<article class="message message--post" data-author="Alice">
				<div class="message-main"><div class="bbWrapper">
					<blockquote class="bbCodeBlock bbCodeBlock--quote" data-x="a>b">
						<div class="bbCodeBlock-title">Quoted &#91;xss&#93;(https://evil.com)</div>
						<div class="bbCodeBlock-content"><p>Simple quote body &#91;xss&#93;(https://evil.com)</p></div>
					</blockquote>
					<p>Reply body <a href="javascript:alert(1)">&#91;xss&#93;</a>(https://evil.com)</p>
				</div></div>
			</article>
		</div>
	</body></html>`
	xfDoc := ExtractHTMLDocumentFull(xfHTML, FullExtractOptions{
		BaseURL:         "https://forums.electricbikereview.com/threads/test.123/",
		OnlyMainContent: true,
	})
	assertNoEvil(t, "xenforo-comment-quote-title", xfDoc.Markdown, "https://forums.electricbikereview.com/threads/test.123/")
	if strings.Contains(xfDoc.Markdown, `b">`) || !strings.Contains(xfDoc.Markdown, "Simple quote body") {
		t.Fatalf("xenforo quote data-x=\"a>b\" leaked or dropped body:\n%s", xfDoc.Markdown)
	}
	if strings.Contains(xfDoc.Markdown, "Commented out") || len(xfDoc.Records) != 1 {
		t.Fatalf("xenforo commented article leaked into records=%+v md=\n%s", xfDoc.Records, xfDoc.Markdown)
	}

	// 5. Inertia props triple-encoded &amp;amp;lsqb;... idempotence
	inertiaDoc := FormatInertiaPagePropsToMarkdown(map[string]any{
		"component": "Docs/Show",
		"props": map[string]any{
			"note": "Vend &amp;amp;lsqb;xss&amp;amp;rsqb;(https://evil.com)",
		},
	}, "https://docs.sram.com/page")
	if inertiaDoc == nil {
		t.Fatal("expected inertiaDoc")
	}
	assertNoEvil(t, "inertia-triple-amp", inertiaDoc.Markdown, "https://docs.sram.com/page")
}

func TestM3Iteration7MetaCommentSkipping(t *testing.T) {
	headHTML := `<!doctype html><html><head>
		<!-- <meta property="og:title" content="COMMENTED_OG"> -->
		<meta property="og:title" content="REAL_OG &#91;xss&#93;(https://evil.com)">
	</head><body><main><div class="ft-topic-content"><p>Inspect the speed sensor magnet on the rear wheel spoke and ensure the gap is between 5 mm and 17 mm.</p></div></main></body></html>`

	gotTitle := extractRawMetaTitleEscapingBracketsDeclHTML(headHTML, "og:title")
	if strings.Contains(gotTitle, "COMMENTED_OG") {
		t.Fatalf("extractRawMetaTitleEscapingBracketsDeclHTML matched commented <meta>: %q", gotTitle)
	}
	if gotTitle != `REAL_OG \[xss\](https://evil.com)` {
		t.Fatalf("extractRawMetaTitleEscapingBracketsDeclHTML = %q, want escaped REAL_OG", gotTitle)
	}

	sramDoc := ExtractHTMLDocumentFull(headHTML, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/7E6x3h",
		OnlyMainContent: true,
	})
	if sramDoc.ExtractorID != "sram-docs" {
		t.Fatalf("expected sram-docs, got %q", sramDoc.ExtractorID)
	}
	if strings.Contains(sramDoc.Markdown, "COMMENTED_OG") {
		t.Fatalf("sram-docs markdown leaked COMMENTED_OG:\n%s", sramDoc.Markdown)
	}
	if !strings.Contains(sramDoc.Markdown, `REAL_OG \[xss\](https://evil.com)`) {
		t.Fatalf("sram-docs markdown missing escaped REAL_OG:\n%s", sramDoc.Markdown)
	}
}

func TestM3Iteration8BoundedRawElementFallback(t *testing.T) {
	// 1. Unbalanced inner <div> inside <main> slices up to </main> without dropping inner <section>/<blockquote><footer>.
	unbalMain := `<main class="sw-product-detail"><div class="product-detail-description-text"><p>Safe &#91;xss&#93;&#40;https://evil.com&#41;</p><section><p>InnerSec</p></section><blockquote><footer>QuoteFooter</footer></blockquote><div><span>Unclosed<a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Watch</a></div></main><footer>PageFooter</footer>`
	if _, ok := ExtractFirstRawElementHTML(unbalMain, RawElementSelector{Class: "product-detail-description-text"}); ok {
		t.Fatal("expected strict ExtractFirstRawElementHTML to return false on unbalanced container")
	}
	gotMain, ok := ExtractFirstRawElementOrBoundedHTML(unbalMain, RawElementSelector{Class: "product-detail-description-text"})
	if !ok {
		t.Fatal("expected ExtractFirstRawElementOrBoundedHTML to succeed on unbalanced container")
	}
	if !strings.Contains(gotMain, "&#91;xss&#93;&#40;https://evil.com&#41;") ||
		!strings.Contains(gotMain, "&currentTime=45&section=2&region=us") ||
		!strings.Contains(gotMain, "InnerSec") ||
		!strings.Contains(gotMain, "QuoteFooter") {
		t.Fatalf("bounded slice corrupted or truncated valid inner content: %q", gotMain)
	}
	if strings.Contains(gotMain, "PageFooter") || strings.Contains(gotMain, "</main>") {
		t.Fatalf("bounded slice leaked past </main> into page footer: %q", gotMain)
	}

	// 2. Unbalanced inner <div> stopped by sibling <footer> (and ignoring decoy <footer> inside HTML comment/<script>).
	unbalFooter := `<div id="tab-description"><!-- <footer>CommentDecoy</footer> --><script>var x = "<footer>ScriptDecoy</footer>";</script><div><span>Unclosed</div><footer id="site-footer">SiteFooter</footer>`
	gotFooter, ok := ExtractFirstRawElementOrBoundedHTML(unbalFooter, RawElementSelector{ID: "tab-description"})
	if !ok {
		t.Fatal("expected ExtractFirstRawElementOrBoundedHTML to succeed before sibling <footer>")
	}
	if !strings.Contains(gotFooter, "Unclosed") || strings.Contains(gotFooter, "SiteFooter") {
		t.Fatalf("unexpected sibling <footer> boundary slice: %q", gotFooter)
	}

	// 3. Unbalanced container with no closing ancestor or sibling falls back to bounded EOF.
	unbalEOF := `<div class="productView-description"><p>EOF &#91;xss&#93;</p><div><span>Unclosed</div>`
	gotEOF, ok := ExtractFirstRawElementOrBoundedHTML(unbalEOF, RawElementSelector{Class: "productview-description"})
	if !ok || gotEOF != unbalEOF {
		t.Fatalf("expected EOF fallback to return full raw slice, got ok=%v slice=%q", ok, gotEOF)
	}
}

func TestM3Iteration9UnbalancedDocsForumsAndDirectAsideFooter(t *testing.T) {
	assertCleanBounded := func(t *testing.T, label, md string, mustContain []string, mustNotContain []string) {
		t.Helper()
		if strings.Contains(md, "[xss](https://evil.com)") || strings.Contains(md, "[xss2](https://evil.com)") {
			t.Fatalf("%s: emitted active evil.com link:\n%s", label, md)
		}
		if !strings.Contains(md, "https://videos.example/watch?v=1&currentTime=45&section=2&region=us") {
			t.Fatalf("%s: corrupted semicolonless query params:\n%s", label, md)
		}
		for _, want := range mustContain {
			if !strings.Contains(md, want) {
				t.Fatalf("%s: missing %q in:\n%s", label, want, md)
			}
		}
		for _, bad := range mustNotContain {
			if strings.Contains(md, bad) {
				t.Fatalf("%s: unexpected %q leaked in:\n%s", label, bad, md)
			}
		}
	}

	// (a) unbalanced sram-docs .ft-topic-content
	sramUnbal := `<!doctype html><html><body><main>
		<h1 class="ft-topic-title">SRAM Guide</h1>
		<div class="ft-topic-content">
			<p>Check bolt &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar;</p>
			<section><p>TorqueSection</p></section>
			<div><span>Unclosed inner div <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Video</a>
		</div>
	</main><footer>SRAM_OUTER_FOOTER</footer></body></html>`
	sramDoc := ExtractHTMLDocumentFull(sramUnbal, FullExtractOptions{
		BaseURL:         "https://docs.sram.com/en-US/publications/7E6x3h",
		OnlyMainContent: true,
	})
	if sramDoc.ExtractorID != "sram-docs" {
		t.Fatalf("expected sram-docs, got %q", sramDoc.ExtractorID)
	}
	assertCleanBounded(t, "sram-unbalanced", sramDoc.Markdown, []string{"TorqueSection", "Unclosed inner div"}, []string{"SRAM_OUTER_FOOTER"})

	// (b) unbalanced bosch-ebike-help .article-body
	boschBodyUnbal := `<!doctype html><html><body><main>
		<h1>Bosch Smart System Error 500</h1>
		<div class="article-body">
			<p>Inspect drive unit &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar; across at least twenty chars.</p>
			<section><p>BoschInnerSec</p></section>
			<div><span>Unclosed inner div <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">BoschVideo</a>
		</div>
	</main><footer>BOSCH_OUTER_FOOTER</footer></body></html>`
	boschBodyDoc := ExtractHTMLDocumentFull(boschBodyUnbal, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if boschBodyDoc.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("expected bosch-ebike-help, got %q", boschBodyDoc.ExtractorID)
	}
	assertCleanBounded(t, "bosch-article-body-unbalanced", boschBodyDoc.Markdown, []string{"BoschInnerSec", "Unclosed inner div"}, []string{"BOSCH_OUTER_FOOTER"})

	// (c1) unbalanced bosch-ebike-help S:0 with non-empty <main> shell
	boschS0NonEmptyMain := `<!doctype html><html><body>
		<main><h1>Bosch Suspense Unbal</h1><p>Shell placeholder text longer than twenty chars.</p><template id="B:0"></template></main>
		<div hidden id="S:0">
			<p>Rescued suspense &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar; with <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Video</a></p>
			<div>Unclosed inside S:0
		</div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	boschS0DocA := ExtractHTMLDocumentFull(boschS0NonEmptyMain, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if boschS0DocA.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("expected bosch-ebike-help (non-empty main), got %q", boschS0DocA.ExtractorID)
	}
	assertCleanBounded(t, "bosch-s0-nonempty-main", boschS0DocA.Markdown, []string{"Rescued suspense", "Unclosed inside S:0"}, []string{"$RC("})

	// (c2) unbalanced bosch-ebike-help S:0 with empty <main> shell + nested S:2
	boschS0EmptyMain := `<!doctype html><html><body>
		<main><h1>Bosch Suspense Unbal</h1><template id="B:0"></template></main>
		<div hidden id="S:0">
			<p>Rescued suspense &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar; with <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Video</a></p>
			<template id="B:2"></template>
			<div>Unclosed inside S:0
		</div>
		<div hidden id="S:2"><p>Nested S2 rescued &#91;xss&#93;&#40;https://evil.com&#41;</p><div>Unclosed inside S:2</div>
		<script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
	</body></html>`
	boschS0DocB := ExtractHTMLDocumentFull(boschS0EmptyMain, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if boschS0DocB.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("expected bosch-ebike-help (empty main), got %q", boschS0DocB.ExtractorID)
	}
	assertCleanBounded(t, "bosch-s0-empty-main", boschS0DocB.Markdown, []string{"Rescued suspense", "Unclosed inside S:0", "Nested S2 rescued", "Unclosed inside S:2"}, []string{"$RC("})

	// (c3) orphan unbalanced S:0 (no <template id="B:0">) with non-empty <main>
	boschS0Orphan := `<!doctype html><html><body>
		<main><h1>Bosch Orphan Unbal</h1><p>Shell placeholder text longer than twenty chars.</p></main>
		<div hidden id="S:0">
			<p>Orphan S0 &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar; with <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Video</a></p>
			<div>Unclosed orphan S:0
		</div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	boschOrphanDoc := ExtractHTMLDocumentFull(boschS0Orphan, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	assertCleanBounded(t, "bosch-s0-orphan", boschOrphanDoc.Markdown, []string{"Orphan S0", "Unclosed orphan S:0"}, []string{"$RC("})

	// (d1) unbalanced xenforo-thread div.bbWrapper (no outer .message-main wrapper)
	xfUnbalWrapper := `<!doctype html><html><body>
		<h1 class="p-title-value">XF Unbalanced Thread</h1>
		<div class="p-body-main">
			<article class="message message--post" data-author="Alice">
				<div class="bbWrapper">
					<p>Post text &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar;</p>
					<div><span>Unclosed inner div <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">Video</a>
				</div>
				<footer class="message-footer">XF_FOOTER_NOISE</footer>
			</article>
		</div>
	</body></html>`
	xfDoc1 := ExtractHTMLDocumentFull(xfUnbalWrapper, FullExtractOptions{
		BaseURL:         "https://forums.electricbikereview.com/threads/test.123/",
		OnlyMainContent: true,
	})
	if xfDoc1.ExtractorID != "xenforo-thread" {
		t.Fatalf("expected xenforo-thread, got %q", xfDoc1.ExtractorID)
	}
	assertCleanBounded(t, "xf-bbWrapper-unbalanced", xfDoc1.Markdown, []string{"Post text", "Unclosed inner div"}, []string{"XF_FOOTER_NOISE"})

	// (d2) unbalanced xenforo-thread .bbCodeBlock-content
	xfUnbalQuote := `<!doctype html><html><body>
		<h1 class="p-title-value">XF Unbalanced Quote</h1>
		<div class="p-body-main">
			<article class="message message--post" data-author="Bob">
				<div class="bbWrapper">
					<blockquote class="bbCodeBlock bbCodeBlock--quote">
						<div class="bbCodeBlock-title">Alice said:</div>
						<div class="bbCodeBlock-content">
							<p>Quoted &#91;xss&#93;&#40;https://evil.com&#41; and &lsqb;xss2&rsqb;&lpar;https://evil.com&rpar; <a href="https://videos.example/watch?v=1&currentTime=45&section=2&region=us">QVid</a></p>
							<div>Unclosed quote div
						</div>
					</blockquote>
					<p>Actual reply body</p>
				</div>
			</article>
		</div>
	</body></html>`
	xfDoc2 := ExtractHTMLDocumentFull(xfUnbalQuote, FullExtractOptions{
		BaseURL:         "https://forums.electricbikereview.com/threads/test.456/",
		OnlyMainContent: true,
	})
	if xfDoc2.ExtractorID != "xenforo-thread" {
		t.Fatalf("expected xenforo-thread, got %q", xfDoc2.ExtractorID)
	}
	assertCleanBounded(t, "xf-quote-unbalanced", xfDoc2.Markdown, []string{"> **Alice said:**", "> Quoted", "> Unclosed quote div", "Actual reply body"}, nil)

	// (e) Probe 4.3e: balanced container with direct <aside> + <footer> must NOT truncate prematurely
	balWithDirectAsideFooter := `<main><div id="tab-description"><p>BeforeFooter</p><aside class="callout">CalloutNote</aside><footer>InsideFooter</footer><p>AfterFooter</p></div></main>`
	got43e, ok43e := ExtractFirstRawElementOrBoundedHTML(balWithDirectAsideFooter, RawElementSelector{ID: "tab-description"})
	if !ok43e {
		t.Fatal("expected balanced container with direct <aside> and <footer> to succeed")
	}
	for _, want := range []string{"BeforeFooter", "CalloutNote", "InsideFooter", "AfterFooter"} {
		if !strings.Contains(got43e, want) {
			t.Fatalf("Probe 4.3e balanced container truncated %q: got %q", want, got43e)
		}
	}
}

func TestM3Iteration10BoschScriptSkipAndFallbackInnerEnd(t *testing.T) {
	// 1. boschD_rc_with_closing_div_in_js: inline <script> containing "</div></div>" after $RC(...)
	// must NOT decrement sStack depth or close S:0 mid-<script>, preserving <main> tail content.
	boschDivInJS := `<!doctype html><html><body>
		<main>
			<h1>Bosch</h1>
			<p>Placeholder shell text longer than twenty chars.</p>
			<template id="B:0"></template>
			<p>Tail in main that must survive</p>
		</main>
		<div hidden id="S:0">
			<p>Rescued text</p>
			<div>Unclosed
		</div>
		<script>$RC("B:0","S:0");var x="</div></div>";</script>
		<script>var noop=1;</script>
	</body></html>`
	docJS := ExtractHTMLDocumentFull(boschDivInJS, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if docJS.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("boschD: expected bosch-ebike-help, got %q", docJS.ExtractorID)
	}
	for _, want := range []string{"Rescued text", "Unclosed", "Tail in main that must survive"} {
		if !strings.Contains(docJS.Markdown, want) {
			t.Fatalf("boschD: missing %q in:\n%s", want, docJS.Markdown)
		}
	}
	if strings.Contains(docJS.Markdown, "$RC(") || strings.Contains(docJS.Markdown, "var x=") {
		t.Fatalf("boschD: script leaked into markdown:\n%s", docJS.Markdown)
	}

	// Also verify <style>, <noscript>, <svg>, and <script> inside S:0 containing </div> do not corrupt depth.
	boschInsideSkipTags := `<!doctype html><html><body>
		<main><h1>Bosch</h1><template id="B:0"></template><p>Main tail ok</p></main>
		<div hidden id="S:0">
			<p>Before skip tags</p>
			<script>var y="</div></div>";</script>
			<style>/* </div> */</style>
			<noscript><div></div></div></noscript>
			<svg><g></div></g></svg>
			<p>After skip tags inside S:0</p>
		</div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docSkip := ExtractHTMLDocumentFull(boschInsideSkipTags, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	for _, want := range []string{"Before skip tags", "After skip tags inside S:0", "Main tail ok"} {
		if !strings.Contains(docSkip.Markdown, want) {
			t.Fatalf("boschSkipTags: missing %q in:\n%s", want, docSkip.Markdown)
		}
	}

	// 2. stress_bosch_next_wrapper: unbalanced S:0 inside outer #__next wrapper with <footer>
	// followed by <div class="site-promo">SITE_PROMO_OUTSIDE_S0</div> and closing #__next </div>.
	boschNextWrapper := `<!doctype html><html><body>
		<div id="__next">
			<main>
				<h1>Next Wrapper</h1>
				<p>Placeholder text longer than twenty chars.</p>
				<template id="B:0"></template>
			</main>
			<div hidden id="S:0">
				<p>Slot S0 &#91;xss&#93;&#40;https://evil.com&#41; content</p>
				<div>Unclosed inside S:0
				<footer><p>Site footer noise</p></footer>
				<div class="site-promo">SITE_PROMO_OUTSIDE_S0</div>
			</div>
		</div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docNext := ExtractHTMLDocumentFull(boschNextWrapper, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if docNext.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("stress_bosch_next_wrapper: expected bosch-ebike-help, got %q", docNext.ExtractorID)
	}
	for _, want := range []string{"Slot S0", "Unclosed inside S:0"} {
		if !strings.Contains(docNext.Markdown, want) {
			t.Fatalf("stress_bosch_next_wrapper: missing %q in:\n%s", want, docNext.Markdown)
		}
	}
	for _, bad := range []string{"SITE_PROMO_OUTSIDE_S0", "Site footer noise", "[xss](https://evil.com)"} {
		if strings.Contains(docNext.Markdown, bad) {
			t.Fatalf("stress_bosch_next_wrapper: unexpected %q leaked in:\n%s", bad, docNext.Markdown)
		}
	}

	// 3. stress_bosch_closedivs2: <template id="B:0"> inside .article-body followed by
	// IMPORTANT_AFTER_B0_PARAGRAPH_2 + unbalanced S:0 + <footer><div class="f1"><div class="f2">.
	boschCloseDivs2 := `<!doctype html><html><body>
		<div class="article-body">
			<h1>Bosch CloseDivs 2</h1>
			<p>Intro text longer than twenty characters for body check.</p>
			<template id="B:0"></template>
			<p>IMPORTANT_AFTER_B0_PARAGRAPH_2</p>
		</div>
		<div hidden id="S:0">
			<p>Rescued S0 paragraph</p>
			<div>Unclosed inside S:0
			<footer>
				<div class="f1"><div class="f2"><p>FOOTER_NOISE</p>
			</footer>
		</div>
		<script>$RC("B:0","S:0")</script>
	</body></html>`
	docCloseDivs := ExtractHTMLDocumentFull(boschCloseDivs2, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	if docCloseDivs.ExtractorID != "bosch-ebike-help" {
		t.Fatalf("stress_bosch_closedivs2: expected bosch-ebike-help, got %q", docCloseDivs.ExtractorID)
	}
	for _, want := range []string{"Rescued S0 paragraph", "Unclosed inside S:0", "IMPORTANT_AFTER_B0_PARAGRAPH_2"} {
		if !strings.Contains(docCloseDivs.Markdown, want) {
			t.Fatalf("stress_bosch_closedivs2: missing %q in:\n%s", want, docCloseDivs.Markdown)
		}
	}
	if strings.Contains(docCloseDivs.Markdown, "FOOTER_NOISE") {
		t.Fatalf("stress_bosch_closedivs2: unexpected FOOTER_NOISE in:\n%s", docCloseDivs.Markdown)
	}

	// 4. Verify unbalanced <div> inside <template id="B:2"> inside S:0 does not corrupt S:0 depth.
	boschTplDivInsideS0 := `<!doctype html><html><body>
		<main><h1>Bosch Tpl Div</h1><template id="B:0"></template><p>Main survivor</p></main>
		<div hidden id="S:0">
			<p>Before template</p>
			<template id="B:2"><div class="skeleton">Loading</template>
			<p>After template inside S:0</p>
		</div>
		<div hidden id="S:2"><p>Nested S2 body</p></div>
		<script>$RC("B:0","S:0");$RC("B:2","S:2")</script>
	</body></html>`
	docTplDiv := ExtractHTMLDocumentFull(boschTplDivInsideS0, FullExtractOptions{
		BaseURL:         "https://help.bosch-ebike.com/us/help-center/ebw-error-codes",
		OnlyMainContent: true,
	})
	for _, want := range []string{"Before template", "Nested S2 body", "After template inside S:0", "Main survivor"} {
		if !strings.Contains(docTplDiv.Markdown, want) {
			t.Fatalf("boschTplDivInsideS0: missing %q in:\n%s", want, docTplDiv.Markdown)
		}
	}
}
