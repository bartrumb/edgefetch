package extract

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func formatNuGetRegistrationJSONGo(rawBytes []byte, params map[string]string, origURL string) (*DeclarativeFormattedDoc, bool) {
	parsed, ok := decodeJSONWithNumbers(rawBytes)
	if !ok || parsed == nil {
		return nil, false
	}
	root, okRoot := parsed.(map[string]any)
	if !okRoot || root == nil {
		return nil, false
	}
	rawPages, okPages := root["items"].([]any)
	if !okPages || len(rawPages) == 0 {
		return nil, false
	}

	type catalogPageStub struct {
		id    string
		lower string
		upper string
		count int64
	}
	type inlinedEntry struct {
		entry  map[string]any
		listed bool
	}

	var pages []catalogPageStub
	var entries []inlinedEntry
	var totalVersions int64

	for _, rp := range rawPages {
		po, okP := rp.(map[string]any)
		if !okP || po == nil {
			continue
		}
		pageID := strings.TrimSpace(jsonScalarToString(po["@id"]))
		lower := strings.TrimSpace(jsonScalarToString(po["lower"]))
		upper := strings.TrimSpace(jsonScalarToString(po["upper"]))
		var pageCount int64
		const maxSafeNuGetCountFloat = 9223372036854774784.0
		if cf, okC := jsonValueToFloat(po["count"]); okC && cf >= 0 && !math.IsNaN(cf) && !math.IsInf(cf, 0) {
			if cf >= maxSafeNuGetCountFloat {
				pageCount = math.MaxInt64
			} else {
				pageCount = int64(math.Round(cf))
			}
		}

		var leafArr []any
		if la, okL := po["items"].([]any); okL {
			leafArr = la
		}
		if pageCount == 0 && len(leafArr) > 0 {
			pageCount = int64(len(leafArr))
		}
		if pageCount > math.MaxInt64-totalVersions {
			totalVersions = math.MaxInt64
		} else {
			totalVersions += pageCount
		}

		if pageID != "" || lower != "" || upper != "" || pageCount > 0 {
			pages = append(pages, catalogPageStub{
				id:    pageID,
				lower: lower,
				upper: upper,
				count: pageCount,
			})
		}

		for _, rl := range leafArr {
			lo, okL := rl.(map[string]any)
			if !okL || lo == nil {
				continue
			}
			ce, okCE := lo["catalogEntry"].(map[string]any)
			if !okCE || ce == nil {
				if jsonScalarToString(lo["version"]) != "" {
					ce = lo
				} else {
					continue
				}
			}
			listed := true
			if rawListed, hasListed := ce["listed"]; hasListed {
				if lb, isB := rawListed.(bool); isB {
					listed = lb
				} else if !isJSONTruthy(rawListed) {
					listed = false
				}
			}
			entries = append(entries, inlinedEntry{entry: ce, listed: listed})
		}
	}

	if len(pages) == 0 && len(entries) == 0 {
		return nil, false
	}

	requestedVer := strings.TrimSpace(params["ver"])
	paramPkgID := strings.TrimSpace(params["pkgId"])

	var links []string
	seenLinks := make(map[string]bool)
	pushLink := func(raw string) {
		clean := strings.TrimSpace(raw)
		if isSafePublicHTTPSFeedURL(clean) && !seenLinks[clean] && len(links) < 100 {
			seenLinks[clean] = true
			links = append(links, clean)
		}
	}

	// Branch 1: Inlined catalogEntry leaves exist.
	if len(entries) > 0 {
		var selected map[string]any
		if requestedVer != "" {
			for i := len(entries) - 1; i >= 0; i-- {
				v := strings.TrimSpace(jsonScalarToString(entries[i].entry["version"]))
				if strings.EqualFold(v, requestedVer) {
					selected = entries[i].entry
					break
				}
			}
			if selected == nil {
				return nil, false
			}
		} else {
			for i := len(entries) - 1; i >= 0; i-- {
				if entries[i].listed {
					selected = entries[i].entry
					break
				}
			}
			if selected == nil {
				selected = entries[len(entries)-1].entry
			}
		}

		pkgID := strings.TrimSpace(jsonScalarToString(selected["id"]))
		if pkgID == "" {
			pkgID = paramPkgID
		}
		ver := strings.TrimSpace(jsonScalarToString(selected["version"]))
		if pkgID == "" || ver == "" {
			return nil, false
		}

		desc := strings.TrimSpace(stripInvisibleAndNUL(jsonScalarToString(selected["description"])))
		if desc == "" {
			desc = strings.TrimSpace(stripInvisibleAndNUL(jsonScalarToString(selected["summary"])))
		}
		authors := formatNuGetStringOrArray(selected["authors"], 12)
		licenseExpr := strings.TrimSpace(jsonScalarToString(selected["licenseExpression"]))
		licenseURL := strings.TrimSpace(jsonScalarToString(selected["licenseUrl"]))
		projectURL := strings.TrimSpace(jsonScalarToString(selected["projectUrl"]))
		published := strings.TrimSpace(jsonScalarToString(selected["published"]))
		publishedDate := published
		if len(publishedDate) > 10 {
			publishedDate = publishedDate[:10]
		}
		tags := formatNuGetStringOrArray(selected["tags"], 12)

		pushLink(projectURL)
		pushLink(licenseURL)

		pkgIDClean := SanitizeScrapedMeta(pkgID)
		verClean := SanitizeScrapedMeta(ver)
		title := fmt.Sprintf("%s v%s (NuGet)", pkgIDClean, verClean)
		var bullets []string
		bullets = append(bullets, "- **Install**: "+formatNuGetInlineCode("dotnet add package "+pkgIDClean+" --version "+verClean))
		bullets = append(bullets, "- **Version**: "+formatNuGetInlineCode(verClean))
		if authors != "" {
			bullets = append(bullets, fmt.Sprintf("- **Authors**: %s", escapeDeclMarkdownBrackets(SanitizeScrapedMeta(authors))))
		}
		if licenseExpr != "" {
			bullets = append(bullets, fmt.Sprintf("- **License**: %s", escapeDeclMarkdownBrackets(SanitizeScrapedMeta(licenseExpr))))
		} else if isSafePublicHTTPSFeedURL(licenseURL) {
			bullets = append(bullets, fmt.Sprintf("- **License**: %s", escapeDeclMarkdownBrackets(licenseURL)))
		}
		if isSafePublicHTTPSFeedURL(projectURL) {
			bullets = append(bullets, fmt.Sprintf("- **Project URL**: %s", escapeDeclMarkdownBrackets(projectURL)))
		}
		if publishedDate != "" {
			bullets = append(bullets, fmt.Sprintf("- **Published**: %s", escapeDeclMarkdownBrackets(publishedDate)))
		}
		if totalVersions > 0 {
			bullets = append(bullets, fmt.Sprintf("- **Total Versions**: %s", formatIntComma(totalVersions)))
		}
		if tags != "" {
			bullets = append(bullets, fmt.Sprintf("- **Tags**: %s", escapeDeclMarkdownBrackets(SanitizeScrapedMeta(tags))))
		}

		safeDesc := escapeDeclMarkdownBlock(desc)
		var blocks []string
		blocks = append(blocks, "# "+escapeDeclMarkdownBrackets(title))
		if safeDesc != "" {
			blocks = append(blocks, sliceRunesMax(safeDesc, 260))
		}
		blocks = append(blocks, strings.Join(bullets, "\n"))
		if safeDesc != "" {
			blocks = append(blocks, "## Description\n\n"+safeDesc)
		}

		if depGroups, okDG := selected["dependencyGroups"].([]any); okDG && len(depGroups) > 0 {
			var depLines []string
			totalDeps := 0
			for gIdx, rg := range depGroups {
				if gIdx >= 20 || totalDeps >= 60 {
					break
				}
				goObj, okGO := rg.(map[string]any)
				if !okGO {
					continue
				}
				tfm := strings.TrimSpace(jsonScalarToString(goObj["targetFramework"]))
				if tfm == "" {
					tfm = "Any"
				}
				depsArr, _ := goObj["dependencies"].([]any)
				if len(depsArr) == 0 {
					continue
				}
				var depItems []string
				for _, rd := range depsArr {
					if totalDeps >= 60 {
						break
					}
					do, okD := rd.(map[string]any)
					if !okD {
						continue
					}
					did := strings.TrimSpace(jsonScalarToString(do["id"]))
					drange := strings.TrimSpace(jsonScalarToString(do["range"]))
					if did == "" {
						continue
					}
					totalDeps++
					if drange != "" {
						depItems = append(depItems, fmt.Sprintf("%s (%s)", formatNuGetInlineCode(did), escapeDeclMarkdownBrackets(SanitizeScrapedMeta(drange))))
					} else {
						depItems = append(depItems, formatNuGetInlineCode(did))
					}
				}
				if len(depItems) > 0 {
					depLines = append(depLines, fmt.Sprintf("- **%s**: %s", escapeDeclMarkdownBrackets(SanitizeScrapedMeta(tfm)), strings.Join(depItems, ", ")))
				}
			}
			if len(depLines) > 0 {
				blocks = append(blocks, "## Dependencies\n\n"+strings.Join(depLines, "\n"))
			}
		}

		var relRows [][]string
		for i := len(entries) - 1; i >= 0 && len(relRows) < 15; i-- {
			if !entries[i].listed && len(entries) > 1 {
				continue
			}
			e := entries[i].entry
			ev := strings.TrimSpace(jsonScalarToString(e["version"]))
			if ev == "" {
				continue
			}
			ep := strings.TrimSpace(jsonScalarToString(e["published"]))
			if len(ep) > 10 {
				ep = ep[:10]
			}
			if ep == "" {
				ep = "-"
			}
			listedLabel := "Listed"
			if !entries[i].listed {
				listedLabel = "Unlisted"
			}
			relRows = append(relRows, []string{formatNuGetInlineCode(ev), ep, listedLabel})
		}
		if len(relRows) > 0 {
			blocks = append(blocks, "## Recent Releases\n\n"+formatDeclarativeGFMTable([]string{"Version", "Published", "Status"}, relRows))
		}

		return &DeclarativeFormattedDoc{
			Title:         title,
			Description:   sliceRunesMax(desc, 260),
			Author:        SanitizeScrapedMeta(authors),
			PublishedTime: published,
			Markdown:      strings.Join(blocks, "\n\n"),
			Links:         links,
		}, true
	}

	// Branch 2: Un-inlined CatalogPage stubs (large packages such as Serilog / Microsoft.Extensions.*).
	pkgDisplay := SanitizeScrapedMeta(paramPkgID)
	if pkgDisplay == "" {
		pkgDisplay = "nuget-package"
	}
	latestUpper := SanitizeScrapedMeta(pages[len(pages)-1].upper)
	reqVerClean := SanitizeScrapedMeta(requestedVer)
	title := fmt.Sprintf("%s (NuGet)", pkgDisplay)
	if latestUpper != "" {
		title = fmt.Sprintf("%s — up to v%s (NuGet)", pkgDisplay, latestUpper)
	}

	var bullets []string
	if reqVerClean != "" {
		bullets = append(bullets, "- **Install**: "+formatNuGetInlineCode("dotnet add package "+pkgDisplay+" --version "+reqVerClean))
		bullets = append(bullets, "- **Requested Version**: "+formatNuGetInlineCode(reqVerClean))
	} else {
		bullets = append(bullets, "- **Install**: "+formatNuGetInlineCode("dotnet add package "+pkgDisplay))
	}
	if latestUpper != "" {
		bullets = append(bullets, "- **Latest Version**: "+formatNuGetInlineCode(latestUpper))
	}
	if totalVersions > 0 {
		bullets = append(bullets, fmt.Sprintf("- **Total Versions**: %s", formatIntComma(totalVersions)))
	}
	bullets = append(bullets, fmt.Sprintf("- **Registration Pages**: %s", strconv.Itoa(len(pages))))

	var pageRows [][]string
	for i := len(pages) - 1; i >= 0 && len(pageRows) < 30; i-- {
		pg := pages[i]
		rng := "-"
		if pg.lower != "" && pg.upper != "" {
			rng = fmt.Sprintf("%s .. %s", formatNuGetInlineCode(pg.lower), formatNuGetInlineCode(pg.upper))
		} else if pg.upper != "" {
			rng = fmt.Sprintf(".. %s", formatNuGetInlineCode(pg.upper))
		} else if pg.lower != "" {
			rng = fmt.Sprintf("%s ..", formatNuGetInlineCode(pg.lower))
		}
		cnt := "-"
		if pg.count > 0 {
			cnt = formatIntComma(pg.count)
		}
		pgLink := "-"
		if isSafePublicHTTPSFeedURL(pg.id) {
			pgLink = pg.id
			pushLink(pg.id)
		}
		pageRows = append(pageRows, []string{rng, cnt, pgLink})
	}

	var blocks []string
	blocks = append(blocks, "# "+escapeDeclMarkdownBrackets(title))
	blocks = append(blocks, strings.Join(bullets, "\n"))
	if len(pageRows) > 0 {
		blocks = append(blocks, "## Registration Pages\n\n"+formatDeclarativeGFMTable([]string{"Version Range", "Versions", "Catalog Page"}, pageRows))
	}

	_ = origURL
	return &DeclarativeFormattedDoc{
		Title:    title,
		Markdown: strings.Join(blocks, "\n\n"),
		Links:    links,
	}, true
}

func formatNuGetInlineCode(raw string) string {
	clean := strings.TrimSpace(stripInvisibleAndNUL(raw))
	if clean == "" {
		return ""
	}
	clean = strings.NewReplacer("\r", " ", "\n", " ", "`", "'", "|", "\\|").Replace(clean)
	return "`" + clean + "`"
}

func formatNuGetStringOrArray(raw any, limit int) string {
	switch tv := raw.(type) {
	case string:
		return strings.TrimSpace(tv)
	case []any:
		var out []string
		for _, el := range tv {
			if len(out) >= limit {
				break
			}
			if s := strings.TrimSpace(jsonScalarToString(el)); s != "" {
				out = append(out, s)
			}
		}
		return strings.Join(out, ", ")
	default:
		return ""
	}
}
