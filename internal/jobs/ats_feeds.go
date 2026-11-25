package jobs

import (
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

func (s *ATSPreFetchSpec) formatWWRFeed(rawBody string) *ATSFormattedResult {
	records := ParsePublicJobFeedRecords("weworkremotely", rawBody)
	if len(records) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("# We Work Remotely Jobs (%d)", len(records))}
	links := make([]string, 0, len(records))
	for i, r := range records {
		links = append(links, r.URL)
		if i < 50 {
			loc := "Remote"
			if len(r.Locations) > 0 && r.Locations[0] != "" {
				loc = r.Locations[0]
			}
			lines = append(lines, fmt.Sprintf("- **[%s](%s)** — %s · %s", r.Title, r.URL, r.Company, loc))
		}
	}
	return &ATSFormattedResult{
		Title:     fmt.Sprintf("We Work Remotely Jobs (%d)", len(records)),
		Markdown:  strings.Join(lines, "\n"),
		Links:     links,
		Jobs:      records,
		Total:     intPtr(len(records)),
		Returned:  intPtr(len(records)),
		Truncated: boolPtr(false),
	}
}

func (s *ATSPreFetchSpec) formatHimalayasFeed(rawBody string) *ATSFormattedResult {
	parsed, ok := SafeJSONParse(rawBody).(map[string]any)
	if !ok || parsed == nil {
		return nil
	}
	if _, okJ := parsed["jobs"].([]any); !okJ {
		return nil
	}
	records := ParsePublicJobFeedRecords("himalayas", rawBody)
	total := len(records)
	if tc, okT := parsed["totalCount"].(float64); okT && int(tc) > total {
		total = int(tc)
	}
	lines := []string{fmt.Sprintf("# Himalayas Remote Jobs (%d of %d)", len(records), total)}
	links := make([]string, 0, len(records))
	for _, r := range records {
		links = append(links, r.URL)
		lines = append(lines, fmt.Sprintf("- **[%s](%s)** — %s", r.Title, r.URL, r.Company))
	}
	return &ATSFormattedResult{
		Title:     fmt.Sprintf("Himalayas Remote Jobs (%d)", len(records)),
		Markdown:  strings.Join(lines, "\n"),
		Links:     links,
		Jobs:      records,
		Total:     intPtr(total),
		Returned:  intPtr(len(records)),
		Truncated: boolPtr(total > len(records)),
	}
}

func (s *ATSPreFetchSpec) formatWorkingNomadsFeed(rawBody string) *ATSFormattedResult {
	records := ParsePublicJobFeedRecords("workingnomads", rawBody)
	if len(records) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("# Working Nomads Remote Jobs (%d)", len(records))}
	links := make([]string, 0, len(records))
	for i, r := range records {
		links = append(links, r.URL)
		if i < 50 {
			lines = append(lines, fmt.Sprintf("- **[%s](%s)** — %s", r.Title, r.URL, r.Company))
		}
	}
	return &ATSFormattedResult{
		Title:     fmt.Sprintf("Working Nomads Remote Jobs (%d)", len(records)),
		Markdown:  strings.Join(lines, "\n"),
		Links:     links,
		Jobs:      records,
		Total:     intPtr(len(records)),
		Returned:  intPtr(len(records)),
		Truncated: boolPtr(false),
	}
}

func extractLinearXMLSimpleTag(xml, tag string) string {
	tagLow := strings.ToLower(tag)
	openToken := "<" + tagLow
	closeToken := "</" + tagLow + ">"
	lower := strings.ToLower(xml)
	openIdx := strings.Index(lower, openToken)
	if openIdx < 0 {
		return ""
	}
	gt := strings.IndexByte(xml[openIdx+len(openToken):], '>')
	if gt < 0 {
		return ""
	}
	gt += openIdx + len(openToken)
	closeIdx := strings.Index(lower[gt+1:], closeToken)
	if closeIdx < 0 {
		return ""
	}
	closeIdx += gt + 1
	inner := strings.TrimSpace(xml[gt+1 : closeIdx])
	if strings.HasPrefix(inner, "<![CDATA[") && strings.HasSuffix(inner, "]]>") {
		return strings.TrimSpace(inner[9 : len(inner)-3])
	}
	return inner
}

func parseFlexiblePubDateISO(raw string) *string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		time.RFC3339Nano,
		time.RFC3339,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, trimmed); err == nil {
			iso := t.UTC().Format("2006-01-02T15:04:05.000Z")
			return &iso
		}
	}
	return nil
}

// ParsePublicJobFeedRecords parses We Work Remotely RSS, Himalayas JSON, and Working Nomads JSON job feeds.
func ParsePublicJobFeedRecords(feedID, rawBody string) []StructuredJobRecord {
	out := make([]StructuredJobRecord, 0, 16)
	switch feedID {
	case "weworkremotely":
		lower := strings.ToLower(rawBody)
		pos := 0
		for pos < len(rawBody) && len(out) < 100 {
			openIdx := strings.Index(lower[pos:], "<item")
			if openIdx < 0 {
				break
			}
			openIdx += pos
			if openIdx+5 >= len(rawBody) {
				break
			}
			gt := strings.IndexByte(rawBody[openIdx+5:], '>')
			if gt < 0 {
				break
			}
			gt += openIdx + 5
			closeIdx := strings.Index(lower[gt+1:], "</item>")
			if closeIdx < 0 {
				break
			}
			closeIdx += gt + 1
			itemXML := rawBody[gt+1 : closeIdx]
			pos = closeIdx + 7

			fullTitle := StripTagsPlain(extractLinearXMLSimpleTag(itemXML, "title"))
			link := StripTagsPlain(extractLinearXMLSimpleTag(itemXML, "link"))
			if fullTitle == "" || !strings.HasPrefix(link, "https://") {
				continue
			}
			company := "We Work Remotely"
			role := fullTitle
			if colon := strings.IndexByte(fullTitle, ':'); colon > 0 {
				company = strings.TrimSpace(fullTitle[:colon])
				role = strings.TrimSpace(fullTitle[colon+1:])
			}
			region := StripTagsPlain(extractLinearXMLSimpleTag(itemXML, "region"))
			if region == "" {
				region = "Remote"
			}
			pubDate := StripTagsPlain(extractLinearXMLSimpleTag(itemXML, "pubDate"))
			desc := StripTagsPlain(extractLinearXMLSimpleTag(itemXML, "description"))
			snippet := ""
			if desc != "" {
				snippet = sliceUTF16Max(desc, 220)
			}
			out = append(out, StructuredJobRecord{
				Title:         role,
				Company:       company,
				URL:           link,
				ApplyURL:      link,
				WorkplaceType: WorkplaceRemote,
				Locations:     []string{region},
				Pay:           ParsePayFromText(desc),
				PostedAt:      parseFlexiblePubDateISO(pubDate),
				Source:        "weworkremotely",
				Snippet:       snippet,
			})
		}
		return out

	case "himalayas":
		data, _ := SafeJSONParse(rawBody).(map[string]any)
		jobsAny, _ := data["jobs"].([]any)
		for i := 0; i < len(jobsAny) && i < 100; i++ {
			j, okJ := jobsAny[i].(map[string]any)
			if !okJ || j == nil {
				continue
			}
			title := strings.TrimSpace(anyString(j["title"]))
			company := strings.TrimSpace(anyString(j["companyName"]))
			if company == "" {
				company = "Himalayas Listing"
			}
			jURL := ""
			if al, okA := j["applicationLink"].(string); okA && strings.HasPrefix(al, "https://") {
				jURL = al
			} else if g, okG := j["guid"].(string); okG && strings.HasPrefix(g, "https://") {
				jURL = g
			}
			if title == "" || jURL == "" {
				continue
			}
			var locs []string
			if lr, okL := j["locationRestrictions"].([]any); okL {
				for _, x := range lr {
					if sx := anyString(x); sx != "" {
						locs = append(locs, sx)
					}
				}
			}
			if len(locs) == 0 {
				locs = []string{"Remote"}
			}
			var minSal, maxSal *float64
			if ms, okM := j["minSalary"].(float64); okM && ms > 0 {
				r := math.Round(ms)
				minSal = &r
			}
			if xs, okX := j["maxSalary"].(float64); okX && xs > 0 {
				r := math.Round(xs)
				maxSal = &r
			}
			var pay *NormalizedPay
			if minSal != nil || maxSal != nil {
				effMax := maxSal
				if effMax == nil {
					effMax = minSal
				}
				cur := "USD"
				if cs, okC := j["currency"].(string); okC && strings.TrimSpace(cs) != "" {
					cur = strings.ToUpper(strings.TrimSpace(cs))
				}
				pay = &NormalizedPay{
					Min:      minSal,
					Max:      effMax,
					Currency: cur,
					Period:   PayPeriodYear,
					Basis:    PayBasisBase,
				}
			}
			var postedAt *string
			switch pd := j["pubDate"].(type) {
			case float64:
				if !math.IsNaN(pd) && !math.IsInf(pd, 0) {
					ms := int64(pd * 1_000)
					if pd > 1e12 {
						ms = int64(pd)
					}
					iso := time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
					postedAt = &iso
				}
			case string:
				postedAt = strPtr(pd)
			}
			snippet := ""
			if exc, okE := j["excerpt"].(string); okE && exc != "" {
				snippet = sliceUTF16Max(StripTagsPlain(exc), 220)
			}
			out = append(out, StructuredJobRecord{
				Title:         title,
				Company:       company,
				URL:           jURL,
				ApplyURL:      jURL,
				WorkplaceType: WorkplaceRemote,
				Locations:     locs,
				Pay:           pay,
				PostedAt:      postedAt,
				Source:        "himalayas",
				Snippet:       snippet,
			})
		}
		return out

	case "workingnomads":
		items, _ := SafeJSONParse(rawBody).([]any)
		for i := 0; i < len(items) && i < 100; i++ {
			j, okJ := items[i].(map[string]any)
			if !okJ || j == nil {
				continue
			}
			title := strings.TrimSpace(anyString(j["title"]))
			company := strings.TrimSpace(anyString(j["company_name"]))
			if company == "" {
				company = "Working Nomads Listing"
			}
			jURL := ""
			if uStr, okU := j["url"].(string); okU && strings.HasPrefix(uStr, "https://") {
				jURL = uStr
			}
			if title == "" || jURL == "" {
				continue
			}
			loc := strings.TrimSpace(anyString(j["location"]))
			if loc == "" {
				loc = "Remote"
			}
			desc := StripTagsPlain(anyString(j["description"]))
			var postedAt *string
			if pd, okP := j["pub_date"].(string); okP && pd != "" {
				postedAt = strPtr(pd)
			}
			snippet := ""
			if desc != "" {
				snippet = sliceUTF16Max(desc, 220)
			}
			out = append(out, StructuredJobRecord{
				Title:         title,
				Company:       company,
				URL:           jURL,
				ApplyURL:      jURL,
				WorkplaceType: WorkplaceRemote,
				Locations:     []string{loc},
				Pay:           ParsePayFromText(desc),
				PostedAt:      postedAt,
				Source:        "workingnomads",
				Snippet:       snippet,
			})
		}
		return out
	default:
		return out
	}
}

func humanizeSmartRecruitersSlugTitle(jobSeg string) string {
	withoutNum := reSRNumericPrefix.ReplaceAllString(jobSeg, "")
	if withoutNum == "" || reDigitsOnly.MatchString(withoutNum) {
		return ""
	}
	var words []string
	for _, w := range strings.FieldsFunc(withoutNum, func(r rune) bool { return r == '-' || r == '_' }) {
		if w != "" {
			words = append(words, strings.ToUpper(w[:1])+w[1:])
		}
	}
	return strings.TrimSpace(strings.Join(words, " "))
}

// ParseSmartRecruitersBoardScrape extracts StructuredJobRecord rows from public `https://jobs.smartrecruiters.com/{Company}` HTML/Markdown boards.
func ParseSmartRecruitersBoardScrape(origURL, markdown, rawHTML string, links []string) []StructuredJobRecord {
	company, _, ok := IsSmartRecruitersBoardURL(origURL)
	if !ok {
		return []StructuredJobRecord{}
	}
	orgLower := strings.ToLower(company)
	baseU, okBase := parseStrictURL(origURL)
	if !okBase {
		return []StructuredJobRecord{}
	}

	var order []string
	byURL := make(map[string]StructuredJobRecord)

	isPostingPath := func(candidateURL string) (cleanURL, seg string, valid bool) {
		ref, err := url.Parse(strings.TrimSpace(candidateURL))
		if err != nil {
			return "", "", false
		}
		u := baseU.ResolveReference(ref)
		if !strings.EqualFold(u.Scheme, "https") || !strings.EqualFold(u.Hostname(), "jobs.smartrecruiters.com") {
			return "", "", false
		}
		parts := splitCleanPathSegments(u.EscapedPath())
		if len(parts) < 2 || !strings.EqualFold(parts[0], orgLower) {
			return "", "", false
		}
		decSeg, okDec := DecodeURIComponent(parts[1])
		if !okDec || len(decSeg) < 4 || reSRSkipSeg.MatchString(decSeg) {
			return "", "", false
		}
		return "https://jobs.smartrecruiters.com/" + parts[0] + "/" + parts[1], decSeg, true
	}

	if markdown != "" {
		matches := reSRMDLink.FindAllStringSubmatch(markdown, -1)
		for _, m := range matches {
			if len(byURL) >= 500 {
				break
			}
			cleanURL, _, valid := isPostingPath(m[2])
			key := strings.ToLower(cleanURL)
			if !valid || hasKey(byURL, key) {
				continue
			}
			rawTitle := strings.TrimSpace(strings.ReplaceAll(m[1], "*", ""))
			if rawTitle == "" || reSRSkipTitle.MatchString(rawTitle) {
				continue
			}
			tailCtx := strings.TrimSpace(reSRLeadingSep.ReplaceAllString(m[3]+" "+m[4], ""))
			locLine := strings.TrimSpace(reSRLeadingSep.ReplaceAllString(m[3], ""))
			if locLine == "" {
				locLine = strings.TrimSpace(m[4])
			}
			cleanLoc := ""
			if locLine != "" && len(locLine) <= 96 && !reSRBracketOrHTTP.MatchString(locLine) {
				cleanLoc = locLine
			}
			wp := InferWorkplaceType(cleanLoc + " " + rawTitle + " " + tailCtx)
			locs := []string{}
			if cleanLoc != "" {
				locs = []string{cleanLoc}
			} else if wp == WorkplaceRemote {
				locs = []string{"Remote"}
			}
			snippet := ""
			if tailCtx != "" {
				snippet = sliceUTF16Max(tailCtx, 220)
			}
			byURL[key] = StructuredJobRecord{
				Title:         rawTitle,
				Company:       company,
				URL:           cleanURL,
				ApplyURL:      cleanURL,
				WorkplaceType: wp,
				Locations:     locs,
				Pay:           ParsePayFromText(tailCtx),
				PostedAt:      nil,
				Source:        "smartrecruiters",
				Snippet:       snippet,
			}
			order = append(order, key)
		}
	}

	if rawHTML != "" {
		locs := reSRHTMLAnchor.FindAllStringSubmatchIndex(rawHTML, -1)
		for _, loc := range locs {
			if len(byURL) >= 500 {
				break
			}
			href := rawHTML[loc[2]:loc[3]]
			inner := rawHTML[loc[4]:loc[5]]
			cleanURL, seg, valid := isPostingPath(href)
			key := strings.ToLower(cleanURL)
			if !valid || hasKey(byURL, key) {
				continue
			}
			anchorText := StripTagsPlain(inner)
			title := anchorText
			if title == "" || reSRSkipHTMLTitle.MatchString(title) {
				title = humanizeSmartRecruitersSlugTitle(seg)
			}
			if title == "" {
				continue
			}
			afterSlice := StripTagsPlain(rawHTML[loc[1]:min(len(rawHTML), loc[1]+260)])
			wp := InferWorkplaceType(afterSlice + " " + title)
			jLocs := []string{}
			if wp == WorkplaceRemote {
				jLocs = []string{"Remote"}
			}
			byURL[key] = StructuredJobRecord{
				Title:         title,
				Company:       company,
				URL:           cleanURL,
				ApplyURL:      cleanURL,
				WorkplaceType: wp,
				Locations:     jLocs,
				Pay:           ParsePayFromText(afterSlice),
				PostedAt:      nil,
				Source:        "smartrecruiters",
			}
			order = append(order, key)
		}
	}

	for _, lnk := range links {
		if len(byURL) >= 500 {
			break
		}
		cleanURL, seg, valid := isPostingPath(lnk)
		key := strings.ToLower(cleanURL)
		if !valid || hasKey(byURL, key) {
			continue
		}
		title := humanizeSmartRecruitersSlugTitle(seg)
		if title == "" {
			continue
		}
		wp := InferWorkplaceType(title)
		jLocs := []string{}
		if wp == WorkplaceRemote {
			jLocs = []string{"Remote"}
		}
		byURL[key] = StructuredJobRecord{
			Title:         title,
			Company:       company,
			URL:           cleanURL,
			ApplyURL:      cleanURL,
			WorkplaceType: wp,
			Locations:     jLocs,
			Pay:           nil,
			PostedAt:      nil,
			Source:        "smartrecruiters",
		}
		order = append(order, key)
	}

	out := make([]StructuredJobRecord, 0, len(order))
	for _, k := range order {
		out = append(out, byURL[k])
	}
	return out
}

// ParseBuiltInMarkdownCards extracts BuiltIn job cards and inline compensation from scraped BuiltIn Markdown.
func ParseBuiltInMarkdownCards(biMD string, maxCards int, wantRemoteFalse bool) []StructuredJobRecord {
	if biMD == "" || maxCards <= 0 {
		return []StructuredJobRecord{}
	}
	locs := reBuiltInMDCard.FindAllStringSubmatchIndex(biMD, -1)
	out := make([]StructuredJobRecord, 0, min(len(locs), maxCards))
	for i, loc := range locs {
		if len(out) >= maxCards {
			break
		}
		cardTitle := strings.TrimSpace(biMD[loc[2]:loc[3]])
		cardURL := strings.TrimSpace(biMD[loc[4]:loc[5]])
		ctxEnd := min(len(biMD), loc[1]+260)
		if i+1 < len(locs) && locs[i+1][0] < ctxEnd {
			ctxEnd = locs[i+1][0]
		}
		cardCtx := biMD[loc[1]:ctxEnd]
		remoteHint := "remote"
		if wantRemoteFalse {
			remoteHint = ""
		}
		wp := InferWorkplaceType(remoteHint + " " + cardCtx)
		jLocs := []string{}
		if wp == WorkplaceRemote {
			jLocs = []string{"Remote"}
		}
		out = append(out, StructuredJobRecord{
			Title:         cardTitle,
			Company:       "Built In Listing",
			URL:           cardURL,
			ApplyURL:      cardURL,
			WorkplaceType: wp,
			Locations:     jLocs,
			Pay:           ParsePayFromText(cardCtx),
			PostedAt:      nil,
			Source:        "builtin",
			Snippet:       sliceUTF16Max(StripTagsPlain(cardCtx), 200),
		})
	}
	return out
}

func hasKey[V any](m map[string]V, k string) bool {
	_, ok := m[k]
	return ok
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func joinNonEmptyBlocks(blocks ...string) string {
	var nonEmpty []string
	for _, b := range blocks {
		if b != "" {
			nonEmpty = append(nonEmpty, b)
		}
	}
	return strings.Join(nonEmpty, "\n\n")
}

func joinNonEmptySep(sep string, parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, sep)
}
