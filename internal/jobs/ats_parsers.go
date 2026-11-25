package jobs

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reWorkdaySafeExtPath = regexp.MustCompile(`^/?job/(?:[A-Za-z0-9._~%-]+/)*[A-Za-z0-9._~%-]+$`)
	reWorkdayBadPct      = regexp.MustCompile(`(?i)%2e|%2f|%5c`)
	reMarkdownLinkChars  = regexp.MustCompile(`([\\\[\]()])`)
	reBracketParenStrip  = regexp.MustCompile(`[\[\]()]`)

	reSRNumericPrefix = regexp.MustCompile(`^\d{6,}-`)
	reSRSkipSeg       = regexp.MustCompile(`(?i)^(?:api|reset|login|signin|privacy|legal|terms|cookies|search|jobs)$`)
	reSRSkipTitle     = regexp.MustCompile(`(?i)^(?:apply|read more|learn more|view job)$`)
	reSRSkipHTMLTitle = regexp.MustCompile(`(?i)^(?:apply|view|details)$`)
	reSRMDLink        = regexp.MustCompile(`(?i)\[([^\[\]\n]{3,180})\]\((https://jobs\.smartrecruiters\.com/[^)\s]+)\)([^\n]{0,200})(?:\n+([^\n#\[]{0,160}))?`)
	reSRHTMLAnchor    = regexp.MustCompile(`(?i)<a\b[^>]{0,400}\bhref=["'](https?://jobs\.smartrecruiters\.com/[^"'#?\s]+|/[A-Za-z0-9_-]+/[A-Za-z0-9_-]{6,})["'][^>]*>(?s:(.{1,600}?))</a>`)
	reSRLeadingSep    = regexp.MustCompile(`^[ \t·|–—-]+`)
	reSRBracketOrHTTP = regexp.MustCompile(`(?i)\[|\]|\bhttp`)
	reBuiltInMDCard   = regexp.MustCompile(`(?i)\[([^\[\]\n]{4,120})\]\((https://(?:www\.)?builtin\.com/job/[^)\s]+)\)`)
)

func (s *ATSPreFetchSpec) formatWithNow(rawBody, origURL string, htmlToMD HTMLToMDFunc, now time.Time) *ATSFormattedResult {
	if htmlToMD == nil {
		htmlToMD = DefaultHTMLToMD
	}
	if now.IsZero() {
		now = time.Now()
	}

	switch s.ID {
	case "ashby-job", "ashby-board":
		return s.formatAshby(rawBody, origURL, htmlToMD)
	case "workday-job":
		return s.formatWorkdayJob(rawBody, origURL, htmlToMD, now)
	case "workday-board":
		return s.formatWorkdayBoard(rawBody, now)
	case "greenhouse-board", "greenhouse-eu-board":
		return s.formatGreenhouseBoard(rawBody)
	case "greenhouse-job":
		return s.formatGreenhouseJob(rawBody, origURL, htmlToMD)
	case "lever-board", "lever-eu-board":
		return s.formatLeverBoard(rawBody)
	case "lever-job":
		return s.formatLeverJob(rawBody, origURL, htmlToMD)
	case "workable-board":
		return s.formatWorkableBoard(rawBody)
	case "workable-job":
		return s.formatWorkableJob(rawBody, origURL, htmlToMD)
	case "gem-board":
		return s.formatGemBoard(rawBody)
	case "rippling-board":
		return s.formatRipplingBoard(rawBody)
	case "rippling-job":
		return s.formatRipplingJob(rawBody, origURL, htmlToMD)
	case "weworkremotely-feed":
		return s.formatWWRFeed(rawBody)
	case "himalayas-feed":
		return s.formatHimalayasFeed(rawBody)
	case "workingnomads-feed":
		return s.formatWorkingNomadsFeed(rawBody)
	default:
		return nil
	}
}

func streamAshbyBoardJSON(rawBody string, visit func(j map[string]any)) (orgName string, ok bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(rawBody, "\ufeff"))
	if !strings.HasPrefix(trimmed, "{") {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", false
	}
	sawJobs := false
	for dec.More() {
		kt, err := dec.Token()
		key, okK := kt.(string)
		if err != nil || !okK {
			return "", false
		}
		switch key {
		case "organizationName":
			var on any
			if err := dec.Decode(&on); err != nil {
				return "", false
			}
			if s, okS := on.(string); okS && s != "" {
				orgName = s
			}
		case "jobs":
			jt, err := dec.Token()
			if err != nil || jt != json.Delim('[') {
				return "", false
			}
			sawJobs = true
			for dec.More() {
				var elem any
				if err := dec.Decode(&elem); err != nil {
					return "", false
				}
				if m, okM := elem.(map[string]any); okM && m != nil {
					visit(m)
				}
			}
			if ct, err := dec.Token(); err != nil || ct != json.Delim(']') {
				return "", false
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", false
			}
		}
	}
	if ct, err := dec.Token(); err != nil || ct != json.Delim('}') {
		return "", false
	}
	return orgName, sawJobs
}

func (s *ATSPreFetchSpec) formatAshby(rawBody, origURL string, htmlToMD HTMLToMDFunc) *ATSFormattedResult {
	if s.jobID != "" {
		var match map[string]any
		orgTitle := s.org
		if streamedOrg, ok := streamAshbyBoardJSON(rawBody, func(j map[string]any) {
			if match == nil && strings.EqualFold(anyString(j["id"]), s.jobID) {
				match = j
			}
		}); ok {
			if streamedOrg != "" {
				orgTitle = streamedOrg
			}
		} else if strings.Contains(rawBody, `"jobs"`) {
			if salv := SalvageAshbyBoardFromTruncatedJSON(rawBody); salv != nil {
				if salv.OrganizationName != "" {
					orgTitle = salv.OrganizationName
				}
				for _, j := range salv.Jobs {
					if strings.EqualFold(anyString(j["id"]), s.jobID) {
						match = j
						break
					}
				}
			}
		}
		if match == nil {
			return nil
		}
		title := strings.TrimSpace(firstNonEmpty(anyString(match["title"]), "Job Posting"))
		allLocs := extractAshbyLocations(match)
		descHTML, _ := match["descriptionHtml"].(string)
		descPlain, _ := match["descriptionPlain"].(string)
		bodyMD := strings.TrimSpace(descPlain)
		if strings.TrimSpace(descHTML) != "" {
			md, _ := htmlToMD(descHTML, origURL)
			bodyMD = strings.TrimSpace(md)
		}
		wpField, _ := match["workplaceType"].(string)
		explicitWP := ResolveExplicitWorkplaceType(wpField, "", descPlain+" "+bodyMD)
		wp := explicitWP
		if wp == "" {
			if isRem, _ := match["isRemote"].(bool); isRem {
				wp = WorkplaceRemote
			} else {
				wp = InferWorkplaceType(strings.Join(allLocs, " ") + " " + title)
			}
		}
		pay := parseAshbyPay(match, descPlain+" "+bodyMD)
		postedAt, _ := match["publishedAt"].(string)
		empType, _ := match["employmentType"].(string)
		jobURL := normalizeCanonicalAshbyURL(match["jobUrl"], s.org, s.jobID)
		applyCand := normalizeCanonicalAshbyURL(match["applyUrl"], s.org, s.jobID)
		var applyURL string
		if strings.HasSuffix(strings.TrimRight(applyCand, "/"), "/application") {
			applyURL = applyCand
		} else if rawApply, ok := match["applyUrl"].(string); ok && strings.TrimSpace(rawApply) != "" {
			applyURL = applyCand
		} else {
			applyURL = strings.TrimRight(jobURL, "/") + "/application"
		}

		var baseSal *NormalizedPay
		if pay != nil && pay.Basis == PayBasisBase {
			baseSal = pay
		}
		jp := &StructuredJobPosting{
			Title:              title,
			HiringOrganization: orgTitle,
			JobLocation:        allLocs,
			WorkplaceType:      wp,
			BaseSalary:         baseSal,
			Pay:                pay,
			DatePosted:         postedAt,
			EmploymentType:     empType,
			URL:                jobURL,
			ApplyURL:           applyURL,
			Source:             "ashby",
		}
		headerMD := FormatJobPostingHeaderMarkdown(*jp)
		descOut := ""
		if descPlain != "" {
			descOut = sliceUTF16Max(descPlain, 280)
		}
		return &ATSFormattedResult{
			Title:         title + " @ " + orgTitle,
			Description:   descOut,
			PublishedTime: postedAt,
			JobPosting:    jp,
			Markdown:      joinNonEmptyBlocks("# "+title+" @ "+orgTitle, headerMD, bodyMD),
			Links:         []string{applyURL},
		}
	}

	const linkLimit = 2_000
	const maxBoardRecords = 2_500
	const maxMarkdownBullets = 120

	type rawBullet struct {
		title  string
		url    string
		suffix string
	}

	var links []string
	var records []StructuredJobRecord
	var bullets []rawBullet
	total := 0
	salvaged := false
	orgTitle := s.org

	processAshbyItem := func(j map[string]any) {
		idx := total
		total++
		jID := anyString(j["id"])
		jURL := normalizeCanonicalAshbyURL(j["jobUrl"], s.org, jID)
		if len(links) < linkLimit {
			links = append(links, jURL)
		}
		if idx < s.reqOffset || len(records) >= maxBoardRecords {
			return
		}
		jTitle := strings.TrimSpace(firstNonEmpty(anyString(j["title"]), "Role"))
		allLocs := extractAshbyLocations(j)
		if allLocs == nil {
			allLocs = []string{}
		}
		rawDescPlain := anyString(j["descriptionPlain"])
		descPlain := rawDescPlain
		if descPlain == "" {
			if dh, ok := j["descriptionHtml"].(string); ok && dh != "" {
				descPlain = StripTagsPlain(sliceUTF16Max(dh, 12_000))
			}
		}
		wpField, _ := j["workplaceType"].(string)
		explicitWP := ResolveExplicitWorkplaceType(wpField, "", sliceUTF16Max(descPlain, 16_000))
		wp := explicitWP
		if wp == "" {
			if isRem, _ := j["isRemote"].(bool); isRem {
				wp = WorkplaceRemote
			} else {
				wp = InferWorkplaceType(strings.Join(allLocs, " ") + " " + jTitle)
			}
		}
		pay := parseAshbyPay(j, sliceUTF16Max(descPlain, 24_000))
		applyURL := strings.TrimRight(jURL, "/") + "/application"
		if rawApply, ok := j["applyUrl"].(string); ok && strings.TrimSpace(rawApply) != "" {
			applyURL = normalizeCanonicalAshbyURL(rawApply, s.org, jID)
		}
		var postedAt *string
		if pub, ok := j["publishedAt"].(string); ok {
			postedAt = strPtr(pub)
		}
		empType, _ := j["employmentType"].(string)
		snippet := ""
		if descPlain != "" {
			snippet = sliceUTF16Max(descPlain, 240)
		}
		records = append(records, StructuredJobRecord{
			Title:          jTitle,
			Company:        orgTitle,
			URL:            jURL,
			ApplyURL:       applyURL,
			WorkplaceType:  wp,
			Locations:      allLocs,
			Pay:            pay,
			PostedAt:       postedAt,
			EmploymentType: empType,
			Source:         "ashby",
			Snippet:        snippet,
		})
		if len(bullets) < maxMarkdownBullets {
			firstLoc := ""
			if len(allLocs) > 0 {
				firstLoc = allLocs[0]
			}
			wpMeta := ""
			if wp != WorkplaceUnknown {
				wpMeta = string(wp)
			}
			payMeta := ""
			if pay != nil {
				payMeta = FormatNormalizedPay(pay)
			}
			meta := joinNonEmptySep(" · ", firstLoc, wpMeta, payMeta)
			suffix := ""
			if meta != "" {
				suffix = " — " + meta
			}
			bullets = append(bullets, rawBullet{title: jTitle, url: jURL, suffix: suffix})
		}
	}

	streamedOrg, streamOK := streamAshbyBoardJSON(rawBody, processAshbyItem)
	if streamOK {
		if streamedOrg != "" {
			orgTitle = streamedOrg
		}
	} else {
		links = nil
		records = nil
		bullets = nil
		total = 0
		if strings.Contains(rawBody, `"jobs"`) {
			if salv := SalvageAshbyBoardFromTruncatedJSON(rawBody); salv != nil {
				salvaged = true
				if salv.OrganizationName != "" {
					orgTitle = salv.OrganizationName
				}
				for _, j := range salv.Jobs {
					processAshbyItem(j)
				}
			} else {
				return nil
			}
		} else {
			return nil
		}
	}

	if orgTitle != s.org {
		for i := range records {
			records[i].Company = orgTitle
		}
	}

	if total == 0 {
		return &ATSFormattedResult{
			Title:     fmt.Sprintf("%s Jobs (0)", orgTitle),
			Markdown:  fmt.Sprintf("# %s — Open Roles (0)\n\nNo open positions currently listed.", orgTitle),
			Links:     []string{},
			Jobs:      []StructuredJobRecord{},
			Total:     intPtr(0),
			Returned:  intPtr(0),
			Truncated: boolPtr(false),
		}
	}

	if links == nil {
		links = []string{}
	}
	if records == nil {
		records = []StructuredJobRecord{}
	}

	countLabel := strconv.Itoa(total)
	if salvaged {
		countLabel = strconv.Itoa(total) + "+"
	}
	lines := make([]string, 0, len(bullets)+4)
	lines = append(lines, fmt.Sprintf("# %s — Open Roles (%s)", orgTitle, countLabel))
	for _, b := range bullets {
		lines = append(lines, fmt.Sprintf("- **[%s](%s)**%s", b.title, b.url, b.suffix))
	}

	returned := len(records)
	truncated := salvaged || total > s.reqOffset+returned
	nextOffsetVal := s.reqOffset + returned
	hasNextCursor := truncated && (salvaged || nextOffsetVal < total)
	if len(records) > maxMarkdownBullets {
		lines = append(lines, fmt.Sprintf("- *... and %d additional open roles in `jobs[]`*", len(records)-maxMarkdownBullets))
	}
	if hasNextCursor {
		lines = append(lines, "", fmt.Sprintf("*Showing %d–%d of %s open roles (list cut short — pass `?offset=%d` on `scrape` or `cursor: \"%d\"` on `jobs` for the next page).*", s.reqOffset+1, s.reqOffset+returned, countLabel, nextOffsetVal, nextOffsetVal))
	}
	var totalPtr *int
	if !salvaged {
		totalPtr = intPtr(total)
	}
	nextCur := ""
	if hasNextCursor {
		nextCur = strconv.Itoa(nextOffsetVal)
	}
	return &ATSFormattedResult{
		Title:      fmt.Sprintf("%s Jobs (%s)", orgTitle, countLabel),
		Markdown:   strings.Join(lines, "\n"),
		Links:      links,
		Jobs:       records,
		Total:      totalPtr,
		Returned:   intPtr(returned),
		Truncated:  boolPtr(truncated),
		NextCursor: nextCur,
	}
}

func (s *ATSPreFetchSpec) formatWorkdayJob(rawBody, origURL string, htmlToMD HTMLToMDFunc, now time.Time) *ATSFormattedResult {
	data, _ := SafeJSONParse(rawBody).(map[string]any)
	if data == nil {
		return nil
	}
	info := data
	if jpi, ok := data["jobPostingInfo"].(map[string]any); ok && jpi != nil {
		info = jpi
	}
	rawTitle, ok := info["title"].(string)
	if !ok {
		return nil
	}
	title := SanitizeJobFieldPlain(rawTitle, 512)
	if title == "" {
		return nil
	}
	var allLocs []string
	if loc, okL := info["location"].(string); okL {
		if cl := SanitizeJobFieldPlain(loc, 256); cl != "" {
			allLocs = append(allLocs, cl)
		}
	}
	if addArr, okA := info["additionalLocations"].([]any); okA {
		for _, x := range addArr {
			if cl := SanitizeJobFieldPlain(anyString(x), 256); cl != "" {
				allLocs = append(allLocs, cl)
			}
		}
	}
	remoteType := ""
	if rt, okR := info["remoteType"].(string); okR {
		remoteType = SanitizeJobFieldPlain(rt, 80)
	}
	timeType := ""
	if tt, okT := info["timeType"].(string); okT {
		timeType = SanitizeJobFieldPlain(tt, 80)
	}
	rawPostedOn := ""
	if sd, okS := info["startDate"].(string); okS {
		rawPostedOn = sd
	} else if po, okP := info["postedOn"].(string); okP {
		rawPostedOn = po
	}
	postedOn := NormalizeWorkdayPostedAt(rawPostedOn, now)
	descHTML, _ := info["jobDescription"].(string)
	bodyMD := ""
	if descHTML != "" {
		md, _ := htmlToMD(descHTML, origURL)
		bodyMD = strings.TrimSpace(md)
	}
	pay := ParsePayFromText(bodyMD)
	extURL := origURL
	if rawExt, okE := info["externalUrl"].(string); okE && len(rawExt) <= 2048 {
		cleanedExt := strings.TrimSpace(StripInvisibleJobChars(rawExt))
		if parsedExt, okU := parseStrictURL(cleanedExt); okU &&
			strings.EqualFold(parsedExt.Scheme, "https") &&
			parsedExt.User == nil &&
			(parsedExt.Port() == "" || parsedExt.Port() == "443") &&
			strings.EqualFold(parsedExt.Hostname(), s.host) {
			extURL = canonicalWhatwgURLString(parsedExt)
		}
	}
	wp := InferWorkdayWorkplaceType(remoteType, strings.Join(allLocs, " "), title)
	var baseSal *NormalizedPay
	if pay != nil && pay.Basis == PayBasisBase {
		baseSal = pay
	}
	jp := &StructuredJobPosting{
		Title:              title,
		HiringOrganization: s.org,
		JobLocation:        allLocs,
		WorkplaceType:      wp,
		BaseSalary:         baseSal,
		Pay:                pay,
		DatePosted:         postedOn,
		EmploymentType:     timeType,
		URL:                origURL,
		ApplyURL:           extURL,
		Source:             "workday",
	}
	headerMD := FormatJobPostingHeaderMarkdown(*jp)
	return &ATSFormattedResult{
		Title:         fmt.Sprintf("%s (%s)", title, s.org),
		PublishedTime: postedOn,
		JobPosting:    jp,
		Markdown:      joinNonEmptyBlocks("# "+title, headerMD, bodyMD),
		Links:         []string{extURL},
	}
}

func (s *ATSPreFetchSpec) formatWorkdayBoard(rawBody string, now time.Time) *ATSFormattedResult {
	data, _ := SafeJSONParse(rawBody).(map[string]any)
	if data == nil {
		return nil
	}
	postingsAny, ok := data["jobPostings"].([]any)
	if !ok {
		return nil
	}
	rawTotal := 0
	if tf, okT := data["total"].(float64); okT && !math.IsNaN(tf) && !math.IsInf(tf, 0) && tf > 0 {
		rawTotal = int(tf)
	}
	var knownTotal *int
	if rawTotal > 0 {
		kt := rawTotal
		if len(postingsAny) > 0 && s.reqOffset+len(postingsAny) > kt {
			kt = s.reqOffset + len(postingsAny)
		}
		knownTotal = intPtr(kt)
	} else if s.reqOffset == 0 {
		knownTotal = intPtr(len(postingsAny))
	} else if len(postingsAny) < 20 {
		knownTotal = intPtr(s.reqOffset + len(postingsAny))
	}

	countDesc := fmt.Sprintf("showing %d–%d", s.reqOffset+1, s.reqOffset+len(postingsAny))
	if knownTotal != nil {
		countDesc = fmt.Sprintf("%d open roles", *knownTotal)
	}
	cleanSearchHeading := ""
	if s.searchText != "" {
		cleanSearchHeading = strings.ReplaceAll(SanitizeJobFieldPlain(s.searchText, 120), `"`, "'")
	}
	searchSuffix := ""
	if cleanSearchHeading != "" {
		searchSuffix = fmt.Sprintf(` matching "%s"`, cleanSearchHeading)
	}
	heading := fmt.Sprintf("%s (%s) — Workday Job Board (%s%s)", s.org, s.site, countDesc, searchSuffix)
	lines := []string{"# " + heading}
	links := make([]string, 0, len(postingsAny))
	records := make([]StructuredJobRecord, 0, len(postingsAny))

	for _, item := range postingsAny {
		p, okP := item.(map[string]any)
		if !okP || p == nil {
			continue
		}
		pTitle := SanitizeJobFieldPlain(anyString(p["title"]), 512)
		if pTitle == "" {
			continue
		}
		rawExtPath := ""
		if ep, okE := p["externalPath"].(string); okE {
			rawExtPath = strings.TrimSpace(StripInvisibleJobChars(ep))
		}
		isSafeExtPath := rawExtPath != "" && len(rawExtPath) <= 512 &&
			!strings.Contains(rawExtPath, "..") &&
			!reWorkdayBadPct.MatchString(rawExtPath) &&
			reWorkdaySafeExtPath.MatchString(rawExtPath)
		fullURL := "https://" + s.host + "/" + s.site
		if isSafeExtPath {
			if strings.HasPrefix(rawExtPath, "/") {
				fullURL = "https://" + s.host + "/" + s.site + rawExtPath
			} else {
				fullURL = "https://" + s.host + "/" + s.site + "/" + rawExtPath
			}
		}
		locTxt := ""
		if lt, okL := p["locationsText"].(string); okL {
			locTxt = SanitizeJobFieldPlain(lt, 256)
		}
		rawPostedOn := ""
		if po, okPo := p["postedOn"].(string); okPo {
			rawPostedOn = strings.TrimSpace(po)
		}
		postedAt, postedLabel := ParseWorkdayPostedField(rawPostedOn, now)
		bullets := ""
		if bfArr, okB := p["bulletFields"].([]any); okB {
			var bParts []string
			for _, b := range bfArr {
				cb := reBracketParenStrip.ReplaceAllString(SanitizeJobFieldPlain(anyString(b), 80), "")
				if cb != "" {
					bParts = append(bParts, cb)
					if len(bParts) >= 6 {
						break
					}
				}
			}
			bullets = strings.Join(bParts, ", ")
		}
		wp := InferWorkdayWorkplaceType(anyString(p["remoteType"]), locTxt, pTitle)
		locs := []string{}
		if locTxt != "" {
			locs = []string{locTxt}
		}
		links = append(links, fullURL)
		records = append(records, StructuredJobRecord{
			Title:         pTitle,
			Company:       s.org,
			URL:           fullURL,
			ApplyURL:      fullURL,
			WorkplaceType: wp,
			Locations:     locs,
			Pay:           nil,
			PostedAt:      postedAt,
			PostedLabel:   postedLabel,
			Source:        "workday",
		})
		postedDisplay := postedLabel
		if postedAt != nil {
			postedDisplay = *postedAt
		}
		meta := joinNonEmptySep(" · ", locTxt, postedDisplay, bullets)
		mdSafeTitle := reMarkdownLinkChars.ReplaceAllString(pTitle, `\$1`)
		suffix := ""
		if meta != "" {
			suffix = " — " + meta
		}
		lines = append(lines, fmt.Sprintf("- **[%s](%s)**%s", mdSafeTitle, fullURL, suffix))
	}

	returned := len(records)
	truncated := len(postingsAny) > 0 && ((knownTotal != nil && *knownTotal > s.reqOffset+returned) || (knownTotal == nil && len(postingsAny) >= 20))
	nextOffsetVal := s.reqOffset + 20
	if truncated {
		ofTotal := ""
		if knownTotal != nil {
			ofTotal = fmt.Sprintf(" of %d", *knownTotal)
		}
		lines = append(lines, "", fmt.Sprintf("*Showing %d–%d%s open roles (list cut short — pass `?offset=%d` on `scrape` or `cursor: \"%d\"` on `jobs` for the next page).*", s.reqOffset+1, s.reqOffset+returned, ofTotal, nextOffsetVal, nextOffsetVal))
	} else if len(records) == 0 {
		lines = append(lines, "", "No open positions currently listed.")
	}
	nextCur := ""
	if truncated {
		nextCur = strconv.Itoa(nextOffsetVal)
	}
	return &ATSFormattedResult{
		Title:      heading,
		Markdown:   strings.Join(lines, "\n"),
		Links:      links,
		Jobs:       records,
		Total:      knownTotal,
		Returned:   intPtr(returned),
		Truncated:  boolPtr(truncated),
		NextCursor: nextCur,
	}
}

func streamGreenhouseBoardJSON(rawBody string, visit func(idx int, elem any)) (metaTotal int, ok bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(rawBody, "\ufeff"))
	if !strings.HasPrefix(trimmed, "{") {
		return 0, false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return 0, false
	}
	sawJobs := false
	idx := 0
	for dec.More() {
		kt, err := dec.Token()
		key, okK := kt.(string)
		if err != nil || !okK {
			return 0, false
		}
		switch key {
		case "jobs":
			jt, err := dec.Token()
			if err != nil || jt != json.Delim('[') {
				return 0, false
			}
			sawJobs = true
			for dec.More() {
				var elem any
				if err := dec.Decode(&elem); err != nil {
					return 0, false
				}
				visit(idx, elem)
				idx++
			}
			if ct, err := dec.Token(); err != nil || ct != json.Delim(']') {
				return 0, false
			}
		case "meta":
			var metaVal any
			if err := dec.Decode(&metaVal); err != nil {
				return 0, false
			}
			if metaObj, okM := metaVal.(map[string]any); okM && metaObj != nil {
				if mt, okT := metaObj["total"].(float64); okT && !math.IsNaN(mt) && !math.IsInf(mt, 0) && int(mt) > metaTotal {
					metaTotal = int(mt)
				}
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, false
			}
		}
	}
	if ct, err := dec.Token(); err != nil || ct != json.Delim('}') {
		return 0, false
	}
	return metaTotal, sawJobs
}

func (s *ATSPreFetchSpec) formatGreenhouseBoard(rawBody string) *ATSFormattedResult {
	const linkCap = 2_500
	const maxBoardRecords = 2_500
	const maxMarkdownBullets = 120

	var links []string
	var records []StructuredJobRecord
	var bulletLines []string
	jobsCount := 0

	metaTotal, ok := streamGreenhouseBoardJSON(rawBody, func(idx int, it any) {
		jobsCount++
		j, okJ := it.(map[string]any)
		if idx < linkCap && okJ && j != nil {
			jURL := "https://" + s.host + "/" + s.org + "/jobs/" + anyString(j["id"])
			if abs, okA := j["absolute_url"].(string); okA && strings.HasPrefix(abs, "https://") {
				jURL = abs
			}
			links = append(links, jURL)
		}
		if idx < s.reqOffset || idx >= s.reqOffset+maxBoardRecords || !okJ || j == nil {
			return
		}
		jTitle := strings.TrimSpace(anyString(j["title"]))
		if jTitle == "" {
			return
		}
		ghLocs := extractGreenhouseLocations(j)
		jURL := "https://" + s.host + "/" + s.org + "/jobs/" + anyString(j["id"])
		if abs, okA := j["absolute_url"].(string); okA && strings.HasPrefix(abs, "https://") {
			jURL = abs
		}
		rawContent, _ := j["content"].(string)
		plainPreview := ""
		if rawContent != "" {
			plainPreview = StripTagsPlain(DecodeEntitiesBasic(DecodeEntitiesBasic(sliceUTF16Max(rawContent, 12_000))))
		}
		wp := InferWorkplaceType(strings.Join(ghLocs, " ") + " " + jTitle + " " + sliceUTF16Max(plainPreview, 320))
		pay := parseGreenhousePay(j, "")
		var postedAt *string
		if ua, okU := j["updated_at"].(string); okU {
			postedAt = strPtr(ua)
		} else if fp, okF := j["first_published"].(string); okF {
			postedAt = strPtr(fp)
		}
		companyName := s.org
		if cn, okC := j["company_name"].(string); okC && strings.TrimSpace(cn) != "" {
			companyName = strings.TrimSpace(cn)
		}
		snippet := ""
		if plainPreview != "" {
			snippet = sliceUTF16Max(plainPreview, 240)
		}
		records = append(records, StructuredJobRecord{
			Title:         jTitle,
			Company:       companyName,
			URL:           jURL,
			ApplyURL:      jURL,
			WorkplaceType: wp,
			Locations:     ghLocs,
			Pay:           pay,
			PostedAt:      postedAt,
			Source:        "greenhouse",
			Snippet:       snippet,
		})
		if len(bulletLines) < maxMarkdownBullets {
			locMeta := strings.Join(ghLocs[:min(len(ghLocs), 2)], ", ")
			wpMeta := ""
			if wp != WorkplaceUnknown {
				wpMeta = string(wp)
			}
			payMeta := ""
			if pay != nil {
				payMeta = FormatNormalizedPay(pay)
			}
			meta := joinNonEmptySep(" · ", locMeta, wpMeta, payMeta)
			suffix := ""
			if meta != "" {
				suffix = " — " + meta
			}
			bulletLines = append(bulletLines, fmt.Sprintf("- **[%s](%s)**%s", jTitle, jURL, suffix))
		}
	})
	if !ok {
		return nil
	}
	if links == nil {
		links = []string{}
	}
	if records == nil {
		records = []StructuredJobRecord{}
	}

	total := jobsCount
	if metaTotal > total {
		total = metaTotal
	}
	lines := make([]string, 0, len(bulletLines)+4)
	lines = append(lines, fmt.Sprintf("# %s — Greenhouse Job Board (%d open roles)", s.org, total))
	lines = append(lines, bulletLines...)

	returned := len(records)
	nextOffsetVal := s.reqOffset + returned
	truncated := total > nextOffsetVal
	if len(records) > maxMarkdownBullets {
		lines = append(lines, fmt.Sprintf("- *... and %d additional open roles in `jobs[]`*", len(records)-maxMarkdownBullets))
	}
	if truncated {
		lines = append(lines, "", fmt.Sprintf("*Showing %d–%d of %d open roles (list cut short — pass `?offset=%d` on `scrape` or `cursor: \"%d\"` on `jobs` for the next page).*", s.reqOffset+1, nextOffsetVal, total, nextOffsetVal, nextOffsetVal))
	}
	nextCur := ""
	if truncated {
		nextCur = strconv.Itoa(nextOffsetVal)
	}
	return &ATSFormattedResult{
		Title:      fmt.Sprintf("%s Jobs (%d)", s.org, total),
		Markdown:   strings.Join(lines, "\n"),
		Links:      links,
		Jobs:       records,
		Total:      intPtr(total),
		Returned:   intPtr(returned),
		Truncated:  boolPtr(truncated),
		NextCursor: nextCur,
	}
}

func (s *ATSPreFetchSpec) formatGreenhouseJob(rawBody, origURL string, htmlToMD HTMLToMDFunc) *ATSFormattedResult {
	data, _ := SafeJSONParse(rawBody).(map[string]any)
	if data == nil {
		return nil
	}
	rawTitle, ok := data["title"].(string)
	if !ok {
		return nil
	}
	title := strings.TrimSpace(rawTitle)
	companyName := s.org
	if cn, okC := data["company_name"].(string); okC && cn != "" {
		companyName = cn
	}
	ghLocs := extractGreenhouseLocations(data)
	loc := strings.Join(ghLocs, " ")
	rawContent := ""
	if rc, okR := data["content"].(string); okR {
		rawContent = DecodeEntitiesBasic(DecodeEntitiesBasic(rc))
	}
	bodyMD := ""
	if rawContent != "" {
		md, _ := htmlToMD(rawContent, origURL)
		bodyMD = strings.TrimSpace(md)
	}
	pay := parseGreenhousePay(data, bodyMD)
	updatedAt := ""
	if ua, okU := data["updated_at"].(string); okU {
		updatedAt = ua
	} else if fp, okF := data["first_published"].(string); okF {
		updatedAt = fp
	}
	absURL := origURL
	if au, okA := data["absolute_url"].(string); okA && strings.HasPrefix(au, "http") {
		absURL = au
	}
	wp := InferWorkplaceType(loc + " " + title + " " + sliceUTF16Max(bodyMD, 400))
	var baseSal *NormalizedPay
	if pay != nil && pay.Basis == PayBasisBase {
		baseSal = pay
	}
	jp := &StructuredJobPosting{
		Title:              title,
		HiringOrganization: companyName,
		JobLocation:        ghLocs,
		WorkplaceType:      wp,
		BaseSalary:         baseSal,
		Pay:                pay,
		DatePosted:         updatedAt,
		URL:                origURL,
		ApplyURL:           absURL,
		Source:             "greenhouse",
	}
	headerMD := FormatJobPostingHeaderMarkdown(*jp)
	return &ATSFormattedResult{
		Title:         title + " @ " + companyName,
		PublishedTime: updatedAt,
		JobPosting:    jp,
		Markdown:      joinNonEmptyBlocks("# "+title+" @ "+companyName, headerMD, bodyMD),
		Links:         []string{absURL},
	}
}
