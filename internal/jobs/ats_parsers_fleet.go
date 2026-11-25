package jobs

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func extractLeverLocations(cats map[string]any) []string {
	if cats == nil {
		return []string{}
	}
	if allArr, ok := cats["allLocations"].([]any); ok {
		out := make([]string, 0, len(allArr))
		for _, x := range allArr {
			if s := anyString(x); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if loc, ok := cats["location"].(string); ok && loc != "" {
		return []string{loc}
	}
	return []string{}
}

func (s *ATSPreFetchSpec) formatLeverBoard(rawBody string) *ATSFormattedResult {
	jobsAny, ok := SafeJSONParse(rawBody).([]any)
	if !ok {
		return nil
	}
	total := len(jobsAny)
	linkCap := min(total, 2500)
	links := make([]string, 0, linkCap)
	for _, it := range jobsAny[:linkCap] {
		j, okJ := it.(map[string]any)
		if !okJ {
			continue
		}
		jURL := "https://" + s.host + "/" + s.org + "/" + anyString(j["id"])
		if hu, okH := j["hostedUrl"].(string); okH && strings.HasPrefix(hu, "https://") {
			jURL = hu
		}
		links = append(links, jURL)
	}
	lines := []string{fmt.Sprintf("# %s — Lever Job Board (%d open roles)", s.org, total)}
	const maxBoardRecords = 2_500
	const maxMarkdownBullets = 120
	start := min(s.reqOffset, total)
	end := min(start+maxBoardRecords, total)
	records := make([]StructuredJobRecord, 0, end-start)

	for _, it := range jobsAny[start:end] {
		j, okJ := it.(map[string]any)
		if !okJ || j == nil {
			continue
		}
		jTitle := strings.TrimSpace(anyString(j["text"]))
		if jTitle == "" {
			continue
		}
		cats, _ := j["categories"].(map[string]any)
		allLocs := extractLeverLocations(cats)
		wp := InferWorkplaceType(anyString(j["workplaceType"]) + " " + strings.Join(allLocs, " "))
		jURL := "https://" + s.host + "/" + s.org + "/" + anyString(j["id"])
		if hu, okH := j["hostedUrl"].(string); okH && strings.HasPrefix(hu, "https://") {
			jURL = hu
		}
		applyURL := jURL + "/apply"
		if au, okA := j["applyUrl"].(string); okA && strings.HasPrefix(au, "https://") {
			applyURL = au
		}
		var createdISO *string
		if cm, okC := j["createdAt"].(float64); okC && !math.IsNaN(cm) && !math.IsInf(cm, 0) {
			iso := time.UnixMilli(int64(cm)).UTC().Format("2006-01-02T15:04:05.000Z")
			createdISO = &iso
		}
		pay := parseLeverPay(j, "")
		snippet := ""
		if dp, okD := j["descriptionPlain"].(string); okD && strings.TrimSpace(dp) != "" {
			snippet = sliceUTF16Max(strings.TrimSpace(dp), 240)
		}
		records = append(records, StructuredJobRecord{
			Title:         jTitle,
			Company:       s.org,
			URL:           jURL,
			ApplyURL:      applyURL,
			WorkplaceType: wp,
			Locations:     allLocs,
			Pay:           pay,
			PostedAt:      createdISO,
			Source:        "lever",
			Snippet:       snippet,
		})
		if len(lines)-1 < maxMarkdownBullets {
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
			lines = append(lines, fmt.Sprintf("- **[%s](%s)**%s", jTitle, jURL, suffix))
		}
	}

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

func (s *ATSPreFetchSpec) formatLeverJob(rawBody, origURL string, htmlToMD HTMLToMDFunc) *ATSFormattedResult {
	data, _ := SafeJSONParse(rawBody).(map[string]any)
	if data == nil {
		return nil
	}
	rawText, ok := data["text"].(string)
	if !ok {
		return nil
	}
	title := strings.TrimSpace(rawText)
	cats, _ := data["categories"].(map[string]any)
	allLocs := extractLeverLocations(cats)
	commitment := ""
	if cats != nil {
		commitment, _ = cats["commitment"].(string)
	}
	wp := InferWorkplaceType(anyString(data["workplaceType"]) + " " + strings.Join(allLocs, " "))

	var descParts []string
	if introHTML, okI := data["description"].(string); okI && introHTML != "" {
		md, _ := htmlToMD(introHTML, origURL)
		if trimmed := strings.TrimSpace(md); trimmed != "" {
			descParts = append(descParts, trimmed)
		}
	}
	if lists, okL := data["lists"].([]any); okL {
		for _, it := range lists {
			lst, okM := it.(map[string]any)
			if !okM || lst == nil {
				continue
			}
			lHead := strings.TrimSpace(anyString(lst["text"]))
			lContent := ""
			if lc, okC := lst["content"].(string); okC {
				md, _ := htmlToMD("<ul>"+lc+"</ul>", origURL)
				lContent = strings.TrimSpace(md)
			}
			if lHead != "" || lContent != "" {
				headLine := ""
				if lHead != "" {
					headLine = "## " + lHead
				}
				descParts = append(descParts, joinNonEmptyBlocks(headLine, lContent))
			}
		}
	}
	if addHTML, okA := data["additional"].(string); okA && addHTML != "" {
		md, _ := htmlToMD(addHTML, origURL)
		if trimmed := strings.TrimSpace(md); trimmed != "" {
			descParts = append(descParts, trimmed)
		}
	}
	bodyMD := strings.Join(descParts, "\n\n")
	pay := parseLeverPay(data, bodyMD)

	createdISO := ""
	if cm, okC := data["createdAt"].(float64); okC && !math.IsNaN(cm) && !math.IsInf(cm, 0) {
		createdISO = time.UnixMilli(int64(cm)).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	applyURL := strings.TrimRight(origURL, "/") + "/apply"
	if au, okU := data["applyUrl"].(string); okU && strings.HasPrefix(au, "http") {
		applyURL = au
	}
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
		DatePosted:         createdISO,
		EmploymentType:     commitment,
		URL:                origURL,
		ApplyURL:           applyURL,
		Source:             "lever",
	}
	headerMD := FormatJobPostingHeaderMarkdown(*jp)
	return &ATSFormattedResult{
		Title:         title + " @ " + s.org,
		PublishedTime: createdISO,
		JobPosting:    jp,
		Markdown:      joinNonEmptyBlocks("# "+title+" @ "+s.org, headerMD, bodyMD),
		Links:         []string{applyURL},
	}
}

func (s *ATSPreFetchSpec) formatWorkableBoard(rawBody string) *ATSFormattedResult {
	data, _ := SafeJSONParse(rawBody).(map[string]any)
	if data == nil {
		return nil
	}
	rawJobs, ok := data["jobs"].([]any)
	if !ok {
		return nil
	}
	orgName := s.org
	if nm, okN := data["name"].(string); okN && strings.TrimSpace(nm) != "" {
		orgName = strings.TrimSpace(nm)
	}
	var order []string
	merged := make(map[string]*StructuredJobRecord)

	for _, it := range rawJobs {
		j, okJ := it.(map[string]any)
		if !okJ || j == nil {
			continue
		}
		code := strings.TrimSpace(anyString(j["shortcode"]))
		jTitle := strings.TrimSpace(anyString(j["title"]))
		if code == "" || jTitle == "" {
			continue
		}
		var locParts []string
		for _, k := range []string{"city", "state", "country"} {
			if sv, okS := j[k].(string); okS && sv != "" {
				locParts = append(locParts, sv)
			}
		}
		loc := strings.Join(locParts, ", ")
		tele, _ := j["telecommuting"].(bool)
		wpTypeStr := anyString(j["workplace_type"])
		isRemote := tele || strings.Contains(strings.ToLower(wpTypeStr), "remote")
		wp := WorkplaceRemote
		if !isRemote {
			wp = InferWorkplaceType(wpTypeStr + " " + loc)
		}
		jURL := "https://apply.workable.com/" + s.org + "/j/" + code + "/"
		if uStr, okU := j["url"].(string); okU && strings.HasPrefix(uStr, "https://") {
			jURL = uStr
		}
		if existing, exists := merged[code]; exists {
			if loc != "" && !containsString(existing.Locations, loc) {
				existing.Locations = append(existing.Locations, loc)
			}
			if isRemote {
				existing.WorkplaceType = WorkplaceRemote
			}
		} else {
			descPlain := StripTagsPlain(anyString(j["description"]))
			locs := []string{}
			if loc != "" {
				locs = []string{loc}
			}
			var postedAt *string
			if po, okP := j["published_on"].(string); okP {
				postedAt = strPtr(po)
			}
			rec := &StructuredJobRecord{
				Title:         jTitle,
				Company:       orgName,
				URL:           jURL,
				ApplyURL:      strings.TrimRight(jURL, "/") + "/apply/",
				WorkplaceType: wp,
				Locations:     locs,
				Pay:           ParsePayFromText(descPlain),
				PostedAt:      postedAt,
				Source:        "workable",
			}
			merged[code] = rec
			order = append(order, code)
		}
	}

	records := make([]StructuredJobRecord, 0, len(order))
	links := make([]string, 0, len(order))
	lines := []string{fmt.Sprintf("# %s — Workable Job Board (%d open roles)", orgName, len(order))}
	for _, code := range order {
		r := *merged[code]
		records = append(records, r)
		links = append(links, r.URL)
		wpMeta := ""
		if r.WorkplaceType != WorkplaceUnknown {
			wpMeta = string(r.WorkplaceType)
		}
		meta := joinNonEmptySep(" · ", strings.Join(r.Locations, "; "), wpMeta)
		suffix := ""
		if meta != "" {
			suffix = " — " + meta
		}
		lines = append(lines, fmt.Sprintf("- **[%s](%s)**%s", r.Title, r.URL, suffix))
	}
	return &ATSFormattedResult{
		Title:    fmt.Sprintf("%s Jobs (%d)", orgName, len(records)),
		Markdown: strings.Join(lines, "\n"),
		Links:    links,
		Jobs:     records,
	}
}

func (s *ATSPreFetchSpec) formatWorkableJob(rawBody, origURL string, htmlToMD HTMLToMDFunc) *ATSFormattedResult {
	data, _ := SafeJSONParse(rawBody).(map[string]any)
	if data == nil {
		return nil
	}
	rawTitle, ok := data["title"].(string)
	if !ok {
		return nil
	}
	title := strings.TrimSpace(rawTitle)
	locObj, _ := data["location"].(map[string]any)
	var locParts []string
	if locObj != nil {
		for _, k := range []string{"city", "region", "country"} {
			if sv, okS := locObj[k].(string); okS && sv != "" {
				locParts = append(locParts, sv)
			}
		}
	}
	loc := strings.Join(locParts, ", ")
	wp := InferWorkplaceType(anyString(data["workplace"]) + " " + loc)
	if locObj != nil {
		if tele, _ := locObj["telecommuting"].(bool); tele {
			wp = WorkplaceRemote
		}
	}
	var bodyParts []string
	for _, sec := range [][2]string{{"", "description"}, {"Requirements", "requirements"}, {"Benefits", "benefits"}} {
		if fv, okF := data[sec[1]].(string); okF && strings.TrimSpace(fv) != "" {
			md, _ := htmlToMD(fv, origURL)
			trimmed := strings.TrimSpace(md)
			if sec[0] != "" {
				bodyParts = append(bodyParts, "## "+sec[0]+"\n\n"+trimmed)
			} else {
				bodyParts = append(bodyParts, trimmed)
			}
		}
	}
	bodyMD := strings.Join(bodyParts, "\n\n")
	var pay *NormalizedPay
	if salObj, okS := data["salary"].(map[string]any); okS && salObj != nil {
		_, hasFrom := salObj["salary_from"].(float64)
		_, hasTo := salObj["salary_to"].(float64)
		if hasFrom || hasTo {
			var minP, maxP *float64
			if sf, okF := salObj["salary_from"].(float64); okF {
				minP = &sf
			}
			if st, okT := salObj["salary_to"].(float64); okT {
				maxP = &st
			}
			cur := "USD"
			if sc, okC := salObj["salary_currency"].(string); okC && sc != "" {
				cur = strings.ToUpper(sc)
			}
			pay = &NormalizedPay{
				Min:      minP,
				Max:      maxP,
				Currency: cur,
				Period:   PayPeriodYear,
				Basis:    PayBasisBase,
			}
		}
	}
	if pay == nil {
		pay = ParsePayFromText(bodyMD)
	}
	published, _ := data["published"].(string)
	applyURL := "https://apply.workable.com/" + s.org + "/j/" + s.jobID + "/apply/"
	var jobLocs []string
	if loc != "" {
		jobLocs = []string{loc}
	}
	var baseSal *NormalizedPay
	if pay != nil && pay.Basis == PayBasisBase {
		baseSal = pay
	}
	jp := &StructuredJobPosting{
		Title:              title,
		HiringOrganization: s.org,
		JobLocation:        jobLocs,
		WorkplaceType:      wp,
		BaseSalary:         baseSal,
		Pay:                pay,
		DatePosted:         published,
		URL:                origURL,
		ApplyURL:           applyURL,
		Source:             "workable",
	}
	headerMD := FormatJobPostingHeaderMarkdown(*jp)
	return &ATSFormattedResult{
		Title:         title + " @ " + s.org,
		PublishedTime: published,
		JobPosting:    jp,
		Markdown:      joinNonEmptyBlocks("# "+title+" @ "+s.org, headerMD, bodyMD),
		Links:         []string{applyURL},
	}
}

func (s *ATSPreFetchSpec) formatGemBoard(rawBody string) *ATSFormattedResult {
	posts, ok := SafeJSONParse(rawBody).([]any)
	if !ok {
		return nil
	}
	capPosts := min(len(posts), 2_500)
	records := make([]StructuredJobRecord, 0, capPosts)
	links := make([]string, 0, capPosts)
	lines := []string{fmt.Sprintf("# %s — Gem Job Board (%d open roles)", s.org, len(posts))}
	for _, it := range posts[:capPosts] {
		p, okP := it.(map[string]any)
		if !okP || p == nil {
			continue
		}
		pTitle := strings.TrimSpace(anyString(p["title"]))
		if pTitle == "" {
			continue
		}
		loc := ""
		if locObj, okL := p["location"].(map[string]any); okL && locObj != nil {
			loc = strings.TrimSpace(anyString(locObj["name"]))
		}
		wp := InferWorkplaceType(anyString(p["location_type"]) + " " + loc)
		pURL := "https://jobs.gem.com/" + s.org + "/" + anyString(p["id"])
		if au, okA := p["absolute_url"].(string); okA && strings.HasPrefix(au, "https://") {
			pURL = au
		}
		locs := []string{}
		if loc != "" {
			locs = []string{loc}
		}
		var postedAt *string
		if fp, okF := p["first_published_at"].(string); okF {
			postedAt = strPtr(fp)
		}
		links = append(links, pURL)
		records = append(records, StructuredJobRecord{
			Title:         pTitle,
			Company:       s.org,
			URL:           pURL,
			ApplyURL:      pURL,
			WorkplaceType: wp,
			Locations:     locs,
			Pay:           ParsePayFromText(anyString(p["content_plain"])),
			PostedAt:      postedAt,
			Source:        "gem",
		})
		if len(lines)-1 < 120 {
			suffix := ""
			if loc != "" {
				suffix = " — " + loc
			}
			lines = append(lines, fmt.Sprintf("- **[%s](%s)**%s", pTitle, pURL, suffix))
		}
	}
	return &ATSFormattedResult{
		Title:    fmt.Sprintf("%s Jobs (%d)", s.org, len(records)),
		Markdown: strings.Join(lines, "\n"),
		Links:    links,
		Jobs:     records,
	}
}

func (s *ATSPreFetchSpec) formatRipplingBoard(rawBody string) *ATSFormattedResult {
	parsed := SafeJSONParse(rawBody)
	var items []any
	switch pv := parsed.(type) {
	case []any:
		items = pv
	case map[string]any:
		if resArr, ok := pv["results"].([]any); ok {
			items = resArr
		}
	}
	if items == nil {
		return nil
	}
	var order []string
	byUUID := make(map[string]*StructuredJobRecord)

	for _, it := range items {
		item, okI := it.(map[string]any)
		if !okI || item == nil {
			continue
		}
		uuid := strings.TrimSpace(firstNonEmpty(anyString(item["uuid"]), anyString(item["id"])))
		jTitle := strings.TrimSpace(firstNonEmpty(anyString(item["name"]), anyString(item["title"])))
		if uuid == "" || jTitle == "" {
			continue
		}
		locLabel := ""
		switch wl := item["workLocation"].(type) {
		case string:
			locLabel = wl
		case map[string]any:
			locLabel, _ = wl["label"].(string)
		}
		if locLabel == "" {
			if wlArr, okA := item["workLocations"].([]any); okA {
				var parts []string
				for _, w := range wlArr {
					switch wv := w.(type) {
					case string:
						if wv != "" {
							parts = append(parts, wv)
						}
					case map[string]any:
						if lbl, okL := wv["label"].(string); okL && lbl != "" {
							parts = append(parts, lbl)
						}
					}
				}
				locLabel = strings.Join(parts, "; ")
			}
		}
		jURL := "https://ats.rippling.com/" + s.org + "/jobs/" + uuid
		if uStr, okU := item["url"].(string); okU && strings.HasPrefix(uStr, "https://") {
			jURL = uStr
		}
		var createdAt *string
		if co, okC := item["createdOn"].(string); okC {
			createdAt = strPtr(co)
		} else if pa, okP := item["publishedAt"].(string); okP {
			createdAt = strPtr(pa)
		}
		if existing, exists := byUUID[uuid]; exists {
			if locLabel != "" && !containsString(existing.Locations, locLabel) {
				existing.Locations = append(existing.Locations, locLabel)
			}
			if strings.Contains(strings.ToLower(locLabel), "remote") {
				existing.WorkplaceType = WorkplaceRemote
			}
		} else {
			locs := []string{}
			if locLabel != "" {
				locs = []string{locLabel}
			}
			rec := &StructuredJobRecord{
				Title:         jTitle,
				Company:       s.org,
				URL:           jURL,
				ApplyURL:      jURL,
				WorkplaceType: InferWorkplaceType(locLabel + " " + jTitle),
				Locations:     locs,
				Pay:           parseRipplingPay(item, ""),
				PostedAt:      createdAt,
				Source:        "rippling",
			}
			byUUID[uuid] = rec
			order = append(order, uuid)
		}
	}

	records := make([]StructuredJobRecord, 0, len(order))
	links := make([]string, 0, len(order))
	lines := []string{fmt.Sprintf("# %s — Rippling Job Board (%d open roles)", s.org, len(order))}
	for idx, uuid := range order {
		r := *byUUID[uuid]
		records = append(records, r)
		links = append(links, r.URL)
		if idx < 120 {
			suffix := ""
			if len(r.Locations) > 0 {
				suffix = " — " + strings.Join(r.Locations, "; ")
			}
			lines = append(lines, fmt.Sprintf("- **[%s](%s)**%s", r.Title, r.URL, suffix))
		}
	}
	return &ATSFormattedResult{
		Title:     fmt.Sprintf("%s Jobs (%d)", s.org, len(records)),
		Markdown:  strings.Join(lines, "\n"),
		Links:     links,
		Jobs:      records,
		Total:     intPtr(len(records)),
		Returned:  intPtr(len(records)),
		Truncated: boolPtr(false),
	}
}

func (s *ATSPreFetchSpec) formatRipplingJob(rawBody, origURL string, htmlToMD HTMLToMDFunc) *ATSFormattedResult {
	parsed := SafeJSONParse(rawBody)
	var data map[string]any
	switch pv := parsed.(type) {
	case []any:
		for _, it := range pv {
			if m, okM := it.(map[string]any); okM && m != nil {
				candID := firstNonEmpty(anyString(m["uuid"]), anyString(m["id"]))
				if strings.EqualFold(candID, s.jobID) {
					data = m
					break
				}
			}
		}
	case map[string]any:
		data = pv
	}
	if data == nil {
		return nil
	}
	title := strings.TrimSpace(firstNonEmpty(anyString(data["name"]), anyString(data["title"])))
	if title == "" {
		return nil
	}
	companyName := s.org
	if cn, okC := data["companyName"].(string); okC && strings.TrimSpace(cn) != "" {
		companyName = strings.TrimSpace(cn)
	}
	var locs []string
	switch wl := data["workLocation"].(type) {
	case string:
		if strings.TrimSpace(wl) != "" {
			locs = append(locs, strings.TrimSpace(wl))
		}
	case map[string]any:
		if lbl, okL := wl["label"].(string); okL && strings.TrimSpace(lbl) != "" {
			locs = append(locs, strings.TrimSpace(lbl))
		}
	}
	if wlArr, okA := data["workLocations"].([]any); okA {
		for _, w := range wlArr {
			lbl := ""
			switch wv := w.(type) {
			case string:
				lbl = strings.TrimSpace(wv)
			case map[string]any:
				if l, okL := wv["label"].(string); okL {
					lbl = strings.TrimSpace(l)
				}
			}
			if lbl != "" && !containsString(locs, lbl) {
				locs = append(locs, lbl)
			}
		}
	}
	var descParts []string
	switch desc := data["description"].(type) {
	case string:
		if strings.TrimSpace(desc) != "" {
			md, _ := htmlToMD(desc, origURL)
			if trimmed := strings.TrimSpace(md); trimmed != "" {
				descParts = append(descParts, trimmed)
			}
		}
	case map[string]any:
		for _, k := range []string{"company", "role"} {
			if hp, okH := desc[k].(string); okH && strings.TrimSpace(hp) != "" {
				md, _ := htmlToMD(hp, origURL)
				if trimmed := strings.TrimSpace(md); trimmed != "" {
					descParts = append(descParts, trimmed)
				}
			}
		}
	}
	bodyMD := strings.Join(descParts, "\n\n")
	pay := parseRipplingPay(data, bodyMD)
	wp := InferWorkplaceType(strings.Join(locs, " ") + " " + title + " " + sliceUTF16Max(bodyMD, 400))
	postedAt := ""
	if co, okC := data["createdOn"].(string); okC {
		postedAt = co
	} else if pa, okP := data["publishedAt"].(string); okP {
		postedAt = pa
	}
	jobURL := origURL
	if uStr, okU := data["url"].(string); okU && strings.HasPrefix(uStr, "https://") {
		jobURL = uStr
	}
	var baseSal *NormalizedPay
	if pay != nil && pay.Basis == PayBasisBase {
		baseSal = pay
	}
	jp := &StructuredJobPosting{
		Title:              title,
		HiringOrganization: companyName,
		JobLocation:        locs,
		WorkplaceType:      wp,
		BaseSalary:         baseSal,
		Pay:                pay,
		DatePosted:         postedAt,
		URL:                origURL,
		ApplyURL:           jobURL,
		Source:             "rippling",
	}
	headerMD := FormatJobPostingHeaderMarkdown(*jp)
	return &ATSFormattedResult{
		Title:         title + " @ " + companyName,
		PublishedTime: postedAt,
		JobPosting:    jp,
		Markdown:      joinNonEmptyBlocks("# "+title+" @ "+companyName, headerMD, bodyMD),
		Links:         []string{jobURL},
	}
}
