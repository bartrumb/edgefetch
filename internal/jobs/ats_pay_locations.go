package jobs

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

var (
	reAshbySalaryCompType = newLazyRegexp(`(?i)salary|base|cash`)
	reAshbyOrgHead        = newLazyRegexp(`"organizationName"\s*:\s*"((?:\\.|[^"\\])*)"`)
	reGHJunkLoc           = newLazyRegexp(`(?i)^(?:n/a|none|null|undefined|tbd|-)$`)
	reGHMetaLocName       = newLazyRegexp(`(?i)^(?:job\s+posting\s+location|hiring\s+location|work\s+location|office\s+location|location|locations|country|countries|region)$`)
	reGHMetaPayName       = newLazyRegexp(`(?i)salary|compensation|pay|wage|remuneration|base`)

	reWorkdayHost       = newLazyRegexp(`(?i)^([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com$`)
	reLocaleSegment     = newLazyRegexp(`^[a-z]{2}(?:-[A-Za-z]{2,4})?$`)
	reWorkdaySiteIdent  = newLazyRegexp(`^[A-Za-z0-9_.-]{1,120}$`)
	reGHSlugIdent       = newLazyRegexp(`^[A-Za-z0-9_-]+$`)
	reDigitsOnly        = newLazyRegexp(`^\d+$`)
	reLeverSlugIdent    = newLazyRegexp(`^[A-Za-z0-9_.-]+$`)
	reLeverJobID        = newLazyRegexp(`(?i)^[0-9a-f-]{20,40}$`)
	reWorkableSlugIdent = newLazyRegexp(`^[A-Za-z0-9_-]{1,80}$`)
	reWorkableJobCode   = newLazyRegexp(`^[A-Za-z0-9_-]{4,24}$`)
	reRipplingJobUUID   = newLazyRegexp(`^[A-Za-z0-9_-]{6,64}$`)
)

// SalvagedAshbyBoard holds complete job objects salvaged linearly from a truncated Ashby job-board JSON payload.
type SalvagedAshbyBoard struct {
	Salvaged         bool             `json:"salvaged"`
	OrganizationName string           `json:"organizationName,omitempty"`
	Jobs             []map[string]any `json:"jobs"`
}

// SalvageAshbyBoardFromTruncatedJSON scans a truncated `posting-api/job-board/{org}` JSON response in O(N) time
// and recovers all complete job objects before truncation.
func SalvageAshbyBoardFromTruncatedJSON(raw string) *SalvagedAshbyBoard {
	jobsKeyIdx := strings.Index(raw, `"jobs"`)
	if jobsKeyIdx < 0 {
		return nil
	}
	organizationName := ""
	headSlice := raw
	if len(headSlice) > 4096 {
		headSlice = headSlice[:4096]
	}
	if m := reAshbyOrgHead.FindStringSubmatch(headSlice); len(m) >= 2 && m[1] != "" {
		var unq string
		if err := json.Unmarshal([]byte(`"`+m[1]+`"`), &unq); err == nil {
			organizationName = unq
		} else {
			organizationName = m[1]
		}
	}

	pos := jobsKeyIdx + 6
	for pos < len(raw) && (raw[pos] == ' ' || raw[pos] == '\t' || raw[pos] == '\r' || raw[pos] == '\n') {
		pos++
	}
	if pos >= len(raw) || raw[pos] != ':' {
		return nil
	}
	pos++
	for pos < len(raw) && (raw[pos] == ' ' || raw[pos] == '\t' || raw[pos] == '\r' || raw[pos] == '\n') {
		pos++
	}
	if pos >= len(raw) || raw[pos] != '[' {
		return nil
	}
	pos++

	var jobs []map[string]any
	inString := false
	escaped := false
	depth := 0
	objStart := -1

	for i := pos; i < len(raw); i++ {
		ch := raw[i]
		if inString {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			continue
		}
		switch ch {
		case '{':
			if depth == 0 {
				objStart = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && objStart >= 0 {
					if parsed, ok := SafeJSONParse(raw[objStart : i+1]).(map[string]any); ok && parsed != nil {
						jobs = append(jobs, parsed)
						if len(jobs) >= 5_000 {
							i = len(raw)
						}
					}
					objStart = -1
				}
			}
		case ']':
			if depth == 0 {
				i = len(raw)
			}
		}
	}

	if len(jobs) == 0 {
		return nil
	}
	return &SalvagedAshbyBoard{
		Salvaged:         true,
		OrganizationName: organizationName,
		Jobs:             jobs,
	}
}

func extractAshbyLocations(job map[string]any) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 4)
	pushLoc := func(raw string) {
		clean := strings.TrimSpace(raw)
		if clean == "" {
			return
		}
		key := strings.ToLower(clean)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, clean)
	}
	pushPostal := func(addrContainer any) {
		addrObj, ok := addrContainer.(map[string]any)
		if !ok || addrObj == nil {
			return
		}
		postal := addrObj
		if pa, okPa := addrObj["postalAddress"].(map[string]any); okPa && pa != nil {
			postal = pa
		}
		var parts []string
		for _, k := range []string{"addressLocality", "addressRegion", "addressCountry"} {
			if s, okS := postal[k].(string); okS && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		if len(parts) > 0 {
			pushLoc(strings.Join(parts, ", "))
		}
	}

	if loc, ok := job["location"].(string); ok {
		pushLoc(loc)
	}
	pushPostal(job["address"])

	if secArr, ok := job["secondaryLocations"].([]any); ok {
		for _, item := range secArr {
			switch s := item.(type) {
			case string:
				pushLoc(s)
			case map[string]any:
				if loc, okL := s["location"].(string); okL {
					pushLoc(loc)
				}
				pushPostal(s["address"])
			}
		}
	}
	return out
}

func parseAshbyPay(job map[string]any, descText string) *NormalizedPay {
	if comp, ok := job["compensation"].(map[string]any); ok && comp != nil {
		var components []map[string]any
		if scArr, okS := comp["summaryComponents"].([]any); okS {
			for _, it := range scArr {
				if m, okM := it.(map[string]any); okM {
					components = append(components, m)
				}
			}
		}
		if tiers, okT := comp["compensationTiers"].([]any); okT && len(tiers) > 0 {
			if firstTier, okF := tiers[0].(map[string]any); okF {
				if tcArr, okC := firstTier["components"].([]any); okC {
					for _, it := range tcArr {
						if m, okM := it.(map[string]any); okM {
							components = append(components, m)
						}
					}
				}
			}
		}
		var salaryComp map[string]any
		for _, c := range components {
			lbl := firstNonEmpty(anyString(c["compensationType"]), anyString(c["summary"]), anyString(c["title"]))
			if reAshbySalaryCompType.MatchString(lbl) {
				salaryComp = c
				break
			}
		}
		if salaryComp == nil && len(components) > 0 {
			salaryComp = components[0]
		}
		if salaryComp != nil {
			currency := "USD"
			if cc, okC := salaryComp["currencyCode"].(string); okC && cc != "" {
				currency = strings.ToUpper(cc)
			}
			period := NormalizePeriod(firstNonEmpty(anyString(salaryComp["interval"]), anyString(salaryComp["period"]), "year"))
			var rawMin, rawMax *float64
			if mv, okM := salaryComp["minValue"].(float64); okM {
				rawMin = &mv
			}
			if xv, okX := salaryComp["maxValue"].(float64); okX {
				rawMax = &xv
			}
			minVal := ScaleShorthandAnnualAmount(rawMin, period)
			maxVal := ScaleShorthandAnnualAmount(rawMax, period)
			if minVal != nil || maxVal != nil {
				effMax := maxVal
				if effMax == nil {
					effMax = minVal
				}
				tierSum, _ := comp["compensationTierSummary"].(string)
				summaryLabel := anyString(salaryComp["compensationType"]) + " " + tierSum
				return &NormalizedPay{
					Min:      minVal,
					Max:      effMax,
					Currency: currency,
					Period:   period,
					Basis:    InferPayBasis(summaryLabel),
					Raw:      tierSum,
				}
			}
		}
		if tierSum, okS := comp["compensationTierSummary"].(string); okS && tierSum != "" {
			if fromSummary := ParsePayFromText(tierSum); fromSummary != nil {
				return fromSummary
			}
		}
	}
	return ParsePayFromText(descText)
}

func extractGreenhouseLocations(job map[string]any) []string {
	out := make([]string, 0, 4)
	seen := make(map[string]bool)
	addLoc := func(raw any) {
		s, ok := raw.(string)
		if !ok || len(out) >= 12 {
			return
		}
		preDecoded := DecodeEntitiesBasic(sliceUTF16Max(s, 240))
		twice := preDecoded
		if strings.IndexByte(preDecoded, '&') >= 0 {
			twice = DecodeEntitiesBasic(preDecoded)
		}
		cleaned := SanitizeJobFieldPlain(twice, 180)
		if cleaned == "" || reGHJunkLoc.MatchString(cleaned) {
			return
		}
		key := strings.ToLower(cleaned)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, cleaned)
	}

	if locObj, ok := job["location"].(map[string]any); ok && locObj != nil {
		addLoc(locObj["name"])
	}
	if offices, ok := job["offices"].([]any); ok {
		for i := 0; i < len(offices) && i < 12; i++ {
			if off, okO := offices[i].(map[string]any); okO && off != nil {
				addLoc(off["name"])
				addLoc(off["location"])
			}
		}
	}
	if metadata, ok := job["metadata"].([]any); ok {
		for i := 0; i < len(metadata) && i < 16; i++ {
			m, okM := metadata[i].(map[string]any)
			if !okM || m == nil {
				continue
			}
			mName, _ := m["name"].(string)
			if len(mName) > 64 {
				continue
			}
			mName = strings.TrimSpace(mName)
			if !reGHMetaLocName.MatchString(mName) {
				continue
			}
			if valArr, okA := m["value"].([]any); okA {
				for j := 0; j < len(valArr) && j < 8; j++ {
					addLoc(valArr[j])
				}
			} else {
				addLoc(m["value"])
			}
		}
	}
	return out
}

func parseCentsValue(v any) *float64 {
	var raw float64
	switch x := v.(type) {
	case float64:
		raw = x
	case string:
		p, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return nil
		}
		raw = p
	default:
		return nil
	}
	if math.IsNaN(raw) || math.IsInf(raw, 0) || raw <= 0 {
		return nil
	}
	r := math.Round(raw / 100.0)
	return &r
}

func parseGreenhousePay(job map[string]any, extraProse string) *NormalizedPay {
	if payRanges, ok := job["pay_input_ranges"].([]any); ok && len(payRanges) > 0 {
		if pr, okP := payRanges[0].(map[string]any); okP && pr != nil {
			cur := "USD"
			if ct, okC := pr["currency_type"].(string); okC && strings.TrimSpace(ct) != "" {
				cur = strings.ToUpper(strings.TrimSpace(ct))
			}
			minCents := parseCentsValue(pr["min_cents"])
			maxCents := parseCentsValue(pr["max_cents"])
			if minCents != nil || maxCents != nil {
				effMin := minCents
				if effMin == nil {
					effMin = maxCents
				}
				effMax := maxCents
				if effMax == nil {
					effMax = minCents
				}
				return &NormalizedPay{
					Min:      effMin,
					Max:      effMax,
					Currency: cur,
					Period:   PayPeriodYear,
					Basis:    InferPayBasis(anyString(pr["title"]) + " " + anyString(pr["blurb"])),
				}
			}
		}
	}

	if metadata, ok := job["metadata"].([]any); ok {
		for _, item := range metadata {
			m, okM := item.(map[string]any)
			if !okM || m == nil {
				continue
			}
			mName, _ := m["name"].(string)
			if !reGHMetaPayName.MatchString(mName) {
				continue
			}
			mVal := ""
			switch mv := m["value"].(type) {
			case []any:
				parts := make([]string, 0, len(mv))
				for _, p := range mv {
					parts = append(parts, anyString(p))
				}
				mVal = strings.Join(parts, " ")
			case string:
				mVal = mv
			}
			if mVal != "" {
				if fromMeta := ParsePayFromText(mName + ": " + mVal); fromMeta != nil {
					return fromMeta
				}
			}
		}
	}

	rawContent, _ := job["content"].(string)
	plainContent := ""
	if rawContent != "" {
		decoded := DecodeEntitiesBasic(DecodeEntitiesBasic(sliceUTF16Max(rawContent, 48_000)))
		plainContent = StripTagsPlain(decoded)
	}
	combined := plainContent
	if extraProse != "" {
		combined = plainContent + " " + extraProse
	}
	if strings.TrimSpace(combined) == "" {
		return nil
	}
	return ParsePayFromText(combined)
}

func parseLeverPay(job map[string]any, extraProse string) *NormalizedPay {
	if salObj, ok := job["salaryRange"].(map[string]any); ok && salObj != nil {
		period := NormalizePeriod(firstNonEmpty(anyString(salObj["interval"]), "year"))
		rawMin := parseNumericSalField(salObj["min"])
		rawMax := parseNumericSalField(salObj["max"])
		minVal := ScaleShorthandAnnualAmount(rawMin, period)
		maxVal := ScaleShorthandAnnualAmount(rawMax, period)
		if minVal != nil || maxVal != nil {
			effMin := minVal
			if effMin == nil {
				effMin = maxVal
			}
			effMax := maxVal
			if effMax == nil {
				effMax = minVal
			}
			cur := "USD"
			if cStr, okC := salObj["currency"].(string); okC && strings.TrimSpace(cStr) != "" {
				cur = strings.ToUpper(strings.TrimSpace(cStr))
			}
			salDesc := firstNonEmpty(anyString(job["salaryDescriptionPlain"]), anyString(job["salaryDescription"]))
			return &NormalizedPay{
				Min:      effMin,
				Max:      effMax,
				Currency: cur,
				Period:   period,
				Basis:    InferPayBasis(salDesc),
			}
		}
	}

	var textChunks []string
	for _, field := range []string{"salaryDescriptionPlain", "salaryDescription", "descriptionPlain", "additionalPlain"} {
		if v, ok := job[field].(string); ok && strings.TrimSpace(v) != "" {
			textChunks = append(textChunks, StripTagsPlain(sliceUTF16Max(v, 32_000)))
		}
	}
	if lists, ok := job["lists"].([]any); ok {
		for _, it := range lists {
			if lst, okL := it.(map[string]any); okL && lst != nil {
				lText, _ := lst["text"].(string)
				lContent := ""
				if lc, okC := lst["content"].(string); okC {
					lContent = StripTagsPlain(sliceUTF16Max(lc, 16_000))
				}
				if lText != "" || lContent != "" {
					textChunks = append(textChunks, lText+" "+lContent)
				}
			}
		}
	}
	if strings.TrimSpace(anyString(job["descriptionPlain"])) == "" {
		if desc, ok := job["description"].(string); ok && desc != "" {
			textChunks = append(textChunks, StripTagsPlain(sliceUTF16Max(desc, 32_000)))
		}
	}
	if strings.TrimSpace(anyString(job["additionalPlain"])) == "" {
		if add, ok := job["additional"].(string); ok && add != "" {
			textChunks = append(textChunks, StripTagsPlain(sliceUTF16Max(add, 32_000)))
		}
	}
	if extraProse != "" {
		textChunks = append(textChunks, extraProse)
	}
	combined := strings.Join(textChunks, "\n")
	if combined == "" {
		return nil
	}
	return ParsePayFromText(combined)
}

func parseRipplingPay(item map[string]any, extraProse string) *NormalizedPay {
	payDetails := item["payRangeDetails"]
	if payDetails == nil {
		payDetails = item["payRange"]
	}
	if payDetails == nil {
		payDetails = item["compensation"]
	}
	var candidate map[string]any
	switch pd := payDetails.(type) {
	case []any:
		if len(pd) > 0 {
			candidate, _ = pd[0].(map[string]any)
		}
	case map[string]any:
		candidate = pd
	}
	if candidate != nil {
		period := NormalizePeriod(firstNonEmpty(anyString(candidate["frequency"]), anyString(candidate["interval"]), anyString(candidate["period"]), "year"))
		rawMin := parseNumericSalField(firstNonNil(candidate["min"], candidate["minValue"], candidate["minAmount"]))
		rawMax := parseNumericSalField(firstNonNil(candidate["max"], candidate["maxValue"], candidate["maxAmount"]))
		minVal := ScaleShorthandAnnualAmount(rawMin, period)
		maxVal := ScaleShorthandAnnualAmount(rawMax, period)
		if minVal != nil || maxVal != nil {
			effMin := minVal
			if effMin == nil {
				effMin = maxVal
			}
			effMax := maxVal
			if effMax == nil {
				effMax = minVal
			}
			cur := "USD"
			if c1, ok := candidate["currency"].(string); ok && strings.TrimSpace(c1) != "" {
				cur = strings.ToUpper(strings.TrimSpace(c1))
			} else if c2, ok := candidate["currencyCode"].(string); ok && strings.TrimSpace(c2) != "" {
				cur = strings.ToUpper(strings.TrimSpace(c2))
			}
			return &NormalizedPay{
				Min:      effMin,
				Max:      effMax,
				Currency: cur,
				Period:   period,
				Basis:    PayBasisBase,
			}
		}
	}
	if extraProse != "" {
		return ParsePayFromText(extraProse)
	}
	return nil
}

func firstNonNil(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}
