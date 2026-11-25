package jobs

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const maxJobPIChars = 1_572_864

var (
	reJobPostingToken    = newLazyRegexp(`(?i)JobPosting`)
	reTelecommuteToken   = newLazyRegexp(`(?i)TELECOMMUTE`)
	reSafeHTTPApplyURL   = newLazyRegexp(`(?i)^https?://[^\s<>()"` + "`" + `]+$`)
	reBoilerplateHeading = newLazyRegexp(`(?i)^(?:equal\s+(?:employment\s+)?opportunity|eeo\s+statement|accommodations?|reasonable\s+accommodation|ai\s+in\s+hiring|applicant\s+privacy|privacy\s+notice|ccpa|fair\s+chance)`)
	reBoilerplateEEO1    = newLazyRegexp(`\bequal\s+(?:employment\s+)?opportunity\s+employer\b|\bproud\s+to\s+be\s+an?\s+equal\s+opportunity\b`)
	reBoilerplateEEO2    = newLazyRegexp(`\bwithout\s+regard\s+to\s+race,\s*color,\s*religion\b|\bnational\s+origin,\s*(?:sex|gender|age|disability)\b`)
	reBoilerplateAccomm  = newLazyRegexp(`(?s)\breasonable\s+accommodations?\b.{0,120}\b(?:disabilit(?:y|ies)|qualified\s+individuals)\b`)
	reBoilerplateAI1     = newLazyRegexp(`(?s)\bartificial\s+intelligence\b.{0,140}\b(?:hiring|recruitment|application\s+process|automated\s+employment\s+decision)\b`)
	reBoilerplateAI2     = newLazyRegexp(`\bautomated\s+employment\s+decision\s+tool\b|\bnyc\s+local\s+law\s+144\b|\bcandidate\s+privacy\s+notice\b`)

	reScriptTagProbe   = newLazyRegexp(`(?i)<script\b`)
	reScriptOpenAttrs  = newLazyRegexp(`(?i)<script\b([^>]{0,600})>`)
	reScriptTypeAttr   = newLazyRegexp(`(?i)\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	reMarkdownHeading  = newLazyRegexp(`^#{1,6}\s`)
	reMarkdownInlineLk = newLazyRegexp(`\[([^\]]*)\]\([^)]+\)`)
	reMarkdownListPfx  = newLazyRegexp(`^[-*+]\s*`)

	reJSONURLHint       = newLazyRegexp(`(?i)\.json(?:$|[?#])|/api/|posting-api|/v\d+/`)
	reJSONFilterSplit   = newLazyRegexp(`\s*(?:&&|,)\s*`)
	reJSONFilterClause  = newLazyRegexp(`^([A-Za-z0-9_.-]+)\s*(!=|~=|~|=)\s*(.+)$`)
	reRegexMetachar     = newLazyRegexp(`[\\^$.*+?()[\]{}|]`)
	reHTMLTagProbeChunk = newLazyRegexp(`(?is)<[a-z].*>`)
	reHTMLEntityProbe   = newLazyRegexp(`(?i)&(?:lt|gt|amp|nbsp|#\d+);`)
)

// scanScriptBlocksQuoteAware scans `<script ...>...</script>` blocks linearly using HTML5 quote-aware tag boundaries.
func scanScriptBlocksQuoteAware(rawHTML string, visit func(attrStr, inner string)) {
	if rawHTML == "" || !reScriptTagProbe.MatchString(rawHTML) {
		return
	}
	n := len(rawHTML)
	var deadMask []uint8
	nextGtPos := -2
	i := 0
	for i < n {
		lt := strings.IndexByte(rawHTML[i:], '<')
		if lt < 0 {
			break
		}
		lt += i
		if lt+7 >= n {
			break
		}
		if lt+3 < n && rawHTML[lt+1] == '!' && rawHTML[lt+2] == '-' && rawHTML[lt+3] == '-' {
			end := findHTMLCommentEndLinear(rawHTML, lt)
			if end > lt {
				i = end
				continue
			}
			i = lt + 1
			continue
		}
		if !strings.EqualFold(rawHTML[lt+1:lt+7], "script") {
			i = lt + 1
			continue
		}
		b := rawHTML[lt+7]
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' && b != '\v' && b != '\f' && b != '/' && b != '>' {
			i = lt + 1
			continue
		}
		openGt := findQuoteAwareTagEnd(rawHTML, lt+7, &nextGtPos, &deadMask)
		if openGt < 0 {
			break
		}
		attrStr := strings.TrimSuffix(strings.TrimSpace(rawHTML[lt+7:openGt]), "/")
		// Self-closing `<script ... />` is NOT self-closing in HTML5; scan for `</script` boundary.
		closePos := findClosingScriptTag(rawHTML, openGt+1)
		if closePos.start < 0 {
			break
		}
		inner := rawHTML[openGt+1 : closePos.start]
		visit(attrStr, inner)
		i = closePos.end
	}
}

type tagSpan struct {
	start int
	end   int
}

func findClosingScriptTag(s string, from int) (res tagSpan) {
	res.start = -1
	pos := from
	for pos < len(s) {
		idx := strings.Index(s[pos:], "</")
		if idx < 0 {
			return res
		}
		cand := pos + idx
		if cand+8 < len(s) && strings.EqualFold(s[cand+2:cand+8], "script") {
			after := s[cand+8]
			if after == '>' {
				return tagSpan{start: cand, end: cand + 9}
			}
			if after == ' ' || after == '\t' || after == '\n' || after == '\r' || after == '\v' || after == '\f' || after == '/' {
				gt := strings.IndexByte(s[cand+8:], '>')
				if gt >= 0 {
					return tagSpan{start: cand, end: cand + 8 + gt + 1}
				}
				return res
			}
		}
		pos = cand + 2
	}
	return res
}

func parseJobPostingJSONLDCandidatesLinear(rawHTML string) []map[string]any {
	var candidates []map[string]any
	var collectEntities func(node any, depth int)
	collectEntities = func(node any, depth int) {
		if node == nil || depth > 16 || len(candidates) >= 64 {
			return
		}
		switch v := node.(type) {
		case []any:
			for _, item := range v {
				collectEntities(item, depth+1)
			}
		case map[string]any:
			isJob := false
			switch t := v["@type"].(type) {
			case string:
				isJob = reJobPostingToken.MatchString(t)
			case []any:
				for _, x := range t {
					if xs, ok := x.(string); ok && reJobPostingToken.MatchString(xs) {
						isJob = true
						break
					}
				}
			}
			if isJob {
				candidates = append(candidates, v)
			}
			if graph, ok := v["@graph"].([]any); ok {
				collectEntities(graph, depth+1)
			}
		}
	}

	scanScriptBlocksQuoteAware(rawHTML, func(attrStr, inner string) {
		if !extract.IsJSONLDScriptAttr(attrStr) {
			return
		}
		rawJSON := strings.TrimSpace(inner)
		if rawJSON == "" || !reJobPostingToken.MatchString(rawJSON) {
			return
		}
		parsed := SafeJSONParse(rawJSON)
		if parsed == nil && strings.IndexByte(rawJSON, '&') >= 0 {
			parsed = SafeJSONParse(DecodeEntitiesBasic(rawJSON))
		}
		collectEntities(parsed, 0)
	})

	return candidates
}

// RawJobPostingInspection holds the primary description HTML and flattened decoded strings for prompt-injection scanning.
type RawJobPostingInspection struct {
	DescriptionHTML             string `json:"descriptionHtml"`
	RawDecodedStringsForPICheck string `json:"rawDecodedStringsForPiCheck"`
}

// InspectRawJobPostingJSONLDLinear extracts entity-decoded string values from all JobPosting JSON-LD blocks
// using the same quote-aware `<script>` parser as ExtractJobPostingJSONLD, preserving Unicode Tag smuggling detection.
func InspectRawJobPostingJSONLDLinear(rawHTML string) RawJobPostingInspection {
	candidates := parseJobPostingJSONLDCandidatesLinear(rawHTML)
	sawUnicodeTag := extract.HasRawOrEncodedUnicodeTag(rawHTML)
	if len(candidates) == 0 {
		pi := ""
		if sawUnicodeTag {
			pi = "\U000E0069"
		}
		return RawJobPostingInspection{
			DescriptionHTML:             "",
			RawDecodedStringsForPICheck: pi,
		}
	}

	descriptionHTML := ""
	var chunks []string
	totalChars := 0
	visited := 0

	pushDecodedString := func(rawVal string) {
		trimmed := strings.TrimSpace(rawVal)
		if trimmed == "" {
			return
		}
		entityDecoded := trimmed
		if strings.IndexByte(trimmed, '&') >= 0 {
			entityDecoded = DecodeEntitiesBasic(trimmed)
		}
		if !sawUnicodeTag && extract.HasRawOrEncodedUnicodeTag(entityDecoded) {
			sawUnicodeTag = true
		}
		if totalChars < maxJobPIChars {
			rem := maxJobPIChars - totalChars
			sliced := sliceUTF16Max(entityDecoded, rem)
			if sliced != "" {
				chunks = append(chunks, sliced)
				totalChars += len(sliced)
			}
		}
	}

	var visitValue func(val any, depth int)
	visitValue = func(val any, depth int) {
		if val == nil || depth > 18 || visited > 100_000 {
			return
		}
		switch v := val.(type) {
		case string:
			if v == "" {
				return
			}
			visited++
			pushDecodedString(v)
		case []any:
			if len(v) == 0 {
				return
			}
			visited++
			for _, el := range v {
				if visited > 100_000 {
					break
				}
				switch el.(type) {
				case string, []any, map[string]any:
					visitValue(el, depth+1)
				}
			}
		case map[string]any:
			if len(v) == 0 {
				return
			}
			visited++
			for _, child := range v {
				if visited > 100_000 {
					break
				}
				switch child.(type) {
				case string, []any, map[string]any:
					visitValue(child, depth+1)
				}
			}
		}
	}

	for _, cand := range candidates {
		if descriptionHTML == "" {
			if desc, ok := cand["description"].(string); ok && strings.TrimSpace(desc) != "" {
				descriptionHTML = strings.TrimSpace(desc)
				pushDecodedString(descriptionHTML)
			}
		}
		visitValue(cand, 0)
	}

	if sawUnicodeTag {
		chunks = append(chunks, "\U000E0069")
	}

	return RawJobPostingInspection{
		DescriptionHTML:             descriptionHTML,
		RawDecodedStringsForPICheck: strings.Join(chunks, "\n"),
	}
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

func parseNumericSalField(v any) *float64 {
	switch x := v.(type) {
	case float64:
		if !math.IsNaN(x) && !math.IsInf(x, 0) && x > 0 {
			return &x
		}
	case string:
		cleaned := strings.NewReplacer("$", "", "£", "", "€", "", ",", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(x)
		if n, err := strconv.ParseFloat(cleaned, 64); err == nil && !math.IsNaN(n) && !math.IsInf(n, 0) && n > 0 {
			return &n
		}
	}
	return nil
}

// ExtractJobPostingJSONLD parses `<script type="application/ld+json">` blocks for `@type: JobPosting`.
func ExtractJobPostingJSONLD(rawHTML, baseURL, fallbackProse string) *StructuredJobPosting {
	candidates := parseJobPostingJSONLDCandidatesLinear(rawHTML)
	if len(candidates) == 0 {
		return nil
	}
	jp := candidates[0]

	rawTitle := anyString(jp["title"])
	if rawTitle == "" {
		rawTitle = anyString(jp["name"])
	}
	title := SanitizeJobFieldPlain(rawTitle, 512)
	if title == "" {
		return nil
	}

	hiringOrganization := ""
	switch org := jp["hiringOrganization"].(type) {
	case string:
		hiringOrganization = SanitizeJobFieldPlain(org, 256)
	case map[string]any:
		if name, ok := org["name"].(string); ok {
			hiringOrganization = SanitizeJobFieldPlain(name, 256)
		}
	}

	var locations []string
	var rawLocs []any
	if arr, ok := jp["jobLocation"].([]any); ok {
		rawLocs = arr
	} else if jp["jobLocation"] != nil {
		rawLocs = []any{jp["jobLocation"]}
	}
	for _, loc := range rawLocs {
		switch lv := loc.(type) {
		case string:
			if cleanLoc := SanitizeJobFieldPlain(lv, 256); cleanLoc != "" {
				locations = append(locations, cleanLoc)
			}
		case map[string]any:
			addrAny := lv["address"]
			if addrAny == nil {
				addrAny = lv
			}
			switch addr := addrAny.(type) {
			case string:
				if cleanAddr := SanitizeJobFieldPlain(addr, 256); cleanAddr != "" {
					locations = append(locations, cleanAddr)
				}
			case map[string]any:
				var parts []string
				for _, k := range []string{"addressLocality", "addressRegion", "addressCountry"} {
					var part string
					switch pv := addr[k].(type) {
					case string:
						part = SanitizeJobFieldPlain(pv, 128)
					case map[string]any:
						if nm, ok := pv["name"].(string); ok {
							part = SanitizeJobFieldPlain(nm, 128)
						}
					}
					if part != "" {
						parts = append(parts, part)
					}
				}
				if len(parts) > 0 {
					locations = append(locations, strings.Join(parts, ", "))
				}
			}
		}
	}

	jobLocationType := ""
	if jlt, ok := jp["jobLocationType"].(string); ok {
		jobLocationType = SanitizeJobFieldPlain(jlt, 128)
	}

	htmlHead := sliceUTF16Max(rawHTML, 120_000)
	pagePlainWindow := StripTagsPlain(htmlHead) + " " + fallbackProse
	wpFieldStr, _ := jp["workplaceType"].(string)
	explicitWorkplace := ResolveExplicitWorkplaceType(wpFieldStr, rawHTML, pagePlainWindow)

	if (explicitWorkplace == "" || explicitWorkplace == WorkplaceRemote) &&
		jobLocationType != "" &&
		reTelecommuteToken.MatchString(jobLocationType) &&
		len(locations) == 0 {
		appReqName := ""
		if appReq, ok := jp["applicantLocationRequirements"].(map[string]any); ok {
			if nm, ok := appReq["name"].(string); ok {
				appReqName = SanitizeJobFieldPlain(nm, 128)
			}
		}
		if appReqName != "" {
			locations = append(locations, "Remote ("+appReqName+")")
		} else {
			locations = append(locations, "Remote")
		}
	}

	var structuredPay *NormalizedPay
	rawSal := jp["baseSalary"]
	if rawSal == nil {
		if estArr, ok := jp["estimatedSalary"].([]any); ok && len(estArr) > 0 {
			rawSal = estArr[0]
		} else {
			rawSal = jp["estimatedSalary"]
		}
	}

	switch sal := rawSal.(type) {
	case string:
		structuredPay = ParsePayFromText(sal)
	case float64:
		if !math.IsNaN(sal) && !math.IsInf(sal, 0) && sal > 0 {
			if scaled := ScaleShorthandAnnualAmount(&sal, PayPeriodYear); scaled != nil {
				structuredPay = &NormalizedPay{
					Min:      scaled,
					Max:      scaled,
					Currency: "USD",
					Period:   PayPeriodYear,
					Basis:    PayBasisBase,
				}
			}
		}
	case map[string]any:
		curRaw, _ := sal["currency"].(string)
		if curRaw == "" {
			curRaw, _ = sal["priceCurrency"].(string)
		}
		currency := SanitizeISOCurrencyCode(curRaw, "USD")
		var minVal, maxVal *float64
		unitText := ""
		switch vo := sal["value"].(type) {
		case float64:
			minVal = &vo
			maxVal = &vo
		case string:
			parsedRange := ParsePayFromText(vo)
			if parsedRange == nil {
				parsedRange = ParsePayFromText(currency + " " + vo)
			}
			if parsedRange != nil {
				minVal = parsedRange.Min
				maxVal = parsedRange.Max
			} else if single := parseNumericSalField(vo); single != nil {
				minVal = single
				maxVal = single
			}
		case map[string]any:
			mv := vo["minValue"]
			if mv == nil {
				mv = vo["value"]
			}
			xv := vo["maxValue"]
			if xv == nil {
				xv = vo["value"]
			}
			minVal = parseNumericSalField(mv)
			maxVal = parseNumericSalField(xv)
			if ut, ok := vo["unitText"].(string); ok {
				unitText = ut
			}
		}
		if minVal == nil && maxVal == nil {
			minVal = parseNumericSalField(sal["minValue"])
			maxVal = parseNumericSalField(sal["maxValue"])
		}
		if unitText == "" {
			unitText, _ = sal["unitText"].(string)
		}
		period := NormalizePeriod(unitText)
		minVal = ScaleShorthandAnnualAmount(minVal, period)
		maxVal = ScaleShorthandAnnualAmount(maxVal, period)
		if minVal != nil || maxVal != nil {
			effMin := minVal
			if effMin == nil {
				effMin = maxVal
			}
			effMax := maxVal
			if effMax == nil {
				effMax = minVal
			}
			structuredPay = &NormalizedPay{
				Min:      effMin,
				Max:      effMax,
				Currency: currency,
				Period:   period,
				Basis:    PayBasisBase,
			}
		}
	}

	descHTML, _ := jp["description"].(string)
	proseForPay := StripTagsPlain(descHTML) + " " + fallbackProse
	prosePay := ParsePayFromText(proseForPay)

	finalPay := structuredPay
	if finalPay == nil {
		finalPay = prosePay
	} else if prosePay != nil && prosePay.Basis != PayBasisBase &&
		equalOptFloat(prosePay.Min, structuredPay.Min) && equalOptFloat(prosePay.Max, structuredPay.Max) {
		copied := *structuredPay
		copied.Basis = prosePay.Basis
		finalPay = &copied
	}

	wpText := strings.Join([]string{jobLocationType, strings.Join(locations, " "), title}, " ")
	var workplaceType WorkplaceType
	if explicitWorkplace != "" {
		workplaceType = explicitWorkplace
	} else if jobLocationType != "" && reTelecommuteToken.MatchString(jobLocationType) {
		if strings.Contains(strings.ToLower(wpText), "hybrid") {
			workplaceType = WorkplaceHybrid
		} else {
			workplaceType = WorkplaceRemote
		}
	} else {
		workplaceType = InferWorkplaceType(wpText)
	}

	rawEmpStr := ""
	switch er := jp["employmentType"].(type) {
	case []any:
		parts := make([]string, 0, len(er))
		for _, item := range er {
			parts = append(parts, fmt.Sprint(item))
		}
		rawEmpStr = strings.Join(parts, ", ")
	case string:
		rawEmpStr = er
	}
	employmentType := ""
	if rawEmpStr != "" {
		employmentType = SanitizeJobFieldPlain(rawEmpStr, 160)
	}

	datePosted := ""
	if dp, ok := jp["datePosted"].(string); ok {
		datePosted = SanitizeJobFieldPlain(dp, 64)
	}
	validThrough := ""
	if vt, ok := jp["validThrough"].(string); ok {
		validThrough = SanitizeJobFieldPlain(vt, 64)
	}

	rawJpURL := ""
	if u, ok := jp["url"].(string); ok {
		rawJpURL = strings.TrimSpace(StripInvisibleJobChars(u))
	}
	applyURL := baseURL
	if len(rawJpURL) <= 2048 && reSafeHTTPApplyURL.MatchString(rawJpURL) {
		applyURL = rawJpURL
	}

	if finalPay != nil && finalPay.Raw != "" {
		copied := *finalPay
		copied.Raw = SanitizeJobFieldPlain(copied.Raw, 160)
		finalPay = &copied
	}

	var baseSalary *NormalizedPay
	if finalPay != nil && finalPay.Basis == PayBasisBase {
		baseSalary = finalPay
	} else {
		baseSalary = structuredPay
	}

	return &StructuredJobPosting{
		Title:              title,
		HiringOrganization: hiringOrganization,
		JobLocation:        locations,
		JobLocationType:    jobLocationType,
		WorkplaceType:      workplaceType,
		BaseSalary:         baseSalary,
		Pay:                finalPay,
		DatePosted:         datePosted,
		ValidThrough:       validThrough,
		EmploymentType:     employmentType,
		URL:                baseURL,
		ApplyURL:           applyURL,
		Source:             "json-ld",
	}
}

func equalOptFloat(a, b *float64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// FormatJobPostingHeaderMarkdown formats a crisp top-of-document Markdown summary block for a StructuredJobPosting.
func FormatJobPostingHeaderMarkdown(jp StructuredJobPosting) string {
	var bullets []string
	if jp.HiringOrganization != "" {
		bullets = append(bullets, "- **Company**: "+jp.HiringOrganization)
	}
	if len(jp.JobLocation) > 0 {
		bullets = append(bullets, "- **Location**: "+strings.Join(jp.JobLocation, "; "))
	}
	if jp.WorkplaceType != "" && jp.WorkplaceType != WorkplaceUnknown {
		bullets = append(bullets, "- **Workplace**: "+string(jp.WorkplaceType))
	}
	if jp.Pay != nil {
		if formatted := FormatNormalizedPay(jp.Pay); formatted != "" {
			bullets = append(bullets, "- **Compensation**: "+formatted)
		}
	}
	if jp.EmploymentType != "" {
		bullets = append(bullets, "- **Employment Type**: "+jp.EmploymentType)
	}
	if jp.DatePosted != "" {
		dp := jp.DatePosted
		if len(dp) > 10 {
			dp = dp[:10]
		}
		bullets = append(bullets, "- **Posted**: "+dp)
	}
	if jp.ApplyURL != "" {
		bullets = append(bullets, "- **Apply URL**: "+jp.ApplyURL)
	}
	return strings.Join(bullets, "\n")
}

// IsJobLegalBoilerplateChunk detects EEO, disability accommodations, AI-in-hiring, and privacy boilerplate chunks.
func IsJobLegalBoilerplateChunk(text, heading string) bool {
	if reBoilerplateHeading.MatchString(strings.TrimSpace(heading)) {
		return true
	}
	combined := strings.ToLower(heading + "\n" + text)
	signals := 0
	if reBoilerplateEEO1.MatchString(combined) {
		signals += 2
	}
	if reBoilerplateEEO2.MatchString(combined) {
		signals += 2
	}
	if reBoilerplateAccomm.MatchString(combined) {
		signals += 2
	}
	if reBoilerplateAI1.MatchString(combined) {
		signals += 2
	}
	if reBoilerplateAI2.MatchString(combined) {
		signals += 2
	}
	return signals >= 2
}

// DetectWorkdayRedirectStub detects Workday's `{"widget":"redirect","url":"/Workday","externalSpa":true}` stub response.
func DetectWorkdayRedirectStub(rawBody, baseURL string) (string, bool) {
	parsed, ok := SafeJSONParse(rawBody).(map[string]any)
	if !ok || parsed == nil {
		return "", false
	}
	w, _ := parsed["widget"].(string)
	uStr, _ := parsed["url"].(string)
	uStr = strings.TrimSpace(uStr)
	if w != "redirect" || uStr == "" {
		return "", false
	}
	base, okBase := parseStrictURL(baseURL)
	if !okBase {
		return "", false
	}
	ref, err := url.Parse(uStr)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme == "" || resolved.Host == "" {
		return "", false
	}
	return resolved.String(), true
}

// HasExecutableScriptTag returns true only when rawHTML contains at least one executable `<script>` tag.
func HasExecutableScriptTag(rawHTML string) bool {
	if !reScriptTagProbe.MatchString(rawHTML) {
		return false
	}
	matches := reScriptOpenAttrs.FindAllStringSubmatch(rawHTML, -1)
	for _, m := range matches {
		attrs := ""
		if len(m) >= 2 {
			attrs = m[1]
		}
		tVal := ""
		if tm := reScriptTypeAttr.FindStringSubmatch(attrs); len(tm) >= 4 {
			tVal = strings.ToLower(strings.TrimSpace(firstNonEmpty(tm[1], tm[2], tm[3])))
		}
		if tVal == "application/ld+json" ||
			tVal == "application/json" ||
			tVal == "text/plain" ||
			tVal == "text/template" ||
			tVal == "text/x-template" ||
			strings.HasPrefix(tVal, "math/tex") {
			continue
		}
		return true
	}
	return false
}

func countUnicodeWords(s string) int {
	count := 0
	inWord := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' {
			if !inWord {
				count++
				inWord = true
			}
		} else {
			inWord = false
		}
	}
	return count
}

// IsThinScriptedPage determines whether a `<script>`-bearing HTML page yielded a thin/filter-only shell (`< 80` words or `> 60%` nav/link lines).
func IsThinScriptedPage(rawHTML, extractedMarkdown string) bool {
	if !HasExecutableScriptTag(rawHTML) {
		return false
	}
	trimmed := strings.TrimSpace(extractedMarkdown)
	if countUnicodeWords(trimmed) < 80 {
		return true
	}
	rawLines := strings.Split(trimmed, "\n")
	var lines []string
	for _, rl := range rawLines {
		l := strings.TrimSpace(rl)
		if l != "" && !reMarkdownHeading.MatchString(l) {
			lines = append(lines, l)
		}
	}
	if len(lines) >= 6 {
		navOrLinkLines := 0
		for _, ln := range lines {
			withoutLinks := strings.TrimSpace(reMarkdownListPfx.ReplaceAllString(reMarkdownInlineLk.ReplaceAllString(ln, ""), ""))
			lineWords := countUnicodeWords(ln)
			if len(withoutLinks) <= 4 || lineWords <= 3 {
				navOrLinkLines++
			}
		}
		if float64(navOrLinkLines)/float64(len(lines)) > 0.6 {
			return true
		}
	}
	return false
}

// JSONRecordChunk represents a single self-contained record chunk produced by ChunkJSONRecords.
