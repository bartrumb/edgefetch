package jobs

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	rePayBasisTotal = newLazyRegexp(`\b(?:total\s+target\s+cash|total\s+cash|total\s+comp(?:ensation)?|total\s+rewards|annual\s+total|base\s*\+\s*(?:bonus|variable|equity)|ttc\b|target\s+cash)\b`)
	rePayBasisOTE   = newLazyRegexp(`\b(?:ote|on[- ]target\s+earnings|target\s+commission|base\s*\+\s*commission|variable\s+target)\b`)

	rePeriodHour  = newLazyRegexp(`hour|hr|hourly`)
	rePeriodDay   = newLazyRegexp(`day|daily`)
	rePeriodWeek  = newLazyRegexp(`week|wk|weekly`)
	rePeriodMonth = newLazyRegexp(`month|mo|monthly`)

	rePayRangeGo = newLazyRegexp(`(?i)(?:(USD|CAD|EUR|GBP|AUD|CHF)[ \t]{0,4})?(?:([\$£€])[ \t]{0,4})?(\d{1,3}(?:,\d{3}){1,3}(?:\.\d{1,2})?|\d{2,7}(?:\.\d{1,2})?)(?:[ \t]{0,2}([kK]))?[ \t]{0,6}(?:[-–—]|to)[ \t]{0,6}(?:(USD|CAD|EUR|GBP|AUD|CHF)[ \t]{0,4})?(?:([\$£€])[ \t]{0,4})?(\d{1,3}(?:,\d{3}){1,3}(?:\.\d{1,2})?|\d{2,7}(?:\.\d{1,2})?)(?:[ \t]{0,2}([kK]))?(?:[ \t]{0,4}(USD|CAD|EUR|GBP|AUD|CHF)\b)?`)

	reForeignBeforeNear = newLazyRegexp(`(?i)(?:[₹¥₩₪₫₱฿₴₦₲₵₡₸₺₽]|(?:R|S|HK|NT|NZ|MX|A|C)\$|\b(?:INR|JPY|CNY|RMB|KRW|BRL|MXN|PLN|SEK|NOK|DKK|CZK|HUF|RON|TRY|ILS|ZAR|SGD|HKD|TWD|NZD|PHP|THB|IDR|MYR|VND|AED|SAR|COP|CLP|ARS|PEN|UAH|PKR|BDT|NGN|EGP|ZIP(?:\s+CODE)?))[ \t:]*$`)
	reForeignAfterNear  = newLazyRegexp(`(?i)^[ \t]*(?:[₹¥₩₪₫₱฿₴₦₲₵₡₸₺₽]|\b(?:INR|JPY|CNY|RMB|KRW|BRL|MXN|PLN|SEK|NOK|DKK|CZK|HUF|RON|TRY|ILS|ZAR|SGD|HKD|TWD|NZD|PHP|THB|IDR|MYR|VND|AED|SAR|COP|CLP|ARS|PEN|UAH|PKR|BDT|NGN|EGP))\b`)
	reCompKeyword       = newLazyRegexp(`(?i)\b(?:compensation|base\s+salary|salary|pay\s+(?:range|rate|band|scale|offered|for)|base\s+(?:pay|range)|hourly\s+(?:rate|wage)|annual\s+base|target\s+cash|remuneration)\b`)
	reNonMonetaryAfter  = newLazyRegexp(`(?i)^\s*(?:%|percent\b|years?\b|yrs?\b|months?\b|mos?\b|weeks?\b|days?\b|hours?\b|hrs?\b|employees?\b|people\b|users?\b|customers?\b|clients?\b|members?\b|seats?\b|locations?\b|offices?\b|stores?\b|countries\b|miles?\b|km\b|mb\b|gb\b|tb\b|points?\b|tokens?\b|requests?\b|transactions?\b|events?\b|ops\b|rps\b|qps\b|queries\b|rsus?\b|shares?\b|options?\b|stock\b|equity\b|zip\b|codes?\b)`)
	reExplicitHourly    = newLazyRegexp(`(?i)\b(?:per\s+hour|/\s*hr|hourly)\b`)
	reExplicitMonthly   = newLazyRegexp(`(?i)\b(?:per\s+month|/\s*mo|monthly)\b`)
	reExplicitAnnual    = newLazyRegexp(`(?i)\b(?:annually|annual|per\s+(?:year|annum|month)|/\s*(?:yr|year|mo|month)|monthly|a\s+year)\b`)
	reCommaThousands    = newLazyRegexp(`^\d{1,3}(?:,\d{3}){1,2}(?:\.\d{2})?$`)
	reHourlyFormatted   = newLazyRegexp(`^\d{2,3}(?:\.\d{2})?$`)
	reFundingValuation  = newLazyRegexp(`(?i)\b(?:arr|mrr|funding|raised|valuation|series\s+[a-f]|revenue)\b`)

	reCtxGBP = newLazyRegexp(`(?i)\b(?:gbp|pounds?\s+sterling)\b`)
	reCtxEUR = newLazyRegexp(`(?i)\beuros?\b`)
	reCtxCAD = newLazyRegexp(`(?i)\bcad\b`)
	reCtxAUD = newLazyRegexp(`(?i)\baud\b`)
	reCtxCHF = newLazyRegexp(`(?i)\bchf\b`)

	reWpHybrid = newLazyRegexp(`\bhybrid\b`)
	reWpRemote = newLazyRegexp(`\b(?:remote|telecommute|work\s+from\s+anywhere|distributed)\b`)
	reWpOnsite = newLazyRegexp(`\b(?:on[- ]?site|in[- ]?office|in[- ]?person)\b`)

	reExplicitWpHybrid = newLazyRegexp(`(?i)^hybrid$|\bhybrid\b`)
	reExplicitWpOnsite = newLazyRegexp(`(?i)^(?:on[-_\s]?site|in[-_\s]?office|in[-_\s]?person)$|\bon[-_\s]?site\b|\bin[-_\s]?office\b`)
	reExplicitWpRemote = newLazyRegexp(`(?i)^remote$|\bremote\b`)
	reAshbyEmbeddedWp  = newLazyRegexp(`(?i)"workplaceType"\s*:\s*"(Hybrid|OnSite|On-site|Remote)"`)
	reProseLabelWp     = newLazyRegexp(`(?i)(?:Location|Workplace)\s*Type\s*[:\n\r\t-]+\s*(Hybrid|On[-_\s]?site|In[-_\s]?office|Remote)\b`)
	reVagueWorkdayLoc  = newLazyRegexp(`(?i)^(?:locations?|multiple(?:\s+locations?)?|various|flexible|global|worldwide|anywhere|tbd|n/a|\d+\s+locations?)$`)

	reWorkdayISODate    = newLazyRegexp(`^(\d{4}-\d{2}-\d{2})(?:$|T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?$)`)
	reWorkdayPostedTdy  = newLazyRegexp(`(?i)^posted\s+today\b`)
	reWorkdayPostedYest = newLazyRegexp(`(?i)^posted\s+yesterday\b`)
	reWorkdayPostedDays = newLazyRegexp(`(?i)^posted\s+(\d+)(\+)?\s+days?\s+ago\b`)
	reWorkdayPostedPfx  = newLazyRegexp(`(?i)^posted\s+`)
)

// InferPayBasis classifies compensation basis (`base` vs `ote` vs `total`) from surrounding prose context.
func InferPayBasis(labelOrContext string) PayBasis {
	lower := strings.ToLower(labelOrContext)
	if rePayBasisTotal.MatchString(lower) {
		return PayBasisTotal
	}
	if rePayBasisOTE.MatchString(lower) {
		return PayBasisOTE
	}
	return PayBasisBase
}

// NormalizePeriod maps raw compensation period strings to `hour`, `day`, `week`, `month`, or `year`.
func NormalizePeriod(rawPeriod string) PayPeriod {
	s := strings.ToLower(strings.TrimSpace(rawPeriod))
	if rePeriodHour.MatchString(s) {
		return PayPeriodHour
	}
	if rePeriodDay.MatchString(s) {
		return PayPeriodDay
	}
	if rePeriodWeek.MatchString(s) {
		return PayPeriodWeek
	}
	if rePeriodMonth.MatchString(s) {
		return PayPeriodMonth
	}
	return PayPeriodYear
}

// ScaleShorthandAnnualAmount expands Ashby/shorthand annual thousands (`230` -> `230000`) when period == `year`.
func ScaleShorthandAnnualAmount(val *float64, period PayPeriod) *float64 {
	if val == nil || math.IsNaN(*val) || math.IsInf(*val, 0) || *val <= 0 {
		return nil
	}
	v := *val
	if period == PayPeriodYear && v >= 25 && v < 1_000 {
		r := math.Round(v * 1_000)
		return &r
	}
	r := math.Round(v)
	return &r
}

func formatNumberCommas(n float64) string {
	rounded := int64(math.Round(n))
	neg := rounded < 0
	if neg {
		rounded = -rounded
	}
	digits := strconv.FormatInt(rounded, 10)
	if len(digits) <= 3 {
		if neg {
			return "-" + digits
		}
		return digits
	}
	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	rem := len(digits) % 3
	if rem > 0 {
		sb.WriteString(digits[:rem])
	}
	for i := rem; i < len(digits); i += 3 {
		if sb.Len() > 0 && !(neg && sb.Len() == 1) {
			sb.WriteByte(',')
		}
		sb.WriteString(digits[i : i+3])
	}
	return sb.String()
}

// FormatNormalizedPay formats a NormalizedPay into a crisp summary (e.g. `$230,000–$350,000 USD/year (base)`).
func FormatNormalizedPay(pay *NormalizedPay) string {
	if pay == nil || (pay.Min == nil && pay.Max == nil) {
		return ""
	}
	sym := pay.Currency + " "
	switch pay.Currency {
	case "USD":
		sym = "$"
	case "GBP":
		sym = "£"
	case "EUR":
		sym = "€"
	}
	fmtAmt := func(v float64) string {
		return sym + formatNumberCommas(v)
	}
	var rangeStr string
	if pay.Min != nil && pay.Max != nil && *pay.Min != *pay.Max {
		rangeStr = fmtAmt(*pay.Min) + "–" + fmtAmt(*pay.Max)
	} else if pay.Min != nil {
		rangeStr = fmtAmt(*pay.Min)
	} else {
		rangeStr = fmtAmt(*pay.Max)
	}
	return fmt.Sprintf("%s %s/%s (%s)", rangeStr, pay.Currency, pay.Period, pay.Basis)
}

func checkNumberBoundaries(s string, start, end int) bool {
	// Emulate `(?<!\d)(?<!\d[.,])` before `start` and `(?!(?:\d|[.,]\d))` after `end`.
	if start > 0 {
		prev := s[start-1]
		if prev >= '0' && prev <= '9' {
			return false
		}
		if (prev == '.' || prev == ',') && start >= 2 && s[start-2] >= '0' && s[start-2] <= '9' {
			return false
		}
	}
	if end < len(s) {
		next := s[end]
		if next >= '0' && next <= '9' {
			return false
		}
		if (next == '.' || next == ',') && end+1 < len(s) && s[end+1] >= '0' && s[end+1] <= '9' {
			return false
		}
	}
	return true
}

func hasDigitInSpan(s string, lo, hi int) bool {
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	for i := lo; i < hi; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func collectPayRangeCandidateWindows(s string) [][2]int {
	n := len(s)
	if n <= 256 {
		return [][2]int{{0, n}}
	}
	var wins [][2]int
	addWin := func(sepStart, sepEnd int) {
		if !hasDigitInSpan(s, sepStart-12, sepStart) || !hasDigitInSpan(s, sepEnd, sepEnd+24) {
			return
		}
		lo := max(0, sepStart-64)
		hi := min(n, sepEnd+64)
		if m := len(wins); m > 0 && lo <= wins[m-1][1] {
			if hi > wins[m-1][1] {
				wins[m-1][1] = hi
			}
			return
		}
		wins = append(wins, [2]int{lo, hi})
	}
	for i := 0; i < n; i++ {
		b := s[i]
		if b == '-' {
			addWin(i, i+1)
		} else if b == 0xe2 && i+2 < n && s[i+1] == 0x80 && (s[i+2] == 0x93 || s[i+2] == 0x94) {
			addWin(i, i+3)
			i += 2
		} else if (b|0x20) == 't' && i+1 < n && (s[i+1]|0x20) == 'o' {
			addWin(i, i+2)
		}
	}
	return wins
}

// ParsePayFromText extracts standardized NormalizedPay from prose compensation text.
func ParsePayFromText(text string) *NormalizedPay {
	if text == "" {
		return nil
	}
	bounded := sliceUTF16Max(text, 65_536)
	onceDecoded := DecodeEntitiesBasic(bounded)
	normalized := onceDecoded
	if strings.IndexByte(onceDecoded, '&') >= 0 {
		normalized = DecodeEntitiesBasic(onceDecoded)
	}
	normalized = strings.ReplaceAll(normalized, "\u00a0", " ")

	windows := collectPayRangeCandidateWindows(normalized)
	for _, win := range windows {
		pos := win[0]
		winEndBound := win[1]
		for pos < winEndBound {
			loc := rePayRangeGo.FindStringSubmatchIndex(normalized[pos:winEndBound])
			if loc == nil {
				break
			}
			mStart := pos + loc[0]
			mEnd := pos + loc[1]

			num1Start, num1End := pos+loc[6], pos+loc[7]
			num2Start, num2End := pos+loc[14], pos+loc[15]
			if !checkNumberBoundaries(normalized, num1Start, num1End) || !checkNumberBoundaries(normalized, num2Start, num2End) {
				_, w := utf8.DecodeRuneInString(normalized[mStart:])
				if w <= 0 {
					w = 1
				}
				pos = mStart + w
				continue
			}
			pos = mEnd

			sub := func(g int) string {
				s, e := loc[g*2], loc[g*2+1]
				if s < 0 || e < 0 {
					return ""
				}
				return normalized[mStart-loc[0]+s : mStart-loc[0]+e]
			}

			explicitCur := strings.ToUpper(firstNonEmpty(sub(1), sub(5), sub(9)))
			sym := firstNonEmpty(sub(2), sub(6))
			hasCurrencyMarker := explicitCur != "" || sym != ""

			winStart := max(0, mStart-90)
			winEnd := min(len(normalized), mEnd+90)
			ctxWindow := normalized[winStart:winEnd]

			num1Str := sub(3)
			num2Str := sub(7)

			if !hasCurrencyMarker {
				beforeNear := normalized[max(0, mStart-18):mStart]
				afterNear := normalized[mEnd:min(len(normalized), mEnd+18)]
				if reForeignBeforeNear.MatchString(beforeNear) || reForeignAfterNear.MatchString(afterNear) {
					continue
				}
				labelCtx := normalized[max(0, mStart-90):min(len(normalized), mEnd+60)]
				if !reCompKeyword.MatchString(labelCtx) {
					continue
				}
				afterSlice := normalized[mEnd:min(len(normalized), mEnd+32)]
				if reNonMonetaryAfter.MatchString(afterSlice) {
					continue
				}
				hasExplicitHourly := reExplicitHourly.MatchString(labelCtx)
				hasExplicitPeriodWord := hasExplicitHourly || reExplicitAnnual.MatchString(labelCtx)
				bothCommaThousands := reCommaThousands.MatchString(num1Str) && reCommaThousands.MatchString(num2Str)
				bothHourlyFormatted := hasExplicitHourly && reHourlyFormatted.MatchString(num1Str) && reHourlyFormatted.MatchString(num2Str)
				if !bothCommaThousands && !bothHourlyFormatted {
					continue
				}
				if !hasExplicitPeriodWord && !bothCommaThousands {
					continue
				}
			}

			if reFundingValuation.MatchString(ctxWindow) {
				continue
			}

			currency := explicitCur
			if currency == "" {
				switch {
				case sym == "£":
					currency = "GBP"
				case sym == "€":
					currency = "EUR"
				case !hasCurrencyMarker && reCtxGBP.MatchString(ctxWindow):
					currency = "GBP"
				case !hasCurrencyMarker && reCtxEUR.MatchString(ctxWindow):
					currency = "EUR"
				case !hasCurrencyMarker && reCtxCAD.MatchString(ctxWindow):
					currency = "CAD"
				case !hasCurrencyMarker && reCtxAUD.MatchString(ctxWindow):
					currency = "AUD"
				case !hasCurrencyMarker && reCtxCHF.MatchString(ctxWindow):
					currency = "CHF"
				default:
					currency = "USD"
				}
			}

			rawMin, err1 := strconv.ParseFloat(strings.ReplaceAll(num1Str, ",", ""), 64)
			rawMax, err2 := strconv.ParseFloat(strings.ReplaceAll(num2Str, ",", ""), 64)
			if err1 != nil || err2 != nil {
				continue
			}
			minHasK := sub(4) != ""
			maxHasK := sub(8) != "" || (minHasK && rawMax < 1_000)

			period := PayPeriodYear
			if reExplicitHourly.MatchString(ctxWindow) {
				period = PayPeriodHour
			} else if reExplicitMonthly.MatchString(ctxWindow) {
				period = PayPeriodMonth
			}

			minVal := rawMin
			if minHasK {
				minVal *= 1_000
			}
			maxVal := rawMax
			if maxHasK {
				maxVal *= 1_000
			}
			if hasCurrencyMarker {
				if scaledMin := ScaleShorthandAnnualAmount(&minVal, period); scaledMin != nil {
					minVal = *scaledMin
				}
				if scaledMax := ScaleShorthandAnnualAmount(&maxVal, period); scaledMax != nil {
					maxVal = *scaledMax
				}
			}

			if math.IsNaN(minVal) || math.IsInf(minVal, 0) || math.IsNaN(maxVal) || math.IsInf(maxVal, 0) || minVal <= 0 || maxVal < minVal {
				continue
			}
			if period == PayPeriodYear && (minVal < 25_000 || maxVal > 2_500_000) {
				continue
			}
			minMonthBound := 2_000.0
			if hasCurrencyMarker {
				minMonthBound = 1_000.0
			}
			if period == PayPeriodMonth && (minVal < minMonthBound || maxVal > 250_000) {
				continue
			}
			minHourBound, maxHourBound := 15.0, 1_000.0
			if hasCurrencyMarker {
				minHourBound, maxHourBound = 7.0, 2_000.0
			}
			if period == PayPeriodHour && (minVal < minHourBound || maxVal > maxHourBound) {
				continue
			}

			rMin := math.Round(minVal)
			rMax := math.Round(maxVal)
			return &NormalizedPay{
				Min:      &rMin,
				Max:      &rMax,
				Currency: currency,
				Period:   period,
				Basis:    InferPayBasis(ctxWindow),
				Raw:      SanitizeJobFieldPlain(normalized[mStart:mEnd], 160),
			}
		}
	}
	return nil
}

// InferWorkplaceType classifies workplace arrangement (`remote` | `hybrid` | `onsite` | `unknown`) from free text.
func InferWorkplaceType(text string) WorkplaceType {
	lower := strings.ToLower(text)
	if reWpHybrid.MatchString(lower) {
		return WorkplaceHybrid
	}
	if reWpRemote.MatchString(lower) {
		return WorkplaceRemote
	}
	if reWpOnsite.MatchString(lower) {
		return WorkplaceOnsite
	}
	return WorkplaceUnknown
}

// ResolveExplicitWorkplaceType inspects explicit fields, embedded Ashby workplaceType JSON, and prose `Location Type:` labels.
// Returns `""` when no explicit workplace type is found.
func ResolveExplicitWorkplaceType(explicitField, htmlContext, proseContext string) WorkplaceType {
	checkToken := func(val string) WorkplaceType {
		t := strings.TrimSpace(val)
		if t == "" {
			return ""
		}
		if reExplicitWpHybrid.MatchString(t) {
			return WorkplaceHybrid
		}
		if reExplicitWpOnsite.MatchString(t) {
			return WorkplaceOnsite
		}
		if reExplicitWpRemote.MatchString(t) {
			return WorkplaceRemote
		}
		return ""
	}

	if explicitField != "" {
		if direct := checkToken(explicitField); direct != "" {
			return direct
		}
	}
	if htmlContext != "" {
		sub := htmlContext
		if len(sub) > 200_000 {
			sub = sub[:200_000]
		}
		if m := reAshbyEmbeddedWp.FindStringSubmatch(sub); len(m) >= 2 {
			if parsed := checkToken(m[1]); parsed != "" {
				return parsed
			}
		}
	}
	if proseContext != "" {
		if m := reProseLabelWp.FindStringSubmatch(proseContext); len(m) >= 2 {
			if parsed := checkToken(m[1]); parsed != "" {
				return parsed
			}
		}
	}
	return ""
}

// InferWorkdayWorkplaceType resolves Workday `remoteType` + location + title, defaulting concrete non-vague locations to `onsite`.
func InferWorkdayWorkplaceType(remoteType, locText, title string) WorkplaceType {
	if explicit := ResolveExplicitWorkplaceType(remoteType, "", ""); explicit != "" {
		return explicit
	}
	if inferred := InferWorkplaceType(remoteType + " " + locText + " " + title); inferred != WorkplaceUnknown {
		return inferred
	}
	cleanLoc := strings.TrimSpace(locText)
	if cleanLoc != "" && !reVagueWorkdayLoc.MatchString(cleanLoc) {
		return WorkplaceOnsite
	}
	return WorkplaceUnknown
}

// ParseWorkdayPostedField parses Workday `postedOn` / `startDate` values into genuine ISO dates vs open-ended bucket labels (`30+ days ago`).
func ParseWorkdayPostedField(rawPostedOn string, now time.Time) (postedAt *string, postedLabel string) {
	if rawPostedOn == "" {
		return nil, ""
	}
	bounded := sliceUTF16Max(rawPostedOn, 256)
	trimmed := strings.TrimSpace(StripInvisibleJobChars(bounded))
	if trimmed == "" {
		return nil, ""
	}
	if m := reWorkdayISODate.FindStringSubmatch(trimmed); len(m) >= 2 {
		dateOnly := m[1]
		parsedDay, errDay := time.Parse("2006-01-02", dateOnly)
		if errDay == nil && parsedDay.UTC().Format("2006-01-02") == dateOnly && isValidISOTimestampOrDate(trimmed) {
			return strPtr(trimmed), ""
		}
		return nil, ""
	}
	if reWorkdayPostedTdy.MatchString(trimmed) {
		d := now.UTC().Format("2006-01-02")
		return &d, ""
	}
	if reWorkdayPostedYest.MatchString(trimmed) {
		d := now.UTC().Add(-24 * time.Hour).Format("2006-01-02")
		return &d, ""
	}
	if dm := reWorkdayPostedDays.FindStringSubmatch(trimmed); len(dm) >= 3 {
		baseDays, err := strconv.Atoi(dm[1])
		if err == nil && baseDays >= 0 {
			if dm[2] == "+" || baseDays > 365 {
				capped := min(baseDays, 3650)
				return nil, fmt.Sprintf("%d+ days ago", capped)
			}
			d := now.UTC().Add(-time.Duration(baseDays) * 24 * time.Hour).Format("2006-01-02")
			return &d, ""
		}
	}
	cleanLabel := strings.ToLower(SanitizeJobFieldPlain(reWorkdayPostedPfx.ReplaceAllString(trimmed, ""), 64))
	return nil, cleanLabel
}

// NormalizeWorkdayPostedAt returns only the authoritative ISO date string (or `""`) for a Workday `startDate`/`postedOn`.
func NormalizeWorkdayPostedAt(rawPostedOn string, now time.Time) string {
	at, _ := ParseWorkdayPostedField(rawPostedOn, now)
	if at == nil {
		return ""
	}
	return *at
}

func isValidISOTimestampOrDate(s string) bool {
	if len(s) == 10 {
		t, err := time.Parse("2006-01-02", s)
		return err == nil && t.Format("2006-01-02") == s
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04Z07:00",
		"2006-01-02T15:04-0700",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
	} {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
