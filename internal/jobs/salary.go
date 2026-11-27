package jobs

// Salary aggregation over employer-posted ATS pay ranges.
//
// Pipeline: StructuredJobRecord -> SalaryObservationFromJob (plausibility gate, annualization,
// title/location/company normalization) -> hub persists one observation per posting URL ->
// AggregateSalaries (URL dedupe, age/family/seniority/location/company filters, single-currency
// and single-basis selection, cross-location cluster collapse, type-7 percentiles, Markdown).
//
// Everything here is deterministic, allocation-bounded, regex-free, and linear in its input size
// so it runs unchanged inside cmd/edgefetch-wasm (GOOS=wasip1).

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Annualization multipliers (standard full-time conventions).
const (
	HoursPerYear  = 2080 // 40h x 52w
	DaysPerYear   = 260  // 5d x 52w
	WeeksPerYear  = 52
	MonthsPerYear = 12

	salaryMinAnnualFloor   = 1_000     // annualized values below this (x currency scale) are rejected
	salaryMaxAnnualCeiling = 5_000_000 // annualized values above this (x currency scale) are rejected
	salaryMinHourly        = 1         // hourly values below this (x currency scale) are rejected

	salaryDefaultMaxAgeDays = 180
	salaryMaxTitleBytes     = 300
	salaryMaxLocationBytes  = 256
	salarySampleSize        = 10
	salaryTopN              = 10
	salaryThinThreshold     = 5
	salaryBasisMinBase      = 3
)

// SeniorityUnspecified is the seniority assigned when a title carries no level signal.
const SeniorityUnspecified = "unspecified"

// LocationUnknown is the bucket assigned when a location cannot be normalized confidently.
const LocationUnknown = "unknown"

// SalaryObservation is one employer-posted pay range, normalized and annualized. URL is the dedupe key.
type SalaryObservation struct {
	URL            string        `json:"url"`
	TitleRaw       string        `json:"titleRaw"`
	TitleFamily    string        `json:"titleFamily"`
	Seniority      string        `json:"seniority"`
	CompanyKey     string        `json:"companyKey"`
	Company        string        `json:"company"`
	LocationRaw    string        `json:"locationRaw,omitempty"`
	LocationBucket string        `json:"locationBucket"`
	Country        string        `json:"country,omitempty"`
	WorkplaceType  WorkplaceType `json:"workplaceType"`
	Currency       string        `json:"currency"`
	Period         PayPeriod     `json:"period"`
	Basis          PayBasis      `json:"basis"`
	Min            float64       `json:"min"`
	Max            float64       `json:"max"`
	MinAnnual      float64       `json:"minAnnual"`
	MaxAnnual      float64       `json:"maxAnnual"`
	PostedAt       string        `json:"postedAt,omitempty"`
	Source         string        `json:"source"`
	SeenAt         int64         `json:"seenAt"`
}

// AnnualizationFactor returns the multiplier that converts an amount in period p to a yearly amount (0 = unknown).
func AnnualizationFactor(p PayPeriod) float64 {
	switch p {
	case PayPeriodYear:
		return 1
	case PayPeriodMonth:
		return MonthsPerYear
	case PayPeriodWeek:
		return WeeksPerYear
	case PayPeriodDay:
		return DaysPerYear
	case PayPeriodHour:
		return HoursPerYear
	}
	return 0
}

// salaryCurrencyScale widens plausibility bounds for low-denomination currencies so that, e.g., a
// JPY 8,000,000 or KRW 70,000,000 salary is not rejected by the 5,000,000 ceiling. Unlisted = 1.
var salaryCurrencyScale = map[string]float64{
	"ZAR": 10, "MXN": 10, "SEK": 10, "NOK": 10, "DKK": 10, "CNY": 10, "HKD": 10, "CZK": 10,
	"TRY": 10, "EGP": 10, "MAD": 10, "UAH": 10, "BRL": 10, "PLN": 10, "ILS": 10,
	"INR": 100, "PHP": 100, "THB": 100, "RUB": 100, "TWD": 100, "PKR": 100, "KES": 100,
	"BDT": 100, "ISK": 100, "DOP": 100,
	"JPY": 1000, "HUF": 1000, "CLP": 1000, "NGN": 1000, "KZT": 1000, "LKR": 1000, "ARS": 1000,
	"KRW": 10000, "IDR": 10000, "VND": 10000, "COP": 10000, "IRR": 10000, "UZS": 10000, "PYG": 10000,
}

func isISO4217Shape(c string) bool {
	if len(c) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if c[i] < 'A' || c[i] > 'Z' {
			return false
		}
	}
	return true
}

func finitePositive(p *float64) (float64, bool) {
	if p == nil || math.IsNaN(*p) || math.IsInf(*p, 0) || *p <= 0 {
		return 0, false
	}
	return *p, true
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// SalaryObservationFromJob converts a normalized job record into a salary observation. It returns false
// when pay is missing or implausible: no positive finite bound, non-ISO currency, unknown period, empty
// URL or title family, hourly < 1, annualized min < 1,000 or annualized max > 5,000,000 (bounds are
// multiplied by salaryCurrencyScale for low-denomination currencies). A single bound is used for both
// ends; min > max is swapped.
func SalaryObservationFromJob(rec StructuredJobRecord, seenAtMs int64) (SalaryObservation, bool) {
	var zero SalaryObservation
	if rec.Pay == nil {
		return zero, false
	}
	urlKey := canonicalSalaryURL(rec.URL)
	if urlKey == "" {
		return zero, false
	}
	lo, okLo := finitePositive(rec.Pay.Min)
	hi, okHi := finitePositive(rec.Pay.Max)
	switch {
	case !okLo && !okHi:
		return zero, false
	case !okLo:
		lo = hi
	case !okHi:
		hi = lo
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	cur := strings.ToUpper(strings.TrimSpace(StripInvisibleJobChars(rec.Pay.Currency)))
	if !isISO4217Shape(cur) {
		return zero, false
	}
	period := PayPeriod(strings.ToLower(strings.TrimSpace(string(rec.Pay.Period))))
	factor := AnnualizationFactor(period)
	if factor == 0 {
		return zero, false
	}
	scale := salaryCurrencyScale[cur]
	if scale == 0 {
		scale = 1
	}
	if period == PayPeriodHour && lo < salaryMinHourly*scale {
		return zero, false
	}
	minA, maxA := lo*factor, hi*factor
	if minA < salaryMinAnnualFloor*scale || maxA > salaryMaxAnnualCeiling*scale {
		return zero, false
	}
	title := SanitizeJobFieldPlain(rec.Title, salaryMaxTitleBytes)
	family, seniority := NormalizeTitleFamily(rec.Title)
	if family == "" {
		return zero, false
	}
	company := SanitizeJobFieldPlain(rec.Company, 200)
	bucket, country, locRaw := locationBucketForRecord(rec)
	basis := normalizeSalaryBasis(rec.Pay.Basis)
	wt := rec.WorkplaceType
	if wt == "" {
		wt = WorkplaceUnknown
	}
	posted := ""
	if rec.PostedAt != nil {
		posted = SanitizeJobFieldPlain(*rec.PostedAt, 64)
	}
	return SalaryObservation{
		URL:            urlKey,
		TitleRaw:       title,
		TitleFamily:    family,
		Seniority:      seniority,
		CompanyKey:     NormalizeCompanyKey(rec.Company),
		Company:        company,
		LocationRaw:    locRaw,
		LocationBucket: bucket,
		Country:        country,
		WorkplaceType:  wt,
		Currency:       cur,
		Period:         period,
		Basis:          basis,
		Min:            round2(lo),
		Max:            round2(hi),
		MinAnnual:      round2(minA),
		MaxAnnual:      round2(maxA),
		PostedAt:       posted,
		Source:         strings.ToLower(SanitizeJobFieldPlain(rec.Source, 64)),
		SeenAt:         seenAtMs,
	}, true
}

// SalaryObservationsFromJobs maps SalaryObservationFromJob over recs, returning accepted observations
// (never nil) and the number rejected.
func SalaryObservationsFromJobs(recs []StructuredJobRecord, seenAtMs int64) ([]SalaryObservation, int) {
	out := make([]SalaryObservation, 0, len(recs))
	rejected := 0
	for _, r := range recs {
		if o, ok := SalaryObservationFromJob(r, seenAtMs); ok {
			out = append(out, o)
		} else {
			rejected++
		}
	}
	return out, rejected
}

func normalizeSalaryBasis(b PayBasis) PayBasis {
	switch PayBasis(strings.ToLower(strings.TrimSpace(string(b)))) {
	case PayBasisTotal:
		return PayBasisTotal
	case PayBasisOTE:
		return PayBasisOTE
	}
	return PayBasisBase
}

// canonicalSalaryURL trims whitespace, drops the #fragment and a trailing slash, and lowercases scheme+host.
func canonicalSalaryURL(raw string) string {
	s := strings.TrimSpace(StripInvisibleJobChars(raw))
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")
	if s == "" || len(s) > 2048 {
		return ""
	}
	if i := strings.Index(s, "://"); i > 0 {
		rest := s[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			j = len(rest)
		}
		s = strings.ToLower(s[:i+3]+rest[:j]) + rest[j:]
	}
	return s
}

var companyLegalSuffixes = map[string]bool{
	"inc": true, "incorporated": true, "llc": true, "ltd": true, "limited": true, "corp": true,
	"corporation": true, "co": true, "company": true, "gmbh": true, "plc": true, "sa": true, "ag": true,
	"bv": true, "pty": true, "srl": true, "ab": true, "oy": true, "as": true, "lp": true, "llp": true,
}

// NormalizeCompanyKey lowercases, folds accents, keeps ASCII letters/digits as space-separated words,
// and drops trailing legal suffixes ("Acme, Inc." -> "acme").
func NormalizeCompanyKey(name string) string {
	words := salaryWords(foldSalaryText(StripInvisibleJobChars(DecodeEntitiesBasic(name)), 200))
	for len(words) > 1 && companyLegalSuffixes[words[len(words)-1]] {
		words = words[:len(words)-1]
	}
	return strings.Join(words, " ")
}

// foldSalaryText lowercases, folds common Latin accents, and caps the input at maxBytes (rune-safe).
func foldSalaryText(s string, maxBytes int) string {
	if len(s) > maxBytes {
		cut := maxBytes
		for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 {
			cut--
		}
		s = s[:cut]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		switch r {
		case 'á', 'à', 'â', 'ä', 'ã', 'å':
			r = 'a'
		case 'é', 'è', 'ê', 'ë':
			r = 'e'
		case 'í', 'ì', 'î', 'ï':
			r = 'i'
		case 'ó', 'ò', 'ô', 'ö', 'õ', 'ø':
			r = 'o'
		case 'ú', 'ù', 'û', 'ü':
			r = 'u'
		case 'ç':
			r = 'c'
		case 'ñ':
			r = 'n'
		case 'ł':
			r = 'l'
		case '–', '—', '−':
			r = '-'
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// salaryWords splits s into lowercase ASCII alphanumeric words ('+' and '#' kept for c++/c#).
func salaryWords(s string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		keep := false
		if i < len(s) {
			c := s[i]
			keep = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '#'
		}
		if keep {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	return out
}

func parseSalaryTimeMs(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

// observationRecencyMs is the later of postedAt and seenAt (a posting still live today is current data).
func observationRecencyMs(o SalaryObservation) int64 {
	p := parseSalaryTimeMs(o.PostedAt)
	if o.SeenAt > p {
		return o.SeenAt
	}
	return p
}

// ---------------------------------------------------------------------------------------------
// Percentiles
// ---------------------------------------------------------------------------------------------

// SalaryPercentile returns the p-quantile (0..1) of sorted values using linear interpolation between
// closest ranks (Hyndman-Fan type 7; numpy default, Excel PERCENTILE.INC): h = (n-1)p,
// q = x[floor(h)] + (h-floor(h)) * (x[floor(h)+1] - x[floor(h)]). Returns 0 for an empty slice.
func SalaryPercentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	h := float64(n-1) * p
	lo := int(math.Floor(h))
	if lo+1 >= n {
		return sorted[n-1]
	}
	return sorted[lo] + (h-float64(lo))*(sorted[lo+1]-sorted[lo])
}

// SalaryStats summarizes one annualized series. Values are rounded to whole currency units.
type SalaryStats struct {
	Count  int     `json:"count"`
	P10    float64 `json:"p10"`
	P25    float64 `json:"p25"`
	Median float64 `json:"median"`
	P75    float64 `json:"p75"`
	P90    float64 `json:"p90"`
	Mean   float64 `json:"mean"`
}

// ComputeSalaryStats computes type-7 percentiles and the arithmetic mean of vals (input is not mutated).
func ComputeSalaryStats(vals []float64) SalaryStats {
	if len(vals) == 0 {
		return SalaryStats{}
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	return SalaryStats{
		Count:  len(s),
		P10:    math.Round(SalaryPercentile(s, 0.10)),
		P25:    math.Round(SalaryPercentile(s, 0.25)),
		Median: math.Round(SalaryPercentile(s, 0.50)),
		P75:    math.Round(SalaryPercentile(s, 0.75)),
		P90:    math.Round(SalaryPercentile(s, 0.90)),
		Mean:   math.Round(sum / float64(len(s))),
	}
}

func medianOf(vals []float64) float64 {
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	return math.Round(SalaryPercentile(s, 0.5))
}

func formatSalaryAmount(v float64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	digits := strconv.FormatFloat(math.Round(v), 'f', 0, 64)
	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	for i, c := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			sb.WriteByte(',')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// ---------------------------------------------------------------------------------------------
// Location normalization
// ---------------------------------------------------------------------------------------------

type salaryMetro struct {
	slug    string
	country string
}

// salaryMetroAliases maps a folded city/area name to its metro slug and ISO-3166 alpha-2 country.
var salaryMetroAliases = func() map[string]salaryMetro {
	m := map[string]salaryMetro{}
	add := func(slug, country string, names ...string) {
		for _, n := range names {
			m[n] = salaryMetro{slug: slug, country: country}
		}
	}
	add("new-york", "US", "new york", "new york city", "nyc", "manhattan", "brooklyn", "greater new york", "new york metro")
	add("san-francisco", "US", "san francisco", "sf", "bay area", "sf bay area", "san francisco bay area", "oakland",
		"palo alto", "mountain view", "menlo park", "sunnyvale", "san mateo", "redwood city", "south san francisco",
		"cupertino", "san jose", "santa clara", "silicon valley")
	add("seattle", "US", "seattle", "bellevue", "redmond", "kirkland", "greater seattle area")
	add("los-angeles", "US", "los angeles", "santa monica", "culver city", "greater los angeles")
	add("boston", "US", "boston", "greater boston")
	add("austin", "US", "austin")
	add("chicago", "US", "chicago")
	add("denver", "US", "denver", "boulder")
	add("washington-dc", "US", "washington dc", "washington d c", "district of columbia")
	add("atlanta", "US", "atlanta")
	add("miami", "US", "miami")
	add("dallas", "US", "dallas", "fort worth", "plano", "dallas fort worth")
	add("houston", "US", "houston")
	add("philadelphia", "US", "philadelphia")
	add("phoenix", "US", "phoenix", "scottsdale")
	add("san-diego", "US", "san diego")
	add("portland", "US", "portland")
	add("salt-lake-city", "US", "salt lake city")
	add("minneapolis", "US", "minneapolis")
	add("detroit", "US", "detroit")
	add("pittsburgh", "US", "pittsburgh")
	add("raleigh", "US", "raleigh", "durham", "research triangle")
	add("nashville", "US", "nashville")
	add("toronto", "CA", "toronto")
	add("vancouver", "CA", "vancouver")
	add("montreal", "CA", "montreal")
	add("london", "GB", "london", "greater london", "city of london")
	add("manchester", "GB", "manchester")
	add("edinburgh", "GB", "edinburgh")
	add("dublin", "IE", "dublin")
	add("berlin", "DE", "berlin")
	add("munich", "DE", "munich", "munchen")
	add("paris", "FR", "paris")
	add("amsterdam", "NL", "amsterdam")
	add("madrid", "ES", "madrid")
	add("barcelona", "ES", "barcelona")
	add("lisbon", "PT", "lisbon", "lisboa")
	add("stockholm", "SE", "stockholm")
	add("zurich", "CH", "zurich")
	add("warsaw", "PL", "warsaw", "warszawa")
	add("krakow", "PL", "krakow")
	add("prague", "CZ", "prague", "praha")
	add("tel-aviv", "IL", "tel aviv", "tel aviv yafo")
	add("bangalore", "IN", "bangalore", "bengaluru")
	add("hyderabad", "IN", "hyderabad")
	add("mumbai", "IN", "mumbai")
	add("delhi", "IN", "delhi", "new delhi", "gurgaon", "gurugram", "noida")
	add("pune", "IN", "pune")
	add("singapore", "SG", "singapore")
	add("sydney", "AU", "sydney")
	add("melbourne", "AU", "melbourne")
	add("tokyo", "JP", "tokyo")
	add("seoul", "KR", "seoul")
	add("hong-kong", "HK", "hong kong")
	add("shanghai", "CN", "shanghai")
	add("beijing", "CN", "beijing")
	add("sao-paulo", "BR", "sao paulo")
	add("mexico-city", "MX", "mexico city", "ciudad de mexico", "cdmx")
	return m
}()

// salaryCountryNames maps folded country names/aliases to ISO-3166 alpha-2.
var salaryCountryNames = map[string]string{
	"united states": "US", "united states of america": "US", "usa": "US", "us": "US", "u s": "US", "u s a": "US", "america": "US",
	"united kingdom": "GB", "uk": "GB", "u k": "GB", "great britain": "GB", "britain": "GB", "england": "GB",
	"scotland": "GB", "wales": "GB", "northern ireland": "GB", "gb": "GB",
	"canada": "CA", "germany": "DE", "deutschland": "DE", "france": "FR", "spain": "ES", "portugal": "PT",
	"italy": "IT", "netherlands": "NL", "the netherlands": "NL", "holland": "NL", "belgium": "BE",
	"switzerland": "CH", "austria": "AT", "ireland": "IE", "poland": "PL", "sweden": "SE", "norway": "NO",
	"denmark": "DK", "finland": "FI", "czech republic": "CZ", "czechia": "CZ", "romania": "RO", "israel": "IL",
	"india": "IN", "singapore": "SG", "japan": "JP", "china": "CN", "hong kong": "HK", "south korea": "KR",
	"korea": "KR", "australia": "AU", "new zealand": "NZ", "brazil": "BR", "brasil": "BR", "mexico": "MX",
	"argentina": "AR", "colombia": "CO", "chile": "CL", "peru": "PE", "uruguay": "UY", "costa rica": "CR",
	"philippines": "PH", "vietnam": "VN", "indonesia": "ID", "malaysia": "MY", "thailand": "TH", "taiwan": "TW",
	"pakistan": "PK", "uae": "AE", "united arab emirates": "AE", "south africa": "ZA", "nigeria": "NG",
	"kenya": "KE", "egypt": "EG", "turkey": "TR", "turkiye": "TR", "ukraine": "UA", "estonia": "EE",
	"lithuania": "LT", "latvia": "LV", "greece": "GR", "hungary": "HU", "serbia": "RS",
}

// salaryUSStates holds US state names and USPS codes (including DC). Codes take precedence over
// colliding ISO country codes (CA = California, IN = Indiana, DE = Delaware) in "City, ST" forms.
var salaryUSStates = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields("al ak az ar ca co ct de fl ga hi id il in ia ks ky la me md ma mi mn ms mo mt ne nv nh nj nm ny nc nd oh ok or pa ri sc sd tn tx ut vt va wa wv wi wy dc") {
		m[s] = true
	}
	for _, s := range []string{"alabama", "alaska", "arizona", "arkansas", "california", "colorado", "connecticut",
		"delaware", "florida", "georgia", "hawaii", "idaho", "illinois", "indiana", "iowa", "kansas", "kentucky",
		"louisiana", "maine", "maryland", "massachusetts", "michigan", "minnesota", "mississippi", "missouri",
		"montana", "nebraska", "nevada", "new hampshire", "new jersey", "new mexico", "new york", "north carolina",
		"north dakota", "ohio", "oklahoma", "oregon", "pennsylvania", "rhode island", "south carolina",
		"south dakota", "tennessee", "texas", "utah", "vermont", "virginia", "washington", "west virginia",
		"wisconsin", "wyoming", "d c"} {
		m[s] = true
	}
	return m
}()

var salaryCAProvinces = map[string]bool{
	"on": true, "bc": true, "qc": true, "ab": true, "mb": true, "sk": true, "ns": true, "nb": true, "nl": true, "pe": true,
	"ontario": true, "british columbia": true, "quebec": true, "alberta": true, "manitoba": true, "saskatchewan": true,
	"nova scotia": true, "new brunswick": true,
}

// salaryISO2 is the set of ISO alpha-2 codes known to salaryCountryNames (used for trailing "City, XX").
var salaryISO2 = func() map[string]string {
	m := map[string]string{}
	for _, c := range salaryCountryNames {
		m[strings.ToLower(c)] = c
	}
	m["uk"] = "GB"
	return m
}()

// salaryRegionCountry resolves a folded location segment to an ISO2 country via country name,
// US state, Canadian province, then ISO2 code (in that order).
func salaryRegionCountry(seg string) string {
	if c, ok := salaryCountryNames[seg]; ok {
		return c
	}
	if salaryUSStates[seg] {
		return "US"
	}
	if salaryCAProvinces[seg] {
		return "CA"
	}
	if c, ok := salaryISO2[seg]; ok {
		return c
	}
	return ""
}

func isRemoteLocationWord(w string) bool {
	switch w {
	case "remote", "anywhere", "wfh", "distributed", "telecommute", "virtual":
		return true
	}
	return false
}

// salaryLocationSegments splits a folded location on , - | / ( ) [ ] : and returns each segment as
// space-joined alphanumeric words (empty segments dropped).
func salaryLocationSegments(s string) []string {
	var segs []string
	start := 0
	flush := func(end int) {
		if w := salaryWords(s[start:end]); len(w) > 0 {
			segs = append(segs, strings.Join(w, " "))
		}
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',', '-', '|', '/', '(', ')', '[', ']', ':':
			flush(i)
			start = i + 1
		}
	}
	flush(len(s))
	return segs
}

// NormalizeLocationBucket maps a free-text posting location to a deterministic bucket and ISO2 country:
//
//   - "remote" when the text says remote/anywhere/WFH/distributed (country = any region named, e.g. "Remote - US" -> US)
//   - "metro:<slug>" for a known metro alias (suburbs fold in, e.g. "Palo Alto, CA" -> metro:san-francisco) unless an
//     explicit region contradicts the metro's country ("London, ON" -> country:CA, "Vancouver, WA" -> country:US)
//   - "country:<ISO2>" when only a country, US state, Canadian province or ISO code is recognized
//   - "unknown" otherwise
//
// Only the first of several ';' / ' or ' / ' and ' / ' & ' separated locations is considered.
func NormalizeLocationBucket(loc string) (bucket, country string) {
	s := foldSalaryText(StripInvisibleJobChars(DecodeEntitiesBasic(loc)), salaryMaxLocationBytes)
	s = strings.ReplaceAll(s, ".", " ")
	for _, sep := range []string{";", " or ", " and ", " & ", "\n"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	s = strings.ReplaceAll(s, "work from home", "wfh")
	segs := salaryLocationSegments(s)
	if len(segs) == 0 {
		return LocationUnknown, ""
	}
	remote := false
	var cleaned []string
	for _, seg := range segs {
		var kept []string
		for _, w := range strings.Fields(seg) {
			switch {
			case isRemoteLocationWord(w):
				remote = true
			case w == "hybrid" || w == "onsite" || w == "office" || w == "hq" || w == "headquarters" || w == "based" || w == "only" || w == "in":
			default:
				kept = append(kept, w)
			}
		}
		if len(kept) > 0 {
			cleaned = append(cleaned, strings.Join(kept, " "))
		}
	}
	var metro salaryMetro
	metroIdx := -1
	for i, seg := range cleaned {
		if m, ok := salaryMetroAliases[seg]; ok {
			metro, metroIdx = m, i
			break
		}
	}
	// "Washington, DC" / "Washington, D.C."
	if metroIdx < 0 && len(cleaned) >= 2 && cleaned[0] == "washington" && (cleaned[1] == "dc" || cleaned[1] == "d c" || cleaned[1] == "district of columbia") {
		metro, metroIdx = salaryMetroAliases["washington dc"], 0
	}
	explicit := ""
	for i := len(cleaned) - 1; i >= 0; i-- {
		if i == metroIdx {
			continue
		}
		if c := salaryRegionCountry(cleaned[i]); c != "" {
			explicit = c
			break
		}
	}
	if remote {
		if explicit == "" && metroIdx >= 0 {
			explicit = metro.country
		}
		return "remote", explicit
	}
	if metroIdx >= 0 && (explicit == "" || explicit == metro.country) {
		return "metro:" + metro.slug, metro.country
	}
	if explicit != "" {
		return "country:" + explicit, explicit
	}
	return LocationUnknown, ""
}

// locationBucketForRecord picks the bucket for a posting: remote when WorkplaceType is remote (country from
// the first location naming one), otherwise the first location that normalizes to a non-unknown bucket.
func locationBucketForRecord(rec StructuredJobRecord) (bucket, country, raw string) {
	if len(rec.Locations) > 0 {
		raw = SanitizeJobFieldPlain(rec.Locations[0], 200)
	}
	bucket = LocationUnknown
	for i, l := range rec.Locations {
		if i >= 25 {
			break
		}
		b, c := NormalizeLocationBucket(l)
		if country == "" {
			country = c
		}
		if bucket == LocationUnknown && b != LocationUnknown {
			bucket, country = b, c
			raw = SanitizeJobFieldPlain(l, 200)
		}
	}
	if rec.WorkplaceType == WorkplaceRemote {
		bucket = "remote"
	}
	return bucket, country, raw
}

// NormalizeLocationQuery normalizes a user location query: already-bucketed values ("remote",
// "country:us", "metro:london") pass through canonicalized; free text goes through NormalizeLocationBucket.
// Empty input returns "" (no location filter).
func NormalizeLocationQuery(q string) string {
	t := strings.ToLower(strings.TrimSpace(q))
	switch {
	case t == "", t == LocationUnknown, t == "any", t == "all":
		return ""
	case t == "remote":
		return "remote"
	case strings.HasPrefix(t, "country:"):
		c := strings.ToUpper(strings.TrimSpace(t[len("country:"):]))
		if len(c) == 2 && isISO4217Shape(c+"X") {
			return "country:" + c
		}
		return LocationUnknown
	case strings.HasPrefix(t, "metro:"):
		slug := strings.Join(salaryWords(t[len("metro:"):]), "-")
		if slug == "" {
			return LocationUnknown
		}
		return "metro:" + slug
	}
	b, _ := NormalizeLocationBucket(q)
	return b
}

// ---------------------------------------------------------------------------------------------
// Title normalization
// ---------------------------------------------------------------------------------------------

// salaryLevelRank orders seniority levels; when a title carries several word levels the highest wins
// ("Senior Staff" -> staff, "Associate Director" -> director).
var salaryLevelRank = map[string]int{
	"intern": 1, "junior": 2, "mid": 3, "senior": 4, "lead": 5, "staff": 6, "principal": 7,
	"manager": 8, "senior manager": 9, "director": 10, "head": 11, "vp": 12, "executive": 13,
}

// salaryWordLevels maps a title word (after phrase folding) to a seniority level.
var salaryWordLevels = map[string]string{
	"intern": "intern", "interns": "intern", "internship": "intern", "coop": "intern", "apprentice": "intern",
	"junior": "junior", "jr": "junior", "jnr": "junior", "associate": "junior", "entry": "junior",
	"graduate": "junior", "newgrad": "junior",
	"mid": "mid", "intermediate": "mid",
	"senior": "senior", "sr": "senior", "snr": "senior",
	"lead": "lead", "staff": "staff", "principal": "principal", "distinguished": "principal",
	"seniormanager": "senior manager", "director": "director", "head": "head",
	"vp": "vp", "svp": "vp", "evp": "vp", "avp": "vp", "chief": "executive",
}

// salaryNumeralLevels maps roman numerals (anywhere in the head) and single digits (last head word only).
// Numerals only apply when no word level is present ("Sr. Software Engineer II" -> senior).
var salaryNumeralLevels = map[string]string{
	"i": "junior", "ii": "mid", "iii": "senior", "iv": "staff", "v": "principal",
}

var salaryDigitLevels = map[string]string{
	"1": "junior", "2": "mid", "3": "senior", "4": "staff", "5": "principal",
}

// salaryNoiseWords never contribute to a family (workplace, contract type, region, filler).
var salaryNoiseWords = map[string]bool{
	"remote": true, "hybrid": true, "onsite": true, "contract": true, "contractor": true, "temporary": true,
	"temp": true, "freelance": true, "fulltime": true, "parttime": true, "permanent": true, "fte": true,
	"w2": true, "us": true, "usa": true, "uk": true, "eu": true, "emea": true, "apac": true, "amer": true,
	"americas": true, "latam": true, "na": true, "global": true, "worldwide": true, "anywhere": true,
	"position": true, "role": true, "opening": true, "opportunity": true, "urgent": true, "hiring": true,
	"the": true, "req": true, "requisition": true,
}

// salaryPhraseFolds rewrites multi-word forms into single canonical words before level detection.
// Applied in order on a space-padded, space-joined word string.
var salaryPhraseFolds = [][2]string{
	{" member of technical staff ", " mts "},
	{" software development engineer in test ", " sdet "},
	{" software engineer in test ", " sdet "},
	{" software development engineer ", " software engineer "},
	{" senior vice president ", " vp "},
	{" executive vice president ", " vp "},
	{" vice president ", " vp "},
	{" head of ", " head "},
	{" senior manager ", " seniormanager "},
	{" sr manager ", " seniormanager "},
	{" new grad ", " newgrad "},
	{" new graduate ", " newgrad "},
	{" recent graduate ", " newgrad "},
	{" entry level ", " newgrad "},
	{" early career ", " newgrad "},
	{" mid senior ", " senior "},
	{" mid level ", " mid "},
	{" co op ", " coop "},
	{" working student ", " intern "},
	{" lead generation ", " leadgen "},
	{" full time ", " "},
	{" part time ", " "},
	{" on site ", " onsite "},
	{" all genders ", " "},
	{" m f d ", " "}, {" f m d ", " "}, {" m w d ", " "}, {" w m d ", " "}, {" f m x ", " "}, {" m f x ", " "}, {" h f ", " "},
	{" back end ", " backend "},
	{" front end ", " frontend "},
	{" fullstack ", " full stack "},
	{" dev ops ", " devops "},
	{" ui ux ", " ux "},
	{" ux ui ", " ux "},
	{" user experience ", " ux "},
}

// salaryFamilySynonyms maps a reduced family phrase to its canonical family.
var salaryFamilySynonyms = map[string]string{
	"swe": "software engineer", "sde": "software engineer", "software developer": "software engineer",
	"software dev": "software engineer", "developer": "software engineer", "programmer": "software engineer",
	"software programmer": "software engineer", "engineer": "software engineer", "software": "software engineer",
	"tech": "software engineer", "technical": "software engineer",
	"software engineering": "software engineer",
	"sre":                  "site reliability engineer", "site reliability": "site reliability engineer",
	"site reliability engineering": "site reliability engineer",
	"devops":                       "devops engineer",
	"pm":                           "product manager", "tpm": "technical program manager",
	"em": "engineering manager", "eng manager": "engineering manager",
	"software engineering manager": "engineering manager", "software development manager": "engineering manager",
	"sdm": "engineering manager", "software manager": "engineering manager",
	"mts": "member of technical staff", "sdet": "software engineer in test",
	"ux designer": "ux designer", "ui designer": "ux designer", "ux": "ux designer",
	"solution engineer": "solutions engineer", "solution architect": "solutions architect",
	"ae": "account executive", "sdr": "sales development representative", "bdr": "business development representative",
	"csm": "customer success manager", "mle": "machine learning engineer", "ml engineer": "machine learning engineer",
	"ai engineer": "ai engineer", "data science": "data science",
}

// salaryDevPrefixes: "<prefix> developer" and "<prefix> software engineer" fold to "<prefix> engineer".
var salaryDevPrefixes = map[string]bool{
	"backend": true, "frontend": true, "full stack": true, "web": true, "mobile": true, "ios": true,
	"android": true, "application": true, "applications": true, "game": true, "embedded": true,
}

// salaryPeopleManagerFunctions: "<function> manager" is a people-management level (seniority manager)
// rather than a functional title like "product manager" or "account manager".
var salaryPeopleManagerFunctions = map[string]bool{
	"engineering": true, "science": true, "design": true, "analytics": true, "research": true,
	"infrastructure": true, "qa": true,
}

// splitSalaryParens removes (...) [...] {...} groups (depth-tracked, linear) and returns their contents.
func splitSalaryParens(s string) (string, []string) {
	var main, cur strings.Builder
	var inner []string
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(', '[', '{':
			if depth == 0 {
				cur.Reset()
			} else {
				cur.WriteByte(' ')
			}
			depth++
			main.WriteByte(' ')
			continue
		case ')', ']', '}':
			if depth > 0 {
				depth--
				if depth == 0 {
					inner = append(inner, cur.String())
				}
				continue
			}
			main.WriteByte(' ')
			continue
		}
		if depth > 0 {
			cur.WriteByte(c)
		} else {
			main.WriteByte(c)
		}
	}
	if depth > 0 {
		inner = append(inner, cur.String())
	}
	return main.String(), inner
}

// dropSalaryReqIDs removes whitespace tokens carrying 3+ ASCII digits (requisition ids, years).
func dropSalaryReqIDs(s string) string {
	fields := strings.Fields(s)
	kept := fields[:0]
	for _, f := range fields {
		digits := 0
		for i := 0; i < len(f); i++ {
			if f[i] >= '0' && f[i] <= '9' {
				digits++
			}
		}
		if digits < 3 {
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, " ")
}

// splitSalaryTitleSegments splits on clause separators: , ; : | @ " - " and " / " (hyphens or slashes
// inside words become spaces, so "full-stack" / "ui/ux" stay in one clause).
func splitSalaryTitleSegments(s string) []string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		spacedPrev := i == 0 || s[i-1] == ' '
		spacedNext := i+1 >= len(s) || s[i+1] == ' '
		switch c {
		case ',', ';', ':', '|', '@':
			sb.WriteByte(',')
		case '-', '/':
			if spacedPrev || spacedNext {
				sb.WriteByte(',')
			} else {
				sb.WriteByte(' ')
			}
		case '.':
			sb.WriteByte(' ')
		default:
			sb.WriteByte(c)
		}
	}
	return strings.Split(sb.String(), ",")
}

// salaryTitleWords tokenizes a clause, expands abbreviations, and applies salaryPhraseFolds.
func salaryTitleWords(seg string) []string {
	words := salaryWords(seg)
	if len(words) == 0 {
		return nil
	}
	expanded := make([]string, 0, len(words)+2)
	for i, w := range words {
		last := i == len(words)-1
		switch w {
		case "mgr":
			w = "manager"
		case "eng", "engr":
			if last {
				w = "engineer"
			} else {
				w = "engineering"
			}
		case "dev":
			if last {
				w = "developer"
			}
		case "sw":
			w = "software"
		case "ml":
			expanded = append(expanded, "machine")
			w = "learning"
		}
		expanded = append(expanded, w)
	}
	joined := " " + strings.Join(expanded, " ") + " "
	for _, pf := range salaryPhraseFolds {
		if strings.Contains(joined, pf[0]) {
			joined = strings.ReplaceAll(joined, pf[0], pf[1])
		}
	}
	return strings.Fields(joined)
}

type salaryClause struct {
	rest     []string // non-level, non-noise words in order
	levels   []string // word levels
	numerals []string // numeral levels
}

func classifySalaryClause(seg string) salaryClause {
	var c salaryClause
	words := salaryTitleWords(seg)
	for i, w := range words {
		if lv, ok := salaryWordLevels[w]; ok {
			c.levels = append(c.levels, lv)
			continue
		}
		if lv, ok := salaryNumeralLevels[w]; ok {
			c.numerals = append(c.numerals, lv)
			continue
		}
		if lv, ok := salaryDigitLevels[w]; ok && i == len(words)-1 {
			c.numerals = append(c.numerals, lv)
			continue
		}
		if salaryNoiseWords[w] {
			continue
		}
		c.rest = append(c.rest, w)
	}
	return c
}

func trimSalaryConnectors(words []string) []string {
	isConn := func(w string) bool { return w == "of" || w == "for" || w == "and" || w == "to" || w == "in" }
	for len(words) > 0 && isConn(words[0]) {
		words = words[1:]
	}
	for len(words) > 0 && isConn(words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	return words
}

func canonicalSalaryFamily(words []string) string {
	words = trimSalaryConnectors(words)
	if len(words) == 0 {
		return ""
	}
	f := strings.Join(words, " ")
	if syn, ok := salaryFamilySynonyms[f]; ok {
		return syn
	}
	if strings.HasSuffix(f, " developer") {
		prefix := strings.TrimSuffix(f, " developer")
		if salaryDevPrefixes[prefix] {
			return prefix + " engineer"
		}
	}
	if strings.HasSuffix(f, " software engineer") {
		prefix := strings.TrimSuffix(f, " software engineer")
		if salaryDevPrefixes[prefix] {
			return prefix + " engineer"
		}
	}
	return f
}

// NormalizeTitleFamily reduces a posting title to a canonical (family, seniority) pair. Deterministic rules:
//
//  1. Decode entities, strip invisible runes, lowercase, fold accents, cap at 300 bytes.
//  2. Remove (...) [...] {...} groups; a group consisting only of level words still contributes its level.
//  3. Drop tokens with 3+ digits (requisition ids, years).
//  4. Split into clauses on , ; : | @ " - " " / ". The first clause with non-level words is the head; trailing
//     clauses (specializations, teams, locations) never enter the family and contribute a level only when
//     they consist solely of level words ("Software Engineer, Senior").
//  5. Level words: intern/co-op, junior/jr/associate/new grad/entry level, mid/intermediate, senior/sr, lead,
//     staff, principal/distinguished, manager, senior manager, director, head (of), vp/vice president, chief
//     (executive). Highest word level wins. Roman I..V (and a trailing 1..5) map to junior, mid, senior, staff,
//     principal and apply only when no word level is present.
//  6. Manager: "Manager, X" / "Manager of X" / "Senior Manager, X" give family "X manager" and seniority manager
//     (senior manager); "<engineering|science|design|analytics|research|infrastructure|qa> manager" is also a
//     people-management level; other "X manager" titles (product, account, ...) are functional families.
//  7. Noise words (remote, hybrid, contract, US/EMEA, ...) are dropped and the remainder maps through a small
//     synonym table (swe/software developer/engineer -> software engineer, sre -> site reliability engineer,
//     pm -> product manager when standalone, "<backend|frontend|...> developer" -> "<...> engineer").
//
// Seniority is SeniorityUnspecified when no level is found; family is "" when nothing remains.
func NormalizeTitleFamily(title string) (family string, seniority string) {
	s := foldSalaryText(StripInvisibleJobChars(DecodeEntitiesBasic(title)), salaryMaxTitleBytes)
	main, parens := splitSalaryParens(s)
	main = dropSalaryReqIDs(main)
	var levels, numerals []string
	for _, p := range parens {
		c := classifySalaryClause(dropSalaryReqIDs(p))
		if len(c.rest) == 0 {
			levels = append(levels, c.levels...)
			numerals = append(numerals, c.numerals...)
		}
	}
	var clauses []salaryClause
	for _, seg := range splitSalaryTitleSegments(main) {
		c := classifySalaryClause(seg)
		if len(c.rest) == 0 && len(c.levels) == 0 && len(c.numerals) == 0 {
			continue
		}
		clauses = append(clauses, c)
	}
	headIdx := -1
	for i, c := range clauses {
		if len(trimSalaryConnectors(c.rest)) > 0 {
			headIdx = i
			break
		}
	}
	for i, c := range clauses {
		if i == headIdx || len(c.rest) == 0 {
			levels = append(levels, c.levels...)
			numerals = append(numerals, c.numerals...)
		}
	}
	var rest []string
	if headIdx >= 0 {
		rest = trimSalaryConnectors(clauses[headIdx].rest)
	}
	managerLevel := false
	hasSeniorManager := false
	for _, lv := range levels {
		if lv == "senior manager" {
			hasSeniorManager = true
		}
	}
	if len(rest) > 0 && rest[0] == "manager" && len(rest) > 1 {
		// "Manager of Data Science" -> "data science manager"
		rest = append(trimSalaryConnectors(append([]string(nil), rest[1:]...)), "manager")
		managerLevel = true
	} else if len(rest) == 1 && rest[0] == "manager" && headIdx+1 < len(clauses) {
		// "Manager, Software Engineering"
		if next := trimSalaryConnectors(clauses[headIdx+1].rest); len(next) > 0 {
			rest = append(append([]string(nil), next...), "manager")
			managerLevel = true
		}
	}
	if hasSeniorManager && len(rest) > 0 && rest[len(rest)-1] != "manager" {
		rest = append(append([]string(nil), rest...), "manager")
	}
	family = canonicalSalaryFamily(rest)
	if strings.HasSuffix(family, " manager") {
		fw := strings.Fields(family)
		if len(fw) >= 2 && salaryPeopleManagerFunctions[fw[len(fw)-2]] {
			managerLevel = true
		}
	}
	best, bestRank := "", 0
	for _, lv := range levels {
		if r := salaryLevelRank[lv]; r > bestRank {
			best, bestRank = lv, r
		}
	}
	if managerLevel {
		if best == "senior" {
			best, bestRank = "senior manager", salaryLevelRank["senior manager"]
		} else if bestRank < salaryLevelRank["manager"] {
			best, bestRank = "manager", salaryLevelRank["manager"]
		}
	}
	if best == "" {
		for _, lv := range numerals {
			if r := salaryLevelRank[lv]; r > bestRank {
				best, bestRank = lv, r
			}
		}
	}
	if best == "" {
		best = SeniorityUnspecified
	}
	return family, best
}

var salaryQueryNoise = map[string]bool{
	"salary": true, "salaries": true, "pay": true, "paid": true, "compensation": true, "comp": true,
	"range": true, "ranges": true, "band": true, "bands": true, "jobs": true, "job": true, "roles": true,
	"positions": true, "average": true, "avg": true, "typical": true, "median": true, "what": true,
	"whats": true, "is": true, "are": true, "how": true, "much": true, "does": true, "do": true,
	"make": true, "makes": true, "earn": true, "earns": true, "a": true, "an": true,
}

// MatchTitleQuery normalizes a free-text user query ("senior swe salary in london") into the same
// (family, seniority) space as NormalizeTitleFamily: it drops salary/question filler words and anything
// after " in " / " at " / " near " (location and company are separate query fields), then normalizes.
// Seniority is "" (no filter) when the query names no level.
func MatchTitleQuery(query string) (family string, seniority string) {
	s := " " + foldSalaryText(StripInvisibleJobChars(query), salaryMaxTitleBytes) + " "
	for _, cut := range []string{" in ", " at ", " near ", " @ "} {
		if cut == " in " && strings.Contains(s, " in test ") {
			continue
		}
		if i := strings.Index(s, cut); i > 0 {
			s = s[:i]
		}
	}
	var kept []string
	for _, w := range strings.Fields(s) {
		if !salaryQueryNoise[strings.Trim(w, "?!.,'\"")] {
			kept = append(kept, w)
		}
	}
	family, seniority = NormalizeTitleFamily(strings.Join(kept, " "))
	if seniority == SeniorityUnspecified {
		seniority = ""
	}
	return family, seniority
}

// NormalizeSeniorityQuery canonicalizes a seniority filter ("Sr" -> senior, "VP" -> vp); unknown -> "".
func NormalizeSeniorityQuery(s string) string {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return ""
	}
	if t == SeniorityUnspecified {
		return t
	}
	if _, ok := salaryLevelRank[t]; ok {
		return t
	}
	if lv, ok := salaryWordLevels[strings.ReplaceAll(t, " ", "")]; ok {
		return lv
	}
	if lv, ok := salaryNumeralLevels[t]; ok {
		return lv
	}
	if t == "manager" {
		return t
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------------------------

// SalaryQuery selects observations for AggregateSalaries. Empty fields do not filter.
type SalaryQuery struct {
	TitleFamily    string `json:"titleFamily,omitempty"`
	Seniority      string `json:"seniority,omitempty"`
	LocationBucket string `json:"locationBucket,omitempty"`
	Company        string `json:"company,omitempty"`
	Currency       string `json:"currency,omitempty"`
	Basis          string `json:"basis,omitempty"`
	MaxAgeDays     int    `json:"maxAgeDays,omitempty"`
	NowMs          int64  `json:"nowMs,omitempty"`
}

// SalaryBreakdown is one group row (seniority, location bucket, or company) with its median midpoint.
type SalaryBreakdown struct {
	Key    string  `json:"key"`
	Label  string  `json:"label,omitempty"`
	Count  int     `json:"count"`
	Median float64 `json:"median"`
}

// SalarySample is one representative observation (cluster) for display.
type SalarySample struct {
	Title          string    `json:"title"`
	Company        string    `json:"company"`
	Location       string    `json:"location,omitempty"`
	LocationBucket string    `json:"locationBucket"`
	Seniority      string    `json:"seniority"`
	Currency       string    `json:"currency"`
	Period         PayPeriod `json:"period"`
	Basis          PayBasis  `json:"basis"`
	Min            float64   `json:"min"`
	Max            float64   `json:"max"`
	MinAnnual      float64   `json:"minAnnual"`
	MaxAnnual      float64   `json:"maxAnnual"`
	URL            string    `json:"url"`
	PostedAt       string    `json:"postedAt,omitempty"`
	Source         string    `json:"source,omitempty"`
	Postings       int       `json:"postings"`
}

// SalaryReport is the AggregateSalaries result. All statistics are in Currency, annualized.
type SalaryReport struct {
	Query        SalaryQuery       `json:"query"`
	Matched      int               `json:"matched"`
	Postings     int               `json:"postings"`
	Currency     string            `json:"currency"`
	Basis        string            `json:"basis"`
	Currencies   map[string]int    `json:"currencies"`
	Midpoint     SalaryStats       `json:"midpoint"`
	Min          SalaryStats       `json:"min"`
	Max          SalaryStats       `json:"max"`
	BySeniority  []SalaryBreakdown `json:"bySeniority"`
	ByLocation   []SalaryBreakdown `json:"byLocation"`
	TopCompanies []SalaryBreakdown `json:"topCompanies"`
	Sample       []SalarySample    `json:"sample"`
	Sources      map[string]int    `json:"sources"`
	Notes        []string          `json:"notes"`
	Method       string            `json:"method"`
	Markdown     string            `json:"markdown"`
}

// SalaryMethod documents the statistics and weighting rules (also embedded in every report).
const SalaryMethod = "Employer-posted ranges from official ATS boards, annualized (hour x2080, day x260, week x52, month x12). " +
	"Deduplicated by posting URL, then postings with the same company, title family, seniority, currency, basis and " +
	"annualized range are collapsed into one observation (one employer posting one band in many cities counts once). " +
	"Percentiles use linear interpolation between closest ranks (Hyndman-Fan type 7). Currencies are never mixed."

type salaryCluster struct {
	rep      SalaryObservation
	recency  int64
	postings int
	buckets  map[string]bool
}

func (c *salaryCluster) mid() float64 { return (c.rep.MinAnnual + c.rep.MaxAnnual) / 2 }

// sanitizeObservationForAggregate re-validates an observation that round-tripped through storage.
func sanitizeObservationForAggregate(o SalaryObservation) (SalaryObservation, bool) {
	o.URL = canonicalSalaryURL(o.URL)
	o.Currency = strings.ToUpper(strings.TrimSpace(o.Currency))
	if o.URL == "" || !isISO4217Shape(o.Currency) {
		return o, false
	}
	for _, v := range []float64{o.MinAnnual, o.MaxAnnual} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			return o, false
		}
	}
	if o.MinAnnual > o.MaxAnnual {
		o.MinAnnual, o.MaxAnnual = o.MaxAnnual, o.MinAnnual
		o.Min, o.Max = o.Max, o.Min
	}
	o.TitleFamily = strings.Join(strings.Fields(strings.ToLower(o.TitleFamily)), " ")
	o.Seniority = NormalizeSeniorityQuery(o.Seniority)
	if o.Seniority == "" {
		o.Seniority = SeniorityUnspecified
	}
	if o.CompanyKey == "" {
		o.CompanyKey = NormalizeCompanyKey(o.Company)
	} else {
		o.CompanyKey = NormalizeCompanyKey(o.CompanyKey)
	}
	o.LocationBucket = strings.ToLower(strings.TrimSpace(o.LocationBucket))
	if o.LocationBucket == "" {
		o.LocationBucket = LocationUnknown
	}
	o.Country = strings.ToUpper(strings.TrimSpace(o.Country))
	o.Basis = normalizeSalaryBasis(o.Basis)
	o.Source = strings.ToLower(strings.TrimSpace(o.Source))
	return o, true
}

func salaryLocationMatches(o SalaryObservation, want string) bool {
	switch {
	case want == "":
		return true
	case want == "remote":
		return o.LocationBucket == "remote"
	case strings.HasPrefix(want, "country:"):
		return o.LocationBucket == want || o.Country == strings.TrimPrefix(want, "country:")
	}
	return o.LocationBucket == want
}

func pickMostCommon(counts map[string]int) string {
	best, bestN := "", 0
	for k, n := range counts {
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

func buildSalaryBreakdown(groups map[string][]float64, labels map[string]string, limit int) []SalaryBreakdown {
	out := make([]SalaryBreakdown, 0, len(groups))
	for k, vals := range groups {
		out = append(out, SalaryBreakdown{Key: k, Label: labels[k], Count: len(vals), Median: medianOf(vals)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// AggregateSalaries computes a single-currency salary report. Order of operations:
//
//  1. Re-validate observations; dedupe by canonical URL keeping the most recently seen.
//  2. Age filter: keep observations whose max(postedAt, seenAt) is within maxAgeDays (default 180; < 0 disables)
//     of nowMs (default: the newest observation's recency, so results are deterministic).
//  3. Filter by titleFamily (normalized via NormalizeTitleFamily), seniority, locationBucket ("remote" matches
//     remote; "country:XX" matches country:XX, metros in XX and remote postings tagged XX; "metro:x" exact),
//     and company (NormalizeCompanyKey).
//  4. Currency: query value, else the most common currency among matches (ties alphabetical); other currencies
//     are only counted in Currencies and Notes.
//  5. Basis: query value (base/total/ote/all), else base when >= 3 base postings, else all.
//  6. Collapse clusters keyed (company, family, seniority, currency, basis, rounded minAnnual, rounded maxAnnual)
//     into one observation each (weight 1); statistics, breakdowns and samples are over clusters. A cluster
//     counts once in every location bucket it was posted in. Sources count postings.
func AggregateSalaries(obs []SalaryObservation, q SalaryQuery) SalaryReport {
	rep := SalaryReport{
		Currencies:   map[string]int{},
		Sources:      map[string]int{},
		BySeniority:  []SalaryBreakdown{},
		ByLocation:   []SalaryBreakdown{},
		TopCompanies: []SalaryBreakdown{},
		Sample:       []SalarySample{},
		Notes:        []string{},
		Method:       SalaryMethod,
	}
	var notes []string

	// Normalize the query.
	eq := SalaryQuery{MaxAgeDays: q.MaxAgeDays, NowMs: q.NowMs}
	if t := strings.TrimSpace(q.TitleFamily); t != "" {
		if f, _ := NormalizeTitleFamily(t); f != "" {
			eq.TitleFamily = f
		} else {
			eq.TitleFamily = strings.Join(strings.Fields(strings.ToLower(t)), " ")
		}
	}
	eq.Seniority = NormalizeSeniorityQuery(q.Seniority)
	if strings.TrimSpace(q.Seniority) != "" && eq.Seniority == "" {
		notes = append(notes, "seniority filter not recognized; showing all levels")
	}
	eq.LocationBucket = NormalizeLocationQuery(q.LocationBucket)
	if eq.LocationBucket == LocationUnknown {
		eq.LocationBucket = ""
		notes = append(notes, "location filter not recognized; showing all locations")
	}
	eq.Company = NormalizeCompanyKey(q.Company)
	if c := strings.ToUpper(strings.TrimSpace(q.Currency)); isISO4217Shape(c) {
		eq.Currency = c
	}
	switch b := strings.ToLower(strings.TrimSpace(q.Basis)); b {
	case "base", "total", "ote", "all":
		eq.Basis = b
	}
	if eq.MaxAgeDays == 0 {
		eq.MaxAgeDays = salaryDefaultMaxAgeDays
	}

	// 1. URL dedupe.
	byURL := map[string]int{}
	uniq := make([]SalaryObservation, 0, len(obs))
	for _, raw := range obs {
		o, ok := sanitizeObservationForAggregate(raw)
		if !ok {
			continue
		}
		if i, seen := byURL[o.URL]; seen {
			if o.SeenAt > uniq[i].SeenAt {
				uniq[i] = o
			}
			continue
		}
		byURL[o.URL] = len(uniq)
		uniq = append(uniq, o)
	}

	// 2. Age filter.
	if eq.NowMs <= 0 {
		for _, o := range uniq {
			if r := observationRecencyMs(o); r > eq.NowMs {
				eq.NowMs = r
			}
		}
	}
	stale := 0
	fresh := uniq[:0:0]
	for _, o := range uniq {
		if eq.MaxAgeDays > 0 && eq.NowMs > 0 {
			cutoff := eq.NowMs - int64(eq.MaxAgeDays)*86_400_000
			if observationRecencyMs(o) < cutoff {
				stale++
				continue
			}
		}
		fresh = append(fresh, o)
	}

	// 3. Filters.
	var matched []SalaryObservation
	for _, o := range fresh {
		if eq.TitleFamily != "" && o.TitleFamily != eq.TitleFamily {
			continue
		}
		if eq.Seniority != "" && o.Seniority != eq.Seniority {
			continue
		}
		if !salaryLocationMatches(o, eq.LocationBucket) {
			continue
		}
		if eq.Company != "" && o.CompanyKey != eq.Company {
			continue
		}
		matched = append(matched, o)
		rep.Currencies[o.Currency]++
	}

	// 4. Currency.
	cur := eq.Currency
	if cur == "" {
		cur = pickMostCommon(rep.Currencies)
	}
	rep.Currency = cur
	var inCur []SalaryObservation
	baseN := 0
	for _, o := range matched {
		if o.Currency == cur {
			inCur = append(inCur, o)
			if o.Basis == PayBasisBase {
				baseN++
			}
		}
	}
	others := make([]string, 0, len(rep.Currencies))
	for c, n := range rep.Currencies {
		if c != cur {
			others = append(others, c+" "+strconv.Itoa(n))
		}
	}
	sort.Strings(others)
	if len(others) > 0 {
		notes = append(notes, "excluded postings in other currencies ("+strings.Join(others, ", ")+"); pass currency to view them")
	}

	// 5. Basis.
	basis := eq.Basis
	if basis == "" {
		if baseN >= salaryBasisMinBase {
			basis = string(PayBasisBase)
		} else {
			basis = "all"
			if len(inCur) > baseN {
				notes = append(notes, "fewer than 3 base-salary postings; statistics mix base, total and OTE ranges")
			}
		}
	}
	rep.Basis = basis
	var sel []SalaryObservation
	for _, o := range inCur {
		if basis == "all" || string(o.Basis) == basis {
			sel = append(sel, o)
		}
	}
	rep.Postings = len(sel)

	// 6. Cluster collapse.
	clusters := map[string]*salaryCluster{}
	var order []string
	hourly := 0
	for _, o := range sel {
		rep.Sources[o.Source]++
		if o.Period == PayPeriodHour {
			hourly++
		}
		key := strings.Join([]string{o.CompanyKey, o.TitleFamily, o.Seniority, o.Currency, string(o.Basis),
			strconv.FormatFloat(math.Round(o.MinAnnual), 'f', 0, 64), strconv.FormatFloat(math.Round(o.MaxAnnual), 'f', 0, 64)}, "\x00")
		r := observationRecencyMs(o)
		c, ok := clusters[key]
		if !ok {
			c = &salaryCluster{rep: o, recency: r, buckets: map[string]bool{}}
			clusters[key] = c
			order = append(order, key)
		} else if r > c.recency || (r == c.recency && o.URL < c.rep.URL) {
			c.rep, c.recency = o, r
		}
		c.postings++
		c.buckets[o.LocationBucket] = true
	}
	delete(rep.Sources, "")
	list := make([]*salaryCluster, 0, len(order))
	for _, k := range order {
		list = append(list, clusters[k])
	}
	rep.Matched = len(list)

	// 7. Statistics.
	mids := make([]float64, 0, len(list))
	mins := make([]float64, 0, len(list))
	maxs := make([]float64, 0, len(list))
	bySen := map[string][]float64{}
	byLoc := map[string][]float64{}
	byCo := map[string][]float64{}
	coLabel := map[string]string{}
	coRecency := map[string]int64{}
	for _, c := range list {
		m := c.mid()
		mids = append(mids, m)
		mins = append(mins, c.rep.MinAnnual)
		maxs = append(maxs, c.rep.MaxAnnual)
		bySen[c.rep.Seniority] = append(bySen[c.rep.Seniority], m)
		for b := range c.buckets {
			byLoc[b] = append(byLoc[b], m)
		}
		ck := c.rep.CompanyKey
		if ck == "" {
			ck = "unknown"
		}
		byCo[ck] = append(byCo[ck], m)
		if prev, ok := coRecency[ck]; !ok || c.recency > prev {
			coRecency[ck] = c.recency
			coLabel[ck] = c.rep.Company
		}
	}
	rep.Midpoint = ComputeSalaryStats(mids)
	rep.Min = ComputeSalaryStats(mins)
	rep.Max = ComputeSalaryStats(maxs)
	rep.BySeniority = buildSalaryBreakdown(bySen, nil, 0)
	rep.ByLocation = buildSalaryBreakdown(byLoc, nil, salaryTopN)
	rep.TopCompanies = buildSalaryBreakdown(byCo, coLabel, salaryTopN)

	// 8. Sample.
	sorted := append([]*salaryCluster(nil), list...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].recency != sorted[j].recency {
			return sorted[i].recency > sorted[j].recency
		}
		return sorted[i].rep.URL < sorted[j].rep.URL
	})
	for i, c := range sorted {
		if i >= salarySampleSize {
			break
		}
		o := c.rep
		rep.Sample = append(rep.Sample, SalarySample{
			Title: o.TitleRaw, Company: o.Company, Location: o.LocationRaw, LocationBucket: o.LocationBucket,
			Seniority: o.Seniority, Currency: o.Currency, Period: o.Period, Basis: o.Basis,
			Min: o.Min, Max: o.Max, MinAnnual: o.MinAnnual, MaxAnnual: o.MaxAnnual,
			URL: o.URL, PostedAt: o.PostedAt, Source: o.Source, Postings: c.postings,
		})
	}

	// 9. Notes.
	switch {
	case rep.Matched == 0:
		notes = append(notes, "no observations matched; widen the title, seniority or location filters, or refresh company boards")
	case rep.Matched < salaryThinThreshold:
		notes = append(notes, "only "+strconv.Itoa(rep.Matched)+" observations; widen location or add refresh")
	}
	if rep.Postings > rep.Matched {
		notes = append(notes, "collapsed "+strconv.Itoa(rep.Postings)+" postings into "+strconv.Itoa(rep.Matched)+
			" observations (same company, title, seniority and range across locations)")
	}
	if hourly > 0 {
		notes = append(notes, strconv.Itoa(hourly)+" postings annualized from hourly pay (x2080)")
	}
	if stale > 0 {
		notes = append(notes, strconv.Itoa(stale)+" observations older than "+strconv.Itoa(eq.MaxAgeDays)+" days ignored")
	}
	rep.Notes = append(rep.Notes, notes...)
	rep.Query = eq
	rep.Markdown = FormatSalaryReportMarkdown(rep)
	return rep
}

// ---------------------------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------------------------

// salaryMDText sanitizes untrusted display text and escapes Markdown/table metacharacters.
func salaryMDText(s string, maxLen int) string {
	s = SanitizeJobFieldPlain(s, maxLen)
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '`', '*', '_', '[', ']', '|', '#', '!', '~':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case '\n', '\r':
			sb.WriteByte(' ')
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// salaryMDURL returns a safe http(s) link destination or "".
func salaryMDURL(raw string) string {
	u, ok := parseStrictURL(raw)
	if !ok || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	out := u.String()
	return strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", "<", "%3C", ">", "%3E").Replace(out)
}

func salaryStatsRow(label string, s SalaryStats) string {
	return "| " + label + " | " + formatSalaryAmount(s.P10) + " | " + formatSalaryAmount(s.P25) + " | " +
		formatSalaryAmount(s.Median) + " | " + formatSalaryAmount(s.P75) + " | " + formatSalaryAmount(s.P90) + " | " +
		formatSalaryAmount(s.Mean) + " |\n"
}

// FormatSalaryReportMarkdown renders a compact Markdown summary of rep.
func FormatSalaryReportMarkdown(rep SalaryReport) string {
	var sb strings.Builder
	title := rep.Query.TitleFamily
	if title == "" {
		title = "all roles"
	}
	sb.WriteString("## Salary ranges: " + salaryMDText(title, 120))
	if rep.Query.Seniority != "" {
		sb.WriteString(" (" + salaryMDText(rep.Query.Seniority, 40) + ")")
	}
	if rep.Query.LocationBucket != "" {
		sb.WriteString(" - " + salaryMDText(rep.Query.LocationBucket, 80))
	}
	if rep.Query.Company != "" {
		sb.WriteString(" at " + salaryMDText(rep.Query.Company, 120))
	}
	sb.WriteString("\n\n")
	if rep.Matched == 0 {
		sb.WriteString("No employer-posted pay ranges matched.\n")
	} else {
		sb.WriteString(strconv.Itoa(rep.Matched) + " observations (" + strconv.Itoa(rep.Postings) +
			" postings) from official ATS boards; annualized " + rep.Currency + ", basis " + rep.Basis + ".\n\n")
		sb.WriteString("| " + rep.Currency + " / year | P10 | P25 | Median | P75 | P90 | Mean |\n")
		sb.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
		sb.WriteString(salaryStatsRow("Midpoint", rep.Midpoint))
		sb.WriteString(salaryStatsRow("Range min", rep.Min))
		sb.WriteString(salaryStatsRow("Range max", rep.Max))
		writeGroup := func(heading string, rows []SalaryBreakdown) {
			if len(rows) == 0 {
				return
			}
			sb.WriteString("\n### " + heading + "\n\n| " + heading + " | Count | Median midpoint |\n| --- | ---: | ---: |\n")
			for _, r := range rows {
				name := r.Label
				if name == "" {
					name = r.Key
				}
				sb.WriteString("| " + salaryMDText(name, 120) + " | " + strconv.Itoa(r.Count) + " | " + formatSalaryAmount(r.Median) + " |\n")
			}
		}
		writeGroup("Seniority", rep.BySeniority)
		writeGroup("Location", rep.ByLocation)
		writeGroup("Company", rep.TopCompanies)
		if len(rep.Sample) > 0 {
			sb.WriteString("\n### Recent postings\n\n")
			for _, s := range rep.Sample {
				loc := s.Location
				if loc == "" {
					loc = s.LocationBucket
				}
				sb.WriteString("- " + salaryMDText(s.Title, 160) + " - " + salaryMDText(s.Company, 120) + " - " +
					salaryMDText(loc, 120) + " - " + s.Currency + " " + formatSalaryAmount(s.Min) + "-" +
					formatSalaryAmount(s.Max) + "/" + string(s.Period))
				if s.Postings > 1 {
					sb.WriteString(" (" + strconv.Itoa(s.Postings) + " postings)")
				}
				if u := salaryMDURL(s.URL); u != "" {
					sb.WriteString(" - [posting](" + u + ")")
				}
				if s.PostedAt != "" {
					sb.WriteString(" - " + salaryMDText(s.PostedAt, 32))
				}
				sb.WriteString("\n")
			}
		}
	}
	if len(rep.Notes) > 0 {
		sb.WriteString("\n### Notes\n\n")
		for _, n := range rep.Notes {
			sb.WriteString("- " + salaryMDText(n, 400) + "\n")
		}
	}
	sb.WriteString("\n_" + SalaryMethod + "_\n")
	return sb.String()
}
