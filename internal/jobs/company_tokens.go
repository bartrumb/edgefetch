package jobs

import (
	"regexp"
	"strings"
	"unicode"
)

const maxJobsQueryChars = 256

var (
	queryStopWords = map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"into": true, "role": true, "job": true, "jobs": true, "open": true, "position": true,
	}

	companyLegalEntitySuffixes = map[string]bool{
		"inc": true, "incorporated": true, "corp": true, "corporation": true, "llc": true,
		"llp": true, "lp": true, "pbc": true, "plc": true, "ltd": true, "limited": true,
		"gmbh": true, "ag": true, "se": true, "sa": true, "sas": true, "sarl": true,
		"bv": true, "nv": true, "oy": true, "ab": true, "as": true, "aps": true,
		"kk": true, "gk": true, "pty": true, "pte": true, "bhd": true, "sdn": true,
		"co": true, "company": true, "companies": true, "holdings": true, "holding": true, "enterprises": true,
	}

	companySubsidiaryAndGeoQualifiers = func() map[string]bool {
		m := make(map[string]bool, 180)
		for k := range companyLegalEntitySuffixes {
			m[k] = true
		}
		for _, w := range []string{
			"labs", "lab", "technologies", "technology", "tech", "systems", "software", "networks", "network",
			"security", "cloud", "ai", "research", "robotics", "industries", "industrial", "payments",
			"financial", "finance", "markets", "capital", "bank", "banking", "commerce", "media", "studios",
			"studio", "entertainment", "gaming", "games", "health", "healthcare", "bio", "therapeutics",
			"energy", "power", "logistics", "mobility", "automotive", "motors", "aerospace", "aviation",
			"space", "defense", "pharma", "pharmaceuticals", "biosciences", "biotech", "diagnostics",
			"medical", "devices", "insurance", "retail", "electronics", "semiconductor", "semiconductors",
			"microelectronics", "federal", "government", "public", "sector", "services", "solutions", "web",
			"people", "center", "digital", "platform", "platforms", "data", "analytics", "computing",
			"communications", "telecom", "wireless", "group", "international", "intl", "hq", "io", "so",
			"app", "dev", "net", "org", "com",
			"us", "usa", "uk", "eu", "na", "emea", "apac", "latam", "americas", "europe", "asia", "pacific",
			"global", "worldwide", "north", "south", "east", "west", "america", "canada", "mexico", "brazil",
			"argentina", "chile", "colombia", "ireland", "germany", "france", "spain", "italy", "netherlands",
			"sweden", "norway", "denmark", "finland", "poland", "switzerland", "austria", "belgium",
			"portugal", "india", "japan", "korea", "singapore", "australia", "new", "zealand", "israel",
			"uae", "taiwan", "philippines", "indonesia", "vietnam", "thailand", "malaysia", "china", "hong", "kong",
		} {
			m[w] = true
		}
		return m
	}()

	unhyphenatedATSGeoHQSuffixes = map[string]bool{
		"usa": true, "us": true, "uk": true, "eu": true, "hq": true, "na": true,
		"emea": true, "apac": true, "latam": true, "canada": true, "japan": true,
		"india": true, "australia": true, "germany": true, "france": true, "ireland": true, "singapore": true,
	}

	companyNegationWords = map[string]bool{
		"not": true, "non": true, "anti": true, "ex": true, "former": true, "unlike": true,
		"never": true, "no": true, "without": true, "vs": true, "versus": true, "fake": true,
		"clone": true, "mock": true, "phish": true, "phishing": true, "scam": true, "spoof": true,
		"parody": true, "impostor": true, "imposter": true, "unofficial": true, "recruiting": true,
		"recruitment": true, "recruiter": true, "recruiters": true, "staffing": true, "headhunter": true,
		"agency": true, "outsourcing": true, "confidential": true, "stealth": true,
	}

	twoPartPublicSuffixes = map[string]bool{
		"co.uk": true, "org.uk": true, "me.uk": true, "com.au": true, "net.au": true, "org.au": true,
		"co.jp": true, "ne.jp": true, "or.jp": true, "co.nz": true, "co.in": true, "firm.in": true,
		"co.kr": true, "co.il": true, "com.br": true, "com.mx": true, "com.ar": true, "com.co": true,
		"com.sg": true, "com.hk": true, "com.tw": true, "com.my": true, "com.ph": true, "com.vn": true,
		"com.tr": true, "co.za": true, "co.id": true, "co.th": true,
	}

	centralNicPrivateSuffixes = map[string]bool{
		"us.com": true, "uk.com": true, "eu.com": true, "de.com": true, "jpn.com": true, "cn.com": true,
		"br.com": true, "ru.com": true, "sa.com": true, "za.com": true, "se.com": true, "no.com": true,
		"qc.com": true, "uy.com": true, "kr.com": true, "co.com": true, "com.de": true, "com.se": true,
		"gb.net": true, "uk.net": true, "se.net": true, "in.net": true,
	}

	unverifiedJobAggregatorDomains = []string{
		"linkedin.com", "indeed.com", "glassdoor.com", "ziprecruiter.com", "monster.com", "dice.com",
		"simplyhired.com", "careerbuilder.com", "talent.com", "jooble.org", "snagajob.com", "lensa.com",
		"wayup.com", "wellfound.com", "angel.co", "otta.com", "builtin.com", "levels.fyi", "ycombinator.com",
		"reddit.com", "medium.com", "substack.com", "wordpress.com", "blogspot.com", "wixsite.com",
		"squarespace.com", "webflow.io", "notion.site", "github.io", "gitlab.io", "vercel.app",
		"netlify.app", "pages.dev", "workers.dev", "herokuapp.com", "onrender.com", "railway.app",
		"fly.dev", "web.app", "firebaseapp.com", "myshopify.com",
	}

	vettedCorporateTLDs = map[string]bool{
		"com": true, "io": true, "ai": true, "co": true, "org": true, "net": true, "app": true, "dev": true,
		"so": true, "sh": true, "gg": true, "tech": true, "cloud": true, "security": true, "finance": true,
		"money": true, "vc": true, "bio": true, "health": true, "energy": true, "jobs": true,
		"uk": true, "de": true, "fr": true, "ca": true, "eu": true, "ch": true, "nl": true, "se": true,
		"no": true, "dk": true, "fi": true, "ie": true, "es": true, "it": true, "pl": true, "at": true,
		"be": true, "pt": true, "jp": true, "au": true, "nz": true, "in": true, "sg": true, "kr": true,
		"il": true, "br": true, "mx": true, "ar": true, "za": true, "hk": true, "tw": true,
		"google": true, "apple": true, "amazon": true, "aws": true, "microsoft": true,
		"netflix": true, "bloomberg": true, "barclays": true, "deloitte": true, "cern": true,
	}

	officialCompanyCareerDomains = map[string][]string{
		"google":           {"google.com", "about.google", "careers.google", "deepmind.google", "alphabet.com"},
		"alphabet":         {"alphabet.com", "google.com", "about.google", "waymo.com", "verily.com"},
		"meta":             {"meta.com", "metacareers.com", "facebook.com", "fb.com"},
		"facebook":         {"metacareers.com", "meta.com", "facebook.com"},
		"amazon":           {"amazon.com", "amazon.jobs"},
		"aws":              {"amazon.jobs", "amazon.com"},
		"apple":            {"apple.com"},
		"microsoft":        {"microsoft.com", "github.com", "linkedin.com"},
		"netflix":          {"netflix.com", "netflix.net"},
		"stripe":           {"stripe.com", "stripe.co.jp", "stripe.co.uk"},
		"cloudflare":       {"cloudflare.com"},
		"openai":           {"openai.com"},
		"anthropic":        {"anthropic.com"},
		"datadog":          {"datadoghq.com"},
		"notion":           {"notion.so", "makenotion.com"},
		"block":            {"block.xyz", "squareup.com", "cash.app"},
		"xai":              {"x.ai"},
		"1password":        {"1password.com"},
		"huggingface":      {"huggingface.co"},
		"paloaltonetworks": {"paloaltonetworks.com"},
		"scaleai":          {"scale.com"},
		"fly":              {"fly.io"},
		"linear":           {"linear.app"},
	}

	curatedPublicFeedHostBySource = map[string]string{
		"weworkremotely":           "weworkremotely.com",
		"weworkremotely-feed":      "weworkremotely.com",
		"himalayas":                "himalayas.app",
		"himalayas-feed":           "himalayas.app",
		"workingnomads":            "workingnomads.com",
		"workingnomads-feed":       "workingnomads.com",
		"workatastartup":           "workatastartup.com",
		"workatastartup-yc-mirror": "workatastartup.com",
	}

	subdomainCareerPrefixes = map[string]bool{
		"www": true, "jobs": true, "careers": true, "career": true, "hiring": true,
		"work": true, "join": true, "about": true, "people": true, "talent": true, "boards": true,
	}

	knownMultiwordSlugParts = map[string]bool{
		"ai": true, "io": true, "db": true, "os": true, "ui": true, "ml": true, "labs": true, "tech": true,
		"cloud": true, "data": true, "face": true, "open": true, "scale": true, "hugging": true, "palo": true,
		"alto": true, "networks": true, "systems": true, "crowd": true, "strike": true, "snow": true,
		"flake": true, "dog": true, "mongo": true, "cyber": true, "digital": true, "ocean": true, "tail": true,
		"eleven": true, "deep": true, "mind": true, "together": true, "fire": true, "crawl": true, "edge": true,
		"fetch": true, "new": true, "relic": true, "service": true, "now": true, "work": true, "day": true,
		"door": true, "dash": true, "coin": true, "base": true, "robin": true, "hood": true, "instacart": true,
		"one": true, "password": true, "weights": true, "biases": true, "magic": true, "red": true, "hat": true,
	}

	genericNonBrandTLDs = map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true, "mil": true, "int": true,
		"app": true, "dev": true, "tech": true, "cloud": true, "jobs": true, "info": true, "biz": true, "xyz": true,
	}
	nonBrandFirstPartyTLDs = map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true, "io": true, "ai": true,
		"co": true, "app": true, "dev": true, "so": true, "sh": true, "gg": true, "tech": true, "cloud": true, "jobs": true,
	}

	reConcatNegationPrefix = regexp.MustCompile(`^(?:not|non|anti|ex|former|unlike|fake|clone|mock|spoof|phish|scam|impostor|imposter|unofficial)`)
	reNumericOrHexTLD      = regexp.MustCompile(`(?i)^(?:\d+|0x[0-9a-f]+)$`)
	reDottedCorpAbbrev     = regexp.MustCompile(`(?i)\b(?:l\.l\.c|p\.b\.c|p\.l\.c|l\.l\.p|i\.n\.c|c\.o\.r\.p|l\.t\.d|u\.s\.a|u\.s|u\.k|s\.a|b\.v|n\.v|a\.g|s\.e|k\.k)\.?`)
	reDomainLikeInput      = regexp.MustCompile(`(?i)^[a-z0-9-]+(?:\.[a-z0-9-]+)+$`)
	reDottedAbbrevTail     = regexp.MustCompile(`(?i)\.(?:l\.l\.c|p\.b\.c|p\.l\.c|i\.n\.c|l\.t\.d|u\.k|u\.s\.a|k\.k)\.?$`)
	reAlnumWords           = regexp.MustCompile(`[a-z0-9]+`)
	reAshbySpaceSlug       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]| [A-Za-z0-9_-])*$`)
	reATSSlugChars         = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reSingleLetterBrandSpf = regexp.MustCompile(`(?:^|\s)[A-Za-z](?:[.\-/][A-Za-z]){3,}\b`)
	reAllowedCareerPath    = regexp.MustCompile(`(?i)^/(?:careers|jobs|about|company|en|intl)\b`)
	reParenStrip           = regexp.MustCompile(`\(.*?\)`)

	reICRoleWord   = regexp.MustCompile(`^(?:engineers?|developers?|scientists?|designers?|researchers?|architects?|analysts?)$`)
	reMgmtRoleWord = regexp.MustCompile(`^(?:managers?|management|directors?|vp|presidents?|chief|head)$`)
	reUSExplicit   = regexp.MustCompile(`(?i)\b(?:united states|usa|u\.s\.a?\.?|us\b|americas?[ \t]{0,8}\(us\)|us-[a-z]{2}\b|alabama|alaska|arizona|arkansas|california|colorado|connecticut|delaware|district of columbia|florida|hawaii|idaho|illinois|indiana|iowa|kansas|kentucky|louisiana|maine|maryland|massachusetts|michigan|minnesota|mississippi|missouri|montana|nebraska|nevada|new hampshire|new jersey|new mexico|new york|north carolina|north dakota|ohio|oklahoma|oregon|pennsylvania|rhode island|south carolina|south dakota|tennessee|texas|utah|vermont|virginia|washington|west virginia|wisconsin|wyoming|san francisco|nyc|seattle|austin|boston|chicago|los angeles|denver|atlanta|menlo park|mountain view|palo alto|sunnyvale|santa clara|san jose|redmond|bellevue|mclean|reston|pittsburgh|philadelphia|phoenix|portland|san diego|raleigh|durham|minneapolis|detroit|salt lake city|miami|dallas|houston|charlotte|nashville|columbus|indianapolis)\b`)
	reGeorgiaWord  = regexp.MustCompile(`(?i)\bgeorgia\b`)
	reTbilisiWord  = regexp.MustCompile(`(?i)\btbilisi\b`)
	reRemoteAmer   = regexp.MustCompile(`(?i)\bremote\b[^|]{0,24}\b(?:north america|americas)\b|\b(?:north america|americas)\b[^|]{0,24}\bremote\b`)
	reCanadianLoc  = regexp.MustCompile(`(?i)\b(?:canada|toronto|vancouver|montreal|ottawa|calgary|ontario|quebec|british columbia)\b|,[ \t]{0,8}(?:on|bc|qc|ab),[ \t]{0,8}ca\b`)
	reUSStateAbbr  = regexp.MustCompile(`(?i),[ \t]{0,8}(?:al|ak|az|ar|ca|co|ct|de|dc|fl|ga|hi|id|il|in|ia|ks|ky|la|me|md|ma|mi|mn|ms|mo|mt|ne|nv|nh|nj|nm|ny|nc|nd|oh|ok|or|pa|ri|sc|sd|tn|tx|ut|vt|va|wa|wv|wi|wy)\b`)
	reAgeLabel     = regexp.MustCompile(`(?i)^(\d+)(\+)?\s*(days?|weeks?|months?|years?)\b`)
)

// RegistrableBrandInfo describes the registrable brand SLD and TLD of a hostname.
type RegistrableBrandInfo struct {
	SLD               string `json:"sld"`
	TLD               string `json:"tld"`
	RegistrableDomain string `json:"registrableDomain"`
	JoinedRegistrable string `json:"joinedRegistrable"`
	IsVettedTLD       bool   `json:"isVettedTld"`
}

// ExtractRegistrableBrandInfo extracts the brand SLD, TLD, and registrable domain, rejecting CentralNic private suffixes and numeric TLDs.
func ExtractRegistrableBrandInfo(hostname string) *RegistrableBrandInfo {
	clean := strings.TrimRight(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if clean == "" || !strings.Contains(clean, ".") {
		return nil
	}
	labels := strings.Split(clean, ".")
	if len(labels) < 2 {
		return nil
	}
	for _, l := range labels {
		if l == "" {
			return nil
		}
	}
	if reNumericOrHexTLD.MatchString(labels[len(labels)-1]) {
		return nil
	}
	lastTwo := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if centralNicPrivateSuffixes[lastTwo] {
		return nil
	}
	if twoPartPublicSuffixes[lastTwo] {
		if len(labels) < 3 {
			return nil
		}
		sld := labels[len(labels)-3]
		cc := labels[len(labels)-1]
		return &RegistrableBrandInfo{
			SLD:               sld,
			TLD:               lastTwo,
			RegistrableDomain: sld + "." + lastTwo,
			JoinedRegistrable: sld + strings.ReplaceAll(lastTwo, ".", ""),
			IsVettedTLD:       vettedCorporateTLDs[cc],
		}
	}
	sld := labels[len(labels)-2]
	tld := labels[len(labels)-1]
	return &RegistrableBrandInfo{
		SLD:               sld,
		TLD:               tld,
		RegistrableDomain: sld + "." + tld,
		JoinedRegistrable: sld + tld,
		IsVettedTLD:       vettedCorporateTLDs[tld],
	}
}

// NormalizeDottedCorporateAbbreviations collapses dotted corporate/geo abbreviations (`L.L.C.` -> `llc`, `U.S.A.` -> `usa`)
// without collapsing spaced/dotted brand spoofs like `S.T.R.I.P.E`.
func NormalizeDottedCorporateAbbreviations(raw string) string {
	return reDottedCorpAbbrev.ReplaceAllStringFunc(raw, func(m string) string {
		return strings.ReplaceAll(m, ".", "")
	})
}

// ExpandCompanyFilterTokens expands a raw company name, domain, or career URL into canonical brand filter tokens.
func ExpandCompanyFilterTokens(rawCompany string) []string {
	bounded := strings.TrimSpace(sliceUTF16Max(rawCompany, 256))
	if bounded == "" {
		return []string{}
	}
	var order []string
	seen := make(map[string]bool)
	addOut := func(tok string) {
		if len(tok) >= 2 && !seen[tok] {
			seen[tok] = true
			order = append(order, tok)
		}
	}

	candidateHost := ""
	lowBounded := strings.ToLower(bounded)
	if strings.HasPrefix(lowBounded, "http://") || strings.HasPrefix(lowBounded, "https://") {
		if u, ok := parseStrictURL(bounded); ok {
			candidateHost = strings.TrimRight(strings.ToLower(u.Hostname()), ".")
		}
	} else if reDomainLikeInput.MatchString(bounded) && !reDottedAbbrevTail.MatchString(bounded) {
		candidateHost = strings.TrimRight(lowBounded, ".")
	}
	if candidateHost != "" && !IsKnownMultiTenantATSHost(candidateHost) {
		if info := ExtractRegistrableBrandInfo(candidateHost); info != nil {
			if len(info.SLD) >= 2 && !subdomainCareerPrefixes[info.SLD] {
				addOut(reNonAlnumSplit.ReplaceAllString(info.SLD, ""))
				if strings.HasSuffix(info.SLD, "hq") && len(info.SLD) >= 5 {
					addOut(reNonAlnumSplit.ReplaceAllString(info.SLD[:len(info.SLD)-2], ""))
				}
			}
			if len(info.JoinedRegistrable) >= 2 && !subdomainCareerPrefixes[info.SLD] {
				addOut(info.JoinedRegistrable)
			}
			if len(info.TLD) >= 3 && !twoPartPublicSuffixes[info.TLD] && !genericNonBrandTLDs[info.TLD] {
				addOut(info.TLD)
			}
			if order == nil {
				return []string{}
			}
			return order
		}
	}

	collapsed := strings.ToLower(NormalizeDottedCorporateAbbreviations(bounded))
	fullClean := reNonAlnumSplit.ReplaceAllString(collapsed, "")
	addOut(fullClean)

	words := reAlnumWords.FindAllString(collapsed, -1)
	for len(words) > 1 && companySubsidiaryAndGeoQualifiers[words[len(words)-1]] {
		words = words[:len(words)-1]
		core := strings.Join(words, "")
		addOut(core)
	}
	if order == nil {
		return []string{}
	}
	return order
}

func isVerifiedMultiWordHyphenJoin(parts []string, tok, rawCompanyHint string, segmentedTokens map[string]bool) bool {
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if len(p) < 2 {
			return false
		}
	}
	if strings.Join(parts, "") != tok {
		return false
	}
	segmentedKey := strings.Join(parts, "-")
	if segmentedTokens[segmentedKey] {
		return true
	}
	if rawCompanyHint != "" {
		normHint := NormalizeDottedCorporateAbbreviations(rawCompanyHint)
		prefixCheck := sliceUTF16Max(normHint, len(tok)+4)
		if !strings.ContainsAny(prefixCheck, ".-/_") {
			cWords := reAlnumWords.FindAllString(strings.ToLower(normHint), -1)
			if len(cWords) >= len(parts) {
				prefixMatch := true
				for idx, p := range parts {
					if cWords[idx] != p {
						prefixMatch = false
						break
					}
				}
				if prefixMatch {
					qualOK := true
					for _, w := range cWords[len(parts):] {
						if !companySubsidiaryAndGeoQualifiers[w] {
							qualOK = false
							break
						}
					}
					if qualOK {
						return true
					}
				}
			}
		}
	}
	for _, p := range parts {
		if !knownMultiwordSlugParts[p] {
			return false
		}
	}
	return true
}

func hasSpoofControlOrFormatRune(s string) bool {
	for _, r := range s {
		if r <= 0x1F || (r >= 0x7F && r <= 0xA0) || r == 0x00AD || r == 0x034F || r == 0x061C ||
			r == 0x17B4 || r == 0x17B5 || (r >= 0x180B && r <= 0x180F) ||
			(r >= 0x2000 && r <= 0x200F) || (r >= 0x2028 && r <= 0x202F) ||
			(r >= 0x205F && r <= 0x206F) || r == 0xFEFF {
			return true
		}
	}
	return false
}

// TenantSlugMatchOptions configures MatchesATSTenantSlugAgainstToken.
type TenantSlugMatchOptions struct {
	Host             string
	JobCompany       string
	SegmentedTokens  map[string]bool
	AllowAshbySpaces bool
}

// MatchesATSTenantSlugAgainstToken checks whether rawSlug legitimately matches brand token tok.
func MatchesATSTenantSlugAgainstToken(rawSlug, tok string, opts TenantSlugMatchOptions) bool {
	if rawSlug == "" || len(tok) < 2 || len(tok) > 128 {
		return false
	}
	bounded := sliceUTF16Max(rawSlug, 128)
	if hasSpoofControlOrFormatRune(bounded) {
		return false
	}
	hostLower := strings.ToLower(opts.Host)
	canHaveAshbySpace := opts.AllowAshbySpaces || hostLower == "ashbyhq.com" || strings.HasSuffix(hostLower, ".ashbyhq.com")
	if canHaveAshbySpace && strings.Contains(bounded, " ") {
		if !reAshbySpaceSlug.MatchString(bounded) {
			return false
		}
		spaceParts := strings.FieldsFunc(strings.ToLower(bounded), func(r rune) bool {
			return r == '-' || r == '_' || r == ' '
		})
		return isVerifiedMultiWordHyphenJoin(spaceParts, tok, "", opts.SegmentedTokens)
	}
	if !reATSSlugChars.MatchString(bounded) {
		return false
	}
	lower := strings.ToLower(bounded)
	if lower == tok {
		return true
	}
	if strings.Contains(lower, "-") || strings.Contains(lower, "_") {
		parts := strings.FieldsFunc(lower, func(r rune) bool { return r == '-' || r == '_' })
		return isVerifiedMultiWordHyphenJoin(parts, tok, opts.JobCompany, opts.SegmentedTokens)
	}
	if len(tok) >= 3 && isAllLowerAlnum(lower) && strings.HasPrefix(lower, tok) {
		rem := lower[len(tok):]
		if unhyphenatedATSGeoHQSuffixes[rem] {
			return true
		}
		if rem == "inc" && !(hostLower != "" && (hostLower == "lever.co" || strings.HasSuffix(hostLower, ".lever.co"))) {
			return true
		}
	}
	return false
}

func isAllLowerAlnum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
			return false
		}
	}
	return true
}

func extractUnicodeAlnumWords(s string) []string {
	var words []string
	start := -1
	for idx, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if start < 0 {
				start = idx
			}
		} else if start >= 0 {
			words = append(words, s[start:idx])
			start = -1
		}
	}
	if start >= 0 {
		words = append(words, s[start:])
	}
	return words
}

// foldLatinDiacriticsToASCII matches JS `/^[\p{Script=Latin}0-9]+$/u` + `.normalize('NFD').replace(/[\u0300-\u036f]/g, ”)`.
func foldLatinDiacriticsToASCII(w string) (string, bool) {
	var sb strings.Builder
	sb.Grow(len(w))
	for _, r := range w {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			continue
		}
		if r >= 0x0300 && r <= 0x036F {
			continue
		}
		if !unicode.Is(unicode.Latin, r) {
			return "", false
		}
		base := latinPrecomposedBase(unicode.ToLower(r))
		if base == 0 {
			return "", false
		}
		sb.WriteByte(base)
	}
	res := sb.String()
	return res, isAllLowerAlnum(res)
}

func latinPrecomposedBase(r rune) byte {
	switch r {
	case 'à', 'á', 'â', 'ã', 'ä', 'å', 'ā', 'ă', 'ą', 'ǎ':
		return 'a'
	case 'ç', 'ć', 'ĉ', 'ċ', 'č':
		return 'c'
	case 'ď':
		return 'd'
	case 'è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě':
		return 'e'
	case 'ĝ', 'ğ', 'ġ', 'ģ':
		return 'g'
	case 'ĥ':
		return 'h'
	case 'ì', 'í', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į', 'ǐ':
		return 'i'
	case 'ĵ':
		return 'j'
	case 'ķ':
		return 'k'
	case 'ĺ', 'ļ', 'ľ':
		return 'l'
	case 'ñ', 'ń', 'ņ', 'ň':
		return 'n'
	case 'ò', 'ó', 'ô', 'õ', 'ö', 'ō', 'ŏ', 'ő', 'ǒ', 'ơ':
		return 'o'
	case 'ŕ', 'ŗ', 'ř':
		return 'r'
	case 'ś', 'ŝ', 'ş', 'š', 'ș':
		return 's'
	case 'ţ', 'ť', 'ț':
		return 't'
	case 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ǔ', 'ư':
		return 'u'
	case 'ŵ':
		return 'w'
	case 'ý', 'ÿ', 'ŷ':
		return 'y'
	case 'ź', 'ż', 'ž':
		return 'z'
	default:
		return 0
	}
}

func hasExplicitSpoofOrNegationInCompany(rawCompany string, allowedTokens map[string]bool) bool {
	bounded := sliceUTF16Max(rawCompany, 256)
	if hasSpoofControlOrFormatRune(bounded) {
		return true
	}
	normalizedAbbrev := NormalizeDottedCorporateAbbreviations(bounded)
	if reSingleLetterBrandSpf.MatchString(normalizedAbbrev) {
		return true
	}
	rawWords := extractUnicodeAlnumWords(strings.ToLower(normalizedAbbrev))
	for _, rw := range rawWords {
		w := rw
		if !isAllLowerAlnum(w) {
			folded, ok := foldLatinDiacriticsToASCII(w)
			if !ok {
				return true
			}
			w = folded
		}
		if companyNegationWords[w] && !allowedTokens[w] {
			return true
		}
		if !allowedTokens[w] && reConcatNegationPrefix.MatchString(w) {
			for tok := range allowedTokens {
				if len(tok) >= 3 && strings.HasSuffix(w, tok) {
					return true
				}
			}
		}
	}
	return false
}

func matchesFirstPartyDomainAgainstToken(hostname, tok, rawCompany string, segmentedTokens map[string]bool) bool {
	info := ExtractRegistrableBrandInfo(hostname)
	if info == nil {
		return false
	}
	if !strings.HasPrefix(info.SLD, tok) && reConcatNegationPrefix.MatchString(info.SLD) {
		return false
	}
	if officialDomains, ok := officialCompanyCareerDomains[tok]; ok {
		for _, d := range officialDomains {
			if info.RegistrableDomain == d || hostname == d || strings.HasSuffix(hostname, "."+d) {
				return true
			}
		}
		return false
	}
	if len(tok) >= 3 && info.TLD == tok && !nonBrandFirstPartyTLDs[info.TLD] {
		return true
	}
	if info.JoinedRegistrable == tok {
		return true
	}
	if info.SLD == tok && info.TLD == "com" && info.IsVettedTLD {
		return true
	}
	if strings.Contains(info.SLD, "-") && info.TLD == "com" && info.IsVettedTLD {
		parts := strings.FieldsFunc(info.SLD, func(r rune) bool { return r == '-' })
		return isVerifiedMultiWordHyphenJoin(parts, tok, rawCompany, segmentedTokens)
	}
	return false
}

func matchesCompanyCandidateAgainstToken(rawCandidate, tok string) bool {
	if rawCandidate == "" || len(tok) < 2 || len(tok) > 128 {
		return false
	}
	bounded := sliceUTF16Max(rawCandidate, 256)
	if hasSpoofControlOrFormatRune(bounded) {
		return false
	}
	normalizedAbbrev := NormalizeDottedCorporateAbbreviations(bounded)
	rawWords := extractUnicodeAlnumWords(strings.ToLower(normalizedAbbrev))
	if len(rawWords) == 0 {
		return false
	}
	words := make([]string, 0, len(rawWords))
	for i, rw := range rawWords {
		w := rw
		if i > 0 && !isAllLowerAlnum(w) {
			if folded, ok := foldLatinDiacriticsToASCII(w); ok {
				w = folded
			}
		}
		if !isAllLowerAlnum(w) {
			return false
		}
		if companyNegationWords[w] && w != tok {
			return false
		}
		words = append(words, w)
	}

	for idx, w := range words {
		if w == "dba" && idx > 0 && idx+1 < len(words) {
			afterDba := words[idx+1:]
			if afterDba[0] == tok {
				qualOK := true
				for _, q := range afterDba[1:] {
					if !companySubsidiaryAndGeoQualifiers[q] {
						qualOK = false
						break
					}
				}
				if qualOK {
					return true
				}
			}
			break
		}
	}

	if len(words) == 1 {
		only := words[0]
		if only == tok {
			return true
		}
		if len(tok) >= 3 && strings.HasPrefix(only, tok) {
			rem := only[len(tok):]
			if companySubsidiaryAndGeoQualifiers[rem] {
				return true
			}
		}
		return false
	}

	clean := strings.Join(words, "")
	if !strings.HasPrefix(clean, tok) && reConcatNegationPrefix.MatchString(clean) {
		return false
	}

	if words[0] == tok && len(words) <= 7 {
		qualOK := true
		for _, w := range words[1:] {
			if !companySubsidiaryAndGeoQualifiers[w] {
				qualOK = false
				break
			}
		}
		if qualOK {
			return true
		}
	}

	prefixSlice := sliceUTF16Max(normalizedAbbrev, len(tok)+4)
	if len(tok) >= 4 && !strings.ContainsAny(prefixSlice, ".-/_") {
		acc := ""
		limit := min(len(words), 4)
		for k := 0; k < limit; k++ {
			part := words[k]
			if len(part) < 2 {
				break
			}
			if k == 0 && len(part) < 3 && len(words) == 2 && len(words[1]) < 3 {
				break
			}
			acc += part
			if acc == tok && k >= 1 {
				qualOK := true
				for _, w := range words[k+1:] {
					if !companySubsidiaryAndGeoQualifiers[w] {
						qualOK = false
						break
					}
				}
				if qualOK {
					return true
				}
			}
			if len(acc) >= len(tok) {
				break
			}
		}
	}
	return false
}

func isAggregatorDomain(host string) bool {
	for _, d := range unverifiedJobAggregatorDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
