package jobs

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// MatchesAllowedCompanyOrDomain strictly verifies whether job belongs to the requested company/domain scope,
// blocking impostor ATS slugs, cross-TLD spoofs, shared-hosting subdomains, and open job aggregators.
func MatchesAllowedCompanyOrDomain(job StructuredJobRecord, allowedTokens []string, allowedBoardPrefixes []string) bool {
	rawURL := sliceUTF16Max(job.URL, 2048)
	urlLower := strings.ToLower(rawURL)
	trimmedCompany := strings.TrimSpace(job.Company)
	hasExplicitCompany := trimmedCompany != "" && !strings.EqualFold(trimmedCompany, "unknown")

	var expandedOrder []string
	expandedSet := make(map[string]bool)
	addExpanded := func(t string) {
		if len(t) >= 2 && !expandedSet[t] && len(expandedSet) < 128 {
			expandedSet[t] = true
			expandedOrder = append(expandedOrder, t)
		}
	}
	segmentedTokens := make(map[string]bool)
	explicitAllowedRegistrableDomains := make(map[string]bool)

	registerAllowedDomainCandidate := func(rawStr string) {
		trimmed := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawStr)), "/")
		if trimmed == "" {
			return
		}
		hostCand := ""
		if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
			if u, ok := parseStrictURL(trimmed); ok {
				h := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
				p := u.EscapedPath()
				if h != "" && !IsKnownMultiTenantATSHost(h) && (p == "" || p == "/" || reAllowedCareerPath.MatchString(p)) {
					hostCand = h
				}
			}
		} else if reDomainLikeInput.MatchString(trimmed) && !reDottedAbbrevTail.MatchString(trimmed) {
			hostCand = strings.TrimRight(trimmed, ".")
		}
		if hostCand != "" && !IsKnownMultiTenantATSHost(hostCand) && !isAggregatorDomain(hostCand) {
			if info := ExtractRegistrableBrandInfo(hostCand); info != nil {
				explicitAllowedRegistrableDomains[info.RegistrableDomain] = true
				if len(info.TLD) >= 3 {
					if mapped, okM := officialCompanyCareerDomains[info.TLD]; okM {
						for _, d := range mapped {
							if !isAggregatorDomain(d) {
								explicitAllowedRegistrableDomains[d] = true
							}
						}
					}
				}
			}
		}
	}

	for _, rawTok := range allowedTokens {
		if rawTok == "" || len(expandedSet) >= 128 {
			continue
		}
		bounded := strings.TrimSpace(sliceUTF16Max(rawTok, 256))
		if bounded == "" {
			continue
		}
		registerAllowedDomainCandidate(bounded)
		words := reAlnumWords.FindAllString(strings.ToLower(NormalizeDottedCorporateAbbreviations(bounded)), -1)
		if len(words) >= 2 && len(words) <= 4 {
			segmentedTokens[strings.Join(words, "-")] = true
		}
		cleanLower := strings.ToLower(bounded)
		if len(cleanLower) >= 2 && len(cleanLower) <= 128 && reATSSlugChars.MatchString(cleanLower) {
			stripped := strings.NewReplacer("-", "", "_", "").Replace(cleanLower)
			addExpanded(stripped)
			if strings.Contains(cleanLower, "-") || strings.Contains(cleanLower, "_") {
				segmentedTokens[strings.ReplaceAll(cleanLower, "_", "-")] = true
			}
		}
		for _, exp := range ExpandCompanyFilterTokens(bounded) {
			addExpanded(exp)
		}
	}
	for _, p := range allowedBoardPrefixes {
		if p != "" {
			registerAllowedDomainCandidate(p)
		}
	}

	for _, rawP := range allowedBoardPrefixes {
		if rawP == "" {
			continue
		}
		p := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawP)), "/")
		if p != "" && (urlLower == p || strings.HasPrefix(urlLower, p+"/") || strings.HasPrefix(urlLower, p+"?")) {
			if hasExplicitCompany && hasExplicitSpoofOrNegationInCompany(job.Company, expandedSet) {
				return false
			}
			return true
		}
	}

	parsedURL, okU := parseStrictURL(rawURL)
	if !okU || (!strings.EqualFold(parsedURL.Scheme, "https") && !strings.EqualFold(parsedURL.Scheme, "http")) {
		return false
	}
	host := strings.TrimRight(strings.ToLower(parsedURL.Hostname()), ".")
	if host == "" || isAggregatorDomain(host) {
		return false
	}

	isMultiTenantATS := IsKnownMultiTenantATSHost(host)
	inferredSlug := ""
	if isMultiTenantATS {
		inferredSlug = InferCompanyFromATSURL(rawURL)
	}
	curatedFeedHost := curatedPublicFeedHostBySource[job.Source]
	isCuratedPublicFeed := curatedFeedHost != "" && (host == curatedFeedHost || strings.HasSuffix(host, "."+curatedFeedHost))

	if hasExplicitCompany && hasExplicitSpoofOrNegationInCompany(job.Company, expandedSet) {
		return false
	}

	if !isMultiTenantATS && !isCuratedPublicFeed && len(explicitAllowedRegistrableDomains) > 0 {
		hostInfo := ExtractRegistrableBrandInfo(host)
		if hostInfo == nil {
			return false
		}
		if explicitAllowedRegistrableDomains[hostInfo.RegistrableDomain] {
			return true
		}
		for d := range explicitAllowedRegistrableDomains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
		return false
	}

	for checked, tok := range expandedOrder {
		if checked >= 128 {
			break
		}
		if len(tok) < 2 {
			continue
		}
		if isMultiTenantATS {
			if !MatchesATSTenantSlugAgainstToken(inferredSlug, tok, TenantSlugMatchOptions{
				Host:            host,
				JobCompany:      job.Company,
				SegmentedTokens: segmentedTokens,
			}) {
				continue
			}
			if hasExplicitCompany {
				cleanComp := strings.ToLower(trimmedCompany)
				if cleanComp != strings.ToLower(inferredSlug) && !matchesCompanyCandidateAgainstToken(job.Company, tok) {
					continue
				}
			}
			return true
		}
		if isCuratedPublicFeed {
			if hasExplicitCompany && matchesCompanyCandidateAgainstToken(job.Company, tok) {
				return true
			}
			continue
		}
		if matchesFirstPartyDomainAgainstToken(host, tok, job.Company, segmentedTokens) {
			return true
		}
	}
	return false
}

// CanonicalJobKey returns a deduplication key `company::title` stripping parenthetical suffixes and punctuation.
func CanonicalJobKey(company, title string) string {
	c := reNonAlnumSplit.ReplaceAllString(strings.ToLower(company), "")
	t := reNonAlnumSplit.ReplaceAllString(reParenStrip.ReplaceAllString(strings.ToLower(title), ""), "")
	return c + "::" + t
}

func extractJobWordTokens(text string) []string {
	var out []string
	start := -1
	for idx, r := range text {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '+' || r == '#' {
			if start < 0 {
				start = idx
			}
		} else if start >= 0 {
			out = append(out, text[start:idx])
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, text[start:])
	}
	return out
}

func jobWordTokensMatch(hayToken, queryToken string) bool {
	if hayToken == queryToken {
		return true
	}
	if len(queryToken) >= 3 {
		if hayToken == queryToken+"s" || hayToken == queryToken+"es" {
			return true
		}
		if strings.HasSuffix(queryToken, "s") && queryToken[:len(queryToken)-1] == hayToken {
			return true
		}
		if strings.HasSuffix(queryToken, "es") && len(queryToken) >= 4 && queryToken[:len(queryToken)-2] == hayToken {
			return true
		}
	}
	return false
}

func containsJobTokenSequence(hayTokens, querySeq []string) bool {
	if len(querySeq) == 0 || len(hayTokens) < len(querySeq) {
		return false
	}
	maxStart := len(hayTokens) - len(querySeq)
	for i := 0; i <= maxStart; i++ {
		ok := true
		for j := 0; j < len(querySeq); j++ {
			if !jobWordTokensMatch(hayTokens[i+j], querySeq[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// MatchesJobQueryRelevance returns `"phrase"`, `"all_tokens"`, or `""` (no match).
func MatchesJobQueryRelevance(title, snippet, query string) string {
	cappedQuery := sliceUTF16Max(query, maxJobsQueryChars)
	normPhrase := strings.TrimSpace(reMultiSpacesJobs.ReplaceAllString(strings.ToLower(cappedQuery), " "))
	if normPhrase == "" {
		return "phrase"
	}
	cappedTitle := sliceUTF16Max(title, 1024)
	titleLower := reMultiSpacesJobs.ReplaceAllString(strings.ToLower(cappedTitle), " ")
	rawQueryWords := extractJobWordTokens(normPhrase)
	if len(rawQueryWords) > 32 {
		rawQueryWords = rawQueryWords[:32]
	}
	titleWords := extractJobWordTokens(titleLower)
	if len(rawQueryWords) > 0 && containsJobTokenSequence(titleWords, rawQueryWords) {
		return "phrase"
	}
	if len(rawQueryWords) == 0 && strings.Contains(titleLower, normPhrase) {
		return "phrase"
	}

	var qTokens []string
	for _, t := range rawQueryWords {
		if len(t) >= 2 && !queryStopWords[t] {
			qTokens = append(qTokens, t)
		}
	}
	if len(qTokens) == 0 {
		if len(rawQueryWords) > 0 && containsJobTokenSequence(titleWords, rawQueryWords) {
			return "phrase"
		}
		return ""
	}
	allInTitle := true
	for _, qt := range qTokens {
		found := false
		for _, tw := range titleWords {
			if jobWordTokensMatch(tw, qt) {
				found = true
				break
			}
		}
		if !found {
			allInTitle = false
			break
		}
	}
	if allInTitle {
		return "all_tokens"
	}

	var distinctiveQ, icTokens []string
	queryHasICRole := false
	queryHasMgmtRole := false
	for _, qt := range qTokens {
		if !genericRoleTokens[qt] {
			distinctiveQ = append(distinctiveQ, qt)
		}
		if reICRoleWord.MatchString(qt) {
			queryHasICRole = true
			icTokens = append(icTokens, qt)
		}
		if reMgmtRoleWord.MatchString(qt) {
			queryHasMgmtRole = true
		}
	}

	titleHasMgmt := false
	for _, tw := range titleWords {
		if reMgmtRoleWord.MatchString(tw) {
			titleHasMgmt = true
			break
		}
	}
	titleHasIC := false
	for _, icTok := range icTokens {
		for _, tw := range titleWords {
			if jobWordTokensMatch(tw, icTok) {
				titleHasIC = true
				break
			}
		}
		if titleHasIC {
			break
		}
	}
	titleHasMgmtWithoutIC := queryHasICRole && !queryHasMgmtRole && titleHasMgmt && !titleHasIC

	if !titleHasMgmtWithoutIC && len(distinctiveQ) > 0 {
		allDistinctiveInTitle := true
		for _, qt := range distinctiveQ {
			found := false
			for _, tw := range titleWords {
				if jobWordTokensMatch(tw, qt) {
					found = true
					break
				}
			}
			if !found {
				allDistinctiveInTitle = false
				break
			}
		}
		if allDistinctiveInTitle {
			cappedSnippet := sliceUTF16Max(snippet, 2048)
			fullWords := append(append([]string{}, titleWords...), extractJobWordTokens(strings.ToLower(cappedSnippet))...)
			allInFull := true
			for _, qt := range qTokens {
				found := false
				for _, fw := range fullWords {
					if jobWordTokensMatch(fw, qt) {
						found = true
						break
					}
				}
				if !found {
					allInFull = false
					break
				}
			}
			if allInFull {
				return "all_tokens"
			}
		}
	}
	return ""
}

func matchesSingleGeoLocation(locStr, filterTerm string) bool {
	isUSFilter := filterTerm == "united states" || filterTerm == "usa" || filterTerm == "u.s." || filterTerm == "u.s.a." || filterTerm == "us"
	if !isUSFilter {
		return strings.Contains(locStr, filterTerm)
	}
	if reUSExplicit.MatchString(locStr) ||
		(reGeorgiaWord.MatchString(locStr) && !reTbilisiWord.MatchString(locStr)) ||
		reRemoteAmer.MatchString(locStr) {
		return true
	}
	if reCanadianLoc.MatchString(locStr) {
		return false
	}
	return reUSStateAbbr.MatchString(locStr)
}

// MatchesGeoLocationsFilter checks jobLocations against geographic filter tokens (including US state/city vs Canadian province disambiguation).
func MatchesGeoLocationsFilter(jobLocations, geoFilters []string) bool {
	if len(jobLocations) == 0 || len(geoFilters) == 0 {
		return false
	}
	capLocs := min(len(jobLocations), 32)
	parts := make([]string, 0, capLocs)
	for _, s := range jobLocations[:capLocs] {
		parts = append(parts, sliceUTF16Max(s, 256))
	}
	locStr := strings.TrimSpace(strings.ToLower(strings.Join(parts, " | ")))
	if locStr == "" {
		return false
	}
	capFilters := min(len(geoFilters), 32)
	for _, gf := range geoFilters[:capFilters] {
		if matchesSingleGeoLocation(locStr, sliceUTF16Max(gf, 128)) {
			return true
		}
	}
	return false
}

// IsJobLabelKnownStale checks whether an unparsed relative postedLabel (e.g. `30+ days ago`) is older than maxDays.
func IsJobLabelKnownStale(label string, maxDays float64) bool {
	if label == "" {
		return false
	}
	lm := reAgeLabel.FindStringSubmatch(label)
	if len(lm) < 4 {
		return false
	}
	unit := strings.ToLower(lm[3])
	mult := 1.0
	switch {
	case strings.HasPrefix(unit, "w"):
		mult = 7
	case strings.HasPrefix(unit, "m"):
		mult = 30
	case strings.HasPrefix(unit, "y"):
		mult = 365
	}
	base, err := strconv.ParseFloat(lm[1], 64)
	if err != nil {
		return false
	}
	minAgeDays := base * mult
	if lm[2] == "+" {
		return maxDays <= minAgeDays
	}
	return minAgeDays > maxDays
}

// JobExcludeEntry specifies a URL or company/title pattern to exclude from search results.
type JobExcludeEntry struct {
	Company string `json:"company"`
	Title   string `json:"title"`
	URL     string `json:"url"`
}

// FilterAndRankParams configures FilterAndRankJobs.
type FilterAndRankParams struct {
	Collected               []StructuredJobRecord `json:"collected"`
	Query                   string                `json:"query"`
	HasCompanyOrDomainScope bool                  `json:"hasCompanyOrDomainScope"`
	AllowedCompanyTokens    []string              `json:"allowedCompanyTokens"`
	AllowedBoardPrefixes    []string              `json:"allowedBoardPrefixes"`
	ExcludeList             []JobExcludeEntry     `json:"excludeList"`
	WantRemote              *bool                 `json:"wantRemote"`
	GeoLocationsFilter      []string              `json:"geoLocationsFilter"`
	MinBase                 *float64              `json:"minBase"`
	MinBaseMode             string                `json:"minBaseMode"`
	StrictPay               bool                  `json:"strictPay"`
	PostedWithinDays        *float64              `json:"postedWithinDays"`
	Limit                   int                   `json:"limit"`
	NowMs                   int64                 `json:"nowMs"`
}

// RankedJobIndex records the surviving source index and computed relevance/pay flags.
type RankedJobIndex struct {
	Index      int    `json:"index"`
	MatchedOn  string `json:"matchedOn"`
	PayUnknown bool   `json:"payUnknown,omitempty"`
}

// FilterAndRankResult holds both the full ranked StructuredJobRecord slice and index mapping.
type FilterAndRankResult struct {
	FinalJobs       []StructuredJobRecord `json:"finalJobs"`
	FinalIndices    []RankedJobIndex      `json:"finalIndices"`
	MatchedTotal    int                   `json:"matchedTotal"`
	PayUnknownCount *int                  `json:"payUnknownCount,omitempty"`
}

func parseJSCompatibleTimestampMs(raw string) (int64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		time.RFC1123Z,
		time.RFC1123,
	} {
		if t, err := time.Parse(layout, trimmed); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

// FilterAndRankJobs deduplicates, scopes, filters, and ranks collected job postings.
func FilterAndRankJobs(params FilterAndRankParams) FilterAndRankResult {
	nowMs := params.NowMs
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	var maxAgeCutoffMs *int64
	if params.PostedWithinDays != nil && *params.PostedWithinDays > 0 {
		cut := nowMs - int64(*params.PostedWithinDays*86_400_000)
		maxAgeCutoffMs = &cut
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}

	seenKeys := make(map[string]bool)
	seenURLs := make(map[string]bool)
	var matchedIndices []RankedJobIndex

	for idx, rawJob := range params.Collected {
		cleanURLKey := strings.ToLower(strings.TrimRight(rawJob.URL, "/"))
		dedupKey := CanonicalJobKey(rawJob.Company, rawJob.Title)
		if seenURLs[cleanURLKey] || seenKeys[dedupKey] {
			continue
		}

		if params.HasCompanyOrDomainScope && !MatchesAllowedCompanyOrDomain(rawJob, params.AllowedCompanyTokens, params.AllowedBoardPrefixes) {
			continue
		}

		excluded := false
		for _, ex := range params.ExcludeList {
			if ex.URL != "" && ex.URL == cleanURLKey {
				excluded = true
				break
			}
			compMatch := ex.Company != "" && strings.Contains(strings.ToLower(rawJob.Company), ex.Company)
			titleMatch := ex.Title != "" && strings.Contains(strings.ToLower(rawJob.Title), ex.Title)
			if (ex.Company != "" && ex.Title != "" && compMatch && titleMatch) || (ex.Company != "" && ex.Title == "" && compMatch) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		matchedOn := "company_filter"
		if params.Query != "" {
			qMatch := MatchesJobQueryRelevance(rawJob.Title, rawJob.Snippet, params.Query)
			if qMatch == "" {
				continue
			}
			matchedOn = qMatch
		}

		if params.WantRemote != nil && *params.WantRemote {
			hasRemLoc := false
			for _, l := range rawJob.Locations {
				if strings.Contains(strings.ToLower(l), "remote") {
					hasRemLoc = true
					break
				}
			}
			if rawJob.WorkplaceType != WorkplaceRemote && !hasRemLoc {
				continue
			}
		}

		if len(params.GeoLocationsFilter) > 0 && !MatchesGeoLocationsFilter(rawJob.Locations, params.GeoLocationsFilter) {
			continue
		}

		payUnknown := false
		if params.MinBase != nil {
			if rawJob.Pay == nil || rawJob.Pay.Currency != "USD" {
				if params.StrictPay {
					continue
				}
				payUnknown = true
			} else {
				if rawJob.Pay.Basis != PayBasisBase {
					continue
				}
				rawCompared := 0.0
				if params.MinBaseMode == "ceiling" || params.MinBaseMode == "overlap" {
					if rawJob.Pay.Max != nil {
						rawCompared = *rawJob.Pay.Max
					} else if rawJob.Pay.Min != nil {
						rawCompared = *rawJob.Pay.Min
					}
				} else {
					if rawJob.Pay.Min != nil {
						rawCompared = *rawJob.Pay.Min
					} else if rawJob.Pay.Max != nil {
						rawCompared = *rawJob.Pay.Max
					}
				}
				effPeriod := string(rawJob.Pay.Period)
				if effPeriod == "" {
					effPeriod = rawJob.Pay.Interval
				}
				annualMult := 1.0
				switch effPeriod {
				case "hour":
					annualMult = 2080
				case "day":
					annualMult = 260
				case "week":
					annualMult = 52
				case "month":
					annualMult = 12
				}
				comparedPay := rawCompared * annualMult
				if math.IsNaN(comparedPay) || math.IsInf(comparedPay, 0) || comparedPay < *params.MinBase {
					continue
				}
			}
		}

		if maxAgeCutoffMs != nil {
			if rawJob.PostedAt != nil && *rawJob.PostedAt != "" {
				parsedTs, okT := parseJSCompatibleTimestampMs(*rawJob.PostedAt)
				if !okT || parsedTs < *maxAgeCutoffMs {
					continue
				}
			} else if rawJob.PostedLabel != "" && params.PostedWithinDays != nil {
				if IsJobLabelKnownStale(rawJob.PostedLabel, *params.PostedWithinDays) {
					continue
				}
			}
		}

		seenURLs[cleanURLKey] = true
		seenKeys[dedupKey] = true
		matchedIndices = append(matchedIndices, RankedJobIndex{
			Index:      idx,
			MatchedOn:  matchedOn,
			PayUnknown: payUnknown,
		})
	}

	rankMatch := func(m string) int {
		switch m {
		case "phrase":
			return 0
		case "all_tokens":
			return 1
		default:
			return 2
		}
	}

	sort.SliceStable(matchedIndices, func(i, j int) bool {
		dm := rankMatch(matchedIndices[i].MatchedOn) - rankMatch(matchedIndices[j].MatchedOn)
		if dm != 0 {
			return dm < 0
		}
		if params.MinBase != nil && matchedIndices[i].PayUnknown != matchedIndices[j].PayUnknown {
			return !matchedIndices[i].PayUnknown
		}
		return false
	})

	matchedTotal := len(matchedIndices)
	finalIndices := matchedIndices
	if len(finalIndices) > limit {
		finalIndices = finalIndices[:limit]
	}

	finalJobs := make([]StructuredJobRecord, 0, len(finalIndices))
	unknownCount := 0
	for _, ri := range finalIndices {
		copied := params.Collected[ri.Index]
		if copied.Locations == nil {
			copied.Locations = []string{}
		}
		copied.MatchedOn = ri.MatchedOn
		copied.PayUnknown = ri.PayUnknown
		if ri.PayUnknown {
			unknownCount++
		}
		finalJobs = append(finalJobs, copied)
	}

	var payUnknownPtr *int
	if params.MinBase != nil {
		payUnknownPtr = intPtr(unknownCount)
	}

	if finalIndices == nil {
		finalIndices = []RankedJobIndex{}
	}
	return FilterAndRankResult{
		FinalJobs:       finalJobs,
		FinalIndices:    finalIndices,
		MatchedTotal:    matchedTotal,
		PayUnknownCount: payUnknownPtr,
	}
}

// MatchesScopedATSCandidateURL checks whether a search-discovered ATS URL belongs to the requested company/domain scope.
func MatchesScopedATSCandidateURL(u string, hasScope bool, allowedTokens []string, segmentedTokens []string, confirmedBoardURLs []string, companyFilter string) bool {
	if !hasScope || len(allowedTokens) == 0 {
		return true
	}
	cleanU := strings.ToLower(strings.TrimRight(u, "/"))
	for _, cb := range confirmedBoardURLs {
		if cb == cleanU {
			return true
		}
	}
	info := ClassifyFullBoardKey(u)
	srOrg, _, isSR := "", "", false
	if info == nil {
		srOrg, _, isSR = IsSmartRecruitersBoardURL(u)
	}
	srPostingSlug := ""
	if info == nil && !isSR {
		if m := reSRPostingPath.FindStringSubmatch(u); len(m) >= 2 {
			srPostingSlug = m[1]
		}
	}
	tenantSlug := ""
	if info != nil {
		tenantSlug = strings.ToLower(strings.Split(info.Slug, "/")[0])
	} else if srOrg != "" {
		tenantSlug = strings.ToLower(srOrg)
	} else if srPostingSlug != "" {
		tenantSlug = strings.ToLower(srPostingSlug)
	}
	if tenantSlug == "" {
		return true
	}

	segMap := make(map[string]bool, len(segmentedTokens))
	for _, st := range segmentedTokens {
		segMap[st] = true
	}
	host := ""
	allowAshby := false
	if info != nil && info.Platform == "ashby" {
		host = "jobs.ashbyhq.com"
		allowAshby = true
	}
	for _, tok := range allowedTokens {
		normTok := reNonAlnumSplit.ReplaceAllString(strings.ToLower(tok), "")
		if normTok != "" && MatchesATSTenantSlugAgainstToken(tenantSlug, normTok, TenantSlugMatchOptions{
			Host:             host,
			JobCompany:       companyFilter,
			SegmentedTokens:  segMap,
			AllowAshbySpaces: allowAshby,
		}) {
			return true
		}
	}
	return false
}
