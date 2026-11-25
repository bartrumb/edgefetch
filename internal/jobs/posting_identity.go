package jobs

import (
	"sort"
	"strings"
)

type ATSPostingIdentity struct {
	Platform   string   `json:"platform"`
	Slug       string   `json:"slug"`
	BoardURL   string   `json:"boardUrl"`
	PostingID  string   `json:"postingId"`
	RoleTokens []string `json:"roleTokens"`
}

func tokenizeRoleSlug(slugOrPath, excludeSlug string) []string {
	stop := map[string]bool{
		"job": true, "jobs": true, "apply": true, "application": true,
		"careers": true, "postings": true, "senior": true, "lead": true,
		"the": true, "and": true, "for": true,
	}
	if excludeSlug != "" {
		for _, part := range reNonAlnumSplit.Split(strings.ToLower(sliceUTF16Max(excludeSlug, 256)), -1) {
			if len(part) >= 2 {
				stop[part] = true
			}
		}
	}
	matches := reRoleAlpha3.FindAllString(strings.ToLower(sliceUTF16Max(slugOrPath, 512)), -1)
	out := make([]string, 0, min(len(matches), 32))
	for _, w := range matches {
		if !stop[w] {
			out = append(out, w)
			if len(out) >= 32 {
				break
			}
		}
	}
	return out
}

// ParseATSPostingIdentity parses a saved ATS posting URL into `(platform, slug, boardUrl, postingId, roleTokens)`.
func ParseATSPostingIdentity(urlStr string) *ATSPostingIdentity {
	u, ok := parseStrictURL(urlStr)
	if !ok || !strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	q := u.Query()
	if strings.HasSuffix(host, ".greenhouse.io") && strings.EqualFold(q.Get("error"), "true") {
		return nil
	}
	parts := splitCleanPathSegments(u.EscapedPath())

	isGHUS := host == "boards.greenhouse.io" || host == "job-boards.greenhouse.io"
	isGHEU := host == "eu-boards.greenhouse.io" || host == "job-boards.eu.greenhouse.io"
	if (isGHUS || isGHEU) && len(parts) >= 1 {
		org := parts[0]
		ghJid := q.Get("gh_jid")
		postingID := ""
		if len(parts) >= 3 && parts[1] == "jobs" {
			postingID = parts[2]
		} else if reDigitsOnly.MatchString(ghJid) {
			postingID = ghJid
		}
		if postingID != "" && IsValidATSSlug(org) {
			boardHost := "job-boards.greenhouse.io"
			if isGHEU {
				boardHost = "job-boards.eu.greenhouse.io"
			}
			roleSrc := u.EscapedPath()
			if len(parts) > 2 {
				roleSrc = strings.Join(parts[2:], "-")
			}
			return &ATSPostingIdentity{
				Platform:   "greenhouse",
				Slug:       org,
				BoardURL:   "https://" + boardHost + "/" + org,
				PostingID:  postingID,
				RoleTokens: tokenizeRoleSlug(roleSrc, org),
			}
		}
	}
	if ghQueryID := q.Get("gh_jid"); ghQueryID != "" && reDigitsOnly.MatchString(ghQueryID) {
		stripped := reCareerHostPfx.ReplaceAllString(host, "")
		baseCo := strings.Split(stripped, ".")[0]
		if IsValidATSSlug(baseCo) {
			return &ATSPostingIdentity{
				Platform:   "greenhouse",
				Slug:       baseCo,
				BoardURL:   "https://job-boards.greenhouse.io/" + baseCo,
				PostingID:  ghQueryID,
				RoleTokens: tokenizeRoleSlug(u.EscapedPath(), baseCo),
			}
		}
	}

	if host == "jobs.ashbyhq.com" && len(parts) >= 2 && !strings.EqualFold(parts[1], "jobs") && !strings.EqualFold(parts[1], "application") {
		orgDec, ok1 := DecodeURIComponent(parts[0])
		jobDec, ok2 := DecodeURIComponent(parts[1])
		if !ok1 || !ok2 {
			return nil
		}
		org := strings.TrimSpace(orgDec)
		jobID := strings.TrimSpace(jobDec)
		if jobID != "" && IsValidAshbySlug(org) {
			return &ATSPostingIdentity{
				Platform:   "ashby",
				Slug:       org,
				BoardURL:   "https://jobs.ashbyhq.com/" + EncodeURIComponent(org),
				PostingID:  jobID,
				RoleTokens: []string{},
			}
		}
	}

	if (host == "jobs.lever.co" || host == "jobs.eu.lever.co") && len(parts) >= 2 {
		orgDec, ok1 := DecodeURIComponent(parts[0])
		if !ok1 {
			return nil
		}
		org := strings.TrimSpace(orgDec)
		if IsValidATSSlug(org) {
			return &ATSPostingIdentity{
				Platform:   "lever",
				Slug:       org,
				BoardURL:   "https://" + host + "/" + org,
				PostingID:  parts[1],
				RoleTokens: []string{},
			}
		}
	}

	if wdMatch := reWorkdayHost.FindStringSubmatch(host); len(wdMatch) >= 2 && len(parts) >= 3 {
		tenant := wdMatch[1]
		idx := 0
		if reLocaleSegment.MatchString(parts[0]) {
			idx = 1
		}
		if idx < len(parts) {
			site := parts[idx]
			rest := parts[idx+1:]
			if site != "" && len(rest) >= 2 && rest[0] == "job" {
				tailSeg := rest[len(rest)-1]
				return &ATSPostingIdentity{
					Platform:   "workday",
					Slug:       tenant + "/" + site,
					BoardURL:   "https://" + host + "/" + site,
					PostingID:  tailSeg,
					RoleTokens: tokenizeRoleSlug(tailSeg, ""),
				}
			}
		}
	}

	if host == "apply.workable.com" && len(parts) >= 3 && parts[1] == "j" {
		return &ATSPostingIdentity{
			Platform:   "workable",
			Slug:       parts[0],
			BoardURL:   "https://apply.workable.com/" + parts[0] + "/",
			PostingID:  parts[2],
			RoleTokens: []string{},
		}
	}

	if host == "jobs.gem.com" && len(parts) >= 2 {
		return &ATSPostingIdentity{
			Platform:   "gem",
			Slug:       parts[0],
			BoardURL:   "https://jobs.gem.com/" + parts[0],
			PostingID:  parts[1],
			RoleTokens: []string{},
		}
	}

	if host == "ats.rippling.com" && len(parts) >= 3 {
		idx := 0
		if reLocaleSegment.MatchString(parts[0]) {
			idx = 1
		}
		if idx < len(parts) {
			org := parts[idx]
			rest := parts[idx+1:]
			if org != "" && len(rest) >= 2 && rest[0] == "jobs" && rest[1] != "" {
				return &ATSPostingIdentity{
					Platform:   "rippling",
					Slug:       org,
					BoardURL:   "https://ats.rippling.com/" + org + "/jobs",
					PostingID:  rest[1],
					RoleTokens: []string{},
				}
			}
		}
	}

	if pm := rePinpointHost.FindStringSubmatch(host); len(pm) >= 2 && len(parts) >= 2 && parts[0] == "postings" {
		return &ATSPostingIdentity{
			Platform:   "pinpoint",
			Slug:       pm[1],
			BoardURL:   "https://" + host + "/",
			PostingID:  parts[1],
			RoleTokens: tokenizeRoleSlug(parts[1], ""),
		}
	}
	if bm := reBambooHost.FindStringSubmatch(host); len(bm) >= 2 && len(parts) >= 2 && parts[0] == "careers" {
		return &ATSPostingIdentity{
			Platform:   "bamboohr",
			Slug:       bm[1],
			BoardURL:   "https://" + host + "/careers",
			PostingID:  parts[1],
			RoleTokens: []string{},
		}
	}
	if rm := reRecruiteeHost.FindStringSubmatch(host); len(rm) >= 2 && len(parts) >= 2 && parts[0] == "o" {
		return &ATSPostingIdentity{
			Platform:   "recruitee",
			Slug:       rm[1],
			BoardURL:   "https://" + host + "/",
			PostingID:  parts[1],
			RoleTokens: tokenizeRoleSlug(parts[1], ""),
		}
	}
	if im := reICIMSHost.FindStringSubmatch(host); len(im) >= 2 && len(parts) >= 2 && parts[0] == "jobs" && reDigitsOnly.MatchString(parts[1]) {
		tail := ""
		if len(parts) > 2 {
			tail = strings.Join(parts[2:], "-")
		}
		return &ATSPostingIdentity{
			Platform:   "icims",
			Slug:       im[1],
			BoardURL:   "https://" + host + "/jobs/search?ss=1&in_iframe=1",
			PostingID:  parts[1],
			RoleTokens: tokenizeRoleSlug(tail, ""),
		}
	}
	return nil
}

// SimilarRole holds an open role suggested when a saved posting is closed.
type SimilarRole struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// FindSimilarRoles scores open roles against roleTokens extracted from a closed posting URL.
func FindSimilarRoles(openRoles []SimilarRole, roleTokens []string) []SimilarRole {
	if len(openRoles) == 0 || len(roleTokens) == 0 {
		return []SimilarRole{}
	}
	seenTok := make(map[string]bool)
	var uniqueTokens []string
	allTokensGeneric := true
	for _, tok := range roleTokens {
		if !seenTok[tok] {
			seenTok[tok] = true
			uniqueTokens = append(uniqueTokens, tok)
			if !genericRoleTokens[tok] {
				allTokensGeneric = false
			}
			if len(uniqueTokens) >= 32 {
				break
			}
		}
	}
	bounded := openRoles
	if len(bounded) > 500 {
		bounded = bounded[:500]
	}
	type scoredRole struct {
		role  SimilarRole
		score int
		idx   int
	}
	var scored []scoredRole
	for idx, r := range bounded {
		titleWords := make(map[string]bool)
		for _, w := range reTitleAlnum2.FindAllString(strings.ToLower(sliceUTF16Max(r.Title, 256)), -1) {
			titleWords[w] = true
		}
		distinctiveHits := 0
		genericHits := 0
		for _, tok := range uniqueTokens {
			if !titleWords[tok] {
				continue
			}
			if genericRoleTokens[tok] {
				genericHits++
			} else {
				distinctiveHits++
			}
		}
		totalHits := distinctiveHits + genericHits
		qualifies := distinctiveHits >= 2 ||
			(distinctiveHits >= 1 && totalHits >= 2) ||
			(distinctiveHits >= 1 && len(uniqueTokens) == 1) ||
			(distinctiveHits == 0 && genericHits >= 2 && allTokensGeneric)
		if qualifies {
			scored = append(scored, scoredRole{role: r, score: distinctiveHits*3 + genericHits, idx: idx})
		}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	limit := min(len(scored), 3)
	out := make([]SimilarRole, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, scored[i].role)
	}
	return out
}

// IsKnownATSPostingHostWithUnresolvedSlug checks if urlStr targets a known ATS host whose slug failed normal parsing.
func IsKnownATSPostingHostWithUnresolvedSlug(urlStr string) (platform, rawSlug string, ok bool) {
	u, valid := parseStrictURL(urlStr)
	if !valid {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	parts := splitCleanPathSegments(u.EscapedPath())
	first := ""
	if len(parts) > 0 {
		dec, okD := DecodeURIComponent(parts[0])
		if !okD {
			return "", "", false
		}
		first = strings.TrimSpace(dec)
	}
	switch {
	case host == "jobs.ashbyhq.com":
		return "ashby", first, true
	case strings.HasSuffix(host, ".greenhouse.io"):
		return "greenhouse", first, true
	case host == "jobs.lever.co" || host == "jobs.eu.lever.co":
		return "lever", first, true
	case host == "apply.workable.com":
		return "workable", first, true
	case host == "jobs.gem.com":
		return "gem", first, true
	case host == "ats.rippling.com":
		return "rippling", first, true
	default:
		return "", "", false
	}
}

// FallbackBoard describes a compact or hyphenated slug fallback board URL.
type FallbackBoard struct {
	Slug     string `json:"slug"`
	BoardURL string `json:"boardUrl"`
}

// BuildCompactSlugFallbackBoards builds compact and hyphenated board URL fallbacks for space-bearing display slugs.
func BuildCompactSlugFallbackBoards(platform, slug string) []FallbackBoard {
	if !strings.ContainsAny(slug, " \t\r\n") {
		return []FallbackBoard{}
	}
	compact := strings.ToLower(reMultiSpacesJobs.ReplaceAllString(slug, ""))
	hyphenated := strings.ToLower(reMultiSpacesJobs.ReplaceAllString(slug, "-"))
	var cands []string
	for _, s := range []string{compact, hyphenated} {
		if s != "" && IsValidATSSlug(s) && !containsString(cands, s) {
			cands = append(cands, s)
		}
	}
	var out []FallbackBoard
	for _, cand := range cands {
		switch platform {
		case "ashby":
			out = append(out, FallbackBoard{Slug: cand, BoardURL: "https://jobs.ashbyhq.com/" + EncodeURIComponent(cand)})
		case "greenhouse":
			out = append(out, FallbackBoard{Slug: cand, BoardURL: "https://job-boards.greenhouse.io/" + cand})
		case "lever":
			out = append(out, FallbackBoard{Slug: cand, BoardURL: "https://jobs.lever.co/" + cand})
		case "workable":
			out = append(out, FallbackBoard{Slug: cand, BoardURL: "https://apply.workable.com/" + cand + "/"})
		case "gem":
			out = append(out, FallbackBoard{Slug: cand, BoardURL: "https://jobs.gem.com/" + cand})
		case "rippling":
			out = append(out, FallbackBoard{Slug: cand, BoardURL: "https://ats.rippling.com/" + cand + "/jobs"})
		}
	}
	return out
}

// FullBoardKeyInfo classifies an ATS URL into its canonical board key and whether the URL itself is the parent board.
type FullBoardKeyInfo struct {
	Key      string `json:"key"`
	Platform string `json:"platform"`
	Slug     string `json:"slug"`
	IsBoard  bool   `json:"isBoard"`
	BoardURL string `json:"boardUrl"`
}

// ClassifyFullBoardKey classifies an ATS board or posting URL into its parent board key and canonical board URL.
func ClassifyFullBoardKey(urlStr string) *FullBoardKeyInfo {
	u, ok := parseStrictURL(urlStr)
	if !ok || !strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	parts := splitCleanPathSegments(u.EscapedPath())
	q := u.Query()

	if host == "jobs.ashbyhq.com" && len(parts) >= 1 {
		orgDec, okD := DecodeURIComponent(parts[0])
		if !okD {
			return nil
		}
		org := strings.TrimSpace(orgDec)
		if !IsValidAshbySlug(org) {
			return nil
		}
		isBoard := len(parts) == 1 || (len(parts) == 2 && strings.EqualFold(parts[1], "jobs"))
		return &FullBoardKeyInfo{
			Key:      "ashby:" + strings.ToLower(org),
			Platform: "ashby",
			Slug:     org,
			IsBoard:  isBoard,
			BoardURL: "https://jobs.ashbyhq.com/" + EncodeURIComponent(org),
		}
	}

	isGHUS := host == "boards.greenhouse.io" || host == "job-boards.greenhouse.io"
	isGHEU := host == "eu-boards.greenhouse.io" || host == "job-boards.eu.greenhouse.io"
	if (isGHUS || isGHEU) && len(parts) >= 1 {
		isEmbedPath := strings.EqualFold(parts[0], "embed")
		org := parts[0]
		if isEmbedPath {
			org = strings.TrimSpace(q.Get("for"))
		}
		if org == "" || !IsValidATSSlug(org) {
			return nil
		}
		canonicalHost := "job-boards.greenhouse.io"
		if isGHEU {
			canonicalHost = "job-boards.eu.greenhouse.io"
		}
		isErrorRedirect := strings.EqualFold(q.Get("error"), "true")
		return &FullBoardKeyInfo{
			Key:      "greenhouse:" + strings.ToLower(org),
			Platform: "greenhouse",
			Slug:     org,
			IsBoard:  len(parts) == 1 && !q.Has("gh_jid") && !isErrorRedirect && !isEmbedPath,
			BoardURL: "https://" + canonicalHost + "/" + org,
		}
	}

	if (host == "jobs.lever.co" || host == "jobs.eu.lever.co") && len(parts) >= 1 {
		org := parts[0]
		if !IsValidATSSlug(org) {
			return nil
		}
		return &FullBoardKeyInfo{
			Key:      "lever:" + strings.ToLower(org),
			Platform: "lever",
			Slug:     org,
			IsBoard:  len(parts) == 1,
			BoardURL: "https://" + host + "/" + org,
		}
	}

	if host == "ats.rippling.com" && len(parts) >= 1 {
		idx := 0
		if len(parts) >= 2 && reLocaleSegment.MatchString(parts[0]) {
			idx = 1
		}
		if idx < len(parts) {
			org := parts[idx]
			rest := parts[idx+1:]
			if org != "" && IsValidATSSlug(org) {
				isBoard := len(rest) == 0 || (len(rest) == 1 && rest[0] == "jobs")
				return &FullBoardKeyInfo{
					Key:      "rippling:" + strings.ToLower(org),
					Platform: "rippling",
					Slug:     org,
					IsBoard:  isBoard,
					BoardURL: "https://ats.rippling.com/" + org + "/jobs",
				}
			}
		}
	}

	if host == "apply.workable.com" && len(parts) >= 1 && IsValidATSSlug(parts[0]) {
		return &FullBoardKeyInfo{
			Key:      "workable:" + strings.ToLower(parts[0]),
			Platform: "workable",
			Slug:     parts[0],
			IsBoard:  len(parts) == 1,
			BoardURL: "https://apply.workable.com/" + parts[0] + "/",
		}
	}

	if host == "jobs.gem.com" && len(parts) >= 1 && IsValidATSSlug(parts[0]) {
		return &FullBoardKeyInfo{
			Key:      "gem:" + strings.ToLower(parts[0]),
			Platform: "gem",
			Slug:     parts[0],
			IsBoard:  len(parts) == 1,
			BoardURL: "https://jobs.gem.com/" + parts[0],
		}
	}

	if wdMatch := reFullBoardWDHost.FindStringSubmatch(host); len(wdMatch) >= 2 && len(parts) >= 1 {
		tenant := strings.ToLower(wdMatch[1])
		site := ""
		var rest []string
		if len(parts) >= 4 && strings.EqualFold(parts[0], "wday") && strings.EqualFold(parts[1], "cxs") {
			if parts[2] != "" {
				tenant = strings.ToLower(parts[2])
			}
			site = parts[3]
			rest = parts[4:]
		} else {
			idx := 0
			if len(parts) >= 2 && reLocaleSegment.MatchString(parts[0]) {
				idx = 1
			}
			if idx < len(parts) {
				site = parts[idx]
				rest = parts[idx+1:]
			}
		}
		if site != "" && !strings.EqualFold(site, "wday") && reWorkdaySiteIdent.MatchString(site) {
			return &FullBoardKeyInfo{
				Key:      "workday:" + tenant + ":" + strings.ToLower(site),
				Platform: "workday",
				Slug:     tenant + "/" + site,
				IsBoard:  len(rest) == 0,
				BoardURL: "https://" + host + "/" + site,
			}
		}
	}
	return nil
}

// IsSmartRecruitersBoardURL checks if urlStr is a root SmartRecruiters company board URL (`https://jobs.smartrecruiters.com/{Org}`).
func IsSmartRecruitersBoardURL(urlStr string) (org, boardURL string, ok bool) {
	u, valid := parseStrictURL(urlStr)
	if !valid || !strings.EqualFold(u.Scheme, "https") || !strings.EqualFold(u.Hostname(), "jobs.smartrecruiters.com") {
		return "", "", false
	}
	parts := splitCleanPathSegments(u.EscapedPath())
	if len(parts) == 1 && IsValidATSSlug(parts[0]) {
		dec, okD := DecodeURIComponent(parts[0])
		if !okD {
			return "", "", false
		}
		return dec, "https://jobs.smartrecruiters.com/" + parts[0], true
	}
	return "", "", false
}

// ExtractWorkdayReqID extracts the trailing `_<reqId>` token from a Workday job posting URL.
func ExtractWorkdayReqID(uStr string) string {
	if uStr == "" {
		return ""
	}
	bounded := sliceUTF16Max(uStr, 2048)
	pathPart := bounded
	if idx := strings.IndexAny(bounded, "?#\r\n\u2028\u2029"); idx >= 0 {
		pathPart = bounded[:idx]
	}
	pathPart = strings.TrimRight(pathPart, "/")
	tail := pathPart
	if lastSlash := strings.LastIndexByte(pathPart, '/'); lastSlash >= 0 {
		tail = pathPart[lastSlash+1:]
	}
	lastUnder := strings.LastIndexByte(tail, '_')
	if lastUnder < 0 || lastUnder+1 >= len(tail) {
		return ""
	}
	req := tail[lastUnder+1:]
	if len(req) <= 96 && reWorkdayReqTail.MatchString(req) {
		return strings.ToLower(req)
	}
	return ""
}
