package jobs

import (
	"strings"
)

var (
	junkATSSlugs = map[string]bool{
		"embed": true, "__assets__": true, "api": true, "v0": true, "v1": true, "v2": true, "v3": true,
		"static": true, "assets": true, "cdn": true, "js": true, "css": true, "www": true, "app": true,
		"resources": true, "help": true, "docs": true, "documentation": true, "developers": true,
		"support": true, "blog": true, "status": true, "login": true, "signin": true, "internal": true,
		"careers": true, "jobs": true, "favicon.ico": true,
	}

	genericRoleTokens = map[string]bool{
		"engineer": true, "engineering": true, "developer": true, "software": true, "manager": true,
		"director": true, "staff": true, "principal": true, "specialist": true, "analyst": true,
		"associate": true, "intern": true, "consultant": true, "architect": true, "designer": true,
		"product": true, "operations": true, "systems": true, "technical": true, "remote": true,
		"hybrid": true, "junior": true, "senior": true, "lead": true,
	}

	reValidATSSlugSeg  = newLazyRegexp(`(?i)^[a-z0-9][a-z0-9_.-]*$`)
	reValidAshbySlug   = newLazyRegexp(`(?i)^[a-z0-9](?:[a-z0-9_.-]| [a-z0-9_.-]){0,79}$`)
	reVendorHomeHost   = newLazyRegexp(`(?i)^(?:www\.)?(?:bamboohr\.com|breezy\.hr|applytojob\.com|recruitee\.com|pinpointhq\.com)$`)
	reHTMLAmpEntity    = newLazyRegexp(`(?i)&(?:amp|#0*38|#x0*26);`)
	reJSONEscapedSlash = newLazyRegexp(`\\u002[fF]|\\/`)

	reDiscGHBoard     = newLazyRegexp(`(?i)(?:https?:)?//((?:job-boards|boards|eu-boards|job-boards\.eu)\.greenhouse\.io)/(?:embed/job_board(?:/js)?\?for=([A-Za-z0-9_-]+)|([A-Za-z0-9_-]+))`)
	reDiscGHAPI       = newLazyRegexp(`(?i)(?:https?:)?//(boards-api(?:\.eu)?\.greenhouse\.io)/v1/boards/([A-Za-z0-9_-]+)`)
	reDiscAshby       = newLazyRegexp(`(?i)(?:https?:)?//(?:jobs\.ashbyhq\.com|api\.ashbyhq\.com/posting-api/job-board)/((?:[A-Za-z0-9_.-]|%20)+)`)
	reDiscLever       = newLazyRegexp(`(?i)(?:https?:)?//(jobs(?:\.eu)?\.lever\.co)/([A-Za-z0-9_.-]+)`)
	reDiscWorkday     = newLazyRegexp(`(?i)(?:https?:)?//(([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com)/([A-Za-z0-9_/-]+)`)
	reDiscWorkable    = newLazyRegexp(`(?i)https?://apply\.workable\.com/([A-Za-z0-9_-]+)`)
	reDiscGem         = newLazyRegexp(`(?i)https?://jobs\.gem\.com/([A-Za-z0-9_-]+)`)
	reDiscRippling    = newLazyRegexp(`(?i)https?://ats\.rippling\.com/(?:[a-z]{2}(?:-[A-Za-z]{2,4})?/)?([A-Za-z0-9_-]+)`)
	reDiscPinpoint    = newLazyRegexp(`(?i)https?://([a-z0-9-]+)\.pinpointhq\.com\b`)
	reDiscTeamtailor  = newLazyRegexp(`(?i)https?://(([a-z0-9-]+)(?:\.[a-z]{2})?\.teamtailor\.com)\b`)
	reDiscBambooHR    = newLazyRegexp(`(?i)https?://([a-z0-9-]+)\.bamboohr\.com/(?:careers|jobs)`)
	reDiscBreezy      = newLazyRegexp(`(?i)https?://([a-z0-9-]+)\.breezy\.hr\b`)
	reDiscRecruitee   = newLazyRegexp(`(?i)https?://([a-z0-9-]+)\.recruitee\.com\b`)
	reDiscJazzHR      = newLazyRegexp(`(?i)https?://([a-z0-9-]+)\.applytojob\.com\b`)
	reDiscPersonio    = newLazyRegexp(`(?i)https?://(([a-z0-9-]+)\.jobs\.personio\.(?:de|com))\b`)
	reDiscSmartRec    = newLazyRegexp(`(?i)https?://jobs\.smartrecruiters\.com/([A-Za-z0-9_-]+)`)
	reDiscJobvite     = newLazyRegexp(`(?i)https?://jobs\.jobvite\.com/([A-Za-z0-9_-]+)`)
	reDiscICIMS       = newLazyRegexp(`(?i)https?://([a-z0-9-]+)\.icims\.com/jobs\b`)
	reFullBoardWDHost = newLazyRegexp(`(?i)^([a-z0-9-]+)\.wd\d+\.myworkday(?:jobs|site)\.com$`)

	reInferICIMSHost = newLazyRegexp(`(?i)^(?:(?:careers|jobs|external|hub|global)-)?([a-z0-9-]+?)(?:-(?:careers|jobs|portal))?\.icims\.com$`)
	reInferSubATSHst = newLazyRegexp(`(?i)^(?:careers-|jobs-)?([a-z0-9-]+)\.(?:pinpointhq\.com|pinpoint\.hq|bamboohr\.com|breezy\.hr|recruitee\.com|applytojob\.com|jazzhr\.(?:com|co)|(?:[a-z]{2}\.)?teamtailor\.com|(?:jobs\.)?personio\.(?:de|com)|eightfold\.ai|avature\.net|taleo\.net|homerun\.co|traffit\.com|zohorecruit\.com|freshteam\.com|comeet\.com)$`)
	reCareerHostPfx  = newLazyRegexp(`(?i)^(?:www|jobs|careers)\.`)
	reGenericSubATS  = newLazyRegexp(`(?i)^(?:www|jobs|careers|apply|search|login|app)$`)
	reRoleAlpha3     = newLazyRegexp(`[a-z]{3,}`)
	reTitleAlnum2    = newLazyRegexp(`[a-z0-9]{2,}`)
	reNonAlnumSplit  = newLazyRegexp(`[^a-z0-9]+`)
	rePinpointHost   = newLazyRegexp(`(?i)^([a-z0-9-]+)\.pinpointhq\.com$`)
	reBambooHost     = newLazyRegexp(`(?i)^([a-z0-9-]+)\.bamboohr\.com$`)
	reRecruiteeHost  = newLazyRegexp(`(?i)^([a-z0-9-]+)\.recruitee\.com$`)
	reICIMSHost      = newLazyRegexp(`(?i)^([a-z0-9-]+)\.icims\.com$`)
	reSRPostingPath  = newLazyRegexp(`(?i)^https://jobs\.smartrecruiters\.com/([A-Za-z0-9_.-]+)/`)
	reWorkdayReqTail = newLazyRegexp(`^[A-Za-z0-9-]+$`)
)

// IsValidATSSlug checks whether an ATS board slug (1 or 2 `/`-separated segments) is non-junk and structurally valid.
func IsValidATSSlug(slug string) bool {
	parts := strings.Split(strings.TrimSpace(slug), "/")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	for _, seg := range parts {
		s := strings.ToLower(seg)
		if len(s) < 2 || len(s) > 80 {
			return false
		}
		if junkATSSlugs[s] || strings.HasPrefix(s, "internal-") || strings.HasPrefix(s, "_") {
			return false
		}
		if !reValidATSSlugSeg.MatchString(s) {
			return false
		}
	}
	return true
}

// IsValidAshbySlug checks Ashby organization slugs, permitting single internal spaces (e.g. `Hippocratic AI`).
func IsValidAshbySlug(slug string) bool {
	s := strings.TrimSpace(slug)
	if len(s) < 2 || len(s) > 80 {
		return false
	}
	low := strings.ToLower(s)
	if junkATSSlugs[low] || strings.HasPrefix(low, "internal-") || strings.HasPrefix(low, "_") {
		return false
	}
	return reValidAshbySlug.MatchString(s)
}

// ClassifyBoardStatusParams configures ClassifyATSBoardStatus.
type ClassifyBoardStatusParams struct {
	HTTPStatus   int    `json:"httpStatus"`
	RequestedURL string `json:"requestedUrl"`
	FinalURL     string `json:"finalUrl,omitempty"`
	ContentState string `json:"contentState,omitempty"`
	JobCount     int    `json:"jobCount,omitempty"`
}

// ClassifyATSBoardStatus classifies an ATS board HTTP response into `ok`, `empty_board`, `wrong_slug`, or `blocked_or_down`.
func ClassifyATSBoardStatus(params ClassifyBoardStatusParams) ATSBoardStatus {
	if params.HTTPStatus == 404 || params.HTTPStatus == 410 || params.ContentState == "soft_404" {
		return BoardStatusWrongSlug
	}
	if params.HTTPStatus == 401 || params.HTTPStatus == 403 || params.HTTPStatus == 422 || params.HTTPStatus == 429 || params.HTTPStatus >= 500 || params.HTTPStatus == 0 {
		return BoardStatusBlockedOrDown
	}
	if params.FinalURL != "" {
		reqU, ok1 := parseStrictURL(params.RequestedURL)
		finU, ok2 := parseStrictURL(params.FinalURL)
		if ok1 && ok2 {
			finHost := strings.ToLower(finU.Hostname())
			if (!strings.EqualFold(reqU.Hostname(), finHost) && reVendorHomeHost.MatchString(finHost)) ||
				(strings.Contains(finHost, "greenhouse.io") && finU.Query().Get("error") == "true") {
				return BoardStatusWrongSlug
			}
		}
	}
	if params.JobCount > 0 {
		return BoardStatusOK
	}
	return BoardStatusEmptyBoard
}

// DiscoverBoardsParams configures DiscoverATSBoardsFromHTML.
type DiscoverBoardsParams struct {
	SourceURL string   `json:"sourceUrl"`
	FinalURL  string   `json:"finalUrl,omitempty"`
	RawHTML   string   `json:"rawHtml,omitempty"`
	Links     []string `json:"links,omitempty"`
}

// DiscoverATSBoardsFromHTML scans a company `/careers` or `/jobs` page for 16+ ATS platforms.
func DiscoverATSBoardsFromHTML(params DiscoverBoardsParams) []DiscoveredATSBoard {
	unescapedHTML := reHTMLAmpEntity.ReplaceAllString(reJSONEscapedSlash.ReplaceAllString(params.RawHTML, "/"), "&")
	corpusParts := make([]string, 0, len(params.Links)+2)
	corpusParts = append(corpusParts, params.FinalURL)
	corpusParts = append(corpusParts, params.Links...)
	corpusParts = append(corpusParts, unescapedHTML)
	corpus := strings.Join(corpusParts, "\n")

	var order []string
	found := make(map[string]DiscoveredATSBoard)

	addBoard := func(platform, slug, boardURL string) {
		if !IsValidATSSlug(slug) {
			return
		}
		key := platform + ":" + strings.ToLower(slug)
		if !hasKey(found, key) {
			found[key] = DiscoveredATSBoard{
				Platform:       platform,
				Slug:           slug,
				BoardURL:       boardURL,
				DiscoveredFrom: params.SourceURL,
			}
			order = append(order, key)
		}
	}

	for _, m := range reDiscGHBoard.FindAllStringSubmatch(corpus, -1) {
		ghHost := strings.ToLower(m[1])
		slug := firstNonEmpty(m[2], m[3])
		canonicalHost := "job-boards.greenhouse.io"
		if strings.Contains(ghHost, "eu") {
			canonicalHost = "job-boards.eu.greenhouse.io"
		}
		addBoard("greenhouse", slug, "https://"+canonicalHost+"/"+slug)
	}
	for _, m := range reDiscGHAPI.FindAllStringSubmatch(corpus, -1) {
		canonicalHost := "job-boards.greenhouse.io"
		if strings.Contains(strings.ToLower(m[1]), ".eu.") {
			canonicalHost = "job-boards.eu.greenhouse.io"
		}
		addBoard("greenhouse", m[2], "https://"+canonicalHost+"/"+m[2])
	}
	for _, m := range reDiscAshby.FindAllStringSubmatch(corpus, -1) {
		dec, ok := DecodeURIComponent(m[1])
		if !ok {
			continue
		}
		ashbyOrg := strings.TrimSpace(dec)
		if IsValidAshbySlug(ashbyOrg) {
			key := "ashby:" + strings.ToLower(ashbyOrg)
			if !hasKey(found, key) {
				found[key] = DiscoveredATSBoard{
					Platform:       "ashby",
					Slug:           ashbyOrg,
					BoardURL:       "https://jobs.ashbyhq.com/" + EncodeURIComponent(ashbyOrg),
					DiscoveredFrom: params.SourceURL,
				}
				order = append(order, key)
			}
		}
	}
	for _, m := range reDiscLever.FindAllStringSubmatch(corpus, -1) {
		addBoard("lever", m[2], "https://"+strings.ToLower(m[1])+"/"+m[2])
	}
	for _, m := range reDiscWorkday.FindAllStringSubmatch(corpus, -1) {
		wdHost := strings.ToLower(m[1])
		tenant := m[2]
		segs := splitCleanPathSegments(m[3])
		site := ""
		if len(segs) >= 4 && strings.EqualFold(segs[0], "wday") && strings.EqualFold(segs[1], "cxs") {
			if segs[2] != "" {
				tenant = segs[2]
			}
			site = segs[3]
		} else if len(segs) > 0 {
			siteIdx := 0
			if len(segs) >= 2 && reLocaleSegment.MatchString(segs[0]) {
				siteIdx = 1
			}
			site = segs[siteIdx]
		}
		if site != "" && !strings.EqualFold(site, "wday") && IsValidATSSlug(tenant) {
			addBoard("workday", tenant+"/"+site, "https://"+wdHost+"/"+site)
		}
	}
	for _, m := range reDiscWorkable.FindAllStringSubmatch(corpus, -1) {
		addBoard("workable", m[1], "https://apply.workable.com/"+m[1]+"/")
	}
	for _, m := range reDiscGem.FindAllStringSubmatch(corpus, -1) {
		addBoard("gem", m[1], "https://jobs.gem.com/"+m[1])
	}
	for _, m := range reDiscRippling.FindAllStringSubmatch(corpus, -1) {
		addBoard("rippling", m[1], "https://ats.rippling.com/"+m[1]+"/jobs")
	}
	for _, m := range reDiscPinpoint.FindAllStringSubmatch(corpus, -1) {
		addBoard("pinpoint", m[1], "https://"+strings.ToLower(m[1])+".pinpointhq.com/")
	}
	for _, m := range reDiscTeamtailor.FindAllStringSubmatch(corpus, -1) {
		addBoard("teamtailor", m[2], "https://"+strings.ToLower(m[1])+"/")
	}
	for _, m := range reDiscBambooHR.FindAllStringSubmatch(corpus, -1) {
		addBoard("bamboohr", m[1], "https://"+strings.ToLower(m[1])+".bamboohr.com/careers")
	}
	for _, m := range reDiscBreezy.FindAllStringSubmatch(corpus, -1) {
		addBoard("breezy", m[1], "https://"+strings.ToLower(m[1])+".breezy.hr/")
	}
	for _, m := range reDiscRecruitee.FindAllStringSubmatch(corpus, -1) {
		addBoard("recruitee", m[1], "https://"+strings.ToLower(m[1])+".recruitee.com/")
	}
	for _, m := range reDiscJazzHR.FindAllStringSubmatch(corpus, -1) {
		addBoard("jazzhr", m[1], "https://"+strings.ToLower(m[1])+".applytojob.com/")
	}
	for _, m := range reDiscPersonio.FindAllStringSubmatch(corpus, -1) {
		addBoard("personio", m[2], "https://"+strings.ToLower(m[1])+"/")
	}
	for _, m := range reDiscSmartRec.FindAllStringSubmatch(corpus, -1) {
		addBoard("smartrecruiters", m[1], "https://jobs.smartrecruiters.com/"+m[1])
	}
	for _, m := range reDiscJobvite.FindAllStringSubmatch(corpus, -1) {
		addBoard("jobvite", m[1], "https://jobs.jobvite.com/"+m[1])
	}
	for _, m := range reDiscICIMS.FindAllStringSubmatch(corpus, -1) {
		icimsSlug := strings.ToLower(m[1])
		if icimsSlug != "www" && icimsSlug != "login" {
			addBoard("icims", icimsSlug, "https://"+icimsSlug+".icims.com/jobs/search?ss=1&in_iframe=1")
		}
	}

	out := make([]DiscoveredATSBoard, 0, len(order))
	for _, k := range order {
		out = append(out, found[k])
	}
	return out
}

// IsKnownMultiTenantATSHost reports whether host belongs to a multi-tenant ATS vendor.
func IsKnownMultiTenantATSHost(host string) bool {
	host = strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, exact := range []string{
		"greenhouse.io", "ashbyhq.com", "lever.co", "smartrecruiters.com", "workable.com",
		"gem.com", "rippling.com", "jobvite.com", "dover.com", "dover.io", "polymer.co",
		"join.com", "www.join.com", "app.jazz.co", "pinpoint.hq", "bamboohr.com", "breezy.hr",
		"recruitee.com", "applytojob.com", "jazzhr.com", "jazzhr.co", "icims.com",
		"personio.de", "personio.com",
	} {
		if host == exact {
			return true
		}
	}
	for _, suffix := range []string{
		".greenhouse.io", ".ashbyhq.com", ".lever.co", ".smartrecruiters.com", ".workable.com",
		".gem.com", ".rippling.com", ".rippling-ats.com", ".jobvite.com", ".dover.com", ".dover.io",
		".polymer.co", ".myworkdayjobs.com", ".myworkdaysite.com", ".pinpointhq.com", ".pinpoint.hq",
		".bamboohr.com", ".breezy.hr", ".recruitee.com", ".applytojob.com", ".jazzhr.com", ".jazzhr.co",
		".teamtailor.com", ".icims.com", ".personio.de", ".personio.com", ".oraclecloud.com",
		".taleo.net", ".successfactors.com", ".successfactors.eu", ".eightfold.ai", ".avature.net",
		".dayforcehcm.com", ".ultipro.com", ".paylocity.com", ".paycomonline.net", ".adp.com",
		".homerun.co", ".traffit.com", ".zohorecruit.com", ".freshteam.com", ".comeet.com",
	} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func decodeSegOrEmpty(seg string) (string, bool) {
	return DecodeURIComponent(seg)
}

// InferCompanyFromATSURL extracts the tenant/company slug from a known ATS URL.
func InferCompanyFromATSURL(urlStr string) string {
	u, ok := parseStrictURL(urlStr)
	if !ok {
		return "unknown"
	}
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	parts := splitCleanPathSegments(u.EscapedPath())
	q := u.Query()

	if host == "greenhouse.io" || strings.HasSuffix(host, ".greenhouse.io") {
		forParam := strings.TrimSpace(q.Get("for"))
		if forParam != "" && (len(parts) == 0 || strings.EqualFold(parts[0], "embed") || strings.EqualFold(parts[0], "view_job")) {
			return forParam
		}
		if len(parts) >= 3 && strings.EqualFold(parts[0], "v1") && strings.EqualFold(parts[1], "boards") {
			if dec, okD := decodeSegOrEmpty(parts[2]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "embed") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if (host == "ats.rippling.com" || host == "rippling.com" || strings.HasSuffix(host, ".rippling.com")) && len(parts) >= 1 {
		idx := 0
		if len(parts) >= 2 && reLocaleSegment.MatchString(parts[0]) {
			idx = 1
		}
		if idx < len(parts) && !strings.EqualFold(parts[idx], "jobs") && !strings.EqualFold(parts[idx], "careers") && !strings.EqualFold(parts[idx], "api") {
			if dec, okD := decodeSegOrEmpty(parts[idx]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if strings.HasSuffix(host, ".rippling-ats.com") {
		sub := strings.TrimSuffix(host, ".rippling-ats.com")
		if sub != "" && !strings.Contains(sub, ".") {
			return sub
		}
	}
	if host == "ashbyhq.com" || strings.HasSuffix(host, ".ashbyhq.com") {
		if len(parts) >= 3 && strings.EqualFold(parts[0], "posting-api") && strings.EqualFold(parts[1], "job-board") {
			if dec, okD := decodeSegOrEmpty(parts[2]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "api") && !strings.EqualFold(parts[0], "posting-api") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if host == "lever.co" || strings.HasSuffix(host, ".lever.co") {
		if len(parts) >= 3 && strings.EqualFold(parts[0], "v0") && strings.EqualFold(parts[1], "postings") {
			if dec, okD := decodeSegOrEmpty(parts[2]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "v0") && !strings.EqualFold(parts[0], "api") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if host == "smartrecruiters.com" || strings.HasSuffix(host, ".smartrecruiters.com") {
		if len(parts) >= 3 && strings.EqualFold(parts[0], "v1") && strings.EqualFold(parts[1], "companies") {
			if dec, okD := decodeSegOrEmpty(parts[2]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "v1") && !strings.EqualFold(parts[0], "api") && !strings.EqualFold(parts[0], "app") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if host == "workable.com" || strings.HasSuffix(host, ".workable.com") {
		if host != "apply.workable.com" && host != "jobs.workable.com" && host != "www.workable.com" && host != "workable.com" {
			sub := strings.TrimSuffix(host, ".workable.com")
			if sub != "" && !strings.Contains(sub, ".") {
				return sub
			}
		}
		if len(parts) >= 4 && strings.EqualFold(parts[0], "api") && strings.EqualFold(parts[2], "accounts") {
			if dec, okD := decodeSegOrEmpty(parts[3]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "j") && !strings.EqualFold(parts[0], "view") && !strings.EqualFold(parts[0], "api") && !strings.EqualFold(parts[0], "jobs") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if host == "dover.com" || strings.HasSuffix(host, ".dover.com") || host == "dover.io" || strings.HasSuffix(host, ".dover.io") {
		if len(parts) >= 2 && (strings.EqualFold(parts[0], "apply") || strings.EqualFold(parts[0], "jobs") || strings.EqualFold(parts[0], "careers")) {
			if dec, okD := decodeSegOrEmpty(parts[1]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "apply") && !strings.EqualFold(parts[0], "jobs") && !strings.EqualFold(parts[0], "careers") && !strings.EqualFold(parts[0], "api") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if host == "jobvite.com" || strings.HasSuffix(host, ".jobvite.com") {
		if host != "jobs.jobvite.com" && host != "www.jobvite.com" && host != "jobvite.com" {
			sub := strings.TrimSuffix(host, ".jobvite.com")
			if sub != "" && !strings.Contains(sub, ".") {
				return sub
			}
		}
		if len(parts) >= 2 && strings.EqualFold(parts[0], "careers") {
			if dec, okD := decodeSegOrEmpty(parts[1]); okD {
				return dec
			}
			return "unknown"
		}
		if len(parts) >= 1 && !strings.EqualFold(parts[0], "CompanyJobs") && !strings.EqualFold(parts[0], "j") && !strings.EqualFold(parts[0], "api") {
			if dec, okD := decodeSegOrEmpty(parts[0]); okD {
				return dec
			}
			return "unknown"
		}
		return ""
	}
	if host == "app.jazz.co" {
		for i, p := range parts {
			if strings.EqualFold(p, "create") && i+1 < len(parts) {
				if dec, okD := decodeSegOrEmpty(parts[i+1]); okD {
					return dec
				}
				return "unknown"
			}
		}
		return ""
	}
	if (host == "gem.com" || strings.HasSuffix(host, ".gem.com") || host == "jobs.polymer.co" || strings.HasSuffix(host, ".polymer.co")) && len(parts) >= 1 {
		if dec, okD := decodeSegOrEmpty(parts[0]); okD {
			return dec
		}
		return "unknown"
	}
	if (host == "join.com" || host == "www.join.com") && len(parts) >= 2 && strings.EqualFold(parts[0], "companies") {
		if dec, okD := decodeSegOrEmpty(parts[1]); okD {
			return dec
		}
		return "unknown"
	}
	if wd := reWorkdayHost.FindStringSubmatch(host); len(wd) >= 2 {
		return wd[1]
	}
	if icims := reInferICIMSHost.FindStringSubmatch(host); len(icims) >= 2 && !reGenericSubATS.MatchString(icims[1]) {
		return icims[1]
	}
	if subATS := reInferSubATSHst.FindStringSubmatch(host); len(subATS) >= 2 && !reGenericSubATS.MatchString(subATS[1]) {
		return subATS[1]
	}
	return reCareerHostPfx.ReplaceAllString(host, "")
}

// ATSPostingIdentity holds parsed board and posting identifiers for batch `verify` mode.
