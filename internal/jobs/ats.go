package jobs

import (
	"strconv"
	"strings"
	"time"
)

func normalizeCanonicalAshbyURL(rawURL any, fallbackOrg, jobID string) string {
	if s, ok := rawURL.(string); ok && strings.TrimSpace(s) != "" {
		if parsed, okP := parseStrictURL(strings.TrimSpace(s)); okP && strings.EqualFold(parsed.Scheme, "https") {
			return canonicalWhatwgURLString(parsed)
		}
	}
	encOrg := EncodeURIComponent(fallbackOrg)
	if jobID != "" {
		return "https://jobs.ashbyhq.com/" + encOrg + "/" + EncodeURIComponent(jobID)
	}
	return "https://jobs.ashbyhq.com/" + encOrg
}

func splitCleanPathSegments(escapedPath string) []string {
	var parts []string
	for _, seg := range strings.Split(escapedPath, "/") {
		if seg != "" {
			parts = append(parts, seg)
		}
	}
	return parts
}

func parseNonNegOffset(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// ResolveATSPreFetchSpec resolves pre-fetch ATS API twin specs (Ashby, Workday CXS, Greenhouse US/EU,
// Lever US/EU, Workable, Gem, Rippling, We Work Remotely, Himalayas, Working Nomads).
func ResolveATSPreFetchSpec(urlStr string) *ATSPreFetchSpec {
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

	// P1: Ashby (`jobs.ashbyhq.com/{org}[/{jobId}[/application]]`)
	if host == "jobs.ashbyhq.com" && len(parts) >= 1 {
		orgDec, ok1 := DecodeURIComponent(parts[0])
		if !ok1 {
			return nil
		}
		org := strings.TrimSpace(orgDec)
		rawSecond := ""
		if len(parts) >= 2 {
			secDec, ok2 := DecodeURIComponent(parts[1])
			if !ok2 {
				return nil
			}
			rawSecond = strings.TrimSpace(secDec)
		}
		secondSeg := strings.ToLower(rawSecond)
		jobID := ""
		if len(parts) >= 2 && secondSeg != "application" && !(len(parts) == 2 && secondSeg == "jobs") {
			jobID = rawSecond
		}
		reqOffset := parseNonNegOffset(q.Get("offset"))
		if IsValidAshbySlug(org) {
			id := "ashby-board"
			if jobID != "" {
				id = "ashby-job"
			}
			return &ATSPreFetchSpec{
				ID:        id,
				FetchURL:  "https://api.ashbyhq.com/posting-api/job-board/" + EncodeURIComponent(org) + "?includeCompensation=true",
				Method:    "GET",
				Kind:      "json",
				Accept:    "application/json",
				host:      host,
				org:       org,
				jobID:     jobID,
				reqOffset: reqOffset,
			}
		}
	}

	// P2: Workday CXS (`{tenant}.wd{N}.myworkdayjobs.com/[{locale}/]{site}[/job/{externalPath}]` or `/wday/cxs/{tenant}/{site}/jobs`)
	if wdMatch := reWorkdayHost.FindStringSubmatch(host); len(wdMatch) >= 2 && len(parts) >= 1 {
		tenant := wdMatch[1]
		site := ""
		var rest []string
		if len(parts) >= 4 && strings.EqualFold(parts[0], "wday") && strings.EqualFold(parts[1], "cxs") {
			if parts[2] != "" {
				tenant = parts[2]
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
			if len(rest) >= 2 && rest[0] == "job" {
				extPath := strings.Join(rest[1:], "/")
				return &ATSPreFetchSpec{
					ID:       "workday-job",
					FetchURL: "https://" + host + "/wday/cxs/" + tenant + "/" + site + "/job/" + extPath,
					Method:   "GET",
					Kind:     "json",
					Accept:   "application/json",
					host:     host,
					org:      tenant,
					site:     site,
					jobID:    extPath,
				}
			}
			searchText := strings.TrimSpace(firstNonEmpty(q.Get("q"), q.Get("searchText"), q.Get("search")))
			reqOffset := parseNonNegOffset(q.Get("offset"))
			reqBody := MarshalNoEscape(map[string]any{
				"appliedFacets": map[string]any{},
				"limit":         20,
				"offset":        reqOffset,
				"searchText":    searchText,
			})
			return &ATSPreFetchSpec{
				ID:          "workday-board",
				FetchURL:    "https://" + host + "/wday/cxs/" + tenant + "/" + site + "/jobs",
				Method:      "POST",
				RequestBody: reqBody,
				ContentType: "application/json",
				Kind:        "json",
				Accept:      "application/json",
				host:        host,
				org:         tenant,
				site:        site,
				reqOffset:   reqOffset,
				searchText:  searchText,
			}
		}
	}

	// Greenhouse US & EU
	isGHUS := host == "boards.greenhouse.io" || host == "job-boards.greenhouse.io"
	isGHEU := host == "eu-boards.greenhouse.io" || host == "job-boards.eu.greenhouse.io"
	if (isGHUS || isGHEU) && len(parts) >= 1 {
		ghAPIHost := "boards-api.greenhouse.io"
		if isGHEU {
			ghAPIHost = "boards-api.eu.greenhouse.io"
		}
		co := parts[0]
		if len(parts) == 1 && reGHSlugIdent.MatchString(co) && !strings.EqualFold(co, "embed") && !strings.EqualFold(co, "v1") {
			id := "greenhouse-board"
			if isGHEU {
				id = "greenhouse-eu-board"
			}
			return &ATSPreFetchSpec{
				ID:        id,
				FetchURL:  "https://" + ghAPIHost + "/v1/boards/" + EncodeURIComponent(co) + "/jobs?content=true",
				Method:    "GET",
				Kind:      "json",
				Accept:    "application/json",
				host:      host,
				org:       co,
				reqOffset: parseNonNegOffset(q.Get("offset")),
			}
		}
		if len(parts) >= 3 && parts[1] == "jobs" {
			jobID := parts[2]
			if reGHSlugIdent.MatchString(co) && reDigitsOnly.MatchString(jobID) {
				return &ATSPreFetchSpec{
					ID:       "greenhouse-job",
					FetchURL: "https://" + ghAPIHost + "/v1/boards/" + EncodeURIComponent(co) + "/jobs/" + jobID + "?content=true",
					Method:   "GET",
					Kind:     "json",
					Accept:   "application/json",
					host:     host,
					org:      co,
					jobID:    jobID,
				}
			}
		}
	}

	// Lever US & EU
	if (host == "jobs.lever.co" || host == "jobs.eu.lever.co") && len(parts) >= 1 {
		leverAPIHost := "api.lever.co"
		if host == "jobs.eu.lever.co" {
			leverAPIHost = "api.eu.lever.co"
		}
		co := parts[0]
		if len(parts) == 1 && reLeverSlugIdent.MatchString(co) {
			id := "lever-board"
			if host == "jobs.eu.lever.co" {
				id = "lever-eu-board"
			}
			return &ATSPreFetchSpec{
				ID:        id,
				FetchURL:  "https://" + leverAPIHost + "/v0/postings/" + EncodeURIComponent(co) + "?mode=json",
				Method:    "GET",
				Kind:      "json",
				Accept:    "application/json",
				host:      host,
				org:       co,
				reqOffset: parseNonNegOffset(q.Get("offset")),
			}
		}
		if len(parts) >= 2 && reLeverJobID.MatchString(parts[1]) {
			jobID := parts[1]
			return &ATSPreFetchSpec{
				ID:       "lever-job",
				FetchURL: "https://" + leverAPIHost + "/v0/postings/" + EncodeURIComponent(co) + "/" + EncodeURIComponent(jobID),
				Method:   "GET",
				Kind:     "json",
				Accept:   "application/json",
				host:     host,
				org:      co,
				jobID:    jobID,
			}
		}
	}

	// Workable (`apply.workable.com/<org>[/j/<shortcode>]`)
	if host == "apply.workable.com" && len(parts) >= 1 {
		org := parts[0]
		orgLow := strings.ToLower(org)
		if reWorkableSlugIdent.MatchString(org) && orgLow != "api" && orgLow != "j" && orgLow != "assets" && orgLow != "static" {
			if len(parts) == 1 {
				return &ATSPreFetchSpec{
					ID:       "workable-board",
					FetchURL: "https://apply.workable.com/api/v1/widget/accounts/" + EncodeURIComponent(org) + "?details=true",
					Method:   "GET",
					Kind:     "json",
					Accept:   "application/json",
					host:     host,
					org:      org,
				}
			}
			if len(parts) >= 3 && parts[1] == "j" && reWorkableJobCode.MatchString(parts[2]) {
				code := parts[2]
				return &ATSPreFetchSpec{
					ID:       "workable-job",
					FetchURL: "https://apply.workable.com/api/v2/accounts/" + EncodeURIComponent(org) + "/jobs/" + EncodeURIComponent(code),
					Method:   "GET",
					Kind:     "json",
					Accept:   "application/json",
					host:     host,
					org:      org,
					jobID:    code,
				}
			}
		}
	}

	// Gem (`jobs.gem.com/<org>`)
	if host == "jobs.gem.com" && len(parts) == 1 && reWorkableSlugIdent.MatchString(parts[0]) {
		org := parts[0]
		return &ATSPreFetchSpec{
			ID:       "gem-board",
			FetchURL: "https://api.gem.com/job_board/v0/" + EncodeURIComponent(org) + "/job_posts/",
			Method:   "GET",
			Kind:     "json",
			Accept:   "application/json",
			host:     host,
			org:      org,
		}
	}

	// Rippling (`ats.rippling.com/[locale/]<org>/jobs[/<uuid>]`)
	if host == "ats.rippling.com" && len(parts) >= 1 {
		idx := 0
		if len(parts) >= 2 && reLocaleSegment.MatchString(parts[0]) {
			idx = 1
		}
		org := parts[idx]
		rest := parts[idx+1:]
		if org != "" && reWorkableSlugIdent.MatchString(org) {
			if len(rest) == 0 || (len(rest) == 1 && rest[0] == "jobs") {
				return &ATSPreFetchSpec{
					ID:       "rippling-board",
					FetchURL: "https://api.rippling.com/platform/api/ats/v1/board/" + EncodeURIComponent(org) + "/jobs",
					Method:   "GET",
					Kind:     "json",
					Accept:   "application/json",
					host:     host,
					org:      org,
				}
			}
			if len(rest) >= 2 && rest[0] == "jobs" && reRipplingJobUUID.MatchString(rest[1]) {
				uuid := rest[1]
				return &ATSPreFetchSpec{
					ID:       "rippling-job",
					FetchURL: "https://api.rippling.com/platform/api/ats/v1/board/" + EncodeURIComponent(org) + "/jobs/" + EncodeURIComponent(uuid),
					Method:   "GET",
					Kind:     "json",
					Accept:   "application/json",
					host:     host,
					org:      org,
					jobID:    uuid,
				}
			}
		}
	}

	// Robots-allowed Public Remote Job Feeds
	if (host == "weworkremotely.com" || host == "www.weworkremotely.com") && strings.HasSuffix(strings.ToLower(u.EscapedPath()), ".rss") {
		return &ATSPreFetchSpec{
			ID:       "weworkremotely-feed",
			FetchURL: urlStr,
			Method:   "GET",
			Kind:     "text",
			Accept:   "application/rss+xml",
			host:     host,
		}
	}
	if (host == "himalayas.app" || host == "www.himalayas.app") && strings.HasPrefix(u.EscapedPath(), "/jobs/api") {
		return &ATSPreFetchSpec{
			ID:       "himalayas-feed",
			FetchURL: urlStr,
			Method:   "GET",
			Kind:     "json",
			Accept:   "application/json",
			host:     host,
		}
	}
	if (host == "www.workingnomads.com" || host == "workingnomads.com") && strings.HasPrefix(u.EscapedPath(), "/api/exposed_jobs") {
		return &ATSPreFetchSpec{
			ID:       "workingnomads-feed",
			FetchURL: urlStr,
			Method:   "GET",
			Kind:     "json",
			Accept:   "application/json",
			host:     host,
		}
	}

	return nil
}

// FormatATSResponse resolves urlStr via ResolveATSPreFetchSpec and formats rawBody into an ATSFormattedResult.
func FormatATSResponse(urlStr, rawBody, origURL string, htmlToMD HTMLToMDFunc, now time.Time) *ATSFormattedResult {
	spec := ResolveATSPreFetchSpec(urlStr)
	if spec == nil {
		return nil
	}
	if origURL == "" {
		origURL = urlStr
	}
	return spec.formatWithNow(rawBody, origURL, htmlToMD, now)
}
