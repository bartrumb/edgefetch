package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/jobs"
)

func init() {
	phase2JobsRPC = handlePhase2JobsRPC
	phase2JobsRawRPC = handlePhase2JobsRawRPC
}

func handlePhase2JobsRawRPC(op string, meta json.RawMessage, rawStr string) (any, bool, error) {
	switch op {
	case "jobs_inspect_jsonld":
		return jobs.InspectRawJobPostingJSONLDLinear(rawStr), true, nil

	case "jobs_extract_jsonld":
		var m struct {
			BaseURL       string `json:"baseUrl"`
			FallbackProse string `json:"fallbackProse"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"jobPosting": jobs.ExtractJobPostingJSONLD(rawStr, m.BaseURL, m.FallbackProse),
		}, true, nil

	case "jobs_salvage_ashby":
		return map[string]any{
			"salvaged": jobs.SalvageAshbyBoardFromTruncatedJSON(rawStr),
		}, true, nil

	case "jobs_format_ats":
		var m struct {
			SpecURL string `json:"specUrl"`
			OrigURL string `json:"origUrl"`
			NowMs   int64  `json:"nowMs"`
		}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &m); err != nil {
				return nil, true, err
			}
		}
		now := time.Now()
		if m.NowMs > 0 {
			now = time.UnixMilli(m.NowMs)
		}
		return map[string]any{
			"result": jobs.FormatATSResponse(m.SpecURL, rawStr, m.OrigURL, defaultHTMLToMD, now),
		}, true, nil

	case "jobs_parse_public_feed":
		var m struct {
			FeedID string `json:"feedId"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"records": jobs.ParsePublicJobFeedRecords(m.FeedID, rawStr),
		}, true, nil

	case "jobs_chunk_json_records":
		var m struct {
			ContentType string `json:"contentType"`
			URL         string `json:"url"`
			JSONFilter  string `json:"jsonFilter"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"result": jobs.ChunkJSONRecords(jobs.ChunkJSONRecordsParams{
				RawBody:     rawStr,
				ContentType: m.ContentType,
				URL:         m.URL,
				JSONFilter:  m.JSONFilter,
				HTMLToMD:    defaultHTMLToMD,
			}),
		}, true, nil

	case "jobs_has_executable_script":
		return map[string]any{
			"hasScript": jobs.HasExecutableScriptTag(rawStr),
		}, true, nil

	case "jobs_is_thin_scripted":
		var m struct {
			HTMLByteLen int    `json:"htmlByteLen"`
			Markdown    string `json:"markdown"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		rawHTML := rawStr
		md := m.Markdown
		if m.HTMLByteLen > 0 && m.HTMLByteLen <= len(rawStr) {
			rawHTML = rawStr[:m.HTMLByteLen]
			md = rawStr[m.HTMLByteLen:]
		}
		return map[string]any{
			"thin": jobs.IsThinScriptedPage(rawHTML, md),
		}, true, nil

	case "jobs_discover_boards":
		var m struct {
			SourceURL string   `json:"sourceUrl"`
			FinalURL  string   `json:"finalUrl"`
			Links     []string `json:"links"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"boards": jobs.DiscoverATSBoardsFromHTML(jobs.DiscoverBoardsParams{
				SourceURL: m.SourceURL,
				FinalURL:  m.FinalURL,
				RawHTML:   rawStr,
				Links:     m.Links,
			}),
		}, true, nil

	default:
		return nil, false, nil
	}
}

func handlePhase2JobsRPC(op string, payload json.RawMessage) (any, bool, error) {
	if !strings.HasPrefix(op, "jobs_") {
		return nil, false, nil
	}
	switch op {
	case "jobs_infer_pay_basis":
		var p struct {
			Context string `json:"context"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"basis": jobs.InferPayBasis(p.Context)}, true, nil

	case "jobs_normalize_period":
		var p struct {
			Period string `json:"period"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"period": jobs.NormalizePeriod(p.Period)}, true, nil

	case "jobs_format_pay":
		var p struct {
			Pay *jobs.NormalizedPay `json:"pay"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": jobs.FormatNormalizedPay(p.Pay)}, true, nil

	case "jobs_parse_pay":
		var p struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"pay": jobs.ParsePayFromText(p.Text)}, true, nil

	case "jobs_infer_workplace":
		var p struct {
			Text       string `json:"text"`
			RemoteType string `json:"remoteType"`
			LocText    string `json:"locText"`
			Title      string `json:"title"`
			Workday    bool   `json:"workday"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		if p.Workday {
			return map[string]any{"workplaceType": jobs.InferWorkdayWorkplaceType(p.RemoteType, p.LocText, p.Title)}, true, nil
		}
		return map[string]any{"workplaceType": jobs.InferWorkplaceType(p.Text)}, true, nil

	case "jobs_format_header_md":
		var p struct {
			JobPosting jobs.StructuredJobPosting `json:"jobPosting"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"markdown": jobs.FormatJobPostingHeaderMarkdown(p.JobPosting)}, true, nil

	case "jobs_is_legal_boilerplate":
		var p struct {
			Text    string `json:"text"`
			Heading string `json:"heading"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"boilerplate": jobs.IsJobLegalBoilerplateChunk(p.Text, p.Heading)}, true, nil

	case "jobs_detect_workday_stub":
		var p struct {
			RawBody string `json:"rawBody"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		if redir, ok := jobs.DetectWorkdayRedirectStub(p.RawBody, p.BaseURL); ok {
			return map[string]any{"stub": map[string]string{"redirectUrl": redir}}, true, nil
		}
		return map[string]any{"stub": nil}, true, nil

	case "jobs_resolve_ats_spec":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"spec": jobs.ResolveATSPreFetchSpec(p.URL)}, true, nil

	case "jobs_analyze_redirect":
		var p struct {
			RequestedURL string `json:"requestedUrl"`
			FinalURL     string `json:"finalUrl"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"analysis": jobs.AnalyzeURLRedirect(p.RequestedURL, p.FinalURL)}, true, nil

	case "jobs_parse_x402":
		var p struct {
			Status       int               `json:"status"`
			Headers      map[string]string `json:"headers"`
			RawBody      string            `json:"rawBody"`
			ExpectedHost string            `json:"expectedHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"result": jobs.ParseX402PaymentTerms(p.Status, p.Headers, p.RawBody, p.ExpectedHost)}, true, nil

	case "jobs_build_blocked":
		var p struct {
			URL     string            `json:"url"`
			Outcome string            `json:"outcome"`
			Problem string            `json:"problem"`
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
			RawBody string            `json:"rawBody"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"blocked": jobs.BuildBlockedInfo(p.URL, p.Outcome, p.Problem, p.Status, p.Headers, p.RawBody)}, true, nil

	case "jobs_classify_board_status":
		var p jobs.ClassifyBoardStatusParams
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"status": jobs.ClassifyATSBoardStatus(p)}, true, nil

	case "jobs_parse_posting_identity":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"identity": jobs.ParseATSPostingIdentity(p.URL)}, true, nil

	case "jobs_find_similar_roles":
		var p struct {
			OpenRoles  []jobs.SimilarRole `json:"openRoles"`
			RoleTokens []string           `json:"roleTokens"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"roles": jobs.FindSimilarRoles(p.OpenRoles, p.RoleTokens)}, true, nil

	case "jobs_unresolved_ats_host":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		plat, slug, ok := jobs.IsKnownATSPostingHostWithUnresolvedSlug(p.URL)
		if !ok {
			return map[string]any{"info": nil}, true, nil
		}
		return map[string]any{"info": map[string]string{"platform": plat, "rawSlug": slug}}, true, nil

	case "jobs_compact_slug_fallbacks":
		var p struct {
			Platform string `json:"platform"`
			Slug     string `json:"slug"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"fallbacks": jobs.BuildCompactSlugFallbackBoards(p.Platform, p.Slug)}, true, nil

	case "jobs_expand_company_tokens":
		var p struct {
			Company string `json:"company"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"tokens": jobs.ExpandCompanyFilterTokens(p.Company)}, true, nil

	case "jobs_match_company":
		var p struct {
			Job                  jobs.StructuredJobRecord `json:"job"`
			AllowedTokens        []string                 `json:"allowedTokens"`
			AllowedBoardPrefixes []string                 `json:"allowedBoardPrefixes"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"matched": jobs.MatchesAllowedCompanyOrDomain(p.Job, p.AllowedTokens, p.AllowedBoardPrefixes),
		}, true, nil

	case "jobs_parse_smartrecruiters_board":
		var p struct {
			OrigURL  string   `json:"origUrl"`
			Markdown string   `json:"markdown"`
			RawHTML  string   `json:"rawHtml"`
			Links    []string `json:"links"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"records": jobs.ParseSmartRecruitersBoardScrape(p.OrigURL, p.Markdown, p.RawHTML, p.Links),
		}, true, nil

	case "jobs_parse_builtin_cards":
		var p struct {
			Markdown        string `json:"markdown"`
			MaxCards        int    `json:"maxCards"`
			WantRemoteFalse bool   `json:"wantRemoteFalse"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"records": jobs.ParseBuiltInMarkdownCards(p.Markdown, p.MaxCards, p.WantRemoteFalse),
		}, true, nil

	case "jobs_url_helpers":
		var p struct {
			Kind               string   `json:"kind"`
			URL                string   `json:"url"`
			Slug               string   `json:"slug"`
			Token              string   `json:"token"`
			Host               string   `json:"host"`
			JobCompany         string   `json:"jobCompany"`
			SegmentedTokens    []string `json:"segmentedTokens"`
			AllowAshbySpaces   bool     `json:"allowAshbySpaces"`
			HasScope           bool     `json:"hasScope"`
			AllowedTokens      []string `json:"allowedTokens"`
			ConfirmedBoardURLs []string `json:"confirmedBoardUrls"`
			Title              string   `json:"title"`
			Snippet            string   `json:"snippet"`
			Query              string   `json:"query"`
			Locations          []string `json:"locations"`
			GeoFilters         []string `json:"geoFilters"`
			Label              string   `json:"label"`
			MaxDays            float64  `json:"maxDays"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		switch p.Kind {
		case "classify_full_board":
			return map[string]any{"info": jobs.ClassifyFullBoardKey(p.URL)}, true, nil
		case "is_smartrecruiters_board":
			org, bURL, ok := jobs.IsSmartRecruitersBoardURL(p.URL)
			if !ok {
				return map[string]any{"info": nil}, true, nil
			}
			return map[string]any{"info": map[string]string{"org": org, "boardUrl": bURL}}, true, nil
		case "infer_company_ats":
			return map[string]any{"company": jobs.InferCompanyFromATSURL(p.URL)}, true, nil
		case "is_multitenant_ats":
			return map[string]any{"ok": jobs.IsKnownMultiTenantATSHost(p.Host)}, true, nil
		case "registrable_brand":
			return map[string]any{"info": jobs.ExtractRegistrableBrandInfo(p.Host)}, true, nil
		case "valid_ats_slug":
			return map[string]any{"ok": jobs.IsValidATSSlug(p.Slug)}, true, nil
		case "valid_ashby_slug":
			return map[string]any{"ok": jobs.IsValidAshbySlug(p.Slug)}, true, nil
		case "norm_corp_abbrev":
			return map[string]any{"out": jobs.NormalizeDottedCorporateAbbreviations(p.JobCompany)}, true, nil
		case "match_tenant_slug":
			segMap := make(map[string]bool, len(p.SegmentedTokens))
			for _, s := range p.SegmentedTokens {
				segMap[s] = true
			}
			return map[string]any{
				"ok": jobs.MatchesATSTenantSlugAgainstToken(p.Slug, p.Token, jobs.TenantSlugMatchOptions{
					Host:             p.Host,
					JobCompany:       p.JobCompany,
					SegmentedTokens:  segMap,
					AllowAshbySpaces: p.AllowAshbySpaces,
				}),
			}, true, nil
		case "match_scoped_candidate":
			return map[string]any{
				"ok": jobs.MatchesScopedATSCandidateURL(p.URL, p.HasScope, p.AllowedTokens, p.SegmentedTokens, p.ConfirmedBoardURLs, p.JobCompany),
			}, true, nil
		case "query_relevance":
			rel := jobs.MatchesJobQueryRelevance(p.Title, p.Snippet, p.Query)
			if rel == "" {
				return map[string]any{"rel": nil}, true, nil
			}
			return map[string]any{"rel": rel}, true, nil
		case "geo_filter":
			return map[string]any{"ok": jobs.MatchesGeoLocationsFilter(p.Locations, p.GeoFilters)}, true, nil
		case "canonical_key":
			return map[string]any{"key": jobs.CanonicalJobKey(p.JobCompany, p.Title)}, true, nil
		case "workday_req_id":
			return map[string]any{"reqId": jobs.ExtractWorkdayReqID(p.URL)}, true, nil
		case "label_stale":
			return map[string]any{"stale": jobs.IsJobLabelKnownStale(p.Label, p.MaxDays)}, true, nil
		case "strip_plain":
			return map[string]any{"out": jobs.StripTagsPlain(p.Snippet)}, true, nil
		default:
			return map[string]any{"ok": false}, true, nil
		}

	case "jobs_filter_and_rank":
		var p jobs.FilterAndRankParams
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return jobs.FilterAndRankJobs(p), true, nil

	default:
		return nil, false, nil
	}
}
