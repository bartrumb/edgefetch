package catalog

import (
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

var (
	reUCPEndpointPath      = newLazyRegexp(`(?i)(?:/api/ucp/mcp|/\.well-known/ucp)\b`)
	reOAuthMultiClient     = newLazyRegexp(`(?i)^([a-z0-9_]+)-client-\d+$`)
	reChallengeProblem     = newLazyRegexp(`(?i)challenge|cf-mitigated|turnstile|captcha|verify you are human`)
	reChallengeBodyMarkers = newLazyRegexp(`(?i)cf-mitigated|_cf_chl_opt|challenge-platform|turnstile|verify you are human`)
	reNonStorefrontWAFText = newLazyRegexp(`(?i)blocked|access\s+denied|forbidden|captcha|turnstile|cf-mitigated|just\s+a\s+moment|attention\s+required|_incapsula_resource|incapsula|awswafintegration|aws-waf-token|px-captcha|_pxappid|perimeterx|captcha-delivery\.com|datadome|kpsdk|/ips\.js|sec-cpt|bazadebezolkohpepadr|verifying\s+your\s+browser|checking\s+your\s+browser|pardon\s+our\s+interruption|human\s+verification|bot\s+verification|security\s+check|enable\s+javascript|enable\s+js`)
	reNonStorefrontShopify = newLazyRegexp(`(?i)cdn\.shopify\.com|shopify\.theme|shopify-digital-wallet`)
	reNonStorefrontWoo     = newLazyRegexp(`(?i)woocommerce|wc-block|wp-content/plugins/woocommerce`)
	reDoctypeHTML          = newLazyRegexp(`(?i)^<!doctype\s+html\b`)
	reHTMLOpenTag          = newLazyRegexp(`(?i)^<html\b`)
	reContentSignalProb    = newLazyRegexp(`(?i)content-signal|ai-input\s*=\s*no`)
	reRobotsProb           = newLazyRegexp(`(?i)robots\.txt`)
	reUnreachableProb      = newLazyRegexp(`(?i)timed?\s*out|unreachable`)
	reValidCatalogID       = newLazyRegexp(`^[A-Za-z0-9_-]{1,80}$`)
)

// IsValidCatalogID validates a `catalogId` parameter against path traversal and control-byte injection.
func IsValidCatalogID(id string) bool {
	return reValidCatalogID.MatchString(id)
}

// DiscoverUCPEndpointFromRobots inspects `robots.txt` text for advertised Shopify / Universal Commerce Protocol
// endpoints (`/.well-known/ucp` or `/api/ucp/mcp`), strictly treating `robots.txt` prose as untrusted data.
func DiscoverUCPEndpointFromRobots(originStr, robotsText string) *CatalogUCPMetadata {
	if robotsText == "" || strings.TrimSpace(originStr) == "" {
		return nil
	}
	baseU, err := url.Parse(strings.TrimSpace(originStr))
	if err != nil || (baseU.Scheme != "https" && baseU.Scheme != "http") || baseU.Host == "" {
		return nil
	}
	bounded := robotsText
	if len(bounded) > 32_768 {
		bounded = bounded[:32_768]
	}
	m := reUCPEndpointPath.FindString(bounded)
	if m == "" {
		return nil
	}
	ref, err := url.Parse(m)
	if err != nil {
		return nil
	}
	resolved := baseU.ResolveReference(ref)
	return &CatalogUCPMetadata{
		Advertised: true,
		Endpoint:   resolved.String(),
	}
}

// IsSafeHTTPSStoreURL validates that urlStr is a strictly public `https://` storefront URL on port 443
// without credentials, trailing-dot hostnames, IP literals, or recursive selfHost matches.
func IsSafeHTTPSStoreURL(urlStr, selfHost string) (*url.URL, bool) {
	trimmed := strings.TrimSpace(urlStr)
	if trimmed == "" || strings.IndexByte(trimmed, '\\') >= 0 {
		return nil, false
	}
	u, err := url.Parse(trimmed)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil {
		return nil, false
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, false
	}
	rawHost := strings.ToLower(u.Hostname())
	if rawHost == "" || strings.HasSuffix(rawHost, ".") || !strings.Contains(rawHost, ".") {
		return nil, false
	}
	if !IsSafePublicHostname(rawHost, selfHost) {
		return nil, false
	}
	cloned := *u
	cloned.Scheme = "https"
	cloned.Host = rawHost
	if cloned.Path == "" {
		cloned.Path = "/"
	}
	return &cloned, true
}

func stripLeadingWww(host string) string {
	if strings.HasPrefix(host, "www.") {
		return host[4:]
	}
	return host
}

// IsAllowedStoreRedirectURL ensures `finalURLStr` stays on a safe public `https://` store host matching
// the requested store origin (or its `www.` equivalent).
func IsAllowedStoreRedirectURL(finalURLStr, requestedOriginStr, selfHost string) bool {
	parsedFinal, ok := IsSafeHTTPSStoreURL(finalURLStr, selfHost)
	if !ok {
		return false
	}
	reqU, err := url.Parse(strings.TrimSpace(requestedOriginStr))
	if err != nil || reqU.Hostname() == "" {
		return false
	}
	reqHost := strings.ToLower(reqU.Hostname())
	finHost := strings.ToLower(parsedFinal.Hostname())
	return finHost == reqHost || stripLeadingWww(finHost) == stripLeadingWww(reqHost)
}

// CatalogTenantInfo holds resolved multi-tenant ownership and concurrency bucket keys.
type CatalogTenantInfo struct {
	OwnerKey             string `json:"ownerKey"`
	ConcurrencyBucketKey string `json:"concurrencyBucketKey"`
	IsOwner              bool   `json:"isOwner"`
}

// ResolveCatalogTenantBucket normalizes userId/principal into tenant storage and concurrency keys,
// grouping `oauth:<member>-client-1..N` onto `oauth:<member>` so multi-client rotation cannot multiply concurrency.
func ResolveCatalogTenantBucket(cleanUserID, principal, activeUserID, activeRole string) CatalogTenantInfo {
	if cleanUserID != "" {
		isOwner := cleanUserID == "owner"
		if activeRole != "" {
			isOwner = activeRole == "owner"
		}
		return CatalogTenantInfo{
			OwnerKey:             cleanUserID,
			ConcurrencyBucketKey: cleanUserID,
			IsOwner:              isOwner,
		}
	}
	if activeUserID != "" {
		return CatalogTenantInfo{
			OwnerKey:             activeUserID,
			ConcurrencyBucketKey: activeUserID,
			IsOwner:              activeRole == "owner",
		}
	}
	rawPrincipal := strings.TrimSpace(principal)
	if rawPrincipal == "anonymous" {
		return CatalogTenantInfo{OwnerKey: "anonymous", ConcurrencyBucketKey: "anonymous", IsOwner: false}
	}
	if rawPrincipal == "" || rawPrincipal == "owner_token" || rawPrincipal == "mcp_token" || rawPrincipal == "owner" {
		return CatalogTenantInfo{OwnerKey: "owner", ConcurrencyBucketKey: "owner", IsOwner: true}
	}
	bucket := rawPrincipal
	if strings.HasPrefix(rawPrincipal, "oauth:") {
		clientPart := rawPrincipal[len("oauth:"):]
		if m := reOAuthMultiClient.FindStringSubmatch(clientPart); len(m) == 2 {
			bucket = "oauth:" + strings.ToLower(m[1])
		}
	}
	if len(rawPrincipal) > 128 {
		rawPrincipal = rawPrincipal[:128]
	}
	if len(bucket) > 128 {
		bucket = bucket[:128]
	}
	return CatalogTenantInfo{OwnerKey: rawPrincipal, ConcurrencyBucketKey: bucket, IsOwner: false}
}

// CatalogInitRequest holds input parameters for initializing a catalog pull plan.
type CatalogInitRequest struct {
	URL             string `json:"url"`
	Platform        string `json:"platform,omitempty"`
	Collection      string `json:"collection,omitempty"`
	ScopeCollection string `json:"scopeCollection,omitempty"`
	Fields          string `json:"fields,omitempty"`
	MaxPages        *int   `json:"maxPages,omitempty"`
	PauseMs         *int   `json:"pauseMs,omitempty"`
	SelfHost        string `json:"selfHost,omitempty"`
	ShopifyPauseMs  int    `json:"shopifyPauseMs,omitempty"`
	ShopifyPageCap  int    `json:"shopifyPageCap,omitempty"`
	WooPauseMs      int    `json:"wooPauseMs,omitempty"`
	WooPageCap      int    `json:"wooPageCap,omitempty"`
}

// CatalogPullPlan contains validated, normalized parameters for executing a storefront catalog run.
type CatalogPullPlan struct {
	Origin                 string `json:"origin"`
	OriginWithCollection   string `json:"originWithCollection"`
	Collection             string `json:"collection,omitempty"`
	Fields                 string `json:"fields"`
	RawPlatform            string `json:"rawPlatform"`
	InitialPlatform        string `json:"initialPlatform"`
	EffectivePauseMs       int    `json:"effectivePauseMs"`
	MaxPages               int    `json:"maxPages"`
	CallerExplicitMaxPages bool   `json:"callerExplicitMaxPages"`
	FirstPageURL           string `json:"firstPageUrl"`
}

// CatalogValidationError represents a 400 validation failure during pull initialization.
type CatalogValidationError struct {
	ErrorCode string `json:"error"`
	Message   string `json:"message"`
}

func computeEffectiveCatalogPauseMs(platform string, specPauseMs int, reqPause *int) int {
	req := specPauseMs
	if reqPause != nil {
		req = *reqPause
	}
	floor := specPauseMs
	if platform == "shopify" && floor < 2000 {
		floor = 2000
	}
	if req < floor {
		req = floor
	}
	if req > 30_000 {
		req = 30_000
	}
	return req
}

// InitCatalogPullPlan validates the requested storefront URL and platform and computes the initial pagination plan.
func InitCatalogPullPlan(req CatalogInitRequest) (*CatalogPullPlan, *CatalogValidationError) {
	parsedURL, ok := IsSafeHTTPSStoreURL(req.URL, req.SelfHost)
	if !ok {
		return nil, &CatalogValidationError{
			ErrorCode: "invalid_url",
			Message:   "Provide a valid public `https://` storefront URL in `url` (or `catalogId` to poll an existing run).",
		}
	}
	rawPlatform := strings.ToLower(strings.TrimSpace(req.Platform))
	if rawPlatform == "" {
		rawPlatform = "auto"
	}
	if rawPlatform != "auto" && rawPlatform != "shopify" && rawPlatform != "woocommerce" {
		return nil, &CatalogValidationError{
			ErrorCode: "invalid_platform",
			Message:   "Supported `platform` values are `\"auto\"`, `\"shopify\"`, or `\"woocommerce\"`.",
		}
	}

	collection := strings.TrimSpace(req.Collection)
	if collection == "" {
		collection = strings.TrimSpace(req.ScopeCollection)
	}
	if collection == "" {
		if m := reShopifyColPath.FindStringSubmatch(parsedURL.Path); len(m) == 2 {
			collection = m[1]
		}
	}
	fields := "full"
	if req.Fields == "lean" {
		fields = "lean"
	}

	origin := "https://" + strings.ToLower(parsedURL.Hostname())
	originWithCol := origin
	if collection != "" {
		originWithCol = origin + "/collections/" + EncodeURIComponent(collection)
	}

	initialPlatform := rawPlatform
	if rawPlatform == "auto" {
		if strings.Contains(strings.ToLower(parsedURL.Path), "/wp-json/wc/store/") {
			initialPlatform = "woocommerce"
		} else {
			initialPlatform = "shopify"
		}
	}

	shopCfg := DeclarativeCatalogConfig{
		Platform: "shopify",
		PauseMs:  req.ShopifyPauseMs,
		PageCap:  req.ShopifyPageCap,
	}
	if shopCfg.PauseMs <= 0 {
		shopCfg.PauseMs = 2000
	}
	if shopCfg.PageCap <= 0 {
		shopCfg.PageCap = 200
	}
	wooCfg := DeclarativeCatalogConfig{
		Platform: "woocommerce",
		PauseMs:  req.WooPauseMs,
		PageCap:  req.WooPageCap,
	}
	if wooCfg.PauseMs <= 0 {
		wooCfg.PauseMs = 1000
	}
	if wooCfg.PageCap <= 0 {
		wooCfg.PageCap = 200
	}

	activeCfg := shopCfg
	if initialPlatform == "woocommerce" {
		activeCfg = wooCfg
	}
	pauseMs := computeEffectiveCatalogPauseMs(activeCfg.Platform, activeCfg.PauseMs, req.PauseMs)
	explicitMax := req.MaxPages != nil && *req.MaxPages >= 1
	maxPages := activeCfg.PageCap
	if explicitMax && *req.MaxPages < maxPages {
		maxPages = *req.MaxPages
	}
	firstURL, _ := CatalogSpecFirstPage(activeCfg, originWithCol, collection)

	return &CatalogPullPlan{
		Origin:                 origin,
		OriginWithCollection:   originWithCol,
		Collection:             collection,
		Fields:                 fields,
		RawPlatform:            rawPlatform,
		InitialPlatform:        initialPlatform,
		EffectivePauseMs:       pauseMs,
		MaxPages:               maxPages,
		CallerExplicitMaxPages: explicitMax,
		FirstPageURL:           firstURL,
	}, nil
}

// ParseRetryAfterMs parses numeric or HTTP-date `Retry-After` headers into bounded cooldown milliseconds `[1000..300000]`.
func ParseRetryAfterMs(retryAfterMs *float64, headers map[string]string, defaultMs int, nowMs int64) int {
	clampWait := func(ms int64) int {
		if ms < 1000 {
			return 1000
		}
		if ms > 300_000 {
			return 300_000
		}
		return int(ms)
	}
	if retryAfterMs != nil && !math.IsNaN(*retryAfterMs) && !math.IsInf(*retryAfterMs, 0) && *retryAfterMs > 0 {
		return clampWait(int64(math.Round(*retryAfterMs)))
	}
	hdr := readHeaderCaseInsensitive(headers, "retry-after")
	if hdr != "" {
		allDigits := true
		for i := 0; i < len(hdr); i++ {
			if hdr[i] < '0' || hdr[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			if secs, err := strconv.ParseInt(hdr, 10, 64); err == nil && secs > 0 {
				return clampWait(secs * 1000)
			}
		}
		if nowMs <= 0 {
			nowMs = time.Now().UnixMilli()
		}
		for _, layout := range []string{
			"Mon, 02 Jan 2006 15:04:05 GMT",
			time.RFC1123,
			time.RFC1123Z,
			time.RFC3339,
			time.RFC850,
			time.ANSIC,
		} {
			if t, err := time.ParseInLocation(layout, hdr, time.UTC); err == nil {
				if delta := t.UnixMilli() - nowMs; delta > 0 {
					return clampWait(delta)
				}
				break
			}
		}
	}
	return defaultMs
}

func hasAntiBotResponseHeader(headers map[string]string) bool {
	for _, k := range []string{
		"cf-mitigated",
		"x-datadome",
		"x-dd-b",
		"x-kpsdk-ct",
		"x-px-blocked",
		"x-amzn-waf-action",
		"x-vercel-mitigated",
	} {
		if readHeaderCaseInsensitive(headers, k) != "" {
			return true
		}
	}
	return false
}

// IsRobotsOrSignalBlocked classifies robots.txt and Content-Signal ethical block outcomes.
func IsRobotsOrSignalBlocked(outcome, problem string) string {
	outLow := strings.ToLower(strings.TrimSpace(outcome))
	if outLow == "content_signal_disallowed" || reContentSignalProb.MatchString(problem) {
		return "content_signal_disallowed"
	}
	if outLow == "robots_unreachable" || (reRobotsProb.MatchString(problem) && reUnreachableProb.MatchString(problem)) {
		return "robots_unreachable"
	}
	if outLow == "robots_disallowed" || reRobotsProb.MatchString(problem) {
		return "robots_disallowed"
	}
	return ""
}

// IsChallengePageResponse detects WAF / anti-bot interstitials while exempting valid JSON product payloads.
func IsChallengePageResponse(status int, outcome, problem string, headers map[string]string, body string) bool {
	if strings.EqualFold(strings.TrimSpace(outcome), "challenge") {
		return true
	}
	if readHeaderCaseInsensitive(headers, "cf-mitigated") != "" {
		return true
	}
	if reChallengeProblem.MatchString(problem) {
		return true
	}
	bodyHead := body
	if len(bodyHead) > 4096 {
		bodyHead = bodyHead[:4096]
	}
	trimmedHead := strings.TrimLeft(bodyHead, " \t\r\n")
	ctLow := strings.ToLower(readHeaderCaseInsensitive(headers, "content-type"))
	isJSONPayload := strings.Contains(ctLow, "json") ||
		strings.HasPrefix(trimmedHead, "{") ||
		strings.HasPrefix(trimmedHead, "[")

	if !isJSONPayload && hasAntiBotResponseHeader(headers) {
		return true
	}
	if !isJSONPayload {
		wafHeaders := make(map[string][]string, len(headers))
		for k, v := range headers {
			wafHeaders[k] = []string{v}
		}
		if classify.ClassifyWAF(status, wafHeaders, []byte(body)) != nil {
			return true
		}
	}
	if (status == 403 || status == 503 || (status == 200 && !isJSONPayload)) && reChallengeBodyMarkers.MatchString(bodyHead) {
		return true
	}
	return false
}

// IsNonStorefrontHTMLFallback detects plain non-storefront HTML SPA/site fallbacks (with zero WAF or platform markers)
// so `platform: "auto"` exits cleanly with `unsupported_storefront` instead of false `challenged`.
func IsNonStorefrontHTMLFallback(status int, outcome, problem string, headers map[string]string, body, platform string) bool {
	if IsChallengePageResponse(status, outcome, problem, headers, body) || hasAntiBotResponseHeader(headers) {
		return false
	}
	head := body
	if len(head) > 65_536 {
		head = head[:65_536]
	}
	head = strings.TrimLeft(head, " \t\r\n")
	if head == "" || (!reDoctypeHTML.MatchString(head) && !reHTMLOpenTag.MatchString(head)) {
		return false
	}
	if reNonStorefrontWAFText.MatchString(head) {
		return false
	}
	if platform == "shopify" && reNonStorefrontShopify.MatchString(head) {
		return false
	}
	if platform == "woocommerce" && reNonStorefrontWoo.MatchString(head) {
		return false
	}
	return true
}

// CatalogPageEvalInput describes a single fetched page to evaluate during a catalog pull.
type CatalogPageEvalInput struct {
	CurrentURL              string                   `json:"currentUrl"`
	OriginWithCollection    string                   `json:"originWithCollection"`
	Collection              string                   `json:"collection,omitempty"`
	SelfHost                string                   `json:"selfHost,omitempty"`
	Platform                string                   `json:"platform"`
	Fields                  string                   `json:"fields"`
	PagesRead               int                      `json:"pagesRead"`
	TriedAutoFallbackToWC   bool                     `json:"triedAutoFallbackToWc"`
	AutoFallbackFromShopify bool                     `json:"autoFallbackFromShopify"`
	ReqPauseMs              *int                     `json:"reqPauseMs,omitempty"`
	CatalogCfg              DeclarativeCatalogConfig `json:"catalogCfg"`
	WooCatalogCfg           DeclarativeCatalogConfig `json:"wooCatalogCfg"`
	Status                  int                      `json:"status"`
	Outcome                 string                   `json:"outcome,omitempty"`
	Problem                 string                   `json:"problem,omitempty"`
	Headers                 map[string]string        `json:"headers,omitempty"`
	FinalURL                string                   `json:"finalUrl,omitempty"`
	RetryAfterMs            *float64                 `json:"retryAfterMs,omitempty"`
	NowMs                   int64                    `json:"nowMs,omitempty"`
}

// ClampedRecordItem pairs a clamped CatalogRecord with its computed V8/Go memory footprint.
type ClampedRecordItem struct {
	Key            string        `json:"key"`
	Record         CatalogRecord `json:"record"`
	FootprintBytes int           `json:"footprintBytes"`
}

// CatalogPageEvalOutput describes the pure-CPU state transition after inspecting/parsing a fetched catalog page.
type CatalogPageEvalOutput struct {
	Action           string              `json:"action"` // "parsed" | "cooldown" | "fallback_wc" | "halt"
	StopReason       string              `json:"stopReason,omitempty"`
	BlockKind        string              `json:"blockKind,omitempty"`
	Challenged       bool                `json:"challenged,omitempty"`
	UnsupportedStore bool                `json:"unsupportedStore,omitempty"`
	WaitMs           int                 `json:"waitMs,omitempty"`
	NewPauseMs       int                 `json:"newPauseMs,omitempty"`
	NextURL          string              `json:"nextUrl,omitempty"`
	Done             bool                `json:"done,omitempty"`
	Items            []ClampedRecordItem `json:"items,omitempty"`
}

// EvaluateCatalogPageResponse evaluates redirect safety, robots/signal blocks, WAF challenges, 429 cooldowns,
// `auto` Shopify->WooCommerce fallback, strict JSON parsing, record clamping, and next-page URL resolution.
func EvaluateCatalogPageResponse(in CatalogPageEvalInput, rawBody string) CatalogPageEvalOutput {
	if in.FinalURL != "" && !IsAllowedStoreRedirectURL(in.FinalURL, in.OriginWithCollection, in.SelfHost) {
		return CatalogPageEvalOutput{Action: "halt", StopReason: "cross_origin_redirect"}
	}
	if blockKind := IsRobotsOrSignalBlocked(in.Outcome, in.Problem); blockKind != "" {
		return CatalogPageEvalOutput{Action: "halt", StopReason: blockKind, BlockKind: blockKind}
	}
	if IsChallengePageResponse(in.Status, in.Outcome, in.Problem, in.Headers, rawBody) {
		return CatalogPageEvalOutput{Action: "halt", StopReason: "challenge", Challenged: true}
	}
	if in.Status == 429 || strings.EqualFold(strings.TrimSpace(in.Outcome), "rate_limited") {
		defCooldown := 30_000
		if in.Platform == "shopify" {
			defCooldown = 60_000
		}
		waitMs := ParseRetryAfterMs(in.RetryAfterMs, in.Headers, defCooldown, in.NowMs)
		return CatalogPageEvalOutput{Action: "cooldown", WaitMs: waitMs}
	}

	makeFallbackWC := func() CatalogPageEvalOutput {
		wcCfg := in.WooCatalogCfg
		wcCfg.Platform = "woocommerce"
		if wcCfg.PauseMs <= 0 {
			wcCfg.PauseMs = 1000
		}
		if wcCfg.PageCap <= 0 {
			wcCfg.PageCap = 200
		}
		firstWC, _ := CatalogSpecFirstPage(wcCfg, in.OriginWithCollection, in.Collection)
		newPause := computeEffectiveCatalogPauseMs("woocommerce", wcCfg.PauseMs, in.ReqPauseMs)
		return CatalogPageEvalOutput{
			Action:     "fallback_wc",
			NextURL:    firstWC,
			NewPauseMs: newPause,
		}
	}

	if in.PagesRead == 0 && !in.TriedAutoFallbackToWC && (in.Status == 404 || in.Status == 400 || in.Status == 405) {
		return makeFallbackWC()
	}
	if in.Status != 200 {
		if in.PagesRead == 0 && in.AutoFallbackFromShopify && (in.Status == 404 || in.Status == 400 || in.Status == 405) {
			return CatalogPageEvalOutput{Action: "halt", StopReason: "unsupported_storefront", UnsupportedStore: true}
		}
		reason := "http_error"
		if in.Status > 0 {
			reason = "http_" + strconv.Itoa(in.Status)
		}
		return CatalogPageEvalOutput{Action: "halt", StopReason: reason}
	}

	cfg := in.CatalogCfg
	cfg.Platform = in.Platform
	records, done, err := CatalogSpecParsePage(cfg, rawBody, in.OriginWithCollection, in.Fields, in.Headers)
	if err != nil {
		trimmed := strings.TrimSpace(rawBody)
		looksLikeJSON := strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
		nonStorefrontHTML := IsNonStorefrontHTMLFallback(in.Status, in.Outcome, in.Problem, in.Headers, rawBody, in.Platform)
		if in.PagesRead == 0 && !in.TriedAutoFallbackToWC && (looksLikeJSON || nonStorefrontHTML) {
			return makeFallbackWC()
		}
		if in.PagesRead == 0 && in.AutoFallbackFromShopify && nonStorefrontHTML {
			return CatalogPageEvalOutput{Action: "halt", StopReason: "unsupported_storefront", UnsupportedStore: true}
		}
		return CatalogPageEvalOutput{Action: "halt", StopReason: "non_json_body", Challenged: true}
	}

	items := make([]ClampedRecordItem, 0, len(records))
	for _, rec := range records {
		key := rec.ProductID
		if key == "" {
			key = rec.Handle
		}
		if key == "" {
			key = rec.URL
		}
		clamped, rawBytes := ClampCatalogRecord(rec)
		footprint := rawBytes + len(clamped.Variants)*96
		items = append(items, ClampedRecordItem{
			Key:            key,
			Record:         clamped,
			FootprintBytes: footprint,
		})
	}

	nextURL := ""
	if !done {
		nextURL, _ = CatalogSpecNextPage(cfg, in.CurrentURL, rawBody, in.PagesRead, in.Headers)
		if nextURL == "" {
			done = true
		}
	}

	return CatalogPageEvalOutput{
		Action:  "parsed",
		Done:    done,
		NextURL: nextURL,
		Items:   items,
	}
}

// ParseShopifyCurrencyProbe extracts a 3-letter ISO currency code from Shopify `/meta.json` or `/cart.js` JSON.
func ParseShopifyCurrencyProbe(rawBody string) string {
	obj, ok := parseJSONObjectCommerce(rawBody)
	if !ok {
		return ""
	}
	cand := ""
	if s, okS := obj["currency"].(string); okS {
		cand = strings.ToUpper(strings.TrimSpace(s))
	} else if m, okM := obj["currency"].(map[string]any); okM {
		if act, okA := m["active"].(string); okA {
			cand = strings.ToUpper(strings.TrimSpace(act))
		}
	}
	if reISOCurrency3.MatchString(cand) {
		return cand
	}
	return ""
}

// ApplyShopifyCurrencyBackfill populates missing variant currencies in-place with `currency`.
func ApplyShopifyCurrencyBackfill(records []CatalogRecord, currency string) []CatalogRecord {
	curUp := strings.ToUpper(strings.TrimSpace(currency))
	if !reISOCurrency3.MatchString(curUp) {
		return records
	}
	for i := range records {
		for j := range records[i].Variants {
			if records[i].Variants[j].Currency == nil || *records[i].Variants[j].Currency == "" {
				cp := curUp
				records[i].Variants[j].Currency = &cp
			}
		}
	}
	return records
}
