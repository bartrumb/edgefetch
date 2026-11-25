package mcpfed

import (
	"encoding/json"
	"net/url"
	"strings"
)

var oauthScopeTokenRe = newLazyRegexp(`^[\x21-\x7e]{1,80}$`)

// DiscoveredRemoteOAuthMetadata describes validated RFC 9728 / RFC 8414 OAuth 2.1 endpoints.
type DiscoveredRemoteOAuthMetadata struct {
	Supported                      bool     `json:"supported"`
	RequiresAuthOriginConfirmation bool     `json:"requiresAuthOriginConfirmation,omitempty"`
	Error                          string   `json:"error,omitempty"`
	AuthOrigin                     string   `json:"authOrigin,omitempty"`
	ConnectorOrigin                string   `json:"connectorOrigin,omitempty"`
	Resource                       string   `json:"resource,omitempty"`
	Issuer                         string   `json:"issuer,omitempty"`
	AuthorizationEndpoint          string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint                  string   `json:"tokenEndpoint,omitempty"`
	RegistrationEndpoint           string   `json:"registrationEndpoint,omitempty"`
	ScopesSupported                []string `json:"scopesSupported,omitempty"`
	CodeChallengeMethods           []string `json:"codeChallengeMethods,omitempty"`
}

// NormalizeConfirmedAuthOrigin validates an optional https:// origin without path or query.
func NormalizeConfirmedAuthOrigin(raw, selfHost string) (origin string, ok bool, reason string) {
	if strings.TrimSpace(raw) == "" {
		return "", true, ""
	}
	check := IsSafePublicHTTPSURL(raw, selfHost)
	if !check.OK {
		return "", false, check.Reason
	}
	if (check.Pathname != "" && check.Pathname != "/") || check.Search != "" {
		return "", false, "confirmedAuthOrigin must be an exact https:// origin without path or query"
	}
	return check.Origin, true, ""
}

// OAuthProbePlan holds candidate RFC 9728 Protected Resource Metadata URLs for a remote MCP endpoint.
type OAuthProbePlan struct {
	OK                 bool     `json:"ok"`
	Reason             string   `json:"reason,omitempty"`
	NormalizedRemote   string   `json:"normalizedRemote,omitempty"`
	ConnectorOrigin    string   `json:"connectorOrigin,omitempty"`
	ConfirmedOrigin    string   `json:"confirmedOrigin,omitempty"`
	PRCandidates       []string `json:"prCandidates,omitempty"`
	FallbackCandidates []string `json:"fallbackCandidates,omitempty"`
}

// PrepareOAuthProbe validates remoteURL + confirmedAuthOrigin and computes RFC 9728 / RFC 8414 candidate URLs.
func PrepareOAuthProbe(remoteURL, confirmedAuthOrigin, selfHost string) OAuthProbePlan {
	urlCheck := IsSafePublicHTTPSURL(remoteURL, selfHost)
	if !urlCheck.OK {
		return OAuthProbePlan{OK: false, Reason: urlCheck.Reason}
	}
	confOrigin, confOk, confReason := NormalizeConfirmedAuthOrigin(confirmedAuthOrigin, selfHost)
	if !confOk {
		return OAuthProbePlan{OK: false, Reason: confReason}
	}
	pathSuffix := ""
	if urlCheck.Pathname != "" && urlCheck.Pathname != "/" {
		pathSuffix = strings.TrimRight(urlCheck.Pathname, "/")
	}
	var prCandidates []string
	if pathSuffix != "" {
		prCandidates = []string{
			urlCheck.Origin + "/.well-known/oauth-protected-resource" + pathSuffix,
			urlCheck.Origin + "/.well-known/oauth-protected-resource",
		}
	} else {
		prCandidates = []string{urlCheck.Origin + "/.well-known/oauth-protected-resource"}
	}
	return OAuthProbePlan{
		OK:               true,
		NormalizedRemote: urlCheck.Normalized,
		ConnectorOrigin:  urlCheck.Origin,
		ConfirmedOrigin:  confOrigin,
		PRCandidates:     prCandidates,
		FallbackCandidates: []string{
			urlCheck.Origin + "/.well-known/oauth-authorization-server",
			urlCheck.Origin + "/.well-known/openid-configuration",
		},
	}
}

// OAuthPRMCheckResult is the result of validating an HTTP 200 RFC 9728 Protected Resource Metadata JSON payload.
type OAuthPRMCheckResult struct {
	Valid                          bool     `json:"valid"`
	RequiresAuthOriginConfirmation bool     `json:"requiresAuthOriginConfirmation,omitempty"`
	Error                          string   `json:"error,omitempty"`
	AuthOrigin                     string   `json:"authOrigin,omitempty"`
	ConnectorOrigin                string   `json:"connectorOrigin,omitempty"`
	ResourceURI                    string   `json:"resourceUri,omitempty"`
	AuthIssuerURL                  string   `json:"authIssuerUrl,omitempty"`
	AllowedAuthOrigin              string   `json:"allowedAuthOrigin,omitempty"`
	ASCandidates                   []string `json:"asCandidates,omitempty"`
	ScopesSupported                []string `json:"scopesSupported,omitempty"`
}

func buildASCandidates(authIssuerURL string) []string {
	u, err := url.Parse(authIssuerURL)
	if err != nil {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname())
	issuerPath := ""
	if p := u.EscapedPath(); p != "" && p != "/" {
		issuerPath = strings.TrimRight(p, "/")
	}
	if issuerPath != "" {
		return []string{
			origin + "/.well-known/oauth-authorization-server" + issuerPath,
			origin + issuerPath + "/.well-known/openid-configuration",
		}
	}
	return []string{
		origin + "/.well-known/oauth-authorization-server",
		origin + "/.well-known/openid-configuration",
	}
}

func filterValidOAuthScopes(arr []any) []string {
	out := make([]string, 0, min(len(arr), 20))
	for _, item := range arr {
		s, ok := item.(string)
		if ok && oauthScopeTokenRe.MatchString(s) {
			out = append(out, s)
			if len(out) >= 20 {
				break
			}
		}
	}
	return out
}

// ValidateOAuthProtectedResource enforces RFC 9728 §3.3 resource pinning, shared-hosting sibling tenant isolation,
// and cross-origin authorization server confirmation.
func ValidateOAuthProtectedResource(prRaw json.RawMessage, remoteURL, confirmedAuthOrigin, selfHost string) OAuthPRMCheckResult {
	urlCheck := IsSafePublicHTTPSURL(remoteURL, selfHost)
	if !urlCheck.OK {
		return OAuthPRMCheckResult{Valid: false}
	}
	confOrigin, confOk, _ := NormalizeConfirmedAuthOrigin(confirmedAuthOrigin, selfHost)
	if !confOk {
		return OAuthPRMCheckResult{Valid: false}
	}
	parsedAny, err := ParseOrderedJSON(prRaw, 32)
	if err != nil {
		return OAuthPRMCheckResult{Valid: false}
	}
	prObj, isObj := parsedAny.(OrderedObject)
	if !isObj {
		return OAuthPRMCheckResult{Valid: false}
	}
	resStr, hasRes := prObj.GetString("resource")
	if !hasRes {
		return OAuthPRMCheckResult{Valid: false}
	}
	rc := IsSafePublicHTTPSURL(resStr, selfHost)
	if !rc.OK || rc.Search != "" {
		return OAuthPRMCheckResult{Valid: false}
	}

	connectorOrigin := urlCheck.Origin
	canonicalRemoteNoSlash := strings.TrimRight(urlCheck.Normalized, "/")
	pathSuffix := ""
	if urlCheck.Pathname != "" && urlCheck.Pathname != "/" {
		pathSuffix = strings.TrimRight(urlCheck.Pathname, "/")
	}
	prResourceNoSlash := strings.TrimRight(rc.Normalized, "/")
	matchesExactURL := prResourceNoSlash == canonicalRemoteNoSlash
	matchesPathlessOrigin := pathSuffix == "" && prResourceNoSlash == connectorOrigin
	if !matchesExactURL && !matchesPathlessOrigin {
		return OAuthPRMCheckResult{Valid: false}
	}

	authIssuerURL := connectorOrigin
	allowedAuthOrigin := connectorOrigin

	if rawAS, hasAS := prObj.Get("authorization_servers"); hasAS && rawAS != nil {
		asArr, isArr := rawAS.([]any)
		if !isArr || len(asArr) == 0 {
			return OAuthPRMCheckResult{Valid: false}
		}
		firstAS, isStr := asArr[0].(string)
		if !isStr {
			return OAuthPRMCheckResult{Valid: false}
		}
		asCheck := IsSafePublicHTTPSURL(firstAS, selfHost)
		if !asCheck.OK || asCheck.Search != "" {
			return OAuthPRMCheckResult{Valid: false}
		}
		if asCheck.Origin != connectorOrigin {
			if IsSharedHostingHostname(urlCheck.Hostname) && IsSharedHostingHostname(asCheck.Hostname) {
				return OAuthPRMCheckResult{Valid: false}
			}
			if confOrigin != asCheck.Origin {
				return OAuthPRMCheckResult{
					Valid:                          false,
					RequiresAuthOriginConfirmation: true,
					Error:                          "cross_origin_auth_confirmation_required",
					AuthOrigin:                     asCheck.Origin,
					ConnectorOrigin:                connectorOrigin,
				}
			}
			allowedAuthOrigin = confOrigin
		}
		authIssuerURL = strings.TrimRight(asCheck.Normalized, "/")
	}

	var scopes []string
	if rawScopes, ok := prObj.GetArray("scopes_supported"); ok {
		scopes = filterValidOAuthScopes(rawScopes)
	}

	return OAuthPRMCheckResult{
		Valid:             true,
		ResourceURI:       rc.Normalized,
		AuthIssuerURL:     authIssuerURL,
		AllowedAuthOrigin: allowedAuthOrigin,
		ASCandidates:      buildASCandidates(authIssuerURL),
		ScopesSupported:   scopes,
	}
}

// ValidateOAuthAuthorizationServer enforces RFC 8414 issuer & endpoint same-origin pinning and S256 PKCE support.
func ValidateOAuthAuthorizationServer(
	asRaw json.RawMessage,
	expectedIssuerURL, allowedAuthOrigin, connectorOrigin, resourceURI string,
	prScopes []string,
	selfHost string,
) (meta DiscoveredRemoteOAuthMetadata, abort bool) {
	parsedAny, err := ParseOrderedJSON(asRaw, 32)
	if err != nil {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}
	asObj, isObj := parsedAny.(OrderedObject)
	if !isObj {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}
	issuerStr, ok := asObj.GetString("issuer")
	if !ok {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}
	issCheck := IsSafePublicHTTPSURL(issuerStr, selfHost)
	if !issCheck.OK || issCheck.Search != "" {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}
	expectedNorm := strings.TrimRight(expectedIssuerURL, "/")
	reportedNorm := strings.TrimRight(issCheck.Normalized, "/")
	if reportedNorm != expectedNorm || issCheck.Origin != allowedAuthOrigin {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}

	authEpStr, _ := asObj.GetString("authorization_endpoint")
	tokenEpStr, _ := asObj.GetString("token_endpoint")
	authEpCheck := IsSafePublicHTTPSURL(authEpStr, selfHost)
	tokenEpCheck := IsSafePublicHTTPSURL(tokenEpStr, selfHost)
	if !authEpCheck.OK || !tokenEpCheck.OK {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}
	if authEpCheck.Origin != allowedAuthOrigin || tokenEpCheck.Origin != allowedAuthOrigin {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}

	var validatedRegEndpoint string
	if rawReg, hasReg := asObj.Get("registration_endpoint"); hasReg && rawReg != nil {
		regStr, isStr := rawReg.(string)
		if !isStr {
			return DiscoveredRemoteOAuthMetadata{Supported: false}, true
		}
		regCheck := IsSafePublicHTTPSURL(regStr, selfHost)
		if !regCheck.OK || regCheck.Origin != allowedAuthOrigin {
			return DiscoveredRemoteOAuthMetadata{Supported: false}, true
		}
		validatedRegEndpoint = regCheck.Normalized
	}

	var methods []string
	if rawMethods, hasMethods := asObj.GetArray("code_challenge_methods_supported"); hasMethods {
		for _, m := range rawMethods {
			if s, ok := m.(string); ok {
				methods = append(methods, s)
			}
		}
	} else {
		methods = []string{"S256"}
	}
	hasS256 := false
	for _, m := range methods {
		if m == "S256" {
			hasS256 = true
			break
		}
	}
	if !hasS256 {
		return DiscoveredRemoteOAuthMetadata{Supported: false}, false
	}

	scopes := prScopes
	if len(scopes) == 0 {
		if rawScopes, ok := asObj.GetArray("scopes_supported"); ok {
			scopes = filterValidOAuthScopes(rawScopes)
		}
	}

	out := DiscoveredRemoteOAuthMetadata{
		Supported:             true,
		Resource:              resourceURI,
		Issuer:                reportedNorm,
		AuthorizationEndpoint: authEpCheck.Normalized,
		TokenEndpoint:         tokenEpCheck.Normalized,
		RegistrationEndpoint:  validatedRegEndpoint,
		ScopesSupported:       scopes,
		CodeChallengeMethods:  methods,
	}
	if allowedAuthOrigin != connectorOrigin {
		out.AuthOrigin = allowedAuthOrigin
		out.ConnectorOrigin = connectorOrigin
	}
	return out, false
}

// OAuthTokenEndpointCheck holds the result of validating an OAuth token_endpoint before code exchange or refresh.
type OAuthTokenEndpointCheck struct {
	OK            bool   `json:"ok"`
	NormalizedURL string `json:"normalizedUrl,omitempty"`
	Status        int    `json:"status,omitempty"`
	Error         string `json:"error,omitempty"`
	Message       string `json:"message,omitempty"`
}

// ValidateOAuthTokenEndpoint validates tokenEndpoint + expectedIssuer against allowedAuthOrigin and SSRF rules.
func ValidateOAuthTokenEndpoint(tokenEndpoint, expectedIssuer, confirmedAuthOrigin, remoteOrigin, selfHost string) OAuthTokenEndpointCheck {
	allowedAuthOrigin := strings.ToLower(strings.TrimSpace(remoteOrigin))
	if strings.TrimSpace(confirmedAuthOrigin) != "" {
		allowedAuthOrigin = strings.ToLower(strings.TrimSpace(confirmedAuthOrigin))
	}
	epCheck := IsSafePublicHTTPSURL(tokenEndpoint, selfHost)
	if !epCheck.OK {
		return OAuthTokenEndpointCheck{
			OK:      false,
			Status:  400,
			Error:   "unsafe_token_endpoint",
			Message: epCheck.Reason,
		}
	}
	if epCheck.Origin != allowedAuthOrigin {
		return OAuthTokenEndpointCheck{
			OK:      false,
			Status:  409,
			Error:   "cross_origin_auth_confirmation_required",
			Message: "Token endpoint origin does not match connector origin or confirmed authorization server origin.",
		}
	}
	if strings.TrimSpace(expectedIssuer) != "" {
		issCheck := IsSafePublicHTTPSURL(strings.TrimRight(strings.TrimSpace(expectedIssuer), "/"), selfHost)
		if !issCheck.OK || issCheck.Origin != allowedAuthOrigin || epCheck.Origin != issCheck.Origin {
			return OAuthTokenEndpointCheck{
				OK:      false,
				Status:  400,
				Error:   "unsafe_token_endpoint",
				Message: "Token endpoint origin does not match expected issuer origin.",
			}
		}
	}
	return OAuthTokenEndpointCheck{
		OK:            true,
		NormalizedURL: epCheck.Normalized,
	}
}
