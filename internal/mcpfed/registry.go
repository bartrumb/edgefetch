package mcpfed

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	// OfficialMCPRegistryURL is the upstream Official Model Context Protocol Registry v0 endpoint.
	OfficialMCPRegistryURL = "https://registry.modelcontextprotocol.io/v0/servers"
	// GlamaMCPRegistryURL is the upstream Glama MCP Directory v1 endpoint.
	GlamaMCPRegistryURL = "https://glama.ai/api/mcp/v1/servers"
)

var (
	envVarNameStrictRe      = newLazyRegexp(`^[A-Za-z0-9_]{1,80}$`)
	secretEnvVarHeuristicRe = newLazyRegexp(`(?i)KEY|TOKEN|SECRET|PASSWORD|AUTH|PAT`)
)

var forbiddenManifestHeaderNames = map[string]bool{
	"cookie":              true,
	"set-cookie":          true,
	"host":                true,
	":authority":          true,
	":method":             true,
	":path":               true,
	":scheme":             true,
	"origin":              true,
	"referer":             true,
	"forwarded":           true,
	"x-forwarded-for":     true,
	"x-forwarded-host":    true,
	"x-forwarded-proto":   true,
	"x-real-ip":           true,
	"cf-connecting-ip":    true,
	"true-client-ip":      true,
	"content-length":      true,
	"transfer-encoding":   true,
	"connection":          true,
	"keep-alive":          true,
	"upgrade":             true,
	"te":                  true,
	"proxy-authorization": true,
	"mcp-session-id":      true,
}

// MCPRemoteHeaderSpec describes a manifest header advertised by a remote MCP server.
type MCPRemoteHeaderSpec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsRequired  bool   `json:"isRequired"`
	IsSecret    bool   `json:"isSecret"`
	Default     string `json:"default,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
}

// MCPRemoteEndpointSpec describes a validated public HTTPS remote endpoint for an MCP server.
type MCPRemoteEndpointSpec struct {
	Type    string                `json:"type"`
	URL     string                `json:"url"`
	Headers []MCPRemoteHeaderSpec `json:"headers"`
}

// MCPEnvVarSpec describes an environment variable advertised by an MCP package manifest.
type MCPEnvVarSpec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsRequired  bool   `json:"isRequired"`
	IsSecret    bool   `json:"isSecret"`
	Default     string `json:"default,omitempty"`
}

// MCPPackageSpec describes a local package manifest entry for an MCP server.
type MCPPackageSpec struct {
	RegistryType         string          `json:"registryType,omitempty"`
	Identifier           string          `json:"identifier"`
	Version              string          `json:"version,omitempty"`
	Transport            string          `json:"transport,omitempty"`
	EnvironmentVariables []MCPEnvVarSpec `json:"environmentVariables"`
}

// NormalizedMCPRegistryEntry is a normalized, sanitized, deduplicated MCP server listing.
type NormalizedMCPRegistryEntry struct {
	ID            string                  `json:"id"`
	Slug          string                  `json:"slug"`
	Name          string                  `json:"name"`
	Title         string                  `json:"title"`
	Description   string                  `json:"description"`
	Version       string                  `json:"version,omitempty"`
	WebsiteURL    string                  `json:"websiteUrl,omitempty"`
	RepositoryURL string                  `json:"repositoryUrl,omitempty"`
	Sources       []string                `json:"sources"`
	HasRemote     bool                    `json:"hasRemote"`
	Remotes       []MCPRemoteEndpointSpec `json:"remotes"`
	Packages      []MCPPackageSpec        `json:"packages"`
	Domains       []string                `json:"domains"`
}

func boolOrDefault(obj OrderedObject, k1, k2 string, def bool) bool {
	if v, ok := obj.Get(k1); ok && v != nil {
		return isTruthyAny(v)
	}
	if k2 != "" {
		if v, ok := obj.Get(k2); ok && v != nil {
			return isTruthyAny(v)
		}
	}
	return def
}

func isTruthyAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, ok := numberToFiniteFloat(x)
		return ok && f != 0
	default:
		return v != nil
	}
}

func firstStringField(obj OrderedObject, keys ...string) string {
	for _, k := range keys {
		if s, ok := obj.GetString(k); ok {
			return s
		}
	}
	return ""
}

func parseHeadersArray(rawHeaders any) []MCPRemoteHeaderSpec {
	arr, isArr := rawHeaders.([]any)
	if !isArr {
		return []MCPRemoteHeaderSpec{}
	}
	limit := min(len(arr), 20)
	out := make([]MCPRemoteHeaderSpec, 0, limit)
	seen := make(map[string]bool, limit)
	for i := 0; i < limit; i++ {
		h, isObj := arr[i].(OrderedObject)
		if !isObj {
			continue
		}
		rawName, _ := h.GetString("name")
		rawName = strings.TrimSpace(rawName)
		if rawName == "" || !httpTokenHeaderRe.MatchString(rawName) {
			continue
		}
		lower := strings.ToLower(rawName)
		if forbiddenManifestHeaderNames[lower] || seen[lower] {
			continue
		}
		seen[lower] = true
		inferredSecret := boolOrDefault(h, "isSecret", "secret", false) ||
			lower == "authorization" ||
			strings.Contains(lower, "key") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "auth")
		desc := SanitizeManifestString(firstStringField(h, "description"), 240)
		var defVal string
		if rawDef, ok := h.GetString("default"); ok && !inferredSecret {
			defVal = SanitizeManifestString(rawDef, 120)
		}
		var placeholder string
		if rawPh, ok := h.GetString("placeholder"); ok {
			placeholder = SanitizeManifestString(rawPh, 120)
		} else if rawVal, ok := h.GetString("value"); ok && strings.Contains(rawVal, "{") {
			placeholder = SanitizeManifestString(rawVal, 120)
		} else if lower == "authorization" {
			placeholder = "Bearer <token>"
		}
		out = append(out, MCPRemoteHeaderSpec{
			Name:        rawName,
			Description: desc,
			IsRequired:  boolOrDefault(h, "isRequired", "required", true),
			IsSecret:    inferredSecret,
			Default:     defVal,
			Placeholder: placeholder,
		})
	}
	return out
}

func parseEnvVarsArray(rawEnvVars any) []MCPEnvVarSpec {
	arr, isArr := rawEnvVars.([]any)
	if !isArr {
		return []MCPEnvVarSpec{}
	}
	limit := min(len(arr), 25)
	out := make([]MCPEnvVarSpec, 0, limit)
	for i := 0; i < limit; i++ {
		if strItem, isStr := arr[i].(string); isStr {
			n := strings.TrimSpace(strItem)
			if envVarNameStrictRe.MatchString(n) {
				out = append(out, MCPEnvVarSpec{
					Name:       n,
					IsRequired: true,
					IsSecret:   secretEnvVarHeuristicRe.MatchString(n),
				})
			}
			continue
		}
		ev, isObj := arr[i].(OrderedObject)
		if !isObj {
			continue
		}
		rawName, _ := ev.GetString("name")
		name := strings.TrimSpace(rawName)
		if name == "" || !envVarNameStrictRe.MatchString(name) {
			continue
		}
		desc := SanitizeManifestString(firstStringField(ev, "description"), 240)
		isSecret := boolOrDefault(ev, "isSecret", "secret", false) || secretEnvVarHeuristicRe.MatchString(name)
		var defVal string
		if rawDef, ok := ev.GetString("default"); ok && !isSecret {
			defVal = SanitizeManifestString(rawDef, 120)
		}
		out = append(out, MCPEnvVarSpec{
			Name:        name,
			Description: desc,
			IsRequired:  boolOrDefault(ev, "isRequired", "required", false),
			IsSecret:    isSecret,
			Default:     defVal,
		})
	}
	return out
}

func parseRemotesArray(rawRemotes any, selfHost string) []MCPRemoteEndpointSpec {
	arr, isArr := rawRemotes.([]any)
	if !isArr {
		return []MCPRemoteEndpointSpec{}
	}
	limit := min(len(arr), 10)
	out := make([]MCPRemoteEndpointSpec, 0, limit)
	seenURLs := make(map[string]bool, limit)
	for i := 0; i < limit; i++ {
		r, isObj := arr[i].(OrderedObject)
		if !isObj {
			continue
		}
		rawType := firstStringField(r, "type", "transportType", "transport")
		if rawType == "" {
			rawType = "streamable-http"
		}
		rawType = strings.ToLower(strings.TrimSpace(rawType))
		var rType string
		switch rawType {
		case "streamable-http", "http", "streamable_http":
			rType = "streamable-http"
		case "sse":
			rType = "sse"
		default:
			continue
		}
		rawURL, ok := r.GetString("url")
		if !ok {
			continue
		}
		urlCheck := IsSafePublicHTTPSURL(rawURL, selfHost)
		if !urlCheck.OK || seenURLs[urlCheck.Normalized] {
			continue
		}
		seenURLs[urlCheck.Normalized] = true
		rawHdrs, _ := r.Get("headers")
		out = append(out, MCPRemoteEndpointSpec{
			Type:    rType,
			URL:     urlCheck.Normalized,
			Headers: parseHeadersArray(rawHdrs),
		})
	}
	return out
}

func parsePackagesArray(rawPackages any) []MCPPackageSpec {
	arr, isArr := rawPackages.([]any)
	if !isArr {
		return []MCPPackageSpec{}
	}
	limit := min(len(arr), 10)
	out := make([]MCPPackageSpec, 0, limit)
	for i := 0; i < limit; i++ {
		p, isObj := arr[i].(OrderedObject)
		if !isObj {
			continue
		}
		identifier := SanitizeManifestString(firstStringField(p, "identifier", "name"), 160)
		if identifier == "" {
			continue
		}
		regType := SanitizeManifestString(firstStringField(p, "registryType", "registry_name"), 40)
		version := SanitizeManifestString(firstStringField(p, "version"), 48)
		var transportStr string
		if tObj, ok := p.GetObject("transport"); ok {
			transportStr = SanitizeManifestString(firstStringField(tObj, "type"), 40)
		} else if tRaw, ok := p.GetString("transport"); ok {
			transportStr = SanitizeManifestString(tRaw, 40)
		}
		rawEv, hasEv := p.Get("environmentVariables")
		if !hasEv || rawEv == nil {
			rawEv, _ = p.Get("environment_variables")
		}
		out = append(out, MCPPackageSpec{
			RegistryType:         regType,
			Identifier:           identifier,
			Version:              version,
			Transport:            transportStr,
			EnvironmentVariables: parseEnvVarsArray(rawEv),
		})
	}
	return out
}

func extractServerListFromPayload(rawJSON json.RawMessage) ([]any, error) {
	if len(strings.TrimSpace(string(rawJSON))) == 0 || strings.TrimSpace(string(rawJSON)) == "null" {
		return []any{}, nil
	}
	parsedAny, err := ParseOrderedJSON(rawJSON, 32)
	if err != nil {
		return nil, err
	}
	if arr, isArr := parsedAny.([]any); isArr {
		return arr, nil
	}
	if obj, isObj := parsedAny.(OrderedObject); isObj {
		if arr, hasSrv := obj.GetArray("servers"); hasSrv {
			return arr, nil
		}
	}
	return []any{}, nil
}

func extractSafeRepoURL(srv OrderedObject, selfHost string) string {
	var repoRaw string
	if s, ok := srv.GetString("repository"); ok {
		repoRaw = s
	} else if rObj, ok := srv.GetObject("repository"); ok {
		repoRaw, _ = rObj.GetString("url")
	}
	if repoRaw == "" {
		return ""
	}
	c := IsSafePublicHTTPSURL(repoRaw, selfHost)
	if !c.OK {
		return ""
	}
	return c.Normalized
}

// ParseOfficialRegistryPayload normalizes and sanitizes entries from registry.modelcontextprotocol.io.
func ParseOfficialRegistryPayload(rawJSON json.RawMessage, selfHost string) ([]NormalizedMCPRegistryEntry, error) {
	list, err := extractServerListFromPayload(rawJSON)
	if err != nil {
		return nil, err
	}
	limit := min(len(list), 250)
	entries := make([]NormalizedMCPRegistryEntry, 0, limit)
	for i := 0; i < limit; i++ {
		wrapper, isObj := list[i].(OrderedObject)
		if !isObj {
			continue
		}
		srv := wrapper
		if inner, ok := wrapper.GetObject("server"); ok {
			srv = inner
		}
		name := SanitizeManifestString(firstStringField(srv, "name"), 160)
		if name == "" {
			continue
		}
		title := SanitizeManifestString(firstStringField(srv, "title"), 140)
		if title == "" {
			title = name
		}
		description := SanitizeManifestString(firstStringField(srv, "description"), 600)
		version := SanitizeManifestString(firstStringField(srv, "version"), 48)

		var websiteURL string
		if webRaw := firstStringField(srv, "websiteUrl", "homepage"); webRaw != "" {
			if wc := IsSafePublicHTTPSURL(webRaw, selfHost); wc.OK {
				websiteURL = wc.Normalized
			}
		}
		repoURL := extractSafeRepoURL(srv, selfHost)
		rawRemotes, _ := srv.Get("remotes")
		remotes := parseRemotesArray(rawRemotes, selfHost)
		rawPkgs, _ := srv.Get("packages")
		packages := parsePackagesArray(rawPkgs)

		entries = append(entries, NormalizedMCPRegistryEntry{
			ID:            name,
			Slug:          SlugifyMCPServerName(name),
			Name:          name,
			Title:         title,
			Description:   description,
			Version:       version,
			WebsiteURL:    websiteURL,
			RepositoryURL: repoURL,
			Sources:       []string{"official-registry"},
			HasRemote:     len(remotes) > 0,
			Remotes:       remotes,
			Packages:      packages,
			Domains:       []string{},
		})
	}
	return entries, nil
}

// ParseGlamaRegistryPayload normalizes and sanitizes entries from glama.ai/api/mcp/v1/servers.
func ParseGlamaRegistryPayload(rawJSON json.RawMessage, selfHost string) ([]NormalizedMCPRegistryEntry, error) {
	list, err := extractServerListFromPayload(rawJSON)
	if err != nil {
		return nil, err
	}
	limit := min(len(list), 250)
	entries := make([]NormalizedMCPRegistryEntry, 0, limit)
	for i := 0; i < limit; i++ {
		srv, isObj := list[i].(OrderedObject)
		if !isObj {
			continue
		}
		namespace := SanitizeManifestString(firstStringField(srv, "namespace"), 80)
		baseName := SanitizeManifestString(firstStringField(srv, "slug", "name", "id"), 120)
		if baseName == "" {
			continue
		}
		fullName := baseName
		if namespace != "" && !strings.Contains(baseName, "/") {
			fullName = namespace + "/" + baseName
		}
		title := SanitizeManifestString(firstStringField(srv, "name", "title"), 140)
		if title == "" {
			title = fullName
		}
		description := SanitizeManifestString(firstStringField(srv, "description"), 600)
		version := SanitizeManifestString(firstStringField(srv, "version"), 48)
		repoURL := extractSafeRepoURL(srv, selfHost)

		var websiteURL string
		if webRaw := firstStringField(srv, "homepage", "websiteUrl", "url"); webRaw != "" {
			if wc := IsSafePublicHTTPSURL(webRaw, selfHost); wc.OK && !strings.HasSuffix(wc.Hostname, "glama.ai") {
				websiteURL = wc.Normalized
			}
		}

		rawRemotes, _ := srv.Get("remotes")
		remotes := parseRemotesArray(rawRemotes, selfHost)
		rawSrvHeaders, _ := srv.Get("headers")
		for _, pair := range [][2]string{
			{"remoteUrl", "streamable-http"},
			{"httpUrl", "streamable-http"},
			{"streamableHttpUrl", "streamable-http"},
			{"sseUrl", "sse"},
		} {
			if rawF, ok := srv.GetString(pair[0]); ok && rawF != "" {
				if c := IsSafePublicHTTPSURL(rawF, selfHost); c.OK && !hasRemoteURL(remotes, c.Normalized) {
					remotes = append(remotes, MCPRemoteEndpointSpec{
						Type:    pair[1],
						URL:     c.Normalized,
						Headers: parseHeadersArray(rawSrvHeaders),
					})
				}
			}
		}
		if rawEps, ok := srv.Get("endpoints"); ok {
			for _, ep := range parseRemotesArray(rawEps, selfHost) {
				if !hasRemoteURL(remotes, ep.URL) {
					remotes = append(remotes, ep)
				}
			}
		}

		rawEv, _ := srv.Get("environmentVariables")
		envVars := parseEnvVarsArray(rawEv)
		if envSchema, ok := srv.GetObject("environmentVariablesJsonSchema"); ok {
			if props, hasProps := envSchema.GetObject("properties"); hasProps {
				reqSet := make(map[string]bool)
				if reqArr, hasReq := envSchema.GetArray("required"); hasReq {
					for _, r := range reqArr {
						reqSet[stringifyAnySimple(r)] = true
					}
				}
				pLimit := min(len(props), 20)
				for j := 0; j < pLimit; j++ {
					k := props[j].Key
					if !envVarNameStrictRe.MatchString(k) || hasEnvVarName(envVars, k) {
						continue
					}
					var desc string
					if propObj, ok := props[j].Value.(OrderedObject); ok {
						desc = SanitizeManifestString(firstStringField(propObj, "description"), 240)
					}
					envVars = append(envVars, MCPEnvVarSpec{
						Name:        k,
						Description: desc,
						IsRequired:  reqSet[k],
						IsSecret:    secretEnvVarHeuristicRe.MatchString(k),
					})
				}
			}
		}

		rawPkgs, _ := srv.Get("packages")
		packages := parsePackagesArray(rawPkgs)
		if len(packages) == 0 && len(envVars) > 0 {
			packages = append(packages, MCPPackageSpec{
				Identifier:           fullName,
				EnvironmentVariables: envVars,
			})
		}

		entries = append(entries, NormalizedMCPRegistryEntry{
			ID:            fullName,
			Slug:          SlugifyMCPServerName(fullName),
			Name:          fullName,
			Title:         title,
			Description:   description,
			Version:       version,
			WebsiteURL:    websiteURL,
			RepositoryURL: repoURL,
			Sources:       []string{"glama"},
			HasRemote:     len(remotes) > 0,
			Remotes:       remotes,
			Packages:      packages,
			Domains:       InferAssociatedDomains(),
		})
	}
	return entries, nil
}

func hasRemoteURL(remotes []MCPRemoteEndpointSpec, target string) bool {
	for _, r := range remotes {
		if r.URL == target {
			return true
		}
	}
	return false
}

func hasEnvVarName(vars []MCPEnvVarSpec, name string) bool {
	for _, v := range vars {
		if v.Name == name {
			return true
		}
	}
	return false
}

func canonicalDedupeKeys(entry NormalizedMCPRegistryEntry) []string {
	keys := make([]string, 0, len(entry.Remotes)+2)
	if entry.RepositoryURL != "" {
		repoNorm := strings.ToLower(entry.RepositoryURL)
		repoNorm = strings.TrimSuffix(repoNorm, ".git")
		repoNorm = strings.TrimRight(repoNorm, "/")
		keys = append(keys, "repo:"+repoNorm)
	}
	for _, r := range entry.Remotes {
		keys = append(keys, "remote:"+strings.TrimRight(strings.ToLower(r.URL), "/"))
	}
	keys = append(keys, "slug:"+entry.Slug)
	return keys
}

// FuseRegistryEntries deduplicates, merges, and ranks Official MCP Registry and Glama entries.
func FuseRegistryEntries(officialEntries, glamaEntries []NormalizedMCPRegistryEntry) []NormalizedMCPRegistryEntry {
	merged := make([]NormalizedMCPRegistryEntry, 0, len(officialEntries)+len(glamaEntries))
	keyToIndex := make(map[string]int, (len(officialEntries)+len(glamaEntries))*2)

	upsert := func(entry NormalizedMCPRegistryEntry) {
		keys := canonicalDedupeKeys(entry)
		existingIdx := -1
		for _, k := range keys {
			if idx, ok := keyToIndex[k]; ok {
				existingIdx = idx
				break
			}
		}
		if existingIdx < 0 {
			idx := len(merged)
			cloned := entry
			cloned.Sources = append([]string{}, entry.Sources...)
			cloned.Remotes = append([]MCPRemoteEndpointSpec{}, entry.Remotes...)
			cloned.Packages = append([]MCPPackageSpec{}, entry.Packages...)
			cloned.Domains = append([]string{}, entry.Domains...)
			merged = append(merged, cloned)
			for _, k := range keys {
				keyToIndex[k] = idx
			}
			return
		}

		target := &merged[existingIdx]
		for _, src := range entry.Sources {
			if !containsString(target.Sources, src) {
				target.Sources = append(target.Sources, src)
			}
		}
		if target.Description == "" && entry.Description != "" {
			target.Description = entry.Description
		}
		if target.Version == "" && entry.Version != "" {
			target.Version = entry.Version
		}
		if target.WebsiteURL == "" && entry.WebsiteURL != "" {
			target.WebsiteURL = entry.WebsiteURL
		}
		if target.RepositoryURL == "" && entry.RepositoryURL != "" {
			target.RepositoryURL = entry.RepositoryURL
		}
		for _, rem := range entry.Remotes {
			foundIdx := -1
			for ri := range target.Remotes {
				if strings.EqualFold(target.Remotes[ri].URL, rem.URL) {
					foundIdx = ri
					break
				}
			}
			if foundIdx < 0 {
				target.Remotes = append(target.Remotes, rem)
			} else if len(target.Remotes[foundIdx].Headers) == 0 && len(rem.Headers) > 0 {
				target.Remotes[foundIdx].Headers = rem.Headers
			}
		}
		target.HasRemote = len(target.Remotes) > 0
		if len(target.Packages) == 0 && len(entry.Packages) > 0 {
			target.Packages = append(target.Packages, entry.Packages...)
		}
		for _, d := range entry.Domains {
			if !containsString(target.Domains, d) {
				target.Domains = append(target.Domains, d)
			}
		}
		for _, k := range keys {
			keyToIndex[k] = existingIdx
		}
	}

	for _, e := range officialEntries {
		upsert(e)
	}
	for _, e := range glamaEntries {
		upsert(e)
	}

	rankRemote := func(e NormalizedMCPRegistryEntry) int {
		for _, r := range e.Remotes {
			if r.Type == "streamable-http" {
				return 2
			}
		}
		if e.HasRemote {
			return 1
		}
		return 0
	}

	sort.SliceStable(merged, func(i, j int) bool {
		ri, rj := rankRemote(merged[i]), rankRemote(merged[j])
		if ri != rj {
			return ri > rj
		}
		if len(merged[i].Sources) != len(merged[j].Sources) {
			return len(merged[i].Sources) > len(merged[j].Sources)
		}
		return merged[i].Name < merged[j].Name
	})

	return merged
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
