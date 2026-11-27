package mcpfed

import "strings"

// First-party MCP presets: vendor-hosted, officially documented remote MCP servers that callers can connect through the
// vault with their own credentials. They are prepended to discovery results when the query is about their domain, so an
// agent searching for "google maps" finds the official server ahead of community wrappers.
//
// Presets never claim scrape-routing domains: connecting one must not silently reroute ordinary page scrapes.

// GoogleMapsMCPURL is Google Maps Platform's hosted MCP endpoint (Maps Grounding Lite / Maps agent tools).
const GoogleMapsMCPURL = "https://mapstools.googleapis.com/mcp"

// GoogleMapsMCPSlug is the slug the hub looks for when enriching company profiles with place data.
const GoogleMapsMCPSlug = "google-maps"

type firstPartyPreset struct {
	entry    NormalizedMCPRegistryEntry
	keywords []string
}

func firstPartyPresets() []firstPartyPreset {
	return []firstPartyPreset{
		{
			entry: NormalizedMCPRegistryEntry{
				ID:    "first-party/google-maps",
				Slug:  GoogleMapsMCPSlug,
				Name:  GoogleMapsMCPSlug,
				Title: "Google Maps (official, Google-hosted)",
				Description: "Google Maps Platform's hosted MCP server (Maps Grounding Lite): place search, place details, " +
					"routes, weather, and Maps URL resolution. Connect with your own Google Maps Platform API key " +
					"(sent as X-Goog-Api-Key; billed to your Google Cloud project).",
				WebsiteURL: "https://developers.google.com/maps/ai/maps-experience-agent-tools",
				Sources:    []string{"first-party"},
				HasRemote:  true,
				Remotes: []MCPRemoteEndpointSpec{{
					Type: "streamable-http",
					URL:  GoogleMapsMCPURL,
					Headers: []MCPRemoteHeaderSpec{{
						Name:        "X-Goog-Api-Key",
						Description: "Google Maps Platform API key with the Maps agent tools (Grounding Lite) API enabled",
						IsRequired:  true,
						IsSecret:    true,
						Placeholder: "AIza...",
					}},
				}},
				Packages: []MCPPackageSpec{},
				Domains:  []string{},
			},
			keywords: []string{"google maps", "maps", "map", "places", "place", "geocod", "routes", "directions", "local business", "poi"},
		},
	}
}

// FirstPartyRegistryEntries returns every first-party preset (for listings and tests).
func FirstPartyRegistryEntries() []NormalizedMCPRegistryEntry {
	presets := firstPartyPresets()
	out := make([]NormalizedMCPRegistryEntry, 0, len(presets))
	for _, p := range presets {
		out = append(out, p.entry)
	}
	return out
}

// PrependFirstPartyPresets puts presets whose keywords match query ahead of the fused registry entries, replacing any
// community entry that points at the same remote URL. An empty query returns entries unchanged.
func PrependFirstPartyPresets(entries []NormalizedMCPRegistryEntry, query string) []NormalizedMCPRegistryEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return entries
	}
	var matched []NormalizedMCPRegistryEntry
	presetURLs := map[string]bool{}
	for _, p := range firstPartyPresets() {
		for _, kw := range p.keywords {
			if strings.Contains(q, kw) {
				matched = append(matched, p.entry)
				for _, r := range p.entry.Remotes {
					presetURLs[strings.TrimRight(strings.ToLower(r.URL), "/")] = true
				}
				break
			}
		}
	}
	if len(matched) == 0 {
		return entries
	}
	out := make([]NormalizedMCPRegistryEntry, 0, len(matched)+len(entries))
	out = append(out, matched...)
	for _, e := range entries {
		dup := false
		for _, r := range e.Remotes {
			if presetURLs[strings.TrimRight(strings.ToLower(r.URL), "/")] {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, e)
		}
	}
	return out
}
