package mcpfed

import (
	"strings"
	"testing"
)

func TestPrependFirstPartyPresetsGoogleMaps(t *testing.T) {
	community := NormalizedMCPRegistryEntry{
		ID: "community/maps-wrapper", Slug: "maps-wrapper", Name: "maps-wrapper",
		Remotes: []MCPRemoteEndpointSpec{{Type: "streamable-http", URL: "https://maps-wrapper.example.com/mcp"}},
	}
	dupOfficial := NormalizedMCPRegistryEntry{
		ID: "community/google-maps-copy", Slug: "gm-copy", Name: "gm-copy",
		Remotes: []MCPRemoteEndpointSpec{{Type: "streamable-http", URL: GoogleMapsMCPURL + "/"}},
	}

	out := PrependFirstPartyPresets([]NormalizedMCPRegistryEntry{community, dupOfficial}, "Google Maps places")
	if len(out) != 2 || out[0].Slug != GoogleMapsMCPSlug || out[1].Slug != "maps-wrapper" {
		t.Fatalf("expected official preset first and the same-URL copy dropped, got %+v", out)
	}
	gm := out[0]
	if !gm.HasRemote || len(gm.Remotes) != 1 || gm.Remotes[0].URL != GoogleMapsMCPURL {
		t.Fatalf("unexpected remote: %+v", gm.Remotes)
	}
	h := gm.Remotes[0].Headers
	if len(h) != 1 || h[0].Name != "X-Goog-Api-Key" || !h[0].IsSecret || !h[0].IsRequired {
		t.Fatalf("expected a required secret X-Goog-Api-Key header, got %+v", h)
	}
	if len(gm.Domains) != 0 {
		t.Fatalf("presets must not claim scrape-routing domains, got %v", gm.Domains)
	}

	// Unrelated or empty queries leave discovery untouched.
	for _, q := range []string{"", "github issues", "postgres"} {
		got := PrependFirstPartyPresets([]NormalizedMCPRegistryEntry{community}, q)
		if len(got) != 1 || got[0].Slug != "maps-wrapper" {
			t.Fatalf("query %q must not inject presets, got %+v", q, got)
		}
	}
	if len(FirstPartyRegistryEntries()) == 0 {
		t.Fatal("expected at least one first-party preset")
	}
}

func TestToolSchemaLimitForOrigin(t *testing.T) {
	if got := ToolSchemaLimitForOrigin("https://mapstools.googleapis.com"); got != FirstPartyMaxToolSchemaBytes {
		t.Fatalf("first-party origin limit = %d", got)
	}
	for _, o := range []string{"", "https://evil.example.com", "https://mapstools.googleapis.com.evil.example", "http://mapstools.googleapis.com", "https://maps.googleapis.com"} {
		if got := ToolSchemaLimitForOrigin(o); got != MaxMCPToolSchemaBytes {
			t.Fatalf("origin %q must keep the 16 KiB H3 limit, got %d", o, got)
		}
	}
}

func TestSanitizeRemoteToolDefsFirstPartyLargeSchema(t *testing.T) {
	// ~40 KiB tools/list: rejected for any server, accepted for the first-party Maps origin, and still sanitized.
	desc := strings.Repeat("Search for places by text query. ", 600)
	raw := []byte(`[{"name":"search_places","description":"` + desc + `","inputSchema":{"type":"object","properties":{"textQuery":{"type":"string"}},"required":["textQuery"]}}]`)
	if r := SanitizeRemoteMCPToolDefsForOrigin(raw, "https://other.example.com"); !r.OversizedRejected {
		t.Fatal("non-first-party origin must reject > 16 KiB")
	}
	r := SanitizeRemoteMCPToolDefsForOrigin(raw, "https://mapstools.googleapis.com")
	if r.OversizedRejected || len(r.Tools) != 1 || r.Tools[0].Name != "search_places" {
		t.Fatalf("first-party origin must accept and sanitize, got %+v", r)
	}
	if len(r.Tools[0].Description) > 260 {
		t.Fatalf("description must still be capped by sanitization, got %d chars", len(r.Tools[0].Description))
	}
}
