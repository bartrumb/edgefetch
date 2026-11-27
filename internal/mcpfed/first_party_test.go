package mcpfed

import "testing"

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
