package company

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// maxPlaces bounds the number of places considered from a Maps result.
const maxPlaces = 50

// Place is the best-matching map place for the company (from a Google Maps `search_places` result).
type Place struct {
	Name        string   `json:"name,omitempty"`
	Address     string   `json:"address,omitempty"`
	MapsURL     string   `json:"mapsUrl,omitempty"`
	Phone       string   `json:"phone,omitempty"`
	Website     string   `json:"website,omitempty"`
	Rating      float64  `json:"rating,omitempty"`
	RatingCount int      `json:"ratingCount,omitempty"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
	MatchedBy   string   `json:"matchedBy,omitempty"`
}

// PlacesQueryInput is the `company_places_query` request.
type PlacesQueryInput struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	HQHint string `json:"hqHint,omitempty"`
}

// PlacesQuery builds the `search_places` text query: "<name> headquarters <hqHint>". When name is empty the
// domain label is used. Returns "" when there is nothing to search for.
func PlacesQuery(in PlacesQueryInput) string {
	name := plainOneLine(in.Name, 120)
	if name == "" {
		if d, err := NormalizeDomain(in.Domain); err == nil {
			name = domainLabel(d)
		}
	}
	if name == "" {
		return ""
	}
	q := name + " headquarters"
	if hint := plainOneLine(in.HQHint, 120); hint != "" {
		q += " " + hint
	}
	return q
}

// plainOneLine strips control/invisible characters and collapses whitespace without HTML escaping, for
// use in outbound query text (never rendered).
func plainOneLine(s string, maxLen int) string {
	s = extract.StripInvisibleSmugglingChars(s)
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == ' ' {
			space = true
			continue
		}
		if r == '<' || r == '>' {
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
		if b.Len() >= maxLen {
			break
		}
	}
	return b.String()
}

// parsePlaces accepts `{places:[...]}`, a top-level array, an MCP tool result wrapper
// (`{content:[{type:"text",text:"<json>"}]}` / `{structuredContent:{...}}`), and returns raw place objects.
func parsePlaces(body string) []map[string]any {
	if strings.TrimSpace(body) == "" || len(body) > maxJSONBodyBytes {
		return nil
	}
	var v any
	if json.Unmarshal([]byte(body), &v) != nil {
		return nil
	}
	return placesFromValue(v, 0)
}

func placesFromValue(v any, depth int) []map[string]any {
	if depth > 3 {
		return nil
	}
	switch t := v.(type) {
	case []any:
		var out []map[string]any
		for _, el := range t {
			if m, ok := el.(map[string]any); ok && len(out) < maxPlaces {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		for _, k := range []string{"places", "results"} {
			if arr, ok := t[k].([]any); ok {
				return placesFromValue(arr, depth+1)
			}
		}
		if sc, ok := t["structuredContent"]; ok {
			if out := placesFromValue(sc, depth+1); len(out) > 0 {
				return out
			}
		}
		if content, ok := t["content"].([]any); ok {
			for _, c := range content {
				cm, _ := c.(map[string]any)
				txt, _ := cm["text"].(string)
				if txt == "" || len(txt) > maxJSONBodyBytes {
					continue
				}
				var inner any
				if json.Unmarshal([]byte(txt), &inner) == nil {
					if out := placesFromValue(inner, depth+1); len(out) > 0 {
						return out
					}
				}
			}
		}
		if _, ok := t["formattedAddress"]; ok {
			return []map[string]any{t}
		}
		if _, ok := t["displayName"]; ok {
			return []map[string]any{t}
		}
	}
	return nil
}

func placeText(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case map[string]any:
			if s, ok := v["text"].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func placeNumber(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				return v, true
			}
		case json.Number:
			if f, err := v.Float64(); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

func toPlace(m map[string]any) Place {
	p := Place{
		Name:    cleanText(placeText(m, "displayName", "name", "title"), 200),
		Address: cleanText(placeText(m, "formattedAddress", "address", "shortFormattedAddress"), 300),
		MapsURL: extract.SanitizeSchemaHTTPSURL(placeText(m, "googleMapsUri", "mapsUri", "url"), ""),
		Phone:   cleanText(placeText(m, "internationalPhoneNumber", "nationalPhoneNumber", "phone"), 40),
		Website: extract.SanitizeSchemaHTTPSURL(placeText(m, "websiteUri", "website"), ""),
	}
	if r, ok := placeNumber(m, "rating"); ok && r >= 0 && r <= 5 {
		p.Rating = math.Round(r*10) / 10
	}
	if n, ok := placeNumber(m, "userRatingCount", "ratingCount", "user_ratings_total"); ok && n >= 0 && n < 1e9 {
		p.RatingCount = int(n)
	}
	if loc, ok := m["location"].(map[string]any); ok {
		lat, ok1 := placeNumber(loc, "latitude", "lat")
		lng, ok2 := placeNumber(loc, "longitude", "lng")
		if ok1 && ok2 && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180 {
			p.Latitude, p.Longitude = &lat, &lng
		}
	}
	return p
}

// normalizeCompanyName lowercases, keeps alphanumerics, and drops legal suffix words ("inc", "llc", ...).
func normalizeCompanyName(s string) string {
	var b strings.Builder
	for _, w := range strings.FieldsFunc(asciiLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r > 0x7f)
	}) {
		if legalSuffixWords[w] {
			continue
		}
		b.WriteString(w)
	}
	return b.String()
}

// PickPlace selects the place whose website matches domain; otherwise one whose normalized name equals a
// normalized company name — but a place whose website points at a different domain is never chosen.
func PickPlace(body, domain string, names []string) *Place {
	raw := parsePlaces(body)
	if len(raw) == 0 {
		return nil
	}
	places := make([]Place, 0, len(raw))
	for _, m := range raw {
		places = append(places, toPlace(m))
	}
	if domain != "" {
		for i := range places {
			if places[i].Website != "" && urlMatchesDomain(places[i].Website, domain) {
				places[i].MatchedBy = "website"
				return &places[i]
			}
		}
	}
	wanted := map[string]bool{}
	for _, n := range names {
		if k := normalizeCompanyName(n); len(k) >= 2 {
			wanted[k] = true
		}
	}
	for i := range places {
		p := &places[i]
		if domain != "" && p.Website != "" && !urlMatchesDomain(p.Website, domain) {
			continue
		}
		if wanted[normalizeCompanyName(p.Name)] {
			p.MatchedBy = "name"
			return p
		}
	}
	return nil
}
