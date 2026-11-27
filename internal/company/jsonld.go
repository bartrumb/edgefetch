package company

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

func jsonUnmarshalString(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func jsonUnmarshalRaw(raw json.RawMessage, v any) error { return json.Unmarshal(raw, v) }

// orgTypes are schema.org types treated as the company entity.
var orgTypes = map[string]bool{
	"organization": true, "corporation": true, "localbusiness": true, "onlinebusiness": true,
	"onlinestore": true, "ngo": true, "newsmediaorganization": true, "educationalorganization": true,
	"governmentorganization": true, "medicalorganization": true, "sportsorganization": true,
	"researchorganization": true, "airline": true, "store": true, "professionalservice": true,
	"financialservice": true, "bankorcreditunion": true, "insuranceagency": true, "workersunion": true,
	"fundingscheme": true, "consortium": true, "cooperative": true, "searchrescueorganization": true,
	"performinggroup": true, "library": true,
}

func isOrgType(t any) bool {
	switch v := t.(type) {
	case string:
		s := asciiLower(v)
		if i := strings.LastIndexAny(s, "/#:"); i >= 0 {
			s = s[i+1:]
		}
		return orgTypes[s]
	case []any:
		for _, x := range v {
			if isOrgType(x) {
				return true
			}
		}
	}
	return false
}

// findOrganization returns the schema.org Organization (or subtype) JSON-LD object on the page, preferring one
// whose `url` / `@id` host matches domain. WebSite.publisher / brand / parentOrganization objects are considered.
func findOrganization(rawHTML, domain string) map[string]any {
	if len(rawHTML) > maxHTMLBodyBytes {
		rawHTML = rawHTML[:maxHTMLBodyBytes]
	}
	objs := extract.ExtractJSONLDObjects(rawHTML, 100)
	var orgs []map[string]any
	for _, o := range objs {
		if isOrgType(o["@type"]) {
			orgs = append(orgs, o)
		}
		for _, k := range []string{"publisher", "provider", "author"} {
			if sub, ok := o[k].(map[string]any); ok && isOrgType(sub["@type"]) {
				orgs = append(orgs, sub)
			}
		}
	}
	if len(orgs) == 0 {
		return nil
	}
	if domain != "" {
		for _, o := range orgs {
			for _, k := range []string{"url", "@id"} {
				if s, ok := o[k].(string); ok && urlMatchesDomain(s, domain) {
					return o
				}
			}
		}
	}
	// Prefer the richest object among those without a conflicting url.
	var best map[string]any
	bestScore := -1
	for _, o := range orgs {
		if domain != "" {
			if s, ok := o["url"].(string); ok && strings.Contains(s, "://") && !urlMatchesDomain(s, domain) {
				continue
			}
		}
		score := 0
		for _, k := range []string{"name", "description", "logo", "sameAs", "address", "foundingDate"} {
			if o[k] != nil {
				score++
			}
		}
		if score > bestScore {
			best, bestScore = o, score
		}
	}
	return best
}

func jsonldStr(o map[string]any, key string, maxLen int) string {
	if o == nil {
		return ""
	}
	v := o[key]
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		v = arr[0]
	}
	if m, ok := v.(map[string]any); ok {
		v = firstPresent(m, "name", "@value")
	}
	return extract.SanitizeSchemaPlainField(v, maxLen)
}

func firstPresent(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	return nil
}

func jsonldURL(o map[string]any, key, baseURL string) string {
	if o == nil {
		return ""
	}
	v := o[key]
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		v = arr[0]
	}
	if m, ok := v.(map[string]any); ok {
		v = firstPresent(m, "url", "contentUrl", "@id")
	}
	return extract.SanitizeSchemaHTTPSURL(v, baseURL)
}

func jsonldLocation(o map[string]any) *Location {
	if o == nil {
		return nil
	}
	addr := o["address"]
	if arr, ok := addr.([]any); ok && len(arr) > 0 {
		addr = arr[0]
	}
	if addr == nil {
		if loc, ok := o["location"].(map[string]any); ok {
			addr = loc["address"]
		}
	}
	m, ok := addr.(map[string]any)
	if !ok {
		if s, ok := addr.(string); ok {
			if a := extract.SanitizeSchemaPlainField(s, 300); a != "" {
				return &Location{Address: a}
			}
		}
		return nil
	}
	loc := &Location{
		City:   jsonldStr(m, "addressLocality", maxShortLen),
		Region: jsonldStr(m, "addressRegion", maxShortLen),
	}
	loc.Country = jsonldStr(m, "addressCountry", maxShortLen)
	if loc.City == "" && loc.Region == "" && loc.Country == "" {
		return nil
	}
	return loc
}

func jsonldEmployees(v any) int64 {
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		v = arr[0]
	}
	if m, ok := v.(map[string]any); ok {
		v = firstPresent(m, "value", "maxValue", "minValue")
	}
	var f float64
	switch t := v.(type) {
	case float64:
		f = t
	case string:
		s := strings.ReplaceAll(strings.TrimSpace(t), ",", "")
		if !allDigits(s) || len(s) > 9 {
			return 0
		}
		var n int64
		for i := 0; i < len(s); i++ {
			n = n*10 + int64(s[i]-'0')
		}
		return n
	default:
		return 0
	}
	if math.IsNaN(f) || f <= 0 || f >= 1e8 {
		return 0
	}
	return int64(f)
}

// anyStrings flattens a string or array-of-strings JSON-LD value.
func anyStrings(v any, limit int) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok && len(out) < limit {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
