package extract

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

//go:embed manifests/*
var embeddedManifestFS embed.FS

// DeclarativeParamSegment defines a strictly validated URL path segment capture.
type DeclarativeParamSegment struct {
	Param       string   `json:"param"`
	Charset     string   `json:"charset,omitempty"`
	AllowValues []string `json:"allowValues,omitempty"`
	Reserved    []string `json:"reserved,omitempty"`
	StripSuffix string   `json:"stripSuffix,omitempty"`
	MinLen      int      `json:"minLen,omitempty"`
	MaxLen      int      `json:"maxLen,omitempty"`
	Greedy      bool     `json:"greedy,omitempty"`
}

// DeclarativeSegmentSpec represents either a literal path segment ("gems") or a DeclarativeParamSegment.
type DeclarativeSegmentSpec struct {
	IsLiteral bool
	Literal   string
	ParamSpec DeclarativeParamSegment
}

// UnmarshalJSON decodes a string literal segment or an object parameter segment.
func (s *DeclarativeSegmentSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var lit string
		if err := json.Unmarshal(trimmed, &lit); err != nil {
			return err
		}
		s.IsLiteral = true
		s.Literal = lit
		return nil
	}
	var ps DeclarativeParamSegment
	if err := json.Unmarshal(trimmed, &ps); err != nil {
		return err
	}
	if strings.TrimSpace(ps.Param) == "" {
		return fmt.Errorf("declarative segment object missing param name")
	}
	s.IsLiteral = false
	s.ParamSpec = ps
	return nil
}

// DeclarativeQueryParamSpec defines an optional query parameter capture and validation rule.
type DeclarativeQueryParamSpec struct {
	Name    string `json:"name"`
	Param   string `json:"param"`
	Charset string `json:"charset,omitempty"`
	MinLen  int    `json:"minLen,omitempty"`
	MaxLen  int    `json:"maxLen,omitempty"`
}

// DeclarativeMatchSpec matches incoming HTTPS URLs without regular-expression backtracking.
type DeclarativeMatchSpec struct {
	ExactSegments *bool                       `json:"exactSegments,omitempty"`
	PathSegments  []DeclarativeSegmentSpec    `json:"pathSegments,omitempty"`
	QueryParams   []DeclarativeQueryParamSpec `json:"queryParams,omitempty"`
	Defaults      map[string]string           `json:"defaults,omitempty"`
	AnyOf         []DeclarativeMatchSpec      `json:"anyOf,omitempty"`
}

// DeclarativeTwinSpec describes the 1-hop HTTPS JSON/text endpoint upgrade.
type DeclarativeTwinSpec struct {
	ID            string   `json:"id,omitempty"`
	FetchURL      string   `json:"fetchUrl"`
	RawPathParams []string `json:"rawPathParams,omitempty"`
	Kind          string   `json:"kind"`
	Accept        string   `json:"accept"`
}

// DeclarativeDynamicKeyPath looks up root[Base][vars[KeyVar]][SubPath].
type DeclarativeDynamicKeyPath struct {
	Base    string `json:"base"`
	KeyVar  string `json:"keyVar"`
	SubPath string `json:"subPath,omitempty"`
}

// DeclarativeSubFieldsJoin joins subfields from objects inside an array (e.g. Crossref given + family).
type DeclarativeSubFieldsJoin struct {
	Fields        []string `json:"fields"`
	Sep           string   `json:"sep"`
	FallbackField string   `json:"fallbackField,omitempty"`
}

// DeclarativeVarSpec extracts and formats a named string variable from JSON.
type DeclarativeVarSpec struct {
	Paths               []string                   `json:"paths,omitempty"`
	DynamicKeyPath      *DeclarativeDynamicKeyPath `json:"dynamicKeyPath,omitempty"`
	Template            string                     `json:"template,omitempty"`
	WhenVars            []string                   `json:"whenVars,omitempty"`
	FallbackVar         string                     `json:"fallbackVar,omitempty"`
	FirstNonMatchingKey string                     `json:"firstNonMatchingKey,omitempty"`
	SubField            string                     `json:"subField,omitempty"`
	SubFieldsJoin       *DeclarativeSubFieldsJoin  `json:"subFieldsJoin,omitempty"`
	ItemWrap            string                     `json:"itemWrap,omitempty"`
	Join                string                     `json:"join,omitempty"`
	Limit               int                        `json:"limit,omitempty"`
	Format              string                     `json:"format,omitempty"`
	TrueValue           string                     `json:"trueValue,omitempty"`
	FalseValue          string                     `json:"falseValue,omitempty"`
	StripFrontmatter    bool                       `json:"stripFrontmatter,omitempty"`
	Trim                bool                       `json:"trim,omitempty"`
	RequireHTTPS        bool                       `json:"requireHttps,omitempty"`
	SliceMax            int                        `json:"sliceMax,omitempty"`
	Default             string                     `json:"default,omitempty"`
	FallbackTemplate    string                     `json:"fallbackTemplate,omitempty"`
}

// DeclarativeBulletSpec renders `- **<Label>**: <Template>` (or `**<Label>**: <Template>` in metaLine).
type DeclarativeBulletSpec struct {
	Label    string `json:"label"`
	Template string `json:"template"`
	WhenVar  string `json:"whenVar,omitempty"`
}

// DeclarativeTableColumn defines a column in a GFM Markdown table section.
type DeclarativeTableColumn struct {
	Header          string   `json:"header"`
	Paths           []string `json:"paths,omitempty"`
	FallbackVar     string   `json:"fallbackVar,omitempty"`
	Format          string   `json:"format,omitempty"`
	OutcomesField   string   `json:"outcomesField,omitempty"`
	PricesField     string   `json:"pricesField,omitempty"`
	DefaultOutcomes []string `json:"defaultOutcomes,omitempty"`
	Code            bool     `json:"code,omitempty"`
	SliceMax        int      `json:"sliceMax,omitempty"`
}

// DeclarativeSectionSpec renders a `## <Heading>` prose, GFM table, or nested bullet list section.
type DeclarativeSectionSpec struct {
	Heading        string                        `json:"heading"`
	TextVar        string                        `json:"textVar,omitempty"`
	ArrayPath      string                        `json:"arrayPath,omitempty"`
	Columns        []DeclarativeTableColumn      `json:"columns,omitempty"`
	ListArrayPath  string                        `json:"listArrayPath,omitempty"`
	Limit          int                           `json:"limit,omitempty"`
	IndentField    string                        `json:"indentField,omitempty"`
	IndentOffset   int                           `json:"indentOffset,omitempty"`
	MaxIndent      int                           `json:"maxIndent,omitempty"`
	ItemTemplate   string                        `json:"itemTemplate,omitempty"`
	RequireItemVar string                        `json:"requireItemVar,omitempty"`
	ItemVars       map[string]DeclarativeVarSpec `json:"itemVars,omitempty"`
}

// DeclarativeFindInArray selects a matching element from a JSON array to serve as the active root object.
type DeclarativeFindInArray struct {
	ArrayPath     string `json:"arrayPath"`
	MatchField    string `json:"matchField"`
	MatchTemplate string `json:"matchTemplate"`
	IgnoreCase    bool   `json:"ignoreCase,omitempty"`
}

// DeclarativeExtractSpec defines how a JSON or text twin payload is converted into Markdown and metadata.
type DeclarativeExtractSpec struct {
	TextMode                string                        `json:"textMode,omitempty"`
	PathParam               string                        `json:"pathParam,omitempty"`
	UnwrapFirstArrayElement bool                          `json:"unwrapFirstArrayElement,omitempty"`
	RootPath                string                        `json:"rootPath,omitempty"`
	FindInArray             *DeclarativeFindInArray       `json:"findInArray,omitempty"`
	RequireFields           []string                      `json:"requireFields,omitempty"`
	RequireAnyFields        []string                      `json:"requireAnyFields,omitempty"`
	RequireVars             []string                      `json:"requireVars,omitempty"`
	Vars                    map[string]DeclarativeVarSpec `json:"vars,omitempty"`
	TitleTemplate           string                        `json:"titleTemplate"`
	TitleWhenVar            string                        `json:"titleWhenVar,omitempty"`
	TitleFallbackTemplate   string                        `json:"titleFallbackTemplate,omitempty"`
	DescriptionVar          string                        `json:"descriptionVar,omitempty"`
	AuthorVar               string                        `json:"authorVar,omitempty"`
	PublishedTimeVar        string                        `json:"publishedTimeVar,omitempty"`
	MetaLine                []DeclarativeBulletSpec       `json:"metaLine,omitempty"`
	IntroVar                string                        `json:"introVar,omitempty"`
	Bullets                 []DeclarativeBulletSpec       `json:"bullets,omitempty"`
	ObjectLinksPath         string                        `json:"objectLinksPath,omitempty"`
	BodyVar                 string                        `json:"bodyVar,omitempty"`
	Sections                []DeclarativeSectionSpec      `json:"sections,omitempty"`
	LinksVars               []string                      `json:"linksVars,omitempty"`
}

// DeclarativeRouteSpec pairs a URL match specification with its twin fetch and extraction contract.
type DeclarativeRouteSpec struct {
	Match   DeclarativeMatchSpec   `json:"match"`
	Twin    DeclarativeTwinSpec    `json:"twin"`
	Extract DeclarativeExtractSpec `json:"extract"`
}

// DeclarativeAdapterManifest is the canonical shared Go + TypeScript declarative JSON adapter contract.
type DeclarativeAdapterManifest struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Category    string                  `json:"category"`
	Description string                  `json:"description"`
	Domains     []string                `json:"domains"`
	ExampleURLs []string                `json:"exampleUrls"`
	Match       *DeclarativeMatchSpec   `json:"match,omitempty"`
	Twin        *DeclarativeTwinSpec    `json:"twin,omitempty"`
	Extract     *DeclarativeExtractSpec `json:"extract,omitempty"`
	Routes      []DeclarativeRouteSpec  `json:"routes,omitempty"`
}

// DeclarativeAdapterSummary describes an embedded declarative site adapter in `GET /v1/extractors` and MCP `find_extractors`.
type DeclarativeAdapterSummary struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	Modes           []string `json:"modes"`
	Domains         []string `json:"domains"`
	UniversalEngine bool     `json:"universalEngine"`
	ExampleURLs     []string `json:"exampleUrls"`
}

// DeclarativeFormattedDoc holds the structured Markdown and metadata produced from a declarative twin payload.
type DeclarativeFormattedDoc struct {
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	Author        string   `json:"author,omitempty"`
	PublishedTime string   `json:"publishedTime,omitempty"`
	Markdown      string   `json:"markdown"`
	Links         []string `json:"links,omitempty"`
}

// DeclarativeTwinMatch represents a resolved 1-hop declarative twin upgrade ready to fetch and format.
type DeclarativeTwinMatch struct {
	ID        string
	AdapterID string
	FetchURL  string
	Kind      classify.Kind
	Accept    string

	route  DeclarativeRouteSpec
	params map[string]string
}

type declarativeWildcard struct {
	kind    string // "suffix" or "prefix"
	pattern string
	adapter *DeclarativeAdapterManifest
}

type declarativeRegistry struct {
	manifests []*DeclarativeAdapterManifest
	summaries []DeclarativeAdapterSummary
	byHost    map[string][]*DeclarativeAdapterManifest
	wildcards []declarativeWildcard
}

var (
	regOnce    sync.Once
	defaultReg *declarativeRegistry
	regInitErr error
)

// ParseDeclarativeManifest parses and validates a single declarative JSON manifest.
func ParseDeclarativeManifest(raw []byte) (*DeclarativeAdapterManifest, error) {
	var m DeclarativeAdapterManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.Name) == "" || len(m.Domains) == 0 {
		return nil, fmt.Errorf("manifest %q missing required metadata", m.ID)
	}
	switch m.Category {
	case "developer", "genai", "jobs", "finance", "public-records", "research-health", "commerce-social":
	default:
		return nil, fmt.Errorf("manifest %q has invalid category %q", m.ID, m.Category)
	}
	if len(m.Routes) == 0 {
		if m.Match == nil || m.Twin == nil || m.Extract == nil {
			return nil, fmt.Errorf("manifest %q must define match/twin/extract or routes", m.ID)
		}
		m.Routes = []DeclarativeRouteSpec{{
			Match:   *m.Match,
			Twin:    *m.Twin,
			Extract: *m.Extract,
		}}
	}
	for i, r := range m.Routes {
		if r.Twin.Kind != "json" && r.Twin.Kind != "text" {
			return nil, fmt.Errorf("manifest %q route %d has unsupported twin kind %q", m.ID, i, r.Twin.Kind)
		}
		if !strings.HasPrefix(r.Twin.FetchURL, "https://") {
			return nil, fmt.Errorf("manifest %q route %d fetchUrl must use https://", m.ID, i)
		}
	}
	return &m, nil
}

// ParseDeclarativeYAMLManifest parses and validates a declarative YAML manifest (explicitly rejecting anchors, aliases, and merge keys).
func ParseDeclarativeYAMLManifest(raw []byte) (*DeclarativeAdapterManifest, error) {
	jsonBytes, err := YAMLToJSON(raw)
	if err != nil {
		return nil, err
	}
	return ParseDeclarativeManifest(jsonBytes)
}

func loadRegistry() *declarativeRegistry {
	regOnce.Do(func() {
		reg := &declarativeRegistry{
			byHost: make(map[string][]*DeclarativeAdapterManifest),
		}
		entries, err := embeddedManifestFS.ReadDir("manifests")
		if err != nil {
			regInitErr = err
			defaultReg = reg
			return
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		seenIDs := make(map[string]bool)
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			nameLower := strings.ToLower(ent.Name())
			isYAML := strings.HasSuffix(nameLower, ".yaml") || strings.HasSuffix(nameLower, ".yml")
			isJSON := strings.HasSuffix(nameLower, ".json")
			if !isYAML && !isJSON {
				continue
			}
			raw, rErr := embeddedManifestFS.ReadFile("manifests/" + ent.Name())
			if rErr != nil {
				regInitErr = rErr
				continue
			}
			var m *DeclarativeAdapterManifest
			var pErr error
			if isYAML {
				m, pErr = ParseDeclarativeYAMLManifest(raw)
			} else {
				m, pErr = ParseDeclarativeManifest(raw)
			}
			if pErr != nil {
				regInitErr = fmt.Errorf("%s: %w", ent.Name(), pErr)
				continue
			}
			if seenIDs[m.ID] {
				regInitErr = fmt.Errorf("duplicate declarative manifest id %q", m.ID)
				continue
			}
			seenIDs[m.ID] = true
			reg.manifests = append(reg.manifests, m)
			reg.summaries = append(reg.summaries, DeclarativeAdapterSummary{
				ID:              m.ID,
				Name:            m.Name,
				Category:        m.Category,
				Description:     m.Description,
				Modes:           []string{"twin"},
				Domains:         append([]string(nil), m.Domains...),
				UniversalEngine: false,
				ExampleURLs:     append([]string(nil), m.ExampleURLs...),
			})
			for _, d := range m.Domains {
				pat := strings.ToLower(strings.TrimSpace(d))
				if pat == "" {
					continue
				}
				if strings.HasPrefix(pat, "*.") && !strings.Contains(pat[2:], "*") {
					reg.wildcards = append(reg.wildcards, declarativeWildcard{kind: "suffix", pattern: pat[1:], adapter: m})
				} else if strings.HasSuffix(pat, ".*") && !strings.Contains(pat[:len(pat)-2], "*") {
					reg.wildcards = append(reg.wildcards, declarativeWildcard{kind: "prefix", pattern: pat[:len(pat)-1], adapter: m})
				} else {
					reg.byHost[pat] = append(reg.byHost[pat], m)
				}
			}
		}
		defaultReg = reg
	})
	return defaultReg
}

// ListDeclarativeAdapters returns metadata summaries for all embedded declarative site adapters.
func ListDeclarativeAdapters() []DeclarativeAdapterSummary {
	reg := loadRegistry()
	out := make([]DeclarativeAdapterSummary, len(reg.summaries))
	for i, s := range reg.summaries {
		out[i] = DeclarativeAdapterSummary{
			ID:              s.ID,
			Name:            s.Name,
			Category:        s.Category,
			Description:     s.Description,
			Modes:           append([]string(nil), s.Modes...),
			Domains:         append([]string(nil), s.Domains...),
			UniversalEngine: s.UniversalEngine,
			ExampleURLs:     append([]string(nil), s.ExampleURLs...),
		}
	}
	return out
}

// FindDeclarativeAdapters filters and ranks embedded declarative site adapters by optional query and category.
func FindDeclarativeAdapters(query, category string, limit int) []DeclarativeAdapterSummary {
	all := ListDeclarativeAdapters()
	catNorm := strings.ToLower(strings.TrimSpace(category))
	qNorm := strings.ToLower(strings.TrimSpace(query))
	tokens := strings.Fields(qNorm)

	type scored struct {
		item  DeclarativeAdapterSummary
		score int
	}
	var matches []scored
	for _, a := range all {
		if catNorm != "" && a.Category != catNorm {
			continue
		}
		if len(tokens) == 0 {
			matches = append(matches, scored{item: a, score: 1})
			continue
		}
		haystack := strings.ToLower(a.ID + " " + a.Name + " " + a.Category + " " + a.Description + " " + strings.Join(a.Domains, " "))
		sc := 0
		if qNorm != "" && (a.ID == qNorm || strings.Contains(strings.ToLower(a.Name), qNorm)) {
			sc += 10
		}
		for _, tok := range tokens {
			if a.ID == tok {
				sc += 8
			} else if strings.Contains(a.ID, tok) {
				sc += 5
			}
			for _, dom := range a.Domains {
				if strings.Contains(strings.ToLower(dom), tok) {
					sc += 5
					break
				}
			}
			if strings.Contains(haystack, tok) {
				sc += 2
			}
		}
		if sc > 0 {
			matches = append(matches, scored{item: a, score: sc})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].item.ID < matches[j].item.ID
	})
	if limit > 0 && len(matches) > limit {
		matches = matches[:limit]
	}
	out := make([]DeclarativeAdapterSummary, len(matches))
	for i, m := range matches {
		out[i] = m.item
	}
	return out
}

// ResolveDeclarativeTwin checks if `rawURL` matches any embedded declarative adapter and returns its 1-hop twin descriptor.
func ResolveDeclarativeTwin(rawURL string) (*DeclarativeTwinMatch, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return nil, false
	}
	reg := loadRegistry()
	var candidates []*DeclarativeAdapterManifest
	seen := make(map[*DeclarativeAdapterManifest]bool)
	for _, a := range reg.byHost[host] {
		if !seen[a] {
			seen[a] = true
			candidates = append(candidates, a)
		}
	}
	for _, w := range reg.wildcards {
		if w.kind == "suffix" && strings.HasSuffix(host, w.pattern) && len(host) > len(w.pattern) && !seen[w.adapter] {
			seen[w.adapter] = true
			candidates = append(candidates, w.adapter)
		} else if w.kind == "prefix" && strings.HasPrefix(host, w.pattern) && len(host) > len(w.pattern) && !seen[w.adapter] {
			seen[w.adapter] = true
			candidates = append(candidates, w.adapter)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}

	rawParts := splitNonEmptyEscapedSegments(u.EscapedPath())
	for _, adapter := range candidates {
		if match, ok := resolveManifestTwinOnParsedURL(adapter, u, host, rawParts); ok {
			return match, true
		}
	}
	return nil, false
}

func resolveManifestTwinOnParsedURL(adapter *DeclarativeAdapterManifest, u *url.URL, host string, rawParts []string) (*DeclarativeTwinMatch, bool) {
	for _, route := range adapter.Routes {
		params, matched := matchDeclarativeRoute(route.Match, u, host, rawParts)
		if !matched {
			continue
		}
		rawSet := make(map[string]bool, len(route.Twin.RawPathParams))
		for _, rp := range route.Twin.RawPathParams {
			rawSet[rp] = true
		}
		fetchURL := expandTemplate(route.Twin.FetchURL, func(key string) string {
			if key == "host" {
				return host
			}
			val := params[key]
			if rawSet[key] {
				return encodeSafeSubpath(val)
			}
			return encodeURIComponent(val)
		})
		if !isSafePublicTwinURL(fetchURL) {
			continue
		}
		twinID := route.Twin.ID
		if twinID == "" {
			twinID = adapter.ID
		}
		kind := classify.KindJSON
		if route.Twin.Kind == "text" {
			kind = classify.KindText
		}
		return &DeclarativeTwinMatch{
			ID:        twinID,
			AdapterID: adapter.ID,
			FetchURL:  fetchURL,
			Kind:      kind,
			Accept:    normalizeDeclarativeAccept(route.Twin.Kind, route.Twin.Accept),
			route:     route,
			params:    params,
		}, true
	}
	return nil, false
}

func normalizeDeclarativeAccept(kind, rawAccept string) string {
	if kind != "text" {
		if strings.TrimSpace(rawAccept) == "" {
			return "application/json"
		}
		return strings.TrimSpace(rawAccept)
	}
	trimmed := strings.ToLower(strings.TrimSpace(rawAccept))
	switch trimmed {
	case "text/html", "text/markdown", "text/x-markdown", "application/xml", "text/xml", "application/rss+xml", "application/atom+xml", "application/json", "text/calendar", "text/plain":
		return trimmed
	default:
		return "text/plain"
	}
}

func isSafePublicTwinURL(raw string) bool {
	if !strings.HasPrefix(raw, "https://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || !strings.Contains(h, ".") || strings.Contains(h, ":") {
		return false
	}
	if net.ParseIP(h) != nil {
		return false
	}
	return true
}

func splitNonEmptyEscapedSegments(escapedPath string) []string {
	raw := strings.Split(escapedPath, "/")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func matchDeclarativeRoute(spec DeclarativeMatchSpec, u *url.URL, host string, rawParts []string) (map[string]string, bool) {
	if len(spec.AnyOf) > 0 {
		for _, sub := range spec.AnyOf {
			if params, ok := matchDeclarativeRoute(sub, u, host, rawParts); ok {
				return params, true
			}
		}
		return nil, false
	}

	params := map[string]string{"host": host}
	for k, v := range spec.Defaults {
		params[k] = v
	}

	exact := true
	if spec.ExactSegments != nil {
		exact = *spec.ExactSegments
	}
	hasGreedy := len(spec.PathSegments) > 0 && !spec.PathSegments[len(spec.PathSegments)-1].IsLiteral && spec.PathSegments[len(spec.PathSegments)-1].ParamSpec.Greedy
	if hasGreedy {
		if len(rawParts) < len(spec.PathSegments) {
			return nil, false
		}
	} else if exact {
		if len(rawParts) != len(spec.PathSegments) {
			return nil, false
		}
	} else {
		if len(rawParts) < len(spec.PathSegments) {
			return nil, false
		}
	}

	for idx, seg := range spec.PathSegments {
		if seg.IsLiteral {
			decPart, err := url.PathUnescape(rawParts[idx])
			if err != nil || decPart != seg.Literal {
				return nil, false
			}
			continue
		}
		ps := seg.ParamSpec
		var candidate string
		if ps.Greedy && idx == len(spec.PathSegments)-1 {
			joinedEscaped := strings.Join(rawParts[idx:], "/")
			unesc, err := url.PathUnescape(joinedEscaped)
			if err != nil {
				return nil, false
			}
			candidate = unesc
		} else {
			unesc, err := url.PathUnescape(rawParts[idx])
			if err != nil {
				return nil, false
			}
			candidate = unesc
		}
		if ps.StripSuffix != "" && strings.HasSuffix(candidate, ps.StripSuffix) {
			candidate = strings.TrimSuffix(candidate, ps.StripSuffix)
		}
		if !validateDeclarativeParam(candidate, ps.Charset, ps.AllowValues, ps.Reserved, ps.MinLen, ps.MaxLen) {
			return nil, false
		}
		params[ps.Param] = candidate
	}

	if len(spec.QueryParams) > 0 {
		q := u.Query()
		for _, qp := range spec.QueryParams {
			val := q.Get(qp.Name)
			if !validateDeclarativeParam(val, qp.Charset, nil, nil, qp.MinLen, qp.MaxLen) {
				return nil, false
			}
			params[qp.Param] = val
		}
	}

	return params, true
}

func validateDeclarativeParam(val, charset string, allowValues, reserved []string, minLen, maxLen int) bool {
	if minLen <= 0 {
		minLen = 1
	}
	if maxLen <= 0 {
		maxLen = 160
	}
	if len(val) < minLen || len(val) > maxLen {
		return false
	}
	if len(allowValues) > 0 {
		matched := false
		for _, av := range allowValues {
			if val == av {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(reserved) > 0 {
		lower := strings.ToLower(val)
		for _, r := range reserved {
			if lower == strings.ToLower(r) {
				return false
			}
		}
	}
	cs := charset
	if cs == "" {
		cs = "pkg"
	}
	switch cs {
	case "alnum":
		for i := 0; i < len(val); i++ {
			if !isASCIIAlnum(val[i]) {
				return false
			}
		}
		return true
	case "alnum_dash", "slug":
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '_' && b != '-' {
				return false
			}
		}
		return true
	case "pkg":
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '_' && b != '-' && b != '.' {
				return false
			}
		}
		return val != "." && val != ".."
	case "model_slug":
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '_' && b != '-' && b != '.' && b != ':' {
				return false
			}
		}
		return val != "." && val != ".."
	case "doi_rest":
		return isValidDOIRest(val)
	case "safe_subpath":
		return isValidSafeSubpath(val)
	default:
		return false
	}
}

func isASCIIAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isValidDOIRest(val string) bool {
	if !strings.HasPrefix(val, "10.") {
		return false
	}
	slashIdx := strings.IndexByte(val, '/')
	if slashIdx < 7 || slashIdx > 12 { // "10." (3) + 4..9 digits
		return false
	}
	for i := 3; i < slashIdx; i++ {
		if val[i] < '0' || val[i] > '9' {
			return false
		}
	}
	suffix := val[slashIdx+1:]
	if len(suffix) == 0 {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		b := suffix[i]
		if b <= 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func isValidSafeSubpath(val string) bool {
	parts := strings.Split(val, "/")
	if len(parts) == 0 {
		return false
	}
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			b := seg[i]
			if b <= 0x20 || b >= 0x7f || b == '?' || b == '#' || b == '\\' {
				return false
			}
		}
	}
	return true
}

func encodeURIComponent(s string) string {
	const hexUpper = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if isASCIIAlnum(b) || b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexUpper[b>>4])
			sb.WriteByte(hexUpper[b&0x0f])
		}
	}
	return sb.String()
}

func encodeSafeSubpath(val string) string {
	parts := strings.Split(val, "/")
	for i, p := range parts {
		parts[i] = encodeURIComponent(p)
	}
	return strings.Join(parts, "/")
}

func isIdentChar(b byte) bool {
	return isASCIIAlnum(b) || b == '_'
}

func expandTemplate(tmpl string, lookup func(string) string) string {
	if strings.IndexByte(tmpl, '{') < 0 {
		return tmpl
	}
	var sb strings.Builder
	sb.Grow(len(tmpl) + 16)
	n := len(tmpl)
	i := 0
	for i < n {
		if tmpl[i] != '{' {
			sb.WriteByte(tmpl[i])
			i++
			continue
		}
		j := i + 1
		for j < n && isIdentChar(tmpl[j]) {
			j++
		}
		if j > i+1 && j < n && tmpl[j] == '}' {
			sb.WriteString(lookup(tmpl[i+1 : j]))
			i = j + 1
		} else {
			sb.WriteByte('{')
			i++
		}
	}
	return sb.String()
}

// Format transforms a fetched JSON or text twin body into clean GitHub-Flavored Markdown and structured metadata.
// Returns `(nil, false)` on malformed, HTML soft-404, or schema-mismatched payloads so callers safely fall back to HTML scraping.
func (m *DeclarativeTwinMatch) Format(rawBody string) (*DeclarativeFormattedDoc, bool) {
	if m == nil {
		return nil, false
	}
	body := strings.TrimPrefix(rawBody, "\ufeff")
	if m.route.Twin.Kind == "text" || m.route.Extract.TextMode != "" {
		return m.formatTextTwin(body)
	}
	return m.formatJSONTwin(body)
}

func isLikelyHTMLSoft404(s string) bool {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed == "" {
		return true
	}
	prefix := trimmed
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	lower := strings.ToLower(prefix)
	return strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html")
}

func (m *DeclarativeTwinMatch) formatTextTwin(rawBody string) (*DeclarativeFormattedDoc, bool) {
	if isLikelyHTMLSoft404(rawBody) {
		return nil, false
	}
	ext := m.route.Extract
	fallbackTitle := strings.TrimSpace(expandTemplate(ext.TitleTemplate, func(k string) string { return m.params[k] }))
	cleanRaw := stripInvisibleSmuggling(rawBody)

	switch ext.TextMode {
	case "yaml_frontmatter_card":
		card := formatDeclarativeYAMLFrontmatterCard(cleanRaw, fallbackTitle)
		return card, card != nil && strings.TrimSpace(card.Markdown) != ""
	case "code_or_markdown_by_path":
		filePath := m.params[ext.PathParam]
		lang, isMd := detectDeclarativeFenceLang(filePath)
		if isMd {
			card := formatDeclarativeYAMLFrontmatterCard(cleanRaw, fallbackTitle)
			return card, card != nil && strings.TrimSpace(card.Markdown) != ""
		}
		return &DeclarativeFormattedDoc{
			Title:    fallbackTitle,
			Markdown: fmt.Sprintf("# %s\n\n%s", fallbackTitle, safeDeclarativeFence(cleanRaw, lang)),
		}, true
	default:
		trimmed := strings.TrimSpace(cleanRaw)
		if trimmed == "" {
			return nil, false
		}
		md := trimmed
		if fallbackTitle != "" && !strings.HasPrefix(trimmed, "# ") {
			md = "# " + fallbackTitle + "\n\n" + trimmed
		}
		return &DeclarativeFormattedDoc{
			Title:    fallbackTitle,
			Markdown: md,
		}, true
	}
}

func (m *DeclarativeTwinMatch) formatJSONTwin(rawBody string) (*DeclarativeFormattedDoc, bool) {
	rawBytes := []byte(rawBody)
	parsed, ok := decodeJSONWithNumbers(rawBytes)
	if !ok || parsed == nil {
		return nil, false
	}
	ext := m.route.Extract
	rootVal := parsed
	unwrappedArray := false
	if ext.UnwrapFirstArrayElement {
		if arr, isArr := rootVal.([]any); isArr {
			if len(arr) == 0 {
				return nil, false
			}
			rootVal = arr[0]
			unwrappedArray = true
		}
	}
	rootObj, isObj := rootVal.(map[string]any)
	if !isObj {
		return nil, false
	}
	if ext.RootPath != "" {
		sub, subOK := getByDotPath(rootObj, ext.RootPath).(map[string]any)
		if !subOK || sub == nil {
			return nil, false
		}
		rootObj = sub
	}
	usedFindInArray := false
	if ext.FindInArray != nil {
		arr, isArr := getByDotPath(rootObj, ext.FindInArray.ArrayPath).([]any)
		if !isArr {
			return nil, false
		}
		want := expandTemplate(ext.FindInArray.MatchTemplate, func(k string) string { return m.params[k] })
		var matched map[string]any
		for _, item := range arr {
			obj, okObj := item.(map[string]any)
			if !okObj {
				continue
			}
			got := jsonScalarToString(obj[ext.FindInArray.MatchField])
			if (ext.FindInArray.IgnoreCase && strings.EqualFold(got, want)) || (!ext.FindInArray.IgnoreCase && got == want) {
				matched = obj
				break
			}
		}
		if matched == nil {
			return nil, false
		}
		rootObj = matched
		usedFindInArray = true
	}

	for _, reqField := range ext.RequireFields {
		v := getByDotPath(rootObj, reqField)
		if _, isStr := v.(string); !isStr {
			return nil, false
		}
	}
	if len(ext.RequireAnyFields) > 0 {
		anyOK := false
		for _, f := range ext.RequireAnyFields {
			if isJSONTruthy(getByDotPath(rootObj, f)) {
				anyOK = true
				break
			}
		}
		if !anyOK {
			return nil, false
		}
	}

	resolved := make(map[string]string, len(ext.Vars))
	visiting := make(map[string]bool)

	var lookup func(string) string
	var evalVar func(string, DeclarativeVarSpec, map[string]any) string

	lookup = func(name string) string {
		if val, done := resolved[name]; done {
			return val
		}
		if spec, exists := ext.Vars[name]; exists {
			if visiting[name] {
				return ""
			}
			visiting[name] = true
			v := evalVar(name, spec, rootObj)
			delete(visiting, name)
			resolved[name] = v
			return v
		}
		return m.params[name]
	}

	orderedKeysFor := func(relPath string) []string {
		if !usedFindInArray {
			var fullSegs []string
			if unwrappedArray {
				fullSegs = append(fullSegs, "0")
			}
			if ext.RootPath != "" {
				fullSegs = append(fullSegs, strings.Split(ext.RootPath, ".")...)
			}
			if relPath != "" {
				fullSegs = append(fullSegs, strings.Split(relPath, ".")...)
			}
			if keys := extractOrderedObjectKeys(rawBytes, fullSegs); len(keys) > 0 {
				return keys
			}
		}
		obj, okObj := getByDotPath(rootObj, relPath).(map[string]any)
		if !okObj {
			return nil
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}

	evalVar = func(_ string, spec DeclarativeVarSpec, activeObj map[string]any) string {
		var val string
		if spec.Template != "" {
			allPresent := true
			for _, w := range spec.WhenVars {
				if lookup(w) == "" {
					allPresent = false
					break
				}
			}
			if allPresent {
				val = expandTemplate(spec.Template, lookup)
			} else if spec.FallbackVar != "" {
				val = lookup(spec.FallbackVar)
			}
		} else if spec.Format == "bool_map" {
			var raw any
			if len(spec.Paths) > 0 {
				raw = getByDotPath(activeObj, spec.Paths[0])
			}
			if isJSONTruthy(raw) {
				val = spec.TrueValue
			} else {
				val = spec.FalseValue
			}
		} else if spec.DynamicKeyPath != nil {
			keyVal := lookup(spec.DynamicKeyPath.KeyVar)
			if keyVal != "" {
				baseObj, okBase := getByDotPath(activeObj, spec.DynamicKeyPath.Base).(map[string]any)
				if okBase {
					entry := baseObj[keyVal]
					if spec.DynamicKeyPath.SubPath != "" {
						if entryObj, okEntry := entry.(map[string]any); okEntry {
							entry = getByDotPath(entryObj, spec.DynamicKeyPath.SubPath)
						} else {
							entry = nil
						}
					}
					val = formatExtractedJSONValue(entry, spec, "")
				}
			}
		} else {
			for _, p := range spec.Paths {
				raw := getByDotPath(activeObj, p)
				if raw == nil {
					continue
				}
				if spec.FirstNonMatchingKey != "" {
					keys := orderedKeysFor(p)
					for _, k := range keys {
						if !strings.Contains(k, spec.FirstNonMatchingKey) {
							val = k
							break
						}
					}
					if val == "" && len(keys) > 0 {
						val = keys[0]
					}
					if val != "" {
						break
					}
					continue
				}
				formatted := formatExtractedJSONValue(raw, spec, p)
				if formatted != "" {
					val = formatted
					break
				}
			}
		}

		if val == "" {
			if spec.FallbackTemplate != "" {
				val = expandTemplate(spec.FallbackTemplate, lookup)
			} else if spec.Default != "" {
				val = spec.Default
			}
		}
		if spec.StripFrontmatter && val != "" {
			val = stripLeadingYAMLFrontmatter(val)
		}
		if spec.Format != "" && spec.Format != "bool_map" && spec.Format != "int_comma" && spec.Format != "usd_compact" && spec.Format != "usd_per_million_tokens" && spec.Format != "date_parts" {
			val = applyStringFormat(val, spec.Format)
		}
		if spec.Trim {
			val = strings.TrimSpace(val)
		}
		val = stripInvisibleSmuggling(val)
		if spec.RequireHTTPS && !strings.HasPrefix(val, "https://") {
			val = ""
		}
		if spec.SliceMax > 0 && val != "" {
			val = sliceRunesMax(val, spec.SliceMax)
		}
		return val
	}

	for name := range ext.Vars {
		_ = lookup(name)
	}
	for _, reqVar := range ext.RequireVars {
		if strings.TrimSpace(lookup(reqVar)) == "" {
			return nil, false
		}
	}

	title := ""
	if ext.TitleWhenVar != "" {
		if lookup(ext.TitleWhenVar) != "" {
			title = expandTemplate(ext.TitleTemplate, lookup)
		} else {
			title = expandTemplate(ext.TitleFallbackTemplate, lookup)
		}
	} else {
		title = expandTemplate(ext.TitleTemplate, lookup)
		if strings.TrimSpace(title) == "" && ext.TitleFallbackTemplate != "" {
			title = expandTemplate(ext.TitleFallbackTemplate, lookup)
		}
	}
	title = stripInvisibleSmuggling(strings.TrimSpace(title))
	if title == "" {
		return nil, false
	}

	var metaParts []string
	for _, ml := range ext.MetaLine {
		if ml.WhenVar != "" && lookup(ml.WhenVar) == "" {
			continue
		}
		rendered := strings.TrimSpace(expandTemplate(ml.Template, lookup))
		if rendered != "" {
			metaParts = append(metaParts, fmt.Sprintf("**%s**: %s", ml.Label, rendered))
		}
	}

	var bulletLines []string
	for _, b := range ext.Bullets {
		if b.WhenVar != "" && lookup(b.WhenVar) == "" {
			continue
		}
		rendered := strings.TrimSpace(expandTemplate(b.Template, lookup))
		if rendered != "" {
			bulletLines = append(bulletLines, fmt.Sprintf("- **%s**: %s", b.Label, rendered))
		}
	}
	if ext.ObjectLinksPath != "" {
		if linksObj, okObj := getByDotPath(rootObj, ext.ObjectLinksPath).(map[string]any); okObj {
			for _, label := range orderedKeysFor(ext.ObjectLinksPath) {
				href, isStr := linksObj[label].(string)
				if isStr && strings.HasPrefix(href, "https://") {
					bulletLines = append(bulletLines, fmt.Sprintf("- **%s**: %s", stripInvisibleSmuggling(label), href))
				}
			}
		}
	}

	intro := ""
	if ext.IntroVar != "" {
		intro = strings.TrimSpace(lookup(ext.IntroVar))
	}
	bodyText := ""
	if ext.BodyVar != "" {
		bodyText = strings.TrimSpace(lookup(ext.BodyVar))
	}

	var renderedSections []string
	for _, sec := range ext.Sections {
		if sec.TextVar != "" {
			txt := strings.TrimSpace(lookup(sec.TextVar))
			if txt != "" {
				renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", sec.Heading, txt))
			}
			continue
		}
		if sec.ArrayPath != "" && len(sec.Columns) > 0 {
			arr, isArr := getByDotPath(rootObj, sec.ArrayPath).([]any)
			if !isArr || len(arr) == 0 {
				continue
			}
			lim := sec.Limit
			if lim <= 0 || lim > len(arr) {
				lim = len(arr)
			}
			headers := make([]string, len(sec.Columns))
			for i, col := range sec.Columns {
				headers[i] = col.Header
			}
			var rows [][]string
			for _, rawItem := range arr[:lim] {
				itemObj, okItem := rawItem.(map[string]any)
				if !okItem {
					continue
				}
				row := make([]string, len(sec.Columns))
				for cIdx, col := range sec.Columns {
					row[cIdx] = renderTableColumnCell(itemObj, col, lookup)
				}
				rows = append(rows, row)
			}
			if len(rows) > 0 {
				renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", sec.Heading, formatDeclarativeGFMTable(headers, rows)))
			}
			continue
		}
		if sec.ListArrayPath != "" && sec.ItemTemplate != "" {
			arr, isArr := getByDotPath(rootObj, sec.ListArrayPath).([]any)
			if !isArr || len(arr) == 0 {
				continue
			}
			lim := sec.Limit
			if lim <= 0 || lim > len(arr) {
				lim = len(arr)
			}
			maxInd := sec.MaxIndent
			if maxInd <= 0 {
				maxInd = 6
			}
			lines := []string{"## " + sec.Heading}
			for _, rawItem := range arr[:lim] {
				itemObj, okItem := rawItem.(map[string]any)
				if !okItem {
					continue
				}
				itemMap := make(map[string]string, len(sec.ItemVars))
				for ivName, ivSpec := range sec.ItemVars {
					itemMap[ivName] = evalVar(ivName, ivSpec, itemObj)
				}
				if sec.RequireItemVar != "" && strings.TrimSpace(itemMap[sec.RequireItemVar]) == "" {
					continue
				}
				depth := 0
				if sec.IndentField != "" {
					if n, okNum := jsonValueToFloat(getByDotPath(itemObj, sec.IndentField)); okNum {
						depth = int(n) + sec.IndentOffset
						if depth < 0 {
							depth = 0
						}
						if depth > maxInd {
							depth = maxInd
						}
					}
				}
				indent := strings.Repeat("  ", depth)
				if sec.RequireItemVar != "" {
					itemMap[sec.RequireItemVar] = collapseNewlinesWithIndent(itemMap[sec.RequireItemVar], indent+"  ")
				}
				rendered := expandTemplate(sec.ItemTemplate, func(k string) string {
					if v, has := itemMap[k]; has {
						return v
					}
					return lookup(k)
				})
				lines = append(lines, fmt.Sprintf("%s- %s", indent, rendered))
			}
			if len(lines) > 1 {
				renderedSections = append(renderedSections, strings.Join(lines, "\n"))
			}
		}
	}

	var blocks []string
	onlyBodyAlreadyTitled := bodyText != "" && strings.HasPrefix(bodyText, "# ") &&
		len(metaParts) == 0 && intro == "" && len(bulletLines) == 0 && len(renderedSections) == 0
	if !onlyBodyAlreadyTitled {
		blocks = append(blocks, "# "+title)
	}
	if len(metaParts) > 0 {
		blocks = append(blocks, strings.Join(metaParts, " · "))
	}
	if intro != "" {
		blocks = append(blocks, intro)
	}
	if len(bulletLines) > 0 {
		blocks = append(blocks, strings.Join(bulletLines, "\n"))
	}
	if bodyText != "" {
		blocks = append(blocks, bodyText)
	}
	blocks = append(blocks, renderedSections...)

	var links []string
	for _, lv := range ext.LinksVars {
		uVal := strings.TrimSpace(lookup(lv))
		if strings.HasPrefix(uVal, "https://") {
			links = append(links, uVal)
		}
	}

	doc := &DeclarativeFormattedDoc{
		Title:    title,
		Markdown: strings.Join(blocks, "\n\n"),
		Links:    links,
	}
	if ext.DescriptionVar != "" {
		doc.Description = lookup(ext.DescriptionVar)
	}
	if ext.AuthorVar != "" {
		doc.Author = lookup(ext.AuthorVar)
	}
	if ext.PublishedTimeVar != "" {
		doc.PublishedTime = lookup(ext.PublishedTimeVar)
	}
	return doc, true
}

func renderTableColumnCell(itemObj map[string]any, col DeclarativeTableColumn, lookup func(string) string) string {
	if col.Format == "paired_percent" {
		outcomes := parseJSONStringArrayField(itemObj[col.OutcomesField], col.DefaultOutcomes)
		prices := parseJSONFloatArrayField(itemObj[col.PricesField])
		parts := make([]string, 0, len(outcomes))
		for idx, o := range outcomes {
			if idx < len(prices) && !math.IsNaN(prices[idx]) && !math.IsInf(prices[idx], 0) {
				parts = append(parts, fmt.Sprintf("%s: %.1f%%", o, prices[idx]*100.0))
			} else {
				parts = append(parts, o)
			}
		}
		if len(parts) == 0 {
			return "-"
		}
		return strings.Join(parts, " · ")
	}

	val := ""
	for _, p := range col.Paths {
		raw := getByDotPath(itemObj, p)
		if raw == nil {
			continue
		}
		switch col.Format {
		case "usd_compact":
			val = formatUSDCompact(raw)
		case "int_comma":
			if f, ok := jsonValueToFloat(raw); ok {
				val = formatIntComma(int64(math.Round(f)))
			}
		case "strip_tags":
			val = stripTagsInlineLinear(jsonScalarToString(raw))
		default:
			val = strings.TrimSpace(jsonScalarToString(raw))
		}
		if val != "" {
			break
		}
	}
	if val == "" && col.FallbackVar != "" {
		val = strings.TrimSpace(lookup(col.FallbackVar))
	}
	val = stripInvisibleSmuggling(val)
	if col.SliceMax > 0 && val != "" {
		val = sliceRunesMax(val, col.SliceMax)
	}
	if val == "" {
		return "-"
	}
	if col.Code {
		return "`" + val + "`"
	}
	return val
}

func parseJSONStringArrayField(raw any, fallback []string) []string {
	var v = raw
	if s, isStr := raw.(string); isStr {
		if dec, ok := decodeJSONWithNumbers([]byte(s)); ok {
			v = dec
		}
	}
	if arr, isArr := v.([]any); isArr {
		out := make([]string, 0, len(arr))
		for _, el := range arr {
			out = append(out, jsonScalarToString(el))
		}
		return out
	}
	return append([]string(nil), fallback...)
}

func parseJSONFloatArrayField(raw any) []float64 {
	var v = raw
	if s, isStr := raw.(string); isStr {
		if dec, ok := decodeJSONWithNumbers([]byte(s)); ok {
			v = dec
		}
	}
	if arr, isArr := v.([]any); isArr {
		out := make([]float64, len(arr))
		for i, el := range arr {
			if f, ok := jsonValueToFloat(el); ok {
				out[i] = f
			} else {
				out[i] = math.NaN()
			}
		}
		return out
	}
	return nil
}

func formatExtractedJSONValue(raw any, spec DeclarativeVarSpec, _ string) string {
	if raw == nil {
		return ""
	}
	switch spec.Format {
	case "int_comma":
		if f, ok := jsonValueToFloat(raw); ok {
			return formatIntComma(int64(math.Round(f)))
		}
		return ""
	case "usd_compact":
		return formatUSDCompact(raw)
	case "usd_per_million_tokens":
		return formatUSDPerMillionTokens(raw)
	case "date_parts":
		arr, isArr := raw.([]any)
		if !isArr || len(arr) == 0 {
			return ""
		}
		parts := make([]string, 0, len(arr))
		for idx, el := range arr {
			f, ok := jsonValueToFloat(el)
			if !ok {
				continue
			}
			n := int64(f)
			if idx == 0 {
				parts = append(parts, strconv.FormatInt(n, 10))
			} else {
				parts = append(parts, fmt.Sprintf("%02d", n))
			}
		}
		return strings.Join(parts, "-")
	}

	if arr, isArr := raw.([]any); isArr {
		lim := spec.Limit
		if lim <= 0 || lim > len(arr) {
			lim = len(arr)
		}
		var items []string
		for _, el := range arr[:lim] {
			itemStr := ""
			if spec.SubFieldsJoin != nil {
				if obj, okObj := el.(map[string]any); okObj {
					var subParts []string
					for _, sf := range spec.SubFieldsJoin.Fields {
						if sv, isS := obj[sf].(string); isS && sv != "" {
							subParts = append(subParts, sv)
						}
					}
					if len(subParts) > 0 {
						itemStr = strings.Join(subParts, spec.SubFieldsJoin.Sep)
					} else if spec.SubFieldsJoin.FallbackField != "" {
						itemStr = jsonScalarToString(obj[spec.SubFieldsJoin.FallbackField])
					}
				}
			} else if spec.SubField != "" {
				if obj, okObj := el.(map[string]any); okObj {
					itemStr = jsonScalarToString(getByDotPath(obj, spec.SubField))
				}
			} else {
				itemStr = jsonScalarToString(el)
			}
			if itemStr != "" {
				if spec.ItemWrap != "" {
					itemStr = spec.ItemWrap + itemStr + spec.ItemWrap
				}
				items = append(items, itemStr)
			}
		}
		if len(items) == 0 {
			return ""
		}
		if spec.Join != "" {
			return strings.Join(items, spec.Join)
		}
		return items[0]
	}

	return jsonScalarToString(raw)
}

func decodeJSONWithNumbers(raw []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func extractOrderedObjectKeys(raw []byte, pathSegs []string) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	keys, _ := walkOrderedJSONKeys(dec, pathSegs)
	return keys
}

func walkOrderedJSONKeys(dec *json.Decoder, segs []string) ([]string, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil, nil
	}
	if len(segs) == 0 {
		if delim != '{' {
			return nil, skipJSONCompositeRest(dec, delim)
		}
		var keys []string
		for dec.More() {
			kt, kErr := dec.Token()
			if kErr != nil {
				return keys, kErr
			}
			if ks, ok := kt.(string); ok {
				keys = append(keys, ks)
			}
			if err := skipJSONValue(dec); err != nil {
				return keys, err
			}
		}
		_, _ = dec.Token() // closing '}'
		return keys, nil
	}

	head := segs[0]
	switch delim {
	case '{':
		var found []string
		for dec.More() {
			kt, kErr := dec.Token()
			if kErr != nil {
				return nil, kErr
			}
			ks, _ := kt.(string)
			if ks == head && found == nil {
				res, rErr := walkOrderedJSONKeys(dec, segs[1:])
				if rErr != nil {
					return res, rErr
				}
				found = res
			} else {
				if err := skipJSONValue(dec); err != nil {
					return nil, err
				}
			}
		}
		_, _ = dec.Token()
		return found, nil
	case '[':
		wantIdx, convErr := strconv.Atoi(head)
		if convErr != nil || wantIdx < 0 {
			return nil, skipJSONCompositeRest(dec, '[')
		}
		idx := 0
		var found []string
		for dec.More() {
			if idx == wantIdx {
				res, rErr := walkOrderedJSONKeys(dec, segs[1:])
				if rErr != nil {
					return res, rErr
				}
				found = res
			} else {
				if err := skipJSONValue(dec); err != nil {
					return nil, err
				}
			}
			idx++
		}
		_, _ = dec.Token()
		return found, nil
	}
	return nil, nil
}

func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, isDelim := tok.(json.Delim); isDelim {
		return skipJSONCompositeRest(dec, delim)
	}
	return nil
}

func skipJSONCompositeRest(dec *json.Decoder, open json.Delim) error {
	depth := 1
	_ = open
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			if d == '{' || d == '[' {
				depth++
			} else if d == '}' || d == ']' {
				depth--
			}
		}
	}
	return nil
}

func getByDotPath(root any, dotPath string) any {
	if dotPath == "" || root == nil {
		return root
	}
	cur := root
	for _, seg := range strings.Split(dotPath, ".") {
		if cur == nil {
			return nil
		}
		switch typed := cur.(type) {
		case map[string]any:
			cur = typed[seg]
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(typed) {
				return nil
			}
			cur = typed[idx]
		default:
			return nil
		}
	}
	return cur
}

func jsonScalarToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func jsonValueToFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case float64:
		return t, !math.IsNaN(t) && !math.IsInf(t, 0)
	case string:
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(trimmed, 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

func isJSONTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0 && !math.IsNaN(f)
	case float64:
		return t != 0 && !math.IsNaN(t)
	default:
		return true
	}
}

func formatIntComma(n int64) string {
	neg := n < 0
	if neg {
		if n == math.MinInt64 {
			return strconv.FormatInt(n, 10)
		}
		n = -n
	}
	raw := strconv.FormatInt(n, 10)
	if len(raw) <= 3 {
		if neg {
			return "-" + raw
		}
		return raw
	}
	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	rem := len(raw) % 3
	if rem > 0 {
		sb.WriteString(raw[:rem])
		if len(raw) > rem {
			sb.WriteByte(',')
		}
	}
	for i := rem; i < len(raw); i += 3 {
		if i > rem {
			sb.WriteByte(',')
		}
		sb.WriteString(raw[i : i+3])
	}
	return sb.String()
}

func formatUSDCompact(v any) string {
	num, ok := jsonValueToFloat(v)
	if !ok {
		return ""
	}
	abs := math.Abs(num)
	sign := ""
	if num < 0 {
		sign = "-"
	}
	if abs >= 1e9 {
		return fmt.Sprintf("%s$%.2fB", sign, abs/1e9)
	}
	if abs >= 1e6 {
		return fmt.Sprintf("%s$%.2fM", sign, abs/1e6)
	}
	if abs >= 1e3 {
		return fmt.Sprintf("%s$%s", sign, formatIntComma(int64(math.Round(abs))))
	}
	return fmt.Sprintf("%s$%.2f", sign, abs)
}

func formatUSDPerMillionTokens(v any) string {
	num, ok := jsonValueToFloat(v)
	if !ok || num < 0 {
		return ""
	}
	if num == 0 {
		return "$0.00 / 1M tokens"
	}
	return fmt.Sprintf("$%.2f / 1M tokens", num*1_000_000.0)
}

func applyStringFormat(s, format string) string {
	switch format {
	case "trim":
		return strings.TrimSpace(s)
	case "strip_tags":
		return stripTagsInlineLinear(s)
	case "jats_abstract":
		cleaned := stripTagsInlineLinear(s)
		if len(cleaned) >= 9 && strings.EqualFold(cleaned[:8], "abstract") && (cleaned[8] == ' ' || cleaned[8] == '\t') {
			cleaned = strings.TrimSpace(cleaned[9:])
		}
		return cleaned
	default:
		return s
	}
}

func stripTagsInlineLinear(input string) string {
	if input == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(input))
	n := len(input)
	i := 0
	for i < n {
		if input[i] != '<' {
			sb.WriteByte(input[i])
			i++
			continue
		}
		j := i + 1
		var quote byte
		for j < n {
			c := input[j]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
			} else {
				if c == '"' || c == '\'' {
					quote = c
				} else if c == '>' {
					break
				}
			}
			j++
		}
		if j < n && input[j] == '>' {
			sb.WriteByte(' ')
			i = j + 1
		} else {
			sb.WriteByte('<')
			i++
		}
	}
	unescaped := html.UnescapeString(sb.String())
	return strings.Join(strings.Fields(unescaped), " ")
}

func stripLeadingYAMLFrontmatter(s string) string {
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.HasPrefix(norm, "---") {
		return s
	}
	searchCap := len(norm)
	if searchCap > 1510 {
		searchCap = 1510
	}
	window := norm[:searchCap]
	closeIdx := strings.Index(window[3:], "\n---")
	if closeIdx < 0 {
		return s
	}
	afterDash := 3 + closeIdx + 4
	if afterDash >= len(norm) || norm[afterDash] != '\n' {
		return s
	}
	for afterDash < len(norm) && norm[afterDash] == '\n' {
		afterDash++
	}
	return norm[afterDash:]
}

func collapseNewlinesWithIndent(s, indent string) string {
	lines := strings.Split(s, "\n")
	var nonEmpty []string
	for _, ln := range lines {
		if len(nonEmpty) == 0 && ln == "" {
			continue
		}
		nonEmpty = append(nonEmpty, ln)
	}
	var out strings.Builder
	prevNL := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' {
			continue
		}
		if s[i] == '\n' {
			if !prevNL {
				out.WriteByte('\n')
				out.WriteString(indent)
				prevNL = true
			}
			continue
		}
		prevNL = false
		out.WriteByte(s[i])
	}
	return out.String()
}

func stripInvisibleSmuggling(s string) string {
	if s == "" {
		return ""
	}
	needsClean := false
	for _, r := range s {
		if (r >= 0xE0000 && r <= 0xE007F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			needsClean = true
			break
		}
	}
	if !needsClean {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if (r >= 0xE0000 && r <= 0xE007F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func sliceRunesMax(s string, maxUnits int) string {
	if maxUnits <= 0 || len(s) <= maxUnits {
		return s
	}
	// Count UTF-16 code units so slicing matches JavaScript String.prototype.slice(0, maxUnits) cleanly
	// while never splitting a UTF-8 code point.
	units := 0
	for byteIdx := 0; byteIdx < len(s); {
		r, width := utf8.DecodeRuneInString(s[byteIdx:])
		uLen := 1
		if r > 0xFFFF {
			uLen = 2
		}
		if units+uLen > maxUnits {
			return s[:byteIdx]
		}
		units += uLen
		byteIdx += width
	}
	return s
}

func escapeDeclarativeGFMCell(val string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 180
	}
	clean := strings.ReplaceAll(val, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "|", "\\|")
	clean = strings.Join(strings.Fields(clean), " ")
	if clean == "" {
		return "-"
	}
	if utf8.RuneCountInString(clean) > maxLen {
		return sliceRunesMax(clean, maxLen-1) + "…"
	}
	return clean
}

func formatDeclarativeGFMTable(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return ""
	}
	headCells := make([]string, len(headers))
	sepCells := make([]string, len(headers))
	for i, h := range headers {
		headCells[i] = escapeDeclarativeGFMCell(h, 80)
		sepCells[i] = "---"
	}
	lines := make([]string, 0, len(rows)+2)
	lines = append(lines, "| "+strings.Join(headCells, " | ")+" |")
	lines = append(lines, "| "+strings.Join(sepCells, " | ")+" |")
	for _, r := range rows {
		cells := make([]string, len(headers))
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			cells[i] = escapeDeclarativeGFMCell(v, 180)
		}
		lines = append(lines, "| "+strings.Join(cells, " | ")+" |")
	}
	return strings.Join(lines, "\n")
}

func safeDeclarativeFence(code, lang string) string {
	maxTicks := 2
	run := 0
	for i := 0; i < len(code); i++ {
		if code[i] == '`' {
			run++
			if run > maxTicks {
				maxTicks = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", maxTicks+1)
	norm := strings.TrimRight(strings.ReplaceAll(code, "\r\n", "\n"), " \t\n")
	return fence + lang + "\n" + norm + "\n" + fence
}

var declarativeCodeFenceMap = map[string]string{
	"ts": "ts", "tsx": "tsx", "js": "js", "jsx": "jsx", "mjs": "js", "cjs": "js",
	"py": "python", "go": "go", "rs": "rust", "rb": "ruby", "java": "java", "kt": "kotlin",
	"swift": "swift", "c": "c", "h": "c", "cpp": "cpp", "hpp": "cpp", "cs": "csharp",
	"php": "php", "sh": "bash", "bash": "bash", "zsh": "zsh", "ps1": "powershell",
	"yaml": "yaml", "yml": "yaml", "toml": "toml", "json": "json", "sql": "sql",
	"graphql": "graphql", "proto": "protobuf", "tf": "hcl", "hcl": "hcl", "nix": "nix",
	"zig": "zig", "lua": "lua", "ex": "elixir", "exs": "elixir", "erl": "erlang",
	"css": "css", "scss": "scss", "html": "html", "xml": "xml",
}

func detectDeclarativeFenceLang(filePath string) (string, bool) {
	base := filePath
	if idx := strings.LastIndexByte(filePath, '/'); idx >= 0 {
		base = filePath[idx+1:]
	}
	lower := strings.ToLower(base)
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return "dockerfile", false
	}
	if lower == "makefile" || lower == "gnumakefile" {
		return "makefile", false
	}
	dot := strings.LastIndexByte(lower, '.')
	if dot < 0 || dot == len(lower)-1 {
		return "", false
	}
	ext := lower[dot+1:]
	if ext == "md" || ext == "mdx" || ext == "markdown" {
		return "markdown", true
	}
	if mapped, ok := declarativeCodeFenceMap[ext]; ok {
		return mapped, false
	}
	return ext, false
}

func firstMarkdownH1(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "# ") {
			h := strings.TrimSpace(line[2:])
			if h != "" {
				return h
			}
		}
	}
	return ""
}

func formatDeclarativeYAMLFrontmatterCard(rawMd, fallbackTitle string) *DeclarativeFormattedDoc {
	norm := strings.ReplaceAll(rawMd, "\r\n", "\n")
	if !strings.HasPrefix(norm, "---\n") {
		title := firstMarkdownH1(norm)
		if title == "" {
			title = fallbackTitle
		}
		trimmed := strings.TrimSpace(norm)
		md := trimmed
		if !strings.HasPrefix(trimmed, "# ") {
			md = "# " + title + "\n\n" + trimmed
		}
		return &DeclarativeFormattedDoc{Title: title, Markdown: md}
	}

	windowEnd := len(norm)
	if windowEnd > 8012 {
		windowEnd = 8012
	}
	closeRel := strings.Index(norm[4:windowEnd], "\n---\n")
	if closeRel < 0 {
		title := firstMarkdownH1(norm)
		if title == "" {
			title = fallbackTitle
		}
		trimmed := strings.TrimSpace(norm)
		md := trimmed
		if !strings.HasPrefix(trimmed, "# ") {
			md = "# " + title + "\n\n" + trimmed
		}
		return &DeclarativeFormattedDoc{Title: title, Markdown: md}
	}

	yamlBlock := norm[4 : 4+closeRel]
	afterFM := 4 + closeRel + 5
	for afterFM < len(norm) && norm[afterFM] == '\n' {
		afterFM++
	}
	body := strings.TrimSpace(norm[afterFM:])

	type kvPair struct{ k, v string }
	var kvPairs []kvPair
	currentKey := ""
	var listItems []string
	flushList := func() {
		if currentKey != "" && len(listItems) > 0 {
			capLen := len(listItems)
			if capLen > 12 {
				capLen = 12
			}
			kvPairs = append(kvPairs, kvPair{k: currentKey, v: strings.Join(listItems[:capLen], ", ")})
		}
		currentKey = ""
		listItems = nil
	}

	for _, line := range strings.Split(yamlBlock, "\n") {
		trimLeft := strings.TrimLeft(line, " \t")
		if currentKey != "" && strings.HasPrefix(trimLeft, "- ") {
			item := strings.TrimSpace(trimLeft[2:])
			item = strings.Trim(item, `"'`)
			item = strings.TrimSpace(item)
			if item != "" && !strings.Contains(item, ":") {
				listItems = append(listItems, item)
			}
			continue
		}
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx > 0 {
			keyCand := line[:colonIdx]
			validKey := true
			for i := 0; i < len(keyCand); i++ {
				b := keyCand[i]
				if !isASCIIAlnum(b) && b != '_' && b != '-' {
					validKey = false
					break
				}
			}
			if validKey {
				flushList()
				val := strings.TrimSpace(line[colonIdx+1:])
				val = strings.Trim(val, `"'`)
				val = strings.TrimSpace(val)
				if val == "" {
					currentKey = keyCand
				} else if len(val) <= 140 && !strings.HasPrefix(val, "{") {
					kvPairs = append(kvPairs, kvPair{k: keyCand, v: val})
				}
			}
		}
	}
	flushList()

	title := firstMarkdownH1(body)
	if title == "" {
		for _, kv := range kvPairs {
			if kv.k == "pretty_name" || kv.k == "title" {
				title = kv.v
				break
			}
		}
	}
	if title == "" {
		title = fallbackTitle
	}

	keepKeys := map[string]bool{
		"license": true, "pipeline_tag": true, "library_name": true, "base_model": true,
		"language": true, "tags": true, "datasets": true, "sdk": true,
		"task_categories": true, "size_categories": true,
	}
	var rows [][]string
	for _, kv := range kvPairs {
		if keepKeys[kv.k] {
			rows = append(rows, []string{"**" + kv.k + "**", kv.v})
			if len(rows) >= 10 {
				break
			}
		}
	}
	tableLines := ""
	if len(rows) > 0 {
		tableLines = formatDeclarativeGFMTable([]string{"Property", "Value"}, rows)
	}

	var parts []string
	if !strings.HasPrefix(body, "# ") {
		parts = append(parts, "# "+title)
	}
	if tableLines != "" {
		parts = append(parts, tableLines)
	}
	if body != "" {
		parts = append(parts, body)
	}
	var desc string
	for _, kv := range kvPairs {
		if kv.k == "description" || kv.k == "summary" {
			desc = kv.v
			break
		}
	}
	return &DeclarativeFormattedDoc{
		Title:       title,
		Description: desc,
		Markdown:    strings.TrimSpace(strings.Join(parts, "\n\n")),
	}
}

// Ensure io is referenced for embedded reader error checks when needed.
var _ = io.EOF
