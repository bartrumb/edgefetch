package company

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const (
	// maxJSONBodyBytes caps every raw JSON body handed in by the hub (SEC companyfacts is the largest, a few MiB).
	maxJSONBodyBytes = 24 << 20
	// maxHTMLBodyBytes caps homepage HTML scanning.
	maxHTMLBodyBytes = 4 << 20
	// maxSearchCandidates bounds Wikidata wbsearchentities candidates considered (and entity follow-up URLs).
	maxSearchCandidates = 5
	// maxLabelIDs bounds the wbgetentities label lookup (the API accepts at most 50 ids).
	maxLabelIDs = 50
	// maxClaimScan bounds the per-property Wikidata claim scan.
	maxClaimScan = 2000
)

// Source identifiers used in Profile.FieldSources / Profile.Sources.
const (
	SourceInput           = "input"
	SourceHomepageJSONLD  = "homepage_jsonld"
	SourceHomepageMeta    = "homepage_meta"
	SourceHomepageLinks   = "homepage_links"
	SourceWikidata        = "wikidata"
	SourceSECSubmissions  = "sec_submissions"
	SourceSECCompanyFacts = "sec_companyfacts"
	SourceGitHub          = "github"
	SourceATS             = "ats"
	SourceGoogleMaps      = "google_maps"
)

// ErrNoInput is returned by Plan when neither name nor domain is given.
var ErrNoInput = errors.New("company: name or domain is required")

// ErrInvalidDomain is returned when the domain is not a safe public hostname.
var ErrInvalidDomain = errors.New("company: invalid or non-public domain")

// PlanInput is the `company_plan` request.
type PlanInput struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// FetchRequest is one GET the hub should perform. Kind is "html" or "json".
type FetchRequest struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Method   string `json:"method"`
	Kind     string `json:"kind"`
	Optional bool   `json:"optional,omitempty"`
}

// PlanOutput is the `company_plan` response.
type PlanOutput struct {
	Name       string         `json:"name,omitempty"`
	Domain     string         `json:"domain,omitempty"`
	SearchTerm string         `json:"searchTerm,omitempty"`
	GitHubSlug string         `json:"githubSlug,omitempty"`
	Requests   []FetchRequest `json:"requests"`
}

// Plan normalizes the input and returns the first wave of fetches (homepage, /about, Wikidata search,
// GitHub org). It performs no network I/O.
func Plan(in PlanInput) (PlanOutput, error) {
	name := cleanText(in.Name, 200)
	rawDomain := strings.TrimSpace(in.Domain)
	if name == "" && rawDomain == "" {
		return PlanOutput{Requests: []FetchRequest{}}, ErrNoInput
	}
	out := PlanOutput{Name: name, Requests: []FetchRequest{}}
	if rawDomain != "" {
		d, err := NormalizeDomain(rawDomain)
		if err != nil {
			return out, err
		}
		out.Domain = d
		out.Requests = append(out.Requests,
			FetchRequest{ID: "homepage", URL: "https://" + d + "/", Method: "GET", Kind: "html"},
			FetchRequest{ID: "about", URL: "https://" + d + "/about", Method: "GET", Kind: "html", Optional: true},
		)
	}
	out.SearchTerm = name
	if out.SearchTerm == "" {
		out.SearchTerm = domainLabel(out.Domain)
	}
	if out.SearchTerm != "" {
		out.Requests = append(out.Requests, FetchRequest{
			ID: "wikidata_search", URL: WikidataSearchURL(out.SearchTerm), Method: "GET", Kind: "json",
		})
	}
	if slug := githubSlug(out.Domain, name); slug != "" {
		out.GitHubSlug = slug
		out.Requests = append(out.Requests, FetchRequest{
			ID: "github_org", URL: GitHubOrgURL(slug), Method: "GET", Kind: "json", Optional: true,
		})
	}
	return out, nil
}

// NormalizeDomain strips scheme, credentials-free authority, port, path, and a leading `www.`, lowercases,
// and validates that the result is a safe public, registrable hostname.
func NormalizeDomain(raw string) (string, error) {
	s := asciiLower(strings.TrimSpace(raw))
	if s == "" || len(s) > 2048 {
		return "", ErrInvalidDomain
	}
	if i := strings.Index(s, "://"); i >= 0 {
		if scheme := s[:i]; scheme != "http" && scheme != "https" {
			return "", ErrInvalidDomain
		}
		s = s[i+3:]
	} else {
		s = strings.TrimPrefix(s, "//")
	}
	if i := strings.IndexAny(s, "/?#\\"); i >= 0 {
		s = s[:i]
	}
	if strings.IndexByte(s, '@') >= 0 {
		return "", ErrInvalidDomain
	}
	if c := strings.LastIndexByte(s, ':'); c >= 0 {
		port := s[c+1:]
		if port == "" || !allDigits(port) {
			return "", ErrInvalidDomain
		}
		s = s[:c]
	}
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "www.")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return "", ErrInvalidDomain
		}
	}
	if !extract.IsSafePublicHostname(s) || extract.GetRegistrableDomain(s) == "" {
		return "", ErrInvalidDomain
	}
	return s, nil
}

// HostMatchesDomain reports whether host equals domain (ignoring `www.`) or shares its registrable domain (eTLD+1).
func HostMatchesDomain(host, domain string) bool {
	h := strings.TrimPrefix(strings.TrimSuffix(asciiLower(strings.TrimSpace(host)), "."), "www.")
	d := strings.TrimPrefix(strings.TrimSuffix(asciiLower(strings.TrimSpace(domain)), "."), "www.")
	if h == "" || d == "" {
		return false
	}
	if h == d {
		return true
	}
	rh, rd := extract.GetRegistrableDomain(h), extract.GetRegistrableDomain(d)
	return rh != "" && rh == rd
}

// urlMatchesDomain parses rawURL and checks its host against domain.
func urlMatchesDomain(rawURL, domain string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	return HostMatchesDomain(u.Hostname(), domain)
}

func domainLabel(domain string) string {
	reg := extract.GetRegistrableDomain(domain)
	if reg == "" {
		return ""
	}
	if i := strings.IndexByte(reg, '.'); i > 0 {
		return reg[:i]
	}
	return reg
}

var legalSuffixWords = map[string]bool{
	"inc": true, "incorporated": true, "llc": true, "ltd": true, "limited": true, "corp": true,
	"corporation": true, "co": true, "company": true, "plc": true, "gmbh": true, "ag": true, "sa": true,
	"nv": true, "bv": true, "lp": true, "llp": true, "pbc": true, "the": true,
}

// githubSlug derives a plausible GitHub org login from the domain label, else from the name.
func githubSlug(domain, name string) string {
	if l := domainLabel(domain); validGitHubLogin(l) && len(l) >= 2 {
		return l
	}
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, w := range strings.FieldsFunc(asciiLower(name), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if legalSuffixWords[w] {
			continue
		}
		b.WriteString(w)
	}
	s := b.String()
	if len(s) >= 2 && validGitHubLogin(s) {
		return s
	}
	return ""
}

func validGitHubLogin(s string) bool {
	if s == "" || len(s) > 39 || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// ---- URL builders ----

// WikidataSearchURL builds the wbsearchentities URL for term.
func WikidataSearchURL(term string) string {
	return "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&language=en&type=item&limit=" +
		strconv.Itoa(maxSearchCandidates) + "&search=" + url.QueryEscape(term)
}

// WikidataEntityURL builds the Special:EntityData JSON URL for a QID ("" when invalid).
func WikidataEntityURL(qid string) string {
	if !validQID(qid) {
		return ""
	}
	return "https://www.wikidata.org/wiki/Special:EntityData/" + qid + ".json"
}

// WikidataEntitiesURL builds one wbgetentities URL fetching labels/descriptions/claims for up to 50 QIDs.
func WikidataEntitiesURL(qids []string, labelsOnly bool) string {
	ids := make([]string, 0, len(qids))
	for _, q := range qids {
		if validQID(q) && len(ids) < maxLabelIDs {
			ids = append(ids, q)
		}
	}
	if len(ids) == 0 {
		return ""
	}
	props := "labels%7Cdescriptions%7Cclaims"
	if labelsOnly {
		props = "labels"
	}
	return "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&languages=en&props=" + props +
		"&ids=" + strings.Join(ids, "%7C")
}

// GitHubOrgURL builds the GitHub REST org URL for a login ("" when invalid).
func GitHubOrgURL(login string) string {
	if !validGitHubLogin(login) {
		return ""
	}
	return "https://api.github.com/orgs/" + asciiLower(login)
}

// PadCIK returns the 10-digit zero-padded SEC CIK, or ok=false when cik is not 1-10 digits / zero.
func PadCIK(cik string) (string, bool) {
	s := strings.TrimSpace(cik)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "CIK"), "cik")
	if s == "" || len(s) > 10 || !allDigits(s) {
		return "", false
	}
	if strings.TrimLeft(s, "0") == "" {
		return "", false
	}
	return strings.Repeat("0", 10-len(s)) + s, true
}

// SECSubmissionsURL builds the data.sec.gov submissions URL ("" when cik invalid).
func SECSubmissionsURL(cik string) string {
	p, ok := PadCIK(cik)
	if !ok {
		return ""
	}
	return "https://data.sec.gov/submissions/CIK" + p + ".json"
}

// SECCompanyFactsURL builds the data.sec.gov XBRL companyfacts URL ("" when cik invalid).
func SECCompanyFactsURL(cik string) string {
	p, ok := PadCIK(cik)
	if !ok {
		return ""
	}
	return "https://data.sec.gov/api/xbrl/companyfacts/CIK" + p + ".json"
}

func validQID(q string) bool {
	if len(q) < 2 || len(q) > 13 || q[0] != 'Q' || q[1] == '0' {
		return false
	}
	return allDigits(q[1:])
}

// ---- Wikidata search ----

// WikidataCandidate is one wbsearchentities hit.
type WikidataCandidate struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
}

// ParseWikidataSearch parses a wbsearchentities response into at most 5 valid candidates.
func ParseWikidataSearch(body string) []WikidataCandidate {
	out := []WikidataCandidate{}
	if body == "" || len(body) > maxJSONBodyBytes {
		return out
	}
	var r struct {
		Search []struct {
			ID          string `json:"id"`
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"search"`
	}
	if json.Unmarshal([]byte(body), &r) != nil {
		return out
	}
	seen := map[string]bool{}
	for _, s := range r.Search {
		if len(out) >= maxSearchCandidates {
			break
		}
		if !validQID(s.ID) || seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, WikidataCandidate{ID: s.ID, Label: cleanText(s.Label, 200), Description: cleanText(s.Description, 300)})
	}
	return out
}

// FollowupsInput is the `company_followups` request.
type FollowupsInput struct {
	WikidataSearchJSON string `json:"wikidataSearchJson"`
	Domain             string `json:"domain,omitempty"`
	Name               string `json:"name,omitempty"`
}

// FollowupsOutput is the `company_followups` response.
type FollowupsOutput struct {
	Candidates         []WikidataCandidate `json:"candidates"`
	WikidataEntityURLs []string            `json:"wikidataEntityUrls"`
	WikidataBatchURL   string              `json:"wikidataBatchUrl,omitempty"`
}

// Followups turns a Wikidata search body into entity fetch URLs (per-QID EntityData and one batched wbgetentities).
func Followups(in FollowupsInput) FollowupsOutput {
	c := ParseWikidataSearch(in.WikidataSearchJSON)
	out := FollowupsOutput{Candidates: c, WikidataEntityURLs: []string{}}
	ids := make([]string, 0, len(c))
	for _, cand := range c {
		out.WikidataEntityURLs = append(out.WikidataEntityURLs, WikidataEntityURL(cand.ID))
		ids = append(ids, cand.ID)
	}
	out.WikidataBatchURL = WikidataEntitiesURL(ids, false)
	return out
}

// ---- Wikidata entities ----

type wdText struct {
	Value string `json:"value"`
}

type wdSnak struct {
	Snaktype  string `json:"snaktype"`
	Datavalue struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	} `json:"datavalue"`
}

type wdClaim struct {
	Mainsnak   wdSnak              `json:"mainsnak"`
	Rank       string              `json:"rank"`
	Qualifiers map[string][]wdSnak `json:"qualifiers"`
}

type wdEntity struct {
	ID           string               `json:"id"`
	Labels       map[string]wdText    `json:"labels"`
	Descriptions map[string]wdText    `json:"descriptions"`
	Claims       map[string][]wdClaim `json:"claims"`
}

// parseWikidataEntities parses a Special:EntityData or wbgetentities body (`{"entities":{...}}`).
func parseWikidataEntities(body string) map[string]*wdEntity {
	if body == "" || len(body) > maxJSONBodyBytes {
		return nil
	}
	var r struct {
		Entities map[string]*wdEntity `json:"entities"`
	}
	if json.Unmarshal([]byte(body), &r) != nil {
		return nil
	}
	out := make(map[string]*wdEntity, len(r.Entities))
	for k, e := range r.Entities {
		if e == nil {
			continue
		}
		id := e.ID
		if id == "" {
			id = k
		}
		if validQID(id) {
			e.ID = id
			out[id] = e
		}
	}
	return out
}

func (e *wdEntity) label() string {
	if e == nil {
		return ""
	}
	for _, lang := range []string{"en", "mul"} {
		if t, ok := e.Labels[lang]; ok && t.Value != "" {
			return t.Value
		}
	}
	return ""
}

func (e *wdEntity) description() string {
	if e == nil {
		return ""
	}
	return e.Descriptions["en"].Value
}

// snakString returns a string datavalue ("" otherwise).
func snakString(s wdSnak) string {
	if s.Snaktype != "" && s.Snaktype != "value" {
		return ""
	}
	var v string
	if json.Unmarshal(s.Datavalue.Value, &v) != nil {
		return ""
	}
	return v
}

// snakEntityID returns the QID of a wikibase-entityid datavalue.
func snakEntityID(s wdSnak) string {
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(s.Datavalue.Value, &v) != nil || !validQID(v.ID) {
		return ""
	}
	return v.ID
}

// snakTime returns (year, sortKey, ok) for a time datavalue such as `+2023-12-31T00:00:00Z`.
func snakTime(s wdSnak) (int, int, bool) {
	var v struct {
		Time      string `json:"time"`
		Precision int    `json:"precision"`
	}
	if json.Unmarshal(s.Datavalue.Value, &v) != nil {
		return 0, 0, false
	}
	return parseWDTime(v.Time)
}

func parseWDTime(t string) (int, int, bool) {
	if strings.HasPrefix(t, "-") {
		return 0, 0, false
	}
	t = strings.TrimPrefix(t, "+")
	parts := strings.SplitN(t, "-", 3)
	if len(parts) < 3 || len(parts[2]) < 2 {
		return 0, 0, false
	}
	y, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.Atoi(parts[1])
	d, e3 := strconv.Atoi(parts[2][:2])
	if e1 != nil || e2 != nil || e3 != nil || y <= 0 || y > 9999 {
		return 0, 0, false
	}
	return y, y*10000 + m*100 + d, true
}

// snakQuantity returns the numeric amount of a quantity datavalue.
func snakQuantity(s wdSnak) (float64, bool) {
	var v struct {
		Amount string `json:"amount"`
	}
	if json.Unmarshal(s.Datavalue.Value, &v) != nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimPrefix(v.Amount, "+"), 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// claimPointInTime returns the P585 sort key of a claim (0 when absent).
func claimPointInTime(c *wdClaim) (int, int) {
	for _, q := range c.Qualifiers["P585"] {
		if y, k, ok := snakTime(q); ok {
			return y, k
		}
	}
	return 0, 0
}

// selectClaim implements the preferWhere semantics for Wikidata statements: a preferred-rank statement wins
// (the latest by point-in-time P585 when several are preferred); otherwise the latest normal-rank statement
// by P585; otherwise the first normal-rank statement. Deprecated statements and novalue/somevalue snaks are
// never selected.
func selectClaim(claims []wdClaim) *wdClaim {
	var best *wdClaim
	bestPreferred, bestKey := false, -1
	for i := range claims {
		if i >= maxClaimScan {
			break
		}
		c := &claims[i]
		if c.Rank == "deprecated" || (c.Mainsnak.Snaktype != "" && c.Mainsnak.Snaktype != "value") {
			continue
		}
		pref := c.Rank == "preferred"
		_, key := claimPointInTime(c)
		switch {
		case best == nil:
		case pref && !bestPreferred:
		case pref == bestPreferred && key > bestKey:
		default:
			continue
		}
		best, bestPreferred, bestKey = c, pref, key
	}
	return best
}

// orderedClaims returns non-deprecated value claims, preferred first, preserving order otherwise.
func orderedClaims(claims []wdClaim) []*wdClaim {
	var pref, norm []*wdClaim
	for i := range claims {
		if i >= maxClaimScan {
			break
		}
		c := &claims[i]
		if c.Rank == "deprecated" || (c.Mainsnak.Snaktype != "" && c.Mainsnak.Snaktype != "value") {
			continue
		}
		if c.Rank == "preferred" {
			pref = append(pref, c)
		} else {
			norm = append(norm, c)
		}
	}
	return append(pref, norm...)
}

func (e *wdEntity) claimString(prop string) string {
	if e == nil {
		return ""
	}
	if c := selectClaim(e.Claims[prop]); c != nil {
		return snakString(c.Mainsnak)
	}
	return ""
}

func (e *wdEntity) claimEntityID(prop string) string {
	if e == nil {
		return ""
	}
	if c := selectClaim(e.Claims[prop]); c != nil {
		return snakEntityID(c.Mainsnak)
	}
	return ""
}

// websites returns every non-deprecated P856 official website.
func (e *wdEntity) websites() []string {
	if e == nil {
		return nil
	}
	var out []string
	for _, c := range orderedClaims(e.Claims["P856"]) {
		if s := snakString(c.Mainsnak); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (e *wdEntity) matchesDomain(domain string) (string, bool) {
	for _, w := range e.websites() {
		if urlMatchesDomain(w, domain) {
			return w, true
		}
	}
	return "", false
}

func (e *wdEntity) cik() string {
	if e == nil {
		return ""
	}
	if p, ok := PadCIK(e.claimString("P5531")); ok {
		return p
	}
	return ""
}

var orgDescriptionWords = []string{
	"company", "corporation", "business", "organization", "organisation", "enterprise", "manufacturer",
	"firm", "conglomerate", "retailer", "bank", "airline", "publisher", "developer", "nonprofit",
	"non-profit", "subsidiary", "startup", "brand", "automaker", "provider", "agency", "foundation",
	"cooperative", "holding", "group of companies", "software", "chain",
}

func looksLikeOrganization(desc string) bool {
	d := asciiLower(desc)
	if d == "" || strings.Contains(d, "disambiguation") || strings.Contains(d, "family name") ||
		strings.Contains(d, "given name") {
		return false
	}
	for _, w := range orgDescriptionWords {
		if strings.Contains(d, w) {
			return true
		}
	}
	return false
}

// PickInput is the `company_pick_wikidata` request. EntityJSONs holds Special:EntityData or wbgetentities
// bodies (each may contain several entities).
type PickInput struct {
	WikidataSearchJSON string   `json:"wikidataSearchJson"`
	EntityJSONs        []string `json:"entityJsons,omitempty"`
	Domain             string   `json:"domain,omitempty"`
	Name               string   `json:"name,omitempty"`
}

// PickResult is the `company_pick_wikidata` response.
type PickResult struct {
	QID       string           `json:"qid,omitempty"`
	OK        bool             `json:"ok"`
	Reason    string           `json:"reason"`
	Website   string           `json:"website,omitempty"`
	Followups *EntityFollowups `json:"followups,omitempty"`
}

// PickWikidataEntity chooses the Wikidata item for the company. With a domain, only an entity whose P856
// official website host matches the domain (exact, `www.`-stripped, or same registrable domain) is chosen;
// it never picks an uncorroborated entity. Without a domain, the first candidate whose label equals the
// name and whose description looks like an organization wins, else the first organization-like candidate.
func PickWikidataEntity(in PickInput) PickResult {
	cands := ParseWikidataSearch(in.WikidataSearchJSON)
	entities := map[string]*wdEntity{}
	for i, body := range in.EntityJSONs {
		if i >= 2*maxSearchCandidates {
			break
		}
		for k, v := range parseWikidataEntities(body) {
			entities[k] = v
		}
	}
	domain := ""
	if strings.TrimSpace(in.Domain) != "" {
		d, err := NormalizeDomain(in.Domain)
		if err != nil {
			return PickResult{Reason: "invalid_domain"}
		}
		domain = d
	}
	if len(cands) == 0 && len(entities) == 0 {
		return PickResult{Reason: "no_candidates"}
	}
	order := make([]string, 0, len(cands)+len(entities))
	inSearch := map[string]bool{}
	for _, c := range cands {
		order = append(order, c.ID)
		inSearch[c.ID] = true
	}
	var extra []string
	for k := range entities {
		if !inSearch[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	order = append(order, extra...)

	if domain != "" {
		for _, id := range order {
			e := entities[id]
			if e == nil {
				continue
			}
			if w, ok := e.matchesDomain(domain); ok {
				f := entityFollowups(e, domain)
				return PickResult{QID: id, OK: true, Reason: "website_match", Website: w, Followups: &f}
			}
		}
		return PickResult{Reason: "no_corroborated_candidate"}
	}

	name := asciiLower(strings.TrimSpace(in.Name))
	pick := ""
	for _, c := range cands {
		if looksLikeOrganization(c.Description) && name != "" && asciiLower(c.Label) == name {
			pick = c.ID
			break
		}
	}
	if pick == "" {
		for _, c := range cands {
			if looksLikeOrganization(c.Description) {
				pick = c.ID
				break
			}
		}
	}
	if pick == "" {
		return PickResult{Reason: "no_organization_candidate"}
	}
	res := PickResult{QID: pick, OK: true, Reason: "description_match"}
	if e := entities[pick]; e != nil {
		f := entityFollowups(e, "")
		res.Followups = &f
	}
	return res
}

// EntityFollowupsInput is the `company_entity_followups` request.
type EntityFollowupsInput struct {
	EntityJSON string `json:"entityJson"`
	QID        string `json:"qid,omitempty"`
	Domain     string `json:"domain,omitempty"`
}

// EntityFollowups lists the fetches derived from a chosen Wikidata entity.
type EntityFollowups struct {
	QID                string   `json:"qid,omitempty"`
	CIK                string   `json:"cik,omitempty"`
	SECSubmissionsURL  string   `json:"secSubmissionsUrl,omitempty"`
	SECCompanyFactsURL string   `json:"secCompanyFactsUrl,omitempty"`
	LabelIDs           []string `json:"labelIds"`
	LabelsURL          string   `json:"labelsUrl,omitempty"`
	HomepageURL        string   `json:"homepageUrl,omitempty"`
	GitHubOrgURL       string   `json:"githubOrgUrl,omitempty"`
}

// EntityFollowupsFor derives SEC URLs (from P5531 CIK), the label lookup URL for referenced items
// (HQ, country, industry, exchanges), and — when no domain is known — the P856 homepage and P2037 GitHub org.
func EntityFollowupsFor(in EntityFollowupsInput) EntityFollowups {
	ents := parseWikidataEntities(in.EntityJSON)
	var e *wdEntity
	if in.QID != "" {
		e = ents[in.QID]
	} else if len(ents) == 1 {
		for _, v := range ents {
			e = v
		}
	}
	if e == nil {
		return EntityFollowups{LabelIDs: []string{}}
	}
	domain := ""
	if strings.TrimSpace(in.Domain) != "" {
		domain, _ = NormalizeDomain(in.Domain)
	}
	return entityFollowups(e, domain)
}

var labelProps = []string{"P159", "P17", "P452", "P414", "P749", "P127"}

func entityFollowups(e *wdEntity, domain string) EntityFollowups {
	f := EntityFollowups{QID: e.ID, LabelIDs: []string{}}
	if cik := e.cik(); cik != "" {
		f.CIK = cik
		f.SECSubmissionsURL = SECSubmissionsURL(cik)
		f.SECCompanyFactsURL = SECCompanyFactsURL(cik)
	}
	seen := map[string]bool{}
	for _, p := range labelProps {
		for i, c := range orderedClaims(e.Claims[p]) {
			if i >= 5 || len(f.LabelIDs) >= maxLabelIDs {
				break
			}
			if id := snakEntityID(c.Mainsnak); id != "" && !seen[id] {
				seen[id] = true
				f.LabelIDs = append(f.LabelIDs, id)
			}
		}
	}
	f.LabelsURL = WikidataEntitiesURL(f.LabelIDs, true)
	if domain == "" {
		for _, w := range e.websites() {
			if s := extract.SanitizeSchemaHTTPSURL(w, ""); s != "" {
				f.HomepageURL = s
				break
			}
		}
	}
	if gh := e.claimString("P2037"); validGitHubLogin(gh) {
		f.GitHubOrgURL = GitHubOrgURL(gh)
	}
	return f
}

// ---- SEC ----

type secAddress struct {
	City                      string `json:"city"`
	StateOrCountry            string `json:"stateOrCountry"`
	StateOrCountryDescription string `json:"stateOrCountryDescription"`
}

type secSubmissions struct {
	CIK            json.RawMessage `json:"cik"`
	Name           string          `json:"name"`
	SIC            string          `json:"sic"`
	SICDescription string          `json:"sicDescription"`
	Tickers        []any           `json:"tickers"`
	Exchanges      []any           `json:"exchanges"`
	Addresses      struct {
		Business secAddress `json:"business"`
	} `json:"addresses"`
}

func parseSECSubmissions(body string) *secSubmissions {
	if body == "" || len(body) > maxJSONBodyBytes {
		return nil
	}
	var s secSubmissions
	if json.Unmarshal([]byte(body), &s) != nil {
		return nil
	}
	return &s
}

// rawCIK accepts a JSON string or number CIK and returns the padded form.
func rawCIK(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		var n json.Number
		if json.Unmarshal(raw, &n) != nil {
			return ""
		}
		s = n.String()
	}
	p, _ := PadCIK(s)
	return p
}

type secFact struct {
	Start string  `json:"start"`
	End   string  `json:"end"`
	Val   float64 `json:"val"`
	FY    int     `json:"fy"`
	FP    string  `json:"fp"`
	Form  string  `json:"form"`
	Filed string  `json:"filed"`
	Frame string  `json:"frame"`
}

type secCompanyFacts struct {
	CIK   json.RawMessage                       `json:"cik"`
	Facts map[string]map[string]json.RawMessage `json:"facts"`
}

// revenueConcepts lists the us-gaap revenue concepts considered, in tie-break preference order.
var revenueConcepts = []string{
	"Revenues",
	"RevenueFromContractWithCustomerExcludingAssessedTax",
	"RevenueFromContractWithCustomerIncludingAssessedTax",
	"SalesRevenueNet",
}

var annualForms = map[string]bool{
	"10-K": true, "10-K/A": true, "10-KT": true, "20-F": true, "20-F/A": true, "40-F": true, "40-F/A": true,
}

// latestAnnualRevenue selects the most recent full-year USD revenue fact from annual filings. Among facts with
// the same period end, the earliest filing wins (its `fy` describes that period, not a later comparative).
func latestAnnualRevenue(cf *secCompanyFacts) *Revenue {
	if cf == nil {
		return nil
	}
	gaap := cf.Facts["us-gaap"]
	var best *Revenue
	bestEnd, bestFiled, bestConcept := "", "", 99
	for ci, concept := range revenueConcepts {
		raw, ok := gaap[concept]
		if !ok {
			continue
		}
		var c struct {
			Units map[string][]secFact `json:"units"`
		}
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		for i, f := range c.Units["USD"] {
			if i >= 20000 {
				break
			}
			if !annualForms[f.Form] || f.Val <= 0 {
				continue
			}
			days, ok := daysBetween(f.Start, f.End)
			if !ok || days < 340 || days > 380 {
				continue
			}
			better := best == nil || f.End > bestEnd ||
				(f.End == bestEnd && f.Filed < bestFiled) ||
				(f.End == bestEnd && f.Filed == bestFiled && ci < bestConcept)
			if !better {
				continue
			}
			endYear, _ := strconv.Atoi(f.End[:4])
			fy := endYear
			if f.FY > 0 && f.FY >= endYear-1 && f.FY <= endYear+1 {
				fy = f.FY
			}
			best = &Revenue{
				Value: int64(f.Val), Currency: "USD", FiscalYear: fy, PeriodEnd: f.End,
				Form: f.Form, Filed: cleanText(f.Filed, 10), Concept: concept,
			}
			bestEnd, bestFiled, bestConcept = f.End, f.Filed, ci
		}
	}
	return best
}

func daysBetween(start, end string) (int, bool) {
	s, ok1 := dayNumber(start)
	e, ok2 := dayNumber(end)
	if !ok1 || !ok2 || e < s {
		return 0, false
	}
	return e - s, true
}

// dayNumber converts YYYY-MM-DD to a day count (proleptic Gregorian, days since civil epoch).
func dayNumber(d string) (int, bool) {
	if len(d) != 10 || d[4] != '-' || d[7] != '-' {
		return 0, false
	}
	y, e1 := strconv.Atoi(d[:4])
	m, e2 := strconv.Atoi(d[5:7])
	dd, e3 := strconv.Atoi(d[8:])
	if e1 != nil || e2 != nil || e3 != nil || m < 1 || m > 12 || dd < 1 || dd > 31 {
		return 0, false
	}
	if m <= 2 {
		y--
	}
	era := y / 400
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + dd - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe, true
}

// ---- GitHub ----

type githubOrg struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Blog        string `json:"blog"`
	Description string `json:"description"`
	AvatarURL   string `json:"avatar_url"`
	PublicRepos int    `json:"public_repos"`
	Followers   int    `json:"followers"`
}

func parseGitHubOrg(body string) *githubOrg {
	if body == "" || len(body) > maxJSONBodyBytes {
		return nil
	}
	var g githubOrg
	if json.Unmarshal([]byte(body), &g) != nil || !validGitHubLogin(g.Login) {
		return nil
	}
	return &g
}

// ---- small helpers ----

func cleanText(s string, maxLen int) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return extract.SanitizeSchemaPlainField(s, maxLen)
}

func asciiLower(s string) string {
	b := []byte(s)
	changed := false
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
