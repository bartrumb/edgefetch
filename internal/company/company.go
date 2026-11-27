// Package company builds a public company profile from raw bodies the caller has already fetched
// (homepage HTML, Wikidata, SEC EDGAR, GitHub, ATS summary, Google Maps places). It performs no network
// I/O: Plan / Followups / PickWikidataEntity / EntityFollowupsFor tell the caller what to fetch next,
// and Merge folds the fetched bodies into a sanitized Profile with per-field source attribution.
package company

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// HomepageInput is a fetched HTML page (homepage or /about).
type HomepageInput struct {
	URL         string `json:"url,omitempty"`
	FinalURL    string `json:"finalUrl,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	SiteName    string `json:"siteName,omitempty"`
	HTML        string `json:"html,omitempty"`
}

// ATSSummary is the hiring summary the caller builds from the jobs tool.
type ATSSummary struct {
	BoardURLs   []string `json:"boardUrls,omitempty"`
	Platform    string   `json:"platform,omitempty"`
	OpenRoles   int      `json:"openRoles,omitempty"`
	Departments []string `json:"departments,omitempty"`
	Locations   []string `json:"locations,omitempty"`
	SampleRoles []string `json:"sampleRoles,omitempty"`
}

// MergeInput is the `company_merge` request. Every source is optional.
type MergeInput struct {
	Name                string         `json:"name,omitempty"`
	Domain              string         `json:"domain,omitempty"`
	Homepage            *HomepageInput `json:"homepage,omitempty"`
	About               *HomepageInput `json:"about,omitempty"`
	WikidataID          string         `json:"wikidataId,omitempty"`
	WikidataEntityJSON  string         `json:"wikidataEntityJson,omitempty"`
	WikidataLabelsJSON  string         `json:"wikidataLabelsJson,omitempty"`
	SECSubmissionsJSON  string         `json:"secSubmissionsJson,omitempty"`
	SECCompanyFactsJSON string         `json:"secCompanyFactsJson,omitempty"`
	GitHubOrgJSON       string         `json:"githubOrgJson,omitempty"`
	ATS                 *ATSSummary    `json:"ats,omitempty"`
	PlacesJSON          string         `json:"placesJson,omitempty"`
}

// Location is a headquarters location.
type Location struct {
	City      string   `json:"city,omitempty"`
	Region    string   `json:"region,omitempty"`
	Country   string   `json:"country,omitempty"`
	Address   string   `json:"address,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}

// Industry holds SEC SIC classification and Wikidata P452 industry labels.
type Industry struct {
	SICCode        string   `json:"sicCode,omitempty"`
	SICDescription string   `json:"sicDescription,omitempty"`
	Labels         []string `json:"labels,omitempty"`
}

// Employees is a headcount with its point-in-time date when known.
type Employees struct {
	Count int64  `json:"count"`
	AsOf  string `json:"asOf,omitempty"`
}

// Listing is a ticker on an exchange.
type Listing struct {
	Ticker   string `json:"ticker"`
	Exchange string `json:"exchange,omitempty"`
}

// Revenue is the latest full-year revenue from SEC XBRL companyfacts.
type Revenue struct {
	Value      int64  `json:"value"`
	Currency   string `json:"currency"`
	FiscalYear int    `json:"fiscalYear"`
	PeriodEnd  string `json:"periodEnd"`
	Form       string `json:"form,omitempty"`
	Filed      string `json:"filed,omitempty"`
	Concept    string `json:"concept,omitempty"`
}

// GitHubSummary is the corroborated GitHub organization.
type GitHubSummary struct {
	Login       string `json:"login"`
	URL         string `json:"url,omitempty"`
	PublicRepos int    `json:"publicRepos"`
	Followers   int    `json:"followers"`
}

// Hiring summarizes open roles.
type Hiring struct {
	OpenRoles   int      `json:"openRoles"`
	Platform    string   `json:"platform,omitempty"`
	BoardURLs   []string `json:"boardUrls,omitempty"`
	Departments []string `json:"departments,omitempty"`
	Locations   []string `json:"locations,omitempty"`
	SampleRoles []string `json:"sampleRoles,omitempty"`
}

// Profile is the merged company profile. FieldSources maps a field key (e.g. "name", "headquarters",
// "industry.sic", "socials.linkedin") to the single source id that supplied it; Sources lists every
// source that contributed at least one field.
type Profile struct {
	Name         string            `json:"name,omitempty"`
	LegalName    string            `json:"legalName,omitempty"`
	Domain       string            `json:"domain,omitempty"`
	Website      string            `json:"website,omitempty"`
	Description  string            `json:"description,omitempty"`
	Logo         string            `json:"logo,omitempty"`
	Founded      int               `json:"founded,omitempty"`
	Headquarters *Location         `json:"headquarters,omitempty"`
	Industry     *Industry         `json:"industry,omitempty"`
	Employees    *Employees        `json:"employees,omitempty"`
	Ticker       string            `json:"ticker,omitempty"`
	Exchange     string            `json:"exchange,omitempty"`
	Listings     []Listing         `json:"listings,omitempty"`
	CIK          string            `json:"cik,omitempty"`
	Revenue      *Revenue          `json:"revenue,omitempty"`
	Socials      *Socials          `json:"socials,omitempty"`
	GitHub       *GitHubSummary    `json:"github,omitempty"`
	Hiring       *Hiring           `json:"hiring,omitempty"`
	Place        *Place            `json:"place,omitempty"`
	WikidataID   string            `json:"wikidataId,omitempty"`
	FieldSources map[string]string `json:"fieldSources"`
	Sources      []string          `json:"sources"`
	Warnings     []string          `json:"warnings,omitempty"`
	Markdown     string            `json:"markdown"`
}

const (
	maxNameLen  = 200
	maxDescLen  = 600
	maxShortLen = 120
	maxListLen  = 10
)

type merger struct {
	p *Profile
}

func (m *merger) set(field, source string) {
	m.p.FieldSources[field] = source
}

func (m *merger) warn(w string) {
	for _, x := range m.p.Warnings {
		if x == w {
			return
		}
	}
	m.p.Warnings = append(m.p.Warnings, w)
}

// setStr assigns the first non-empty candidate to *dst and records its source.
func (m *merger) setStr(dst *string, field string, cands ...[2]string) {
	for _, c := range cands {
		if c[0] != "" {
			*dst = c[0]
			m.set(field, c[1])
			return
		}
	}
}

func cand(v, src string) [2]string { return [2]string{v, src} }

// Merge folds the fetched sources into a Profile. Precedence:
//   - legal & financial facts (legalName, cik, ticker/exchange, SIC industry, revenue): SEC first;
//   - founded, employees, headquarters: SEC address for HQ, then Wikidata, then homepage JSON-LD,
//     then Google Maps place address;
//   - description, logo, socials: homepage JSON-LD first, homepage meta / links next, Wikidata last;
//   - display name: Wikidata label, JSON-LD name, og:site_name, input name, SEC name, page title.
//
// Wikidata is used only when it is corroborated by the domain (P856) or no domain was given; SEC only when
// its CIK equals the accepted Wikidata P5531; GitHub only when its blog domain, a homepage/JSON-LD link, or
// Wikidata P2037 corroborates the login.
func Merge(in MergeInput) Profile {
	p := Profile{FieldSources: map[string]string{}, Sources: []string{}}
	m := &merger{p: &p}

	domain := ""
	if strings.TrimSpace(in.Domain) != "" {
		if d, err := NormalizeDomain(in.Domain); err == nil {
			domain = d
		} else {
			m.warn("invalid_domain")
		}
	}
	inputName := cleanText(in.Name, maxNameLen)

	// ---- homepage / about ----
	var org map[string]any
	pages := []*HomepageInput{in.Homepage, in.About}
	for _, pg := range pages {
		if pg == nil {
			continue
		}
		if domain != "" && pg.FinalURL != "" && !urlMatchesDomain(pg.FinalURL, domain) {
			m.warn("homepage_redirected_offsite")
		}
		if org == nil && pg.HTML != "" {
			org = findOrganization(pg.HTML, domain)
		}
	}
	baseURL := ""
	if in.Homepage != nil {
		baseURL = firstNonEmpty(in.Homepage.FinalURL, in.Homepage.URL)
	}
	if baseURL == "" && domain != "" {
		baseURL = "https://" + domain + "/"
	}

	// ---- Wikidata ----
	var ent *wdEntity
	if in.WikidataEntityJSON != "" {
		ents := parseWikidataEntities(in.WikidataEntityJSON)
		switch {
		case in.WikidataID != "":
			ent = ents[in.WikidataID]
		case len(ents) == 1:
			for _, v := range ents {
				ent = v
			}
		}
		if ent == nil {
			m.warn("wikidata_entity_unparsed")
		} else if domain != "" {
			if _, ok := ent.matchesDomain(domain); !ok {
				m.warn("wikidata_uncorroborated")
				ent = nil
			}
		}
	}
	labels := map[string]*wdEntity{}
	if ent != nil {
		for k, v := range parseWikidataEntities(in.WikidataLabelsJSON) {
			labels[k] = v
		}
		p.WikidataID = ent.ID
		m.set("wikidataId", SourceWikidata)
	}
	labelOf := func(qid string) string {
		if qid == "" {
			return ""
		}
		if e := labels[qid]; e != nil {
			return cleanText(e.label(), maxShortLen)
		}
		return ""
	}

	// ---- SEC ----
	sub := parseSECSubmissions(in.SECSubmissionsJSON)
	if in.SECSubmissionsJSON != "" && sub == nil {
		m.warn("sec_submissions_unparsed")
	}
	var facts *secCompanyFacts
	if in.SECCompanyFactsJSON != "" {
		facts = parseCompanyFacts(in.SECCompanyFactsJSON)
		if facts == nil {
			m.warn("sec_companyfacts_unparsed")
		}
	}
	wdCIK := ent.cik()
	if sub != nil && (wdCIK == "" || rawCIK(sub.CIK) != wdCIK) {
		m.warn("sec_uncorroborated")
		sub = nil
	}
	if facts != nil && (wdCIK == "" || rawCIK(facts.CIK) != wdCIK) {
		m.warn("sec_uncorroborated")
		facts = nil
	}

	// ---- domain / website ----
	if domain != "" {
		p.Domain = domain
		m.set("domain", SourceInput)
		p.Website = "https://" + domain + "/"
		m.set("website", SourceInput)
	} else if ent != nil {
		for _, w := range ent.websites() {
			if s := extract.SanitizeSchemaHTTPSURL(w, ""); s != "" {
				p.Website = s
				m.set("website", SourceWikidata)
				if u, err := url.Parse(s); err == nil {
					if d, err := NormalizeDomain(u.Hostname()); err == nil {
						p.Domain = d
						m.set("domain", SourceWikidata)
					}
				}
				break
			}
		}
	}

	// ---- names ----
	var homeSite, homeTitle, homeDesc string
	for _, pg := range pages {
		if pg == nil {
			continue
		}
		homeSite = firstNonEmpty(homeSite, cleanText(pg.SiteName, maxNameLen))
		homeTitle = firstNonEmpty(homeTitle, titleBrand(cleanText(pg.Title, maxNameLen)))
		homeDesc = firstNonEmpty(homeDesc, cleanText(pg.Description, maxDescLen))
	}
	secName := ""
	if sub != nil {
		secName = cleanText(sub.Name, maxNameLen)
	}
	m.setStr(&p.Name, "name",
		cand(cleanText(ent.label(), maxNameLen), SourceWikidata),
		cand(jsonldStr(org, "name", maxNameLen), SourceHomepageJSONLD),
		cand(homeSite, SourceHomepageMeta),
		cand(inputName, SourceInput),
		cand(secName, SourceSECSubmissions),
		cand(homeTitle, SourceHomepageMeta),
	)
	m.setStr(&p.LegalName, "legalName",
		cand(secName, SourceSECSubmissions),
		cand(jsonldStr(org, "legalName", maxNameLen), SourceHomepageJSONLD),
		cand(cleanText(wdMonolingual(ent, "P1448"), maxNameLen), SourceWikidata),
	)

	// ---- description / logo ----
	m.setStr(&p.Description, "description",
		cand(jsonldStr(org, "description", maxDescLen), SourceHomepageJSONLD),
		cand(homeDesc, SourceHomepageMeta),
		cand(cleanText(ent.description(), maxDescLen), SourceWikidata),
	)
	m.setStr(&p.Logo, "logo",
		cand(jsonldURL(org, "logo", baseURL), SourceHomepageJSONLD),
		cand(commonsFileURL(ent.claimString("P154")), SourceWikidata),
	)

	// ---- founded ----
	if ent != nil {
		if c := selectClaim(ent.Claims["P571"]); c != nil {
			if y, _, ok := snakTime(c.Mainsnak); ok && plausibleYear(y) {
				p.Founded = y
				m.set("founded", SourceWikidata)
			}
		}
	}
	if p.Founded == 0 {
		if y := leadingYear(jsonldStr(org, "foundingDate", 40)); plausibleYear(y) {
			p.Founded = y
			m.set("founded", SourceHomepageJSONLD)
		}
	}

	// ---- headquarters ----
	if sub != nil {
		if loc := secLocation(sub.Addresses.Business); loc != nil {
			p.Headquarters = loc
			m.set("headquarters", SourceSECSubmissions)
		}
	}
	if p.Headquarters == nil && ent != nil {
		loc := &Location{City: labelOf(ent.claimEntityID("P159")), Country: labelOf(ent.claimEntityID("P17"))}
		if loc.City != "" || loc.Country != "" {
			p.Headquarters = loc
			m.set("headquarters", SourceWikidata)
		}
	}
	if p.Headquarters == nil {
		if loc := jsonldLocation(org); loc != nil {
			p.Headquarters = loc
			m.set("headquarters", SourceHomepageJSONLD)
		}
	}

	// ---- Google Maps place ----
	if in.PlacesJSON != "" {
		if pl := PickPlace(in.PlacesJSON, firstNonEmpty(domain, p.Domain), []string{p.Name, inputName, p.LegalName}); pl != nil {
			p.Place = pl
			m.set("place", SourceGoogleMaps)
			if p.Headquarters == nil && (pl.Address != "" || pl.Latitude != nil) {
				p.Headquarters = &Location{Address: pl.Address, Latitude: pl.Latitude, Longitude: pl.Longitude}
				m.set("headquarters", SourceGoogleMaps)
			}
		} else {
			m.warn("places_no_match")
		}
	}

	// ---- industry ----
	ind := &Industry{}
	if sub != nil {
		ind.SICCode = cleanText(sub.SIC, 8)
		if !allDigits(ind.SICCode) {
			ind.SICCode = ""
		}
		ind.SICDescription = cleanText(sub.SICDescription, maxShortLen)
		if ind.SICCode != "" || ind.SICDescription != "" {
			m.set("industry.sic", SourceSECSubmissions)
		}
	}
	if ent != nil {
		for _, c := range orderedClaims(ent.Claims["P452"]) {
			if l := labelOf(snakEntityID(c.Mainsnak)); l != "" && !containsFold(ind.Labels, l) && len(ind.Labels) < 5 {
				ind.Labels = append(ind.Labels, l)
			}
		}
		if len(ind.Labels) > 0 {
			m.set("industry.labels", SourceWikidata)
		}
	}
	if ind.SICCode != "" || ind.SICDescription != "" || len(ind.Labels) > 0 {
		p.Industry = ind
	}

	// ---- employees ----
	if ent != nil {
		if c := selectClaim(ent.Claims["P1128"]); c != nil {
			if n, ok := snakQuantity(c.Mainsnak); ok && n > 0 && n < 1e8 {
				e := &Employees{Count: int64(n)}
				for _, q := range c.Qualifiers["P585"] {
					if y, k, ok := snakTime(q); ok {
						e.AsOf = formatDateKey(y, k)
						break
					}
				}
				p.Employees = e
				m.set("employees", SourceWikidata)
			}
		}
	}
	if p.Employees == nil && org != nil {
		if n := jsonldEmployees(org["numberOfEmployees"]); n > 0 {
			p.Employees = &Employees{Count: n}
			m.set("employees", SourceHomepageJSONLD)
		}
	}

	// ---- listings / CIK ----
	if sub != nil {
		p.CIK = rawCIK(sub.CIK)
		m.set("cik", SourceSECSubmissions)
		for i, t := range sub.Tickers {
			ts, _ := t.(string)
			ts = cleanTicker(ts)
			if ts == "" || len(p.Listings) >= 5 {
				continue
			}
			ex := ""
			if i < len(sub.Exchanges) {
				es, _ := sub.Exchanges[i].(string)
				ex = cleanText(es, 40)
			}
			p.Listings = append(p.Listings, Listing{Ticker: ts, Exchange: ex})
		}
		if len(p.Listings) > 0 {
			m.set("listings", SourceSECSubmissions)
		}
	} else if wdCIK != "" {
		p.CIK = wdCIK
		m.set("cik", SourceWikidata)
	}
	if len(p.Listings) == 0 && ent != nil {
		for _, c := range orderedClaims(ent.Claims["P414"]) {
			if len(p.Listings) >= 5 {
				break
			}
			tk := ""
			for _, q := range c.Qualifiers["P249"] {
				if tk = cleanTicker(snakString(q)); tk != "" {
					break
				}
			}
			if tk == "" {
				continue
			}
			p.Listings = append(p.Listings, Listing{Ticker: tk, Exchange: labelOf(snakEntityID(c.Mainsnak))})
		}
		if len(p.Listings) > 0 {
			m.set("listings", SourceWikidata)
		}
	}
	if len(p.Listings) == 0 && org != nil {
		if tk := cleanTicker(jsonldStr(org, "tickerSymbol", 20)); tk != "" {
			p.Listings = append(p.Listings, Listing{Ticker: tk})
			m.set("listings", SourceHomepageJSONLD)
		}
	}
	if len(p.Listings) > 0 {
		p.Ticker, p.Exchange = p.Listings[0].Ticker, p.Listings[0].Exchange
		m.set("ticker", p.FieldSources["listings"])
		if p.Exchange != "" {
			m.set("exchange", p.FieldSources["listings"])
		}
	}

	// ---- revenue ----
	if rev := latestAnnualRevenue(facts); rev != nil {
		p.Revenue = rev
		m.set("revenue", SourceSECCompanyFacts)
	}

	// ---- socials ----
	brand := firstNonEmpty(domainLabel(firstNonEmpty(domain, p.Domain)), normalizeCompanyName(p.Name))
	soc := &Socials{}
	jsonldC := socialCandidates{}
	if org != nil {
		for _, s := range anyStrings(org["sameAs"], 50) {
			jsonldC.add(s)
		}
	}
	linkC := socialCandidates{}
	for _, pg := range pages {
		if pg == nil || pg.HTML == "" {
			continue
		}
		for _, h := range scanHrefs(pg.HTML, 500) {
			linkC.add(h)
		}
	}
	wdC := socialCandidates{}
	if ent != nil {
		if v := ent.claimString("P4264"); v != "" {
			wdC.add("https://www.linkedin.com/company/" + v)
		}
		if v := ent.claimString("P2002"); v != "" {
			wdC.add("https://x.com/" + v)
		}
		if v := ent.claimString("P2037"); v != "" {
			wdC.add("https://github.com/" + v)
		}
		if v := ent.claimString("P2013"); v != "" {
			wdC.add("https://www.facebook.com/" + v)
		}
		if v := ent.claimString("P2003"); v != "" {
			wdC.add("https://www.instagram.com/" + v)
		}
		if v := ent.claimString("P2397"); v != "" {
			wdC.add("https://www.youtube.com/channel/" + v)
		}
	}
	for _, net := range socialNetworks {
		switch {
		case len(jsonldC[net]) > 0:
			soc.set(net, jsonldC.best(net, brand))
			m.set("socials."+net, SourceHomepageJSONLD)
		case len(linkC[net]) > 0:
			soc.set(net, linkC.best(net, brand))
			m.set("socials."+net, SourceHomepageLinks)
		case len(wdC[net]) > 0:
			soc.set(net, wdC.best(net, brand))
			m.set("socials."+net, SourceWikidata)
		}
	}

	// ---- GitHub ----
	if in.GitHubOrgJSON != "" {
		gh := parseGitHubOrg(in.GitHubOrgJSON)
		if gh == nil {
			m.warn("github_unparsed")
		} else {
			login := asciiLower(gh.Login)
			corroborated := (soc.GitHub != "" && asciiLower(socialHandle(soc.GitHub)) == login) ||
				(ent != nil && asciiLower(ent.claimString("P2037")) == login)
			for _, h := range linkC[NetGitHub] {
				if asciiLower(socialHandle(h)) == login {
					corroborated = true
				}
			}
			if !corroborated && gh.Blog != "" && firstNonEmpty(domain, p.Domain) != "" {
				b := gh.Blog
				if !strings.Contains(b, "://") {
					b = "https://" + b
				}
				corroborated = urlMatchesDomain(b, firstNonEmpty(domain, p.Domain))
			}
			if corroborated {
				g := &GitHubSummary{Login: gh.Login, PublicRepos: clampNonNeg(gh.PublicRepos), Followers: clampNonNeg(gh.Followers)}
				g.URL = extract.SanitizeSchemaHTTPSURL(gh.HTMLURL, "")
				if g.URL == "" || !urlMatchesDomain(g.URL, "github.com") {
					g.URL = "https://github.com/" + gh.Login
				}
				p.GitHub = g
				m.set("github", SourceGitHub)
				if soc.GitHub == "" {
					soc.GitHub = "https://github.com/" + gh.Login
					m.set("socials.github", SourceGitHub)
				}
				if p.Logo == "" {
					if a := extract.SanitizeSchemaHTTPSURL(gh.AvatarURL, ""); a != "" {
						p.Logo = a
						m.set("logo", SourceGitHub)
					}
				}
				if p.Description == "" {
					if d := cleanText(gh.Description, maxDescLen); d != "" {
						p.Description = d
						m.set("description", SourceGitHub)
					}
				}
			} else {
				m.warn("github_uncorroborated")
			}
		}
	}
	if !soc.empty() {
		p.Socials = soc
	}

	// ---- hiring ----
	if in.ATS != nil {
		if h := buildHiring(in.ATS); h != nil {
			p.Hiring = h
			m.set("hiring", SourceATS)
		}
	}

	// ---- sources ----
	seen := map[string]bool{}
	for _, s := range p.FieldSources {
		if !seen[s] {
			seen[s] = true
			p.Sources = append(p.Sources, s)
		}
	}
	sort.Strings(p.Sources)
	p.Markdown = renderMarkdown(&p)
	return p
}

func parseCompanyFacts(body string) *secCompanyFacts {
	if body == "" || len(body) > maxJSONBodyBytes {
		return nil
	}
	var cf secCompanyFacts
	if jsonUnmarshalString(body, &cf) != nil {
		return nil
	}
	return &cf
}

func buildHiring(a *ATSSummary) *Hiring {
	h := &Hiring{OpenRoles: clampNonNeg(a.OpenRoles), Platform: cleanText(a.Platform, 40)}
	for _, u := range a.BoardURLs {
		if s := extract.SanitizeSchemaHTTPSURL(u, ""); s != "" && !containsFold(h.BoardURLs, s) && len(h.BoardURLs) < maxListLen {
			h.BoardURLs = append(h.BoardURLs, s)
		}
	}
	h.Departments = cleanList(a.Departments, maxShortLen, maxListLen)
	h.Locations = cleanList(a.Locations, maxShortLen, maxListLen)
	h.SampleRoles = cleanList(a.SampleRoles, maxShortLen, maxListLen)
	if h.OpenRoles == 0 && len(h.BoardURLs) == 0 && h.Platform == "" && len(h.Departments) == 0 && len(h.SampleRoles) == 0 {
		return nil
	}
	return h
}

func cleanList(in []string, maxLen, maxItems int) []string {
	var out []string
	for i, s := range in {
		if i >= 1000 || len(out) >= maxItems {
			break
		}
		if c := cleanText(s, maxLen); c != "" && !containsFold(out, c) {
			out = append(out, c)
		}
	}
	return out
}

var usStates = map[string]bool{}

func init() {
	for _, s := range strings.Fields("AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR GU VI AS MP") {
		usStates[s] = true
	}
}

func secLocation(a secAddress) *Location {
	city := titleCaseASCII(cleanText(a.City, maxShortLen))
	code := strings.ToUpper(cleanText(a.StateOrCountry, 10))
	loc := &Location{City: city}
	if usStates[code] {
		loc.Region = code
		loc.Country = "United States"
	} else if desc := cleanText(a.StateOrCountryDescription, maxShortLen); desc != "" && !strings.EqualFold(desc, code) {
		loc.Country = desc
	}
	if loc.City == "" && loc.Country == "" {
		return nil
	}
	return loc
}

func titleCaseASCII(s string) string {
	if s == "" || s != strings.ToUpper(s) {
		return s
	}
	b := []byte(strings.ToLower(s))
	up := true
	for i, c := range b {
		if up && c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
		up = c == ' ' || c == '-' || c == '.'
	}
	return string(b)
}

func cleanTicker(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" || len(s) > 12 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return ""
		}
	}
	return s
}

func wdMonolingual(e *wdEntity, prop string) string {
	if e == nil {
		return ""
	}
	c := selectClaim(e.Claims[prop])
	if c == nil {
		return ""
	}
	var v struct {
		Text string `json:"text"`
	}
	if jsonUnmarshalRaw(c.Mainsnak.Datavalue.Value, &v) != nil {
		return ""
	}
	return v.Text
}

func commonsFileURL(file string) string {
	file = strings.TrimSpace(file)
	if file == "" || len(file) > 240 || strings.ContainsAny(file, "/\\") {
		return ""
	}
	return extract.SanitizeSchemaHTTPSURL("https://commons.wikimedia.org/wiki/Special:FilePath/"+
		url.PathEscape(strings.ReplaceAll(file, " ", "_")), "")
}

func plausibleYear(y int) bool { return y >= 1000 && y <= 2100 }

func leadingYear(s string) int {
	if len(s) < 4 || !allDigits(s[:4]) {
		return 0
	}
	y, _ := strconv.Atoi(s[:4])
	return y
}

func formatDateKey(y, key int) string {
	mo, d := (key/100)%100, key%100
	if mo < 1 || mo > 12 {
		return strconv.Itoa(y)
	}
	if d < 1 {
		return strconv.Itoa(y) + "-" + pad2(mo)
	}
	return strconv.Itoa(y) + "-" + pad2(mo) + "-" + pad2(d)
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func clampNonNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// titleBrand returns the leading segment of a page title ("Acme | Payments" -> "Acme").
func titleBrand(t string) string {
	for _, sep := range []string{" | ", " - ", " – ", " — ", ": ", " · "} {
		if i := strings.Index(t, sep); i > 0 {
			t = t[:i]
		}
	}
	return strings.TrimSpace(t)
}
