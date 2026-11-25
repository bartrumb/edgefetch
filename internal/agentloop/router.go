package agentloop

import (
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// AdapterCatalogItem describes an indexed keyless site or ATS adapter for dynamic intent routing.
type AdapterCatalogItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
	ExampleURLs []string `json:"exampleUrls"`
}

// RankedAdapterMatch represents a scored adapter returned by FindRelevantAdapters.
type RankedAdapterMatch struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
	ExampleURLs []string `json:"exampleUrls"`
	Score       float64  `json:"score"`
}

// FindRelevantAdaptersInput configures a dynamic adapter search query.
type FindRelevantAdaptersInput struct {
	Query    string               `json:"query"`
	URLs     []string             `json:"urls,omitempty"`
	Category string               `json:"category,omitempty"`
	Limit    int                  `json:"limit,omitempty"`
	Adapters []AdapterCatalogItem `json:"adapters,omitempty"`
}

type indexedAdapterEntry struct {
	item         AdapterCatalogItem
	idLower      string
	idSpaced     string
	nameLower    string
	searchable   string
	cleanDomains []string
}

var categoryIntentKeywords = map[string][]string{
	"jobs": {
		"job", "jobs", "career", "careers", "hiring", "salary", "compensation", "role", "roles",
		"engineer", "ashby", "greenhouse", "lever", "workday", "workable", "rippling", "ats", "remote",
	},
	"finance": {
		"sec", "edgar", "10-k", "10-q", "8-k", "cik", "filing", "filings", "yc", "ycombinator",
		"startup", "founders", "batch", "polymarket", "odds", "prediction", "market",
	},
	"public-records": {
		"dataset", "open-data", "socrata", "ckan", "data.gov", "city", "municipal", "council",
		"ordinance", "legistar", "arcgis", "gis", "usaspending", "federal", "contract", "grant",
	},
	"research-health": {
		"paper", "preprint", "arxiv", "doi", "crossref", "citation", "citations", "openalex",
		"pubmed", "clinical", "trial", "nct", "fda", "recall", "adverse", "pubchem", "compound", "chemical",
	},
	"developer": {
		"github", "gitlab", "npm", "pypi", "crate", "crates", "rust", "rubygems", "packagist",
		"cve", "vulnerability", "nvd", "rfc", "ietf", "stackoverflow", "wayback", "archive", "app-store", "play-store",
	},
	"genai": {
		"huggingface", "openrouter", "llm", "models", "context-length", "pricing", "weights",
	},
	"commerce-social": {
		"shopify", "product", "price", "sku", "variant", "food", "barcode", "nutrition",
		"reddit", "hackernews", "hn", "bluesky", "mastodon", "youtube", "wikipedia",
	},
}

var builtInATSCoreCatalog = []AdapterCatalogItem{
	{
		ID:          "ashby",
		Name:        "Ashby ATS Job Boards & Compensation API",
		Category:    "jobs",
		Description: "Upgrades jobs.ashbyhq.com/<org> boards and postings to api.ashbyhq.com/posting-api/job-board/<org>?includeCompensation=true.",
		Domains:     []string{"jobs.ashbyhq.com"},
		ExampleURLs: []string{"https://jobs.ashbyhq.com/linear"},
	},
	{
		ID:          "workday-cxs",
		Name:        "Workday CXS Career Portals",
		Category:    "jobs",
		Description: "Upgrades <tenant>.wd<N>.myworkdayjobs.com career boards and job postings to Workday /wday/cxs JSON endpoints.",
		Domains:     []string{"*.myworkdayjobs.com", "*.myworkdaysite.com"},
		ExampleURLs: []string{"https://cloudflare.wd1.myworkdayjobs.com/External"},
	},
	{
		ID:          "greenhouse-job",
		Name:        "Greenhouse Single-Job Postings (US & EU)",
		Category:    "jobs",
		Description: "Upgrades Greenhouse job URLs to boards-api.[eu.]greenhouse.io/v1/boards/<org>/jobs/<id>?content=true with normalized pay_input_ranges.",
		Domains:     []string{"boards.greenhouse.io", "job-boards.greenhouse.io", "eu-boards.greenhouse.io", "job-boards.eu.greenhouse.io"},
		ExampleURLs: []string{"https://job-boards.greenhouse.io/cloudflare/jobs/6123456"},
	},
	{
		ID:          "lever-job",
		Name:        "Lever Single-Job Postings (US & EU)",
		Category:    "jobs",
		Description: "Upgrades jobs.[eu.]lever.co/<org>/<id> postings to api.[eu.]lever.co/v0/postings/<org>/<id> with salaryRange normalization.",
		Domains:     []string{"jobs.lever.co", "jobs.eu.lever.co"},
		ExampleURLs: []string{"https://jobs.lever.co/mistral/01234567-89ab-cdef-0123-456789abcdef"},
	},
}

var (
	reStripHTTPScheme = regexp.MustCompile(`https?://`)
	reTokenSplit      = regexp.MustCompile(`[^a-z0-9._-]+`)

	defaultCatalogOnce   sync.Once
	cachedIndexedCatalog []indexedAdapterEntry
)

func buildIndexedEntry(a AdapterCatalogItem) indexedAdapterEntry {
	idLower := strings.ToLower(a.ID)
	nameLower := strings.ToLower(a.Name)
	descLower := strings.ToLower(a.Description)
	searchable := strings.ToLower(idLower + " " + nameLower + " " + descLower + " " +
		strings.Join(a.Domains, " ") + " " + strings.Join(a.ExampleURLs, " "))
	cleanDoms := make([]string, 0, len(a.Domains))
	for _, d := range a.Domains {
		cd := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(d), "*."), "www.")
		if cd != "" && cd != "*" {
			cleanDoms = append(cleanDoms, cd)
		}
	}
	return indexedAdapterEntry{
		item:         a,
		idLower:      idLower,
		idSpaced:     strings.ReplaceAll(idLower, "-", " "),
		nameLower:    nameLower,
		searchable:   searchable,
		cleanDomains: cleanDoms,
	}
}

func loadDefaultIndexedCatalog() []indexedAdapterEntry {
	defaultCatalogOnce.Do(func() {
		decl := extract.ListDeclarativeAdapters()
		seen := make(map[string]bool, len(decl)+len(builtInATSCoreCatalog))
		entries := make([]indexedAdapterEntry, 0, len(decl)+len(builtInATSCoreCatalog))
		for _, d := range decl {
			seen[d.ID] = true
			entries = append(entries, buildIndexedEntry(AdapterCatalogItem{
				ID:          d.ID,
				Name:        d.Name,
				Category:    d.Category,
				Description: d.Description,
				Domains:     append([]string(nil), d.Domains...),
				ExampleURLs: append([]string(nil), d.ExampleURLs...),
			}))
		}
		for _, ats := range builtInATSCoreCatalog {
			if !seen[ats.ID] {
				seen[ats.ID] = true
				entries = append(entries, buildIndexedEntry(AdapterCatalogItem{
					ID:          ats.ID,
					Name:        ats.Name,
					Category:    ats.Category,
					Description: ats.Description,
					Domains:     append([]string(nil), ats.Domains...),
					ExampleURLs: append([]string(nil), ats.ExampleURLs...),
				}))
			}
		}
		cachedIndexedCatalog = entries
	})
	return cachedIndexedCatalog
}

// DefaultAdapterCatalog returns a copy of all embedded declarative + built-in ATS adapters.
func DefaultAdapterCatalog() []AdapterCatalogItem {
	src := loadDefaultIndexedCatalog()
	out := make([]AdapterCatalogItem, len(src))
	for i, e := range src {
		out[i] = e.item
	}
	return out
}

// DefaultTotalIndexedAdapters returns the total count of indexed built-in keyless adapters.
func DefaultTotalIndexedAdapters() int {
	return len(loadDefaultIndexedCatalog())
}

func tokenizeIntent(text string) []string {
	cleaned := reStripHTTPScheme.ReplaceAllString(strings.ToLower(text), " ")
	rawTokens := reTokenSplit.Split(cleaned, -1)
	out := make([]string, 0, len(rawTokens))
	for _, tok := range rawTokens {
		t := strings.TrimSpace(tok)
		if len(t) >= 2 {
			out = append(out, t)
		}
	}
	return out
}

// FindRelevantAdapters ranks all keyless site & ATS adapters against a natural-language query and optional
// seed URLs in <1ms using domain hits, slug/token specificity, and category intent boosting, with zero 3-source cap.
func FindRelevantAdapters(input FindRelevantAdaptersInput) []RankedAdapterMatch {
	var entries []indexedAdapterEntry
	if len(input.Adapters) > 0 {
		entries = make([]indexedAdapterEntry, len(input.Adapters))
		for i, a := range input.Adapters {
			entries[i] = buildIndexedEntry(a)
		}
	} else {
		entries = loadDefaultIndexedCatalog()
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 8
	} else if limit > 50 {
		limit = 50
	}

	qTokens := tokenizeIntent(input.Query)
	qTokenSet := make(map[string]bool, len(qTokens))
	for _, t := range qTokens {
		qTokenSet[t] = true
	}
	qLower := strings.ToLower(input.Query)

	var urlHosts []string
	seenHosts := map[string]bool{}
	for _, rawU := range input.URLs {
		u, err := url.Parse(rawU)
		if err != nil || u.Host == "" {
			continue
		}
		h := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
		if h != "" && !seenHosts[h] {
			seenHosts[h] = true
			urlHosts = append(urlHosts, h)
		}
	}

	boostedCategories := map[string]bool{}
	for cat, kws := range categoryIntentKeywords {
		for _, kw := range kws {
			if qTokenSet[kw] || (len(kw) >= 4 && strings.Contains(qLower, kw)) {
				boostedCategories[cat] = true
				break
			}
		}
	}

	scored := make([]RankedAdapterMatch, 0, 16)
	for _, entry := range entries {
		adapter := entry.item
		if input.Category != "" && adapter.Category != input.Category {
			continue
		}
		score := 0.0
		for _, cleanDom := range entry.cleanDomains {
			for _, uh := range urlHosts {
				if uh == cleanDom || strings.HasSuffix(uh, "."+cleanDom) {
					score += 25
				}
			}
			if strings.Contains(qLower, cleanDom) {
				score += 18
			}
		}

		if strings.Contains(qLower, entry.idSpaced) || qTokenSet[entry.idLower] {
			score += 14
		}

		for _, tok := range qTokens {
			if len(tok) < 3 && tok != "yc" && tok != "hn" {
				continue
			}
			if strings.Contains(entry.idLower, tok) || strings.Contains(entry.nameLower, tok) {
				score += 6
			} else if strings.Contains(entry.searchable, tok) {
				score += 2.5
			}
		}

		if score > 0 && boostedCategories[adapter.Category] {
			score += 3
		}

		if score > 0 || (input.Category != "" && adapter.Category == input.Category) {
			exCount := min(2, len(adapter.ExampleURLs))
			examples := make([]string, exCount)
			copy(examples, adapter.ExampleURLs[:exCount])
			domains := make([]string, len(adapter.Domains))
			copy(domains, adapter.Domains)
			scored = append(scored, RankedAdapterMatch{
				ID:          adapter.ID,
				Name:        adapter.Name,
				Category:    adapter.Category,
				Description: adapter.Description,
				Domains:     domains,
				ExampleURLs: examples,
				Score:       math.Round(score*10) / 10,
			})
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		return scored[i].ID < scored[j].ID
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}
	return scored
}
