package extract

import (
	"net/url"
	"regexp"
	"strings"
)

// LlmsLink represents a single `- [Title](URL): Notes` entry inside `/llms.txt`.
type LlmsLink struct {
	Section string `json:"section,omitempty"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Notes   string `json:"notes,omitempty"`
}

// LlmsDocument represents a parsed `/llms.txt` index per https://llmstxt.org/.
type LlmsDocument struct {
	SourceURL  string     `json:"sourceUrl"`
	Title      string     `json:"title,omitempty"`
	Summary    string     `json:"summary,omitempty"`
	FullTxtURL string     `json:"fullTxtUrl,omitempty"`
	Links      []LlmsLink `json:"links,omitempty"`
	RawPreview string     `json:"rawPreview,omitempty"`
}

// LlmsDiscovery reports `llms.txt` / companion `.md` enrichment attached to a crawled page Result.
type LlmsDiscovery struct {
	Found           bool       `json:"found"`
	LlmsTxtURL      string     `json:"llmsTxtUrl,omitempty"`
	LlmsFullTxtURL  string     `json:"llmsFullTxtUrl,omitempty"`
	CompanionMdURL  string     `json:"companionMdUrl,omitempty"`
	UsedCompanionMd bool       `json:"usedCompanionMd,omitempty"`
	SiteTitle       string     `json:"siteTitle,omitempty"`
	SiteSummary     string     `json:"siteSummary,omitempty"`
	MatchedEntry    *LlmsLink  `json:"matchedEntry,omitempty"`
	RelatedLinks    []LlmsLink `json:"relatedLinks,omitempty"`
}

var reLlmsItem = regexp.MustCompile(`^[-*]\s+\[([^\]]+)\]\(([^)]+)\)(?:\s*:\s*(.*))?$`)

// ParseLlmsTxt parses an `llms.txt` Markdown file, rejecting HTML 200 soft-404 pages masquerading as `/llms.txt`.
func ParseLlmsTxt(raw, sourceURL string) (*LlmsDocument, bool) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 8 {
		return nil, false
	}
	lowerPrefix := strings.ToLower(trimmed[:minInt(len(trimmed), 256)])
	if strings.HasPrefix(lowerPrefix, "<!doctype") || strings.HasPrefix(lowerPrefix, "<html") || strings.Contains(lowerPrefix, "<body") {
		return nil, false
	}

	var base *url.URL
	if sourceURL != "" {
		base, _ = url.Parse(sourceURL)
	}

	doc := &LlmsDocument{SourceURL: sourceURL}
	section := ""
	var summaryLines []string

	for _, rawLine := range strings.Split(trimmed, "\n") {
		line := strings.TrimSpace(strings.ReplaceAll(rawLine, "\r", ""))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") && doc.Title == "" {
			doc.Title = strings.TrimSpace(strings.TrimPrefix(line, "# "))
			continue
		}
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			continue
		}
		if strings.HasPrefix(line, ">") && section == "" && len(summaryLines) < 4 {
			summaryLines = append(summaryLines, strings.TrimSpace(strings.TrimLeft(line, "> ")))
			continue
		}
		if m := reLlmsItem.FindStringSubmatch(line); len(m) >= 3 {
			resolved := resolveHTTPSLink(m[2], base)
			if resolved == "" {
				continue
			}
			item := LlmsLink{
				Section: section,
				Title:   strings.TrimSpace(m[1]),
				URL:     resolved,
				Notes:   strings.TrimSpace(m[3]),
			}
			if strings.HasSuffix(strings.ToLower(resolved), "/llms-full.txt") && doc.FullTxtURL == "" {
				doc.FullTxtURL = resolved
			}
			if len(doc.Links) < 500 {
				doc.Links = append(doc.Links, item)
			}
		}
	}

	doc.Summary = strings.Join(summaryLines, " ")
	if doc.Title == "" && len(doc.Links) == 0 && doc.Summary == "" {
		return nil, false
	}
	if len(trimmed) > 4096 {
		doc.RawPreview = trimmed[:4096]
	} else {
		doc.RawPreview = trimmed
	}
	return doc, true
}

// MatchPage finds any exact orcompanion `.md` entry in `doc` corresponding to `pageURL`, plus up to 8 same-section related links.
func (doc *LlmsDocument) MatchPage(pageURL string) (matched *LlmsLink, companionMdURL string, related []LlmsLink) {
	if doc == nil {
		return nil, "", nil
	}
	pu, err := url.Parse(pageURL)
	if err != nil {
		return nil, "", nil
	}
	wantHost := strings.ToLower(pu.Hostname())
	wantPath := strings.TrimRight(pu.Path, "/")
	if wantPath == "" {
		wantPath = "/"
	}
	wantMdPath := wantPath + ".md"
	wantIndexMd := wantPath + "/index.html.md"

	for i := range doc.Links {
		lnk := &doc.Links[i]
		lu, err := url.Parse(lnk.URL)
		if err != nil || !strings.EqualFold(lu.Hostname(), wantHost) {
			continue
		}
		lp := strings.TrimRight(lu.Path, "/")
		if lp == "" {
			lp = "/"
		}
		if lp == wantPath {
			cp := *lnk
			matched = &cp
		} else if strings.EqualFold(lp, wantMdPath) || strings.EqualFold(lp, wantIndexMd) {
			cp := *lnk
			matched = &cp
			companionMdURL = lnk.URL
		}
	}

	targetSection := ""
	if matched != nil {
		targetSection = matched.Section
	}
	for _, lnk := range doc.Links {
		if matched != nil && lnk.URL == matched.URL {
			continue
		}
		if targetSection != "" && lnk.Section != targetSection {
			continue
		}
		related = append(related, lnk)
		if len(related) >= 8 {
			break
		}
	}
	return matched, companionMdURL, related
}

// CandidateCompanionMarkdownURL returns `<url>.md` when `pageURL` looks like a clean documentation/article path
// (e.g. `https://developers.cloudflare.com/workers/wrangler` -> `https://developers.cloudflare.com/workers/wrangler.md`).
func CandidateCompanionMarkdownURL(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil || u.Scheme != "https" || u.RawQuery != "" {
		return ""
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" || p == "/" {
		return ""
	}
	lower := strings.ToLower(p)
	for _, ext := range []string{".md", ".txt", ".json", ".xml", ".pdf", ".png", ".jpg", ".jpeg", ".webp", ".zip"} {
		if strings.HasSuffix(lower, ext) {
			return ""
		}
	}
	if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") {
		cp := *u
		cp.Path = p + ".md"
		cp.Fragment = ""
		return cp.String()
	}
	cp := *u
	cp.Path = p + ".md"
	cp.Fragment = ""
	return cp.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
