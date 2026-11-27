package company

import (
	"strconv"
	"strings"
)

// renderMarkdown renders a compact Markdown summary from already-sanitized Profile fields.
func renderMarkdown(p *Profile) string {
	var b strings.Builder
	title := firstNonEmpty(p.Name, p.LegalName, p.Domain, "Company profile")
	b.WriteString("# ")
	b.WriteString(title)
	b.WriteString("\n\n")
	if p.Description != "" {
		b.WriteString(p.Description)
		b.WriteString("\n\n")
	}
	bullet := func(label, val string) {
		if val == "" {
			return
		}
		b.WriteString("- **")
		b.WriteString(label)
		b.WriteString("**: ")
		b.WriteString(val)
		b.WriteByte('\n')
	}
	if p.LegalName != "" && p.LegalName != p.Name {
		bullet("Legal name", p.LegalName)
	}
	bullet("Website", p.Website)
	if p.Founded > 0 {
		bullet("Founded", strconv.Itoa(p.Founded))
	}
	if hq := p.Headquarters; hq != nil {
		bullet("Headquarters", firstNonEmpty(joinNonEmpty(", ", hq.City, hq.Region, hq.Country), hq.Address))
	}
	if ind := p.Industry; ind != nil {
		sic := ""
		if ind.SICCode != "" || ind.SICDescription != "" {
			sic = strings.TrimSpace(ind.SICDescription + " (SIC " + ind.SICCode + ")")
			if ind.SICCode == "" {
				sic = ind.SICDescription
			}
		}
		bullet("Industry", joinNonEmpty("; ", sic, strings.Join(ind.Labels, ", ")))
	}
	if e := p.Employees; e != nil {
		v := formatThousands(e.Count)
		if e.AsOf != "" {
			v += " (as of " + e.AsOf + ")"
		}
		bullet("Employees", v)
	}
	if len(p.Listings) > 0 {
		parts := make([]string, 0, len(p.Listings))
		for _, l := range p.Listings {
			parts = append(parts, joinNonEmpty(": ", l.Exchange, l.Ticker))
		}
		bullet("Listed", strings.Join(parts, ", "))
	}
	bullet("SEC CIK", p.CIK)
	if r := p.Revenue; r != nil {
		bullet("Revenue", "$"+formatThousands(r.Value)+" USD (FY"+strconv.Itoa(r.FiscalYear)+", period ending "+r.PeriodEnd+", "+r.Form+")")
	}
	if g := p.GitHub; g != nil {
		bullet("GitHub", g.URL+" ("+strconv.Itoa(g.PublicRepos)+" public repos, "+formatThousands(int64(g.Followers))+" followers)")
	}
	if s := p.Socials; s != nil {
		var parts []string
		for _, n := range socialNetworks {
			if v := s.get(n); v != "" {
				parts = append(parts, v)
			}
		}
		bullet("Social", strings.Join(parts, ", "))
	}
	if pl := p.Place; pl != nil {
		v := joinNonEmpty(", ", pl.Name, pl.Address)
		if pl.Rating > 0 {
			v += " (rating " + strconv.FormatFloat(pl.Rating, 'f', 1, 64)
			if pl.RatingCount > 0 {
				v += " from " + formatThousands(int64(pl.RatingCount)) + " reviews"
			}
			v += ")"
		}
		if pl.MapsURL != "" {
			v += " " + pl.MapsURL
		}
		bullet("Map", strings.TrimSpace(v))
	}
	if h := p.Hiring; h != nil {
		v := strconv.Itoa(h.OpenRoles) + " open roles"
		if h.Platform != "" {
			v += " on " + h.Platform
		}
		bullet("Hiring", v)
		bullet("Top departments", strings.Join(h.Departments, ", "))
		bullet("Top locations", strings.Join(h.Locations, ", "))
		bullet("Job boards", strings.Join(h.BoardURLs, ", "))
	}
	bullet("Wikidata", p.WikidataID)
	if len(p.Sources) > 0 {
		b.WriteString("\nSources: ")
		b.WriteString(strings.Join(p.Sources, ", "))
		b.WriteByte('\n')
	}
	return b.String()
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func formatThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
