package company

import (
	"net/url"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// Socials holds normalized company social profile URLs (https only, canonical hosts).
type Socials struct {
	LinkedIn  string `json:"linkedin,omitempty"`
	X         string `json:"x,omitempty"`
	GitHub    string `json:"github,omitempty"`
	Facebook  string `json:"facebook,omitempty"`
	Instagram string `json:"instagram,omitempty"`
	YouTube   string `json:"youtube,omitempty"`
}

// Social network keys (also used as `socials.<key>` in Profile.FieldSources).
const (
	NetLinkedIn  = "linkedin"
	NetX         = "x"
	NetGitHub    = "github"
	NetFacebook  = "facebook"
	NetInstagram = "instagram"
	NetYouTube   = "youtube"
)

var socialNetworks = []string{NetLinkedIn, NetX, NetGitHub, NetFacebook, NetInstagram, NetYouTube}

func (s *Socials) get(net string) string {
	switch net {
	case NetLinkedIn:
		return s.LinkedIn
	case NetX:
		return s.X
	case NetGitHub:
		return s.GitHub
	case NetFacebook:
		return s.Facebook
	case NetInstagram:
		return s.Instagram
	case NetYouTube:
		return s.YouTube
	}
	return ""
}

func (s *Socials) set(net, v string) {
	switch net {
	case NetLinkedIn:
		s.LinkedIn = v
	case NetX:
		s.X = v
	case NetGitHub:
		s.GitHub = v
	case NetFacebook:
		s.Facebook = v
	case NetInstagram:
		s.Instagram = v
	case NetYouTube:
		s.YouTube = v
	}
}

func (s *Socials) empty() bool {
	for _, n := range socialNetworks {
		if s.get(n) != "" {
			return false
		}
	}
	return true
}

var reservedXPaths = map[string]bool{
	"intent": true, "share": true, "home": true, "search": true, "hashtag": true, "i": true, "login": true,
	"signup": true, "explore": true, "settings": true, "messages": true, "notifications": true, "tos": true,
	"privacy": true,
}

var reservedGitHubPaths = map[string]bool{
	"about": true, "features": true, "pricing": true, "login": true, "join": true, "marketplace": true,
	"sponsors": true, "topics": true, "explore": true, "settings": true, "site": true, "security": true,
	"enterprise": true, "collections": true, "trending": true, "apps": true, "contact": true,
}

var reservedFacebookPaths = map[string]bool{
	"sharer": true, "sharer.php": true, "share": true, "share.php": true, "dialog": true, "plugins": true,
	"tr": true, "profile.php": true, "login": true, "login.php": true, "watch": true, "groups": true,
	"events": true, "hashtag": true, "help": true, "policies": true, "privacy": true, "people": true,
}

var reservedInstagramPaths = map[string]bool{
	"p": true, "reel": true, "reels": true, "explore": true, "accounts": true, "stories": true, "tv": true,
	"about": true, "legal": true, "direct": true,
}

// NormalizeSocialURL validates raw as a public https URL on a known social network and returns its canonical
// form: linkedin `https://www.linkedin.com/company/<slug>` (company/school/showcase pages only, never personal
// `/in/` profiles), `https://x.com/<handle>`, `https://github.com/<login>`, `https://www.facebook.com/<page>`,
// `https://www.instagram.com/<handle>`, `https://www.youtube.com/{@handle|channel/<id>|c/<name>|user/<name>}`.
// Non-https schemes (http:, javascript:, data:) and share/intent links are rejected.
func NormalizeSocialURL(raw string) (network, normalized string, ok bool) {
	t := strings.TrimSpace(raw)
	if len(t) > 2048 || !strings.HasPrefix(asciiLower(t), "https://") {
		return "", "", false
	}
	safe := extract.SanitizeSchemaHTTPSURL(t, "")
	if safe == "" {
		return "", "", false
	}
	u, err := url.Parse(safe)
	if err != nil {
		return "", "", false
	}
	host := asciiLower(u.Hostname())
	for _, p := range []string{"www.", "m.", "mobile.", "mbasic.", "touch."} {
		host = strings.TrimPrefix(host, p)
	}
	segs := pathSegments(u.Path)
	if len(segs) == 0 {
		return "", "", false
	}
	first := segs[0]
	lf := asciiLower(first)
	switch host {
	case "linkedin.com", "uk.linkedin.com", "de.linkedin.com", "fr.linkedin.com", "ca.linkedin.com":
		if len(segs) >= 2 && (lf == "company" || lf == "school" || lf == "showcase") && validSlug(segs[1], 100, "-_.%") {
			return NetLinkedIn, "https://www.linkedin.com/" + lf + "/" + asciiLower(segs[1]), true
		}
	case "twitter.com", "x.com":
		if !reservedXPaths[lf] && validSlug(first, 15, "_") {
			return NetX, "https://x.com/" + first, true
		}
	case "github.com":
		if lf == "orgs" && len(segs) >= 2 && validGitHubLogin(segs[1]) {
			return NetGitHub, "https://github.com/" + segs[1], true
		}
		if !reservedGitHubPaths[lf] && validGitHubLogin(first) {
			return NetGitHub, "https://github.com/" + first, true
		}
	case "facebook.com", "fb.com":
		if lf == "pages" && len(segs) >= 2 && validSlug(segs[len(segs)-1], 80, "-_.") {
			return NetFacebook, "https://www.facebook.com/" + strings.Join(segs[:minInt(len(segs), 3)], "/"), true
		}
		if !reservedFacebookPaths[lf] && validSlug(first, 80, "-_.") {
			return NetFacebook, "https://www.facebook.com/" + first, true
		}
	case "instagram.com":
		if !reservedInstagramPaths[lf] && validSlug(first, 30, "_.") {
			return NetInstagram, "https://www.instagram.com/" + first, true
		}
	case "youtube.com":
		if strings.HasPrefix(first, "@") && validSlug(first[1:], 100, "-_.") {
			return NetYouTube, "https://www.youtube.com/" + first, true
		}
		if (lf == "channel" || lf == "c" || lf == "user") && len(segs) >= 2 && validSlug(segs[1], 100, "-_.") {
			return NetYouTube, "https://www.youtube.com/" + lf + "/" + segs[1], true
		}
	}
	return "", "", false
}

func pathSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func validSlug(s string, maxLen int, extra string) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(extra, c) >= 0 {
			continue
		}
		return false
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// socialHostHints is a cheap pre-filter for homepage hrefs.
var socialHostHints = []string{"linkedin.com", "twitter.com", "x.com", "github.com", "facebook.com", "fb.com", "instagram.com", "youtube.com"}

// scanHrefs extracts up to limit href attribute values from rawHTML in a single forward pass. Each match
// advances the cursor past the scanned value, so total work is linear in the (capped) input.
func scanHrefs(rawHTML string, limit int) []string {
	if len(rawHTML) > maxHTMLBodyBytes {
		rawHTML = rawHTML[:maxHTMLBodyBytes]
	}
	lower := asciiLower(rawHTML)
	var out []string
	pos := 0
	for pos < len(lower) && len(out) < limit {
		i := strings.Index(lower[pos:], "href")
		if i < 0 {
			break
		}
		j := pos + i + 4
		for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t' || lower[j] == '\n' || lower[j] == '\r') {
			j++
		}
		if j >= len(lower) || lower[j] != '=' {
			pos = j
			continue
		}
		j++
		for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t' || lower[j] == '\n' || lower[j] == '\r') {
			j++
		}
		if j >= len(lower) {
			break
		}
		end := minInt(len(lower), j+2048)
		var val string
		if q := lower[j]; q == '"' || q == '\'' {
			k := strings.IndexByte(lower[j+1:end], q)
			if k < 0 {
				pos = end
				continue
			}
			val = rawHTML[j+1 : j+1+k]
			pos = j + 1 + k + 1
		} else {
			k := j
			for k < end && lower[k] != ' ' && lower[k] != '>' && lower[k] != '\t' && lower[k] != '\n' && lower[k] != '\r' {
				k++
			}
			val = rawHTML[j:k]
			pos = k
		}
		lv := asciiLower(val)
		for _, h := range socialHostHints {
			if strings.Contains(lv, h) {
				out = append(out, strings.ReplaceAll(val, "&amp;", "&"))
				break
			}
		}
	}
	return out
}

// socialCandidates collects normalized URLs per network in encounter order (deduplicated).
type socialCandidates map[string][]string

func (c socialCandidates) add(raw string) {
	net, norm, ok := NormalizeSocialURL(raw)
	if !ok {
		return
	}
	for _, v := range c[net] {
		if strings.EqualFold(v, norm) {
			return
		}
	}
	if len(c[net]) < 20 {
		c[net] = append(c[net], norm)
	}
}

// best returns the candidate whose handle contains brand (case-insensitive), else the first one.
func (c socialCandidates) best(net, brand string) string {
	list := c[net]
	if len(list) == 0 {
		return ""
	}
	if b := asciiLower(brand); len(b) >= 2 {
		for _, v := range list {
			if i := strings.LastIndexByte(v, '/'); i >= 0 && strings.Contains(asciiLower(v[i+1:]), b) {
				return v
			}
		}
	}
	return list[0]
}

// socialHandle returns the last path segment of a normalized social URL.
func socialHandle(u string) string {
	if i := strings.LastIndexByte(u, '/'); i >= 0 {
		return strings.TrimPrefix(u[i+1:], "@")
	}
	return ""
}
