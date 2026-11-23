package extract

import (
	"strings"
	"sync"
)

type pslTable struct {
	exact     map[string]bool
	wildcards map[string]bool
	exception map[string]bool
}

var (
	pslOnce   sync.Once
	globalPSL *pslTable
)

func loadPSL() *pslTable {
	pslOnce.Do(func() {
		raw, err := embeddedManifestFS.ReadFile("manifests/public_suffix_list.dat")
		if err != nil {
			panic("extract: read embedded manifests/public_suffix_list.dat: " + err.Error())
		}
		t := &pslTable{
			exact:     make(map[string]bool, 10240),
			wildcards: make(map[string]bool, 384),
			exception: make(map[string]bool, 16),
		}
		inPrivate := false
		for _, rawLine := range strings.Split(string(raw), "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "//") {
				if strings.Contains(line, "===BEGIN PRIVATE DOMAINS===") {
					inPrivate = true
				} else if strings.Contains(line, "===END PRIVATE DOMAINS===") {
					inPrivate = false
				}
				continue
			}
			switch {
			case strings.HasPrefix(line, "!"):
				t.exception[line[1:]] = inPrivate
			case strings.HasPrefix(line, "*."):
				t.wildcards[line[2:]] = inPrivate
			default:
				t.exact[line] = inPrivate
			}
		}
		globalPSL = t
	})
	return globalPSL
}

func normalizePSLHostLabels(rawHost string) ([]string, bool) {
	clean := strings.ToLower(strings.TrimSpace(rawHost))
	if clean == "" || strings.HasPrefix(clean, ".") {
		return nil, false
	}
	clean = strings.TrimRight(clean, ".")
	if clean == "" {
		return nil, false
	}
	labels := strings.Split(clean, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return nil, false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return nil, false
			}
		}
	}
	tld := labels[len(labels)-1]
	if tld[0] >= '0' && tld[0] <= '9' {
		return nil, false
	}
	return labels, true
}

func matchPSL(labels []string) (suffixLen int, isPrivate bool) {
	t := loadPSL()
	suffixLen = 1
	for i := 0; i < len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		rem := len(labels) - i
		if excPriv, ok := t.exception[cand]; ok {
			return rem - 1, excPriv
		}
		if exactPriv, ok := t.exact[cand]; ok && rem > suffixLen {
			suffixLen = rem
			isPrivate = exactPriv
		}
		if i > 0 {
			if wildPriv, ok := t.wildcards[cand]; ok && rem+1 > suffixLen {
				suffixLen = rem + 1
				isPrivate = wildPriv
			}
		}
	}
	return suffixLen, isPrivate
}

// GetRegistrableDomain returns the eTLD+1 registrable domain (or "" if host is itself a public/private suffix or invalid).
func GetRegistrableDomain(host string) string {
	labels, ok := normalizePSLHostLabels(host)
	if !ok {
		return ""
	}
	suffixLen, _ := matchPSL(labels)
	if len(labels) <= suffixLen {
		return ""
	}
	return strings.Join(labels[len(labels)-suffixLen-1:], ".")
}

// IsPublicOrPrivateSuffix reports whether host is itself a public or private suffix (or unregistrable).
func IsPublicOrPrivateSuffix(host string) bool {
	return GetRegistrableDomain(host) == ""
}

// HasPrivateSharedHostingSuffix reports whether host matches a rule from the Mozilla PSL PRIVATE DOMAINS section.
func HasPrivateSharedHostingSuffix(host string) bool {
	labels, ok := normalizePSLHostLabels(host)
	if !ok {
		return false
	}
	_, isPrivate := matchPSL(labels)
	if isPrivate {
		return true
	}
	return loadPSL().wildcards[strings.Join(labels, ".")]
}
