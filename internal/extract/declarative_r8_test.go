package extract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR8VendoredPSLAndMatchesApprovedWildcard(t *testing.T) {
	// 1. Mozilla PSL exact, wildcard (*.ck, *.kobe.jp, *.platformsh.site, *.run.app), exception (!www.ck, !city.kobe.jp), IDN punycode, & PRIVATE DOMAINS
	cases := []struct {
		host     string
		wantReg  string
		wantSuf  bool
		wantPriv bool
	}{
		{"en.wikipedia.org", "wikipedia.org", false, false},
		{"com", "", true, false},
		{"co.uk", "", true, false},
		{"bbc.co.uk", "bbc.co.uk", false, false},
		{"ck", "", true, false},
		{"foo.ck", "", true, false},
		{"bar.foo.ck", "bar.foo.ck", false, false},
		{"www.ck", "www.ck", false, false},
		{"sub.www.ck", "www.ck", false, false},
		{"other.kobe.jp", "", true, false},
		{"city.kobe.jp", "city.kobe.jp", false, false},
		{"ward.city.kobe.jp", "city.kobe.jp", false, false},
		{"supabase.co", "", true, true},
		{"evil.supabase.co", "evil.supabase.co", false, true},
		{"workers.dev", "", true, true},
		{"foo.workers.dev", "foo.workers.dev", false, true},
		{"github.io", "", true, true},
		{"bar.github.io", "bar.github.io", false, true},
		{"s3.amazonaws.com", "", true, true},
		{"bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com", false, true},
		{"eu.platformsh.site", "", true, true},
		{"app.eu.platformsh.site", "app.eu.platformsh.site", false, true},
		{"a.run.app", "", true, true},
		{"svc1.a.run.app", "svc1.a.run.app", false, true},
		{"ngrok-free.app", "", true, true},
		{"z.ngrok-free.app", "z.ngrok-free.app", false, true},
		{"shop.xn--fiqs8s", "shop.xn--fiqs8s", false, false},
		{"xn--fiqs8s", "", true, false},
	}
	for _, tc := range cases {
		if got := GetRegistrableDomain(tc.host); got != tc.wantReg {
			t.Fatalf("GetRegistrableDomain(%q) = %q, want %q", tc.host, got, tc.wantReg)
		}
		if got := IsPublicOrPrivateSuffix(tc.host); got != tc.wantSuf {
			t.Fatalf("IsPublicOrPrivateSuffix(%q) = %v, want %v", tc.host, got, tc.wantSuf)
		}
		if got := HasPrivateSharedHostingSuffix(tc.host); got != tc.wantPriv {
			t.Fatalf("HasPrivateSharedHostingSuffix(%q) = %v, want %v", tc.host, got, tc.wantPriv)
		}
	}

	// 2. Simple 3-shape MatchesApprovedWildcard checks
	mustMatch := [][2]string{
		{"*.wikipedia.org", "en.wikipedia.org"},
		{"*.wikipedia.org", "a.b.wikipedia.org"},
		{"*.wikipedia.org", "*.sub.wikipedia.org"},
		{"careers.*.com", "careers.stripe.com"},
		{"jobs.*.com", "jobs.apple.com"},
		{"gitlab.*", "gitlab.company.org"},
		{"gitlab.*", "gitlab.eu.company.org"},
	}
	for _, pair := range mustMatch {
		if !MatchesApprovedWildcard(pair[0], pair[1]) {
			t.Fatalf("expected MatchesApprovedWildcard(%q, %q) == true", pair[0], pair[1])
		}
	}

	mustNotMatch := [][2]string{
		{"*.wikipedia.org", "*.wikimedia.org"},
		{"*.wikipedia.org", "wikipedia.org"},
		{"careers.*.com", "careers.com"},
		{"jobs.*.com", "jobs.org"},
		{"gitlab.*", "mygitlab.org"},
		{"api.example.com", "app.example.com"},
		{"", "en.wikipedia.org"},
	}
	for _, pair := range mustNotMatch {
		if MatchesApprovedWildcard(pair[0], pair[1]) {
			t.Fatalf("expected MatchesApprovedWildcard(%q, %q) == false", pair[0], pair[1])
		}
	}
}

func TestR8ValidateDeclarativeManifestsOverlapHostingCatalogAndRedirects(t *testing.T) {
	rawCompiled, err := embeddedManifestFS.ReadFile("manifests/compiled.json")
	if err != nil {
		t.Fatalf("ReadFile(manifests/compiled.json): %v", err)
	}
	var bundle compiledManifestBundle
	dec := json.NewDecoder(bytes.NewReader(rawCompiled))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		t.Fatalf("Decode compiled.json: %v", err)
	}
	if len(bundle.Manifests) != 56 {
		t.Fatalf("expected 56 compiled manifests, got %d", len(bundle.Manifests))
	}
	if err := ValidateDeclarativeManifests(bundle.Manifests); err != nil {
		t.Fatalf("expected embedded 56 manifests to pass ValidateDeclarativeManifests, got: %v", err)
	}

	makeRogue := func(id, dom, fetchURL string) DeclarativeManifest {
		return DeclarativeManifest{
			ID:          id,
			Name:        "Rogue Manifest",
			Category:    "developer",
			Description: "Synthetic manifest testing H7 cross-manifest overlap and host guards.",
			Domains:     []string{dom},
			ExampleURLs: []string{"https://example.org/item"},
			Routes: []DeclarativeRouteSpec{{
				Match:   DeclarativeMatchSpec{PathSegments: []DeclarativeSegmentSpec{{IsLiteral: true, Literal: "wiki"}}},
				Twin:    DeclarativeTwinSpec{ID: id + "-twin", FetchURL: fetchURL, Kind: "json", Accept: "application/json"},
				Extract: DeclarativeExtractSpec{TitleTemplate: "Hijacked"},
			}},
		}
	}

	// 1. Exact subdomain hijack against *.wikipedia.org, careers.*.com, jobs.*.com, and gitlab.* MUST fail!
	overlapAttacks := []DeclarativeManifest{
		makeRogue("hijack-wiki", "en.wikipedia.org", "https://en.wikipedia.org/api/rest_v1/page/summary/Bank"),
		makeRogue("hijack-careers", "careers.stripe.com", "https://careers.stripe.com/api/jobs"),
		makeRogue("hijack-jobs", "jobs.stripe.com", "https://jobs.stripe.com/api/jobs"),
		makeRogue("hijack-gitlab", "gitlab.company.org", "https://gitlab.company.org/api/v4/projects"),
	}
	for _, atk := range overlapAttacks {
		combined := append(append([]DeclarativeManifest(nil), bundle.Manifests...), atk)
		vErr := ValidateDeclarativeManifests(combined)
		if vErr == nil || !strings.Contains(strings.ToLower(vErr.Error()), "overlap") {
			t.Fatalf("SECURITY (H7): expected cross-manifest overlap rejection for %s (%v), got err=%v", atk.ID, atk.Domains, vErr)
		}
	}

	// 2. Multi-tenant shared-hosting suffixes MUST be rejected for BOTH wildcards AND exact tenant subdomains!
	for _, badHost := range []string{
		"*.github.io",
		"victim.github.io",
		"*.codeberg.page",
		"docs.codeberg.page",
		"app.pages.dev",
		"worker.workers.dev",
		"preview.vercel.app",
		"site.netlify.app",
		"app.herokuapp.com",
		"svc.up.railway.app",
		"app.eu.platformsh.site",
		"bot.replit.app",
		"fn.deno.dev",
		"proj.supabase.co",
		"app.convex.site",
		"tun.ngrok.app",
		"tun.trycloudflare.com",
	} {
		m := makeRogue("bad-hosting", badHost, "{requestUrl}")
		if err := ValidateDeclarativeManifests([]DeclarativeManifest{m}); err == nil {
			t.Fatalf("SECURITY (H7): expected shared-hosting domain %q to be rejected", badHost)
		}
	}

	// 3. Unapproved cross-domain twin.fetchUrl collector MUST be rejected!
	exfil := makeRogue("exfil-twin", "victim-corp.org", "https://collector.attacker-domain.net/steal")
	if err := ValidateDeclarativeManifests([]DeclarativeManifest{exfil}); err == nil || !strings.Contains(err.Error(), "cross-domain twin host") {
		t.Fatalf("SECURITY (H7): expected unapproved cross-domain twin.fetchUrl rejection, got %v", err)
	}

	// 4. Strict catalog.platform allowlist ("shopify" | "woocommerce") + duplicate platform guard!
	badCat := DeclarativeManifest{
		ID:          "bad-catalog",
		Name:        "Bad Catalog",
		Category:    "commerce-social",
		Description: "Manifest with unsupported catalog platform.",
		Domains:     []string{"store.example.org"},
		ExampleURLs: []string{"https://store.example.org/products"},
		Catalog:     &DeclarativeCatalogConfig{Platform: "magento", PauseMs: 1000, PageCap: 10},
	}
	if err := ValidateDeclarativeManifests([]DeclarativeManifest{badCat}); err == nil || !strings.Contains(err.Error(), "catalog.platform") {
		t.Fatalf("SECURITY (H7): expected unknown catalog.platform 'magento' to fail, got %v", err)
	}
	dupShopify := badCat
	dupShopify.Catalog = &DeclarativeCatalogConfig{Platform: "shopify", PauseMs: 1000, PageCap: 10}
	if err := ValidateDeclarativeManifests(append(append([]DeclarativeManifest(nil), bundle.Manifests...), dupShopify)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate catalog platform") {
		t.Fatalf("expected duplicate shopify catalog platform to fail, got %v", err)
	}

	// 5. Twin redirect target validation: block cross-domain and cross-tenant wildcard redirects!
	shopTwin, ok := ResolveDeclarativeTwin("https://acme-store.myshopify.com/products/shirt")
	if !ok || shopTwin == nil {
		t.Fatal("expected shopify twin resolution")
	}
	if !shopTwin.ValidateRedirectTarget("https://acme-store.myshopify.com/products/shirt.js") {
		t.Fatal("expected same-tenant redirect on shopify twin to pass")
	}
	if shopTwin.ValidateRedirectTarget("https://evil-tenant.myshopify.com/products/shirt.js") {
		t.Fatal("SECURITY: cross-tenant redirect on wildcard *.myshopify.com twin must be rejected")
	}
	if shopTwin.ValidateRedirectTarget("https://attacker.example.com/steal.json") {
		t.Fatal("SECURITY: cross-domain redirect on twin must be rejected")
	}

	rgTwin, ok := ResolveDeclarativeTwin("https://rubygems.org/gems/rails")
	if !ok || rgTwin == nil {
		t.Fatal("expected rubygems twin resolution")
	}
	if !rgTwin.ValidateRedirectTarget("https://www.rubygems.org/api/v1/gems/rails.json") {
		t.Fatal("expected declared domain www.rubygems.org redirect to pass")
	}
	if rgTwin.ValidateRedirectTarget("https://unclaimed.rubygems.org/api/v1/gems/rails.json") {
		t.Fatal("SECURITY: redirect to unclaimed subdomain on same registrable domain must be rejected (TS parity)")
	}
	if rgTwin.ValidateRedirectTarget("https://evil.workers.dev/rails.json") {
		t.Fatal("SECURITY: redirect to shared-hosting workers.dev must be rejected")
	}

	hfTwin, ok := ResolveDeclarativeTwin("https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct")
	if !ok || hfTwin == nil {
		t.Fatal("expected huggingface twin resolution")
	}
	if hfTwin.ValidateRedirectTarget("https://spaces.huggingface.co/steal.json") {
		t.Fatal("SECURITY: redirect to unclaimed spaces.huggingface.co subdomain must be rejected (TS parity)")
	}
}

func TestR8HardenedChromiumSeccompProfileInvariants(t *testing.T) {
	seccompPath := filepath.Join("..", "..", "deploy", "seccomp", "chromium-sandbox.json")
	raw, err := os.ReadFile(seccompPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", seccompPath, err)
	}
	var prof struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names    []string `json:"names"`
			Action   string   `json:"action"`
			ErrnoRet *int     `json:"errnoRet"`
			Includes struct {
				Arches []string `json:"arches"`
			} `json:"includes"`
			Args []struct {
				Index    int    `json:"index"`
				Value    uint64 `json:"value"`
				ValueTwo uint64 `json:"valueTwo"`
				Op       string `json:"op"`
			} `json:"args"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(raw, &prof); err != nil {
		t.Fatalf("invalid JSON in %s: %v", seccompPath, err)
	}
	if prof.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("expected defaultAction SCMP_ACT_ERRNO, got %q", prof.DefaultAction)
	}
	if len(prof.Syscalls) < 5 {
		t.Fatalf("expected structured multi-rule seccomp profile, got %d rules", len(prof.Syscalls))
	}

	allowed := make(map[string]bool)
	unconditionalAllow := make(map[string]bool)
	archGated := make(map[string][]string)
	argGated := make(map[string]int)
	sawClone3Enosys := false
	for _, rule := range prof.Syscalls {
		if rule.Action == "SCMP_ACT_ERRNO" {
			for _, n := range rule.Names {
				if n == "clone3" && rule.ErrnoRet != nil && *rule.ErrnoRet == 38 {
					sawClone3Enosys = true
				}
			}
			continue
		}
		if rule.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, n := range rule.Names {
			allowed[n] = true
			if len(rule.Args) == 0 && len(rule.Includes.Arches) == 0 {
				unconditionalAllow[n] = true
			}
			if len(rule.Includes.Arches) > 0 {
				archGated[n] = append(archGated[n], rule.Includes.Arches...)
			}
			if len(rule.Args) > 0 {
				argGated[n] += len(rule.Args)
			}
		}
	}

	for _, mustDeny := range []string{
		"ptrace", "bpf", "perf_event_open", "userfaultfd",
		"io_uring_setup", "io_uring_enter", "io_uring_register",
		"keyctl", "add_key", "request_key",
		"kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
		"open_by_handle_at", "name_to_handle_at",
		"mount", "umount", "umount2", "pivot_root",
		"setns", "clone3", "socketcall",
		"adjtimex", "clock_adjtime", "clock_adjtime64", "fanotify_mark",
		"chown", "chown32", "fchown", "fchown32", "fchownat", "lchown", "lchown32",
		"mknod", "mknodat", "vmsplice", "remap_file_pages", "swapon", "swapoff", "reboot", "acct",
	} {
		if allowed[mustDeny] {
			t.Fatalf("SECURITY: forbidden syscall %q must NOT be allowed in chromium-sandbox.json", mustDeny)
		}
	}
	if !sawClone3Enosys {
		t.Fatal("expected clone3 to return ENOSYS (errnoRet: 38) so libc falls back cleanly to clone(2)")
	}
	if unconditionalAllow["socket"] || argGated["socket"] < 8 {
		t.Fatalf("SECURITY: socket(2) must NOT be unconditionally allowed (must filter out AF_PACKET/SOCK_RAW); unconditional=%v argRules=%d", unconditionalAllow["socket"], argGated["socket"])
	}

	for _, mustAllowSandbox := range []string{"clone", "unshare", "chroot", "seccomp", "prctl"} {
		if !allowed[mustAllowSandbox] {
			t.Fatalf("expected Chromium sandbox syscall %q in SCMP_ACT_ALLOW", mustAllowSandbox)
		}
	}
	if len(archGated["arch_prctl"]) == 0 || len(archGated["arm_fadvise64_64"]) == 0 {
		t.Fatalf("expected arch_prctl and arm_fadvise64_64 to be gated by includes.arches, got %+v", archGated)
	}
	if argGated["personality"] < 5 {
		t.Fatalf("expected personality to be restricted by explicit SCMP_CMP_EQ args, got %d arg rules", argGated["personality"])
	}
}
