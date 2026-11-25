package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestR10S6SeccompProfileForbids32BitArchitecturesAndSocketcallBypass(t *testing.T) {
	t.Parallel()
	seccompPath := filepath.Join("..", "..", "deploy", "seccomp", "chromium-sandbox.json")
	raw, err := os.ReadFile(seccompPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", seccompPath, err)
	}

	var profile struct {
		DefaultAction   string   `json:"defaultAction"`
		DefaultErrnoRet *uint    `json:"defaultErrnoRet,omitempty"`
		Architectures   []string `json:"architectures,omitempty"`
		ArchMap         []struct {
			Architecture     string   `json:"architecture"`
			SubArchitectures []string `json:"subArchitectures"`
		} `json:"archMap"`
		Syscalls []struct {
			Names    []string `json:"names"`
			Action   string   `json:"action"`
			ErrnoRet *uint    `json:"errnoRet,omitempty"`
			Comment  string   `json:"comment,omitempty"`
			Includes *struct {
				Arches []string `json:"arches,omitempty"`
			} `json:"includes,omitempty"`
			Excludes *struct {
				Arches []string `json:"arches,omitempty"`
			} `json:"excludes,omitempty"`
			Args []struct {
				Index    uint   `json:"index"`
				Value    uint64 `json:"value"`
				ValueTwo uint64 `json:"valueTwo,omitempty"`
				Op       string `json:"op"`
			} `json:"args,omitempty"`
		} `json:"syscalls"`
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&profile); err != nil {
		t.Fatalf("strict JSON decode of chromium-sandbox.json failed: %v", err)
	}

	if profile.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("expected defaultAction == SCMP_ACT_ERRNO, got %q", profile.DefaultAction)
	}

	allowed64 := map[string]bool{
		"SCMP_ARCH_X86_64":  true,
		"SCMP_ARCH_AARCH64": true,
	}
	for _, a := range profile.Architectures {
		if !allowed64[a] {
			t.Fatalf("SECURITY (S6): forbidden non-64-bit architecture %q in top-level architectures", a)
		}
	}
	if len(profile.ArchMap) != 2 {
		t.Fatalf("expected exactly 2 64-bit archMap entries (SCMP_ARCH_X86_64 and SCMP_ARCH_AARCH64), got %d", len(profile.ArchMap))
	}
	seenArch := make(map[string]bool)
	for _, entry := range profile.ArchMap {
		if !allowed64[entry.Architecture] {
			t.Fatalf("SECURITY (S6): forbidden architecture %q in archMap (only 64-bit SCMP_ARCH_X86_64 and SCMP_ARCH_AARCH64 allowed)", entry.Architecture)
		}
		if len(entry.SubArchitectures) != 0 {
			t.Fatalf("SECURITY (S6): archMap[%s].subArchitectures MUST be empty (found %v — 32-bit int $0x80 / compat syscalls allow socketcall bypass!)", entry.Architecture, entry.SubArchitectures)
		}
		seenArch[entry.Architecture] = true
	}
	if !seenArch["SCMP_ARCH_X86_64"] || !seenArch["SCMP_ARCH_AARCH64"] {
		t.Fatalf("expected both SCMP_ARCH_X86_64 and SCMP_ARCH_AARCH64 in archMap, got %+v", seenArch)
	}

	// Verify zero 32-bit sub-arch names appear anywhere in includes/excludes or raw JSON tokens, and socketcall is never allowed.
	allowedOCIArches := map[string]bool{"amd64": true, "arm64": true}
	for idx, rule := range profile.Syscalls {
		if rule.Includes != nil {
			for _, arch := range rule.Includes.Arches {
				if !allowedOCIArches[arch] {
					t.Fatalf("SECURITY (S6): syscall rule #%d includes non-64-bit OCI arch %q", idx, arch)
				}
			}
		}
		if rule.Excludes != nil {
			for _, arch := range rule.Excludes.Arches {
				if !allowedOCIArches[arch] {
					t.Fatalf("SECURITY (S6): syscall rule #%d excludes non-64-bit OCI arch %q", idx, arch)
				}
			}
		}
		if rule.Action == "SCMP_ACT_ALLOW" {
			for _, name := range rule.Names {
				if name == "socketcall" || name == "ia32_syscall" {
					t.Fatalf("SECURITY (S6): %q must NEVER appear in SCMP_ACT_ALLOW", name)
				}
			}
		}
	}
	for _, forbiddenArchToken := range []string{"SCMP_ARCH_X86\"", "SCMP_ARCH_X32", "SCMP_ARCH_ARM\"", "SCMP_ARCH_386"} {
		if strings.Contains(string(raw), forbiddenArchToken) {
			t.Fatalf("SECURITY (S6): forbidden 32-bit architecture token %s still present in chromium-sandbox.json", forbiddenArchToken)
		}
	}

	// Live headless Chromium probe on Linux (WSL Ubuntu / CI) when Chromium is installed.
	if runtime.GOOS == "linux" {
		bin := FindChromeBinary()
		if bin == "" {
			return
		}
		acquireLiveChromeSlot(t)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>S6 Probe</title></head><body><main>seccomp-64bit-ok</main></body></html>`))
		}))
		defer srv.Close()
		srvAddr := srv.Listener.Addr().String()

		r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetch-R10-Seccomp/1.0", 1, nil)
		enableNoSandboxOnRestrictedLinuxHost(r)
		r.extraFlags = []string{"--ignore-certificate-errors"}
		r.proxyDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
		}
		defer r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		out, err := r.Execute(ctx, Task{URL: "https://seccomp-probe.example.com/", WaitForMs: 20})
		if err != nil || !strings.Contains(out.HTML, "seccomp-64bit-ok") {
			t.Fatalf("headless Chromium probe failed: err=%v html=%q", err, out.HTML)
		}
	}
}
