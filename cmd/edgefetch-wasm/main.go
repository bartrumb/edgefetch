package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/internal/extract"
)

func main() {
	os.Exit(runWasmCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runWasmCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts := extract.ExtractOptions{
		OnlyMainContent: true,
		IncludeLinks:    true,
	}
	wantJSON := false

	for _, a := range args {
		switch {
		case a == "--json":
			wantJSON = true
		case a == "--full":
			opts.OnlyMainContent = false
		case a == "--branding":
			opts.IncludeBranding = true
		case a == "--images":
			opts.IncludeImages = true
		case a == "--redact-pii":
			opts.RedactPII = true
		case strings.HasPrefix(a, "--url="):
			opts.BaseURL = strings.TrimPrefix(a, "--url=")
		case strings.HasPrefix(a, "--query="):
			opts.Query = strings.TrimPrefix(a, "--query=")
		case strings.HasPrefix(a, "--max-chars="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--max-chars=")); err == nil && n > 0 {
				opts.MaxChars = n
			}
		case a == "--help" || a == "-h":
			_, _ = fmt.Fprintln(stdout, "Usage: edgefetch-wasm [--json] [--url=https://...] [--query=...] [--max-chars=N] [--branding] < input.html")
			return 0
		}
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, 16<<20))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read stdin: %v\n", err)
		return 1
	}

	res := extract.ExtractHTML(string(raw), opts)
	if wantJSON {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			_, _ = fmt.Fprintf(stderr, "encode json: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(buf.Bytes())
		return 0
	}

	out := strings.TrimSpace(res.Markdown)
	if out != "" {
		_, _ = fmt.Fprintln(stdout, out)
	}
	return 0
}
