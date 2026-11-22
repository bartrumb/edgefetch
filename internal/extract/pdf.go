package extract

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxPDFTextOutputBytes = 8 << 20 // 8 MiB extracted text ceiling

func sanitizedPopplerEnv() []string {
	pathVal := os.Getenv("PATH")
	if pathVal == "" {
		pathVal = "/usr/local/bin:/usr/bin:/bin"
	}
	tmp := os.TempDir()
	env := []string{
		"PATH=" + pathVal,
		"HOME=" + tmp,
		"TMPDIR=" + tmp,
		"TEMP=" + tmp,
		"TMP=" + tmp,
		"LANG=C.UTF-8",
	}
	for _, k := range []string{"SYSTEMROOT", "SystemRoot", "WINDIR", "windir"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// HasPDFToText reports whether `pdftotext` (`poppler-utils`, bundled in the browser/PDF worker image) is available in $PATH.
func HasPDFToText() bool {
	_, err := exec.LookPath("pdftotext")
	return err == nil
}

// ExtractPDFFileText extracts UTF-8 text from an on-disk PDF file up to `maxPages` (default 60) using `pdftotext`
// (`poppler-utils`), falling back to a bounded pure-Go FlateDecode stream reader when `pdftotext` is absent.
// Reading from a seekable file path allows Poppler to seek directly to the PDF `xref` trailer at EOF without buffering
// large manuals in RAM.
func ExtractPDFFileText(ctx context.Context, pdfPath string, maxPages int) (text string, usedPoppler bool, err error) {
	if maxPages <= 0 {
		maxPages = 60
	}
	if maxPages > 500 {
		maxPages = 500
	}
	if bin, lookErr := exec.LookPath("pdftotext"); lookErr == nil {
		pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()

		cmd := exec.CommandContext(pctx, bin, "-layout", "-enc", "UTF-8", "-nopgbrk", "-l", strconv.Itoa(maxPages), pdfPath, "-")
		cmd.Env = sanitizedPopplerEnv()
		cmd.Stderr = io.Discard
		stdout, pipeErr := cmd.StdoutPipe()
		if pipeErr == nil {
			if startErr := cmd.Start(); startErr == nil {
				out, readErr := io.ReadAll(io.LimitReader(stdout, maxPDFTextOutputBytes+1))
				capped := false
				if len(out) > maxPDFTextOutputBytes {
					capped = true
					out = out[:maxPDFTextOutputBytes]
					cancel()
					if cmd.Process != nil {
						_ = cmd.Process.Kill()
					}
				}
				waitErr := cmd.Wait()
				if readErr == nil && (waitErr == nil || capped) {
					cleaned := cleanPDFText(string(out))
					if cleaned == "" {
						return "", true, errors.New("PDF contains no extractable text (scanned image PDF)")
					}
					return cleaned, true, nil
				}
			}
		}
	}

	f, openErr := os.Open(pdfPath)
	if openErr != nil {
		return "", false, openErr
	}
	defer f.Close()
	buf, readErr := io.ReadAll(io.LimitReader(f, 32<<20))
	if readErr != nil {
		return "", false, readErr
	}
	fallback := extractPDFTextPureGo(buf, maxPages)
	if fallback == "" {
		return "", false, fmt.Errorf("PDF contains no extractable text streams (install poppler-utils pdftotext for layout extraction)")
	}
	return fallback, false, nil
}

// ExtractPDFText extracts UTF-8 text from `pdfBytes` up to `maxPages` (default 60).
// When `pdftotext` (`poppler-utils`) is installed, it streams `pdfBytes` directly over stdin into `pdftotext -layout`
// (zero temporary files on disk). On distroless Lite nodes without `pdftotext`, it falls back to a pure-Go FlateDecode
// content-stream text reader so PDF fetches remain functional everywhere.
func ExtractPDFText(ctx context.Context, pdfBytes []byte, maxPages int) (text string, usedPoppler bool, err error) {
	if !IsPDFBytes(pdfBytes) {
		return "", false, errors.New("payload does not start with %PDF- magic header")
	}
	if maxPages <= 0 {
		maxPages = 60
	}
	if maxPages > 500 {
		maxPages = 500
	}

	if bin, lookErr := exec.LookPath("pdftotext"); lookErr == nil {
		pctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()

		cmd := exec.CommandContext(pctx, bin, "-layout", "-enc", "UTF-8", "-nopgbrk", "-l", strconv.Itoa(maxPages), "-", "-")
		cmd.Env = sanitizedPopplerEnv()
		cmd.Stdin = bytes.NewReader(pdfBytes)
		cmd.Stderr = io.Discard
		stdout, pipeErr := cmd.StdoutPipe()
		if pipeErr == nil {
			if startErr := cmd.Start(); startErr == nil {
				out, readErr := io.ReadAll(io.LimitReader(stdout, maxPDFTextOutputBytes+1))
				capped := false
				if len(out) > maxPDFTextOutputBytes {
					capped = true
					out = out[:maxPDFTextOutputBytes]
					cancel()
					if cmd.Process != nil {
						_ = cmd.Process.Kill()
					}
				}
				waitErr := cmd.Wait()
				if readErr == nil && (waitErr == nil || capped) {
					cleaned := cleanPDFText(string(out))
					return cleaned, true, nil
				}
			}
		}
	}

	fallback := extractPDFTextPureGo(pdfBytes, maxPages)
	if fallback == "" {
		return "", false, fmt.Errorf("PDF contains no extractable text streams (install poppler-utils pdftotext for layout extraction)")
	}
	return fallback, false, nil
}

// IsPDFBytes checks whether `data` starts with `%PDF-` within the first 1024 bytes (per PDF spec §7.5.2).
func IsPDFBytes(data []byte) bool {
	window := data
	if len(window) > 1024 {
		window = window[:1024]
	}
	return bytes.Contains(window, []byte("%PDF-"))
}

var (
	rePDFStream  = regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`)
	rePDFTextRun = regexp.MustCompile(`\((?:\\.|[^\\)])*\)\s*Tj|\[(.*?)\]\s*TJ`)
	rePDFParen   = regexp.MustCompile(`\((?:\\.|[^\\)])*\)`)
)

func extractPDFTextPureGo(pdfBytes []byte, maxStreams int) string {
	matches := rePDFStream.FindAllSubmatch(pdfBytes, maxStreams*3)
	var out strings.Builder
	streamsRead := 0

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		raw := m[1]
		decoded := raw
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			buf, rErr := io.ReadAll(io.LimitReader(zr, 2<<20))
			_ = zr.Close()
			if rErr == nil && len(buf) > 0 {
				decoded = buf
			}
		}
		runs := rePDFTextRun.FindAll(decoded, 4000)
		if len(runs) == 0 {
			continue
		}
		streamsRead++
		for _, run := range runs {
			for _, p := range rePDFParen.FindAll(run, -1) {
				if len(p) >= 2 {
					out.WriteString(unescapePDFString(string(p[1 : len(p)-1])))
				}
			}
			out.WriteByte(' ')
		}
		out.WriteString("\n\n")
		if out.Len() >= maxPDFTextOutputBytes || streamsRead >= maxPagesCap(maxStreams) {
			break
		}
	}
	return cleanPDFText(out.String())
}

func maxPagesCap(n int) int {
	if n <= 0 {
		return 60
	}
	return n * 2
}

func unescapePDFString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		if s[i] >= 0x20 && s[i] <= 0x7E || s[i] == '\n' || s[i] == '\t' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func cleanPDFText(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	var out []string
	blankRun := 0
	for _, l := range lines {
		trimmed := strings.TrimRight(l, " \t")
		if strings.TrimSpace(trimmed) == "" {
			blankRun++
			if blankRun <= 1 {
				out = append(out, "")
			}
			continue
		}
		blankRun = 0
		out = append(out, trimmed)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
