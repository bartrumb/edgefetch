package extract

import (
	"bytes"
	"compress/zlib"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutableScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", p, err)
	}
	return p
}

func buildMinimalFlatePDF(t *testing.T, streams ...string) []byte {
	t.Helper()
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.7\n")
	for _, content := range streams {
		var zbuf bytes.Buffer
		zw := zlib.NewWriter(&zbuf)
		_, _ = zw.Write([]byte(content))
		_ = zw.Close()
		pdf.WriteString("1 0 obj << /Filter /FlateDecode >>\nstream\n")
		pdf.Write(zbuf.Bytes())
		pdf.WriteString("\nendstream\nendobj\n")
	}
	pdf.WriteString("%%EOF")
	return pdf.Bytes()
}

func TestSanitizedPopplerEnv(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("SYSTEMROOT", `C:\Windows`)
	t.Setenv("WINDIR", `C:\Windows`)

	env := sanitizedPopplerEnv()
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH=/usr/local/bin:/usr/bin:/bin") {
		t.Fatalf("expected default fallback PATH, got: %v", env)
	}
	if !strings.Contains(joined, "LANG=C.UTF-8") {
		t.Fatalf("expected LANG=C.UTF-8, got: %v", env)
	}
	if !strings.Contains(joined, `SYSTEMROOT=C:\Windows`) || !strings.Contains(joined, `WINDIR=C:\Windows`) {
		t.Fatalf("expected Windows env keys preserved, got: %v", env)
	}
}

func TestHasPDFToTextAndPopplerSubprocess(t *testing.T) {
	emptyBinDir := t.TempDir()
	t.Setenv("PATH", emptyBinDir)
	if HasPDFToText() {
		t.Fatal("expected HasPDFToText() == false with empty PATH")
	}

	fakeDir := t.TempDir()
	t.Setenv("PATH", fakeDir)

	// 1. Happy path script
	writeExecutableScript(t, fakeDir, "pdftotext", "#!/bin/sh\nprintf '  Hello PDF  \\r\\n\\r\\n\\r\\nWorld  '\n")
	if !HasPDFToText() {
		t.Fatal("expected HasPDFToText() == true when pdftotext is in PATH")
	}

	pdfBytes := buildMinimalFlatePDF(t, "BT (Fallback Text) Tj ET")
	pdfFile := filepath.Join(t.TempDir(), "sample.pdf")
	if err := os.WriteFile(pdfFile, pdfBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	txt, usedPoppler, err := ExtractPDFFileText(context.Background(), pdfFile, 0)
	if err != nil || !usedPoppler || txt != "Hello PDF\n\nWorld" {
		t.Fatalf("ExtractPDFFileText happy = (%q, %v, %v)", txt, usedPoppler, err)
	}
	txt2, usedPoppler2, err2 := ExtractPDFText(context.Background(), pdfBytes, 999)
	if err2 != nil || !usedPoppler2 || txt2 != "Hello PDF\n\nWorld" {
		t.Fatalf("ExtractPDFText happy = (%q, %v, %v)", txt2, usedPoppler2, err2)
	}

	// 2. Empty/whitespace output from Poppler
	writeExecutableScript(t, fakeDir, "pdftotext", "#!/bin/sh\nprintf '   \\n\\n '\n")
	if _, used, err := ExtractPDFFileText(context.Background(), pdfFile, 999); err == nil || !used {
		t.Fatalf("expected scanned image PDF error with usedPoppler=true, got used=%v err=%v", used, err)
	}
	if txtEmpty, used, err := ExtractPDFText(context.Background(), pdfBytes, 0); err != nil || !used || txtEmpty != "" {
		t.Fatalf("ExtractPDFText empty poppler = (%q, %v, %v)", txtEmpty, used, err)
	}

	// 3. > 8 MiB stdout capping & process kill (`exec` ensures Kill() terminates the sole process holding stderr)
	writeExecutableScript(t, fakeDir, "pdftotext", "#!/bin/sh\nexec /usr/bin/tr '\\0' 'a' < /dev/zero\n")
	cappedFile, usedCapFile, errCapFile := ExtractPDFFileText(context.Background(), pdfFile, 10)
	if errCapFile != nil || !usedCapFile || len(cappedFile) != maxPDFTextOutputBytes {
		t.Fatalf("ExtractPDFFileText >8MiB cap = (len=%d, used=%v, err=%v)", len(cappedFile), usedCapFile, errCapFile)
	}
	cappedMem, usedCapMem, errCapMem := ExtractPDFText(context.Background(), pdfBytes, 10)
	if errCapMem != nil || !usedCapMem || len(cappedMem) != maxPDFTextOutputBytes {
		t.Fatalf("ExtractPDFText >8MiB cap = (len=%d, used=%v, err=%v)", len(cappedMem), usedCapMem, errCapMem)
	}

	// 4. Non-zero exit falls back to pure-Go
	writeExecutableScript(t, fakeDir, "pdftotext", "#!/bin/sh\nexit 1\n")
	fbFile, usedFBFile, errFBFile := ExtractPDFFileText(context.Background(), pdfFile, 10)
	if errFBFile != nil || usedFBFile || fbFile != "Fallback Text" {
		t.Fatalf("ExtractPDFFileText exit-1 fallback = (%q, %v, %v)", fbFile, usedFBFile, errFBFile)
	}
	fbMem, usedFBMem, errFBMem := ExtractPDFText(context.Background(), pdfBytes, 10)
	if errFBMem != nil || usedFBMem || fbMem != "Fallback Text" {
		t.Fatalf("ExtractPDFText exit-1 fallback = (%q, %v, %v)", fbMem, usedFBMem, errFBMem)
	}

	// 5. cmd.Start() failure via invalid shebang falls back cleanly
	writeExecutableScript(t, fakeDir, "pdftotext", "#!/nonexistent/edgefetch_interp\n")
	fbStartFile, usedStartFile, errStartFile := ExtractPDFFileText(context.Background(), pdfFile, 10)
	if errStartFile != nil || usedStartFile || fbStartFile != "Fallback Text" {
		t.Fatalf("ExtractPDFFileText start-err fallback = (%q, %v, %v)", fbStartFile, usedStartFile, errStartFile)
	}
	fbStartMem, usedStartMem, errStartMem := ExtractPDFText(context.Background(), pdfBytes, 10)
	if errStartMem != nil || usedStartMem || fbStartMem != "Fallback Text" {
		t.Fatalf("ExtractPDFText start-err fallback = (%q, %v, %v)", fbStartMem, usedStartMem, errStartMem)
	}
}

func TestPDFPureGoFallbacksAndEdgeCases(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	// Nonexistent file -> os.Open error
	if _, _, err := ExtractPDFFileText(context.Background(), filepath.Join(t.TempDir(), "missing.pdf"), 5); err == nil {
		t.Fatal("expected os.Open error on missing PDF path")
	}

	// Directory path -> io.ReadAll error (EISDIR on Linux)
	if _, _, err := ExtractPDFFileText(context.Background(), t.TempDir(), 5); err == nil {
		t.Fatal("expected ReadAll error on directory path")
	}

	// File with no text streams -> error
	noTextFile := filepath.Join(t.TempDir(), "empty.pdf")
	if err := os.WriteFile(noTextFile, []byte("%PDF-1.7\n%%EOF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ExtractPDFFileText(context.Background(), noTextFile, 5); err == nil {
		t.Fatal("expected error for PDF file with no text streams")
	}

	// Multi-stream PDF: non-text stream + escape sequences (\n \r \t \( \) \\) + non-printable bytes + maxPagesCap break
	multiPDF := buildMinimalFlatePDF(t,
		"q 1 0 0 1 0 0 cm Q", // no Tj/TJ runs
		"BT (Line1\\nLine2\\r\\t\\(\\)\\\\\x01\x80) Tj ET",
		"BT (Stream2) Tj ET",
		"BT (Stream3_ShouldStop) Tj ET",
	)
	multiFile := filepath.Join(t.TempDir(), "multi.pdf")
	if err := os.WriteFile(multiFile, multiPDF, 0o644); err != nil {
		t.Fatal(err)
	}
	gotFile, used, err := ExtractPDFFileText(context.Background(), multiFile, 1) // maxPagesCap(1) == 2 streams
	if err != nil || used || !strings.Contains(gotFile, "Line1\nLine2\r\t()\\") || !strings.Contains(gotFile, "Stream2") || strings.Contains(gotFile, "Stream3_ShouldStop") {
		t.Fatalf("unexpected multi-stream fallback: used=%v err=%v text=%q", used, err, gotFile)
	}

	// ExtractPDFText error paths & IsPDFBytes > 1024 window
	if _, _, err := ExtractPDFText(context.Background(), []byte("not-a-pdf"), 5); err == nil {
		t.Fatal("expected non-%PDF- error")
	}
	if IsPDFBytes(append(bytes.Repeat([]byte(" "), 1025), []byte("%PDF-1.7")...)) {
		t.Fatal("expected %PDF- past 1024-byte header window to return false")
	}
	if !IsPDFBytes(append([]byte("%PDF-1.7"), bytes.Repeat([]byte(" "), 1025)...)) {
		t.Fatal("expected %PDF- within 1024-byte header window to return true")
	}
	if _, _, err := ExtractPDFText(context.Background(), []byte("%PDF-1.7\n%%EOF"), 5); err == nil {
		t.Fatal("expected error for in-memory PDF with no text streams")
	}

	// Direct maxPagesCap(0) via extractPDFTextPureGo
	if got := extractPDFTextPureGo(multiPDF, 0); got != "" {
		// maxStreams=0 yields 0 matches because FindAllSubmatch(..., 0) returns nil; verify maxPagesCap(0)==60 directly too.
		t.Fatalf("expected empty output for maxStreams=0, got %q", got)
	}
	if maxPagesCap(0) != 60 || maxPagesCap(-3) != 60 || maxPagesCap(5) != 10 {
		t.Fatal("maxPagesCap boundary mismatch")
	}
}
