package extract

import (
	"bytes"
	"compress/zlib"
	"testing"
)

func FuzzExtractPDFPureGo(f *testing.F) {
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write([]byte("BT /F1 12 Tf 72 720 Td (Hello EdgeFetch Security Audit) Tj ET"))
	_ = zw.Close()

	minimalStreamPDF := append([]byte("%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n"), zbuf.Bytes()...)
	minimalStreamPDF = append(minimalStreamPDF, []byte("\nendstream\nendobj\n%%EOF")...)

	f.Add(minimalStreamPDF, 5)
	f.Add([]byte("%PDF-1.4\n1 0 obj\n<<>>\nstream\nBT [(EdgeFetch) -120 (PDF) 0 (Reader)] TJ ET\nendstream\n%%EOF"), 10)
	f.Add([]byte("%PDF-1.7\ncorrupted\x00stream\nendstream\n"), 2)

	f.Fuzz(func(t *testing.T, raw []byte, maxPages int) {
		if len(raw) > 64<<10 {
			return
		}
		if maxPages < 0 || maxPages > 50 {
			maxPages = 5
		}
		out := extractPDFTextPureGo(raw, maxPages)
		if len(out) > maxPDFTextOutputBytes {
			t.Fatalf("extractPDFTextPureGo exceeded maxPDFTextOutputBytes: %d", len(out))
		}
	})
}
