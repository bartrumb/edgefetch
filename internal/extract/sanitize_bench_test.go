package extract

import (
	"strings"
	"testing"
)

var (
	benchSanitizeSinkStr string
	benchSanitizeSinkPI  PromptInjectionResult
)

func buildBenchmarkMarkdownDoc(targetBytes int) string {
	section := strings.Join([]string{
		"## EdgeFetch Section Heading",
		"",
		"Returns `Promise<Array<Record<string, unknown>>>` over HTTP/2 with [API Docs](https://docs.example.com/api)",
		"and neutralizes [hostile](javascript:alert(1)) plus <script>alert(1)</script> inline markup.",
		"",
		"- [x] Completed linear-time CommonMark fence recognizer",
		"- [ ] Pending downstream verification pass",
		"",
		"| Endpoint | Burst | Timeout |",
		"| :--- | ---: | :--- |",
		"| `/v1/scrape` | `60` | `30s` |",
		"| `/v1/extract` | `30` | `45s` |",
		"",
		"```ts",
		"export async function fetchTyped<T>(url: string): Promise<T> {",
		"  return (await fetch(url)).json() as Promise<T>;",
		"}",
		"```",
		"",
	}, "\n")

	var sb strings.Builder
	sb.Grow(targetBytes + len(section))
	for sb.Len() < targetBytes {
		sb.WriteString(section)
	}
	return sb.String()[:targetBytes]
}

func BenchmarkSanitizeScrapedMarkdown512k(b *testing.B) {
	doc := buildBenchmarkMarkdownDoc(512 * 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(doc)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSanitizeSinkStr = SanitizeScrapedMarkdown(doc)
	}
}

func BenchmarkSliceMarkdownByLines(b *testing.B) {
	doc := buildBenchmarkMarkdownDoc(256 * 1024)
	checkpoints := ComputeMarkdownSliceCheckpoints(doc, 16384)
	lineOffsets := make([]int, 0, 16)
	step := len(doc) / 8
	for off := 0; off < len(doc); off += step {
		if nl := strings.IndexByte(doc[off:], '\n'); nl >= 0 && off+nl+1 < len(doc) {
			lineOffsets = append(lineOffsets, off+nl+1)
		}
	}
	const windowBytes = 8192

	b.ReportAllocs()
	b.SetBytes(int64(len(lineOffsets) * windowBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, off := range lineOffsets {
			end := off + windowBytes
			if end > len(doc) {
				end = len(doc)
			}
			benchSanitizeSinkStr = SanitizeMarkdownPageSlice(doc, off, doc[off:end], false, checkpoints)
		}
	}
}

func BenchmarkPromptInjectionLinearScan(b *testing.B) {
	md := buildBenchmarkMarkdownDoc(256 * 1024)
	htmlChunk := `<article class="prose"><p>Technical documentation paragraph with <code>Vec&lt;u8&gt;</code> and &amp;nbsp; entities.</p>` +
		`<div style="color:#111827">Normal visible note about system architecture and developer configuration.</div></article>` + "\n"
	htmlDoc := "<!doctype html><html><head><style>.prose{line-height:1.6}</style></head><body>" +
		strings.Repeat(htmlChunk, (256*1024)/len(htmlChunk)) +
		"</body></html>"

	b.ReportAllocs()
	b.SetBytes(int64(len(md) + len(htmlDoc)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSanitizeSinkPI = DetectPromptInjection(md, htmlDoc)
	}
}
