package politeness

import (
	"strings"
	"testing"
	"time"
)

func TestR8RedactEmbeddedURLsLinear1MiBUnder15ms(t *testing.T) {
	inputs := []struct {
		name      string
		payload   string
		wantExact string
	}{
		{
			name:      "query_pairs_1MiB",
			payload:   strings.Repeat("?a=1&b=2", 131_072),
			wantExact: strings.Repeat("?a=1&b=2", 131_072),
		},
		{
			name:      "bang_a_1MiB",
			payload:   strings.Repeat("!a", 500_000),
			wantExact: strings.Repeat("!a", 500_000),
		},
		{
			name:      "bang_a_1MiB_at_invalid_host",
			payload:   strings.Repeat("!a", 500_000) + "@not_a_host",
			wantExact: strings.Repeat("!a", 500_000) + "@not_a_host",
		},
		{
			name:      "bang_a_1MiB_at_valid_host_no_colon",
			payload:   strings.Repeat("!a", 500_000) + "@example.com",
			wantExact: strings.Repeat("!a", 500_000) + "@example.com",
		},
		{
			name:      "https_url_1MiB_query",
			payload:   "https://example.com/?" + strings.Repeat("a=1&", 250_000),
			wantExact: "https://example.com/",
		},
	}

	// Warm up CPU cache once before timing assertions.
	_ = RedactEmbeddedURLs("?a=1&b=2")

	// Enforce < 15ms uninstrumented; scale strictly by testRaceSlowdown when -race shadow memory is active.
	budget := time.Duration(testRaceSlowdown) * 15 * time.Millisecond

	for _, tc := range inputs {
		start := time.Now()
		got := RedactEmbeddedURLs(tc.payload)
		elapsed := time.Since(start)
		if got != tc.wantExact {
			t.Fatalf("%s: unexpected output len=%d (want len=%d)", tc.name, len(got), len(tc.wantExact))
		}
		if elapsed > budget {
			t.Fatalf("PERF REGRESSION (%s): RedactEmbeddedURLs on %d bytes took %v (budget %v)", tc.name, len(tc.payload), elapsed, budget)
		}
	}
}

func TestR8RedactEmbeddedURLsSchemelessUserinfoParity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			in:   "redirected to user:s3cr3t@internal.example.com/admin?tok=123#frag!",
			want: "redirected to internal.example.com/admin",
		},
		{
			in:   "encoded user%3As3cr3t@api.example.com/v1/items?key=xyz",
			want: "encoded api.example.com/v1/items",
		},
		{
			in:   "contact alice@example.com for details",
			want: "contact alice@example.com for details",
		},
		{
			in:   "link alice@example.com/reset/99887766?sig=secret",
			want: "link alice@example.com/reset/[REDACTED]",
		},
		{
			in:   `prefix !admin: hunter2@example.com and "bob:pw123@db.example.org/p?x=1" done`,
			want: `prefix !admin: hunter2@example.com and "db.example.org/p" done`,
		},
		{
			in:   "space-delimited !bob:pw123@db.example.org/p?x=1 done",
			want: "space-delimited db.example.org/p done",
		},
	}
	for _, tc := range cases {
		if got := RedactEmbeddedURLs(tc.in); got != tc.want {
			t.Fatalf("RedactEmbeddedURLs(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
		}
	}
}

func BenchmarkRedactEmbeddedURLsLinear1MiB(b *testing.B) {
	payload := strings.Repeat("?a=1&b=2", 131_072)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RedactEmbeddedURLs(payload)
	}
}
