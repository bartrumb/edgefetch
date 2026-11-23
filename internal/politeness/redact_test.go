package politeness

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
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

func TestR9RedactEmbeddedURLs90DiverseLeakVectorsAndLinear1MiB(t *testing.T) {
	const canary = "CANARY_R9_987654"
	urlErr := func(op, raw string) string {
		return (&url.Error{Op: op, URL: raw, Err: errors.New("connection refused")}).Error()
	}

	vectors := []struct {
		name string
		in   string
	}{
		// 1-12: Standard schemes + IPv6 [::1] / [2001:db8::1] + query/fragment/userinfo/secret path
		{"01_http_ipv6_query_frag", "http://[::1]:8080/api?tok=" + canary + "#frag=" + canary},
		{"02_https_ipv6_secret_path", "https://[::1]:8443/secret/" + canary + "?x=1"},
		{"03_ws_ipv6_userinfo_query", "ws://admin:" + canary + "@[::1]:9222/devtools/page?token=" + canary},
		{"04_wss_ipv6_full", "wss://[2001:db8::abcd]:443/agent/ws#auth=" + canary},
		{"05_ftp_ipv6_userinfo", "ftp://ftpuser:" + canary + "@[fe80::1%25eth0]:2121/pub?pass=" + canary},
		{"06_ftps_ipv6_query", "ftps://[::ffff:127.0.0.1]:990/files?sig=" + canary},
		{"07_file_triple_slash_path", "file:///Users/" + canary + "/.ssh/id_ed25519?tok=" + canary},
		{"08_file_localhost_path", "file://localhost/etc/" + canary + "/credentials.json#" + canary},
		{"09_file_ipv6_host_path", "file://[::1]/var/run/" + canary + ".sock"},
		{"10_file_userinfo_host_path", "file://root:" + canary + "@fileserver.local/share/" + canary},
		{"11_sftp_ssh_userinfo", "sftp://deploy:" + canary + "@bastion.example.com:22/srv?k=" + canary + " ssh://git:" + canary + "@git.example.com/repo"},
		{"12_s3_gs_cloud_urls", "s3://ak:" + canary + "@bucket.s3.amazonaws.com/obj?X-Amz-Signature=" + canary + " gs://u:" + canary + "@bkt/k?sig=" + canary},

		// 13-24: DB / Queue / Proxy schemes
		{"13_postgres_dsn", "postgres://dbadmin:" + canary + "@db.internal.corp:5432/prod?sslmode=require&password=" + canary},
		{"14_postgresql_ipv6", "postgresql://u:" + canary + "@[fd00::5]:5432/app?options=" + canary},
		{"15_redis_rediss", "redis://:" + canary + "@cache.internal:6379/0?auth=" + canary + " rediss://default:" + canary + "@upstash.example.com:6380"},
		{"16_mongodb_srv", "mongodb+srv://svc:" + canary + "@cluster0.example.mongodb.net/mydb?retryWrites=true&authSource=" + canary},
		{"17_mongodb_plain", "mongodb://admin:" + canary + "@10.0.0.5:27017/admin?replicaSet=" + canary},
		{"18_mysql_amqp_amqps", "mysql://root:" + canary + "@db.local:3306/app amqps://guest:" + canary + "@mq.example.com:5671/vhost?tok=" + canary},
		{"19_socks5_socks5h", "socks5://proxyuser:" + canary + "@127.0.0.1:1080 socks5h://u:" + canary + "@[::1]:1080/p?k=" + canary},
		{"20_ldap_ldaps_nats", "ldaps://cn=admin:" + canary + "@ldap.example.org:636/dc=x?bindpw=" + canary + " nats://tok:" + canary + "@nats.local:4222"},
		{"21_mailto_query_frag", "mailto:security@example.com?subject=" + canary + "&body=" + canary + "#" + canary},
		{"22_blob_https_quoted", fmt.Sprintf(`Get "blob:https://app.example.com/uuid?tok=%s#%s": net/http: timeout`, canary, canary)},
		{"23_blob_http_ipv6_unquoted", "blob:http://[::1]:8080/id-1?key=" + canary + " failed"},
		{"24_upper_mixed_schemes", "HTTPS://u:" + canary + "@Example.COM/p?k=" + canary + " WSS://[::1]:8080/ws?t=" + canary + " FILE:///tmp/" + canary},

		// 25-40: Bare host:port/secret, [::1]:port/secret, localhost:port/secret, bare domain?query#frag
		{"25_bare_host_port_secret_seg", "dial error on internal.corp:8443/" + canary},
		{"26_bare_host_port_deep_path", "upstream api.backend.io:9443/v1/private/" + canary + "/dump failed"},
		{"27_bare_host_port_query_frag", "GET service.example.net:8080/items?api_key=" + canary + "#tok=" + canary},
		{"28_bare_ipv6_port_secret", "connect [::1]:8080/" + canary + "?tok=" + canary + " refused"},
		{"29_bare_ipv6_ula_port_path", "proxy [fd12:3456::1]:3128/proxy-tok/" + canary + " -> [fd12:3456::1]:3128/" + canary},
		{"30_bare_ipv4_port_secret", "http peer 192.168.1.50:8080/admin/" + canary + "?session=" + canary},
		{"31_bare_localhost_port_secret", "target localhost:3000/callback?code=" + canary + "#state=" + canary},
		{"32_bare_localhost_port_path_only", "target localhost:8787/" + canary + " unreachable"},
		{"33_bare_host_port_query_no_slash", "endpoint api.example.com:8443?api_key=" + canary},
		{"34_bare_host_port_frag_no_slash", "endpoint api.example.com:8443#access_token=" + canary},
		{"35_bare_host_port_matrix", "endpoint api.example.com:8443;jsessionid=" + canary},
		{"36_bare_domain_no_port_query", "request to api.example.com/v1/search?key=" + canary + " timed out"},
		{"37_bare_domain_no_port_frag", "navigated to app.example.org/login#id_token=" + canary},
		{"38_bare_domain_no_port_reset", "visit auth.example.org/reset/" + canary + " to continue"},
		{"39_bare_domain_no_port_secret_seg", "leaked via cdn.example.com/secret/" + canary},
		{"40_bare_idn_punycode_port", "connect shop.xn--fiqs8s:8443/" + canary + "?k=" + canary},

		// 41-54: Schemeless user:pass@host forms
		{"41_schemeless_user_pass_path", "auth user:" + canary + "@api.example.com/v1/items"},
		{"42_schemeless_user_pass_port_path", "auth admin:" + canary + "@db.example.com:5432/prod?ssl=1"},
		{"43_schemeless_user_pass_ipv6", "auth root:" + canary + "@[::1]:8080/admin?k=" + canary},
		{"44_schemeless_pct_colon_userinfo", "auth user%3A" + canary + "@api.example.com/v1/data"},
		{"45_schemeless_pct_at_userinfo", "https://user:" + canary + "%40api.example.com/v1/data"},
		{"46_schemeless_quoted_userinfo", fmt.Sprintf(`dial "%s:%s@internal.example.org:8443/p?q=%s": EOF`, "svc", canary, canary)},
		{"47_schemeless_paren_userinfo", "(user:" + canary + "@host.example.com/path?tok=" + canary + ")"},
		{"48_schemeless_user_only_query", "alice@host.example.com/profile?session=" + canary + "#frag=" + canary},
		{"49_schemeless_user_only_verify", "alice@host.example.com/verify/" + canary},
		{"50_at_in_password_https", "https://user:p@" + canary + "@host.example.com/p"},
		{"51_slash_in_password_https", "https://user:p/" + canary + "@host.example.com/p"},
		{"52_qmark_in_password_https", "https://user:p?" + canary + "@host.example.com/p"},
		{"53_hash_in_password_https", "https://user:p#" + canary + "@host.example.com/p"},
		{"54_colon_in_password_https", "https://user:a:b:" + canary + "@host.example.com/p"},

		// 55-68: Protocol-relative //host.tld/... forms
		{"55_protorel_plain_query", "//cdn.example.com/assets/app.js?token=" + canary},
		{"56_protorel_secret_seg", "//host.tld/secret/" + canary + "?x=" + canary},
		{"57_protorel_secret_leaf", "//host.tld/secret?x=" + canary + "#" + canary},
		{"58_protorel_userinfo", "//user:" + canary + "@host.tld:8443/p?k=" + canary},
		{"59_protorel_ipv6", "//[::1]:8080/p?tok=" + canary + "#frag=" + canary},
		{"60_protorel_double_quoted", `Location: "//host.tld/cb?code=` + canary + `"`},
		{"61_protorel_single_quoted", `Location: '//host.tld/cb?code=` + canary + `'`},
		{"62_protorel_parens", `redirect (//host.tld/cb?code=` + canary + `) blocked`},
		{"63_protorel_brackets_braces", `[//host.tld/p?k=` + canary + `] {//host.tld/q?k=` + canary + `}`},
		{"64_protorel_pct22_quoted", `error=%22//host.tld/p?tok=` + canary + `%22: failed`},
		{"65_protorel_strconv_quote", strconv.Quote(`redirect "//host.tld/p?tok=` + canary + `": blocked`)},
		{"66_protorel_semicolon_pipe", `; //host.tld/p?k=` + canary + ` |//host.tld/q#f=` + canary},
		{"67_protorel_localhost", `//localhost:8080/api?secret=` + canary},
		{"68_protorel_matrix_reset", `//auth.example.com/items;sid=` + canary + `/magic/` + canary},

		// 69-82: URL-encoded %22 / %27 / %3A%2F%2F / strconv.Quote \" / Go url.Error wrappers
		{"69_pct22_https_query", "Get %22https://api.example.com/v1?api_key=" + canary + "%22: EOF"},
		{"70_pct22_userinfo_frag", "target=%22https://u:" + canary + "@api.example.com/v1#" + canary + "%22, status=502"},
		{"71_pct27_single_quote_url", "target=%27wss://[::1]:8080/ws?tok=" + canary + "%27"},
		{"72_pct_encoded_full_url", "redirect=https%3A%2F%2Fu%3A" + canary + "%40api.example.com%2Fp%3Fkey%3D" + canary + "%23" + canary},
		{"73_pct3f_pct23_on_plain_scheme", "https://api.example.com/v1/items%3Fapi_key=" + canary + "%23frag=" + canary},
		{"74_json_escaped_slashes_u003f", `{"err":"https:\/\/u:` + canary + `@api.example.com\/v1\u003ftok=` + canary + `\u0023` + canary + `"}`},
		{"75_strconv_quote_level1", strconv.Quote(urlErr("Get", "https://u:"+canary+"@api.example.com/p?k="+canary+"#"+canary))},
		{"76_strconv_quote_level2", strconv.Quote(strconv.Quote(urlErr("Post", "https://api.example.com/p?q=a\"b&tok="+canary)))},
		{"77_strconv_quote_level3", strconv.Quote(strconv.Quote(strconv.Quote(urlErr("Get", "https://[::1]:8080/p?k="+canary))))},
		{"78_even_backslash_before_quote", `prefix\\"https://api.example.com/p?tok=` + canary + `": trailing text preserved`},
		{"79_url_error_ipv6_control_char", (&url.Error{Op: "parse", URL: "https://[::1]:8080/p?tok=" + canary + "\x00", Err: errors.New("invalid control char")}).Error()},
		{"80_url_error_wrapped_fmt", fmt.Errorf("scrape failed: %w", &url.Error{Op: "Head", URL: "https://u:" + canary + "@example.com/reset/" + canary + "?sig=" + canary, Err: errors.New("EOF")}).Error()},
		{"81_sensitive_path_actions", "https://example.com/invite/" + canary + " https://example.com/activate/" + canary + " https://example.com/unsubscribe/" + canary + " https://example.com/webhook/" + canary + " https://example.com/apikey/" + canary},
		{"82_inline_auth_headers_and_kv", "Authorization: Bearer " + canary + ", Proxy-Authorization: Basic " + canary + ", api_key=" + canary + ", apikey:" + canary + ", token=" + canary},

		// 83-88: Multi-URL combinations, trailing punctuation, brackets/angles
		{"83_angle_bracket_url", "<https://u:" + canary + "@api.example.com/v1?tok=" + canary + "#frag>"},
		{"84_markdown_link_in_err", "see [docs](https://api.example.com/v1?api_key=" + canary + "#sec=" + canary + "): 403"},
		{"85_comma_semicolon_separated", "tried https://a.example/p?k=" + canary + ", https://b.example/q#" + canary + "; host.tld:8443/" + canary + "."},
		{"86_unquoted_space_in_query", "Get https://api.example.com/p?filter=a b&secret=" + canary + " failed"},
		{"87_unicode_ls_ps_nel_terminators", "https://api.example.com/p?k=" + canary + "\u2028next https://b.example/p?k=" + canary + "\u0085end"},
		{"88_dns_resolver_plus_url_combo", `Get "https://u:` + canary + `@missing.example:8443/secret?k=` + canary + `": lookup missing.example on 10.0.0.53:53: no such host`},
	}

	if len(vectors) < 85 {
		t.Fatalf("expected >= 85 leak test vectors, got %d", len(vectors))
	}
	for _, tc := range vectors {
		got := RedactEmbeddedURLs(tc.in)
		if strings.Contains(got, canary) || strings.Contains(got, "10.0.0.53") {
			t.Fatalf("SECURITY LEAK [%s]:\n  in : %s\n  out: %s", tc.name, tc.in, got)
		}
	}

	// Verify even-backslash quote handling preserves trailing text after closing quote
	gotEvenBS := RedactEmbeddedURLs(`prefix\\"https://api.example.com/p?tok=` + canary + `": trailing text preserved`)
	if !strings.Contains(gotEvenBS, "trailing text preserved") {
		t.Fatalf("expected trailing text preserved after \\\\\", got %q", gotEvenBS)
	}

	// Verify 1 MiB linear < 15ms budget (scaled by testRaceSlowdown under -race) on slash/colon-heavy non-URL prose too!
	prose1MiB := strings.Repeat("normal log line: worker=ok ratio=3/4 status=200\n", (1<<20)/48)
	_ = RedactEmbeddedURLs(prose1MiB[:4096])
	budget := time.Duration(testRaceSlowdown) * 15 * time.Millisecond
	t0 := time.Now()
	gotProse := RedactEmbeddedURLs(prose1MiB)
	elapsed := time.Since(t0)
	if gotProse != prose1MiB {
		t.Fatalf("expected non-URL colon/slash log prose preserved unchanged (got len=%d want len=%d)", len(gotProse), len(prose1MiB))
	}
	if elapsed > budget {
		t.Fatalf("PERF REGRESSION (colon_slash_prose_1MiB): took %v (budget %v)", elapsed, budget)
	}
}
