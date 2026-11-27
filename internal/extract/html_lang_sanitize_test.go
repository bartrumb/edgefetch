package extract

import "testing"

func TestHTMLLangRejectsRouteParamLeak(t *testing.T) {
	body := `<body><main><h1>Title</h1><p>Some real paragraph text for the page body content.</p></main></body></html>`
	cases := []struct {
		lang string
		want string
	}{
		{"{lang}", ""},
		{"[locale]", ""},
		{"{{ locale }}", ""},
		{"<%= locale %>", ""},
		{"${lang}", ""},
		{":lang", ""},
		{"en-", ""},
		{"e", ""},
		{"english-language-version-of-the-site-x", ""},
		{"en", "en"},
		{" en-US ", "en-US"},
		{"zh-Hant-TW", "zh-Hant-TW"},
		{"es-419", "es-419"},
		{"fil", "fil"},
	}
	for _, tc := range cases {
		doc := ExtractHTMLDocumentFull(`<!doctype html><html lang="`+tc.lang+`"><head><title>T</title></head>`+body, FullExtractOptions{BaseURL: "https://example.com/"})
		if doc.Language != tc.want {
			t.Errorf("lang %q: got Language %q, want %q", tc.lang, doc.Language, tc.want)
		}
		if got := sanitizeHTMLLangAttrFullDocGo(tc.lang); got != tc.want {
			t.Errorf("sanitizeHTMLLangAttrFullDocGo(%q) = %q, want %q", tc.lang, got, tc.want)
		}
	}
}
