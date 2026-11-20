package classify_test

import (
	"fmt"
	"net/http"

	"github.com/bartrumb/edgefetch/internal/classify"
)

func ExampleClassify() {
	htmlHdr := http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}
	okOut, _ := classify.Classify(classify.KindScrape, 200, htmlHdr, []byte("<main><h1>Docs</h1></main>"))

	chalHdr := http.Header{
		"Content-Type": []string{"text/html"},
		"Cf-Mitigated": []string{"challenge"},
	}
	chalOut, prob := classify.Classify(classify.KindScrape, 403, chalHdr, []byte("<html></html>"))

	fmt.Println("200 scrape:", okOut)
	fmt.Println("challenge:", chalOut, "| stopsHost:", classify.StopsHost(classify.KindScrape, chalOut), "|", prob)
	// Output:
	// 200 scrape: ok
	// challenge: challenge | stopsHost: true | Cloudflare challenge (cf-mitigated)
}
