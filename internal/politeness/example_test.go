package politeness_test

import (
	"fmt"
	"net"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

func ExampleParseRobotsTxt() {
	robotsTxt := `
User-agent: *
Disallow: /admin/
Allow: /admin/public-status$
Crawl-delay: 2
`
	entry := politeness.ParseRobotsTxt(robotsTxt, "EdgeFetch/2.1", time.Now().Add(time.Hour))
	fmt.Println("public:", entry.Allowed("/docs/getting-started"))
	fmt.Println("admin:", entry.Allowed("/admin/users"))
	fmt.Println("longest-match allow:", entry.Allowed("/admin/public-status"))
	fmt.Println("crawl-delay:", entry.CrawlDelay)
	// Output:
	// public: true
	// admin: false
	// longest-match allow: true
	// crawl-delay: 2s
}

func ExampleIsPublicIP() {
	fmt.Println("cloudflare-dns:", politeness.IsPublicIP(net.ParseIP("1.1.1.1")))
	fmt.Println("loopback:", politeness.IsPublicIP(net.ParseIP("127.0.0.1")))
	fmt.Println("cgnat-tailscale:", politeness.IsPublicIP(net.ParseIP("100.100.100.100")))
	fmt.Println("ipv4-mapped-loopback:", politeness.IsPublicIP(net.ParseIP("::ffff:127.0.0.1")))
	// Output:
	// cloudflare-dns: true
	// loopback: false
	// cgnat-tailscale: false
	// ipv4-mapped-loopback: false
}
