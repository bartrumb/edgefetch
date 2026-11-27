package classify

import "testing"

func TestContentStateTemporarilyUnavailable(t *testing.T) {
	const url = "https://shop.example.com/"
	cases := []struct {
		name   string
		status int
		raw    string
		md     string
		title  string
		want   string
	}{
		{
			name:   "maintenance notice with retry",
			status: 200,
			md:     "# Down for maintenance\n\nOur site is currently undergoing scheduled maintenance. Please check back soon.",
			title:  "Maintenance",
			want:   "temporarily_unavailable",
		},
		{
			name:   "we're under maintenance, try again",
			status: 200,
			md:     "We're under maintenance right now. Please try again in a few minutes.",
			title:  "Example Store",
			want:   "temporarily_unavailable",
		},
		{
			name:   "be right back",
			status: 200,
			md:     "We'll be right back! Our team is upgrading things and we will be back online shortly.",
			title:  "Example",
			want:   "temporarily_unavailable",
		},
		{
			name:   "service temporarily unavailable",
			status: 200,
			md:     "The service is temporarily unavailable. Please try again later.",
			title:  "Service",
			want:   "temporarily_unavailable",
		},
		{
			name:   "non-2xx is not classified here",
			status: 503,
			md:     "Our site is currently undergoing scheduled maintenance. Please check back soon.",
			title:  "Maintenance",
			want:   "active",
		},
		{
			name:   "notice without retry phrase",
			status: 200,
			md:     "Our site is currently undergoing scheduled maintenance.",
			title:  "Maintenance",
			want:   "active",
		},
		{
			name:   "how-to maintenance article",
			status: 200,
			md: "# How to Do Basic Bike Maintenance\n\nRegular maintenance keeps your bike running smoothly. " +
				"Clean the chain, check the tire pressure, and inspect the brake pads every month. If the shifting " +
				"is still rough after adjusting the cable, try again with a quarter turn of the barrel adjuster, " +
				"and check back on the derailleur alignment after your next ride.",
			title: "How to Do Basic Bike Maintenance",
			want:  "active",
		},
		{
			name:   "bridge down for maintenance news",
			status: 200,
			md: "# Main Street bridge closed\n\nThe Main Street bridge is down for maintenance this week. Drivers " +
				"should use the detour, and city officials said residents can check back for updates as crews work.",
			title: "Main Street bridge closed for repairs - City News",
			want:  "active",
		},
		{
			name:   "maintenance technician job post",
			status: 200,
			md: "# Maintenance Technician\n\nWe are hiring a maintenance technician to perform scheduled maintenance " +
				"on production equipment. Our plant is currently undergoing an expansion. Apply today, or check back " +
				"soon for more openings.",
			title: "Maintenance Technician - Careers",
			want:  "active",
		},
		{
			name:   "maintenance technician job post with JobPosting JSON-LD",
			status: 200,
			raw: `<html><head><script type="application/ld+json">{"@type":"JobPosting","title":"Maintenance Technician"}</script></head>` +
				`<body><p>We are under maintenance staffing review. Check back soon.</p></body></html>`,
			md:    "We are under maintenance staffing review. Check back soon.",
			title: "Maintenance Technician",
			want:  "active",
		},
		{
			name:   "future-tense notice",
			status: 200,
			md: "Heads up: the site will undergo scheduled maintenance on Saturday from 2am to 4am. " +
				"If you see errors during that window, please try again later.",
			title: "Example Store",
			want:  "active",
		},
		{
			name:   "article JSON-LD vetoes",
			status: 200,
			raw: `<html><head><script type="application/ld+json">{"@type":"NewsArticle","headline":"Outage"}</script></head>` +
				`<body><p>The site is down for maintenance. Check back soon.</p></body></html>`,
			md:    "The site is down for maintenance. Check back soon.",
			title: "Outage report",
			want:  "active",
		},
		{
			name:   "product JSON-LD vetoes out-of-stock wording",
			status: 200,
			raw: `<html><head><script type="application/ld+json">{"@type":"Product","name":"Widget"}</script></head>` +
				`<body><p>This store is temporarily unavailable for this item. Check back soon.</p></body></html>`,
			md:    "This store is temporarily unavailable for this item. Check back soon.",
			title: "Widget",
			want:  "active",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyContentState(tc.status, tc.raw, tc.md, url, tc.title)
			if got.State != tc.want {
				t.Fatalf("state = %q (%s), want %q", got.State, got.Reason, tc.want)
			}
		})
	}

	// Long pages (>= 250 words) never classify as maintenance even with the notice present.
	long := "Our site is currently undergoing scheduled maintenance. Please check back soon. "
	for i := 0; i < 30; i++ {
		long += "Additional paragraph text describing the catalog in detail for shoppers. "
	}
	if got := ClassifyContentState(200, "", long, url, "Store"); got.State != "active" {
		t.Fatalf("long page: state = %q, want active", got.State)
	}
}
