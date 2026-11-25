package jobs

import (
	"strings"
	"testing"
)

var (
	benchJobsSinkMatch bool
	benchJobsSinkPay   *NormalizedPay
)

func BenchmarkMatchesAllowedCompanyOrDomain(b *testing.B) {
	bigCompany := strings.Repeat("A", 262_144)
	records := []StructuredJobRecord{
		{
			Title:         "Staff Distributed Systems Engineer",
			Company:       bigCompany,
			URL:           "https://stripe.com/jobs/1",
			ApplyURL:      "https://stripe.com/jobs/1",
			WorkplaceType: WorkplaceRemote,
			Locations:     []string{"Remote"},
			Source:        "ats",
		},
		{
			Title:         "Principal Go Engineer",
			Company:       "Stripe, Inc.",
			URL:           "https://boards.greenhouse.io/stripe/jobs/101",
			ApplyURL:      "https://boards.greenhouse.io/stripe/jobs/101",
			WorkplaceType: WorkplaceRemote,
			Locations:     []string{"Remote"},
			Source:        "ats",
		},
		{
			Title:         "Impostor Role",
			Company:       "Stripe",
			URL:           "https://boards.greenhouse.io/stripe-careers-portal/jobs/1",
			ApplyURL:      "https://boards.greenhouse.io/stripe-careers-portal/jobs/1",
			WorkplaceType: WorkplaceRemote,
			Locations:     []string{"Remote"},
			Source:        "ats",
		},
	}
	tokens := []string{"stripe"}
	prefixes := []string{"https://boards.greenhouse.io/stripe"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, rec := range records {
			benchJobsSinkMatch = MatchesAllowedCompanyOrDomain(rec, tokens, prefixes)
		}
	}
}

func BenchmarkParsePayFromTextLinear(b *testing.B) {
	paragraph := strings.Join([]string{
		"Join a global engineering organization of 10,000 - 50,000 employees building distributed storage on release v1.20 - v2.4.",
		"Offices located in ZIP CODE: 94105 - 94107 with 99.95 - 99.99% availability targets across 12 - 24 regions.",
		"We raised $150,000 - $250,000 in angel funding early on and now process 50,000 - 120,000 requests per second.",
	}, "\n") + "\n"
	prose := strings.Repeat(paragraph, 180) + "Annual base salary range for this position is $185,000 - $245,000 USD per year plus equity.\n"

	b.ReportAllocs()
	b.SetBytes(int64(len(prose)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchJobsSinkPay = ParsePayFromText(prose)
	}
}
