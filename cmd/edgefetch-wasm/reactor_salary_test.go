package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func callSalaryEfCall(t *testing.T, req string) map[string]any {
	t.Helper()
	_ = efInPtr(uint32(len(req)))
	copy(wasmInBuf, req)
	n := efCall(uint32(len(req)))
	var out map[string]any
	if err := json.Unmarshal(wasmOutBuf[:n], &out); err != nil {
		t.Fatalf("decode %q: %v", string(wasmOutBuf[:n]), err)
	}
	if e, ok := out["error"]; ok {
		t.Fatalf("efCall error: %v", e)
	}
	return out
}

func TestSalaryWasmOpsRoundTrip(t *testing.T) {
	jobsReq := `{"op":"salary_observations","payload":{"seenAtMs":1700000000000,"jobs":[` +
		`{"title":"Sr. Software Engineer II, Backend (Remote)","company":"Acme, Inc.","url":"https://boards.example.com/acme/1","applyUrl":"","workplaceType":"onsite","locations":["New York, NY"],"pay":{"min":150000,"max":190000,"currency":"USD","period":"year","basis":"base"},"postedAt":"2023-11-01","source":"greenhouse"},` +
		`{"title":"Senior Software Engineer","company":"Acme","url":"https://boards.example.com/acme/2","applyUrl":"","workplaceType":"onsite","locations":["San Francisco, CA"],"pay":{"min":150000,"max":190000,"currency":"USD","period":"year","basis":"base"},"postedAt":null,"source":"greenhouse"},` +
		`{"title":"Senior Software Engineer","company":"Beta","url":"https://jobs.example.com/beta/9","applyUrl":"","workplaceType":"remote","locations":["Remote - US"],"pay":{"min":80,"max":100,"currency":"USD","period":"hour","basis":"base"},"postedAt":null,"source":"lever"},` +
		`{"title":"Senior Software Engineer","company":"Gamma","url":"https://jobs.example.com/gamma/1","applyUrl":"","workplaceType":"onsite","locations":["Austin, TX"],"pay":null,"postedAt":null,"source":"ashby"}` +
		`]}}`
	out := callSalaryEfCall(t, jobsReq)
	obsRaw, _ := json.Marshal(out["observations"])
	var obs []map[string]any
	if err := json.Unmarshal(obsRaw, &obs); err != nil || len(obs) != 3 || out["rejected"].(float64) != 1 {
		t.Fatalf("observations: %s rejected=%v", obsRaw, out["rejected"])
	}
	if obs[0]["titleFamily"] != "software engineer" || obs[0]["seniority"] != "senior" || obs[0]["locationBucket"] != "metro:new-york" || obs[2]["maxAnnual"].(float64) != 208000 {
		t.Fatalf("unexpected observation fields: %s", obsRaw)
	}

	mq := callSalaryEfCall(t, `{"op":"salary_match_query","payload":{"title":"senior swe salary","location":"Bay Area"}}`)
	if mq["titleFamily"] != "software engineer" || mq["seniority"] != "senior" || mq["locationBucket"] != "metro:san-francisco" {
		t.Fatalf("match query: %v", mq)
	}

	aggReq := `{"op":"salary_aggregate","payload":{"observations":` + string(obsRaw) +
		`,"query":{"titleFamily":"software engineer","seniority":"senior","locationBucket":"country:US","nowMs":1700000000000}}}`
	rep := callSalaryEfCall(t, aggReq)
	if rep["currency"] != "USD" || rep["basis"] != "base" || rep["matched"].(float64) != 2 || rep["postings"].(float64) != 3 {
		t.Fatalf("aggregate: matched=%v postings=%v basis=%v", rep["matched"], rep["postings"], rep["basis"])
	}
	mid := rep["midpoint"].(map[string]any)
	if mid["median"].(float64) != 178600 || !strings.Contains(rep["markdown"].(string), "| Midpoint |") {
		t.Fatalf("midpoint: %v", mid)
	}
	for _, k := range []string{"query", "currencies", "min", "max", "bySeniority", "byLocation", "topCompanies", "sample", "sources", "notes", "method"} {
		if _, ok := rep[k]; !ok {
			t.Errorf("missing report key %q", k)
		}
	}

	if _, handled, _ := handleSalaryRPC("not_a_salary_op", nil); handled {
		t.Fatal("unknown op must not be handled")
	}
}
