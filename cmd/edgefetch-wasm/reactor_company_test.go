package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func callCompanyOp(t *testing.T, op string, payload any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"op": op, "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	_ = efInPtr(uint32(len(raw)))
	copy(wasmInBuf, raw)
	n := efCall(uint32(len(raw)))
	var out map[string]any
	if err := json.Unmarshal(wasmOutBuf[:n], &out); err != nil {
		t.Fatalf("%s: bad json %q", op, string(wasmOutBuf[:n]))
	}
	return out
}

func TestCompanyWasmOpsRoundTrip(t *testing.T) {
	plan := callCompanyOp(t, "company_plan", map[string]any{"name": "Acme Widgets", "domain": "https://www.acmewidgets.com/"})
	reqs, _ := plan["requests"].([]any)
	if plan["domain"] != "acmewidgets.com" || len(reqs) != 4 {
		t.Fatalf("plan %+v", plan)
	}

	if bad := callCompanyOp(t, "company_plan", map[string]any{}); bad["error"] == nil {
		t.Fatalf("expected error for empty plan, got %+v", bad)
	}

	search := `{"search":[{"id":"Q900002","label":"Acme Widgets","description":"widget manufacturing company"}]}`
	fu := callCompanyOp(t, "company_followups", map[string]any{"wikidataSearchJson": search})
	if urls, _ := fu["wikidataEntityUrls"].([]any); len(urls) != 1 || urls[0] != "https://www.wikidata.org/wiki/Special:EntityData/Q900002.json" {
		t.Fatalf("followups %+v", fu)
	}

	entity := `{"entities":{"Q900002":{"id":"Q900002","labels":{"en":{"value":"Acme Widgets"}},"claims":{` +
		`"P856":[{"rank":"normal","mainsnak":{"snaktype":"value","datavalue":{"type":"string","value":"https://acmewidgets.com"}}}],` +
		`"P5531":[{"rank":"normal","mainsnak":{"snaktype":"value","datavalue":{"type":"string","value":"123456"}}}]}}}}`
	pick := callCompanyOp(t, "company_pick_wikidata", map[string]any{"wikidataSearchJson": search, "entityJsons": []string{entity}, "domain": "acmewidgets.com"})
	f, _ := pick["followups"].(map[string]any)
	if pick["qid"] != "Q900002" || pick["ok"] != true || f["cik"] != "0000123456" {
		t.Fatalf("pick %+v", pick)
	}

	sec := callCompanyOp(t, "company_sec_urls", map[string]any{"entityJson": entity, "qid": "Q900002"})
	if sec["secCompanyFactsUrl"] != "https://data.sec.gov/api/xbrl/companyfacts/CIK0000123456.json" {
		t.Fatalf("sec urls %+v", sec)
	}

	q := callCompanyOp(t, "company_places_query", map[string]any{"name": "Acme Widgets", "hqHint": "Springfield"})
	if q["query"] != "Acme Widgets headquarters Springfield" {
		t.Fatalf("places query %+v", q)
	}

	merged := callCompanyOp(t, "company_merge", map[string]any{
		"name": "Acme Widgets", "domain": "acmewidgets.com", "wikidataId": "Q900002", "wikidataEntityJson": entity,
		"ats": map[string]any{"openRoles": 3, "platform": "lever"},
	})
	md, _ := merged["markdown"].(string)
	if merged["name"] != "Acme Widgets" || merged["cik"] != "0000123456" || !strings.Contains(md, "3 open roles on lever") {
		t.Fatalf("merge %+v", merged)
	}
}
