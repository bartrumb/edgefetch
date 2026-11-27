package extract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func rscPushHTMLForTest(t *testing.T, payloads ...string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><title>DU-EP801 Spec</title></head><body><div id="__next"></div>`)
	for _, p := range payloads {
		enc, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		sb.WriteString(`<script>self.__next_f.push([1,`)
		sb.Write(enc)
		sb.WriteString(`])</script>`)
	}
	sb.WriteString(`</body></html>`)
	return sb.String()
}

func flightTextRowForTest(id, body string) string {
	return fmt.Sprintf("%s:T%x,%s", id, len(body), body)
}

const shimanoProseForTest = "The drive unit delivers smooth assistance on steep climbs and long touring days, " +
	"with a café-tuned cadence sensor that reacts quickly to every pedal stroke while keeping " +
	"noise low and battery consumption predictable across varied terrain and weather conditions."

func TestScanFlightTextRowNoTrailingNewline(t *testing.T) {
	s := flightTextRowForTest("a", "héllo wörld") + `b:{"x":1}` + "\n"
	id, body, next, ok := scanFlightTextRowHydrateGo(s, 0)
	if !ok || id != "a" || body != "héllo wörld" {
		t.Fatalf("framed T row: ok=%v id=%q body=%q", ok, id, body)
	}
	if !strings.HasPrefix(s[next:], `b:{"x":1}`) {
		t.Fatalf("expected next row to start at %d, got %q", next, s[next:])
	}

	// Length that does not land on a row boundary must be rejected (fallback path).
	bad := "a:T3,hello world\n"
	if _, _, _, okBad := scanFlightTextRowHydrateGo(bad, 0); okBad {
		t.Fatalf("expected misframed T row to be rejected")
	}
	// Non-T rows are not text rows.
	if _, _, _, okJSON := scanFlightTextRowHydrateGo(`5:["$","div",null,{}]`, 0); okJSON {
		t.Fatalf("expected JSON row to be rejected by T scanner")
	}
	// Framed end at EOF and at a newline are boundaries.
	if _, body2, _, ok2 := scanFlightTextRowHydrateGo("\n  1f:T5,abcde", 0); !ok2 || body2 != "abcde" {
		t.Fatalf("expected EOF boundary acceptance, got ok=%v body=%q", ok2, body2)
	}
}

func TestShimanoRSCTextRowWithoutNewlineDoesNotSwallowNextRows(t *testing.T) {
	specRow := `2:{"__typename":"TableSpecContents","categoryName":"Drive Unit","models":[{"modelName":"DU-EP801","modelValueSet":["85 Nm","600 W"]}],"attributes":[{"attributeId":"t","attributeKey1":"Maximum torque"},{"attributeId":"p","attributeKey1":"Peak power","attributeKey2":"Rated"}]}` + "\n"
	payload := flightTextRowForTest("1", shimanoProseForTest) + specRow + `3:["$","p",null,{"children":"$1"}]` + "\n"
	hyd := ExtractNextRSCFlight(rscPushHTMLForTest(t, payload), "https://productinfo.shimano.com/en/product/DU-EP801", nil)
	if hyd == nil {
		t.Fatalf("expected RSC hydration result")
	}
	if !strings.Contains(hyd.Markdown, "café-tuned cadence sensor") {
		t.Fatalf("expected T row prose in markdown, got:\n%s", hyd.Markdown)
	}
	if strings.Contains(hyd.Markdown, "__typename") || strings.Contains(hyd.Markdown, `2:{`) {
		t.Fatalf("T row swallowed the following row into prose:\n%s", hyd.Markdown)
	}
	for _, want := range []string{"| Specification | DU-EP801 |", "| Maximum torque | 85 Nm |", "| Peak power / Rated | 600 W |"} {
		if !strings.Contains(hyd.Markdown, want) {
			t.Fatalf("expected %q in markdown, got:\n%s", want, hyd.Markdown)
		}
	}
	if len(hyd.Records) != 2 {
		t.Fatalf("expected 2 spec records, got %+v", hyd.Records)
	}
	r0 := hyd.Records[0]
	if r0["category"] != "Drive Unit" || r0["name"] != "Maximum torque" || r0["model"] != "DU-EP801" || r0["value"] != "85 Nm" {
		t.Fatalf("unexpected first record %+v", r0)
	}
}

func TestShimanoTypenameSpecTableValueSetShapes(t *testing.T) {
	// Model A: `$19` -> array of objects keyed by attributeId (out of order, via nested ref).
	// Model B: `$1a` -> map keyed by attributeId. Model C: inline index-aligned scalars.
	rows := strings.Join([]string{
		`19:[{"attributeId":"w","value":"2.7 kg"},{"attributeId":"t","value":"$1b"}]`,
		`1a:{"t":"60 Nm","w":"2.6 kg"}`,
		`1b:"85 Nm"`,
		`20:{"__typename":"TableSpecContents","models":[{"modelName":"EP801","modelValueSet":"$19"},{"modelName":"EP600","modelValueSet":"$1a"},{"modelName":"E5100","modelValueSet":["40 Nm","<b>3.0</b> kg"]}],"attributes":[{"attributeId":"t","attributeKey1":"Drive unit","attributeKey2":"Torque"},{"attributeId":"w","attributeKey1":"Drive unit","attributeKey2":"Weight","attributeKey3":""}]}`,
		`21:["$","section",null,{"spec":"$20"}]`,
	}, "\n") + "\n"
	hyd := ExtractNextRSCFlight(rscPushHTMLForTest(t, payload0ForTest(), rows), "https://productinfo.shimano.com/en/product/DU-EP801", nil)
	if hyd == nil {
		t.Fatalf("expected RSC hydration result")
	}
	for _, want := range []string{
		"| Specification | EP801 | EP600 | E5100 |",
		"| Drive unit / Torque | 85 Nm | 60 Nm | 40 Nm |",
		"| Drive unit / Weight | 2.7 kg | 2.6 kg | 3.0 kg |",
	} {
		if !strings.Contains(hyd.Markdown, want) {
			t.Fatalf("expected %q in markdown, got:\n%s", want, hyd.Markdown)
		}
	}
	if strings.Contains(hyd.Markdown, "<b>") || strings.Contains(hyd.Markdown, "$19") {
		t.Fatalf("expected sanitized, fully resolved cells, got:\n%s", hyd.Markdown)
	}
	if strings.Count(hyd.Markdown, "| Specification |") != 1 {
		t.Fatalf("expected the spec table once (deduped), got:\n%s", hyd.Markdown)
	}
	if len(hyd.Records) != 6 {
		t.Fatalf("expected 6 records (2 attributes x 3 models), got %d: %+v", len(hyd.Records), hyd.Records)
	}
	found := false
	for _, r := range hyd.Records {
		if r["model"] == "EP600" && r["name"] == "Drive unit / Weight" && r["value"] == "2.6 kg" && r["category"] == "Specifications" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing EP600 weight record: %+v", hyd.Records)
	}
}

func payload0ForTest() string {
	return flightTextRowForTest("0", shimanoProseForTest)
}
