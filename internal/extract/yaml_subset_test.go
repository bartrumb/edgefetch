package extract

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseDeclarativeYAMLDocumentAndDepthLimits(t *testing.T) {
	if _, err := ParseDeclarativeYAML(bytes.Repeat([]byte("a"), maxYAMLBytes+1)); err == nil {
		t.Fatal("expected >1 MiB YAML error")
	}
	if _, err := ParseDeclarativeYAML([]byte("--- !tag\na: 1\n")); err == nil {
		t.Fatal("expected directive/tag after --- error")
	}
	for _, emptyDoc := range []string{"", "# just comment\n", "---\n...\n"} {
		v, err := ParseDeclarativeYAML([]byte(emptyDoc))
		if err != nil || v != nil {
			t.Fatalf("ParseDeclarativeYAML(%q) = (%v, %v), want (nil, nil)", emptyDoc, v, err)
		}
	}
	if _, err := ParseDeclarativeYAML([]byte("a: 1\n...\nb: 2\n")); err == nil {
		t.Fatal("expected trailing content after ... error")
	}
	if v, err := ParseDeclarativeYAML([]byte("hello")); err != nil || v != "hello" {
		t.Fatalf("top-level scalar = (%v, %v), want (hello, nil)", v, err)
	}
	if _, err := ParseDeclarativeYAML([]byte("[1, 2")); err == nil {
		t.Fatal("expected top-level unclosed flow error")
	}

	// YAMLToJSON encode error via valid YAML number rejected by json.Number (`+123`)
	if _, err := YAMLToJSON([]byte("n: +123\n")); err == nil {
		t.Fatal("expected YAMLToJSON error on json.Number(\"+123\")")
	}

	// Depth > maxYAMLDepth across block seq, block map, inline scalar/flow, and parseNode
	var deepSeq strings.Builder
	for i := 0; i < maxYAMLDepth+2; i++ {
		deepSeq.WriteString(strings.Repeat("  ", i) + "-\n")
	}
	deepSeq.WriteString(strings.Repeat("  ", maxYAMLDepth+2) + "leaf\n")
	if _, err := ParseDeclarativeYAML([]byte(deepSeq.String())); err == nil {
		t.Fatal("expected deep block seq error")
	}

	var deepMap strings.Builder
	for i := 0; i < maxYAMLDepth+2; i++ {
		deepMap.WriteString(strings.Repeat("  ", i) + "k:\n")
	}
	deepMap.WriteString(strings.Repeat("  ", maxYAMLDepth+2) + "v: 1\n")
	if _, err := ParseDeclarativeYAML([]byte(deepMap.String())); err == nil {
		t.Fatal("expected deep block map error")
	}

	// Shift depth parity via `- a:` so parseNode itself hits depth > maxYAMLDepth
	var deepNode strings.Builder
	deepNode.WriteString("- a:\n")
	for i := 0; i < (maxYAMLDepth/2)+1; i++ {
		deepNode.WriteString(strings.Repeat("  ", i+2) + "k:\n")
	}
	deepNode.WriteString(strings.Repeat("  ", (maxYAMLDepth/2)+3) + "v: 1\n")
	if _, err := ParseDeclarativeYAML([]byte(deepNode.String())); err == nil {
		t.Fatal("expected deep parseNode error")
	}

	if isYAMLCoreNumber("") {
		t.Fatal("expected isYAMLCoreNumber(\"\") == false")
	}

	if _, err := parseYAMLInlineScalarOrFlow("1", 1, maxYAMLDepth+1); err == nil {
		t.Fatal("expected parseYAMLInlineScalarOrFlow depth error")
	}
	if _, err := parseYAMLFlowValue("[]", 1, maxYAMLDepth+1); err == nil {
		t.Fatal("expected parseYAMLFlowValue depth error")
	}
	// Defensive guards in parseNode / parseYAMLFlowValue / splitYAMLFlowItems
	pEmpty := &yamlParser{lines: []yamlLine{{lineNo: 1, indent: 0, text: "x"}}}
	pEmpty.pos = 1
	if v, err := pEmpty.parseNode(0, 0); err != nil || v != nil {
		t.Fatalf("parseNode EOF = (%v, %v)", v, err)
	}
	pDed := &yamlParser{lines: []yamlLine{{lineNo: 1, indent: 0, text: "x"}}}
	if v, err := pDed.parseNode(2, 0); err != nil || v != nil {
		t.Fatalf("parseNode dedent = (%v, %v)", v, err)
	}
	if _, err := parseYAMLFlowValue("[", 1, 0); err == nil {
		t.Fatal("expected malformed short flow value error")
	}
	if _, err := splitYAMLFlowItems("[unclosed", 1); err == nil {
		t.Fatal("expected unclosed bracket error in splitYAMLFlowItems")
	}
}

func TestYAMLBlockSequencesAndMapsEdgeCases(t *testing.T) {
	// Valid sequence edge cases: bare `-` at EOF, bare `-` before sibling, bare `-` with nested map, `- - foo`, `- k: 1\n  k2: 2`
	valid := `
items:
  -
    nested: true
  - - a
    - b
  - k1: 1
    k2: 2
bare_eof:
  -
`
	v, err := ParseDeclarativeYAML([]byte(valid))
	if err != nil {
		t.Fatalf("valid sequences failed: %v", err)
	}
	m := v.(map[string]any)
	if len(m["items"].([]any)) != 3 || m["bare_eof"].([]any)[0] != nil {
		t.Fatalf("unexpected sequence parse: %+v", m)
	}

	if v2, err2 := ParseDeclarativeYAML([]byte("a:\n  -\nb: 2\n")); err2 != nil || v2.(map[string]any)["a"].([]any)[0] != nil {
		t.Fatalf("bare dash before sibling failed: (%v, %v)", v2, err2)
	}
	if v3, err3 := ParseDeclarativeYAML([]byte("a:\nb: 2\n")); err3 != nil || v3.(map[string]any)["a"] != nil {
		t.Fatalf("empty map value before sibling failed: (%v, %v)", v3, err3)
	}
	if v4, err4 := ParseDeclarativeYAML([]byte("a:")); err4 != nil || v4.(map[string]any)["a"] != nil {
		t.Fatalf("empty map value at EOF failed: (%v, %v)", v4, err4)
	}

	errCases := []struct {
		name string
		yaml string
	}{
		{"seq over-indent", "- a\n  - b\n"},
		{"seq followed by mapping", "- a\nb: 1\n"},
		{"bare dash child error", "-\n  k: *bad\n"},
		{"inline seq flow collect err", "- [1, 2\n"},
		{"inline seq flow parse err", "- [*bad]\n"},
		{"nested inline seq err", "- - [*bad]\n"},
		{"inline seq map entry err", "- k: *bad\n"},
		{"inline seq map cont err", "- k: 1\n  badline\n"},
		{"inline seq scalar err", "- *bad\n"},
		{"map over-indent", "a: 1\n  b: 2\n"},
		{"map followed by seq", "a: 1\n- x\n"},
		{"map non-mapping line", "a: 1\nnot_a_pair\n"},
		{"empty key", ": 1\n"},
		{"anchor key", "&k: 1\n"},
		{"quoted key bad", "\"a: 1\n"},
		{"quoted key good + dup", "\"dup\": 1\n'dup': 2\n"},
		{"single-quote escaped colon key", "'it''s': 1\n'it''s': 2\n"},
		{"same-indent seq err", "a:\n- *bad\n"},
		{"block scalar err", "a: |\n    ok\n  bad\n"},
		{"map flow err", "a: [1, 2\n"},
	}
	for _, tc := range errCases {
		if _, err := ParseDeclarativeYAML([]byte(tc.yaml)); err == nil {
			t.Fatalf("expected %s (%q) to fail", tc.name, tc.yaml)
		}
	}
}

func TestYAMLBlockScalarsFlowQuotedAndNumbers(t *testing.T) {
	// Block scalars: |+, |, >, >-, >+ with blank lines, double blank lines, indented code lines, short blank line
	bsYAML := `
empty_keep: |+


empty_clip: |
lit_clip: |
  clipped
lit_keep: |+
  line1
 
  line2

folded_keep: >+
  para1
  cont1

  para2


    code1
    code2
  after

folded_strip: >-
  one
  two
`
	v, err := ParseDeclarativeYAML([]byte(bsYAML))
	if err != nil {
		t.Fatalf("block scalars failed: %v", err)
	}
	m := v.(map[string]any)
	if m["empty_keep"] != "\n\n" || m["empty_clip"] != "" {
		t.Fatalf("empty block scalars = %q / %q", m["empty_keep"], m["empty_clip"])
	}
	if !strings.HasSuffix(m["lit_keep"].(string), "\n\n") || m["folded_keep"] != "para1 cont1\n\npara2\n\n  code1\n  code2\nafter\n\n" {
		t.Fatalf("folded/lit block scalars mismatch: %#v", m)
	}
	if m["folded_strip"] != "one two" || m["lit_clip"] != "clipped\n" {
		t.Fatalf("folded_strip/lit_clip mismatch: %#v", m)
	}

	// Flow collections: multiline flow, single quotes with '', empty [], trailing comma, empty {}, {k: }, null/~, numbers
	flowYAML := `
multi: [
  'it''s',
  null,
  Null,
  ~,
  1.5e-2,
  1E+2,
  ]
empty_arr: []
empty_obj: {}
trail_obj: {a: 1, b: ,}
n1: +
n2: -
n3: 0123
n4: 1.
n5: 1e
n6: 1e+
n7: 1a
n8: 1e999
esc: "\"\\\/\b\f\n\r\t\0\u0041\uD83D\uDE00\U0001F600"
`
	vf, err := ParseDeclarativeYAML([]byte(flowYAML))
	if err != nil {
		t.Fatalf("flow/scalars YAML failed: %v", err)
	}
	mf := vf.(map[string]any)
	arr := mf["multi"].([]any)
	if arr[0] != "it's" || arr[1] != nil || arr[2] != nil || arr[3] != nil || arr[4] != json.Number("1.5e-2") || arr[5] != json.Number("1E+2") {
		t.Fatalf("unexpected multi flow array: %#v", arr)
	}
	if mf["n3"] != "0123" || mf["n8"] != "1e999" {
		t.Fatalf("non-core numbers should remain strings: %#v", mf)
	}
	if mf["esc"] != "\"\\/\b\f\n\r\t\x00A😀😀" {
		t.Fatalf("unexpected double-quoted escapes: %q", mf["esc"])
	}

	// Flow, quote, and balance errors
	badCases := []string{
		"a: [\n  1\nb: 2\n",
		"a: [1] [2]\n",
		"a: [1] trailing\n",
		"a: {x: 1} {y: 2}\n",
		"a: " + strings.Repeat("[", maxYAMLDepth+1) + "\n",
		"a: [\"unclosed\n",
		"a: \"\n",
		"a: '\n",
		"a: \"unclosed\n",
		"a: 'unclosed\n",
		"a: 'a'b'\n",
		"a: \"a\"b\"\n",
		"a: \"a\n",
		"a: \"a\\\"\n",
		"a: \"\\u12\"\n",
		"a: \"\\uZZZZ\"\n",
		"a: \"\\U1234\"\n",
		"a: \"\\UFFFFFFFF\"\n",
		"a: \"\\x41\"\n",
		"a: {bad\n", // unclosed flow
		"a: {bad}\n",
		"a: {*bad: 1}\n",
		"a: {<<: 1}\n",
		"a: {k: 1, k: 2}\n",
		"a: {k: *bad}\n",
		"a: [1, 2]]\n",
	}
	for _, y := range badCases {
		if _, err := ParseDeclarativeYAML([]byte(y)); err == nil {
			t.Fatalf("expected error for invalid YAML: %q", y)
		}
	}
}
