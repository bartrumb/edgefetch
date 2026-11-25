package jobs

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type JSONRecordChunk struct {
	Ordinal  int    `json:"ordinal"`
	Heading  string `json:"heading"`
	Text     string `json:"text"`
	RecordID string `json:"recordId,omitempty"`
}

// ChunkedJSONRecordsResult holds the per-record chunks and combined Markdown for a JSON array response.
type ChunkedJSONRecordsResult struct {
	Title          string            `json:"title"`
	TotalRecords   int               `json:"totalRecords"`
	MatchedRecords int               `json:"matchedRecords"`
	Chunks         []JSONRecordChunk `json:"chunks"`
	Markdown       string            `json:"markdown"`
}

// ChunkJSONRecordsParams configures ChunkJSONRecords.
type ChunkJSONRecordsParams struct {
	RawBody     string       `json:"rawBody"`
	ContentType string       `json:"contentType"`
	URL         string       `json:"url"`
	JSONFilter  string       `json:"jsonFilter"`
	HTMLToMD    HTMLToMDFunc `json:"-"`
}

type jsonFilterClause struct {
	field string
	op    string // "=", "!=", "~"
	value string
}

func parseJSONFilterClauses(filterStr string) []jsonFilterClause {
	var clauses []jsonFilterClause
	for _, rawPart := range reJSONFilterSplit.Split(filterStr, -1) {
		m := reJSONFilterClause.FindStringSubmatch(strings.TrimSpace(rawPart))
		if len(m) < 4 {
			continue
		}
		op := m[2]
		if op == "~=" {
			op = "~"
		}
		val := strings.TrimSpace(m[3])
		if len(val) >= 2 && ((val[0] == '\'' && val[len(val)-1] == '\'') || (val[0] == '"' && val[len(val)-1] == '"')) {
			val = val[1 : len(val)-1]
		}
		clauses = append(clauses, jsonFilterClause{field: m[1], op: op, value: val})
	}
	return clauses
}

func isSafeUserFilterRegex(pattern string) (*regexp.Regexp, bool) {
	if pattern == "" || len(pattern) > 256 {
		return nil, false
	}
	if strings.Contains(pattern, `\k<`) || strings.Contains(pattern, `(?<=`) || strings.Contains(pattern, `(?<!`) || strings.Contains(pattern, `(?=`) || strings.Contains(pattern, `(?!`) {
		return nil, false
	}
	// Reject backreferences (\1..\9) and nested quantifiers / quantified groups containing internal quantifiers (e.g. `(a+)+`, `(a*aaa*)?$`).
	type groupState struct {
		hasQuant bool
	}
	var stack []groupState
	inClass := false
	prevQuantifiable := false
	prevGroupHadQuant := false

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' {
			if i+1 >= len(pattern) {
				return nil, false
			}
			next := pattern[i+1]
			if !inClass && next >= '1' && next <= '9' {
				return nil, false
			}
			i++
			if !inClass {
				prevQuantifiable = next != 'b' && next != 'B'
				prevGroupHadQuant = false
			}
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
				prevQuantifiable = true
				prevGroupHadQuant = false
			}
			continue
		}
		switch c {
		case '[':
			inClass = true
		case '(':
			stack = append(stack, groupState{})
			prevQuantifiable = false
			prevGroupHadQuant = false
		case ')':
			if len(stack) == 0 {
				return nil, false
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.hasQuant && len(stack) > 0 {
				stack[len(stack)-1].hasQuant = true
			}
			prevQuantifiable = true
			prevGroupHadQuant = top.hasQuant
		case '*', '+', '?':
			if !prevQuantifiable || prevGroupHadQuant {
				return nil, false
			}
			if len(stack) > 0 {
				stack[len(stack)-1].hasQuant = true
			}
			if i+1 < len(pattern) && pattern[i+1] == '?' {
				i++
			}
			prevQuantifiable = false
			prevGroupHadQuant = false
		case '{':
			closeBrace := strings.IndexByte(pattern[i+1:], '}')
			if closeBrace > 0 {
				inner := pattern[i+1 : i+1+closeBrace]
				if isQuantifierBraceSpec(inner) {
					if !prevQuantifiable || prevGroupHadQuant {
						return nil, false
					}
					if len(stack) > 0 {
						stack[len(stack)-1].hasQuant = true
					}
					i += closeBrace + 1
					if i+1 < len(pattern) && pattern[i+1] == '?' {
						i++
					}
					prevQuantifiable = false
					prevGroupHadQuant = false
					continue
				}
			}
			prevQuantifiable = true
			prevGroupHadQuant = false
		case '^', '$', '|':
			prevQuantifiable = false
			prevGroupHadQuant = false
		default:
			prevQuantifiable = true
			prevGroupHadQuant = false
		}
	}
	if inClass || len(stack) > 0 {
		return nil, false
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, false
	}
	return re, true
}

func isQuantifierBraceSpec(inner string) bool {
	parts := strings.Split(inner, ",")
	if len(parts) > 2 {
		return false
	}
	n1, err1 := strconv.Atoi(parts[0])
	if err1 != nil || n1 < 0 || n1 > 1000 {
		return false
	}
	if len(parts) == 2 && parts[1] != "" {
		n2, err2 := strconv.Atoi(parts[1])
		if err2 != nil || n2 < n1 || n2 > 1000 {
			return false
		}
	}
	return true
}

func readNestedField(obj map[string]any, path string) string {
	var cur any = obj
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok || m == nil {
			return ""
		}
		cur = m[seg]
	}
	if cur == nil {
		return ""
	}
	switch v := cur.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return MarshalNoEscape(v)
	}
}

func extractOrderedKeysFromRaw(raw string) []string {
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			break
		}
		if ks, ok := kt.(string); ok {
			keys = append(keys, ks)
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			break
		}
	}
	return keys
}

// ChunkJSONRecords detects JSON record arrays, applies optional jsonFilter, converts HTML fields to Markdown,
// and emits one self-contained chunk per record.
func ChunkJSONRecords(params ChunkJSONRecordsParams) *ChunkedJSONRecordsResult {
	ct := strings.ToLower(params.ContentType)
	trimmed := strings.TrimSpace(params.RawBody)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil
	}
	if !strings.Contains(ct, "json") && !reJSONURLHint.MatchString(params.URL) {
		if !strings.HasPrefix(trimmed, "[") {
			return nil
		}
	}

	parsed := SafeJSONParse(trimmed)
	if parsed == nil {
		return nil
	}

	var records []map[string]any
	containerTitle := "JSON Records"
	switch root := parsed.(type) {
	case []any:
		if len(root) == 0 {
			return nil
		}
		recs := make([]map[string]any, 0, len(root))
		for _, item := range root {
			m, ok := item.(map[string]any)
			if !ok || m == nil {
				return nil
			}
			recs = append(recs, m)
		}
		records = recs
	case map[string]any:
		if orgName, ok := root["organizationName"].(string); ok && orgName != "" {
			containerTitle = orgName
		}
		for _, arrKey := range []string{"jobs", "postings", "jobPostings", "results", "data", "items"} {
			cand, ok := root[arrKey].([]any)
			if !ok || len(cand) == 0 {
				continue
			}
			recs := make([]map[string]any, 0, len(cand))
			allObjs := true
			for _, item := range cand {
				m, isMap := item.(map[string]any)
				if !isMap || m == nil {
					allObjs = false
					break
				}
				recs = append(recs, m)
			}
			if allObjs {
				records = recs
				break
			}
		}
	}
	if len(records) == 0 {
		return nil
	}

	htmlToMD := params.HTMLToMD
	if htmlToMD == nil {
		htmlToMD = DefaultHTMLToMD
	}

	var clauses []jsonFilterClause
	if params.JSONFilter != "" {
		clauses = parseJSONFilterClauses(params.JSONFilter)
	}

	filtered := records
	if len(clauses) > 0 {
		filtered = make([]map[string]any, 0, len(records))
		for _, rec := range records {
			matchAll := true
			for _, c := range clauses {
				val := readNestedField(rec, c.field)
				switch c.op {
				case "=":
					if !strings.EqualFold(val, c.value) {
						matchAll = false
					}
				case "!=":
					if strings.EqualFold(val, c.value) {
						matchAll = false
					}
				default:
					safeRe, ok := isSafeUserFilterRegex(c.value)
					if !ok {
						if reRegexMetachar.MatchString(c.value) || len(c.value) > 256 {
							matchAll = false
						} else if !strings.Contains(strings.ToLower(val), strings.ToLower(c.value)) {
							matchAll = false
						}
					} else {
						subj := sliceUTF16Max(val, 2048)
						if !safeRe.MatchString(subj) {
							matchAll = false
						}
					}
				}
				if !matchAll {
					break
				}
			}
			if matchAll {
				filtered = append(filtered, rec)
			}
		}
	}

	scalarFields := []string{
		"id", "location", "locationsText", "workplaceType", "department", "team",
		"employmentType", "publishedAt", "postedOn", "jobUrl", "applyUrl", "hostedUrl", "absolute_url",
	}
	htmlFields := []string{"descriptionHtml", "content", "description", "body_html", "jobDescription"}

	chunks := make([]JSONRecordChunk, 0, len(filtered))
	mdParts := make([]string, 0, len(filtered))
	for i, rec := range filtered {
		recID := firstNonEmpty(anyString(rec["id"]), anyString(rec["reqId"]), anyString(rec["jobId"]), anyString(rec["slug"]))
		if recID == "" {
			recID = strconv.Itoa(i + 1)
		}
		recTitle := strings.TrimSpace(firstNonEmpty(anyString(rec["title"]), anyString(rec["text"]), anyString(rec["name"])))
		if recTitle == "" {
			recTitle = fmt.Sprintf("Record %d", i+1)
		}
		heading := recTitle
		if recID != "" && recID != recTitle {
			heading = fmt.Sprintf("%s [%s]", recTitle, recID)
		}

		lines := []string{"## " + heading}

		var pay *NormalizedPay
		if rec["compensation"] != nil {
			descPlain, _ := rec["descriptionPlain"].(string)
			pay = parseAshbyPay(rec, descPlain)
		} else if rec["salaryRange"] != nil || rec["salaryDescriptionPlain"] != nil || isJSONArray(rec["lists"]) || rec["additionalPlain"] != nil {
			pay = parseLeverPay(rec, "")
		} else if isJSONArray(rec["pay_input_ranges"]) || isJSONArray(rec["metadata"]) {
			pay = parseGreenhousePay(rec, "")
		}
		if pay != nil {
			lines = append(lines, "- **Compensation**: "+FormatNormalizedPay(pay))
		}

		for _, fk := range scalarFields {
			if fv, ok := rec[fk].(string); ok && strings.TrimSpace(fv) != "" {
				lines = append(lines, fmt.Sprintf("- **%s**: %s", fk, strings.TrimSpace(fv)))
			}
		}
		if cats, ok := rec["categories"].(map[string]any); ok {
			for _, ck := range orderedMapKeys(cats) {
				if cv, ok := cats[ck].(string); ok && strings.TrimSpace(cv) != "" {
					lines = append(lines, fmt.Sprintf("- **%s**: %s", ck, strings.TrimSpace(cv)))
				}
			}
		}

		addedRichBody := false
		for _, hk := range htmlFields {
			hv, ok := rec[hk].(string)
			if !ok || strings.TrimSpace(hv) == "" {
				continue
			}
			decoded := hv
			if reHTMLTagProbeChunk.MatchString(hv) || reHTMLEntityProbe.MatchString(hv) {
				decoded = DecodeEntitiesBasic(hv)
			}
			var md string
			if reHTMLTagProbeChunk.MatchString(decoded) {
				rawMD, _ := htmlToMD(decoded, params.URL)
				md = strings.TrimSpace(rawMD)
			} else {
				md = strings.TrimSpace(decoded)
			}
			if md != "" {
				lines = append(lines, "", md)
				addedRichBody = true
				break
			}
		}
		if !addedRichBody {
			if dp, ok := rec["descriptionPlain"].(string); ok && strings.TrimSpace(dp) != "" {
				lines = append(lines, "", strings.TrimSpace(dp))
				addedRichBody = true
			}
		}
		if lists, ok := rec["lists"].([]any); ok {
			for _, item := range lists {
				lst, ok := item.(map[string]any)
				if !ok {
					continue
				}
				lt, _ := lst["text"].(string)
				lt = strings.TrimSpace(lt)
				lc := ""
				if contentStr, ok := lst["content"].(string); ok {
					rawMD, _ := htmlToMD("<ul>"+contentStr+"</ul>", params.URL)
					lc = strings.TrimSpace(rawMD)
				}
				if lt != "" || lc != "" {
					var sub []string
					if lt != "" {
						sub = append(sub, "### "+lt)
					}
					if lc != "" {
						sub = append(sub, lc)
					}
					lines = append(lines, "", strings.Join(sub, "\n"))
				}
			}
		}
		if !addedRichBody && len(lines) <= 2 {
			for _, k := range orderedMapKeys(rec) {
				if k == "title" || k == "name" || k == "id" {
					continue
				}
				v := rec[k]
				if v == nil {
					continue
				}
				switch vt := v.(type) {
				case string:
					cleanV := strings.TrimSpace(vt)
					if reHTMLTagProbeChunk.MatchString(vt) {
						rawMD, _ := htmlToMD(vt, params.URL)
						cleanV = strings.TrimSpace(rawMD)
					}
					if cleanV != "" {
						lines = append(lines, fmt.Sprintf("- **%s**: %s", k, sliceUTF16Max(cleanV, 1200)))
					}
				case float64:
					lines = append(lines, fmt.Sprintf("- **%s**: %s", k, strconv.FormatFloat(vt, 'f', -1, 64)))
				case bool:
					lines = append(lines, fmt.Sprintf("- **%s**: %t", k, vt))
				}
			}
		}

		text := strings.TrimSpace(strings.Join(lines, "\n"))
		chunks = append(chunks, JSONRecordChunk{
			Ordinal:  i,
			Heading:  heading,
			Text:     text,
			RecordID: recID,
		})
		mdParts = append(mdParts, text)
	}

	return &ChunkedJSONRecordsResult{
		Title:          fmt.Sprintf("%s (%d of %d records)", containerTitle, len(filtered), len(records)),
		TotalRecords:   len(records),
		MatchedRecords: len(filtered),
		Chunks:         chunks,
		Markdown:       strings.Join(mdParts, "\n\n---\n\n"),
	}
}

func isJSONArray(v any) bool {
	_, ok := v.([]any)
	return ok
}

func orderedMapKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	raw := MarshalNoEscape(m)
	return extractOrderedKeysFromRaw(raw)
}
