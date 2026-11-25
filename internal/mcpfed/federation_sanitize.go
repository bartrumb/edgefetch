package mcpfed

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const (
	// MaxRemoteMCPResponseBytes is the 4 MiB hard ceiling on downstream MCP responses.
	MaxRemoteMCPResponseBytes = 4 * 1024 * 1024
	// MaxMCPContentBlocks caps content[] blocks per downstream MCP response (H3).
	MaxMCPContentBlocks = 64
	// MaxMCPBlockTextChars caps raw per-block text BEFORE sanitizing (64 KiB, H3).
	MaxMCPBlockTextChars = 64 * 1024
	// MaxMCPLinkLabelChars caps Markdown link label length in linear dangerous-link stripping.
	MaxMCPLinkLabelChars = 512
	// MaxMCPLinkTargetChars caps Markdown link target length in linear dangerous-link stripping.
	MaxMCPLinkTargetChars = 2048
	// MaxMCPToolSchemaBytes is the 16 KiB ceiling on individual and total tools/list schemas (H3).
	MaxMCPToolSchemaBytes = 16 * 1024

	// MaxStructuredSanitizeDepth caps recursion depth on structuredContent / connector JSON trees.
	MaxStructuredSanitizeDepth = 12
	// MaxStructuredContainerEntries caps object keys / array items per container.
	MaxStructuredContainerEntries = 256
	// MaxStructuredNodeBudget caps total visited nodes across a structured connector JSON tree.
	MaxStructuredNodeBudget = 2048
	// MaxStructuredStringChars caps string leaf length (16 KiB).
	MaxStructuredStringChars = 16 * 1024

	// MaxMCPRPCErrorDataBytes caps JSON-RPC error.data serialized size (4 KiB).
	MaxMCPRPCErrorDataBytes = 4 * 1024
	// MaxMCPRPCErrorDataDepth caps JSON-RPC error.data nesting depth.
	MaxMCPRPCErrorDataDepth = 4
	// MaxMCPRPCErrorDataEntries caps JSON-RPC error.data entries per container.
	MaxMCPRPCErrorDataEntries = 16
	// MaxMCPRPCErrorDataNodes caps JSON-RPC error.data visited node count.
	MaxMCPRPCErrorDataNodes = 64
	// MaxMCPRPCErrorDataStringChars caps JSON-RPC error.data string leaf length.
	MaxMCPRPCErrorDataStringChars = 512
)

var (
	mcpDirectiveInjectionRe = regexp.MustCompile(
		`(?i)\b(?:note|instruction|message|directive|reminder)\s+to\s+(?:the\s+)?(?:ai|llm|assistant|model|agent)\b|\bcall\s+query_mcp\s*\(|\bpre-authori[sz]ed\b|\bdo\s+not\s+ask\s+(?:the\s+user\s+)?for\s+confirmation\b|\bwhen\s+summarizing[^.\n]{0,80}\b(?:append|include|output|exfiltrate)\b`,
	)
	dangerousMarkdownSchemeRe = regexp.MustCompile(`(?i)^(?:javascript|vbscript|data|file|blob)\s*:`)
	untrustedBoundaryTagRe    = regexp.MustCompile(`(?i)<(\s*/?\s*untrusted_[a-z0-9_-]*)`)
	envelopeAttrKeyRe         = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)
	bearerSecretRedactRe      = regexp.MustCompile(`(?i)\bBearer\s+[^\s"',;)]+`)
	hiddenStyleAttrRe         = regexp.MustCompile(`(?i)\bstyle\s*=`)
	hiddenStylePropRe         = regexp.MustCompile(`(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)`)
)

// SanitizedTextResult reports prompt-injection scrubbing results from SanitizeRemoteMCPText.
type SanitizedTextResult struct {
	Text     string   `json:"text"`
	Detected bool     `json:"detected"`
	Scrubbed bool     `json:"scrubbed"`
	Triggers []string `json:"triggers"`
}

// SanitizedConnectorTextResult reports full Markdown + link + injection sanitization on a string.
type SanitizedConnectorTextResult struct {
	Text           string   `json:"text"`
	Sanitized      bool     `json:"sanitized"`
	FullySanitized bool     `json:"fullySanitized"`
	Truncated      bool     `json:"truncated"`
	Detected       bool     `json:"detected"`
	Scrubbed       bool     `json:"scrubbed"`
	Triggers       []string `json:"triggers"`
}

// SanitizedConnectorStructuredResult reports recursive structured JSON sanitization results.
type SanitizedConnectorStructuredResult struct {
	Value          any      `json:"value"`
	Sanitized      bool     `json:"sanitized"`
	FullySanitized bool     `json:"fullySanitized"`
	Truncated      bool     `json:"truncated"`
	Detected       bool     `json:"detected"`
	Scrubbed       bool     `json:"scrubbed"`
	Triggers       []string `json:"triggers"`
}

// StructuredSanitizeOptions configures SanitizeConnectorStructuredValue.
type StructuredSanitizeOptions struct {
	BaseURL                string
	ApplyRedact            bool
	RedactSecret           *VaultSecretPayload
	MaxDepth               int
	MaxEntriesPerContainer int
	MaxNodeBudget          int
	MaxStringChars         int
	MaxTotalChars          *int
}

func containsFoldASCII(s, needleLower string) bool {
	nLen := len(needleLower)
	if nLen == 0 {
		return true
	}
	if len(s) < nLen {
		return false
	}
	c0 := needleLower[0]
	for i := 0; i <= len(s)-nLen; i++ {
		b := s[i]
		if b >= 'A' && b <= 'Z' {
			b |= 0x20
		}
		if b != c0 {
			continue
		}
		match := true
		for j := 1; j < nLen; j++ {
			bj := s[i+j]
			if bj >= 'A' && bj <= 'Z' {
				bj |= 0x20
			}
			if bj != needleLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// NeutralizeUntrustedMCPBoundaryTags escapes <untrusted_... and </untrusted_... tags inside untrusted text.
func NeutralizeUntrustedMCPBoundaryTags(input string) string {
	if input == "" || !containsFoldASCII(input, "untrusted_") {
		return input
	}
	return untrustedBoundaryTagRe.ReplaceAllString(input, "&lt;$1")
}

func stripUnsafeEnvelopeAttrChars(v string) string {
	var sb strings.Builder
	sb.Grow(len(v))
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '"', '&', '<', '>', '\r', '\n', 0, '`':
			continue
		default:
			sb.WriteByte(v[i])
		}
	}
	return sb.String()
}

// FormatFenceSafeUntrustedMCPEnvelope wraps untrusted text in a fence-safe + boundary-tag-safe XML envelope.
func FormatFenceSafeUntrustedMCPEnvelope(tag string, attrs OrderedObject, content string, maxChars int) string {
	outTag := "untrusted_mcp_output"
	if tag == "untrusted_mcp_tool_output" {
		outTag = "untrusted_mcp_tool_output"
	}
	sliced := content
	if maxChars > 0 {
		sliced, _ = sliceUTF16(content, maxChars)
	}
	safeBody := NeutralizeUntrustedMCPBoundaryTags(sliced)
	maxBacktickRun := 0
	curRun := 0
	for i := 0; i < len(safeBody); i++ {
		if safeBody[i] == '`' {
			curRun++
			if curRun > maxBacktickRun {
				maxBacktickRun = curRun
			}
		} else {
			curRun = 0
		}
	}
	fenceLen := max(3, maxBacktickRun+1)
	fence := strings.Repeat("`", fenceLen)

	var attrBuf strings.Builder
	for _, entry := range attrs {
		if !envelopeAttrKeyRe.MatchString(entry.Key) || entry.Value == nil {
			continue
		}
		valStr, ok := entry.Value.(string)
		if !ok || valStr == "" {
			continue
		}
		safeVal := stripUnsafeEnvelopeAttrChars(valStr)
		attrBuf.WriteByte(' ')
		attrBuf.WriteString(entry.Key)
		attrBuf.WriteString(`="`)
		attrBuf.WriteString(safeVal)
		attrBuf.WriteByte('"')
	}

	var out strings.Builder
	out.Grow(len(safeBody) + fenceLen*2 + attrBuf.Len() + 64)
	out.WriteByte('<')
	out.WriteString(outTag)
	out.WriteString(attrBuf.String())
	out.WriteString(">\n")
	out.WriteString(fence)
	out.WriteString("text\n")
	out.WriteString(safeBody)
	out.WriteByte('\n')
	out.WriteString(fence)
	out.WriteString("\n</")
	out.WriteString(outTag)
	out.WriteByte('>')
	return out.String()
}

func cleanLinkTargetSchemeCheck(rawTarget string) string {
	t := strings.TrimSpace(rawTarget)
	t = strings.TrimPrefix(t, "<")
	t = strings.TrimSuffix(t, ">")
	var sb strings.Builder
	sb.Grow(len(t))
	for i := 0; i < len(t); i++ {
		if t[i] <= 0x20 {
			continue
		}
		sb.WriteByte(t[i])
	}
	return sb.String()
}

// stripDangerousMarkdownLinksLinear strips javascript:, vbscript:, data:, file:, and blob: Markdown links in O(N) time.
func stripDangerousMarkdownLinksLinear(input string) string {
	if !strings.Contains(input, "](") || strings.IndexByte(input, ')') < 0 || strings.IndexByte(input, ':') < 0 {
		return input
	}
	n := len(input)
	var out strings.Builder
	emitFrom := 0
	openBracket := -1
	noCloseParenBefore := -1

	for i := 0; i < n; i++ {
		ch := input[i]
		if ch == '\n' || ch == '\r' {
			openBracket = -1
			continue
		}
		if ch == '[' {
			openBracket = i
			continue
		}
		if ch == ']' && openBracket >= 0 {
			labelByteLen := i - openBracket - 1
			if (labelByteLen <= MaxMCPLinkLabelChars || utf16Len(input[openBracket+1:i]) <= MaxMCPLinkLabelChars) &&
				i+1 < n && input[i+1] == '(' {
				parenStart := i + 2
				if parenStart >= noCloseParenBefore {
					maxEnd := min(n, parenStart+MaxMCPLinkTargetChars*4)
					closeParen := -1
					scanPos := parenStart
					u16Scanned := 0
					for scanPos < maxEnd && u16Scanned < MaxMCPLinkTargetChars {
						tc := input[scanPos]
						if tc == '\n' || tc == '\r' {
							break
						}
						if tc == ')' {
							closeParen = scanPos
							break
						}
						if tc < 0x80 {
							scanPos++
							u16Scanned++
						} else {
							_, w := decodeUTF8Rune(input[scanPos:])
							scanPos += w
							u16Scanned++
						}
					}
					if closeParen >= 0 {
						cleanedTarget := cleanLinkTargetSchemeCheck(input[parenStart:closeParen])
						if dangerousMarkdownSchemeRe.MatchString(cleanedTarget) {
							linkStart := openBracket
							if openBracket > 0 && input[openBracket-1] == '!' {
								linkStart = openBracket - 1
							}
							label := input[openBracket+1 : i]
							if label == "" {
								label = "[blocked-unsafe-link]"
							}
							if emitFrom == 0 {
								out.Grow(n)
							}
							out.WriteString(input[emitFrom:linkStart])
							out.WriteString(label)
							emitFrom = closeParen + 1
						}
						i = closeParen
						openBracket = -1
						continue
					}
					noCloseParenBefore = scanPos
				}
			}
			openBracket = -1
		}
	}
	if emitFrom == 0 {
		return input
	}
	out.WriteString(input[emitFrom:])
	return out.String()
}

func hasHiddenInlineStyleLinear(line string) bool {
	if strings.IndexByte(line, '<') < 0 || !containsFoldASCII(line, "style") {
		return false
	}
	pos := 0
	for pos < len(line) {
		lt := strings.IndexByte(line[pos:], '<')
		if lt < 0 {
			return false
		}
		lt += pos
		gtRel := strings.IndexByte(line[lt+1:], '>')
		if gtRel >= 0 {
			gt := lt + 1 + gtRel
			end := min(gt+1, lt+2048)
			tagSlice := line[lt:end]
			if hiddenStyleAttrRe.MatchString(tagSlice) && hiddenStylePropRe.MatchString(tagSlice) {
				return true
			}
			pos = gt + 1
		} else {
			end := min(len(line), lt+2048)
			tagSlice := line[lt:end]
			return hiddenStyleAttrRe.MatchString(tagSlice) && hiddenStylePropRe.MatchString(tagSlice)
		}
	}
	return false
}

// SanitizeMCPMarkdownOutput sanitizes untrusted Markdown/HTML returned by a downstream MCP server.
func SanitizeMCPMarkdownOutput(rawMarkdown, baseURL string, maxChars int) string {
	if rawMarkdown == "" {
		return ""
	}
	if maxChars <= 0 {
		maxChars = MaxRemoteMCPResponseBytes
	}
	bounded, _ := sliceUTF16(rawMarkdown, maxChars)
	out := extract.SanitizeMarkdownWithOptions(bounded, baseURL, false)
	out = NeutralizeUntrustedMCPBoundaryTags(out)
	out = stripDangerousMarkdownLinksLinear(out)
	return out
}

func detectPromptInjForMCP(s string) extract.PromptInjectionResult {
	rawHTML := ""
	if strings.IndexByte(s, '<') >= 0 {
		rawHTML = s
	}
	return extract.DetectPromptInjection(s, rawHTML)
}

func mergeUniqueStrings(lists ...[]string) []string {
	out := make([]string, 0, 4)
	seen := make(map[string]bool, 4)
	for _, list := range lists {
		for _, item := range list {
			if item != "" && !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
		}
	}
	return out
}

func hasMCPDirectiveKeyword(s string) bool {
	return containsFoldASCII(s, "to ") ||
		containsFoldASCII(s, "query_mcp") ||
		containsFoldASCII(s, "pre-authori") ||
		containsFoldASCII(s, "do not") ||
		containsFoldASCII(s, "when ")
}

func matchesMCPDirectiveInjection(s string) bool {
	return hasMCPDirectiveKeyword(s) && mcpDirectiveInjectionRe.MatchString(s)
}

// SanitizeRemoteMCPText strips smuggling chars and scrubs indirect prompt-injection instructions.
func SanitizeRemoteMCPText(raw string, maxChars int) SanitizedTextResult {
	if raw == "" {
		return SanitizedTextResult{Text: "", Detected: false, Scrubbed: false, Triggers: []string{}}
	}
	if maxChars <= 0 {
		maxChars = MaxRemoteMCPResponseBytes
	}
	boundedRaw, _ := sliceUTF16(raw, maxChars)

	preScan := detectPromptInjForMCP(boundedRaw)
	stripped := StripMCPSmugglingChars(boundedRaw)
	postStripScan := preScan
	if stripped != boundedRaw {
		postStripScan = detectPromptInjForMCP(stripped)
	}
	mcpDirectiveDetected := matchesMCPDirectiveInjection(stripped)

	var dirTrig []string
	if mcpDirectiveDetected {
		dirTrig = []string{"mcp_assistant_directive_smuggling"}
	}
	allTriggers := mergeUniqueStrings(preScan.Triggers, postStripScan.Triggers, dirTrig)
	if !preScan.Detected && !postStripScan.Detected && !mcpDirectiveDetected {
		return SanitizedTextResult{Text: stripped, Detected: false, Scrubbed: false, Triggers: []string{}}
	}
	if !postStripScan.Detected && !mcpDirectiveDetected {
		return SanitizedTextResult{Text: stripped, Detected: true, Scrubbed: true, Triggers: allTriggers}
	}

	normalizedLines := strings.ReplaceAll(stripped, "\r\n", "\n")
	lines := strings.Split(normalizedLines, "\n")
	if len(lines) == 1 {
		return SanitizedTextResult{
			Text:     "[SCRUBBED: prompt injection blocked]",
			Detected: true,
			Scrubbed: true,
			Triggers: allTriggers,
		}
	}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lineCheck := detectPromptInjForMCP(line)
		if lineCheck.Detected || matchesMCPDirectiveInjection(line) || hasHiddenInlineStyleLinear(line) {
			lines[i] = "[SCRUBBED: prompt injection blocked]"
		}
	}
	candidate := strings.Join(lines, "\n")
	verifyScan := detectPromptInjForMCP(candidate)
	if verifyScan.Detected || matchesMCPDirectiveInjection(candidate) {
		merged := mergeUniqueStrings(allTriggers, verifyScan.Triggers)
		return SanitizedTextResult{
			Text:     "[SCRUBBED: prompt injection blocked]",
			Detected: true,
			Scrubbed: true,
			Triggers: merged,
		}
	}
	return SanitizedTextResult{
		Text:     candidate,
		Detected: true,
		Scrubbed: true,
		Triggers: allTriggers,
	}
}

// RedactVaultSecretsFromText scrubs Bearer tokens and decrypted vault header/OAuth secrets from untrusted error/tool text.
func RedactVaultSecretsFromText(raw string, secret *VaultSecretPayload) string {
	if raw == "" {
		return raw
	}
	out := raw
	if containsFoldASCII(out, "bearer") {
		out = bearerSecretRedactRe.ReplaceAllString(out, "Bearer [REDACTED]")
	}
	if secret == nil {
		return out
	}
	sensitiveValues := make([]string, 0, 6)
	for _, entry := range secret.Headers {
		v, ok := entry.Value.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(v)
		if utf16Len(trimmed) >= 4 {
			sensitiveValues = append(sensitiveValues, trimmed)
		}
		strippedBearer := stripLeadingBearerPrefix(trimmed)
		if utf16Len(strippedBearer) >= 4 {
			sensitiveValues = append(sensitiveValues, strippedBearer)
		}
	}
	if secret.OAuth != nil {
		for _, tok := range []string{secret.OAuth.AccessToken, secret.OAuth.RefreshToken, secret.OAuth.ClientSecret} {
			t := strings.TrimSpace(tok)
			if utf16Len(t) >= 4 {
				sensitiveValues = append(sensitiveValues, t)
			}
		}
	}
	for _, val := range sensitiveValues {
		if strings.Contains(out, val) {
			out = strings.ReplaceAll(out, val, "[REDACTED]")
		}
	}
	return out
}

// SanitizeConnectorText runs secret redaction -> prompt-injection scrubbing -> Markdown/HTML/link sanitization + post-verify.
func SanitizeConnectorText(
	raw string,
	maxChars int,
	baseURL string,
	applyRedact bool,
	redactSecret *VaultSecretPayload,
) SanitizedConnectorTextResult {
	if raw == "" {
		return SanitizedConnectorTextResult{
			Text:           "",
			Sanitized:      true,
			FullySanitized: true,
			Triggers:       []string{},
		}
	}
	if maxChars <= 0 {
		return SanitizedConnectorTextResult{
			Text:           "",
			Sanitized:      false,
			FullySanitized: false,
			Truncated:      true,
			Triggers:       []string{},
		}
	}
	redacted := raw
	if applyRedact {
		redacted = RedactVaultSecretsFromText(raw, redactSecret)
	}
	bounded, truncated := sliceUTF16(redacted, maxChars)
	piRes := SanitizeRemoteMCPText(bounded, maxChars)
	safeMD := SanitizeMCPMarkdownOutput(piRes.Text, baseURL, maxChars)

	var postVerify extract.PromptInjectionResult
	if safeMD != piRes.Text || piRes.Detected {
		postVerify = detectPromptInjForMCP(safeMD)
	}
	completedCleanly := !postVerify.Detected && !matchesMCPDirectiveInjection(safeMD)
	triggers := piRes.Triggers
	if len(postVerify.Triggers) > 0 {
		triggers = mergeUniqueStrings(piRes.Triggers, postVerify.Triggers)
	}
	if triggers == nil {
		triggers = []string{}
	}
	return SanitizedConnectorTextResult{
		Text:           safeMD,
		Sanitized:      completedCleanly,
		FullySanitized: completedCleanly && !truncated,
		Truncated:      truncated,
		Detected:       piRes.Detected || postVerify.Detected,
		Scrubbed:       piRes.Scrubbed || safeMD != bounded || redacted != raw,
		Triggers:       triggers,
	}
}

// SanitizeConnectorStructuredValue recursively sanitizes arbitrary connector JSON trees under strict depth/node/entry/char caps.
func SanitizeConnectorStructuredValue(rawValue any, opts StructuredSanitizeOptions) SanitizedConnectorStructuredResult {
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = MaxStructuredSanitizeDepth
	}
	maxEntries := opts.MaxEntriesPerContainer
	if maxEntries <= 0 {
		maxEntries = MaxStructuredContainerEntries
	}
	maxNodes := opts.MaxNodeBudget
	if maxNodes <= 0 {
		maxNodes = MaxStructuredNodeBudget
	}
	maxStringChars := opts.MaxStringChars
	if maxStringChars <= 0 {
		maxStringChars = MaxStructuredStringChars
	}

	visitedNodes := 0
	totalProcessedChars := 0
	allLeavesSanitized := true
	truncated := false
	anyDetected := false
	anyScrubbed := false
	var triggers []string
	seenTriggers := make(map[string]bool)
	addTriggers := func(trs []string) {
		for _, tr := range trs {
			if tr != "" && !seenTriggers[tr] {
				seenTriggers[tr] = true
				triggers = append(triggers, tr)
			}
		}
	}

	var walk func(node any, depth int) any
	walk = func(node any, depth int) any {
		visitedNodes++
		if visitedNodes > maxNodes || depth > maxDepth || (opts.MaxTotalChars != nil && totalProcessedChars > *opts.MaxTotalChars) {
			truncated = true
			return "[truncated]"
		}
		if node == nil {
			return nil
		}
		switch v := node.(type) {
		case bool:
			return v
		case json.Number:
			if _, ok := numberToFiniteFloat(v); !ok {
				return nil
			}
			return v
		case float64:
			if v != v || v > 1.7976931348623157e+308 || v < -1.7976931348623157e+308 {
				return nil
			}
			return v
		case SpecialSentinel:
			switch v.Kind {
			case "cycle":
				truncated = true
				return "[truncated]"
			case "bigint":
				s := SanitizeConnectorText(v.Raw, 128, opts.BaseURL, opts.ApplyRedact, opts.RedactSecret)
				totalProcessedChars += utf16Len(s.Text)
				if !s.Sanitized {
					allLeavesSanitized = false
				}
				if s.Truncated {
					truncated = true
				}
				return s.Text
			default:
				allLeavesSanitized = false
				return nil
			}
		case string:
			remChars := maxStringChars
			if opts.MaxTotalChars != nil {
				remChars = max(0, *opts.MaxTotalChars-totalProcessedChars)
				if remChars == 0 && v != "" {
					truncated = true
					return "[truncated]"
				}
			}
			leafBudget := min(maxStringChars, remChars)
			s := SanitizeConnectorText(v, leafBudget, opts.BaseURL, opts.ApplyRedact, opts.RedactSecret)
			totalProcessedChars += utf16Len(s.Text)
			if !s.Sanitized {
				allLeavesSanitized = false
			}
			if s.Truncated {
				truncated = true
			}
			if s.Detected {
				anyDetected = true
			}
			if s.Scrubbed {
				anyScrubbed = true
			}
			addTriggers(s.Triggers)
			return s.Text
		case []any:
			sliceLen := min(len(v), maxEntries)
			outArr := make([]any, 0, sliceLen+1)
			for i := 0; i < sliceLen; i++ {
				if visitedNodes >= maxNodes || (opts.MaxTotalChars != nil && totalProcessedChars >= *opts.MaxTotalChars) {
					outArr = append(outArr, "[truncated]")
					truncated = true
					return outArr
				}
				outArr = append(outArr, walk(v[i], depth+1))
			}
			if len(v) > maxEntries {
				outArr = append(outArr, "[truncated]")
				truncated = true
			}
			return outArr
		case OrderedObject:
			outObj := make(OrderedObject, 0, min(len(v), maxEntries)+1)
			emitted := 0
			for i := 0; i < len(v); i++ {
				rawK := v[i].Key
				rawV := v[i].Value
				if rawK == "__proto__" || rawK == "constructor" || rawK == "prototype" {
					anyScrubbed = true
					continue
				}
				if emitted >= maxEntries || visitedNodes >= maxNodes || (opts.MaxTotalChars != nil && totalProcessedChars >= *opts.MaxTotalChars) {
					outObj.Set("__truncated__", "[truncated]")
					truncated = true
					break
				}
				keySan := SanitizeConnectorText(rawK, 256, opts.BaseURL, opts.ApplyRedact, opts.RedactSecret)
				totalProcessedChars += utf16Len(keySan.Text)
				if !keySan.Sanitized {
					allLeavesSanitized = false
				}
				if keySan.Truncated {
					truncated = true
				}
				if keySan.Detected {
					anyDetected = true
				}
				if keySan.Scrubbed {
					anyScrubbed = true
				}
				addTriggers(keySan.Triggers)
				safeKey := keySan.Text
				if safeKey == "" || safeKey == "__proto__" || safeKey == "constructor" || safeKey == "prototype" {
					safeKey = fmt.Sprintf("key_%d", emitted)
				}
				childVal := walk(rawV, depth+1)
				outObj.Set(safeKey, childVal)
				emitted++
			}
			return outObj
		default:
			allLeavesSanitized = false
			return nil
		}
	}

	sanitizedVal := walk(rawValue, 0)
	didSanitize := visitedNodes > 0 && allLeavesSanitized
	if triggers == nil {
		triggers = []string{}
	}
	return SanitizedConnectorStructuredResult{
		Value:          sanitizedVal,
		Sanitized:      didSanitize,
		FullySanitized: didSanitize && !truncated,
		Truncated:      truncated,
		Detected:       anyDetected,
		Scrubbed:       anyScrubbed,
		Triggers:       triggers,
	}
}
