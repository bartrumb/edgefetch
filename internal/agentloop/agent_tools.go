package agentloop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const (
	// UntrustedRemoteParamPrefix marks every sanitized remote MCP tool parameter description in the LLM tools channel (P7).
	UntrustedRemoteParamPrefix = "[UNTRUSTED_REMOTE_PARAM] "
	maxRemoteParamDescChars    = 160
	// MaxConcurrentAgentsPerUser caps concurrent active /v1/agent runs per user.
	MaxConcurrentAgentsPerUser = 4
	maxMCPLinkLabelChars       = 512
	maxMCPLinkTargetChars      = 2048
)

// AgentEffort controls default reasoning step and page budgets.
type AgentEffort string

const (
	EffortLow    AgentEffort = "low"
	EffortMedium AgentEffort = "medium"
	EffortHigh   AgentEffort = "high"
)

// AgentStatus represents the lifecycle state of an /v1/agent run.
type AgentStatus string

const (
	StatusQueued     AgentStatus = "queued"
	StatusProcessing AgentStatus = "processing"
	StatusCompleted  AgentStatus = "completed"
	StatusFailed     AgentStatus = "failed"
	StatusCancelled  AgentStatus = "cancelled"
)

// AgentStopReason describes why an /v1/agent run terminated.
type AgentStopReason string

const (
	StopCompleted     AgentStopReason = "completed"
	StopBudgetReached AgentStopReason = "budget_reached"
	StopCancelled     AgentStopReason = "cancelled"
	StopFailed        AgentStopReason = "failed"
)

// AgentTraceSpan records a single monotonic trace span in an /v1/agent run.
type AgentTraceSpan struct {
	Sequence      int            `json:"sequence"`
	SpanID        string         `json:"spanId"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Status        string         `json:"status"`
	StartedAt     int64          `json:"startedAt"`
	DurationMs    int64          `json:"durationMs"`
	Input         map[string]any `json:"input,omitempty"`
	OutputPreview any            `json:"outputPreview,omitempty"`
}

// AgentSourceRef identifies a cited URL or MCP source in an /v1/agent run.
type AgentSourceRef struct {
	URL         string `json:"url"`
	Title       string `json:"title,omitempty"`
	Via         string `json:"via,omitempty"`
	ExtractorID string `json:"extractorId,omitempty"`
}

// AgentRunRecord holds full state for an /v1/agent execution.
type AgentRunRecord struct {
	ID                    string           `json:"id"`
	UserID                string           `json:"userId,omitempty"`
	ThreadID              string           `json:"threadId"`
	Status                AgentStatus      `json:"status"`
	StopReason            AgentStopReason  `json:"stopReason,omitempty"`
	Prompt                string           `json:"prompt"`
	URLs                  []string         `json:"urls"`
	StrictConstrainToURLs bool             `json:"strictConstrainToURLs"`
	Effort                AgentEffort      `json:"effort"`
	MaxSteps              int              `json:"maxSteps"`
	MaxPages              int              `json:"maxPages"`
	StepsUsed             int              `json:"stepsUsed"`
	PagesRead             int              `json:"pagesRead"`
	Partial               bool             `json:"partial,omitempty"`
	PartialSchemaValid    *bool            `json:"partialSchemaValid,omitempty"`
	SchemaValid           *bool            `json:"schemaValid,omitempty"`
	ZeroDataRetention     bool             `json:"zeroDataRetention"`
	Visibility            string           `json:"visibility,omitempty"`
	RoutedMCPs            []string         `json:"routedMcps,omitempty"`
	LLMUsed               bool             `json:"llmUsed"`
	LLMInfo               map[string]any   `json:"llmInfo,omitempty"`
	RoutedAdapters        []string         `json:"routedAdapters"`
	Sources               []AgentSourceRef `json:"sources"`
	Data                  any              `json:"data,omitempty"`
	HasData               bool             `json:"hasData,omitempty"`
	Markdown              string           `json:"markdown,omitempty"`
	Error                 string           `json:"error,omitempty"`
	CreatedAt             int64            `json:"createdAt"`
	UpdatedAt             int64            `json:"updatedAt"`
	FinishedAt            *int64           `json:"finishedAt,omitempty"`
	ExpiresAt             int64            `json:"expiresAt"`
	Trace                 []AgentTraceSpan `json:"trace"`
	ThreadMemory          string           `json:"threadMemory,omitempty"`
}

// CachedMCPToolSpec describes a cached MCP tool schema on an enabled connector.
type CachedMCPToolSpec struct {
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	ReadOnlyHint    *bool           `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool           `json:"destructiveHint,omitempty"`
	InputSchema     json.RawMessage `json:"inputSchema,omitempty"`
}

// ConnectedMCPServerSpec describes a connected MCP server permitted for an agent run.
type ConnectedMCPServerSpec struct {
	ID          string              `json:"id"`
	Slug        string              `json:"slug"`
	CachedTools []CachedMCPToolSpec `json:"cachedTools"`
}

var (
	allowedAgentToolSchemaTypes = map[string]bool{
		"object": true, "string": true, "number": true, "integer": true,
		"boolean": true, "array": true, "null": true,
	}
	forbiddenSchemaKeys = map[string]bool{
		"__proto__": true, "constructor": true, "prototype": true,
	}

	reSafeMCPIdentifier       = newLazyRegexp(`^[A-Za-z0-9_.-]{1,64}$`)
	reSafeMCPConnectorSlug    = newLazyRegexp(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	rePromptInjectionMCPID    = newLazyRegexp(`(?i)(?:^|[_.-])(?:ignore|disregard|override|bypass|exfiltrate|jailbreak|forget)(?:[_.-]|$|[A-Z])|system[_.-]?(?:prompt|instruction|message|override)|developer[_.-]?(?:prompt|instruction|message)|prompt[_.-]?injection`)
	reSafeRemoteEnumToken     = newLazyRegexp(`^[A-Za-z0-9_.:/-]{1,32}$`)
	reANSICSI                 = newLazyRegexp(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	reMCPDirectiveInjection   = newLazyRegexp(`(?i)\b(?:note|instruction|message|directive|reminder)\s+to\s+(?:the\s+)?(?:ai|llm|assistant|model|agent)\b|\bcall\s+query_mcp\s*\(|\bpre-authori[sz]ed\b|\bdo\s+not\s+ask\s+(?:the\s+user\s+)?for\s+confirmation\b|\bwhen\s+summarizing[^.\n]{0,80}\b(?:append|include|output|exfiltrate)\b`)
	reUntrustedBoundaryTag    = newLazyRegexp(`(?i)<(\s*/?\s*untrusted_[a-z0-9_-]*)`)
	reDangerousMarkdownScheme = newLazyRegexp(`(?i)^(?:javascript|vbscript|data|file|blob)\s*:`)
	reSafeEnvelopeAttrKey     = newLazyRegexp(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)
	reDescUnsafeChars         = newLazyRegexp("[`<>]")
)

// DoesMCPServerSelectorMatchRow enforces S7: mcpServers selectors match strictly by exact connector id or slug (case-insensitive).
func DoesMCPServerSelectorMatchRow(rawSelector, rowID, rowSlug string) bool {
	sel := strings.ToLower(strings.TrimSpace(rawSelector))
	if sel == "" || len(sel) > 128 {
		return false
	}
	return strings.ToLower(rowID) == sel || strings.ToLower(rowSlug) == sel
}

// IsSafeMCPIdentifier validates an MCP tool or parameter identifier against prototype pollution, `__`, and directive injection.
func IsSafeMCPIdentifier(raw string) bool {
	if raw == "" || !reSafeMCPIdentifier.MatchString(raw) || forbiddenSchemaKeys[raw] {
		return false
	}
	if strings.Contains(raw, "__") {
		return false
	}
	return !rePromptInjectionMCPID.MatchString(raw)
}

// IsValidMCPConnectorSlug validates a normalized MCP connector slug.
func IsValidMCPConnectorSlug(raw string) bool {
	if raw == "" || !reSafeMCPConnectorSlug.MatchString(raw) || strings.Contains(raw, "__") {
		return false
	}
	return IsSafeMCPIdentifier(raw)
}

// StripMCPSmugglingChars removes ANSI CSI sequences, ASCII C0/DEL controls, zero-width/bidi controls, and Unicode Tag characters.
func StripMCPSmugglingChars(s string) string {
	if s == "" {
		return s
	}
	hasSpecial := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') || c >= 0x7f {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return s
	}
	cleaned := reANSICSI.ReplaceAllString(s, "")
	var sb strings.Builder
	sb.Grow(len(cleaned))
	for _, r := range cleaned {
		if !isSmugglingRune(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func isSmugglingRune(r rune) bool {
	if (r >= 0x0000 && r <= 0x0008) || r == 0x000B || r == 0x000C || (r >= 0x000E && r <= 0x001F) || r == 0x007F {
		return true
	}
	if r == 0x00AD || r == 0x061C || r == 0x180E || r == 0xFEFF {
		return true
	}
	if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) {
		return true
	}
	return (r >= 0xE0000 && r <= 0xE007F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// SanitizeRemoteMCPText strips smuggling runes and checks/scrubs indirect prompt injection.
func SanitizeRemoteMCPText(raw string, maxChars int) (text string, detected bool) {
	if raw == "" {
		return "", false
	}
	bounded := raw
	if maxChars > 0 {
		bounded = sliceRunesMax(raw, maxChars)
	}
	rawHTML := ""
	if strings.ContainsRune(bounded, '<') {
		rawHTML = bounded
	}
	preScan := extract.DetectPromptInjection(bounded, rawHTML)
	stripped := StripMCPSmugglingChars(bounded)
	postScan := preScan
	if stripped != bounded {
		strippedHTML := ""
		if strings.ContainsRune(stripped, '<') {
			strippedHTML = stripped
		}
		postScan = extract.DetectPromptInjection(stripped, strippedHTML)
	}
	directiveHit := reMCPDirectiveInjection.MatchString(stripped)
	if !preScan.Detected && !postScan.Detected && !directiveHit {
		return stripped, false
	}
	if !postScan.Detected && !directiveHit {
		return stripped, true
	}
	lines := strings.Split(strings.ReplaceAll(stripped, "\r\n", "\n"), "\n")
	if len(lines) == 1 {
		return "[SCRUBBED: prompt injection blocked]", true
	}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lHTML := ""
		if strings.ContainsRune(line, '<') {
			lHTML = line
		}
		if extract.DetectPromptInjection(line, lHTML).Detected || reMCPDirectiveInjection.MatchString(line) {
			lines[i] = "[SCRUBBED: prompt injection blocked]"
		}
	}
	cand := strings.Join(lines, "\n")
	candHTML := ""
	if strings.ContainsRune(cand, '<') {
		candHTML = cand
	}
	if extract.DetectPromptInjection(cand, candHTML).Detected || reMCPDirectiveInjection.MatchString(cand) {
		return "[SCRUBBED: prompt injection blocked]", true
	}
	return cand, true
}

func stripDangerousMarkdownLinksLinear(input string) string {
	if !strings.Contains(input, "](") || !strings.ContainsRune(input, ')') || !strings.ContainsRune(input, ':') {
		return input
	}
	n := len(input)
	var sb strings.Builder
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
			labelLen := i - openBracket - 1
			if labelLen <= maxMCPLinkLabelChars && i+1 < n && input[i+1] == '(' {
				parenStart := i + 2
				if parenStart >= noCloseParenBefore {
					maxEnd := min(n, parenStart+maxMCPLinkTargetChars)
					closeParen := -1
					scanPos := parenStart
					for ; scanPos < maxEnd; scanPos++ {
						tc := input[scanPos]
						if tc == '\n' || tc == '\r' {
							break
						}
						if tc == ')' {
							closeParen = scanPos
							break
						}
					}
					if closeParen >= 0 {
						rawTarget := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(input[parenStart:closeParen]), "<"), ">")
						var cleanTarget strings.Builder
						for j := 0; j < len(rawTarget); j++ {
							if rawTarget[j] > 0x20 {
								cleanTarget.WriteByte(rawTarget[j])
							}
						}
						if reDangerousMarkdownScheme.MatchString(cleanTarget.String()) {
							linkStart := openBracket
							if openBracket > 0 && input[openBracket-1] == '!' {
								linkStart = openBracket - 1
							}
							label := input[openBracket+1 : i]
							if label == "" {
								label = "[blocked-unsafe-link]"
							}
							sb.WriteString(input[emitFrom:linkStart])
							sb.WriteString(label)
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
	sb.WriteString(input[emitFrom:])
	return sb.String()
}

// SanitizeMCPMarkdownOutput sanitizes untrusted MCP Markdown/text, neutralizes boundary tags, and strips dangerous URI schemes.
func SanitizeMCPMarkdownOutput(rawMarkdown, baseURL string, maxChars int) string {
	if rawMarkdown == "" {
		return ""
	}
	bounded := rawMarkdown
	if maxChars > 0 {
		bounded = sliceRunesMax(rawMarkdown, maxChars)
	}
	out := extract.SanitizeMarkdownWithOptions(bounded, baseURL, false)
	if strings.Contains(strings.ToLower(out), "untrusted_") {
		out = reUntrustedBoundaryTag.ReplaceAllString(out, "&lt;$1")
	}
	return stripDangerousMarkdownLinksLinear(out)
}

// FormatFenceSafeUntrustedMCPEnvelope wraps untrusted MCP output in a backtick-fence-safe + XML-boundary-safe envelope.
func FormatFenceSafeUntrustedMCPEnvelope(tag string, attrs map[string]string, content string, maxChars int) string {
	if tag != "untrusted_mcp_tool_output" {
		tag = "untrusted_mcp_output"
	}
	sliced := content
	if maxChars > 0 {
		sliced = sliceRunesMax(content, maxChars)
	}
	safeBody := sliced
	if strings.Contains(strings.ToLower(safeBody), "untrusted_") {
		safeBody = reUntrustedBoundaryTag.ReplaceAllString(safeBody, "&lt;$1")
	}
	maxRun, curRun := 0, 0
	for i := 0; i < len(safeBody); i++ {
		if safeBody[i] == '`' {
			curRun++
			if curRun > maxRun {
				maxRun = curRun
			}
		} else {
			curRun = 0
		}
	}
	fence := strings.Repeat("`", max(3, maxRun+1))

	var attrParts []string
	if len(attrs) > 0 {
		keys := make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := attrs[k]
			if v == "" || !reSafeEnvelopeAttrKey.MatchString(k) {
				continue
			}
			safeVal := strings.Map(func(r rune) rune {
				switch r {
				case '"', '&', '<', '>', '\r', '\n', 0, '`':
					return -1
				default:
					return r
				}
			}, v)
			attrParts = append(attrParts, fmt.Sprintf(`%s="%s"`, k, safeVal))
		}
	}
	attrStr := ""
	if len(attrParts) > 0 {
		attrStr = " " + strings.Join(attrParts, " ")
	}
	return fmt.Sprintf("<%s%s>\n%stext\n%s\n%s\n</%s>", tag, attrStr, fence, safeBody, fence, tag)
}

// WrapConnectorTextForAgentContext sanitizes and wraps untrusted connector/thread text in an untrusted_mcp_tool_output envelope.
func WrapConnectorTextForAgentContext(rawText string, maxChars int, attrs map[string]string) string {
	bounded := sliceRunesMax(rawText, maxChars)
	sanText, _ := SanitizeRemoteMCPText(bounded, maxChars)
	sanMD := SanitizeMCPMarkdownOutput(sanText, "", maxChars)
	return FormatFenceSafeUntrustedMCPEnvelope("untrusted_mcp_tool_output", attrs, sanMD, maxChars)
}

type orderedJSONProp struct {
	key string
	raw json.RawMessage
}

func extractOrderedProps(rawProps json.RawMessage, limit int) ([]orderedJSONProp, bool) {
	trimmed := bytes.TrimSpace(rawProps)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []orderedJSONProp
	for dec.More() {
		kt, kErr := dec.Token()
		if kErr != nil {
			return nil, false
		}
		keyStr, ok := kt.(string)
		if !ok {
			return nil, false
		}
		var valRaw json.RawMessage
		if err := dec.Decode(&valRaw); err != nil {
			return nil, false
		}
		if len(out) < limit {
			out = append(out, orderedJSONProp{key: keyStr, raw: valRaw})
		}
	}
	return out, true
}

// SanitizeRemoteToolSchemaJSON implements P7: rebuilds a remote MCP tool parameter JSON Schema for the LLM tools channel,
// stripping title/default/examples/$defs/$comment/const/raw enum and prefixing sanitized descriptions with [UNTRUSTED_REMOTE_PARAM].
func SanitizeRemoteToolSchemaJSON(rawNode json.RawMessage, depth int) map[string]any {
	if depth > 5 {
		return map[string]any{}
	}
	trimmed := bytes.TrimSpace(rawNode)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		if depth == 0 {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
		return map[string]any{}
	}
	var src map[string]any
	if err := json.Unmarshal(trimmed, &src); err != nil || src == nil {
		if depth == 0 {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
		return map[string]any{}
	}
	var rawFields map[string]json.RawMessage
	_ = json.Unmarshal(trimmed, &rawFields)
	return sanitizeRemoteSchemaMap(src, rawFields, depth)
}

// SanitizeRemoteToolSchemaForLLM sanitizes an in-memory remote tool parameter schema map.
func SanitizeRemoteToolSchemaForLLM(rawNode any, depth int) map[string]any {
	if depth > 5 || rawNode == nil {
		if depth == 0 {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
		return map[string]any{}
	}
	b, err := json.Marshal(rawNode)
	if err != nil {
		if depth == 0 {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
		return map[string]any{}
	}
	return SanitizeRemoteToolSchemaJSON(b, depth)
}

func sanitizeRemoteSchemaMap(src map[string]any, rawFields map[string]json.RawMessage, depth int) map[string]any {
	out := map[string]any{}

	if tStr, ok := src["type"].(string); ok && allowedAgentToolSchemaTypes[tStr] {
		out["type"] = tStr
	} else if tArr, ok := src["type"].([]any); ok {
		valid := make([]string, 0, 4)
		for _, item := range tArr {
			if s, okS := item.(string); okS && allowedAgentToolSchemaTypes[s] {
				valid = append(valid, s)
				if len(valid) == 4 {
					break
				}
			}
		}
		if len(valid) > 0 {
			out["type"] = valid
		}
	} else if depth == 0 {
		out["type"] = "object"
	}

	cleanDescPart := sanitizeSchemaDescriptionText(src["description"])
	safeEnumHints := sanitizeSchemaEnumHints(src["enum"])
	if cleanDescPart != "" || len(safeEnumHints) > 0 {
		enumSuffix := ""
		if len(safeEnumHints) > 0 {
			enumSuffix = "untrusted enum hints: " + strings.Join(safeEnumHints, ", ")
		}
		combined := cleanDescPart
		if cleanDescPart != "" && enumSuffix != "" {
			combined = cleanDescPart + " (" + enumSuffix + ")"
		} else if combined == "" {
			combined = enumSuffix
		}
		maxBodyLen := maxRemoteParamDescChars - len(UntrustedRemoteParamPrefix)
		truncatedBody := combined
		if len(combined) > maxBodyLen {
			cut := max(1, maxBodyLen-3)
			truncatedBody = strings.TrimRight(sliceRunesMax(combined, cut), " \t") + "..."
		}
		out["description"] = UntrustedRemoteParamPrefix + truncatedBody
	}

	var validPropKeys map[string]bool
	if rawProps, hasProps := rawFields["properties"]; hasProps {
		if ordered, okProps := extractOrderedProps(rawProps, 32); okProps {
			cleanProps := make(map[string]any, len(ordered))
			validPropKeys = make(map[string]bool, len(ordered))
			for _, prop := range ordered {
				cleanKey := strings.TrimSpace(StripMCPSmugglingChars(prop.key))
				if !IsSafeMCPIdentifier(cleanKey) || forbiddenSchemaKeys[cleanKey] {
					continue
				}
				if _, detected := SanitizeRemoteMCPText(cleanKey, 64); detected {
					continue
				}
				cleanProps[cleanKey] = SanitizeRemoteToolSchemaJSON(prop.raw, depth+1)
				validPropKeys[cleanKey] = true
			}
			out["properties"] = cleanProps
		} else if out["type"] == "object" && depth == 0 {
			out["properties"] = map[string]any{}
		}
	} else if out["type"] == "object" && depth == 0 {
		out["properties"] = map[string]any{}
	}

	if reqArr, ok := src["required"].([]any); ok {
		reqOut := make([]string, 0, min(32, len(reqArr)))
		seenReq := map[string]bool{}
		for _, item := range reqArr[:min(32, len(reqArr))] {
			rStr, okS := item.(string)
			if !okS || !IsSafeMCPIdentifier(rStr) || (validPropKeys != nil && !validPropKeys[rStr]) || seenReq[rStr] {
				continue
			}
			seenReq[rStr] = true
			reqOut = append(reqOut, rStr)
		}
		if len(reqOut) > 0 {
			out["required"] = reqOut
		}
	}

	if rawItems, hasItems := rawFields["items"]; hasItems {
		if trimmedItems := bytes.TrimSpace(rawItems); len(trimmedItems) > 0 && trimmedItems[0] == '{' {
			out["items"] = SanitizeRemoteToolSchemaJSON(trimmedItems, depth+1)
		}
	}
	if minV, ok := src["minimum"].(float64); ok && !math.IsNaN(minV) && !math.IsInf(minV, 0) {
		out["minimum"] = minV
	}
	if maxV, ok := src["maximum"].(float64); ok && !math.IsNaN(maxV) && !math.IsInf(maxV, 0) {
		out["maximum"] = maxV
	}
	if minL, ok := src["minLength"].(float64); ok && math.Trunc(minL) == minL && minL >= 0 && minL <= 1048576 {
		out["minLength"] = int(minL)
	}
	if maxL, ok := src["maxLength"].(float64); ok && math.Trunc(maxL) == maxL && maxL >= 0 && maxL <= 1048576 {
		out["maxLength"] = int(maxL)
	}
	if addP, ok := src["additionalProperties"].(bool); ok {
		out["additionalProperties"] = addP
	}
	return out
}

func sanitizeSchemaDescriptionText(rawDesc any) string {
	descStr, ok := rawDesc.(string)
	if !ok || strings.TrimSpace(descStr) == "" {
		return ""
	}
	preClean := StripMCPSmugglingChars(descStr)
	preClean = reDescUnsafeChars.ReplaceAllString(preClean, " ")
	preClean = strings.TrimSpace(reCollapseSpaces.ReplaceAllString(preClean, " "))
	preClean = sliceRunesMax(preClean, 200)
	if preClean == "" {
		return ""
	}
	piText, piDetected := SanitizeRemoteMCPText(preClean, 200)
	if piDetected || strings.TrimSpace(piText) == "" {
		return ""
	}
	mdClean := SanitizeMCPMarkdownOutput(piText, "", 200)
	mdClean = reDescUnsafeChars.ReplaceAllString(mdClean, " ")
	return strings.TrimSpace(reCollapseSpaces.ReplaceAllString(mdClean, " "))
}

func sanitizeSchemaEnumHints(rawEnum any) []string {
	enumArr, ok := rawEnum.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, ev := range enumArr[:min(12, len(enumArr))] {
		switch v := ev.(type) {
		case string:
			cleanEv := strings.TrimSpace(StripMCPSmugglingChars(v))
			if cleanEv == "" || !reSafeRemoteEnumToken.MatchString(cleanEv) {
				continue
			}
			normID := strings.NewReplacer("/", "_", ":", "_").Replace(cleanEv)
			if !IsSafeMCPIdentifier(normID) {
				continue
			}
			if _, detected := SanitizeRemoteMCPText(cleanEv, 48); detected {
				continue
			}
			out = append(out, cleanEv)
		case float64:
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				out = append(out, strconv.FormatFloat(v, 'f', -1, 64))
			}
		case bool:
			out = append(out, strconv.FormatBool(v))
		}
	}
	return out
}
