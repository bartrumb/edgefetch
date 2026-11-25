package extract

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxHTMLScanBytesSliceGo = 2 * 1024 * 1024

// MarkdownSliceEscapedUntrusted records an escaped untrusted fence opener across slice checkpoints.
type MarkdownSliceEscapedUntrusted struct {
	Ch             string `json:"ch"`
	Len            int    `json:"len"`
	NeedBlockquote bool   `json:"needBlockquote"`
}

// MarkdownSliceCheckpoint stores canonical CommonMark fence-recognizer state at periodic offsets.
type MarkdownSliceCheckpoint struct {
	Pos                   int                            `json:"pos"`
	UTF16Pos              *int                           `json:"utf16Pos,omitempty"`
	InFence               bool                           `json:"inFence"`
	FenceChar             string                         `json:"fenceChar"`
	FenceLen              int                            `json:"fenceLen"`
	EffectiveFenceLen     int                            `json:"effectiveFenceLen"`
	FenceIndent           int                            `json:"fenceIndent"`
	ActiveListIndent      int                            `json:"activeListIndent"`
	ListIndents           []int                          `json:"listIndents,omitempty"`
	PrevLineWasParagraph  bool                           `json:"prevLineWasParagraph"`
	PrevLineWasAsciiBlank bool                           `json:"prevLineWasAsciiBlank"`
	PossiblyInList        bool                           `json:"possiblyInList"`
	EscapedUntrusted      *MarkdownSliceEscapedUntrusted `json:"escapedUntrusted"`
}

// ReopenedMarkdownFence describes an open top-level fenced code block carried into a slice.
type ReopenedMarkdownFence struct {
	Ch           string `json:"ch"`
	Len          int    `json:"len"`
	EffectiveLen int    `json:"effectiveLen,omitempty"`
}

// MarkdownFenceRecognizerState represents the exported state of the canonical CommonMark fence recognizer.
type MarkdownFenceRecognizerState struct {
	InFence               bool
	FenceChar             string
	FenceLen              int
	EffectiveFenceLen     int
	PrevLineWasAsciiBlank bool
	PossiblyInList        bool
	EscapedUntrusted      *MarkdownSliceEscapedUntrusted
}

// RecognizeMarkdownFencesOptions configures RecognizeAndHardenMarkdownFences.
type RecognizeMarkdownFencesOptions struct {
	Harden                        bool
	PreserveCrLf                  bool
	InitialReopenedFence          *ReopenedMarkdownFence
	InitialState                  *MarkdownFenceRecognizerState
	SkipLeadingSeparatorEmptyLine bool
}

// AttrSelectorSpec specifies a CSS selector and target HTML attribute name for ExtractHTMLAttributesBySelectors.
type AttrSelectorSpec struct {
	Selector  string `json:"selector"`
	Attribute string `json:"attribute"`
}

// AttrSelectorItem holds extracted HTML attribute values matching an AttrSelectorSpec.
type AttrSelectorItem struct {
	Selector  string   `json:"selector"`
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
}

var (
	reAttrSelectorBracketSliceGo = regexp.MustCompile(`\[([a-zA-Z0-9_:-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]`)
	reAttrSelectorIDSliceGo      = regexp.MustCompile(`#([a-zA-Z0-9_-]+)`)
	reAttrSelectorClassSliceGo   = regexp.MustCompile(`\.([a-zA-Z0-9_-]+)`)
	reSimpleTagNameSliceGo       = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)
	reOpenTagAttrPairSliceGo     = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+)))?`)
	reJsonLdScriptTypeSliceGo    = regexp.MustCompile(`(?i)\btype[ \t\r\n]*=[ \t\r\n]*(?:"application/ld\+json(?:[ \t]*;[^"]*)?[ \t]*"|'application/ld\+json(?:[ \t]*;[^']*)?[ \t]*'|application/ld\+json(?:;[^ \t\r\n"'>]*)?(?:[ \t\r\n/>]|$))`)
	reProductTypeNameSliceGo     = regexp.MustCompile(`(?i)^(?:schema:)?(?:Product|ProductGroup|IndividualProduct|SoftwareApplication)$`)
	reSchemaOrgPrefixSliceGo     = regexp.MustCompile(`(?i)^https?://schema\.org/`)
	reBarcodeProductPathSliceGo  = regexp.MustCompile(`(?i)/product/(\d{8,14})(?:/|$)`)
)

var disallowedHostSuffixesSliceGo = []string{
	".localhost",
	".local",
	".internal",
	".arpa",
	".intranet",
	".corp",
	".lan",
	".nip.io",
	".sslip.io",
	".xip.io",
	".localtest.me",
	".lvh.me",
	".vcap.me",
	".traefik.me",
	".1u.ms",
	".rebind.network",
}

var disallowedExactHostsSliceGo = map[string]bool{
	"localhost":                  true,
	"nip.io":                     true,
	"sslip.io":                   true,
	"xip.io":                     true,
	"localtest.me":               true,
	"lvh.me":                     true,
	"vcap.me":                    true,
	"traefik.me":                 true,
	"1u.ms":                      true,
	"rebind.network":             true,
	"metadata.goog":              true,
	"metadata.google.internal":   true,
	"instance-data.ec2.internal": true,
}

var dangerousBlockTagsSliceGo = map[string]bool{
	"script":   true,
	"style":    true,
	"noscript": true,
	"template": true,
	"iframe":   true,
	"svg":      true,
	"object":   true,
	"embed":    true,
}

func minIntSliceGo(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxIntSliceGo(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func asciiLowerSliceGo(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 'A' && b <= 'Z' {
			b |= 0x20
		}
		buf[i] = b
	}
	return string(buf)
}

func isAsciiSpaceOrTabOnlySliceGo(s string, start, end int) bool {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	for i := start; i < end; i++ {
		c := s[i]
		if c != ' ' && c != '\t' {
			return false
		}
	}
	return true
}

// UTF16OffsetToByteOffset converts a JavaScript/UTF-16 code-unit offset into a valid UTF-8 byte offset in s.
func UTF16OffsetToByteOffset(s string, utf16Off int) int {
	if utf16Off <= 0 || s == "" {
		return 0
	}
	byteIdx := 0
	u16Idx := 0
	n := len(s)
	for byteIdx < n && u16Idx < utf16Off {
		for byteIdx < n && u16Idx < utf16Off && s[byteIdx] < 0x80 {
			byteIdx++
			u16Idx++
		}
		if byteIdx >= n || u16Idx >= utf16Off {
			break
		}
		r, w := utf8.DecodeRuneInString(s[byteIdx:])
		if r > 0xFFFF {
			if u16Idx+1 == utf16Off {
				return byteIdx
			}
			u16Idx += 2
			byteIdx += w
		} else {
			u16Idx++
			byteIdx += w
		}
	}
	return byteIdx
}

// NeutralizeAllUnsafeMarkdownLinks neutralizes disallowed inline `](...)` destinations, `[id]: ...`
// reference definitions, and bare `//host.tld` protocol-relative URLs in linear O(N) time.
func NeutralizeAllUnsafeMarkdownLinks(prose string) string {
	return neutralizeAllUnsafeMarkdownLinksLinearGo(prose)
}

// IsDisallowedMarkdownLinkDestination reports whether rawHref violates the strict fail-closed URI allowlist.
func IsDisallowedMarkdownLinkDestination(rawHref string) bool {
	if rawHref == "" {
		return false
	}
	if len(rawHref) > 8192 {
		return true
	}
	if isDisallowedMarkdownLinkDestinationGo(rawHref) {
		return true
	}
	// Enforce TS 4,096-codepoint clean ceiling on delimiter-free oversize destinations.
	if len(rawHref) > 4096 {
		unescaped := rawHref
		if strings.IndexByte(unescaped, '\\') >= 0 {
			var sb strings.Builder
			sb.Grow(len(unescaped))
			for i := 0; i < len(unescaped); i++ {
				if unescaped[i] == '\\' && i+1 < len(unescaped) && isASCIIPunctByte(unescaped[i+1]) {
					sb.WriteByte(unescaped[i+1])
					i++
				} else {
					sb.WriteByte(unescaped[i])
				}
			}
			unescaped = sb.String()
		}
		decoded := decodeURIEntitiesLinearGo(unescaped)
		cpCount := 0
		sawDelim := false
		for _, r := range decoded {
			if isIgnorableURIRuneGo(r) {
				continue
			}
			if r == '/' || r == '?' || r == '#' || r == ':' {
				sawDelim = true
			}
			cpCount++
			if cpCount >= 256 && sawDelim {
				break
			}
			if cpCount > 4096 {
				return true
			}
		}
	}
	return false
}

// EscapeGfmTaskListCheckboxes escapes GFM task-list checkboxes (`- [ ] `, `* [x] `, `1. [X] `) in linear O(N) time.
func EscapeGfmTaskListCheckboxes(prose string) string {
	return escapeGfmTaskListCheckboxesLinearGo(prose)
}

// EscapeAllResidualLtInProse escapes every `<` to `&lt;` outside verified standalone PDF page markers.
func EscapeAllResidualLtInProse(prose string, allowPdfPageMarkers bool) string {
	return escapeAllResidualLtInProseLinearGo(prose, allowPdfPageMarkers)
}

// StripInvisibleSmugglingChars strips invisible Unicode Tag smuggling, variation selectors, bidi controls,
// zero-width characters, ANSI CSI sequences, and raw C0/C1 control bytes.
func StripInvisibleSmugglingChars(s string) string {
	return stripInvisibleSmugglingCharsGo(s)
}

// CleanFenceInfoString sanitizes fenced code block info strings in linear time.
func CleanFenceInfoString(rawInfo string) string {
	return cleanFenceInfoStringLinearGo(rawInfo)
}

func normalizeMarkdownLineEndingsUpfrontSliceGo(raw string) string {
	if strings.IndexByte(raw, '\r') < 0 &&
		!strings.Contains(raw, "\u0085") &&
		!strings.Contains(raw, "\u2028") &&
		!strings.Contains(raw, "\u2029") {
		return raw
	}
	var sb strings.Builder
	sb.Grow(len(raw))
	for i := 0; i < len(raw); {
		b := raw[i]
		if b == '\r' {
			sb.WriteByte('\n')
			if i+1 < len(raw) && raw[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			continue
		}
		if b < 0x80 {
			sb.WriteByte(b)
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(raw[i:])
		if r == 0x0085 || r == 0x2028 || r == 0x2029 {
			sb.WriteByte(' ')
		} else {
			sb.WriteString(raw[i : i+w])
		}
		i += w
	}
	return sb.String()
}

func normalizeSliceLineEndingsSliceGo(s string) (out string, hadMultiByteLineSep bool) {
	hasCR := strings.IndexByte(s, '\r') >= 0
	hasNEL := strings.Contains(s, "\u0085")
	hasLS := strings.Contains(s, "\u2028") || strings.Contains(s, "\u2029")
	if !hasCR && !hasNEL && !hasLS {
		return s, false
	}
	// Check if every '\r' is already part of '\r\n' when no Unicode line separators exist.
	if !hasNEL && !hasLS {
		hasBareCR := false
		for i := 0; i < len(s); i++ {
			if s[i] == '\r' && (i+1 >= len(s) || s[i+1] != '\n') {
				hasBareCR = true
				break
			}
		}
		if !hasBareCR {
			return s, false
		}
		buf := []byte(s)
		for i := 0; i < len(buf); i++ {
			if buf[i] == '\r' && (i+1 >= len(buf) || buf[i+1] != '\n') {
				buf[i] = '\n'
			}
		}
		return string(buf), false
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		b := s[i]
		if b == '\r' {
			if i+1 < len(s) && s[i+1] == '\n' {
				sb.WriteString("\r\n")
				i += 2
			} else {
				sb.WriteByte('\n')
				i++
			}
			continue
		}
		if b < 0x80 {
			sb.WriteByte(b)
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if r == 0x0085 || r == 0x2028 || r == 0x2029 {
			sb.WriteByte(' ')
		} else {
			sb.WriteString(s[i : i+w])
		}
		i += w
	}
	return sb.String(), true
}

func cloneInternalFenceStateSliceGo(s mdFenceRecognizerStateGo) mdFenceRecognizerStateGo {
	out := s
	if s.escapedUntrusted != nil {
		cp := *s.escapedUntrusted
		out.escapedUntrusted = &cp
	}
	if s.untrustedFence != nil {
		cp := *s.untrustedFence
		out.untrustedFence = &cp
	}
	return out
}

func toExportedFenceStateSliceGo(s mdFenceRecognizerStateGo) MarkdownFenceRecognizerState {
	fc := ""
	if s.fenceChar == '`' || s.fenceChar == '~' {
		fc = string(s.fenceChar)
	}
	var esc *MarkdownSliceEscapedUntrusted
	if s.escapedUntrusted != nil {
		esc = &MarkdownSliceEscapedUntrusted{
			Ch:             string(s.escapedUntrusted.ch),
			Len:            s.escapedUntrusted.length,
			NeedBlockquote: s.escapedUntrusted.needBlockquote,
		}
	}
	return MarkdownFenceRecognizerState{
		InFence:               s.inFence,
		FenceChar:             fc,
		FenceLen:              s.fenceLen,
		EffectiveFenceLen:     s.effectiveFenceLen,
		PrevLineWasAsciiBlank: s.prevLineWasASCIIBlank,
		PossiblyInList:        s.possiblyInList,
		EscapedUntrusted:      esc,
	}
}

func fromExportedFenceStateSliceGo(s *MarkdownFenceRecognizerState) mdFenceRecognizerStateGo {
	if s == nil {
		return mdFenceRecognizerStateGo{prevLineWasASCIIBlank: true}
	}
	var fc byte
	if s.FenceChar == "`" || s.FenceChar == "~" {
		fc = s.FenceChar[0]
	}
	var esc *escapedUntrustedFenceGo
	if s.EscapedUntrusted != nil && (s.EscapedUntrusted.Ch == "`" || s.EscapedUntrusted.Ch == "~") {
		esc = &escapedUntrustedFenceGo{
			ch:             s.EscapedUntrusted.Ch[0],
			length:         s.EscapedUntrusted.Len,
			needBlockquote: s.EscapedUntrusted.NeedBlockquote,
		}
	}
	return mdFenceRecognizerStateGo{
		inFence:               s.InFence,
		fenceChar:             fc,
		fenceLen:              s.FenceLen,
		effectiveFenceLen:     s.EffectiveFenceLen,
		prevLineWasASCIIBlank: s.PrevLineWasAsciiBlank,
		possiblyInList:        s.PossiblyInList,
		escapedUntrusted:      esc,
	}
}

// RecognizeAndHardenMarkdownFences runs the single canonical CommonMark fence recognizer & hardener
// (`stepCanonicalMarkdownFenceLineGo` in `sanitize.go`), returning the hardened document and alternating
// `[prose, fence, prose, ...]` segments.
func RecognizeAndHardenMarkdownFences(rawMD string, opts RecognizeMarkdownFencesOptions) (hardened string, segments []string) {
	harden := opts.Harden
	preserveCrLf := opts.PreserveCrLf
	reopened := opts.InitialReopenedFence
	if rawMD == "" && reopened == nil {
		return rawMD, []string{rawMD}
	}

	var md string
	if preserveCrLf {
		md, _ = normalizeSliceLineEndingsSliceGo(rawMD)
	} else {
		md = normalizeMarkdownLineEndingsUpfrontSliceGo(rawMD)
	}
	if reopened == nil && !strings.Contains(md, "```") && !strings.Contains(md, "~~~") {
		return md, []string{md}
	}

	lines := strings.Split(md, "\n")
	var outLines []string
	anyLineChanged := reopened != nil
	if reopened != nil {
		outLines = make([]string, 0, len(lines)+3)
	} else {
		outLines = lines
	}

	var fenceSpans []fenceSpanGo
	state := fromExportedFenceStateSliceGo(opts.InitialState)

	fenceOpenOutIdx := -1
	fenceOpenInfo := ""
	fenceOpenCr := ""

	if reopened != nil {
		ch := byte('`')
		if reopened.Ch == "~" {
			ch = '~'
		}
		effLen := reopened.Len
		if reopened.EffectiveLen > effLen {
			effLen = reopened.EffectiveLen
		}
		if effLen < 3 {
			effLen = 3
		}
		state.inFence = true
		state.fenceChar = ch
		state.fenceLen = reopened.Len
		state.effectiveFenceLen = effLen
		state.prevLineWasASCIIBlank = false
		fenceOpenOutIdx = 1
		fenceOpenInfo = ""
		fenceOpenCr = ""
		outLines = append(outLines, "", strings.Repeat(string(ch), effLen))
	}

	skipSepNl := reopened == nil && opts.SkipLeadingSeparatorEmptyLine

	for li := 0; li < len(lines); li++ {
		rawWithCr := lines[li]
		cr := ""
		raw := rawWithCr
		if preserveCrLf && len(rawWithCr) > 0 && rawWithCr[len(rawWithCr)-1] == '\r' {
			cr = "\r"
			raw = rawWithCr[:len(rawWithCr)-1]
		}

		if li == 0 && skipSepNl && !state.inFence {
			if reopened != nil {
				outLines = append(outLines, rawWithCr)
			}
			continue
		}

		activeFenceCh := state.fenceChar
		step := stepCanonicalMarkdownFenceLineGo(raw, &state, harden)

		switch step.kind {
		case fenceStepOpenTrustedGo:
			if reopened != nil {
				fenceOpenOutIdx = len(outLines)
			} else {
				fenceOpenOutIdx = li
			}
			fenceOpenInfo = step.openedInfo
			fenceOpenCr = cr
			nextLine := step.outLine + cr
			if reopened != nil {
				outLines = append(outLines, nextLine)
			} else if nextLine != rawWithCr {
				outLines[li] = nextLine
				anyLineChanged = true
			}
		case fenceStepCloseTrustedGo:
			nextLine := step.outLine + cr
			closeIdx := li
			if reopened != nil {
				closeIdx = len(outLines)
				outLines = append(outLines, nextLine)
			} else if nextLine != rawWithCr {
				outLines[li] = nextLine
				anyLineChanged = true
			}
			fenceSpans = append(fenceSpans, fenceSpanGo{openLine: fenceOpenOutIdx, closeLine: closeIdx})
			fenceOpenOutIdx = -1
			fenceOpenInfo = ""
			fenceOpenCr = ""
		case fenceStepInTrustedGo:
			if harden && step.lengthenedEffectiveLen > 0 && fenceOpenOutIdx >= 0 {
				outLines[fenceOpenOutIdx] = strings.Repeat(string(activeFenceCh), step.lengthenedEffectiveLen) + fenceOpenInfo + fenceOpenCr
				anyLineChanged = true
			}
			if reopened != nil {
				outLines = append(outLines, step.outLine+cr)
			}
		default:
			nextLine := step.outLine + cr
			if reopened != nil {
				outLines = append(outLines, nextLine)
			} else if nextLine != rawWithCr {
				outLines[li] = nextLine
				anyLineChanged = true
			}
		}
	}

	if state.inFence {
		if harden {
			outLines = append(outLines, strings.Repeat(string(state.fenceChar), state.effectiveFenceLen))
			anyLineChanged = true
		}
		fenceSpans = append(fenceSpans, fenceSpanGo{openLine: fenceOpenOutIdx, closeLine: len(outLines) - 1})
	}

	if anyLineChanged {
		hardened = strings.Join(outLines, "\n")
	} else {
		hardened = md
	}
	if len(fenceSpans) == 0 {
		return hardened, []string{hardened}
	}

	segments = make([]string, 0, len(fenceSpans)*2+1)
	lineCursor := 0
	prefixLeadingNewline := false
	for _, sp := range fenceSpans {
		proseText := strings.Join(outLines[lineCursor:sp.openLine], "\n")
		if prefixLeadingNewline {
			proseText = "\n" + proseText
		}
		if sp.openLine > lineCursor {
			proseText = proseText + "\n"
		}
		segments = append(segments, proseText)

		fenceText := strings.Join(outLines[sp.openLine:sp.closeLine+1], "\n")
		segments = append(segments, fenceText)

		lineCursor = sp.closeLine + 1
		prefixLeadingNewline = lineCursor < len(outLines)
	}

	if lineCursor < len(outLines) {
		tailText := strings.Join(outLines[lineCursor:], "\n")
		if prefixLeadingNewline {
			segments = append(segments, "\n"+tailText)
		} else {
			segments = append(segments, tailText)
		}
	} else {
		segments = append(segments, "")
	}

	return hardened, segments
}

// ComputeMarkdownSliceCheckpoints computes periodic canonical fence-recognizer checkpoints across rawFullMD.
func utf16UnitsInChunkSliceGo(s string) int {
	// Fast path for pure ASCII chunks
	allASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			allASCII = false
			break
		}
	}
	if allASCII {
		return len(s)
	}
	units := 0
	for _, r := range s {
		if r > 0xFFFF {
			units += 2
		} else {
			units++
		}
	}
	return units
}

func ComputeMarkdownSliceCheckpoints(rawFullMD string, stepChars int) []MarkdownSliceCheckpoint {
	if stepChars <= 0 {
		stepChars = 16384
	}
	checkpoints := make([]MarkdownSliceCheckpoint, 0)
	if rawFullMD == "" || len(rawFullMD) <= stepChars {
		return checkpoints
	}
	cleanProbe := stripInvisibleSmugglingCharsGo(stripAllNulBytesSliceGo(rawFullMD))
	fullMd, hadMultiByteLS := normalizeSliceLineEndingsSliceGo(rawFullMD)
	canTrackUTF16 := !hadMultiByteLS && cleanProbe == rawFullMD
	state := mdFenceRecognizerStateGo{prevLineWasASCIIBlank: true}
	nextCheckpointAt := stepChars
	pos := 0
	utf16Pos := 0
	n := len(fullMd)

	for pos < n {
		if pos >= nextCheckpointAt {
			fc := ""
			if state.fenceChar == '`' || state.fenceChar == '~' {
				fc = string(state.fenceChar)
			}
			activeListIndent := 0
			if state.possiblyInList {
				activeListIndent = 2
			}
			var esc *MarkdownSliceEscapedUntrusted
			if state.escapedUntrusted != nil {
				esc = &MarkdownSliceEscapedUntrusted{
					Ch:             string(state.escapedUntrusted.ch),
					Len:            state.escapedUntrusted.length,
					NeedBlockquote: state.escapedUntrusted.needBlockquote,
				}
			}
			var u16Ptr *int
			if canTrackUTF16 {
				u16Copy := utf16Pos
				u16Ptr = &u16Copy
			}
			checkpoints = append(checkpoints, MarkdownSliceCheckpoint{
				Pos:                   pos,
				UTF16Pos:              u16Ptr,
				InFence:               state.inFence,
				FenceChar:             fc,
				FenceLen:              state.fenceLen,
				EffectiveFenceLen:     state.effectiveFenceLen,
				FenceIndent:           0,
				ActiveListIndent:      activeListIndent,
				PrevLineWasParagraph:  !state.prevLineWasASCIIBlank,
				PrevLineWasAsciiBlank: state.prevLineWasASCIIBlank,
				PossiblyInList:        state.possiblyInList,
				EscapedUntrusted:      esc,
			})
			nextCheckpointAt = pos + stepChars
		}
		nlRel := strings.IndexByte(fullMd[pos:], '\n')
		lineEnd := n
		nextPos := n
		if nlRel >= 0 {
			lineEnd = pos + nlRel
			nextPos = lineEnd + 1
		}
		if canTrackUTF16 {
			utf16Pos += utf16UnitsInChunkSliceGo(fullMd[pos:nextPos])
		}
		rawLineEnd := lineEnd
		if rawLineEnd > pos && fullMd[rawLineEnd-1] == '\r' {
			rawLineEnd--
		}
		stepCanonicalMarkdownFenceLineGo(fullMd[pos:rawLineEnd], &state, true)
		pos = nextPos
	}
	return checkpoints
}

func stripAllNulBytesSliceGo(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

func escapeLeadingTicksOrTildesSliceGo(head string, minRun int) string {
	i := 0
	for i < len(head) && (head[i] == ' ' || head[i] == '\t') {
		i++
	}
	if i >= len(head) || (head[i] != '`' && head[i] != '~') {
		return head
	}
	ch := head[i]
	j := i
	for j < len(head) && head[j] == ch {
		j++
	}
	runLen := j - i
	if runLen < minRun {
		return head
	}
	var sb strings.Builder
	sb.Grow(len(head) + runLen)
	sb.WriteString(head[:i])
	for k := 0; k < runLen; k++ {
		sb.WriteByte('\\')
		sb.WriteByte(ch)
	}
	sb.WriteString(head[j:])
	return sb.String()
}

func escapeMidLineProseSliceHeadSliceGo(firstHeadBody string) string {
	escapedBody := escapeLeadingTicksOrTildesSliceGo(firstHeadBody, 3)

	// Escape `^([ \t]*)(?:([-+*])|(\d{1,9})([.)]))(?=[ \t]|$)`
	ws := 0
	for ws < len(escapedBody) && (escapedBody[ws] == ' ' || escapedBody[ws] == '\t') {
		ws++
	}
	if ws < len(escapedBody) {
		c := escapedBody[ws]
		if (c == '-' || c == '+' || c == '*') && (ws+1 == len(escapedBody) || escapedBody[ws+1] == ' ' || escapedBody[ws+1] == '\t') {
			escapedBody = escapedBody[:ws] + `\` + escapedBody[ws:]
		} else if c >= '0' && c <= '9' {
			d := ws
			for d < len(escapedBody) && d-ws < 9 && escapedBody[d] >= '0' && escapedBody[d] <= '9' {
				d++
			}
			if d > ws && d < len(escapedBody) && (escapedBody[d] == '.' || escapedBody[d] == ')') &&
				(d+1 == len(escapedBody) || escapedBody[d+1] == ' ' || escapedBody[d+1] == '\t') {
				escapedBody = escapedBody[:d] + `\` + escapedBody[d:]
			}
		}
	}

	// Escape `^([ \t]*)>`
	ws = 0
	for ws < len(escapedBody) && (escapedBody[ws] == ' ' || escapedBody[ws] == '\t') {
		ws++
	}
	if ws < len(escapedBody) && escapedBody[ws] == '>' {
		escapedBody = escapedBody[:ws] + `\>` + escapedBody[ws+1:]
	}

	// Escape `^ {0,3}(?=\[)` unclosed bracket or empty reference definition
	sp := 0
	for sp < len(escapedBody) && sp < 4 && escapedBody[sp] == ' ' {
		sp++
	}
	if sp <= 3 && sp < len(escapedBody) && escapedBody[sp] == '[' {
		bIdx := sp
		tail := escapedBody[bIdx:]
		qLimit := minIntSliceGo(len(tail), 1024)
		closeIdx := -1
		for q := 1; q < qLimit; q++ {
			qc := tail[q]
			if qc == '\\' {
				q++
				continue
			}
			if qc == ']' {
				closeIdx = q
				break
			}
		}
		if closeIdx < 0 && len(tail) < 1024 {
			escapedBody = escapedBody[:bIdx] + `\` + tail
		} else if closeIdx >= 0 && closeIdx+1 < len(tail) && tail[closeIdx+1] == ':' && isAsciiSpaceOrTabOnlySliceGo(tail, closeIdx+2, len(tail)) {
			escapedBody = escapedBody[:bIdx] + tail[:closeIdx+1] + `\` + tail[closeIdx+1:]
		}
	}
	return escapedBody
}

func findLastBlankParagraphStartSliceGo(s string) int {
	tailParaStart := 0
	pos := 0
	n := len(s)
	for pos < n {
		rel := strings.IndexByte(s[pos:], '\n')
		if rel < 0 {
			break
		}
		nl1 := pos + rel
		p := nl1 + 1
		for p < n && (s[p] == ' ' || s[p] == '\t') {
			p++
		}
		if p < n && s[p] == '\r' && p+1 < n && s[p+1] == '\n' {
			tailParaStart = p + 2
			pos = p + 2
			continue
		}
		if p < n && s[p] == '\n' {
			tailParaStart = p + 1
			pos = p + 1
			continue
		}
		pos = nl1 + 1
	}
	return tailParaStart
}

func startsWithTopLevelFenceSliceGo(s string) bool {
	p := 0
	for p < len(s) && p < 4 && (s[p] == ' ' || s[p] == '\t') {
		p++
	}
	if p > 3 || p+3 > len(s) {
		return false
	}
	ch := s[p]
	if ch != '`' && ch != '~' {
		return false
	}
	return s[p+1] == ch && s[p+2] == ch
}

func sanitizeSliceSegmentsSliceGo(segs []string, allowPdfPageMarkers bool) string {
	var sb strings.Builder
	total := 0
	for _, s := range segs {
		total += len(s)
	}
	sb.Grow(total)
	for idx, seg := range segs {
		if idx%2 == 1 {
			sb.WriteString(seg)
			continue
		}
		cleanProse := stripInvisibleSmugglingCharsGo(seg)
		cleanProse = escapeGfmTaskListCheckboxesLinearGo(cleanProse)
		cleanProse = neutralizeAllUnsafeMarkdownLinksLinearGo(cleanProse)
		cleanProse = escapeAllResidualLtInProseLinearGo(cleanProse, allowPdfPageMarkers)
		sb.WriteString(cleanProse)
	}
	return sb.String()
}

// SanitizeMarkdownPageSliceUTF16 converts a JavaScript UTF-16 code-unit offset to a UTF-8 byte offset
// and delegates to SanitizeMarkdownPageSlice for 100% parity on CJK, emoji, and astral Unicode inputs.
func SanitizeMarkdownPageSliceUTF16(
	rawFullMD string,
	utf16Offset int,
	rawSliceInput string,
	allowPdfPageMarkers bool,
	checkpoints []MarkdownSliceCheckpoint,
) string {
	byteOff := UTF16OffsetToByteOffset(rawFullMD, utf16Offset)
	return SanitizeMarkdownPageSlice(rawFullMD, byteOff, rawSliceInput, allowPdfPageMarkers, checkpoints)
}

// SanitizeMarkdownPageSlice sanitizes an arbitrary byte-offset slice of rawFullMD while preserving
// CommonMark fence polarity, container-prefixed untrusted fence state, CRLF boundaries, and inline code spans.
func SanitizeMarkdownPageSlice(
	rawFullMD string,
	safeOffset int,
	rawSliceInput string,
	allowPdfPageMarkers bool,
	checkpoints []MarkdownSliceCheckpoint,
) string {
	if rawSliceInput == "" {
		return ""
	}
	cleanFullPre := stripInvisibleSmugglingCharsGo(stripAllNulBytesSliceGo(rawFullMD))
	var cleanSlicePre string
	if rawFullMD == rawSliceInput {
		cleanSlicePre = cleanFullPre
	} else {
		cleanSlicePre = stripInvisibleSmugglingCharsGo(stripAllNulBytesSliceGo(rawSliceInput))
	}
	if cleanSlicePre == "" {
		return ""
	}

	hadInvisibleInFull := cleanFullPre != rawFullMD
	effectiveOffset := safeOffset
	if effectiveOffset < 0 {
		effectiveOffset = 0
	}
	if hadInvisibleInFull && effectiveOffset > 0 {
		clampedRaw := minIntSliceGo(effectiveOffset, len(rawFullMD))
		effectiveOffset = len(stripInvisibleSmugglingCharsGo(stripAllNulBytesSliceGo(rawFullMD[:clampedRaw])))
	}
	var effectiveCheckpoints []MarkdownSliceCheckpoint
	if !hadInvisibleInFull {
		effectiveCheckpoints = checkpoints
	}

	fullMd, fullHadMultiByteLS := normalizeSliceLineEndingsSliceGo(cleanFullPre)
	var rawSlice string
	if cleanFullPre == cleanSlicePre {
		rawSlice = fullMd
	} else {
		rawSlice, _ = normalizeSliceLineEndingsSliceGo(cleanSlicePre)
	}
	if fullHadMultiByteLS && effectiveOffset > 0 {
		clampedPre := minIntSliceGo(effectiveOffset, len(cleanFullPre))
		normPrefix, _ := normalizeSliceLineEndingsSliceGo(cleanFullPre[:clampedPre])
		effectiveOffset = len(normPrefix)
	}

	state := mdFenceRecognizerStateGo{prevLineWasASCIIBlank: true}
	reconstructed := rawSlice
	var initialReopenedFence *ReopenedMarkdownFence
	var sliceInitialState *MarkdownFenceRecognizerState
	skipLeadingSeparatorEmptyLine := false
	forceLeadingNewlineForConcat := false

	if effectiveOffset > 0 && len(fullMd) > 0 {
		clampedOffset := minIntSliceGo(effectiveOffset, len(fullMd))
		pos := 0
		if len(effectiveCheckpoints) > 0 {
			lo := 0
			hi := len(effectiveCheckpoints) - 1
			bestIdx := -1
			for lo <= hi {
				mid := int(uint(lo+hi) >> 1)
				if effectiveCheckpoints[mid].Pos <= clampedOffset {
					bestIdx = mid
					lo = mid + 1
				} else {
					hi = mid - 1
				}
			}
			if bestIdx >= 0 {
				cp := effectiveCheckpoints[bestIdx]
				pos = cp.Pos
				state.inFence = cp.InFence
				if cp.FenceChar == "`" || cp.FenceChar == "~" {
					state.fenceChar = cp.FenceChar[0]
				} else {
					state.fenceChar = 0
				}
				state.fenceLen = cp.FenceLen
				state.effectiveFenceLen = maxIntSliceGo(cp.FenceLen, cp.EffectiveFenceLen)
				state.prevLineWasASCIIBlank = cp.PrevLineWasAsciiBlank || !cp.PrevLineWasParagraph
				state.possiblyInList = cp.PossiblyInList || cp.ActiveListIndent > 0
				if cp.EscapedUntrusted != nil && (cp.EscapedUntrusted.Ch == "`" || cp.EscapedUntrusted.Ch == "~") {
					state.escapedUntrusted = &escapedUntrustedFenceGo{
						ch:             cp.EscapedUntrusted.Ch[0],
						length:         cp.EscapedUntrusted.Len,
						needBlockquote: cp.EscapedUntrusted.NeedBlockquote,
					}
				} else {
					state.escapedUntrusted = nil
				}
			}
		}

		for pos <= clampedOffset && pos <= len(fullMd) {
			nlRel := strings.IndexByte(fullMd[pos:], '\n')
			lineEnd := len(fullMd)
			nextPos := len(fullMd) + 1
			if nlRel >= 0 {
				lineEnd = pos + nlRel
				nextPos = lineEnd + 1
			}
			hasCrBeforeLf := lineEnd > pos && fullMd[lineEnd-1] == '\r'
			contentEnd := lineEnd
			if hasCrBeforeLf {
				contentEnd = lineEnd - 1
			}
			rawLine := fullMd[pos:contentEnd]
			containsOffset := clampedOffset >= pos && clampedOffset <= lineEnd

			if !containsOffset {
				stepCanonicalMarkdownFenceLineGo(rawLine, &state, true)
				pos = nextPos
				continue
			}

			stateBeforeLine := cloneInternalFenceStateSliceGo(state)
			stepRes := stepCanonicalMarkdownFenceLineGo(rawLine, &state, true)
			firstSliceNl := strings.IndexByte(reconstructed, '\n')

			if stepRes.kind == fenceStepOpenTrustedGo {
				forceLeadingNewlineForConcat = true
				if clampedOffset > pos {
					effLen := maxIntSliceGo(state.fenceLen, state.effectiveFenceLen)
					if firstSliceNl >= 0 {
						reconstructed = reconstructed[firstSliceNl+1:]
						initialReopenedFence = &ReopenedMarkdownFence{
							Ch:           string(state.fenceChar),
							Len:          state.fenceLen,
							EffectiveLen: effLen,
						}
					} else {
						fStr := strings.Repeat(string(state.fenceChar), effLen)
						reconstructed = "\n" + fStr + "\n" + fStr
					}
				} else {
					exp := toExportedFenceStateSliceGo(stateBeforeLine)
					sliceInitialState = &exp
				}
			} else if stepRes.kind == fenceStepCloseTrustedGo {
				forceLeadingNewlineForConcat = true
				firstHead := reconstructed
				if firstSliceNl >= 0 {
					firstHead = reconstructed[:firstSliceNl]
				}
				escapedFirst := escapeLeadingTicksOrTildesSliceGo(firstHead, 1)
				if firstSliceNl >= 0 {
					reconstructed = escapedFirst + reconstructed[firstSliceNl:]
				} else {
					reconstructed = escapedFirst
				}
				exp := toExportedFenceStateSliceGo(state)
				sliceInitialState = &exp
				skipLeadingSeparatorEmptyLine = true
			} else if stateBeforeLine.inFence && stepRes.kind == fenceStepInTrustedGo {
				forceLeadingNewlineForConcat = true
				initialReopenedFence = &ReopenedMarkdownFence{
					Ch:           string(state.fenceChar),
					Len:          state.fenceLen,
					EffectiveLen: maxIntSliceGo(state.fenceLen, state.effectiveFenceLen),
				}
			} else if clampedOffset == pos {
				exp := toExportedFenceStateSliceGo(stateBeforeLine)
				sliceInitialState = &exp
			} else if (clampedOffset == lineEnd && strings.HasPrefix(rawSlice, "\n")) ||
				(hasCrBeforeLf && clampedOffset == contentEnd && strings.HasPrefix(rawSlice, "\r\n")) {
				exp := toExportedFenceStateSliceGo(state)
				sliceInitialState = &exp
				skipLeadingSeparatorEmptyLine = true
			} else {
				firstHead := reconstructed
				if firstSliceNl >= 0 {
					firstHead = reconstructed[:firstSliceNl]
				}
				firstHeadCr := ""
				firstHeadBody := firstHead
				if strings.HasSuffix(firstHead, "\r") {
					firstHeadCr = "\r"
					firstHeadBody = firstHead[:len(firstHead)-1]
				}
				escapedFirst := escapeMidLineProseSliceHeadSliceGo(firstHeadBody) + firstHeadCr
				if firstSliceNl >= 0 {
					reconstructed = escapedFirst + reconstructed[firstSliceNl:]
				} else {
					reconstructed = escapedFirst
				}
				exp := toExportedFenceStateSliceGo(state)
				sliceInitialState = &exp
				skipLeadingSeparatorEmptyLine = true
			}
			break
		}
	}

	passOpts := RecognizeMarkdownFencesOptions{
		Harden:       true,
		PreserveCrLf: true,
	}
	if initialReopenedFence != nil {
		passOpts.InitialReopenedFence = initialReopenedFence
	} else {
		passOpts.InitialState = sliceInitialState
		passOpts.SkipLeadingSeparatorEmptyLine = skipLeadingSeparatorEmptyLine
	}
	_, segTexts := RecognizeAndHardenMarkdownFences(reconstructed, passOpts)

	reRunOpts := RecognizeMarkdownFencesOptions{
		Harden:       true,
		PreserveCrLf: true,
	}
	if initialReopenedFence == nil {
		reRunOpts.InitialState = sliceInitialState
		reRunOpts.SkipLeadingSeparatorEmptyLine = skipLeadingSeparatorEmptyLine
	}

	// Close any unclosed inline backtick code span in the final prose segment (`A1` truncation parity).
	lastIdx := len(segTexts) - 1
	if lastIdx >= 0 && lastIdx%2 == 0 && strings.IndexByte(segTexts[lastIdx], '`') >= 0 {
		lastProse := segTexts[lastIdx]
		tailParaStart := findLastBlankParagraphStartSliceGo(lastProse)
		tailPara := lastProse
		if tailParaStart > 0 {
			tailPara = lastProse[tailParaStart:]
		}
		hasBackslash := strings.IndexByte(tailPara, '\\') >= 0
		p := 0
		openTickLen := 0
		var noTickMask uint64
		for p < len(tailPara) {
			rel := strings.IndexByte(tailPara[p:], '`')
			if rel < 0 {
				break
			}
			p += rel
			if hasBackslash && isBackslashEscapedAt(tailPara, p) {
				p++
				continue
			}
			tEnd := p + 1
			for tEnd < len(tailPara) && tailPara[tEnd] == '`' {
				tEnd++
			}
			want := tEnd - p
			if want < 64 && (noTickMask&(uint64(1)<<want)) != 0 {
				openTickLen = want
				break
			}
			q := tEnd
			matchedEnd := -1
			for q < len(tailPara) {
				hitRel := strings.IndexByte(tailPara[q:], '`')
				if hitRel < 0 {
					break
				}
				hit := q + hitRel
				rEnd := hit + 1
				for rEnd < len(tailPara) && tailPara[rEnd] == '`' {
					rEnd++
				}
				if rEnd-hit == want {
					matchedEnd = rEnd
					break
				}
				q = rEnd
			}
			if matchedEnd < 0 {
				if want < 64 {
					noTickMask |= uint64(1) << want
				}
				openTickLen = want
				break
			}
			p = matchedEnd
		}
		if openTickLen > 0 {
			trimEndIdx := len(lastProse)
			wsProbe := trimEndIdx
			for wsProbe > 0 && (lastProse[wsProbe-1] == ' ' || lastProse[wsProbe-1] == '\t') {
				wsProbe--
			}
			if wsProbe > 0 && (lastProse[wsProbe-1] == '\n' || lastProse[wsProbe-1] == '\r') {
				trimEndIdx = wsProbe
			}
			for trimEndIdx > 0 && (lastProse[trimEndIdx-1] == '\n' || lastProse[trimEndIdx-1] == '\r') {
				trimEndIdx--
				prevWs := trimEndIdx
				for prevWs > 0 && (lastProse[prevWs-1] == ' ' || lastProse[prevWs-1] == '\t') {
					prevWs--
				}
				if prevWs > 0 && (lastProse[prevWs-1] == '\n' || lastProse[prevWs-1] == '\r') {
					trimEndIdx = prevWs
				}
			}
			bodyBeforeNl := lastProse[:trimEndIdx]
			trailingNls := lastProse[trimEndIdx:]
			pad := ""
			if strings.HasSuffix(bodyBeforeNl, "`") {
				pad = " "
			}
			segTexts[lastIdx] = bodyBeforeNl + pad + strings.Repeat("`", openTickLen) + trailingNls
			_, segTexts = RecognizeAndHardenMarkdownFences(strings.Join(segTexts, ""), reRunOpts)
		}
	}

	pass1 := sanitizeSliceSegmentsSliceGo(segTexts, allowPdfPageMarkers)
	finalOut := pass1
	if strings.Contains(pass1, "```") || strings.Contains(pass1, "~~~") {
		_, pass2Segs := RecognizeAndHardenMarkdownFences(pass1, reRunOpts)
		finalOut = sanitizeSliceSegmentsSliceGo(pass2Segs, allowPdfPageMarkers)
	}

	if safeOffset > 0 && (forceLeadingNewlineForConcat || initialReopenedFence != nil || startsWithTopLevelFenceSliceGo(finalOut)) {
		if !strings.HasPrefix(finalOut, "\n\n") {
			if strings.HasPrefix(finalOut, "\n") {
				return "\n" + finalOut
			}
			return "\n\n" + finalOut
		}
	}
	return finalOut
}

// SanitizeFullMarkdownDocumentForArtifact sanitizes an entire Markdown document in linear O(N) time
// prior to R2 artifact caching and page-boundary slicing.
func SanitizeFullMarkdownDocumentForArtifact(fullMD string) string {
	if fullMD == "" {
		return ""
	}
	stripped := stripInvisibleSmugglingCharsGo(fullMD)
	norm := normalizeMarkdownLineEndingsUpfrontSliceGo(stripped)
	if canFastEscapeCodeSpanOnlyLtInProseGo(norm) {
		return replaceAllLtFastGo(norm)
	}
	return SanitizeMarkdownPageSlice(norm, 0, norm, false, nil)
}

// StripMarkdownTableDividerLinesLinear replaces GFM table alignment divider lines (`/^\|?[ \t:-]+\|[ \t|:-]*$/gm`)
// with `' '` in strictly linear O(N) time without regular-expression backtracking.
func StripMarkdownTableDividerLinesLinear(s string) string {
	if s == "" || strings.IndexByte(s, '|') < 0 {
		return s
	}
	n := len(s)
	var sb strings.Builder
	lastCopy := 0
	lineStart := 0

	for lineStart <= n {
		nlRel := strings.IndexByte(s[lineStart:], '\n')
		rawLineEnd := n
		if nlRel >= 0 {
			rawLineEnd = lineStart + nlRel
		}
		lineEnd := rawLineEnd
		if lineEnd > lineStart && s[lineEnd-1] == '\r' {
			lineEnd--
		}
		lineLen := lineEnd - lineStart

		if lineLen >= 2 {
			p := lineStart
			if s[p] == '|' {
				p++
			}
			firstSegStart := p
			valid := true
			for p < lineEnd {
				c := s[p]
				if c == ' ' || c == '\t' || c == ':' || c == '-' {
					p++
				} else {
					break
				}
			}
			if p > firstSegStart && p < lineEnd && s[p] == '|' {
				p++
				for p < lineEnd {
					c := s[p]
					if c == ' ' || c == '\t' || c == '|' || c == ':' || c == '-' {
						p++
					} else {
						valid = false
						break
					}
				}
				if valid {
					if lastCopy == 0 && sb.Cap() == 0 {
						sb.Grow(n)
					}
					sb.WriteString(s[lastCopy:lineStart])
					sb.WriteByte(' ')
					lastCopy = rawLineEnd
				}
			}
		}

		if nlRel < 0 {
			break
		}
		lineStart = rawLineEnd + 1
	}

	if lastCopy == 0 {
		return s
	}
	sb.WriteString(s[lastCopy:])
	return sb.String()
}

func sliceMaxUTF16UnitsSliceGo(s string, maxUnits int) string {
	if maxUnits <= 0 {
		return ""
	}
	if len(s) <= maxUnits {
		return s
	}
	byteIdx := UTF16OffsetToByteOffset(s, maxUnits)
	return s[:byteIdx]
}

// SanitizePlainMetadataText strips smuggling/control characters, normalizes whitespace, caps length to maxLen,
// neutralizes unsafe Markdown links, and escapes `<` to `&lt;` (returning `""` when empty).
func SanitizePlainMetadataText(raw string, maxLen int) string {
	if raw == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 2000
	}
	if !utf8.ValidString(raw) {
		raw = strings.ToValidUTF8(raw, "\uFFFD")
	}
	s := sliceMaxUTF16UnitsSliceGo(raw, maxLen*2)

	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	prevSpace := true // trims leading spaces
	for i := 0; i < n; {
		if s[i] == 0x1B && i+1 < n && s[i+1] == '[' {
			p := i + 2
			for p < n && ((s[p] >= '0' && s[p] <= '9') || s[p] == ';' || s[p] == '?') {
				p++
			}
			for p < n && s[p] >= ' ' && s[p] <= '/' {
				p++
			}
			if p < n && s[p] >= '@' && s[p] <= '~' {
				i = p + 1
				continue
			}
		}
		if s[i] < 0x80 {
			b := s[i]
			if b == '\r' || b == '\n' || b == '\t' || b == ' ' {
				if !prevSpace {
					sb.WriteByte(' ')
					prevSpace = true
				}
				i++
				continue
			}
			if b < 0x20 || b == 0x7F {
				i++
				continue
			}
			sb.WriteByte(b)
			prevSpace = false
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if r == 0x00AD || r == 0x061C || r == 0x180E ||
			(r >= 0x200B && r <= 0x200F) ||
			(r >= 0x202A && r <= 0x202E) ||
			(r >= 0x2060 && r <= 0x206F) ||
			r == 0xFEFF ||
			(r >= 0xE0000 && r <= 0xE01EF) {
			i += w
			continue
		}
		if r == 0x0085 || r == 0x2028 || r == 0x2029 {
			if !prevSpace {
				sb.WriteByte(' ')
				prevSpace = true
			}
			i += w
			continue
		}
		sb.WriteString(s[i : i+w])
		prevSpace = unicode.IsSpace(r)
		i += w
	}

	out := strings.TrimSpace(sb.String())
	if out == "" {
		return ""
	}
	out = strings.TrimSpace(sliceMaxUTF16UnitsSliceGo(out, maxLen))
	if out == "" {
		return ""
	}
	out = neutralizeAllUnsafeMarkdownLinksLinearGo(out)
	if strings.IndexByte(out, '<') >= 0 {
		out = replaceAllLtFastGo(out)
	}
	return out
}

func isTagNameBoundaryByteSliceGo(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r' || b == '/' || b == '>'
}

type htmlScannerDeadStateSliceGo struct {
	mask                 []uint8
	hasNoCommentClose    bool
	noCommentCloseFrom   int
	hasNoCdataClose      bool
	noCdataCloseFrom     int
	nextStdCommentClose  int
	nextBangCommentClose int
	nextCdataClose       int
	nextGtPos            int
	nextNameBoundary     int
}

func newHTMLScannerDeadStateSliceGo() htmlScannerDeadStateSliceGo {
	return htmlScannerDeadStateSliceGo{
		nextStdCommentClose:  -2,
		nextBangCommentClose: -2,
		nextCdataClose:       -2,
		nextGtPos:            -2,
		nextNameBoundary:     -2,
	}
}

func markDeadTagScanPathSliceGo(src string, fromIdx, stopIdx int, deadMask []uint8) {
	state := uint8(0)
	for i := fromIdx; i < stopIdx; i++ {
		bit := uint8(1) << state
		if (deadMask[i] & bit) != 0 {
			break
		}
		deadMask[i] |= bit
		ch := src[i]
		if state == 1 {
			if ch == '"' {
				state = 0
			}
		} else if state == 2 {
			if ch == '\'' {
				state = 0
			}
		} else if ch == '"' {
			state = 1
		} else if ch == '\'' {
			state = 2
		}
	}
}

func findTagOpenEndQuoteAwareSliceGo(src string, fromIdx int, deadRef *htmlScannerDeadStateSliceGo) int {
	if deadRef != nil && deadRef.nextGtPos == -1 {
		return -1
	}
	if deadRef != nil && (deadRef.nextGtPos == -2 || deadRef.nextGtPos < fromIdx) {
		rel := strings.IndexByte(src[fromIdx:], '>')
		if rel < 0 {
			deadRef.nextGtPos = -1
			return -1
		}
		deadRef.nextGtPos = fromIdx + rel
	} else if deadRef == nil && strings.IndexByte(src[fromIdx:], '>') < 0 {
		return -1
	}
	var existingMask []uint8
	if deadRef != nil {
		existingMask = deadRef.mask
	}
	if existingMask != nil && fromIdx < len(existingMask) && (existingMask[fromIdx]&1) != 0 {
		return -1
	}
	state := uint8(0)
	for i := fromIdx; i < len(src); i++ {
		if existingMask != nil && (existingMask[i]&(uint8(1)<<state)) != 0 {
			markDeadTagScanPathSliceGo(src, fromIdx, i, existingMask)
			return -1
		}
		ch := src[i]
		if state == 1 {
			if ch == '"' {
				state = 0
			}
		} else if state == 2 {
			if ch == '\'' {
				state = 0
			}
		} else if ch == '"' {
			state = 1
		} else if ch == '\'' {
			state = 2
		} else if ch == '>' {
			return i
		}
	}
	if deadRef != nil {
		if deadRef.mask == nil {
			deadRef.mask = make([]uint8, len(src))
		}
		markDeadTagScanPathSliceGo(src, fromIdx, len(src), deadRef.mask)
	}
	return -1
}

func findHtmlCommentCloseEndSliceGo(src string, ltIdx int, deadRef *htmlScannerDeadStateSliceGo) int {
	bodyStart := ltIdx + 4
	n := len(src)
	if bodyStart < n && src[bodyStart] == '>' {
		return bodyStart + 1
	}
	if bodyStart+1 < n && src[bodyStart] == '-' && src[bodyStart+1] == '>' {
		return bodyStart + 2
	}
	if deadRef.hasNoCommentClose && bodyStart >= deadRef.noCommentCloseFrom {
		return -1
	}
	stdIdx := deadRef.nextStdCommentClose
	if stdIdx != -1 && stdIdx < bodyStart {
		rel := strings.Index(src[bodyStart:], "-->")
		if rel < 0 {
			stdIdx = -1
		} else {
			stdIdx = bodyStart + rel
		}
		deadRef.nextStdCommentClose = stdIdx
	}
	bangIdx := deadRef.nextBangCommentClose
	if bangIdx != -1 && bangIdx < bodyStart {
		rel := strings.Index(src[bodyStart:], "--!>")
		if rel < 0 {
			bangIdx = -1
		} else {
			bangIdx = bodyStart + rel
		}
		deadRef.nextBangCommentClose = bangIdx
	}
	if stdIdx < 0 && bangIdx < 0 {
		if !deadRef.hasNoCommentClose || bodyStart < deadRef.noCommentCloseFrom {
			deadRef.hasNoCommentClose = true
			deadRef.noCommentCloseFrom = bodyStart
		}
		return -1
	}
	if stdIdx >= 0 && (bangIdx < 0 || stdIdx <= bangIdx) {
		return stdIdx + 3
	}
	return bangIdx + 4
}

type scannedHtmlTagSliceGo struct {
	index         int
	end           int
	tagNameLower  string
	isClosing     bool
	isSelfClosing bool
	isDeclaration bool
	attrs         string
}

func isASCIIAlphaByteSliceGo(b byte) bool {
	low := b | 0x20
	return low >= 'a' && low <= 'z'
}

func tryParseTagAtSliceGo(src string, ltIdx int, deadRef *htmlScannerDeadStateSliceGo, allowDeclarations bool) (scannedHtmlTagSliceGo, bool) {
	n := len(src)
	if ltIdx+2 > n {
		return scannedHtmlTagSliceGo{}, false
	}
	p := ltIdx + 1
	first := src[p]
	isClosing := false
	isDeclaration := false

	if first == '/' {
		isClosing = true
		p++
		if p >= n || !isASCIIAlphaByteSliceGo(src[p]) {
			return scannedHtmlTagSliceGo{}, false
		}
	} else if allowDeclarations && (first == '!' || first == '?') {
		isDeclaration = true
		p++
		if p >= n {
			return scannedHtmlTagSliceGo{}, false
		}
		declNext := src[p]
		if first == '!' && declNext == '-' && p+1 < n && src[p+1] == '-' {
			end := findHtmlCommentCloseEndSliceGo(src, ltIdx, deadRef)
			if end < 0 {
				return scannedHtmlTagSliceGo{}, false
			}
			bodyStart := ltIdx + 4
			innerEnd := bodyStart
			if end > bodyStart+2 {
				if src[end-2] == '!' {
					innerEnd = end - 4
				} else {
					innerEnd = end - 3
				}
			}
			attrs := ""
			if innerEnd > bodyStart {
				attrs = src[bodyStart:innerEnd]
			}
			return scannedHtmlTagSliceGo{
				index:         ltIdx,
				end:           end,
				tagNameLower:  "!--",
				isSelfClosing: true,
				isDeclaration: true,
				attrs:         attrs,
			}, true
		}
		if first == '!' && declNext == '[' && strings.HasPrefix(src[p:], "[CDATA[") {
			afterCdata := p + 7
			if deadRef.hasNoCdataClose && afterCdata >= deadRef.noCdataCloseFrom {
				return scannedHtmlTagSliceGo{}, false
			}
			cdataEnd := deadRef.nextCdataClose
			if cdataEnd != -1 && cdataEnd < afterCdata {
				rel := strings.Index(src[afterCdata:], "]]>")
				if rel < 0 {
					cdataEnd = -1
				} else {
					cdataEnd = afterCdata + rel
				}
				deadRef.nextCdataClose = cdataEnd
			}
			if cdataEnd < 0 {
				if !deadRef.hasNoCdataClose || afterCdata < deadRef.noCdataCloseFrom {
					deadRef.hasNoCdataClose = true
					deadRef.noCdataCloseFrom = afterCdata
				}
				return scannedHtmlTagSliceGo{}, false
			}
			return scannedHtmlTagSliceGo{
				index:         ltIdx,
				end:           cdataEnd + 3,
				tagNameLower:  "![cdata[",
				isSelfClosing: true,
				isDeclaration: true,
				attrs:         src[afterCdata:cdataEnd],
			}, true
		}
		if !isASCIIAlphaByteSliceGo(declNext) {
			return scannedHtmlTagSliceGo{}, false
		}
	} else if !isASCIIAlphaByteSliceGo(first) {
		return scannedHtmlTagSliceGo{}, false
	}

	nameStart := p
	if isDeclaration {
		nameStart = ltIdx + 1
	}
	p++
	nameEnd := deadRef.nextNameBoundary
	if nameEnd != -1 && nameEnd < p {
		q := p
		for q < n && !isTagNameBoundaryByteSliceGo(src[q]) {
			q++
		}
		if q < n {
			nameEnd = q
		} else {
			nameEnd = -1
		}
		deadRef.nextNameBoundary = nameEnd
	}
	if nameEnd == -1 {
		return scannedHtmlTagSliceGo{}, false
	}
	p = nameEnd

	var openEnd int
	if isClosing {
		rel := strings.IndexByte(src[p:], '>')
		if rel < 0 {
			deadRef.nextGtPos = -1
			return scannedHtmlTagSliceGo{}, false
		}
		openEnd = p + rel
	} else {
		openEnd = findTagOpenEndQuoteAwareSliceGo(src, p, deadRef)
		if openEnd < 0 {
			return scannedHtmlTagSliceGo{}, false
		}
	}

	rawName := src[nameStart:p]
	if strings.IndexByte(rawName, 0) >= 0 {
		rawName = strings.ReplaceAll(rawName, "\x00", "")
	}
	tagNameLower := asciiLowerSliceGo(rawName)
	rawAttrs := src[p:openEnd]
	isSelfClosing := !isClosing && (isDeclaration || (openEnd > p && src[openEnd-1] == '/'))
	attrs := rawAttrs
	if !isClosing && !isDeclaration && isSelfClosing && len(rawAttrs) > 0 {
		attrs = rawAttrs[:len(rawAttrs)-1]
	}
	return scannedHtmlTagSliceGo{
		index:         ltIdx,
		end:           openEnd + 1,
		tagNameLower:  tagNameLower,
		isClosing:     isClosing,
		isSelfClosing: isSelfClosing,
		isDeclaration: isDeclaration,
		attrs:         attrs,
	}, true
}

func scanHtmlTagsLinearSliceGo(rawHTML string, maxChars int, allowDeclarations bool, onTag func(scannedHtmlTagSliceGo) bool) {
	src := rawHTML
	if maxChars > 0 && len(src) > maxChars {
		src = truncateValidUTF8SliceGo(src, maxChars)
	}
	deadRef := newHTMLScannerDeadStateSliceGo()
	rel := strings.IndexByte(src, '<')
	if rel < 0 {
		return
	}
	pos := rel
	for pos >= 0 && pos < len(src) {
		if deadRef.nextGtPos == -1 {
			break
		}
		parsed, ok := tryParseTagAtSliceGo(src, pos, &deadRef, allowDeclarations)
		if !ok {
			if deadRef.mask != nil || deadRef.hasNoCommentClose || deadRef.hasNoCdataClose || deadRef.nextGtPos == -1 {
				if deadRef.nextGtPos == -2 || (deadRef.nextGtPos != -1 && deadRef.nextGtPos <= pos) {
					gtRel := strings.IndexByte(src[pos+1:], '>')
					if gtRel < 0 {
						deadRef.nextGtPos = -1
					} else {
						deadRef.nextGtPos = pos + 1 + gtRel
					}
				}
				if deadRef.nextGtPos < 0 {
					break
				}
			}
			if allowDeclarations && pos+3 < len(src) && src[pos+1] == '!' {
				if src[pos+2] == '-' && src[pos+3] == '-' {
					nx := strings.IndexByte(src[pos+4:], '<')
					if nx < 0 {
						break
					}
					pos = pos + 4 + nx
					continue
				}
				if src[pos+2] == '[' && strings.HasPrefix(src[pos+2:], "[CDATA[") {
					nx := strings.IndexByte(src[pos+9:], '<')
					if nx < 0 {
						break
					}
					pos = pos + 9 + nx
					continue
				}
			}
			nx := strings.IndexByte(src[pos+1:], '<')
			if nx < 0 {
				break
			}
			pos = pos + 1 + nx
			continue
		}
		if !onTag(parsed) {
			break
		}
		if parsed.end >= len(src) {
			break
		}
		nx := strings.IndexByte(src[parsed.end:], '<')
		if nx < 0 {
			break
		}
		pos = parsed.end + nx
	}
}

func truncateValidUTF8SliceGo(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	floor := maxIntSliceGo(0, maxBytes-3)
	for cut > floor && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func guardSplitTagReassemblySliceGo(out *[]string, nextSuffix string, deferSet map[string]bool) {
	if nextSuffix == "" {
		return
	}
	chunks := *out
	chunkIdx := len(chunks) - 1
	for chunkIdx >= 0 && len(chunks[chunkIdx]) == 0 {
		chunkIdx--
	}
	if chunkIdx < 0 {
		return
	}
	tail := chunks[chunkIdx]
	minScan := maxIntSliceGo(0, len(tail)-64)
	ltPos := -1
	for i := len(tail) - 1; i >= minScan; i-- {
		ch := tail[i]
		if ch == '>' || ch == '"' || ch == '\'' || ch == '=' {
			return
		}
		if isTagNameBoundaryByteSliceGo(ch) && ch != '/' {
			return
		}
		if ch == '<' {
			ltPos = i
			break
		}
	}
	if ltPos < 0 {
		return
	}
	if len(deferSet) > 0 {
		prefixAfterLt := tail[ltPos+1:]
		sfx := nextSuffix
		if len(sfx) > 24 {
			sfx = sfx[:24]
		}
		combined := asciiLowerSliceGo(strings.ReplaceAll(prefixAfterLt+sfx, "\x00", ""))
		checkStart := 0
		if strings.HasPrefix(combined, "/") {
			checkStart = 1
		}
		for target := range deferSet {
			if strings.HasPrefix(combined[checkStart:], target) {
				afterIdx := checkStart + len(target)
				if afterIdx < len(combined) && isTagNameBoundaryByteSliceGo(combined[afterIdx]) {
					return
				}
			}
		}
	}
	chunks[chunkIdx] = tail[:ltPos] + "&lt;" + tail[ltPos+1:]
}

func stripHtmlCommentsWithGuardSliceGo(rawHTML string, maxChars int) string {
	src := truncateValidUTF8SliceGo(rawHTML, maxChars)
	rel := strings.Index(src, "<!--")
	if rel < 0 {
		return src
	}
	deadRef := newHTMLScannerDeadStateSliceGo()
	var out []string
	cursor := 0
	pos := rel
	for pos >= 0 {
		closeEnd := findHtmlCommentCloseEndSliceGo(src, pos, &deadRef)
		if closeEnd < 0 {
			abrupt1 := strings.Index(src[pos+4:], "<!-->")
			abrupt2 := strings.Index(src[pos+4:], "<!--->")
			if abrupt1 < 0 && abrupt2 < 0 {
				break
			}
			if abrupt1 >= 0 && (abrupt2 < 0 || abrupt1 <= abrupt2) {
				pos = pos + 4 + abrupt1
			} else {
				pos = pos + 4 + abrupt2
			}
			continue
		}
		if pos > cursor {
			out = append(out, src[cursor:pos])
		}
		if closeEnd < len(src) {
			guardSplitTagReassemblySliceGo(&out, src[closeEnd:minIntSliceGo(len(src), closeEnd+24)], dangerousBlockTagsSliceGo)
		}
		cursor = closeEnd
		nx := strings.Index(src[cursor:], "<!--")
		if nx < 0 {
			break
		}
		pos = cursor + nx
	}
	if cursor == 0 {
		return src
	}
	if cursor < len(src) {
		out = append(out, src[cursor:])
	}
	return strings.Join(out, "")
}

func findNextValidCloseTagSliceGo(lower, src, closeNeedle string, fromIdx int) int {
	pos := fromIdx
	for pos < len(lower) {
		rel := strings.Index(lower[pos:], closeNeedle)
		if rel < 0 {
			return -1
		}
		closePos := pos + rel
		after := closePos + len(closeNeedle)
		if after < len(src) && isTagNameBoundaryByteSliceGo(src[after]) {
			return closePos
		}
		pos = after
	}
	return -1
}

func replaceHtmlTagBlocksLinearSliceGo(
	rawHTML string,
	tagNameLower string,
	maxChars int,
	deferSet map[string]bool,
	replacer func(fullMatch, attrStr, innerHTML string) string,
) string {
	src := stripAllNulBytesSliceGo(truncateValidUTF8SliceGo(rawHTML, maxChars))
	lower := asciiLowerSliceGo(src)
	openNeedle := "<" + tagNameLower
	closeNeedle := "</" + tagNameLower
	firstHit := strings.Index(lower, openNeedle)
	if firstHit < 0 {
		return src
	}

	deadRef := newHTMLScannerDeadStateSliceGo()
	var out []string
	cursor := 0
	cachedClosePos := -2

	for firstHit >= 0 {
		afterNameIdx := firstHit + len(openNeedle)
		if afterNameIdx >= len(src) || !isTagNameBoundaryByteSliceGo(src[afterNameIdx]) {
			nx := strings.Index(lower[afterNameIdx:], openNeedle)
			if nx < 0 {
				break
			}
			firstHit = afterNameIdx + nx
			continue
		}
		openEnd := findTagOpenEndQuoteAwareSliceGo(src, afterNameIdx, &deadRef)
		if openEnd < 0 {
			out = append(out, src[cursor:firstHit])
			cursor = len(src)
			break
		}
		if firstHit > cursor {
			out = append(out, src[cursor:firstHit])
		}
		attrStr := src[afterNameIdx:openEnd]
		if openEnd > afterNameIdx && src[openEnd-1] == '/' {
			rep := replacer(src[firstHit:openEnd+1], attrStr[:len(attrStr)-1], "")
			if rep == "" && openEnd+1 < len(src) {
				guardSplitTagReassemblySliceGo(&out, src[openEnd+1:minIntSliceGo(len(src), openEnd+25)], deferSet)
			} else {
				out = append(out, rep)
			}
			cursor = openEnd + 1
			nx := strings.Index(lower[cursor:], openNeedle)
			if nx < 0 {
				break
			}
			firstHit = cursor + nx
			continue
		}

		if cachedClosePos != -1 && cachedClosePos < openEnd+1 {
			cachedClosePos = findNextValidCloseTagSliceGo(lower, src, closeNeedle, openEnd+1)
		}
		if cachedClosePos < 0 {
			if tagNameLower == "script" || tagNameLower == "style" {
				cursor = len(src)
				break
			}
			cursor = openEnd + 1
			nx := strings.Index(lower[cursor:], openNeedle)
			if nx < 0 {
				break
			}
			firstHit = cursor + nx
			continue
		}

		closeGtRel := strings.IndexByte(src[cachedClosePos+len(closeNeedle):], '>')
		if closeGtRel < 0 {
			cursor = len(src)
			break
		}
		closeEnd := cachedClosePos + len(closeNeedle) + closeGtRel
		inner := src[openEnd+1 : cachedClosePos]
		rep := replacer(src[firstHit:closeEnd+1], attrStr, inner)
		if rep == "" && closeEnd+1 < len(src) {
			guardSplitTagReassemblySliceGo(&out, src[closeEnd+1:minIntSliceGo(len(src), closeEnd+25)], deferSet)
		} else {
			out = append(out, rep)
		}
		cursor = closeEnd + 1
		if cursor >= len(lower) {
			break
		}
		nx := strings.Index(lower[cursor:], openNeedle)
		if nx < 0 {
			break
		}
		firstHit = cursor + nx
	}

	if cursor < len(src) {
		out = append(out, src[cursor:])
	}
	return strings.Join(out, "")
}

func stripHtmlTagsLinearSliceGo(rawHTML string, tagNamesLower []string, replacement string, maxChars int) string {
	cur := stripAllNulBytesSliceGo(truncateValidUTF8SliceGo(rawHTML, maxChars))
	if strings.IndexByte(cur, '<') < 0 || len(tagNamesLower) == 0 {
		return cur
	}
	targetSet := make(map[string]bool, len(tagNamesLower))
	for _, t := range tagNamesLower {
		targetSet[asciiLowerSliceGo(t)] = true
	}
	var deferSet map[string]bool
	if replacement == "" {
		deferSet = targetSet
	}
	initialLower := asciiLowerSliceGo(cur)
	changedAny := false
	for _, tag := range tagNamesLower {
		tl := asciiLowerSliceGo(tag)
		if !strings.Contains(initialLower, "<"+tl) {
			continue
		}
		next := replaceHtmlTagBlocksLinearSliceGo(cur, tl, maxChars, deferSet, func(_, _, _ string) string {
			return replacement
		})
		if next != cur {
			cur = next
			changedAny = true
		}
	}
	if changedAny && replacement == "" {
		for pass := 0; pass < 8; pass++ {
			prevLen := len(cur)
			lower := asciiLowerSliceGo(cur)
			matchedAny := false
			for _, tag := range tagNamesLower {
				tl := asciiLowerSliceGo(tag)
				if strings.Contains(lower, "<"+tl) {
					matchedAny = true
					cur = replaceHtmlTagBlocksLinearSliceGo(cur, tl, maxChars, deferSet, func(_, _, _ string) string {
						return replacement
					})
				}
			}
			if !matchedAny || len(cur) == prevLen {
				break
			}
		}
	}
	return cur
}

func stripHtmlTagsQuoteAwareLinearSliceGo(rawHTML string, replacement string, maxChars int) string {
	src := truncateValidUTF8SliceGo(rawHTML, maxChars)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	var out []string
	cursor := 0
	scanHtmlTagsLinearSliceGo(src, maxChars, true, func(tag scannedHtmlTagSliceGo) bool {
		if tag.index > cursor {
			out = append(out, src[cursor:tag.index])
		}
		if replacement == "" && tag.end < len(src) {
			guardSplitTagReassemblySliceGo(&out, src[tag.end:minIntSliceGo(len(src), tag.end+24)], nil)
		} else {
			out = append(out, replacement)
		}
		cursor = tag.end
		return true
	})
	if cursor == 0 {
		return src
	}
	if cursor < len(src) {
		out = append(out, src[cursor:])
	}
	return strings.Join(out, "")
}

type parsedSimpleSelectorSliceGo struct {
	tag        string
	id         string
	classes    []string
	attrName   string
	attrVal    string
	hasAttrVal bool
}

func splitSelectorCombinatorsSliceGo(s string) string {
	last := s
	curStart := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '>' || c == '+' || c == '~' {
			if curStart >= 0 {
				last = s[curStart:i]
				curStart = -1
			}
		} else if curStart < 0 {
			curStart = i
		}
	}
	if curStart >= 0 {
		last = s[curStart:]
	}
	return last
}

func parseSimpleSelectorSliceGo(rawSelector string) *parsedSimpleSelectorSliceGo {
	s := strings.TrimSpace(rawSelector)
	if s == "" {
		return nil
	}
	rest := splitSelectorCombinatorsSliceGo(s)
	out := &parsedSimpleSelectorSliceGo{}

	if loc := reAttrSelectorBracketSliceGo.FindStringSubmatchIndex(rest); loc != nil {
		out.attrName = asciiLowerSliceGo(rest[loc[2]:loc[3]])
		if loc[4] >= 0 {
			out.attrVal = rest[loc[4]:loc[5]]
			out.hasAttrVal = true
		} else if loc[6] >= 0 {
			out.attrVal = rest[loc[6]:loc[7]]
			out.hasAttrVal = true
		} else if loc[8] >= 0 {
			out.attrVal = rest[loc[8]:loc[9]]
			out.hasAttrVal = true
		}
		rest = rest[:loc[0]] + rest[loc[1]:]
	}

	if loc := reAttrSelectorIDSliceGo.FindStringSubmatchIndex(rest); loc != nil {
		out.id = rest[loc[2]:loc[3]]
		rest = rest[:loc[0]] + rest[loc[1]:]
	}

	for _, m := range reAttrSelectorClassSliceGo.FindAllStringSubmatch(rest, -1) {
		out.classes = append(out.classes, m[1])
	}
	rest = strings.TrimSpace(reAttrSelectorClassSliceGo.ReplaceAllString(rest, ""))
	if rest != "" && rest != "*" && reSimpleTagNameSliceGo.MatchString(rest) {
		out.tag = asciiLowerSliceGo(rest)
	}
	return out
}

func unescapeOpenTagAttrValSliceGo(v string) string {
	if strings.IndexByte(v, '&') < 0 {
		return v
	}
	v = strings.ReplaceAll(v, "&amp;", "&")
	v = strings.ReplaceAll(v, "&quot;", `"`)
	v = strings.ReplaceAll(v, "&#39;", "'")
	return v
}

func parseOpenTagAttributesSliceGo(attrChunk string) map[string]string {
	attrs := make(map[string]string)
	if strings.TrimSpace(attrChunk) == "" {
		return attrs
	}
	for _, loc := range reOpenTagAttrPairSliceGo.FindAllStringSubmatchIndex(attrChunk, -1) {
		key := asciiLowerSliceGo(attrChunk[loc[2]:loc[3]])
		val := ""
		if loc[4] >= 0 {
			val = attrChunk[loc[4]:loc[5]]
		} else if loc[6] >= 0 {
			val = attrChunk[loc[6]:loc[7]]
		} else if loc[8] >= 0 {
			val = attrChunk[loc[8]:loc[9]]
		}
		attrs[key] = unescapeOpenTagAttrValSliceGo(val)
	}
	return attrs
}

// ExtractHTMLAttributesBySelectors extracts HTML attribute values matching up to 25 CSS selectors
// across up to 25,000 open tags (up to 200 values per selector) in linear O(N) time.
func ExtractHTMLAttributesBySelectors(rawHTML string, selectors []AttrSelectorSpec) []AttrSelectorItem {
	cleanedHTML := stripHtmlTagsLinearSliceGo(
		stripHtmlCommentsWithGuardSliceGo(rawHTML, maxHTMLScanBytesSliceGo),
		[]string{"script", "style", "template"},
		"",
		maxHTMLScanBytesSliceGo,
	)

	type openTagEntry struct {
		tag   string
		attrs map[string]string
	}
	var openTags []openTagEntry
	scanHtmlTagsLinearSliceGo(cleanedHTML, maxHTMLScanBytesSliceGo, false, func(t scannedHtmlTagSliceGo) bool {
		if t.isClosing || t.isDeclaration {
			return true
		}
		openTags = append(openTags, openTagEntry{
			tag:   t.tagNameLower,
			attrs: parseOpenTagAttributesSliceGo(t.attrs),
		})
		return len(openTags) < 25000
	})

	limit := minIntSliceGo(len(selectors), 25)
	results := make([]AttrSelectorItem, 0, limit)
	for _, spec := range selectors[:limit] {
		selStr := strings.TrimSpace(spec.Selector)
		attrTarget := asciiLowerSliceGo(strings.TrimSpace(spec.Attribute))
		if selStr == "" || attrTarget == "" {
			continue
		}
		parsed := parseSimpleSelectorSliceGo(selStr)
		if parsed == nil {
			results = append(results, AttrSelectorItem{
				Selector:  selStr,
				Attribute: attrTarget,
				Values:    []string{},
			})
			continue
		}

		values := make([]string, 0)
		for _, item := range openTags {
			if len(values) >= 200 {
				break
			}
			if parsed.tag != "" && item.tag != parsed.tag {
				continue
			}
			if parsed.id != "" && item.attrs["id"] != parsed.id {
				continue
			}
			if len(parsed.classes) > 0 {
				clsTokens := strings.Fields(item.attrs["class"])
				allMatch := true
				for _, wantCls := range parsed.classes {
					found := false
					for _, tok := range clsTokens {
						if tok == wantCls {
							found = true
							break
						}
					}
					if !found {
						allMatch = false
						break
					}
				}
				if !allMatch {
					continue
				}
			}
			if parsed.attrName != "" {
				gotVal, exists := item.attrs[parsed.attrName]
				if !exists {
					continue
				}
				if parsed.hasAttrVal && gotVal != parsed.attrVal {
					continue
				}
			}
			if targetVal, exists := item.attrs[attrTarget]; exists {
				values = append(values, targetVal)
			}
		}
		results = append(results, AttrSelectorItem{
			Selector:  selStr,
			Attribute: attrTarget,
			Values:    values,
		})
	}
	return results
}

func isSafePublicHostnameSliceGo(rawHost string) bool {
	host := strings.TrimRight(asciiLowerSliceGo(strings.TrimSpace(rawHost)), ".")
	if host == "" || len(host) > 253 || strings.IndexByte(host, '.') < 0 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c <= 0x20 || c == ':' || c == '[' || c == ']' {
			return false
		}
	}
	for _, r := range host {
		if unicode.IsSpace(r) {
			return false
		}
	}
	if disallowedExactHostsSliceGo[host] {
		return false
	}
	for _, sfx := range disallowedHostSuffixesSliceGo {
		if strings.HasSuffix(host, sfx) {
			return false
		}
	}
	labels := strings.Split(host, ".")
	for _, lbl := range labels {
		if lbl == "" || lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
	}
	tld := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}
	if len(tld) > 2 && tld[0] == '0' && (tld[1] == 'x' || tld[1] == 'X') {
		allHex := true
		for i := 2; i < len(tld); i++ {
			c := tld[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return false
		}
	}
	return true
}

func normalizePublicProductImageURLSliceGo(raw string, baseURL string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	lowPfx := asciiLowerSliceGo(trimmed[:minIntSliceGo(len(trimmed), 12)])
	if strings.HasPrefix(lowPfx, "data:") || strings.HasPrefix(lowPfx, "blob:") || strings.HasPrefix(lowPfx, "javascript:") {
		return ""
	}
	candidate := trimmed
	if strings.HasPrefix(trimmed, "//") {
		if len(trimmed) > 2 && trimmed[2] != '/' && trimmed[2] != '\\' {
			candidate = "https:" + trimmed
		} else {
			return ""
		}
	}
	var resolved *url.URL
	if baseURL != "" {
		baseParsed, err := url.Parse(baseURL)
		if err != nil {
			return ""
		}
		refParsed, err := url.Parse(candidate)
		if err != nil {
			return ""
		}
		resolved = baseParsed.ResolveReference(refParsed)
	} else {
		u, err := url.Parse(candidate)
		if err != nil {
			return ""
		}
		resolved = u
	}
	scheme := asciiLowerSliceGo(resolved.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	resolved.Scheme = scheme
	if resolved.User != nil {
		return ""
	}
	port := resolved.Port()
	if port != "" && port != "80" && port != "443" {
		return ""
	}
	hostname := asciiLowerSliceGo(resolved.Hostname())
	if !isSafePublicHostnameSliceGo(hostname) {
		return ""
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") || port == "" {
		resolved.Host = hostname
	} else {
		resolved.Host = hostname + ":" + port
	}
	if resolved.Path == "" {
		resolved.Path = "/"
	}
	return resolved.String()
}

func decodeBasicEntitiesSliceGo(s string) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
		if s[i] != '&' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		semi := strings.IndexByte(s[i+1:], ';')
		if semi >= 0 && semi <= 12 {
			body := s[i+1 : i+1+semi]
			low := asciiLowerSliceGo(body)
			matched := true
			switch low {
			case "nbsp":
				sb.WriteByte(' ')
			case "amp":
				sb.WriteByte('&')
			case "lt":
				sb.WriteByte('<')
			case "gt":
				sb.WriteByte('>')
			case "quot":
				sb.WriteByte('"')
			case "#39", "apos":
				sb.WriteByte('\'')
			default:
				matched = false
				if len(body) >= 2 && body[0] == '#' {
					if body[1] == 'x' || body[1] == 'X' {
						if cp, err := strconv.ParseUint(body[2:], 16, 32); err == nil && cp > 0 && cp <= 0x10FFFF {
							sb.WriteRune(rune(cp))
							matched = true
						}
					} else {
						if cp, err := strconv.ParseUint(body[1:], 10, 32); err == nil && cp > 0 && cp <= 0x10FFFF {
							sb.WriteRune(rune(cp))
							matched = true
						}
					}
				}
			}
			if matched {
				i += semi + 2
				continue
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func parseJSONValueSliceGo(raw string) any {
	trimmed := strings.TrimPrefix(raw, "\uFEFF")
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return nil
	}
	return v
}

func extractJsonLdObjectsSliceGo(rawHTML string, maxEntities int) []map[string]any {
	if !strings.Contains(asciiLowerSliceGo(rawHTML), "ld+json") {
		return nil
	}
	capCount := maxIntSliceGo(1, minIntSliceGo(250, maxEntities))
	var results []map[string]any

	var pushItem func(item any, depth int)
	pushItem = func(item any, depth int) {
		if item == nil || depth > 16 || len(results) >= capCount {
			return
		}
		switch v := item.(type) {
		case []any:
			for _, el := range v {
				if len(results) >= capCount {
					break
				}
				pushItem(el, depth+1)
			}
		case map[string]any:
			results = append(results, v)
			if graph, ok := v["@graph"].([]any); ok {
				for _, g := range graph {
					if len(results) >= capCount {
						break
					}
					pushItem(g, depth+1)
				}
			}
		}
	}

	replaceHtmlTagBlocksLinearSliceGo(rawHTML, "script", maxHTMLScanBytesSliceGo, nil, func(_, attrStr, inner string) string {
		if len(results) >= capCount || !reJsonLdScriptTypeSliceGo.MatchString(attrStr) {
			return ""
		}
		raw := strings.TrimSpace(inner)
		if raw == "" || len(raw) > maxHTMLScanBytesSliceGo {
			return ""
		}
		parsed := parseJSONValueSliceGo(raw)
		if parsed == nil && strings.IndexByte(raw, '&') >= 0 {
			parsed = parseJSONValueSliceGo(decodeBasicEntitiesSliceGo(raw))
		}
		pushItem(parsed, 0)
		return ""
	})
	return results
}

func matchMetaContentSliceGo(rawHTML string, names []string) string {
	wanted := make(map[string]int, len(names))
	for idx, n := range names {
		wanted[asciiLowerSliceGo(n)] = idx
	}
	hits := make(map[int]string, len(names))
	scanHtmlTagsLinearSliceGo(rawHTML, 160000, false, func(tag scannedHtmlTagSliceGo) bool {
		if tag.isClosing || tag.tagNameLower != "meta" {
			return true
		}
		attrs := parseOpenTagAttributesSliceGo(tag.attrs)
		key, ok := attrs["property"]
		if !ok {
			key, ok = attrs["name"]
		}
		if !ok {
			key = attrs["itemprop"]
		}
		orderIdx, wantedKey := wanted[asciiLowerSliceGo(key)]
		if wantedKey {
			if _, exists := hits[orderIdx]; !exists {
				if content := strings.TrimSpace(attrs["content"]); content != "" {
					hits[orderIdx] = content
					if orderIdx == 0 {
						return false
					}
				}
			}
		}
		return true
	})
	for i := range names {
		if val, ok := hits[i]; ok && val != "" {
			return val
		}
	}
	return ""
}

func extractFirstHeadingTextLinearSliceGo(rawBody string, tagNameLower string) string {
	heading := ""
	replaceHtmlTagBlocksLinearSliceGo(rawBody, tagNameLower, 200000, nil, func(_, _, inner string) string {
		if heading == "" && len(inner) <= 8000 {
			clean := strings.Join(strings.Fields(stripHtmlTagsQuoteAwareLinearSliceGo(inner, " ", 8000)), " ")
			if clean != "" {
				heading = clean
			}
		}
		return ""
	})
	return heading
}

func parsePriceValueSliceGo(rawPrice any) (any, bool) {
	switch v := rawPrice.(type) {
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return v, true
		}
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			var sb strings.Builder
			for i := 0; i < len(trimmed); i++ {
				if (trimmed[i] >= '0' && trimmed[i] <= '9') || trimmed[i] == '.' {
					sb.WriteByte(trimmed[i])
				}
			}
			numStr := sb.String()
			if numStr != "" {
				if f, err := strconv.ParseFloat(numStr, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f != 0 {
					return f, true
				}
			}
			return trimmed, true
		}
	}
	return nil, false
}

func parseVariantPriceValueSliceGo(rawPrice any) (any, bool) {
	if rawPrice == nil {
		return nil, false
	}
	strVal := fmt.Sprint(rawPrice)
	var sb strings.Builder
	for i := 0; i < len(strVal); i++ {
		if (strVal[i] >= '0' && strVal[i] <= '9') || strVal[i] == '.' {
			sb.WriteByte(strVal[i])
		}
	}
	if numStr := sb.String(); numStr != "" {
		if f, err := strconv.ParseFloat(numStr, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f != 0 {
			return f, true
		}
	}
	return rawPrice, true
}

func jsNumberOrRawSliceGo(v any) any {
	switch val := v.(type) {
	case float64:
		return val
	case string:
		trimmed := strings.TrimSpace(val)
		if trimmed != "" {
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f != 0 {
				return f
			}
		}
		return val
	default:
		return v
	}
}

// ExtractStructuredProduct extracts normalized e-commerce product metadata across Schema.org JSON-LD `Product`,
// OpenGraph `product:*` / `og:*` meta tags, and barcode / H1 fallbacks (`scrape-advanced.ts:3089-3244`).
func ExtractStructuredProduct(rawBody, finalURL, fallbackTitle, fallbackDescription string) map[string]any {
	if rawBody == "" {
		return nil
	}

	jsonLdList := extractJsonLdObjectsSliceGo(rawBody, 100)
	var productLd map[string]any
	for _, obj := range jsonLdList {
		tVal := obj["@type"]
		var types []string
		switch tv := tVal.(type) {
		case string:
			types = []string{tv}
		case []any:
			for _, elem := range tv {
				types = append(types, fmt.Sprint(elem))
			}
		}
		matched := false
		for _, ts := range types {
			if reProductTypeNameSliceGo.MatchString(ts) {
				matched = true
				break
			}
		}
		if matched {
			productLd = obj
			break
		}
	}

	if productLd != nil {
		brandInput := ""
		switch bv := productLd["brand"].(type) {
		case string:
			brandInput = bv
		case map[string]any:
			if bn, ok := bv["name"].(string); ok {
				brandInput = bn
			}
		}
		brand := SanitizePlainMetadataText(brandInput, 240)

		var offerList []map[string]any
		switch ov := productLd["offers"].(type) {
		case []any:
			for _, item := range ov {
				if om, ok := item.(map[string]any); ok {
					offerList = append(offerList, om)
				}
			}
		case map[string]any:
			offerList = []map[string]any{ov}
		}
		var primaryOffer map[string]any
		if len(offerList) > 0 {
			primaryOffer = offerList[0]
		}
		var rawPrice any
		if primaryOffer != nil {
			if p, ok := primaryOffer["price"]; ok && p != nil {
				rawPrice = p
			} else {
				rawPrice = primaryOffer["lowPrice"]
			}
		}
		price, hasPrice := parsePriceValueSliceGo(rawPrice)

		currency := ""
		availability := ""
		if primaryOffer != nil {
			if c, ok := primaryOffer["priceCurrency"].(string); ok {
				currency = c
			}
			if a, ok := primaryOffer["availability"].(string); ok {
				availability = reSchemaOrgPrefixSliceGo.ReplaceAllString(a, "")
			}
		}

		var rawImgs []any
		if imgsVal, ok := productLd["image"]; ok && imgsVal != nil {
			if arr, isArr := imgsVal.([]any); isArr {
				rawImgs = arr
			} else {
				rawImgs = []any{imgsVal}
			}
		}
		var images []string
		for _, im := range rawImgs {
			rawImg := ""
			switch iv := im.(type) {
			case string:
				rawImg = iv
			case map[string]any:
				if u, ok := iv["url"].(string); ok {
					rawImg = u
				}
			}
			if normImg := normalizePublicProductImageURLSliceGo(rawImg, finalURL); normImg != "" {
				images = append(images, normImg)
			}
		}

		ratingObj, _ := productLd["aggregateRating"].(map[string]any)

		titleSrc := fallbackTitle
		if ldName, ok := productLd["name"].(string); ok {
			titleSrc = ldName
		}
		cleanLdTitle := SanitizePlainMetadataText(titleSrc, 400)

		descSrc := fallbackDescription
		if ldDesc, ok := productLd["description"].(string); ok {
			descSrc = ldDesc
		}
		cleanLdDesc := SanitizePlainMetadataText(descSrc, 1200)

		skuSrc := ""
		if ldSku, ok := productLd["sku"].(string); ok {
			skuSrc = ldSku
		}
		cleanSku := SanitizePlainMetadataText(skuSrc, 160)

		rawLdURL := finalURL
		if ldURL, ok := productLd["url"].(string); ok && !IsDisallowedMarkdownLinkDestination(ldURL) {
			rawLdURL = ldURL
		}

		out := map[string]any{
			"url": rawLdURL,
		}
		if cleanLdTitle != "" {
			out["title"] = cleanLdTitle
		}
		if cleanLdDesc != "" {
			out["description"] = cleanLdDesc
		}
		if brand != "" {
			out["brand"] = brand
		}
		if cleanSku != "" {
			out["sku"] = cleanSku
		}
		if g13, ok := productLd["gtin13"].(string); ok {
			out["gtin"] = g13
		} else if g, ok := productLd["gtin"].(string); ok {
			out["gtin"] = g
		}
		if hasPrice {
			out["price"] = price
		}
		if currency != "" {
			out["currency"] = currency
		}
		if availability != "" {
			out["availability"] = availability
		}
		if len(images) > 0 {
			out["images"] = images
		}
		if ratingObj != nil {
			if rv, ok := ratingObj["ratingValue"]; ok && rv != nil {
				out["rating"] = jsNumberOrRawSliceGo(rv)
			}
			if rc, ok := ratingObj["reviewCount"]; ok && rc != nil {
				out["reviewCount"] = jsNumberOrRawSliceGo(rc)
			}
		}
		if len(offerList) > 1 {
			capOffers := minIntSliceGo(len(offerList), 30)
			variants := make([]map[string]any, 0, capOffers)
			for _, o := range offerList[:capOffers] {
				vm := make(map[string]any)
				if vn, ok := o["name"].(string); ok {
					if cleanVN := SanitizePlainMetadataText(vn, 240); cleanVN != "" {
						vm["name"] = cleanVN
					}
				}
				if vs, ok := o["sku"].(string); ok {
					if cleanVS := SanitizePlainMetadataText(vs, 160); cleanVS != "" {
						vm["sku"] = cleanVS
					}
				}
				if vp, ok := o["price"]; ok && vp != nil {
					if parsedVP, okVP := parseVariantPriceValueSliceGo(vp); okVP {
						vm["price"] = parsedVP
					}
				}
				if vc, ok := o["priceCurrency"].(string); ok && vc != "" {
					vm["currency"] = vc
				}
				if va, ok := o["availability"].(string); ok && va != "" {
					vm["availability"] = reSchemaOrgPrefixSliceGo.ReplaceAllString(va, "")
				}
				variants = append(variants, vm)
			}
			out["variants"] = variants
		}
		return out
	}

	// Fallback to OpenGraph `product:price:amount` / meta tags.
	ogPrice := matchMetaContentSliceGo(rawBody, []string{"product:price:amount", "og:price:amount", "price"})
	ogCurrency := matchMetaContentSliceGo(rawBody, []string{"product:price:currency", "og:price:currency", "priceCurrency"})
	ogBrand := SanitizePlainMetadataText(matchMetaContentSliceGo(rawBody, []string{"product:brand", "og:brand", "brand"}), 240)
	ogAvail := matchMetaContentSliceGo(rawBody, []string{"product:availability", "og:availability", "availability"})
	ogImage := normalizePublicProductImageURLSliceGo(matchMetaContentSliceGo(rawBody, []string{"og:image"}), finalURL)

	if ogPrice != "" || ogBrand != "" || ogAvail != "" {
		ogTitleSrc := matchMetaContentSliceGo(rawBody, []string{"og:title"})
		if ogTitleSrc == "" {
			ogTitleSrc = fallbackTitle
		}
		cleanOgTitle := SanitizePlainMetadataText(ogTitleSrc, 400)
		cleanOgDesc := SanitizePlainMetadataText(fallbackDescription, 1200)
		out := map[string]any{
			"url": finalURL,
		}
		if cleanOgTitle != "" {
			out["title"] = cleanOgTitle
		}
		if cleanOgDesc != "" {
			out["description"] = cleanOgDesc
		}
		if ogBrand != "" {
			out["brand"] = ogBrand
		}
		if ogPrice != "" {
			if parsedPrice, ok := parsePriceValueSliceGo(ogPrice); ok {
				out["price"] = parsedPrice
			}
		}
		if ogCurrency != "" {
			out["currency"] = ogCurrency
		}
		if ogAvail != "" {
			out["availability"] = ogAvail
		}
		if ogImage != "" {
			out["images"] = []string{ogImage}
		}
		return out
	}

	// Fallback for barcode / consumer packaged goods & microdata pages (e.g. Open Food Facts `/product/<gtin>`).
	ogType := asciiLowerSliceGo(matchMetaContentSliceGo(rawBody, []string{"og:type"}))
	barcodeMatch := reBarcodeProductPathSliceGo.FindStringSubmatch(finalURL)
	if ogType == "product" || ogType == "og:product" || strings.Contains(ogType, "food") || len(barcodeMatch) >= 2 {
		candSrc := matchMetaContentSliceGo(rawBody, []string{"og:title", "twitter:title"})
		if candSrc == "" {
			candSrc = extractFirstHeadingTextLinearSliceGo(rawBody, "h1")
		}
		if candSrc == "" {
			candSrc = fallbackTitle
		}
		titleCandidate := SanitizePlainMetadataText(candSrc, 400)
		if titleCandidate != "" {
			brandFromTitle := ""
			if strings.Contains(titleCandidate, "\u2013") {
				parts := strings.SplitN(titleCandidate, "\u2013", 2)
				if len(parts) == 2 {
					brandFromTitle = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(titleCandidate, " - ") {
				parts := strings.SplitN(titleCandidate, " - ", 2)
				if len(parts) == 2 {
					brandFromTitle = strings.TrimSpace(parts[1])
				}
			}
			cleanBarcodeDesc := SanitizePlainMetadataText(fallbackDescription, 1200)
			out := map[string]any{
				"title": titleCandidate,
				"url":   finalURL,
			}
			if cleanBarcodeDesc != "" {
				out["description"] = cleanBarcodeDesc
			}
			if brandFromTitle != "" {
				out["brand"] = brandFromTitle
			}
			if len(barcodeMatch) >= 2 && barcodeMatch[1] != "" {
				out["gtin"] = barcodeMatch[1]
			}
			if ogImage != "" {
				out["images"] = []string{ogImage}
			}
			return out
		}
	}

	return nil
}

// SplitPDFPagesAndMarkers splits form-feed (`\f`) separated PDF text into trimmed non-empty pages
// (capped at maxPages when maxPages > 0) and constructs `<!-- page N -->` marked Markdown.
func SplitPDFPagesAndMarkers(rawText string, maxPages int) (pages []string, markedMarkdown string) {
	if rawText == "" {
		return []string{}, ""
	}
	var rawPages []string
	if strings.IndexByte(rawText, '\f') >= 0 {
		for _, p := range strings.Split(rawText, "\f") {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				rawPages = append(rawPages, trimmed)
			}
		}
	} else {
		rawPages = []string{strings.TrimSpace(rawText)}
	}
	if maxPages > 0 && len(rawPages) > maxPages {
		rawPages = rawPages[:maxPages]
	}
	if len(rawPages) == 0 {
		return []string{}, ""
	}
	var sb strings.Builder
	for idx, p := range rawPages {
		if idx > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("<!-- page ")
		sb.WriteString(strconv.Itoa(idx + 1))
		sb.WriteString(" -->\n\n")
		sb.WriteString(p)
	}
	return rawPages, sb.String()
}
