package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

const (
	maxWasmInputBytes   = 48 << 20 // 48 MiB ceiling per call (supports large ATS/HTML payloads)
	shrinkBufCapBytes   = 8 << 20  // Release >8 MiB transient I/O buffers immediately after multi-MiB board/page calls
	baseBufCapBytes     = 256 << 10
	re2RingCapacity     = 1024
	domRingCapacity     = 32
	wasmRawStrUnchanged = ^uint32(0)
)

func init() {
	// Cloudflare Workers shares a hard 128 MiB ceiling across V8 heap + WebAssembly.Memory,
	// and WebAssembly linear memory pages can never shrink once grown. SetMemoryLimit paces
	// GC automatically near 48 MiB without penalizing fast <8 MiB hot-path calls.
	debug.SetMemoryLimit(48 << 20)
}

type domDocSlot struct {
	id    int32
	doc   *extract.HTMLDoc
	nodes []*extract.HTMLNode
}

var (
	wasmInBuf  = make([]byte, baseBufCapBytes)
	wasmOutBuf = make([]byte, 0, baseBufCapBytes)

	re2Table  [re2RingCapacity]*regexp.Regexp
	re2NextID int32 = 1

	domTable  [domRingCapacity]domDocSlot
	domNextID int32 = 1

	phase2JobsRPC       func(op string, payload json.RawMessage) (any, bool, error)
	phase2JobsRawRPC    func(op string, meta json.RawMessage, rawStr string) (any, bool, error)
	phase2CatalogRPC    func(op string, payload json.RawMessage) (any, bool, error)
	phase2CatalogRawRPC func(op string, meta json.RawMessage, rawStr string) (any, bool, error)
	phase2AgentRPC      func(op string, payload json.RawMessage) (any, bool, error)
	phase2AgentRawRPC   func(op string, meta json.RawMessage, rawStr string) (any, bool, error)
	phase2McpRPC        func(op string, payload json.RawMessage) (any, bool, error)
	phase2McpRawRPC     func(op string, meta json.RawMessage, rawStr string) (any, bool, error)
)

func lookupDomNode(docID int32, nodeID int) *extract.HTMLNode {
	if docID <= 0 || domNextID-docID > domRingCapacity {
		return nil
	}
	slot := &domTable[int((docID-1)%domRingCapacity)]
	if slot.id != docID || nodeID < 0 || nodeID >= len(slot.nodes) {
		return nil
	}
	return slot.nodes[nodeID]
}

//go:wasmexport ef_in_ptr
func efInPtr(size uint32) uint32 {
	if size > maxWasmInputBytes {
		return 0
	}
	need := int(size)
	if need <= 0 {
		need = 1
	}
	if cap(wasmOutBuf) > shrinkBufCapBytes {
		wasmOutBuf = make([]byte, 0, baseBufCapBytes)
	}
	if cap(wasmInBuf) < need {
		wasmInBuf = make([]byte, need)
	} else if cap(wasmInBuf) > shrinkBufCapBytes && need <= shrinkBufCapBytes {
		allocCap := max(need, baseBufCapBytes)
		wasmInBuf = make([]byte, need, allocCap)
	} else {
		wasmInBuf = wasmInBuf[:need]
	}
	return uint32(uintptr(unsafe.Pointer(&wasmInBuf[0])))
}

//go:wasmexport ef_out_ptr
func efOutPtr() uint32 {
	if len(wasmOutBuf) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&wasmOutBuf[0])))
}

//go:wasmexport ef_out_len
func efOutLen() uint32 {
	return uint32(len(wasmOutBuf))
}

//go:wasmexport ef_re2_compile
func efRe2Compile(patLen uint32) int32 {
	if patLen > uint32(len(wasmInBuf)) {
		return 0
	}
	pat := string(wasmInBuf[:patLen])
	re, err := regexp.Compile(pat)
	if err != nil {
		return 0
	}
	id := re2NextID
	re2NextID++
	if re2NextID <= 0 {
		re2NextID = 1
	}
	slot := int((id - 1) % re2RingCapacity)
	re2Table[slot] = re
	return id
}

func lookupRe2Handle(id int32) *regexp.Regexp {
	if id <= 0 || re2NextID-id > re2RingCapacity {
		return nil
	}
	slot := int((id - 1) % re2RingCapacity)
	return re2Table[slot]
}

//go:wasmexport ef_re2_test
func efRe2Test(id int32, subjLen uint32) int32 {
	re := lookupRe2Handle(id)
	if re == nil {
		return -1
	}
	if subjLen > uint32(len(wasmInBuf)) {
		return 0
	}
	if re.Match(wasmInBuf[:subjLen]) {
		return 1
	}
	return 0
}

func byteOffsetToUTF16Index(b []byte, byteOff int) int {
	if byteOff <= 0 {
		return 0
	}
	if byteOff > len(b) {
		byteOff = len(b)
	}
	u16 := 0
	i := 0
	for i < byteOff {
		c := b[i]
		if c < 0x80 {
			u16++
			i++
			continue
		}
		r, width := utf8.DecodeRune(b[i:byteOff])
		if width <= 0 {
			break
		}
		if r >= 0x10000 {
			u16 += 2
		} else {
			u16++
		}
		i += width
	}
	return u16
}

//go:wasmexport ef_re2_exec
func efRe2Exec(id int32, subjLen uint32) uint32 {
	re := lookupRe2Handle(id)
	if re == nil || subjLen > uint32(len(wasmInBuf)) {
		wasmOutBuf = wasmOutBuf[:0]
		return 0
	}
	subj := wasmInBuf[:subjLen]
	locs := re.FindSubmatchIndex(subj)
	if locs == nil {
		wasmOutBuf = wasmOutBuf[:0]
		return 0
	}
	groups := make([]*string, len(locs)/2)
	subNames := re.SubexpNames()
	var named map[string]*string
	for g := 0; g*2+1 < len(locs); g++ {
		s, e := locs[g*2], locs[g*2+1]
		var ptr *string
		if s >= 0 && e >= s {
			val := string(subj[s:e])
			ptr = &val
			groups[g] = ptr
		}
		if g > 0 && g < len(subNames) && subNames[g] != "" {
			if named == nil {
				named = make(map[string]*string)
			}
			named[subNames[g]] = ptr
		}
	}
	out := map[string]any{
		"matched": true,
		"index":   byteOffsetToUTF16Index(subj, locs[0]),
		"groups":  groups,
	}
	if named != nil {
		out["namedGroups"] = named
	}
	writeWasmJSON(out)
	return uint32(len(wasmOutBuf))
}

type wasmRPCEnvelope struct {
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload"`
}

func writeWasmJSON(v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		wasmOutBuf = append(wasmOutBuf[:0], `{"error":"encode_failed"}`...)
		return
	}
	raw := bytes.TrimRight(buf.Bytes(), "\n")
	wasmOutBuf = append(wasmOutBuf[:0], raw...)
}

func releaseOversizedWasmInBuf() {
	if cap(wasmInBuf) > shrinkBufCapBytes {
		wasmInBuf = make([]byte, baseBufCapBytes)
	}
}

//go:wasmexport ef_call
func efCall(inLen uint32) (outLen uint32) {
	defer func() {
		if r := recover(); r != nil {
			writeWasmJSON(map[string]any{"error": fmt.Sprintf("wasm_panic: %v", r)})
			outLen = uint32(len(wasmOutBuf))
		}
		releaseOversizedWasmInBuf()
	}()
	if inLen > uint32(len(wasmInBuf)) {
		writeWasmJSON(map[string]any{"error": "invalid_input_length"})
		return uint32(len(wasmOutBuf))
	}
	resp, err := dispatchWasmRPC(wasmInBuf[:inLen])
	if err != nil {
		writeWasmJSON(map[string]any{"error": err.Error()})
		return uint32(len(wasmOutBuf))
	}
	writeWasmJSON(resp)
	return uint32(len(wasmOutBuf))
}

//go:wasmexport ef_call_raw
func efCallRaw(metaLen uint32, totalLen uint32) (outLen uint32) {
	defer func() {
		if r := recover(); r != nil {
			writeWasmJSON(map[string]any{"error": fmt.Sprintf("wasm_panic: %v", r)})
			outLen = uint32(len(wasmOutBuf))
		}
		releaseOversizedWasmInBuf()
	}()
	if totalLen > uint32(len(wasmInBuf)) || metaLen > totalLen {
		writeWasmJSON(map[string]any{"error": "invalid_input_length"})
		return uint32(len(wasmOutBuf))
	}
	var rawStr string
	if totalLen > metaLen {
		rawStr = unsafe.String(&wasmInBuf[metaLen], int(totalLen-metaLen))
	}
	resp, err := dispatchWasmRawRPC(wasmInBuf[:metaLen], rawStr)
	if err != nil {
		writeWasmJSON(map[string]any{"error": err.Error()})
		return uint32(len(wasmOutBuf))
	}
	writeWasmJSON(resp)
	return uint32(len(wasmOutBuf))
}

//go:wasmexport ef_call_raw_str
func efCallRawStr(metaLen uint32, totalLen uint32) (outLen uint32) {
	defer func() {
		if r := recover(); r != nil {
			wasmOutBuf = wasmOutBuf[:0]
			outLen = 0
		}
		releaseOversizedWasmInBuf()
	}()
	if totalLen > uint32(len(wasmInBuf)) || metaLen > totalLen {
		wasmOutBuf = wasmOutBuf[:0]
		return 0
	}
	var inputStr string
	if totalLen > metaLen {
		inputStr = unsafe.String(&wasmInBuf[metaLen], int(totalLen-metaLen))
	}
	outStr, allowUnchanged, err := dispatchWasmRawStrRPC(wasmInBuf[:metaLen], inputStr)
	if err != nil {
		wasmOutBuf = wasmOutBuf[:0]
		return 0
	}
	if allowUnchanged && outStr == inputStr {
		return wasmRawStrUnchanged
	}
	wasmOutBuf = append(wasmOutBuf[:0], outStr...)
	return uint32(len(wasmOutBuf))
}

func dispatchWasmRawStrRPC(metaBytes []byte, rawStr string) (string, bool, error) {
	var env struct {
		Op   string          `json:"op"`
		Meta json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(metaBytes, &env); err != nil {
		return "", false, err
	}
	switch env.Op {
	case "sanitize_markdown":
		var m struct {
			BaseURL             string `json:"baseUrl"`
			AllowPdfPageMarkers bool   `json:"allowPdfPageMarkers"`
		}
		if len(env.Meta) > 0 {
			if err := json.Unmarshal(env.Meta, &m); err != nil {
				return "", false, err
			}
		}
		return extract.SanitizeMarkdownWithOptions(rawStr, m.BaseURL, m.AllowPdfPageMarkers), true, nil
	case "full_artifact_markdown":
		return extract.SanitizeFullMarkdownDocumentForArtifact(rawStr), true, nil
	case "neutralize_unsafe_links":
		return extract.NeutralizeAllUnsafeMarkdownLinks(rawStr), true, nil
	case "format_yaml_card":
		var m struct {
			FallbackTitle string `json:"fallbackTitle"`
		}
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &m)
		}
		card := extract.FormatYAMLFrontmatterCard(rawStr, m.FallbackTitle)
		if card == nil {
			return "", false, nil
		}
		return card.Title + "\x00" + card.Description + "\x00" + card.Markdown, false, nil
	case "recognize_fences":
		var p struct {
			Harden                        bool                                  `json:"harden"`
			PreserveCrLf                  bool                                  `json:"preserveCrLf"`
			InitialReopenedFence          *extract.ReopenedMarkdownFence        `json:"initialReopenedFence"`
			InitialState                  *extract.MarkdownFenceRecognizerState `json:"initialState"`
			SkipLeadingSeparatorEmptyLine bool                                  `json:"skipLeadingSeparatorEmptyLine"`
		}
		if len(env.Meta) > 0 {
			if err := json.Unmarshal(env.Meta, &p); err != nil {
				return "", false, err
			}
		}
		hardened, segs := extract.RecognizeAndHardenMarkdownFences(rawStr, extract.RecognizeMarkdownFencesOptions{
			Harden:                        p.Harden,
			PreserveCrLf:                  p.PreserveCrLf,
			InitialReopenedFence:          p.InitialReopenedFence,
			InitialState:                  p.InitialState,
			SkipLeadingSeparatorEmptyLine: p.SkipLeadingSeparatorEmptyLine,
		})
		if len(segs) == 1 && segs[0] == hardened {
			return "\x00" + hardened, false, nil
		}
		pos := 0
		contiguous := len(segs) > 0
		for _, s := range segs {
			if pos+len(s) > len(hardened) || hardened[pos:pos+len(s)] != s {
				contiguous = false
				break
			}
			pos += len(s)
		}
		if contiguous && pos != len(hardened) {
			contiguous = false
		}
		if contiguous {
			var sb strings.Builder
			sb.Grow(len(segs)*10 + 1 + len(hardened))
			for i, s := range segs {
				if i > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(strconv.Itoa(extract.UTF16Len(s)))
			}
			sb.WriteByte(0)
			sb.WriteString(hardened)
			return sb.String(), false, nil
		}
		jb, err := json.Marshal(map[string]any{"hardened": hardened, "segments": segs})
		if err != nil {
			return "", false, err
		}
		return "J\x00" + string(jb), false, nil
	case "escape_task_checkboxes":
		return extract.EscapeGfmTaskListCheckboxes(rawStr), true, nil
	case "escape_residual_lt":
		var p struct {
			AllowPdfPageMarkers bool `json:"allowPdfPageMarkers"`
		}
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &p)
		}
		return extract.EscapeAllResidualLtInProse(rawStr, p.AllowPdfPageMarkers), true, nil
	case "strip_invisible":
		return extract.StripInvisibleSmugglingChars(rawStr), true, nil
	case "strip_table_dividers":
		return extract.StripMarkdownTableDividerLinesLinear(rawStr), true, nil
	default:
		return "", false, fmt.Errorf("unknown raw_str op %q", env.Op)
	}
}

func dispatchWasmRawRPC(metaBytes []byte, rawStr string) (any, error) {
	var env struct {
		Op   string          `json:"op"`
		Meta json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(metaBytes, &env); err != nil {
		return nil, err
	}
	switch env.Op {
	case "slice_checkpoints":
		var p struct {
			StepChars int `json:"stepChars"`
		}
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &p)
		}
		return map[string]any{
			"checkpoints": extract.ComputeMarkdownSliceCheckpoints(rawStr, p.StepChars),
		}, nil

	case "extract_html_attributes":
		var p struct {
			Selectors []extract.AttrSelectorSpec `json:"selectors"`
		}
		if len(env.Meta) > 0 {
			if err := json.Unmarshal(env.Meta, &p); err != nil {
				return nil, err
			}
		}
		return map[string]any{"items": extract.ExtractHTMLAttributesBySelectors(rawStr, p.Selectors)}, nil

	case "extract_structured_product":
		var p struct {
			FinalURL            string `json:"finalUrl"`
			FallbackTitle       string `json:"fallbackTitle"`
			FallbackDescription string `json:"fallbackDescription"`
		}
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &p)
		}
		return map[string]any{
			"product": extract.ExtractStructuredProduct(rawStr, p.FinalURL, p.FallbackTitle, p.FallbackDescription),
		}, nil

	case "extract_html_full":
		var opts extract.FullExtractOptions
		if len(env.Meta) > 0 {
			if err := json.Unmarshal(env.Meta, &opts); err != nil {
				return nil, err
			}
		}
		return map[string]any{"doc": extract.ExtractHTMLDocumentFull(rawStr, opts)}, nil

	case "recover_ssr_hydration":
		var m struct {
			BaseURL string `json:"baseUrl"`
		}
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &m)
		}
		return map[string]any{"result": extract.RecoverSSRHydrationContent(rawStr, m.BaseURL, defaultHTMLToMD)}, nil

	case "extract_next_rsc":
		var m struct {
			BaseURL string `json:"baseUrl"`
		}
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &m)
		}
		return map[string]any{"result": extract.ExtractNextRSCFlight(rawStr, m.BaseURL, defaultHTMLToMD)}, nil

	case "manifest_format_twin":
		var p struct {
			AdapterID string                              `json:"adapterId"`
			Manifest  *extract.DeclarativeAdapterManifest `json:"manifest"`
			URL       string                              `json:"url"`
			OrigURL   string                              `json:"origUrl"`
		}
		if err := json.Unmarshal(env.Meta, &p); err != nil {
			return nil, err
		}
		var doc *extract.DeclarativeFormattedDoc
		var ok bool
		if p.AdapterID != "" {
			if bm := extract.LookupBuiltInManifest(p.AdapterID); bm != nil {
				doc, ok = extract.FormatTwinOnValidatedManifest(bm, p.URL, rawStr, p.OrigURL)
			}
		} else if p.Manifest != nil {
			doc, ok = extract.FormatTwinOnManifest(p.Manifest, p.URL, rawStr, p.OrigURL)
		}
		if !ok || doc == nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "doc": doc}, nil

	case "manifest_extract_html":
		var p struct {
			AdapterID   string                              `json:"adapterId"`
			Manifest    *extract.DeclarativeAdapterManifest `json:"manifest"`
			BaseURL     string                              `json:"baseUrl"`
			HTMLByteLen *int                                `json:"htmlByteLen"`
			CurrentMD   string                              `json:"currentMd"`
		}
		if err := json.Unmarshal(env.Meta, &p); err != nil {
			return nil, err
		}
		rawHTML := rawStr
		curMD := p.CurrentMD
		if p.HTMLByteLen != nil {
			sp := *p.HTMLByteLen
			if sp < 0 {
				sp = 0
			} else if sp > len(rawStr) {
				sp = len(rawStr)
			}
			rawHTML = rawStr[:sp]
			curMD = rawStr[sp:]
		}
		var res *extract.DeclarativePostFetchResult
		var ok bool
		if p.AdapterID != "" {
			if bm := extract.LookupBuiltInManifest(p.AdapterID); bm != nil {
				res, ok = extract.ExtractHTMLOnValidatedManifest(bm, rawHTML, p.BaseURL, curMD, defaultHTMLToMD)
			}
		} else if p.Manifest != nil {
			res, ok = extract.ExtractHTMLOnManifest(p.Manifest, rawHTML, p.BaseURL, curMD, defaultHTMLToMD)
		}
		if !ok || res == nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "result": res}, nil

	case "format_json_extract_spec":
		var p struct {
			Extract extract.DeclarativeExtractSpec `json:"extract"`
			Params  map[string]string              `json:"params"`
			OrigURL string                         `json:"origUrl"`
		}
		if err := json.Unmarshal(env.Meta, &p); err != nil {
			return nil, err
		}
		doc, ok := extract.FormatJSONWithExtractSpec(rawStr, p.Extract, p.Params, p.OrigURL)
		return map[string]any{"ok": ok, "doc": doc}, nil

	case "validate_easyprivacy":
		var p struct {
			ByteLength           int      `json:"byteLength"`
			PreviousHostCount    int      `json:"previousHostCount"`
			ExtraNeverBlockHosts []string `json:"extraNeverBlockHosts"`
		}
		if len(env.Meta) > 0 {
			if err := json.Unmarshal(env.Meta, &p); err != nil {
				return nil, err
			}
		}
		byteLen := p.ByteLength
		if byteLen <= 0 {
			byteLen = len(rawStr)
		}
		return extract.ParseAndValidateEasyPrivacyGo(rawStr, byteLen, p.PreviousHostCount, p.ExtraNeverBlockHosts), nil

	case "detect_prompt_injection":
		if len(env.Meta) == 0 || string(env.Meta) == "null" {
			return extract.DetectPromptInjection(rawStr, ""), nil
		}
		var p struct {
			MDByteLen int `json:"mdByteLen"`
		}
		_ = json.Unmarshal(env.Meta, &p)
		split := p.MDByteLen
		if split < 0 {
			split = 0
		} else if split > len(rawStr) {
			split = len(rawStr)
		}
		return extract.DetectPromptInjection(rawStr[:split], rawStr[split:]), nil

	case "classify_waf":
		var p classify.WAFChallengeInput
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &p)
		}
		p.RawHTML = rawStr
		return map[string]any{"match": classify.ClassifyWAFAndChallengeFull(p)}, nil

	case "classify_content_state":
		var p classify.ContentStateInput
		if len(env.Meta) > 0 {
			_ = json.Unmarshal(env.Meta, &p)
		}
		p.RawHTML = rawStr
		return map[string]any{"result": classify.ClassifyContentStateFull(p)}, nil

	case "has_unicode_tag":
		return map[string]any{"hit": extract.HasRawOrEncodedUnicodeTag(rawStr)}, nil

	default:
		for _, fn := range []func(string, json.RawMessage, string) (any, bool, error){
			phase2JobsRawRPC,
			phase2CatalogRawRPC,
			phase2AgentRawRPC,
			phase2McpRawRPC,
		} {
			if fn != nil {
				if out, handled, err := fn(env.Op, env.Meta, rawStr); handled {
					return out, err
				}
			}
		}
		return nil, fmt.Errorf("unknown raw op %q", env.Op)
	}
}

func defaultHTMLToMD(frag, base string) (string, []string) {
	doc := extract.ExtractHTMLDocumentFull("<!doctype html><html><body>"+frag+"</body></html>", extract.FullExtractOptions{
		BaseURL:         base,
		OnlyMainContent: false,
		IncludeImages:   true,
		IsFragment:      true,
	})
	return doc.Markdown, doc.Links
}

func dispatchWasmRPC(rawReq []byte) (any, error) {
	var env wasmRPCEnvelope
	if err := json.Unmarshal(rawReq, &env); err != nil {
		return nil, err
	}

	switch env.Op {
	case "psl_lookup":
		var p struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		reg := extract.GetRegistrableDomain(p.Host)
		known, isKnown := extract.LookupKnownRegistrableDomain(p.Host)
		return map[string]any{
			"registrableDomain": reg,
			"isSuffix":          reg == "",
			"isPrivateShared":   extract.HasPrivateSharedHostingSuffix(p.Host),
			"knownRegistrable":  known,
			"isKnown":           isKnown,
		}, nil

	case "sanitize_markdown":
		var p struct {
			MD                  string `json:"md"`
			BaseURL             string `json:"baseUrl"`
			AllowPdfPageMarkers bool   `json:"allowPdfPageMarkers"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"out": extract.SanitizeMarkdownWithOptions(p.MD, p.BaseURL, p.AllowPdfPageMarkers),
		}, nil

	case "sanitize_meta":
		var p struct {
			Text   string `json:"text"`
			MaxLen int    `json:"maxLen"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"out": extract.SanitizePlainMetadataText(p.Text, p.MaxLen),
		}, nil

	case "recognize_fences":
		var p struct {
			MD                            string                                `json:"md"`
			Harden                        bool                                  `json:"harden"`
			PreserveCrLf                  bool                                  `json:"preserveCrLf"`
			InitialReopenedFence          *extract.ReopenedMarkdownFence        `json:"initialReopenedFence"`
			InitialState                  *extract.MarkdownFenceRecognizerState `json:"initialState"`
			SkipLeadingSeparatorEmptyLine bool                                  `json:"skipLeadingSeparatorEmptyLine"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		hardened, segs := extract.RecognizeAndHardenMarkdownFences(p.MD, extract.RecognizeMarkdownFencesOptions{
			Harden:                        p.Harden,
			PreserveCrLf:                  p.PreserveCrLf,
			InitialReopenedFence:          p.InitialReopenedFence,
			InitialState:                  p.InitialState,
			SkipLeadingSeparatorEmptyLine: p.SkipLeadingSeparatorEmptyLine,
		})
		return map[string]any{"hardened": hardened, "segments": segs}, nil

	case "slice_checkpoints":
		var p struct {
			FullMD    string `json:"fullMd"`
			StepChars int    `json:"stepChars"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"checkpoints": extract.ComputeMarkdownSliceCheckpoints(p.FullMD, p.StepChars),
		}, nil

	case "sanitize_slice":
		var p struct {
			FullMD              string                            `json:"fullMd"`
			SafeOffset          int                               `json:"safeOffset"`
			SliceInput          string                            `json:"sliceInput"`
			AllowPdfPageMarkers bool                              `json:"allowPdfPageMarkers"`
			Checkpoints         []extract.MarkdownSliceCheckpoint `json:"checkpoints"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"out": extract.SanitizeMarkdownPageSliceUTF16(p.FullMD, p.SafeOffset, p.SliceInput, p.AllowPdfPageMarkers, p.Checkpoints),
		}, nil

	case "full_artifact_markdown":
		var p struct {
			FullMD string `json:"fullMd"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"out": extract.SanitizeFullMarkdownDocumentForArtifact(p.FullMD),
		}, nil

	case "neutralize_unsafe_links":
		var p struct {
			Prose string `json:"prose"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.NeutralizeAllUnsafeMarkdownLinks(p.Prose)}, nil

	case "is_disallowed_link":
		var p struct {
			Href string `json:"href"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"disallowed": extract.IsDisallowedMarkdownLinkDestination(p.Href)}, nil

	case "escape_task_checkboxes":
		var p struct {
			Prose string `json:"prose"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.EscapeGfmTaskListCheckboxes(p.Prose)}, nil

	case "escape_residual_lt":
		var p struct {
			Prose               string `json:"prose"`
			AllowPdfPageMarkers bool   `json:"allowPdfPageMarkers"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.EscapeAllResidualLtInProse(p.Prose, p.AllowPdfPageMarkers)}, nil

	case "strip_invisible":
		var p struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.StripInvisibleSmugglingChars(p.Text)}, nil

	case "strip_table_dividers":
		var p struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.StripMarkdownTableDividerLinesLinear(p.Text)}, nil

	case "clean_fence_info":
		var p struct {
			Info string `json:"info"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.CleanFenceInfoString(p.Info)}, nil

	case "detect_prompt_injection":
		var p struct {
			Markdown string `json:"markdown"`
			RawHTML  string `json:"rawHtml"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return extract.DetectPromptInjection(p.Markdown, p.RawHTML), nil

	case "extract_html_attributes":
		var p struct {
			RawHTML   string                     `json:"rawHtml"`
			Selectors []extract.AttrSelectorSpec `json:"selectors"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"items": extract.ExtractHTMLAttributesBySelectors(p.RawHTML, p.Selectors)}, nil

	case "extract_structured_product":
		var p struct {
			RawBody             string `json:"rawBody"`
			FinalURL            string `json:"finalUrl"`
			FallbackTitle       string `json:"fallbackTitle"`
			FallbackDescription string `json:"fallbackDescription"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"product": extract.ExtractStructuredProduct(p.RawBody, p.FinalURL, p.FallbackTitle, p.FallbackDescription),
		}, nil

	case "split_pdf_pages":
		var p struct {
			RawText  string `json:"rawText"`
			MaxPages int    `json:"maxPages"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		pages, marked := extract.SplitPDFPagesAndMarkers(p.RawText, p.MaxPages)
		return map[string]any{"pages": pages, "markedMarkdown": marked}, nil

	case "list_adapters":
		var p struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal(env.Payload, &p)
		all := extract.ListDeclarativeAdapters()
		if cat := strings.ToLower(strings.TrimSpace(p.Category)); cat != "" {
			filtered := make([]extract.DeclarativeAdapterSummary, 0, len(all))
			for _, a := range all {
				if a.Category == cat {
					filtered = append(filtered, a)
				}
			}
			all = filtered
		}
		return map[string]any{"adapters": all}, nil

	case "find_adapters":
		var p struct {
			Query    string `json:"query"`
			Category string `json:"category"`
			Limit    int    `json:"limit"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"adapters": extract.FindDeclarativeAdapters(p.Query, p.Category, p.Limit)}, nil

	case "resolve_twin":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		m, ok := extract.ResolveDeclarativeTwin(p.URL)
		if !ok || m == nil {
			return map[string]any{"matched": false}, nil
		}
		return map[string]any{
			"matched":      true,
			"id":           m.ID,
			"adapterId":    m.AdapterID,
			"fetchUrl":     m.FetchURL,
			"kind":         string(m.Kind),
			"accept":       m.Accept,
			"rawAccept":    m.RawAccept(),
			"commerceMode": m.CommerceMode(),
		}, nil

	case "validate_twin_redirect":
		var p struct {
			URL      string `json:"url"`
			FinalURL string `json:"finalUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		m, ok := extract.ResolveDeclarativeTwin(p.URL)
		if !ok || m == nil {
			return map[string]any{"valid": false}, nil
		}
		return map[string]any{"valid": m.ValidateRedirectTarget(p.FinalURL)}, nil

	case "format_twin":
		var p struct {
			URL     string `json:"url"`
			RawBody string `json:"rawBody"`
			OrigURL string `json:"origUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		doc, ok := extract.FormatDeclarativeTwinByURL(p.URL, p.RawBody, p.OrigURL)
		if !ok || doc == nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "doc": doc}, nil

	case "post_extract_html":
		var p struct {
			RawHTML   string `json:"rawHtml"`
			BaseURL   string `json:"baseUrl"`
			CurrentMD string `json:"currentMd"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		res, ok := extract.ApplyDeclarativeHTMLExtractor(p.RawHTML, p.BaseURL, p.CurrentMD, defaultHTMLToMD)
		if !ok || res == nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "result": res}, nil

	case "format_yaml_card":
		var p struct {
			RawMD         string `json:"rawMd"`
			FallbackTitle string `json:"fallbackTitle"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		card := extract.FormatYAMLFrontmatterCard(p.RawMD, p.FallbackTitle)
		return card, nil

	case "validate_manifest":
		var p struct {
			Raw    string `json:"raw"`
			IsJSON bool   `json:"isJson"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		var m *extract.DeclarativeAdapterManifest
		var err error
		if p.IsJSON {
			m, err = extract.ParseDeclarativeManifest([]byte(p.Raw))
		} else {
			m, err = extract.ParseDeclarativeYAMLManifest([]byte(p.Raw))
		}
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		if err := extract.CheckApprovedWildcardDomains(m); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		return map[string]any{"ok": true, "manifest": m}, nil

	case "validate_manifest_set":
		var p struct {
			Manifests []extract.DeclarativeAdapterManifest `json:"manifests"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		if err := extract.ValidateDeclarativeManifests(p.Manifests); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		return map[string]any{"ok": true}, nil

	case "matches_approved_wildcard":
		var p struct {
			Wildcard  string `json:"wildcard"`
			Candidate string `json:"candidate"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"ok": extract.MatchesApprovedWildcard(p.Wildcard, p.Candidate)}, nil

	case "manifest_resolve_twin":
		var p struct {
			AdapterID string                              `json:"adapterId"`
			Manifest  *extract.DeclarativeAdapterManifest `json:"manifest"`
			URL       string                              `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		var m *extract.DeclarativeTwinMatch
		var ok bool
		if p.AdapterID != "" {
			if bm := extract.LookupBuiltInManifest(p.AdapterID); bm != nil {
				m, ok = extract.ResolveTwinOnValidatedManifest(bm, p.URL)
			}
		} else if p.Manifest != nil {
			m, ok = extract.ResolveTwinOnManifest(p.Manifest, p.URL)
		}
		if !ok || m == nil {
			return map[string]any{"matched": false}, nil
		}
		return map[string]any{
			"matched":      true,
			"id":           m.ID,
			"adapterId":    m.AdapterID,
			"fetchUrl":     m.FetchURL,
			"kind":         string(m.Kind),
			"accept":       m.Accept,
			"rawAccept":    m.RawAccept(),
			"commerceMode": m.CommerceMode(),
		}, nil

	case "manifest_format_twin":
		var p struct {
			AdapterID string                              `json:"adapterId"`
			Manifest  *extract.DeclarativeAdapterManifest `json:"manifest"`
			URL       string                              `json:"url"`
			RawBody   string                              `json:"rawBody"`
			OrigURL   string                              `json:"origUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		var doc *extract.DeclarativeFormattedDoc
		var ok bool
		if p.AdapterID != "" {
			if bm := extract.LookupBuiltInManifest(p.AdapterID); bm != nil {
				doc, ok = extract.FormatTwinOnValidatedManifest(bm, p.URL, p.RawBody, p.OrigURL)
			}
		} else if p.Manifest != nil {
			doc, ok = extract.FormatTwinOnManifest(p.Manifest, p.URL, p.RawBody, p.OrigURL)
		}
		if !ok || doc == nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "doc": doc}, nil

	case "manifest_extract_html":
		var p struct {
			AdapterID string                              `json:"adapterId"`
			Manifest  *extract.DeclarativeAdapterManifest `json:"manifest"`
			RawHTML   string                              `json:"rawHtml"`
			BaseURL   string                              `json:"baseUrl"`
			CurrentMD string                              `json:"currentMd"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		var res *extract.DeclarativePostFetchResult
		var ok bool
		if p.AdapterID != "" {
			if bm := extract.LookupBuiltInManifest(p.AdapterID); bm != nil {
				res, ok = extract.ExtractHTMLOnValidatedManifest(bm, p.RawHTML, p.BaseURL, p.CurrentMD, defaultHTMLToMD)
			}
		} else if p.Manifest != nil {
			res, ok = extract.ExtractHTMLOnManifest(p.Manifest, p.RawHTML, p.BaseURL, p.CurrentMD, defaultHTMLToMD)
		}
		if !ok || res == nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "result": res}, nil

	case "match_declarative_route":
		var p struct {
			Match extract.DeclarativeMatchSpec `json:"match"`
			URL   string                       `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		params, ok := extract.MatchDeclarativeRouteURL(p.Match, p.URL)
		return map[string]any{"ok": ok, "params": params}, nil

	case "is_safe_twin_url":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"ok": extract.IsSafeDeclarativeTwinURL(p.URL)}, nil

	case "format_json_extract_spec":
		var p struct {
			RawBody string                         `json:"rawBody"`
			Extract extract.DeclarativeExtractSpec `json:"extract"`
			Params  map[string]string              `json:"params"`
			OrigURL string                         `json:"origUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		doc, ok := extract.FormatJSONWithExtractSpec(p.RawBody, p.Extract, p.Params, p.OrigURL)
		return map[string]any{"ok": ok, "doc": doc}, nil

	case "dom_parse":
		var p struct {
			RawHTML  string `json:"rawHtml"`
			MaxChars int    `json:"maxChars"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		doc := extract.ParseHTMLDoc(p.RawHTML, p.MaxChars)
		id := domNextID
		domNextID++
		if domNextID <= 0 {
			domNextID = 1
		}
		slotIdx := int((id - 1) % domRingCapacity)
		domTable[slotIdx] = domDocSlot{
			id:    id,
			doc:   doc,
			nodes: []*extract.HTMLNode{&doc.HTMLNode},
		}
		return map[string]any{"docId": id, "rootNodeId": 0}, nil

	case "dom_select":
		var p struct {
			DocID    int32  `json:"docId"`
			NodeID   int    `json:"nodeId"`
			Selector string `json:"selector"`
			Limit    *int   `json:"limit"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		if p.Limit != nil && *p.Limit <= 0 {
			return map[string]any{"items": []any{}}, nil
		}
		n := lookupDomNode(p.DocID, p.NodeID)
		if n == nil {
			return map[string]any{"items": []any{}}, nil
		}
		lim := 500
		if p.Limit != nil {
			lim = *p.Limit
		}
		hits := n.Select(p.Selector, lim)
		slot := &domTable[int((p.DocID-1)%domRingCapacity)]
		type selRef struct {
			NodeID int    `json:"nodeId"`
			Tag    string `json:"tag"`
		}
		out := make([]selRef, len(hits))
		for i, h := range hits {
			nid := len(slot.nodes)
			slot.nodes = append(slot.nodes, h)
			out[i] = selRef{NodeID: nid, Tag: h.Tag()}
		}
		return map[string]any{"items": out}, nil

	case "dom_node_op":
		var p struct {
			DocID       int32   `json:"docId"`
			NodeID      int     `json:"nodeId"`
			Op          string  `json:"op"`
			SubSelector *string `json:"subSelector"`
			AttrName    string  `json:"attrName"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		n := lookupDomNode(p.DocID, p.NodeID)
		if n == nil {
			return map[string]any{"ok": false}, nil
		}
		switch p.Op {
		case "text":
			if p.SubSelector != nil {
				return map[string]any{"val": n.Text(*p.SubSelector)}, nil
			}
			return map[string]any{"val": n.Text()}, nil
		case "html":
			if p.SubSelector != nil {
				return map[string]any{"val": n.HTML(*p.SubSelector)}, nil
			}
			return map[string]any{"val": n.HTML()}, nil
		case "outerHtml":
			return map[string]any{"val": n.OuterHTML()}, nil
		case "attr":
			v, ok := n.Attr(p.AttrName)
			return map[string]any{"ok": ok, "val": v}, nil
		case "attrOf":
			sub := ""
			if p.SubSelector != nil {
				sub = *p.SubSelector
			}
			return map[string]any{"val": n.AttrOf(sub, p.AttrName)}, nil
		case "dlMap":
			if p.SubSelector != nil {
				return map[string]any{"val": n.DLMap(*p.SubSelector)}, nil
			}
			return map[string]any{"val": n.DLMap()}, nil
		case "tableRows":
			if p.SubSelector != nil {
				return map[string]any{"val": n.TableRows(*p.SubSelector)}, nil
			}
			return map[string]any{"val": n.TableRows()}, nil
		default:
			return nil, fmt.Errorf("unknown dom_node_op %q", p.Op)
		}

	case "html_dom_query":
		var p struct {
			RawHTML     string `json:"rawHtml"`
			MaxChars    int    `json:"maxChars"`
			Selector    string `json:"selector"`
			SubSelector string `json:"subSelector"`
			AttrName    string `json:"attrName"`
			Limit       int    `json:"limit"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		doc := extract.ParseHTMLDoc(p.RawHTML, p.MaxChars)
		if p.Selector == "" {
			var txt, inner string
			if p.SubSelector != "" {
				txt = doc.Text(p.SubSelector)
				inner = doc.HTML(p.SubSelector)
			} else {
				txt = doc.Text()
				inner = doc.HTML()
			}
			var dl map[string]string
			var rows [][]string
			if p.SubSelector != "" {
				dl = doc.DLMap(p.SubSelector)
				rows = doc.TableRows(p.SubSelector)
			} else {
				dl = doc.DLMap()
				rows = doc.TableRows()
			}
			attrVal := ""
			if p.SubSelector != "" && p.AttrName != "" {
				attrVal = doc.AttrOf(p.SubSelector, p.AttrName)
			}
			return map[string]any{
				"text":      txt,
				"html":      inner,
				"outerHtml": doc.OuterHTML(),
				"attr":      attrVal,
				"dlMap":     dl,
				"tableRows": rows,
			}, nil
		}
		lim := p.Limit
		if lim <= 0 {
			lim = 500
		}
		nodes := doc.Select(p.Selector, lim)
		type domItem struct {
			Tag       string            `json:"tag"`
			Text      string            `json:"text"`
			HTML      string            `json:"html"`
			OuterHTML string            `json:"outerHtml"`
			Attr      *string           `json:"attr,omitempty"`
			DLMap     map[string]string `json:"dlMap,omitempty"`
			TableRows [][]string        `json:"tableRows,omitempty"`
		}
		items := make([]domItem, len(nodes))
		for i, n := range nodes {
			it := domItem{
				Tag:       n.Tag(),
				Text:      n.Text(),
				HTML:      n.HTML(),
				OuterHTML: n.OuterHTML(),
			}
			if p.AttrName != "" {
				if v, ok := n.Attr(p.AttrName); ok {
					it.Attr = &v
				}
			}
			items[i] = it
		}
		return map[string]any{"count": len(items), "items": items}, nil

	case "extract_schema_org":
		var p struct {
			RawHTML string `json:"rawHtml"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.ExtractUniversalSchemaOrg(p.RawHTML, p.BaseURL, defaultHTMLToMD)}, nil

	case "inspect_raw_schema_org":
		var p struct {
			RawHTML string `json:"rawHtml"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.InspectRawSchemaOrgJSONLD(p.RawHTML)}, nil

	case "sanitize_schema_url":
		var p struct {
			Raw     any    `json:"raw"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.SanitizeSchemaHTTPSURL(p.Raw, p.BaseURL)}, nil

	case "sanitize_schema_plain":
		var p struct {
			Raw    any `json:"raw"`
			MaxLen int `json:"maxLen"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.SanitizeSchemaPlainField(p.Raw, p.MaxLen)}, nil

	case "sanitize_schema_rich_md":
		var p struct {
			Raw      any    `json:"raw"`
			BaseURL  string `json:"baseUrl"`
			MaxChars int    `json:"maxChars"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.SanitizeSchemaRichMarkdown(p.Raw, p.BaseURL, defaultHTMLToMD, p.MaxChars)}, nil

	case "extract_jsonld_objects":
		var p struct {
			RawHTML     string `json:"rawHtml"`
			MaxEntities int    `json:"maxEntities"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"objects": extract.ExtractJSONLDObjects(p.RawHTML, p.MaxEntities)}, nil

	case "has_unicode_tag":
		var p struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"hit": extract.HasRawOrEncodedUnicodeTag(p.Raw)}, nil

	case "decode_basic_entities":
		var p struct {
			Input string `json:"input"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.DecodeBasicEntities(p.Input)}, nil

	case "is_jsonld_script_attr":
		var p struct {
			AttrStr string `json:"attrStr"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"ok": extract.IsJSONLDScriptAttr(p.AttrStr)}, nil

	case "recover_ssr_hydration":
		var p struct {
			RawHTML string `json:"rawHtml"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.RecoverSSRHydrationContent(p.RawHTML, p.BaseURL, defaultHTMLToMD)}, nil

	case "distill_captured_json":
		var p struct {
			Inputs  []extract.CapturedJSONPayloadInput `json:"inputs"`
			BaseURL string                             `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.DistillCapturedJSONResponses(p.Inputs, p.BaseURL, defaultHTMLToMD)}, nil

	case "extract_next_rsc":
		var p struct {
			RawHTML string `json:"rawHtml"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.ExtractNextRSCFlight(p.RawHTML, p.BaseURL, defaultHTMLToMD)}, nil

	case "extract_state_tree":
		var p struct {
			Root          any    `json:"root"`
			Framework     string `json:"framework"`
			BaseURL       string `json:"baseUrl"`
			RawSourceHint string `json:"rawSourceHint"`
			HasUnicodeTag bool   `json:"hasUnicodeTag"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"result": extract.ExtractFromParsedStateTree(p.Root, p.Framework, p.BaseURL, defaultHTMLToMD, p.RawSourceHint, p.HasUnicodeTag),
		}, nil

	case "deref_nuxt_devalue":
		var p struct {
			Flat     []any `json:"flat"`
			MaxNodes int   `json:"maxNodes"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		if !extract.IsNuxtDevalueFlatArray(p.Flat) {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{
			"ok":    true,
			"value": extract.DereferenceNuxtDevaluePayload(p.Flat, p.MaxNodes),
		}, nil

	case "distill_json_records":
		var p struct {
			Root       any    `json:"root"`
			BaseURL    string `json:"baseUrl"`
			MaxRecords int    `json:"maxRecords"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.DistillStructuredRecordsFull(p.Root, p.BaseURL, p.MaxRecords)}, nil

	case "cms_discover_wp":
		var p struct {
			RawHTML      string `json:"rawHtml"`
			PageFinalURL string `json:"pageFinalUrl"`
			SelfHost     string `json:"selfHost"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"url": extract.DiscoverWordPressRestTwinURL(p.RawHTML, p.PageFinalURL, p.SelfHost)}, nil

	case "cms_resolve_gatsby":
		var p struct {
			RawHTML      string `json:"rawHtml"`
			PageFinalURL string `json:"pageFinalUrl"`
			SelfHost     string `json:"selfHost"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"url": extract.ResolveGatsbyPageDataTwinURL(p.RawHTML, p.PageFinalURL, p.SelfHost)}, nil

	case "cms_format_wp":
		var p struct {
			RawJSON string `json:"rawJson"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.FormatWordPressRestPostJSON(p.RawJSON, p.BaseURL, defaultHTMLToMD)}, nil

	case "cms_format_gatsby":
		var p struct {
			RawJSON string `json:"rawJson"`
			BaseURL string `json:"baseUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.FormatGatsbyPageDataJSON(p.RawJSON, p.BaseURL, defaultHTMLToMD)}, nil

	case "wiki_parse_url":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"article": extract.ParseWikipediaArticleURL(p.URL)}, nil

	case "wiki_canonical_final":
		var p struct {
			RequestedURL     string `json:"requestedUrl"`
			StoredFinalURL   string `json:"storedFinalUrl"`
			ResponseFinalURL string `json:"responseFinalUrl"`
			Title            string `json:"title"`
			Markdown         string `json:"markdown"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		fin := p.StoredFinalURL
		if fin == "" {
			fin = p.ResponseFinalURL
		}
		return map[string]any{"url": extract.ResolveWikipediaCanonicalFinalURLFull(p.RequestedURL, fin, p.Title, p.Markdown)}, nil

	case "wiki_title_guess":
		var p struct {
			Query string `json:"query"`
			Lang  string `json:"lang"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"url": extract.BuildWikipediaDirectTitleGuessURL(p.Query, p.Lang)}, nil

	case "wiki_robots_suggestion":
		var p struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"suggestion": extract.BuildWikimediaRobotsSuggestion(p.Host)}, nil

	case "wiki_clean_markdown":
		var p struct {
			MD string `json:"md"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.CleanMediaWikiMarkdown(p.MD)}, nil

	case "wiki_host_info":
		var p struct {
			Host     string `json:"host"`
			Fallback string `json:"fallback"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"isWikipedia": extract.IsWikipediaHost(p.Host),
			"isWikimedia": extract.IsWikimediaHost(p.Host),
			"lang":        extract.ExtractWikipediaLangFromHost(p.Host),
		}, nil

	case "wiki_is_disallowed_title":
		var p struct {
			Title string `json:"title"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"disallowed": extract.IsDisallowedWikipediaTitle(p.Title)}, nil

	case "detect_framework":
		var p extract.DetectSiteFrameworkParams
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": extract.DetectSiteFramework(p)}, nil

	case "scan_generator_metas":
		var p struct {
			HTML     string `json:"html"`
			MaxChars int    `json:"maxChars"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"generators": extract.ScanGeneratorMetaTags(p.HTML, p.MaxChars)}, nil

	case "extract_inertia_props":
		var p struct {
			RawHTML      string `json:"rawHtml"`
			MaxScanChars int    `json:"maxScanChars"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"props": extract.ExtractInertiaPageProps(p.RawHTML, p.MaxScanChars)}, nil

	case "classify_waf":
		var p classify.WAFChallengeInput
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"match": classify.ClassifyWAFAndChallengeFull(p)}, nil

	case "classify_content_state":
		var p classify.ContentStateInput
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"result": classify.ClassifyContentStateFull(p),
		}, nil

	case "scan_iframes":
		var p struct {
			RawHTML string `json:"rawHtml"`
			PageURL string `json:"pageUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": classify.HasExternalOrWidgetIframe(p.RawHTML, p.PageURL)}, nil

	case "eligible_wayback":
		var p struct {
			Status         int    `json:"status"`
			Outcome        string `json:"outcome"`
			Problem        string `json:"problem"`
			WAFCategory    string `json:"wafCategory"`
			URL            string `json:"url"`
			Method         string `json:"method"`
			HasAuthHeaders bool   `json:"hasAuthHeaders"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		diagOutcome := p.Outcome
		if p.Problem != "" {
			diagOutcome = p.Outcome + " " + p.Problem
		}
		return map[string]any{
			"eligible": classify.IsEligibleForWaybackFallback(p.Status, diagOutcome, p.WAFCategory, p.URL, p.Method, p.HasAuthHeaders),
		}, nil

	case "refine_blocked_map":
		var p classify.RefineBlockedMapInput
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"result": classify.RefineBlockedInfoMap(p)}, nil

	case "refine_blocked":
		var p struct {
			URL                string             `json:"url"`
			Status             int                `json:"status"`
			Outcome            string             `json:"outcome"`
			WAF                *classify.WAFMatch `json:"waf"`
			ExistingSuggestion string             `json:"existingSuggestion"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{
			"result": classify.RefineBlockedInfo(p.URL, p.Status, p.Outcome, p.WAF, p.ExistingSuggestion),
		}, nil

	case "parse_robots":
		var p struct {
			Body      string   `json:"body"`
			UserAgent string   `json:"userAgent"`
			Paths     []string `json:"paths"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		ua := p.UserAgent
		if ua == "" {
			ua = "EdgeFetch"
		}
		entry := politeness.ParseRobotsTxt(p.Body, ua, time.Now().Add(time.Hour))
		allowed := make([]bool, len(p.Paths))
		for i, path := range p.Paths {
			allowed[i] = entry.Allowed(path)
		}
		return map[string]any{
			"allowed":         allowed,
			"crawlDelayMs":    entry.CrawlDelay.Milliseconds(),
			"disallowAiInput": entry.DisallowAIInput,
		}, nil

	case "extract_html_full":
		var p struct {
			RawHTML string                     `json:"rawHtml"`
			Options extract.FullExtractOptions `json:"options"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"doc": extract.ExtractHTMLDocumentFull(p.RawHTML, p.Options)}, nil

	case "finalize_markdown":
		var p struct {
			MD      string                     `json:"md"`
			BaseURL string                     `json:"baseUrl"`
			Options extract.FullExtractOptions `json:"options"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		finalMD, totalChars, returnedChars, truncated, nextOffset := extract.FinalizeScrapedMarkdown(p.MD, p.BaseURL, p.Options)
		return map[string]any{
			"markdown":      finalMD,
			"totalChars":    totalChars,
			"returnedChars": returnedChars,
			"truncated":     truncated,
			"nextOffset":    nextOffset,
		}, nil

	case "parse_llms_txt":
		var p struct {
			Raw       string `json:"raw"`
			SourceURL string `json:"sourceUrl"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		doc, ok := extract.ParseLlmsTxt(p.Raw, p.SourceURL)
		return map[string]any{"ok": ok, "doc": doc}, nil

	case "redact_pii":
		var p struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.RedactPIIMarkdownSafe(p.Text)}, nil

	case "clean_pdf_markdown":
		var p struct {
			MD string `json:"md"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.CleanPDFMarkdown(p.MD)}, nil

	case "extract_pdf_title":
		var p struct {
			MD  string `json:"md"`
			URL string `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"title": extract.ExtractPDFTitle(p.MD, p.URL)}, nil

	case "parse_frontmatter":
		var p struct {
			MD string `json:"md"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		title, desc, body := extract.ParseMarkdownFrontmatter(p.MD)
		return map[string]any{"title": title, "description": desc, "body": body}, nil

	case "extract_md_links_images":
		var p struct {
			MD            string `json:"md"`
			BaseURL       string `json:"baseUrl"`
			IncludeImages *bool  `json:"includeImages"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		incImg := true
		if p.IncludeImages != nil {
			incImg = *p.IncludeImages
		}
		links, images, title, desc := extract.ExtractMarkdownLinksImagesAndMeta(p.MD, p.BaseURL, incImg)
		return map[string]any{"links": links, "images": images, "title": title, "description": desc}, nil

	case "sanitize_scraped_meta":
		var p struct {
			Raw    string `json:"raw"`
			MaxLen int    `json:"maxLen"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.SanitizeScrapedMetadataField(p.Raw, p.MaxLen)}, nil

	case "sanitize_scraped_ts":
		var p struct {
			Raw    string `json:"raw"`
			MaxLen int    `json:"maxLen"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.SanitizeScrapedTimestampField(p.Raw, p.MaxLen)}, nil

	case "extract_largest_srcset":
		var p struct {
			Srcset string `json:"srcset"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"url": extract.ExtractLargestURLFromSrcset(p.Srcset)}, nil

	case "collapse_tickers":
		var p struct {
			Prose string `json:"prose"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.CollapseAnimatedCounterTickers(p.Prose)}, nil

	case "format_payload":
		var p struct {
			Kind        string         `json:"kind"`
			Raw         string         `json:"raw"`
			URL         string         `json:"url"`
			ContentType string         `json:"contentType"`
			Sep         string         `json:"sep"`
			TitleHint   string         `json:"titleHint"`
			Props       map[string]any `json:"props"`
			DataBase64  string         `json:"dataBase64"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		switch p.Kind {
		case "ipynb":
			return map[string]any{"doc": extract.FormatJupyterNotebookToMarkdown(p.Raw, p.URL)}, nil
		case "openapi":
			return map[string]any{"doc": extract.FormatOpenAPISpecToMarkdown(p.Raw, p.URL)}, nil
		case "vcard":
			return map[string]any{"doc": extract.FormatVCardToMarkdown(p.Raw)}, nil
		case "icalendar":
			return map[string]any{"doc": extract.FormatICalendarToMarkdown(p.Raw)}, nil
		case "git_patch":
			return map[string]any{"doc": extract.FormatGitPatchToMarkdown(p.Raw, p.URL)}, nil
		case "source_code":
			return map[string]any{"doc": extract.FormatSourceCodeURLToMarkdown(p.Raw, p.URL, p.ContentType)}, nil
		case "feed_xml":
			doc, links := extract.FormatFeedXMLToMarkdown(p.Raw, p.URL)
			return map[string]any{"doc": doc, "links": links}, nil
		case "delimited":
			return map[string]any{"doc": extract.FormatDelimitedTableToMarkdown(p.Raw, p.Sep, p.TitleHint)}, nil
		case "json_scrape":
			return map[string]any{"doc": extract.TryParseJSONPayloadForScrape(p.Raw, p.URL)}, nil
		case "inertia_props":
			return map[string]any{"doc": extract.FormatInertiaPagePropsToMarkdown(p.Props, p.URL)}, nil
		case "quick_bytes":
			rawBytes, err := base64.StdEncoding.DecodeString(p.DataBase64)
			if err != nil {
				return map[string]any{"out": ""}, nil
			}
			return map[string]any{"out": extract.DeriveQuickMarkdownFromRawBytes(rawBytes, p.URL)}, nil
		default:
			return nil, fmt.Errorf("unknown format_payload kind %q", p.Kind)
		}

	case "detect_binary":
		var p struct {
			DataBase64  string `json:"dataBase64"`
			ContentType string `json:"contentType"`
			URL         string `json:"url"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		rawBytes, _ := base64.StdEncoding.DecodeString(p.DataBase64)
		unsup, mime, reason := extract.DetectUnsupportedBinaryPayload(rawBytes, p.ContentType, p.URL)
		return map[string]any{"unsupported": unsup, "mimeLabel": mime, "reason": reason}, nil

	case "extract_structured_json":
		var p struct {
			RawHTML string                        `json:"rawHtml"`
			Doc     extract.ExtractedDocumentFull `json:"doc"`
			Schema  map[string]any                `json:"schema"`
			Prompt  string                        `json:"prompt"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		res, matched, unfilled := extract.ExtractStructuredJSONFromPageWithDiagnostics(p.RawHTML, p.Doc, p.Schema, p.Prompt)
		return map[string]any{
			"result":         res,
			"matchedFields":  matched,
			"unfilledFields": unfilled,
		}, nil

	case "extract_youtube":
		var p struct {
			RawHTML           string `json:"rawHtml"`
			URL               string `json:"url"`
			IncludeTranscript bool   `json:"includeTranscript"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		out := map[string]any{
			"meta": extract.ExtractYouTubeWatchMetadataFromHTML(p.RawHTML, p.URL),
		}
		if p.IncludeTranscript {
			out["transcript"] = extract.ExtractYouTubeTranscriptFromHTML(p.RawHTML)
		}
		return out, nil

	case "decode_html_entities":
		var p struct {
			Input string `json:"input"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.DecodeHTMLEntities(p.Input)}, nil

	case "decode_markdown_entities":
		var p struct {
			MD string `json:"md"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.DecodeMarkdownEntities(p.MD)}, nil

	case "make_safe_fence":
		var p struct {
			Code        string `json:"code"`
			Lang        string `json:"lang"`
			PreferTilde bool   `json:"preferTilde"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"out": extract.MakeSafeCodeFence(p.Code, p.Lang, p.PreferTilde)}, nil

	case "split_fences":
		var p struct {
			MD string `json:"md"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, err
		}
		return map[string]any{"segments": extract.SplitMarkdownByCodeFences(p.MD)}, nil

	default:
		for _, fn := range []func(string, json.RawMessage) (any, bool, error){
			phase2JobsRPC,
			phase2CatalogRPC,
			phase2AgentRPC,
			phase2McpRPC,
		} {
			if fn != nil {
				if out, handled, err := fn(env.Op, env.Payload); handled {
					return out, err
				}
			}
		}
		return nil, fmt.Errorf("unknown wasm op %q", env.Op)
	}
}
