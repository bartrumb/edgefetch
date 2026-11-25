package mcpfed

import (
	"encoding/json"
	"strings"
)

var safeResourceMimeRe = newLazyRegexp(`^(?:text/(?:plain|markdown|csv|xml)|application/(?:json|ld\+json))(?:\s*;.*)?$`)

// SanitizeCallToolRPCResponse sanitizes a complete downstream JSON-RPC tools/call response (result or error)
// in a single Go pass, enforcing H3/M10 block, byte, depth, and secret-redaction budgets.
func SanitizeCallToolRPCResponse(
	rpcObj OrderedObject,
	serverSlug, serverName, remoteOrigin, toolName, sanitizeBaseURL, selfHost string,
	tokenRefreshed bool,
	activeSecret *VaultSecretPayload,
) (status int, body OrderedObject) {
	if rawErr, hasErr := rpcObj.Get("error"); hasErr && rawErr != nil {
		errObj, _ := rawErr.(OrderedObject)
		rawMsg := "Remote MCP tool call returned an error"
		if mVal, hasM := errObj.Get("message"); hasM && mVal != nil {
			rawMsg = stringifyAnySimple(mVal)
		}
		msgSan := SanitizeConnectorText(rawMsg, 400, sanitizeBaseURL, true, activeSecret)

		var dataSan *SanitizedConnectorStructuredResult
		if rawData, hasData := errObj.Get("data"); hasData {
			if dataStr, isStr := rawData.(string); isStr {
				sSan := SanitizeConnectorText(dataStr, MaxMCPRPCErrorDataStringChars, sanitizeBaseURL, true, activeSecret)
				dataSan = &SanitizedConnectorStructuredResult{
					Value:          sSan.Text,
					Sanitized:      sSan.Sanitized,
					FullySanitized: sSan.FullySanitized,
					Truncated:      sSan.Truncated,
					Detected:       sSan.Detected,
					Scrubbed:       sSan.Scrubbed,
					Triggers:       sSan.Triggers,
				}
			} else if MeasureOrderedJSONSizeCapped(rawData, MaxMCPRPCErrorDataBytes) > MaxMCPRPCErrorDataBytes {
				dataSan = &SanitizedConnectorStructuredResult{
					Value:          "[truncated]",
					Sanitized:      true,
					FullySanitized: false,
					Truncated:      true,
					Scrubbed:       true,
					Triggers:       []string{},
				}
			} else {
				errTotalCap := MaxMCPRPCErrorDataBytes
				candSan := SanitizeConnectorStructuredValue(rawData, StructuredSanitizeOptions{
					BaseURL:                sanitizeBaseURL,
					ApplyRedact:            true,
					RedactSecret:           activeSecret,
					MaxDepth:               MaxMCPRPCErrorDataDepth,
					MaxEntriesPerContainer: MaxMCPRPCErrorDataEntries,
					MaxNodeBudget:          MaxMCPRPCErrorDataNodes,
					MaxStringChars:         MaxMCPRPCErrorDataStringChars,
					MaxTotalChars:          &errTotalCap,
				})
				serBytes, serErr := MarshalUnescapedJSON(candSan.Value)
				if serErr != nil || len(serBytes) == 0 || utf16Len(string(serBytes)) > MaxMCPRPCErrorDataBytes {
					dataSan = &SanitizedConnectorStructuredResult{
						Value:          "[truncated]",
						Sanitized:      candSan.Sanitized,
						FullySanitized: false,
						Truncated:      true,
						Detected:       candSan.Detected,
						Scrubbed:       true,
						Triggers:       candSan.Triggers,
					}
				} else {
					dataSan = &candSan
				}
			}
		}

		codeVal := any(-32000)
		if rawCode, hasCode := errObj.Get("code"); hasCode {
			if n, isNum := rawCode.(json.Number); isNum {
				if _, ok := numberToFiniteFloat(n); ok {
					codeVal = n
				}
			}
		}
		var dataTriggers []string
		if dataSan != nil {
			dataTriggers = dataSan.Triggers
		}
		errTriggers := mergeUniqueStrings(msgSan.Triggers, dataTriggers)
		san := msgSan.Sanitized && (dataSan == nil || dataSan.Sanitized)
		fullSan := msgSan.FullySanitized && (dataSan == nil || dataSan.FullySanitized)
		out := OrderedObject{
			{Key: "ok", Value: false},
			{Key: "visibility", Value: "private"},
			{Key: "server", Value: serverSlug},
			{Key: "tool", Value: toolName},
			{Key: "error", Value: "remote_mcp_tool_error"},
			{Key: "code", Value: codeVal},
			{Key: "message", Value: msgSan.Text},
		}
		if dataSan != nil {
			out.Set("data", dataSan.Value)
		}
		out.Set("sanitized", san)
		out.Set("fullySanitized", fullSan)
		out.Set("promptInjection", OrderedObject{
			{Key: "detected", Value: msgSan.Detected || (dataSan != nil && dataSan.Detected)},
			{Key: "scrubbed", Value: msgSan.Scrubbed || (dataSan != nil && dataSan.Scrubbed)},
			{Key: "triggers", Value: errTriggers},
		})
		return 502, out
	}

	rawResult, _ := rpcObj.GetObject("result")
	rawContent, _ := rawResult.GetArray("content")
	sanitizedContent := make([]any, 0, min(len(rawContent), MaxMCPContentBlocks))
	anyDetected := false
	anyScrubbed := false
	contentBlocksAllSanitized := true
	fullySanitized := len(rawContent) <= MaxMCPContentBlocks
	droppedContentBlocks := 0
	var triggers []string
	seenTrig := make(map[string]bool)
	addTrig := func(trs []string) {
		for _, tr := range trs {
			if tr != "" && !seenTrig[tr] {
				seenTrig[tr] = true
				triggers = append(triggers, tr)
			}
		}
	}

	remainingTextBudget := MaxRemoteMCPResponseBytes
	blockLimit := min(len(rawContent), MaxMCPContentBlocks)
	for i := 0; i < blockLimit; i++ {
		if remainingTextBudget <= 0 {
			fullySanitized = false
			break
		}
		block, isObj := rawContent[i].(OrderedObject)
		if !isObj {
			droppedContentBlocks++
			continue
		}
		bTypeRaw, _ := block.GetString("type")
		bType := strings.ToLower(strings.TrimSpace(bTypeRaw))
		if bType == "text" {
			textStr, isStr := block.GetString("text")
			if !isStr {
				droppedContentBlocks++
				continue
			}
			blockBudget := min(MaxMCPBlockTextChars, remainingTextBudget)
			rawBlockSlice, wasSliced := sliceUTF16(textStr, blockBudget)
			if wasSliced {
				fullySanitized = false
			}
			remainingTextBudget -= utf16Len(rawBlockSlice)
			san := SanitizeConnectorText(rawBlockSlice, blockBudget, sanitizeBaseURL, true, activeSecret)
			if !san.Sanitized {
				contentBlocksAllSanitized = false
			}
			if !san.FullySanitized {
				fullySanitized = false
			}
			if san.Detected {
				anyDetected = true
			}
			if san.Scrubbed {
				anyScrubbed = true
			}
			addTrig(san.Triggers)
			sanitizedContent = append(sanitizedContent, OrderedObject{
				{Key: "type", Value: "text"},
				{Key: "text", Value: san.Text},
			})
		} else if bType == "resource" {
			resObj, isResObj := block.GetObject("resource")
			if !isResObj {
				droppedContentBlocks++
				continue
			}
			resTextStr, isStr := resObj.GetString("text")
			if !isStr {
				droppedContentBlocks++
				continue
			}
			blockBudget := min(MaxMCPBlockTextChars, remainingTextBudget)
			rawResSlice, wasSliced := sliceUTF16(resTextStr, blockBudget)
			if wasSliced {
				fullySanitized = false
			}
			remainingTextBudget -= utf16Len(rawResSlice)
			resSan := SanitizeConnectorText(rawResSlice, blockBudget, sanitizeBaseURL, true, activeSecret)
			if !resSan.Sanitized {
				contentBlocksAllSanitized = false
			}
			if !resSan.FullySanitized {
				fullySanitized = false
			}
			if resSan.Detected {
				anyDetected = true
			}
			if resSan.Scrubbed {
				anyScrubbed = true
			}
			addTrig(resSan.Triggers)

			resOut := make(OrderedObject, 0, 3)
			if uriRaw, ok := resObj.GetString("uri"); ok {
				if uriCheck := IsSafePublicHTTPSURL(uriRaw, selfHost); uriCheck.OK {
					resOut.Set("uri", uriCheck.Normalized)
				}
			}
			if mimeRaw, ok := resObj.GetString("mimeType"); ok {
				cleanMime := strings.ToLower(strings.TrimSpace(mimeRaw))
				if safeResourceMimeRe.MatchString(cleanMime) {
					slicedMime, _ := sliceUTF16(cleanMime, 80)
					resOut.Set("mimeType", slicedMime)
				}
			}
			resOut.Set("text", resSan.Text)
			sanitizedContent = append(sanitizedContent, OrderedObject{
				{Key: "type", Value: "resource"},
				{Key: "resource", Value: resOut},
			})
		} else {
			droppedContentBlocks++
		}
	}

	var sanitizedStructured any
	hasStructured := false
	structuredAllSanitized := true
	if rawSC, existsSC := rawResult.Get("structuredContent"); existsSC {
		hasStructured = true
		structBudget := min(MaxMCPBlockTextChars, max(0, remainingTextBudget))
		if structBudget <= 0 || MeasureOrderedJSONSizeCapped(rawSC, structBudget) > structBudget {
			sanitizedStructured = "[truncated]"
			fullySanitized = false
		} else {
			structRes := SanitizeConnectorStructuredValue(rawSC, StructuredSanitizeOptions{
				BaseURL:       sanitizeBaseURL,
				ApplyRedact:   true,
				RedactSecret:  activeSecret,
				MaxTotalChars: &structBudget,
			})
			structuredAllSanitized = structRes.Sanitized
			if !structRes.FullySanitized {
				fullySanitized = false
			}
			if structRes.Detected {
				anyDetected = true
			}
			if structRes.Scrubbed {
				anyScrubbed = true
			}
			addTrig(structRes.Triggers)

			serBytes, serErr := MarshalUnescapedJSON(structRes.Value)
			serLen := 0
			if serErr != nil {
				structuredAllSanitized = false
			} else {
				serLen = utf16Len(string(serBytes))
			}
			if serErr != nil || serLen > structBudget {
				sanitizedStructured = "[truncated]"
				fullySanitized = false
			} else {
				sanitizedStructured = structRes.Value
			}
		}
	}

	srvNameSan := SanitizeConnectorText(serverName, 120, sanitizeBaseURL, true, activeSecret)
	if !srvNameSan.Sanitized {
		contentBlocksAllSanitized = false
	}
	isRemoteError := isTruthyJSONValue(rawResult, "isError")
	dynamicallySanitized := contentBlocksAllSanitized && structuredAllSanitized
	if triggers == nil {
		triggers = []string{}
	}

	out := OrderedObject{
		{Key: "ok", Value: !isRemoteError},
		{Key: "action", Value: "call_tool"},
		{Key: "visibility", Value: "private"},
		{Key: "via", Value: "mcp:" + serverSlug},
		{Key: "server", Value: serverSlug},
		{Key: "serverName", Value: srvNameSan.Text},
		{Key: "remoteOrigin", Value: remoteOrigin},
		{Key: "tool", Value: toolName},
		{Key: "isError", Value: isRemoteError},
	}
	if tokenRefreshed {
		out.Set("tokenRefreshed", true)
	}
	if droppedContentBlocks > 0 {
		out.Set("droppedContentBlocks", droppedContentBlocks)
	}
	out.Set("sanitized", dynamicallySanitized)
	out.Set("fullySanitized", dynamicallySanitized && fullySanitized)
	out.Set("promptInjection", OrderedObject{
		{Key: "detected", Value: anyDetected},
		{Key: "scrubbed", Value: anyScrubbed},
		{Key: "triggers", Value: triggers},
	})
	out.Set("content", sanitizedContent)
	if hasStructured {
		out.Set("structuredContent", sanitizedStructured)
	}

	httpStatus := 200
	if isRemoteError {
		httpStatus = 502
	}
	return httpStatus, out
}

func isTruthyJSONValue(obj OrderedObject, key string) bool {
	v, ok := obj.Get(key)
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, ok := numberToFiniteFloat(x)
		return ok && f != 0
	default:
		return true
	}
}

func stringifyAnySimple(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		b, err := MarshalUnescapedJSON(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
