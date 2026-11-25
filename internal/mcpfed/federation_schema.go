package mcpfed

import (
	"encoding/json"
	"math"
	"strings"
)

var (
	whitespaceRunRe = newLazyRegexp(`\s+`)
)

var allowedJSONSchemaTypes = map[string]bool{
	"object":  true,
	"string":  true,
	"number":  true,
	"integer": true,
	"boolean": true,
	"array":   true,
	"null":    true,
}

var allowedSchemaKeywords = map[string]bool{
	"type":                 true,
	"properties":           true,
	"required":             true,
	"description":          true,
	"enum":                 true,
	"items":                true,
	"minimum":              true,
	"maximum":              true,
	"minLength":            true,
	"maxLength":            true,
	"additionalProperties": true,
}

// SanitizedToolDefsResult holds sanitized downstream MCP tools/list schemas.
type SanitizedToolDefsResult struct {
	Tools                   []CachedMCPToolSchema `json:"tools"`
	PromptInjectionScrubbed bool                  `json:"promptInjectionScrubbed"`
	OversizedRejected       bool                  `json:"oversizedRejected,omitempty"`
}

// RebuildSafeMCPInputSchema rebuilds a downstream MCP tool inputSchema via a strict recursive allowlist walker (H3).
func RebuildSafeMCPInputSchema(rawNode any, depth int) (OrderedObject, bool) {
	src, isObj := rawNode.(OrderedObject)
	if !isObj || depth > 6 {
		if depth == 0 {
			return OrderedObject{
				{Key: "type", Value: "object"},
				{Key: "properties", Value: OrderedObject{}},
			}, false
		}
		return OrderedObject{}, false
	}

	out := make(OrderedObject, 0, 6)
	scrubbed := false

	for _, entry := range src {
		k := entry.Key
		if k != "$schema" && !allowedSchemaKeywords[k] {
			switch entry.Value.(type) {
			case string, OrderedObject, []any:
				if ser, err := MarshalUnescapedJSON(entry.Value); err == nil {
					sliced, _ := sliceUTF16(string(ser), 4096)
					if SanitizeRemoteMCPText(sliced, 4096).Detected {
						scrubbed = true
					}
				}
			}
		}
	}

	if typeStr, ok := src.GetString("type"); ok && allowedJSONSchemaTypes[typeStr] {
		out.Set("type", typeStr)
	} else if typeArr, ok := src.GetArray("type"); ok {
		validTypes := make([]string, 0, 4)
		for _, item := range typeArr {
			if ts, isStr := item.(string); isStr && allowedJSONSchemaTypes[ts] {
				validTypes = append(validTypes, ts)
				if len(validTypes) >= 4 {
					break
				}
			}
		}
		if len(validTypes) > 0 {
			out.Set("type", validTypes)
		}
	} else if depth == 0 {
		out.Set("type", "object")
	}

	if descRaw, ok := src.GetString("description"); ok {
		descClean := strings.TrimSpace(whitespaceRunRe.ReplaceAllString(StripMCPSmugglingChars(descRaw), " "))
		descClean, _ = sliceUTF16(descClean, 240)
		if descClean != "" {
			descCheck := SanitizeRemoteMCPText(descClean, 240)
			if descCheck.Detected {
				scrubbed = true
			} else {
				out.Set("description", SanitizeMCPMarkdownOutput(descCheck.Text, "", 240))
			}
		}
	}

	var validPropKeys map[string]bool
	if propsObj, hasProps := src.GetObject("properties"); hasProps {
		limit := min(len(propsObj), 32)
		rebuiltProps := make(OrderedObject, 0, limit)
		validPropKeys = make(map[string]bool, limit)
		for i := 0; i < limit; i++ {
			cleanKey := strings.TrimSpace(StripMCPSmugglingChars(propsObj[i].Key))
			if !IsSafeMCPIdentifier(cleanKey) {
				scrubbed = true
				continue
			}
			if SanitizeRemoteMCPText(cleanKey, 64).Detected {
				scrubbed = true
				continue
			}
			childSchema, childScrubbed := RebuildSafeMCPInputSchema(propsObj[i].Value, depth+1)
			if childScrubbed {
				scrubbed = true
			}
			rebuiltProps.Set(cleanKey, childSchema)
			validPropKeys[cleanKey] = true
		}
		out.Set("properties", rebuiltProps)
	} else if outType, _ := out.GetString("type"); outType == "object" && depth == 0 {
		out.Set("properties", OrderedObject{})
	}

	if reqArr, hasReq := src.GetArray("required"); hasReq {
		limit := min(len(reqArr), 32)
		reqOut := make([]string, 0, limit)
		seenReq := make(map[string]bool, limit)
		for i := 0; i < limit; i++ {
			rStr, isStr := reqArr[i].(string)
			if isStr && IsSafeMCPIdentifier(rStr) && (validPropKeys == nil || validPropKeys[rStr]) && !seenReq[rStr] {
				seenReq[rStr] = true
				reqOut = append(reqOut, rStr)
			}
		}
		if len(reqOut) > 0 {
			out.Set("required", reqOut)
		}
	}

	if enumArr, hasEnum := src.GetArray("enum"); hasEnum {
		limit := min(len(enumArr), 32)
		enumOut := make([]any, 0, limit)
		for i := 0; i < limit; i++ {
			switch ev := enumArr[i].(type) {
			case string:
				cleanEv, _ := sliceUTF16(StripMCPSmugglingChars(ev), 120)
				if SanitizeRemoteMCPText(cleanEv, 120).Detected {
					scrubbed = true
					continue
				}
				enumOut = append(enumOut, cleanEv)
			case json.Number:
				if _, ok := numberToFiniteFloat(ev); ok {
					enumOut = append(enumOut, ev)
				}
			case bool:
				enumOut = append(enumOut, ev)
			case nil:
				enumOut = append(enumOut, nil)
			}
		}
		if len(enumOut) > 0 {
			out.Set("enum", enumOut)
		}
	}

	if itemsObj, hasItems := src.GetObject("items"); hasItems {
		itemSchema, itemScrubbed := RebuildSafeMCPInputSchema(itemsObj, depth+1)
		if itemScrubbed {
			scrubbed = true
		}
		out.Set("items", itemSchema)
	}

	if minVal, ok := src.Get("minimum"); ok {
		if n, isNum := minVal.(json.Number); isNum {
			if _, finite := numberToFiniteFloat(n); finite {
				out.Set("minimum", n)
			}
		}
	}
	if maxVal, ok := src.Get("maximum"); ok {
		if n, isNum := maxVal.(json.Number); isNum {
			if _, finite := numberToFiniteFloat(n); finite {
				out.Set("maximum", n)
			}
		}
	}
	if minLenVal, ok := src.Get("minLength"); ok {
		if n, isNum := minLenVal.(json.Number); isNum {
			if f, finite := numberToFiniteFloat(n); finite && math.Trunc(f) == f && f >= 0 && f <= 1048576 {
				out.Set("minLength", int64(f))
			}
		}
	}
	if maxLenVal, ok := src.Get("maxLength"); ok {
		if n, isNum := maxLenVal.(json.Number); isNum {
			if f, finite := numberToFiniteFloat(n); finite && math.Trunc(f) == f && f >= 0 && f <= 1048576 {
				out.Set("maxLength", int64(f))
			}
		}
	}
	if addProps, ok := src.GetBool("additionalProperties"); ok {
		out.Set("additionalProperties", addProps)
	}

	return out, scrubbed
}

// SanitizeRemoteMCPToolDefs validates and sanitizes a downstream tools/list array under a 16 KiB raw schema ceiling (H3).
func SanitizeRemoteMCPToolDefs(rawToolsJSON []byte) SanitizedToolDefsResult {
	parsedAny, err := ParseOrderedJSON(rawToolsJSON, 32)
	if err != nil {
		return SanitizedToolDefsResult{Tools: []CachedMCPToolSchema{}, PromptInjectionScrubbed: false}
	}
	arr, isArr := parsedAny.([]any)
	if !isArr {
		return SanitizedToolDefsResult{Tools: []CachedMCPToolSchema{}, PromptInjectionScrubbed: false}
	}

	compactTotal, err := MarshalUnescapedJSON(arr)
	if err != nil || len(compactTotal) > MaxMCPToolSchemaBytes {
		return SanitizedToolDefsResult{Tools: []CachedMCPToolSchema{}, PromptInjectionScrubbed: false, OversizedRejected: true}
	}

	limit := min(len(arr), 64)
	tools := make([]CachedMCPToolSchema, 0, limit)
	promptInjectionScrubbed := false

	for i := 0; i < limit; i++ {
		if arr[i] == nil {
			continue
		}
		tObj, isObj := arr[i].(OrderedObject)
		if !isObj {
			continue
		}
		itemBytes, err := MarshalUnescapedJSON(tObj)
		if err != nil || len(itemBytes) > MaxMCPToolSchemaBytes {
			return SanitizedToolDefsResult{Tools: []CachedMCPToolSchema{}, PromptInjectionScrubbed: false, OversizedRejected: true}
		}

		nameStr, _ := tObj.GetString("name")
		rawName := strings.TrimSpace(StripMCPSmugglingChars(nameStr))
		if !IsSafeMCPIdentifier(rawName) {
			promptInjectionScrubbed = true
			continue
		}
		if SanitizeRemoteMCPText(rawName, 64).Detected {
			promptInjectionScrubbed = true
			continue
		}

		var titleSan *SanitizedConnectorTextResult
		if titleStr, ok := tObj.GetString("title"); ok {
			r := SanitizeConnectorText(titleStr, 120, "", false, nil)
			titleSan = &r
			if r.Detected {
				promptInjectionScrubbed = true
			}
		}
		var descSan *SanitizedConnectorTextResult
		if descStr, ok := tObj.GetString("description"); ok {
			r := SanitizeConnectorText(descStr, 240, "", false, nil)
			descSan = &r
			if r.Detected {
				promptInjectionScrubbed = true
			}
		}

		rawSchema, _ := tObj.Get("inputSchema")
		rebuiltSchema, schemaScrubbed := RebuildSafeMCPInputSchema(rawSchema, 0)
		if schemaScrubbed {
			promptInjectionScrubbed = true
		}

		annotations, _ := tObj.GetObject("annotations")
		var readOnlyHint *bool
		if ro, ok := annotations.GetBool("readOnlyHint"); ok {
			roCopy := ro
			readOnlyHint = &roCopy
		} else if ro, ok := tObj.GetBool("readOnlyHint"); ok {
			roCopy := ro
			readOnlyHint = &roCopy
		}

		var destructiveHint *bool
		if dh, ok := annotations.GetBool("destructiveHint"); ok {
			dhCopy := dh
			destructiveHint = &dhCopy
		} else if dh, ok := tObj.GetBool("destructiveHint"); ok {
			dhCopy := dh
			destructiveHint = &dhCopy
		}

		outTool := CachedMCPToolSchema{
			Name:            rawName,
			InputSchema:     rebuiltSchema,
			ReadOnlyHint:    readOnlyHint,
			DestructiveHint: destructiveHint,
		}
		if titleSan != nil && !titleSan.Detected && titleSan.Text != "" {
			outTool.Title = titleSan.Text
		}
		if descSan != nil && !descSan.Detected && descSan.Text != "" {
			outTool.Description = descSan.Text
		}
		tools = append(tools, outTool)
	}

	return SanitizedToolDefsResult{
		Tools:                   tools,
		PromptInjectionScrubbed: promptInjectionScrubbed,
	}
}
