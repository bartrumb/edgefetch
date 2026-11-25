package mcpfed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const (
	sentinelNonJSONKey = "\x00ef_nonjson"
	sentinelBigIntKey  = "\x00ef_bigint"
	sentinelCycleKey   = "\x00ef_cycle"
)

// OrderedEntry represents a single key-value pair in a JSON object preserving wire order.
type OrderedEntry struct {
	Key   string
	Value any
}

// OrderedObject is an insertion-order-preserving JSON object slice.
type OrderedObject []OrderedEntry

// SpecialSentinel represents non-JSON JS values (functions/symbols, BigInt, circular refs) bridged over JSON.
type SpecialSentinel struct {
	Kind string
	Raw  string
}

// Get returns the value for key if present.
func (o OrderedObject) Get(key string) (any, bool) {
	for i := range o {
		if o[i].Key == key {
			return o[i].Value, true
		}
	}
	return nil, false
}

// GetString returns a string field if present and typed as string.
func (o OrderedObject) GetString(key string) (string, bool) {
	v, ok := o.Get(key)
	if !ok {
		return "", false
	}
	s, isStr := v.(string)
	return s, isStr
}

// GetBool returns a boolean field if present and typed as bool.
func (o OrderedObject) GetBool(key string) (bool, bool) {
	v, ok := o.Get(key)
	if !ok {
		return false, false
	}
	b, isBool := v.(bool)
	return b, isBool
}

// GetObject returns a nested OrderedObject if present.
func (o OrderedObject) GetObject(key string) (OrderedObject, bool) {
	v, ok := o.Get(key)
	if !ok {
		return nil, false
	}
	sub, isObj := v.(OrderedObject)
	return sub, isObj
}

// GetArray returns a nested []any if present.
func (o OrderedObject) GetArray(key string) ([]any, bool) {
	v, ok := o.Get(key)
	if !ok {
		return nil, false
	}
	arr, isArr := v.([]any)
	return arr, isArr
}

// Set inserts or updates key in place while preserving initial insertion order.
func (o *OrderedObject) Set(key string, val any) {
	s := *o
	for i := range s {
		if s[i].Key == key {
			s[i].Value = val
			return
		}
	}
	*o = append(s, OrderedEntry{Key: key, Value: val})
}

// Delete removes key if present.
func (o *OrderedObject) Delete(key string) {
	s := *o
	for i := range s {
		if s[i].Key == key {
			*o = append(s[:i], s[i+1:]...)
			return
		}
	}
}

// Clone shallow-copies the OrderedObject slice.
func (o OrderedObject) Clone() OrderedObject {
	if o == nil {
		return OrderedObject{}
	}
	out := make(OrderedObject, len(o))
	copy(out, o)
	return out
}

// MarshalJSON serializes OrderedObject as a JSON object without HTML escaping.
func (o OrderedObject) MarshalJSON() ([]byte, error) {
	return MarshalUnescapedJSON(o)
}

// UnmarshalJSON parses a JSON object into OrderedObject preserving wire order.
func (o *OrderedObject) UnmarshalJSON(data []byte) error {
	val, err := ParseOrderedJSON(data, 64)
	if err != nil {
		return err
	}
	if val == nil {
		*o = nil
		return nil
	}
	obj, ok := val.(OrderedObject)
	if !ok {
		return errors.New("expected JSON object")
	}
	*o = obj
	return nil
}

func writeUnescapedJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	last := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x20 && b != '"' && b != '\\' {
			continue
		}
		if i > last {
			buf.WriteString(s[last:i])
		}
		switch b {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			const hex = "0123456789abcdef"
			buf.WriteString(`\u00`)
			buf.WriteByte(hex[b>>4])
			buf.WriteByte(hex[b&0x0f])
		}
		last = i + 1
	}
	if last < len(s) {
		buf.WriteString(s[last:])
	}
	buf.WriteByte('"')
}

func writeUnescapedJSONInto(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeUnescapedJSONString(buf, x)
	case json.Number:
		if x == "" {
			buf.WriteByte('0')
		} else {
			buf.WriteString(string(x))
		}
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case float64:
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case OrderedObject:
		buf.WriteByte('{')
		for i, entry := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeUnescapedJSONString(buf, entry.Key)
			buf.WriteByte(':')
			if err := writeUnescapedJSONInto(buf, entry.Value); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeUnescapedJSONInto(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		buf.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeUnescapedJSONString(buf, s)
		}
		buf.WriteByte(']')
	default:
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		if b := buf.Bytes(); len(b) > 0 && b[len(b)-1] == '\n' {
			buf.Truncate(len(b) - 1)
		}
	}
	return nil
}

// MarshalUnescapedJSON marshals v to compact JSON without escaping <, >, or &.
func MarshalUnescapedJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeUnescapedJSONInto(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseOrderedJSON parses arbitrary JSON into OrderedObject, []any, string, json.Number, bool, or nil,
// enforcing maxDepth and converting bridged JS sentinels into SpecialSentinel values.
func ParseOrderedJSON(data []byte, maxDepth int) (any, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("empty JSON input")
	}
	if maxDepth <= 0 {
		maxDepth = 32
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	val, err := decodeOrderedValue(dec, 0, maxDepth)
	if err != nil {
		return nil, err
	}
	if tok, extraErr := dec.Token(); extraErr != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON token %v", tok)
	}
	return val, nil
}

func decodeOrderedValue(dec *json.Decoder, depth, maxDepth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeOrderedFromToken(dec, tok, depth, maxDepth)
}

func decodeOrderedFromToken(dec *json.Decoder, tok json.Token, depth, maxDepth int) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			if depth+1 > maxDepth {
				return nil, errors.New("JSON nesting depth exceeded limit")
			}
			obj := make(OrderedObject, 0, 4)
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				keyStr, ok := kt.(string)
				if !ok {
					return nil, errors.New("expected string object key")
				}
				val, err := decodeOrderedValue(dec, depth+1, maxDepth)
				if err != nil {
					return nil, err
				}
				obj = append(obj, OrderedEntry{Key: keyStr, Value: val})
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim('}') {
				return nil, errors.New("unclosed JSON object")
			}
			if len(obj) == 1 {
				switch obj[0].Key {
				case sentinelNonJSONKey:
					return SpecialSentinel{Kind: "non_json"}, nil
				case sentinelCycleKey:
					return SpecialSentinel{Kind: "cycle"}, nil
				case sentinelBigIntKey:
					s, _ := obj[0].Value.(string)
					return SpecialSentinel{Kind: "bigint", Raw: s}, nil
				}
			}
			return obj, nil
		}
		if t == '[' {
			if depth+1 > maxDepth {
				return nil, errors.New("JSON nesting depth exceeded limit")
			}
			arr := make([]any, 0, 4)
			for dec.More() {
				val, err := decodeOrderedValue(dec, depth+1, maxDepth)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim(']') {
				return nil, errors.New("unclosed JSON array")
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	case string, json.Number, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected JSON token %T", tok)
	}
}

// IsJSONDepthWithinLimit verifies in O(N) time that bracket/brace nesting never exceeds maxDepth.
func IsJSONDepthWithinLimit(rawJSON string, maxDepth int) bool {
	if maxDepth <= 0 {
		maxDepth = 32
	}
	depth := 0
	inStr := false
	escaped := false
	for i := 0; i < len(rawJSON); i++ {
		ch := rawJSON[i]
		if inStr {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '[', '{':
			depth++
			if depth > maxDepth {
				return false
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return true
}

// MeasureOrderedJSONSizeCapped estimates serialized JSON size in UTF-16 code units, aborting as soon as acc > maxBytes.
func MeasureOrderedJSONSizeCapped(rawValue any, maxBytes int) int {
	acc := 0
	var visit func(node any)
	visit = func(node any) {
		if acc > maxBytes {
			return
		}
		if node == nil {
			acc += 4
			return
		}
		switch v := node.(type) {
		case bool:
			if v {
				acc += 4
			} else {
				acc += 5
			}
		case json.Number:
			acc += len(v)
		case float64:
			acc += len(strconv.FormatFloat(v, 'g', -1, 64))
		case int:
			acc += len(strconv.Itoa(v))
		case int64:
			acc += len(strconv.FormatInt(v, 10))
		case string:
			acc += utf16Len(v) + 2
		case SpecialSentinel:
			if v.Kind == "cycle" {
				acc = maxBytes + 1
			} else if v.Kind == "bigint" {
				acc += len(v.Raw)
			} else {
				acc += 4
			}
		case []any:
			acc += 2
			for i := 0; i < len(v); i++ {
				if i > 0 {
					acc++
				}
				visit(v[i])
				if acc > maxBytes {
					return
				}
			}
		case OrderedObject:
			acc += 2
			for i := 0; i < len(v); i++ {
				if i > 0 {
					acc++
				}
				acc += utf16Len(v[i].Key) + 3
				if acc > maxBytes {
					return
				}
				visit(v[i].Value)
				if acc > maxBytes {
					return
				}
			}
		default:
			acc += 4
		}
	}
	visit(rawValue)
	return acc
}

func utf16Len(s string) int {
	return extract.UTF16Len(s)
}

func sliceUTF16(s string, maxUnits int) (string, bool) {
	if maxUnits <= 0 {
		if s == "" {
			return "", false
		}
		return "", true
	}
	if len(s) <= maxUnits {
		// Each UTF-8 byte is at most 1 UTF-16 code unit, so len(s) <= maxUnits guarantees UTF16Len(s) <= maxUnits!
		return s, false
	}
	if extract.UTF16Len(s) <= maxUnits {
		return s, false
	}
	off := extract.UTF16OffsetToByteOffset(s, maxUnits)
	return s[:off], true
}

func numberToFiniteFloat(n json.Number) (float64, bool) {
	s := strings.TrimSpace(string(n))
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	if f != f || f > 1.7976931348623157e+308 || f < -1.7976931348623157e+308 {
		return 0, false
	}
	return f, true
}
