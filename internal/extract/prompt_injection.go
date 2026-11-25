package extract

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxPromptInjectionScanBytesPIGo = 8 * 1024 * 1024

// PromptInjectionResult reports whether indirect prompt-injection directives were detected.
type PromptInjectionResult struct {
	Detected bool     `json:"detected"`
	Triggers []string `json:"triggers"`
}

type injectionPatternSpecPIGo struct {
	id        string
	re        *regexp.Regexp
	compactRe *regexp.Regexp
	weight    int
	keywords  []string
	requireCh byte
}

var injectionPatternsPIGo = []injectionPatternSpecPIGo{
	{
		id:        "ignore_previous_instructions",
		re:        regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|each|every)(?:\s+of)?\s+)?(?:(?:the|your|these|those|my|our)\s+)?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)\b`),
		compactRe: regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override)(?:(?:all|any|each|every)(?:of)?)?(?:the|your|these|those|my|our)?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)`),
		weight:    3,
		keywords:  []string{"ignore", "disregard", "forget", "override"},
	},
	{
		id:        "new_system_role_override",
		re:        regexp.MustCompile(`(?i)(?:(?:^|\n)[ \t>]{0,20}(?:\[?[ \t]{0,10}system(?:[ \t]{1,10}(?:prompt|override|instruction|message|role))?[ \t]{0,10}\]?|<[ \t]{0,10}system[ \t]{0,10}>|#{1,6}[ \t]{0,10}system(?:[ \t]{1,10}instruction)?)|(?:^|\s)(?:\[[ \t]{0,6}system[ \t]{1,6}(?:prompt|override|instruction|message|role)[ \t]{0,6}\]|<[ \t]{0,6}system[ \t]{0,6}>))[ \t]{0,10}:`),
		compactRe: regexp.MustCompile(`(?i)(?:(?:^|\s)\[?system(?:prompt|override|instruction|message|role)\]?:|(?:^|\n)[ \t>]{0,10}system:|<system>:|#{1,6}system(?:instruction)?:)`),
		weight:    3,
		keywords:  []string{"system"},
		requireCh: ':',
	},
	{
		id:        "exfiltrate_secrets_or_tools",
		re:        regexp.MustCompile(`(?i)\b(?:send|post|upload|exfiltrate|transmit|forward|leak)\s+(?:(?:the|your|all|my|our)\s+)?(?:api[_\s-]?keys?|tokens?|secrets?|passwords?|credentials?|conversation|system\s+prompt|ssh|env)\s+(?:to|via)\s+(?:https?:(?://|\s+[a-z0-9])|\[[^\]]{1,80}\]\(\s*https?://|(?:[a-z0-9-]+\s+){0,3}[a-z0-9-]+(?:\.[a-z0-9-]+)+\b|this\b|here\b)`),
		compactRe: regexp.MustCompile(`(?i)(?:send|post|upload|exfiltrate|transmit|forward|leak)(?:the|your|all|my|our)?(?:api[_-]?keys?|tokens?|secrets?|passwords?|credentials?|conversation|systemprompt|ssh|env)(?:to|via)(?:https?:|[a-z0-9-]+\.[a-z]{2,}|this\b|here\b)`),
		weight:    4,
		keywords:  []string{"send", "post", "upload", "exfiltrate", "transmit", "forward", "leak"},
	},
	{
		id:        "tool_invocation_hijack",
		re:        regexp.MustCompile(`(?i)(?:(?:\b(?:immediately|now)\s+call\s+the\s+tool|\binvoke\s+the\s+tool)\s+[a-z][a-z0-9_.:/-]{1,63}\b|\b(?:immediately\s+call(?:\s+the\s+tool)?|now\s+call(?:\s+the\s+tool)?|you\s+must\s+now\s+execute|invoke\s+the\s+tool|execute\s+bash\s+command)\b[^\n]{0,80}\b(?:curl|wget|fetch(?:[_\s]?url)?|read[_\s]?artifact|scrape|extract|interact|bash|rm\s+-?rf)\b)`),
		compactRe: regexp.MustCompile(`(?i)(?:immediatelycall(?:thetool)?|nowcall(?:thetool)?|youmustnowexecute|invokethetool|executebashcommand)[a-z0-9_:/.-]{0,80}(?:curl|wget|fetch(?:_?url)?|read_?artifact|bash|rm-?rf)`),
		weight:    4,
		keywords:  []string{"call", "invoke", "execute"},
	},
}

var (
	hiddenStyleTokenRePIGo = regexp.MustCompile(`(?i)(?:display[ \t]*:[ \t]*none|visibility[ \t]*:[ \t]*hidden|opacity[ \t]*:[ \t]*0(?:\.0+)?(?:$|[^0-9.])|font-size[ \t]*:[ \t]*0(?:px|em|rem|pt|%)?(?:$|[^0-9.])|clip-path[ \t]*:[ \t]*inset\(\s*100%|clip[ \t]*:[ \t]*rect\(\s*0|(?:left|top|text-indent)[ \t]*:[ \t]*-\d{3,}|height[ \t]*:[ \t]*0(?:px)?[ \t]*;[^;]{0,60}overflow[ \t]*:[ \t]*hidden|color[ \t]*:[ \t]*(?:#fff(?:fff)?|white|transparent)\b.{0,80}font-size[ \t]*:[ \t]*1px|font-size[ \t]*:[ \t]*1px.{0,80}color[ \t]*:[ \t]*(?:#fff(?:fff)?|white|transparent)\b)`)

	hiddenDirectiveOverrideRePIGo = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|each|every|the|your|these|those|my|our|previous|prior|above|earlier|system|developer|safety)\s+){0,4}(?:instructions?|rules?|prompts?|directives?|guidelines?|constraints?|guardrails?|system)\b`,
		`\bsystem\s+(?:prompt|override|instruction|directive|role)\b`,
		`\b(?:assistant|ai|model|agent)\s*:\s*(?:ignore|disregard|forget|override|execute|call|invoke|send|leak|reveal|output|do\s+not)\b`,
		`\b(?:assistant|ai|model|agent)\s+(?:must\s+|should\s+|shall\s+|will\s+)?(?:now\s+|immediately\s+)?(?:execute|invoke|call|run|ignore|disregard|override|leak|exfiltrate)\s+(?:(?:the|a)\s+)?(?:tool|command|bash|shell|function|rules?|instructions?)\b`,
		`\b(?:call|invoke|execute)\s+(?:the\s+)?tool\s+[a-z0-9_-]{2,}\b`,
		`\bdo\s+not\s+(?:tell|inform|mention\s+to|reveal\s+to|show)\s+the\s+user\b`,
	}, "|"))

	compactSpacedOverrideRePIGo = regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override)(?:(?:all|any|each|every)(?:of)?)?(?:the|your|these|those|my|our)?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)`)

	cssClassRuleRePIGo = regexp.MustCompile(`\.([A-Za-z_-][A-Za-z0-9_-]{0,63})\s*\{([^}]{1,240})\}`)
)

var hiddenDirectiveKeywordsPIGo = []string{
	"ignore", "disregard", "forget", "override", "bypass",
	"system", "assistant", "ai", "model", "agent",
	"call", "invoke", "execute", "do",
}

var inlineSplitTagsPIGo = map[string]bool{
	"a": true, "abbr": true, "b": true, "bdi": true, "bdo": true,
	"cite": true, "code": true, "del": true, "dfn": true, "em": true,
	"font": true, "i": true, "ins": true, "kbd": true, "mark": true,
	"q": true, "s": true, "samp": true, "small": true, "span": true,
	"strike": true, "strong": true, "sub": true, "sup": true, "time": true,
	"u": true, "var": true, "wbr": true,
}

var confusableRuneMapPIGo = map[rune]byte{
	0x0456: 'i', 0x0406: 'i', 0x026A: 'i', 0x0457: 'i', 0x0407: 'i',
	0x0430: 'a', 0x0410: 'a',
	0x0435: 'e', 0x0415: 'e', 0x0451: 'e', 0x0401: 'e',
	0x043E: 'o', 0x041E: 'o', 0x03BF: 'o', 0x039F: 'o',
	0x0440: 'p', 0x0420: 'p',
	0x0441: 'c', 0x0421: 'c',
	0x0443: 'y', 0x0423: 'y',
	0x0445: 'x', 0x0425: 'x',
	0x0455: 's', 0x0405: 's',
	0x0458: 'j', 0x0408: 'j',
	0x04CF: 'l', 0x04C0: 'l',
	0x0501: 'd',
	0x0261: 'g',
	0x0578: 'n',
	0x03C5: 'u',
	0x0475: 'v',
}

// latin1ToExtendedBasePIGo maps precomposed Latin-1 & Latin Extended-A/B code points (U+00C0..U+017F)
// to their NFKD base ASCII letters.
var latinBaseTablePIGo = func() [0x0250]string {
	var t [0x0250]string
	setRange := func(lo, hi rune, val string) {
		for r := lo; r <= hi; r++ {
			t[r] = val
		}
	}
	setPairs := func(upper, lower string, pairs ...rune) {
		for i := 0; i+1 < len(pairs); i += 2 {
			t[pairs[i]] = upper
			t[pairs[i+1]] = lower
		}
	}
	// U+00C0..U+00FF
	setRange(0x00C0, 0x00C5, "A")
	t[0x00C6] = "AE"
	t[0x00C7] = "C"
	setRange(0x00C8, 0x00CB, "E")
	setRange(0x00CC, 0x00CF, "I")
	t[0x00D0] = "D"
	t[0x00D1] = "N"
	setRange(0x00D2, 0x00D6, "O")
	t[0x00D8] = "O"
	setRange(0x00D9, 0x00DC, "U")
	t[0x00DD] = "Y"
	t[0x00DF] = "ss"
	setRange(0x00E0, 0x00E5, "a")
	t[0x00E6] = "ae"
	t[0x00E7] = "c"
	setRange(0x00E8, 0x00EB, "e")
	setRange(0x00EC, 0x00EF, "i")
	t[0x00F0] = "d"
	t[0x00F1] = "n"
	setRange(0x00F2, 0x00F6, "o")
	t[0x00F8] = "o"
	setRange(0x00F9, 0x00FC, "u")
	t[0x00FD] = "y"
	t[0x00FF] = "y"

	// U+0100..U+017F (Latin Extended-A)
	setPairs("A", "a", 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105)
	setPairs("C", "c", 0x0106, 0x0107, 0x0108, 0x0109, 0x010A, 0x010B, 0x010C, 0x010D)
	setPairs("D", "d", 0x010E, 0x010F, 0x0110, 0x0111)
	setPairs("E", "e", 0x0112, 0x0113, 0x0114, 0x0115, 0x0116, 0x0117, 0x0118, 0x0119, 0x011A, 0x011B)
	setPairs("G", "g", 0x011C, 0x011D, 0x011E, 0x011F, 0x0120, 0x0121, 0x0122, 0x0123)
	setPairs("H", "h", 0x0124, 0x0125, 0x0126, 0x0127)
	setPairs("I", "i", 0x0128, 0x0129, 0x012A, 0x012B, 0x012C, 0x012D, 0x012E, 0x012F)
	t[0x0130] = "I"
	t[0x0131] = "i"
	t[0x0132] = "IJ"
	t[0x0133] = "ij"
	setPairs("J", "j", 0x0134, 0x0135)
	setPairs("K", "k", 0x0136, 0x0137)
	setPairs("L", "l", 0x0139, 0x013A, 0x013B, 0x013C, 0x013D, 0x013E, 0x013F, 0x0140, 0x0141, 0x0142)
	setPairs("N", "n", 0x0143, 0x0144, 0x0145, 0x0146, 0x0147, 0x0148)
	t[0x0149] = "n"
	setPairs("O", "o", 0x014C, 0x014D, 0x014E, 0x014F, 0x0150, 0x0151)
	t[0x0152] = "OE"
	t[0x0153] = "oe"
	setPairs("R", "r", 0x0154, 0x0155, 0x0156, 0x0157, 0x0158, 0x0159)
	setPairs("S", "s", 0x015A, 0x015B, 0x015C, 0x015D, 0x015E, 0x015F, 0x0160, 0x0161)
	setPairs("T", "t", 0x0162, 0x0163, 0x0164, 0x0165, 0x0166, 0x0167)
	setPairs("U", "u", 0x0168, 0x0169, 0x016A, 0x016B, 0x016C, 0x016D, 0x016E, 0x016F, 0x0170, 0x0171, 0x0172, 0x0173)
	setPairs("W", "w", 0x0174, 0x0175)
	setPairs("Y", "y", 0x0176, 0x0177)
	t[0x0178] = "Y"
	setPairs("Z", "z", 0x0179, 0x017A, 0x017B, 0x017C, 0x017D, 0x017E)
	t[0x017F] = "s" // Latin small letter long s (`ſ`)

	// Common Latin Extended-B precomposed vowels (U+01CD..U+0217)
	setPairs("A", "a", 0x01CD, 0x01CE, 0x01DE, 0x01DF, 0x01E0, 0x01E1, 0x01FA, 0x01FB, 0x0200, 0x0201, 0x0202, 0x0203, 0x0226, 0x0227)
	setPairs("I", "i", 0x01CF, 0x01D0, 0x0208, 0x0209, 0x020A, 0x020B)
	setPairs("O", "o", 0x01D1, 0x01D2, 0x01EA, 0x01EB, 0x01EC, 0x01ED, 0x020C, 0x020D, 0x020E, 0x020F, 0x022A, 0x022B, 0x022C, 0x022D, 0x022E, 0x022F, 0x0230, 0x0231)
	setPairs("U", "u", 0x01D3, 0x01D4, 0x01D5, 0x01D6, 0x01D7, 0x01D8, 0x01D9, 0x01DA, 0x01DB, 0x01DC, 0x0214, 0x0215, 0x0216, 0x0217)
	setPairs("G", "g", 0x01E6, 0x01E7, 0x01F4, 0x01F5)
	setPairs("K", "k", 0x01E8, 0x01E9)
	setPairs("N", "n", 0x01F8, 0x01F9)
	setPairs("E", "e", 0x0204, 0x0205, 0x0206, 0x0207, 0x0228, 0x0229)
	setPairs("R", "r", 0x0210, 0x0211, 0x0212, 0x0213)
	setPairs("S", "s", 0x0218, 0x0219)
	setPairs("T", "t", 0x021A, 0x021B)
	setPairs("H", "h", 0x021E, 0x021F)
	setPairs("Y", "y", 0x0232, 0x0233)
	return t
}()

// latinExtAdditionalTablePIGo maps Latin Extended Additional (U+1E00..U+1EFF) to base ASCII letters.
var latinExtAdditionalTablePIGo = func() [0x0100]string {
	var t [0x0100]string
	setPairs := func(upper, lower string, lo, hi rune) {
		for r := lo; r <= hi; r += 2 {
			t[r-0x1E00] = upper
			if r+1 <= hi {
				t[r+1-0x1E00] = lower
			}
		}
	}
	setPairs("A", "a", 0x1E00, 0x1E01)
	setPairs("B", "b", 0x1E02, 0x1E07)
	setPairs("C", "c", 0x1E08, 0x1E09)
	setPairs("D", "d", 0x1E0A, 0x1E13)
	setPairs("E", "e", 0x1E14, 0x1E1D)
	setPairs("F", "f", 0x1E1E, 0x1E1F)
	setPairs("G", "g", 0x1E20, 0x1E21)
	setPairs("H", "h", 0x1E22, 0x1E2B)
	setPairs("I", "i", 0x1E2C, 0x1E2F)
	setPairs("K", "k", 0x1E30, 0x1E35)
	setPairs("L", "l", 0x1E36, 0x1E3D)
	setPairs("M", "m", 0x1E3E, 0x1E43)
	setPairs("N", "n", 0x1E44, 0x1E4B)
	setPairs("O", "o", 0x1E4C, 0x1E53)
	setPairs("P", "p", 0x1E54, 0x1E57)
	setPairs("R", "r", 0x1E58, 0x1E5F)
	setPairs("S", "s", 0x1E60, 0x1E69)
	setPairs("T", "t", 0x1E6A, 0x1E71)
	setPairs("U", "u", 0x1E72, 0x1E7B)
	setPairs("V", "v", 0x1E7C, 0x1E7F)
	setPairs("W", "w", 0x1E80, 0x1E89)
	setPairs("X", "x", 0x1E8A, 0x1E8D)
	setPairs("Y", "y", 0x1E8E, 0x1E8F)
	setPairs("Z", "z", 0x1E90, 0x1E95)
	t[0x1E96-0x1E00] = "h"
	t[0x1E97-0x1E00] = "t"
	t[0x1E98-0x1E00] = "w"
	t[0x1E99-0x1E00] = "y"
	t[0x1E9A-0x1E00] = "a"
	t[0x1E9B-0x1E00] = "s"
	setPairs("A", "a", 0x1EA0, 0x1EB7)
	setPairs("E", "e", 0x1EB8, 0x1EC7)
	setPairs("I", "i", 0x1EC8, 0x1ECB)
	setPairs("O", "o", 0x1ECC, 0x1EE3)
	setPairs("U", "u", 0x1EE4, 0x1EF1)
	setPairs("Y", "y", 0x1EF2, 0x1EF9)
	return t
}()

func foldMathAlnumRunePIGo(r rune) (byte, bool) {
	// Mathematical Alphanumeric Symbols (U+1D400..U+1D6A3, U+1D7CE..U+1D7FF)
	if r >= 0x1D400 && r <= 0x1D6A3 {
		offset := int(r - 0x1D400)
		idx := offset % 52
		if idx < 26 {
			return byte('A' + idx), true
		}
		return byte('a' + (idx - 26)), true
	}
	if r >= 0x1D7CE && r <= 0x1D7FF {
		return byte('0' + int(r-0x1D7CE)%10), true
	}
	return 0, false
}

func foldNFKDAndConfusableRunePIGo(r rune, sb *strings.Builder) bool {
	if mapped, ok := confusableRuneMapPIGo[r]; ok {
		sb.WriteByte(mapped)
		return true
	}
	if r < 0x0250 {
		if s := latinBaseTablePIGo[r]; s != "" {
			sb.WriteString(s)
			return true
		}
		return false
	}
	if r >= 0x1E00 && r <= 0x1EFF {
		if s := latinExtAdditionalTablePIGo[r-0x1E00]; s != "" {
			sb.WriteString(s)
			return true
		}
	}
	// Fullwidth ASCII variants (U+FF01..U+FF5E -> 0x21..0x7E)
	if r >= 0xFF01 && r <= 0xFF5E {
		sb.WriteByte(byte(r - 0xFEE0))
		return true
	}
	// Mathematical Alphanumeric Symbols
	if b, ok := foldMathAlnumRunePIGo(r); ok {
		sb.WriteByte(b)
		return true
	}
	// Circled / Parenthesized Latin letters
	if r >= 0x24B6 && r <= 0x24CF {
		sb.WriteByte(byte('A' + (r - 0x24B6)))
		return true
	}
	if r >= 0x24D0 && r <= 0x24E9 {
		sb.WriteByte(byte('a' + (r - 0x24D0)))
		return true
	}
	if r >= 0x249C && r <= 0x24B5 {
		sb.WriteString("(" + string(byte('a'+(r-0x249C))) + ")")
		return true
	}
	// Letterlike NFKD ASCII decompositions & ligatures
	switch r {
	case 0x2102:
		sb.WriteByte('C')
		return true
	case 0x210A:
		sb.WriteByte('g')
		return true
	case 0x210B, 0x210C, 0x210D:
		sb.WriteByte('H')
		return true
	case 0x210E, 0x210F:
		sb.WriteByte('h')
		return true
	case 0x2110, 0x2111:
		sb.WriteByte('I')
		return true
	case 0x2112:
		sb.WriteByte('L')
		return true
	case 0x2113:
		sb.WriteByte('l')
		return true
	case 0x2115:
		sb.WriteByte('N')
		return true
	case 0x2119:
		sb.WriteByte('P')
		return true
	case 0x211A:
		sb.WriteByte('Q')
		return true
	case 0x211B, 0x211C, 0x211D:
		sb.WriteByte('R')
		return true
	case 0x2124, 0x2128:
		sb.WriteByte('Z')
		return true
	case 0x212A:
		sb.WriteByte('K')
		return true
	case 0x212B:
		sb.WriteByte('A')
		return true
	case 0x212C:
		sb.WriteByte('B')
		return true
	case 0x212D:
		sb.WriteByte('C')
		return true
	case 0x212F:
		sb.WriteByte('e')
		return true
	case 0x2130:
		sb.WriteByte('E')
		return true
	case 0x2131:
		sb.WriteByte('F')
		return true
	case 0x2133:
		sb.WriteByte('M')
		return true
	case 0x2134:
		sb.WriteByte('o')
		return true
	case 0x2139:
		sb.WriteByte('i')
		return true
	case 0xFB00:
		sb.WriteString("ff")
		return true
	case 0xFB01:
		sb.WriteString("fi")
		return true
	case 0xFB02:
		sb.WriteString("fl")
		return true
	case 0xFB03:
		sb.WriteString("ffi")
		return true
	case 0xFB04:
		sb.WriteString("ffl")
		return true
	case 0xFB05, 0xFB06:
		sb.WriteString("st")
		return true
	}
	// Superscript/subscript Latin letters with NFKD mappings
	switch r {
	case 0x00AA:
		sb.WriteByte('a')
		return true
	case 0x00BA:
		sb.WriteByte('o')
		return true
	case 0x02B0:
		sb.WriteByte('h')
		return true
	case 0x02B2:
		sb.WriteByte('j')
		return true
	case 0x02B3:
		sb.WriteByte('r')
		return true
	case 0x02B7:
		sb.WriteByte('w')
		return true
	case 0x02B8:
		sb.WriteByte('y')
		return true
	case 0x02E1:
		sb.WriteByte('l')
		return true
	case 0x02E2:
		sb.WriteByte('s')
		return true
	case 0x02E3:
		sb.WriteByte('x')
		return true
	case 0x2071:
		sb.WriteByte('i')
		return true
	case 0x207F:
		sb.WriteByte('n')
		return true
	}
	return false
}

func hasNonASCIIPIGo(s string) bool {
	i := 0
	n := len(s)
	for ; i+8 <= n; i += 8 {
		if (s[i]|s[i+1]|s[i+2]|s[i+3]|s[i+4]|s[i+5]|s[i+6]|s[i+7])&0x80 != 0 {
			return true
		}
	}
	for ; i < n; i++ {
		if s[i]&0x80 != 0 {
			return true
		}
	}
	return false
}

func hasUnicodeTagSmugglingPIGo(s string) bool {
	if !strings.Contains(s, "\xF3\xA0") {
		return false
	}
	for i := 0; i < len(s); {
		if s[i] < 0x80 {
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if r >= 0xE0000 && r <= 0xE007F {
			return true
		}
		i += w
	}
	return false
}

func isCombiningOrDiacriticMarkPIGo(r rune) bool {
	if (r >= 0x0300 && r <= 0x036F) ||
		(r >= 0x0483 && r <= 0x0489) ||
		(r >= 0x1AB0 && r <= 0x1AFF) ||
		(r >= 0x1DC0 && r <= 0x1DFF) ||
		(r >= 0x20D0 && r <= 0x20FF) ||
		(r >= 0xFE20 && r <= 0xFE2F) {
		return true
	}
	return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r)
}

func normalizeNonASCIIForInjectionScanPIGo(s string, stripFillers bool) string {
	if !hasNonASCIIPIGo(s) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] < 0x80 {
			sb.WriteByte(s[i])
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		i += w

		// 1. Strip invisible / format / musical / variation / tag characters
		if r == 0x00AD || r == 0x034F || r == 0x061C || r == 0x17B4 || r == 0x17B5 ||
			(r >= 0x180B && r <= 0x180F) ||
			(r >= 0x200B && r <= 0x200F) ||
			(r >= 0x202A && r <= 0x202E) ||
			(r >= 0x2060 && r <= 0x206F) ||
			(r >= 0xFE00 && r <= 0xFE0F) ||
			r == 0xFEFF ||
			(r >= 0xFFF9 && r <= 0xFFFB) ||
			(r >= 0x1D173 && r <= 0x1D17A) ||
			(r >= 0xE0000 && r <= 0xE01EF) {
			continue
		}
		// 2. Fold Unicode spaces & Braille blank to ASCII space
		if r == 0x0085 || r == 0x00A0 || r == 0x1680 ||
			(r >= 0x2000 && r <= 0x200A) ||
			r == 0x2028 || r == 0x2029 || r == 0x202F || r == 0x205F || r == 0x2800 || r == 0x3000 {
			sb.WriteByte(' ')
			continue
		}
		// 3. Hangul fillers
		if r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 {
			if !stripFillers {
				sb.WriteByte(' ')
			}
			continue
		}
		// 4. Combining diacritical marks
		if isCombiningOrDiacriticMarkPIGo(r) {
			continue
		}
		// 5. NFKD compatibility + Cyrillic/Greek/IPA confusable folding
		if foldNFKDAndConfusableRunePIGo(r, &sb) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func decodeEntitiesForInjectionScanPIGo(raw string) string {
	if strings.IndexByte(raw, '&') < 0 {
		return raw
	}
	out := raw
	for pass := 0; pass < 2 && strings.IndexByte(out, '&') >= 0; pass++ {
		next := decodeEntitiesSinglePassPIGo(out)
		if next == out {
			break
		}
		out = next
	}
	return out
}

func decodeEntitiesSinglePassPIGo(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
		if s[i] != '&' || i+2 >= n {
			sb.WriteByte(s[i])
			i++
			continue
		}
		if s[i+1] == '#' {
			p := i + 2
			isHex := false
			if p < n && (s[p] == 'x' || s[p] == 'X') {
				isHex = true
				p++
			}
			dStart := p
			maxDigits := 7
			if isHex {
				maxDigits = 6
			}
			for p < n && p-dStart < maxDigits {
				c := s[p]
				if isHex {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						break
					}
				} else if c < '0' || c > '9' {
					break
				}
				p++
			}
			if p > dStart {
				digits := s[dStart:p]
				if p < n && s[p] == ';' {
					p++
				}
				base := 10
				if isHex {
					base = 16
				}
				if cp, err := strconv.ParseUint(digits, base, 32); err == nil && cp > 0 && cp <= 0x10FFFF {
					sb.WriteRune(rune(cp))
				}
				// Out-of-range or zero numeric entities (`&#0;`, `&#9999999;`, `&#x110000;`) become `""` per TS!
				i = p
				continue
			}
		} else if isASCIIAlphaByteSliceGo(s[i+1]) {
			semiRel := strings.IndexByte(s[i+1:minIntSliceGo(n, i+24)], ';')
			if semiRel > 0 {
				name := asciiLowerSliceGo(s[i+1 : i+1+semiRel])
				handled := true
				switch name {
				case "nbsp", "nonbreakingspace", "ensp", "emsp", "thinsp", "hairsp", "tab", "newline":
					sb.WriteByte(' ')
				case "shy", "zwj", "zwnj", "zerowidthspace", "negativethinspace":
					// stripped
				case "colon":
					sb.WriteByte(':')
				case "quot":
					sb.WriteByte('"')
				case "apos":
					sb.WriteByte('\'')
				case "lt":
					sb.WriteByte('<')
				case "gt":
					sb.WriteByte('>')
				case "amp":
					sb.WriteByte('&')
				default:
					handled = false
				}
				if handled {
					i = i + 1 + semiRel + 1
					continue
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func normalizeCssStyleForHiddenCheckPIGo(rawStyle string) string {
	if rawStyle == "" {
		return ""
	}
	s := decodeEntitiesForInjectionScanPIGo(rawStyle)
	if strings.Contains(s, "/*") {
		var sb strings.Builder
		sb.Grow(len(s))
		pos := 0
		for pos < len(s) {
			rel := strings.Index(s[pos:], "/*")
			if rel < 0 {
				sb.WriteString(s[pos:])
				break
			}
			hit := pos + rel
			sb.WriteString(s[pos:hit])
			endRel := strings.Index(s[hit+2:minIntSliceGo(len(s), hit+2+258)], "*/")
			if endRel >= 0 && endRel <= 256 {
				pos = hit + 2 + endRel + 2
			} else {
				sb.WriteString("/*")
				pos = hit + 2
			}
		}
		s = sb.String()
	}
	if strings.IndexByte(s, '\\') >= 0 {
		var sb strings.Builder
		sb.Grow(len(s))
		for i := 0; i < len(s); {
			if s[i] != '\\' || i+1 >= len(s) {
				sb.WriteByte(s[i])
				i++
				continue
			}
			p := i + 1
			for p < len(s) && p-(i+1) < 6 {
				c := s[p]
				if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
					p++
				} else {
					break
				}
			}
			if p > i+1 {
				hexStr := s[i+1 : p]
				if p < len(s) && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n') {
					p++
				}
				if cp, err := strconv.ParseUint(hexStr, 16, 32); err == nil && cp > 0 && cp <= 0x7F {
					sb.WriteByte(byte(cp))
				}
				i = p
				continue
			}
			if s[i+1] == '\n' || s[i+1] == '\r' {
				sb.WriteByte(s[i])
				i++
				continue
			}
			sb.WriteByte(s[i+1])
			i += 2
		}
		s = sb.String()
	}
	return s
}

func replaceInlineAndBlockHTMLTagsPIGo(rawHTML string, maxChars int) string {
	src := truncateValidUTF8SliceGo(rawHTML, maxChars)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	var out []string
	cursor := 0
	scanHtmlTagsLinearSliceGo(src, maxChars, false, func(tag scannedHtmlTagSliceGo) bool {
		if tag.index > cursor {
			out = append(out, src[cursor:tag.index])
		}
		if inlineSplitTagsPIGo[tag.tagNameLower] {
			if tag.end < len(src) {
				guardSplitTagReassemblySliceGo(&out, src[tag.end:minIntSliceGo(len(src), tag.end+24)], nil)
			}
		} else {
			out = append(out, " ")
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

func stripFenceMarkerLinesLinearPIGo(s string) string {
	if !strings.Contains(s, "```") && !strings.Contains(s, "~~~") {
		return s
	}
	var sb strings.Builder
	lastCopy := 0
	lineStart := 0
	n := len(s)
	for lineStart <= n {
		nlRel := strings.IndexByte(s[lineStart:], '\n')
		rawEnd := n
		if nlRel >= 0 {
			rawEnd = lineStart + nlRel
		}
		lineEnd := rawEnd
		if lineEnd > lineStart && s[lineEnd-1] == '\r' {
			lineEnd--
		}
		p := lineStart
		for p < lineEnd && p-lineStart < 3 && (s[p] == ' ' || s[p] == '\t') {
			p++
		}
		if p+3 <= lineEnd && (s[p] == '`' || s[p] == '~') && s[p+1] == s[p] && s[p+2] == s[p] {
			if lastCopy == 0 && sb.Cap() == 0 {
				sb.Grow(n)
			}
			sb.WriteString(s[lastCopy:lineStart])
			lastCopy = lineEnd
		}
		if nlRel < 0 {
			break
		}
		lineStart = rawEnd + 1
	}
	if lastCopy == 0 {
		return s
	}
	sb.WriteString(s[lastCopy:])
	return sb.String()
}

func unwrapBackslashEscapesLinearPIGo(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
		if s[i] != '\\' || i+1 >= n {
			sb.WriteByte(s[i])
			i++
			continue
		}
		nx := s[i+1]
		if nx == '\n' {
			sb.WriteByte(' ')
			i += 2
			continue
		}
		if nx == '\r' && i+2 < n && s[i+2] == '\n' {
			sb.WriteByte(' ')
			i += 3
			continue
		}
		if nx == '_' {
			sb.WriteByte(' ')
			i += 2
			continue
		}
		if nx == ' ' || isASCIIPunctByte(nx) {
			sb.WriteByte(nx)
			i += 2
			continue
		}
		sb.WriteByte('\\')
		i++
	}
	return sb.String()
}

func stripWordBracketsLinearPIGo(txt string) string {
	firstOpen := strings.IndexByte(txt, '[')
	if firstOpen < 0 || strings.IndexByte(txt[firstOpen+1:], ']') < 0 {
		return txt
	}
	n := len(txt)
	var sb strings.Builder
	last := 0
	i := firstOpen
	for i < n {
		rel := strings.IndexByte(txt[i:], '[')
		if rel < 0 {
			break
		}
		openPos := i + rel
		openEnd := openPos + 1
		for openEnd < n && txt[openEnd] == '[' {
			openEnd++
		}
		openLen := openEnd - openPos
		if openLen <= 4 && openEnd < n {
			wordEnd := openEnd
			for wordEnd < n && wordEnd-openEnd <= 32 && isASCIIAlphaByteSliceGo(txt[wordEnd]) {
				wordEnd++
			}
			wordLen := wordEnd - openEnd
			if wordLen >= 2 && wordLen <= 32 && wordEnd < n && txt[wordEnd] == ']' {
				closeEnd := wordEnd + 1
				for closeEnd < n && txt[closeEnd] == ']' {
					closeEnd++
				}
				if last == 0 && sb.Cap() == 0 {
					sb.Grow(n)
				}
				sb.WriteString(txt[last:openPos])
				sb.WriteString(txt[openEnd:wordEnd])
				last = closeEnd
				i = closeEnd
				continue
			}
		}
		i = openEnd
	}
	if last == 0 {
		return txt
	}
	sb.WriteString(txt[last:])
	return sb.String()
}

func collapseBracketedSingleLettersLinearPIGo(s string) string {
	n := len(s)
	var sb strings.Builder
	last := 0
	i := 0
	for i+8 < n {
		rel := strings.IndexByte(s[i:], '[')
		if rel < 0 {
			break
		}
		pos := i + rel
		p := pos
		count := 0
		for p+2 < n && s[p] == '[' && isASCIIAlphaByteSliceGo(s[p+1]) && s[p+2] == ']' {
			count++
			p += 3
		}
		if count >= 3 {
			if last == 0 && sb.Cap() == 0 {
				sb.Grow(n)
			}
			sb.WriteString(s[last:pos])
			for k := pos + 1; k < p; k += 3 {
				sb.WriteByte(s[k])
			}
			last = p
			i = p
			continue
		}
		i = pos + 1
	}
	if last == 0 {
		return s
	}
	sb.WriteString(s[last:])
	return sb.String()
}

func stripRefLinkDefsLinearPIGo(s string) string {
	var sb strings.Builder
	lastCopy := 0
	lineStart := 0
	n := len(s)
	for lineStart < n {
		nlRel := strings.IndexByte(s[lineStart:], '\n')
		rawEnd := n
		if nlRel >= 0 {
			rawEnd = lineStart + nlRel
		}
		lineEnd := rawEnd
		if lineEnd > lineStart && s[lineEnd-1] == '\r' {
			lineEnd--
		}
		p := lineStart
		for p < lineEnd && p-lineStart < 12 && (s[p] == ' ' || s[p] == '\t' || s[p] == '>') {
			p++
		}
		if p < lineEnd {
			if (s[p] == '-' || s[p] == '*' || s[p] == '+') && p+1 < lineEnd && (s[p+1] == ' ' || s[p+1] == '\t') {
				p += 2
				for p < lineEnd && (s[p] == ' ' || s[p] == '\t') {
					p++
				}
			} else if s[p] >= '0' && s[p] <= '9' {
				d := p
				for d < lineEnd && d-p < 9 && s[d] >= '0' && s[d] <= '9' {
					d++
				}
				if d > p && d+1 < lineEnd && (s[d] == '.' || s[d] == ')') && (s[d+1] == ' ' || s[d+1] == '\t') {
					p = d + 2
					for p < lineEnd && (s[p] == ' ' || s[p] == '\t') {
						p++
					}
				}
			}
		}
		prefixEnd := p
		if p < lineEnd && s[p] == '[' {
			closeRel := strings.IndexByte(s[p+1:minIntSliceGo(lineEnd, p+202)], ']')
			if closeRel >= 1 && closeRel <= 200 {
				closeBr := p + 1 + closeRel
				if closeBr+1 < lineEnd && s[closeBr+1] == ':' {
					u := closeBr + 2
					for u < lineEnd && (s[u] == ' ' || s[u] == '\t') {
						u++
					}
					uCheck := u
					if uCheck < lineEnd && s[uCheck] == '<' {
						uCheck++
					}
					lowU := asciiLowerSliceGo(s[uCheck:minIntSliceGo(lineEnd, uCheck+12)])
					isURLDef := strings.HasPrefix(lowU, "https:") || strings.HasPrefix(lowU, "http:") ||
						strings.HasPrefix(lowU, "ftp:") || strings.HasPrefix(lowU, "mailto:") ||
						strings.HasPrefix(lowU, "javascript:") || strings.HasPrefix(lowU, "vbscript:") ||
						strings.HasPrefix(lowU, "data:") || strings.HasPrefix(lowU, "file:") ||
						strings.HasPrefix(lowU, "blob:") || strings.HasPrefix(lowU, "/") || strings.HasPrefix(lowU, "#")
					if isURLDef {
						uEnd := uCheck
						for uEnd < lineEnd && s[uEnd] != ' ' && s[uEnd] != '\t' && s[uEnd] != '>' {
							uEnd++
						}
						if uEnd < lineEnd && s[uEnd] == '>' {
							uEnd++
						}
						if lastCopy == 0 && sb.Cap() == 0 {
							sb.Grow(n)
						}
						sb.WriteString(s[lastCopy:prefixEnd])
						sb.WriteString(s[p+1 : closeBr])
						sb.WriteByte(' ')
						lastCopy = uEnd
					}
				}
			}
		}
		if nlRel < 0 {
			break
		}
		lineStart = rawEnd + 1
	}
	if lastCopy == 0 {
		return s
	}
	sb.WriteString(s[lastCopy:])
	return sb.String()
}

func stripScrubbedMarkersLinearPIGo(s string, stripDecoy bool) string {
	low := asciiLowerSliceGo(s)
	if !strings.Contains(low, "[scrubbed") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	last := 0
	pos := 0
	n := len(s)
	for pos < n {
		rel := strings.Index(low[pos:], "[scrubbed")
		if rel < 0 {
			break
		}
		hit := pos + rel
		afterKw := hit + len("[scrubbed")
		if stripDecoy {
			if afterKw < n && s[afterKw] == ':' {
				closeRel := strings.IndexByte(s[afterKw+1:minIntSliceGo(n, afterKw+1+121)], ']')
				if closeRel >= 0 && closeRel <= 120 && !strings.ContainsAny(s[afterKw+1:afterKw+1+closeRel], "\r\n") {
					sb.WriteString(s[last:hit])
					sb.WriteByte(' ')
					last = afterKw + 1 + closeRel + 1
					pos = last
					continue
				}
			}
		} else {
			p := afterKw
			if p < n && s[p] == ':' {
				p++
			}
			for p < n && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n') {
				if s[p] == '\r' || s[p] == '\n' {
					break
				}
				p++
			}
			closeRel := strings.IndexByte(s[p:minIntSliceGo(n, p+241)], ']')
			if closeRel >= 0 && closeRel <= 240 && !strings.ContainsAny(s[p:p+closeRel], "\r\n") {
				sb.WriteString(s[last:hit])
				sb.WriteByte(' ')
				sb.WriteString(s[p : p+closeRel])
				sb.WriteByte(' ')
				last = p + closeRel + 1
				pos = last
				continue
			}
		}
		pos = hit + 1
	}
	if last == 0 {
		return s
	}
	sb.WriteString(s[last:])
	return sb.String()
}

func stripFootnotesLinearPIGo(s string) string {
	var sb strings.Builder
	last := 0
	pos := 0
	n := len(s)
	for pos < n {
		rel := strings.Index(s[pos:], "[^")
		if rel < 0 {
			break
		}
		hit := pos + rel
		p := hit + 2
		for p < n && p-(hit+2) <= 64 && s[p] != ']' && !isASCIIWhitespaceByte(s[p]) {
			p++
		}
		if p > hit+2 && p-(hit+2) <= 64 && p < n && s[p] == ']' {
			if last == 0 && sb.Cap() == 0 {
				sb.Grow(n)
			}
			sb.WriteString(s[last:hit])
			sb.WriteByte(' ')
			last = p + 1
			pos = last
			continue
		}
		pos = hit + 2
	}
	if last == 0 {
		return s
	}
	sb.WriteString(s[last:])
	return sb.String()
}

func stripRefLinkUsagesLinearPIGo(s string) string {
	var sb strings.Builder
	last := 0
	pos := 0
	n := len(s)
	for pos < n {
		rel := strings.Index(s[pos:], "][")
		if rel < 0 {
			break
		}
		hit := pos + rel
		p := hit + 2
		closeRel := strings.IndexByte(s[p:minIntSliceGo(n, p+201)], ']')
		if closeRel >= 0 && closeRel <= 200 && !strings.ContainsAny(s[p:p+closeRel], "\r\n") {
			if last == 0 && sb.Cap() == 0 {
				sb.Grow(n)
			}
			sb.WriteString(s[last : hit+1]) // keep first `]`
			last = p + closeRel + 1
			pos = last
			continue
		}
		pos = hit + 2
	}
	if last == 0 {
		return s
	}
	sb.WriteString(s[last:])
	return sb.String()
}

func isAutolinkLabelPIGo(lbl string) bool {
	if lbl == "" {
		return false
	}
	for i := 0; i < len(lbl); i++ {
		if isASCIIWhitespaceByte(lbl[i]) {
			return false
		}
	}
	low := asciiLowerSliceGo(lbl[:minIntSliceGo(len(lbl), 9)])
	return (strings.HasPrefix(low, "https://") && len(lbl) > 8) ||
		(strings.HasPrefix(low, "http://") && len(lbl) > 7) ||
		(strings.HasPrefix(low, "mailto:") && len(lbl) > 7)
}

func hasCaseInsensitiveBracketScrubbedPIGo(s string) bool {
	const pat = "[scrubbed"
	n := len(s)
	pos := 0
	for pos+len(pat) <= n {
		rel := strings.IndexByte(s[pos:], '[')
		if rel < 0 {
			return false
		}
		i := pos + rel
		if i+len(pat) > n {
			return false
		}
		if (s[i+1] | 0x20) != 's' {
			pos = i + 1
			continue
		}
		match := true
		for k := 2; k < len(pat); k++ {
			if (s[i+k] | 0x20) != pat[k] {
				match = false
				break
			}
		}
		if match {
			return true
		}
		pos = i + 1
	}
	return false
}

func unwrapMarkdownLinksForScanLinearPIGo(s string, stripScrubbedDecoy bool) string {
	work := s
	if strings.IndexByte(work, '[') >= 0 && hasCaseInsensitiveBracketScrubbedPIGo(work) {
		work = stripScrubbedMarkersLinearPIGo(work, stripScrubbedDecoy)
	}
	if strings.Contains(work, "][") {
		work = collapseBracketedSingleLettersLinearPIGo(work)
	}
	if strings.Contains(work, "]:") {
		work = stripRefLinkDefsLinearPIGo(work)
	}
	if strings.Contains(work, "[^") {
		work = stripFootnotesLinearPIGo(work)
	}
	if strings.Contains(work, "][") {
		work = stripRefLinkUsagesLinearPIGo(work)
	}

	if !strings.Contains(work, "](") || strings.IndexByte(work, ')') < 0 {
		return stripWordBracketsLinearPIGo(work)
	}

	var out strings.Builder
	last := 0
	searchPos := 0
	nextCloseParen := -2
	nextDblQuote := -2
	nextSglQuote := -2
	n := len(work)

	for searchPos < n {
		bpRel := strings.Index(work[searchPos:], "](")
		if bpRel < 0 {
			break
		}
		bp := searchPos + bpRel
		if nextCloseParen != -1 && nextCloseParen < bp+2 {
			cpRel := strings.IndexByte(work[bp+2:], ')')
			if cpRel < 0 {
				nextCloseParen = -1
			} else {
				nextCloseParen = bp + 2 + cpRel
			}
		}
		if nextCloseParen < 0 {
			break
		}

		k := bp + 2
		for k < n && (work[k] == ' ' || work[k] == '\t') {
			k++
		}
		valid := true
		if k < n && work[k] == '<' {
			k++
			for k < n && work[k] != '>' && work[k] != '\n' && work[k] != '\r' {
				k++
			}
			if k < n && work[k] == '>' {
				k++
			} else {
				valid = false
			}
		} else {
			depth := 0
			for k < n {
				c := work[k]
				if c == '\\' && k+1 < n {
					k += 2
					continue
				}
				if isASCIIWhitespaceByte(c) {
					break
				}
				if c == '(' {
					depth++
					if depth > 6 {
						valid = false
						break
					}
				} else if c == ')' {
					if depth == 0 {
						break
					}
					depth--
				}
				k++
			}
			if depth != 0 {
				valid = false
			}
		}

		if valid && k < n && (work[k] == ' ' || work[k] == '\t') {
			for k < n && (work[k] == ' ' || work[k] == '\t') {
				k++
			}
			if k < n && (work[k] == '"' || work[k] == '\'') {
				q := work[k]
				qEnd := -1
				if q == '"' {
					if nextDblQuote != -1 && nextDblQuote <= k {
						rel := strings.IndexByte(work[k+1:], '"')
						if rel < 0 {
							nextDblQuote = -1
						} else {
							nextDblQuote = k + 1 + rel
						}
					}
					qEnd = nextDblQuote
				} else {
					if nextSglQuote != -1 && nextSglQuote <= k {
						rel := strings.IndexByte(work[k+1:], '\'')
						if rel < 0 {
							nextSglQuote = -1
						} else {
							nextSglQuote = k + 1 + rel
						}
					}
					qEnd = nextSglQuote
				}
				if qEnd > k && qEnd-k <= 512 && strings.IndexByte(work[k+1:qEnd], '\n') < 0 {
					k = qEnd + 1
					for k < n && (work[k] == ' ' || work[k] == '\t') {
						k++
					}
				} else {
					valid = false
				}
			}
		}

		if valid && k < n && work[k] == ')' {
			if last == 0 && out.Cap() == 0 {
				out.Grow(n)
			}
			openBr := -1
			scanBackFloor := maxIntSliceGo(last, bp-400)
			for b := bp - 1; b >= scanBackFloor; b-- {
				bc := work[b]
				if bc == '\n' || bc == '\r' {
					break
				}
				if bc == '[' {
					openBr = b
					break
				}
			}
			if openBr >= last {
				isImg := openBr > last && work[openBr-1] == '!'
				lbl := strings.TrimSpace(work[openBr+1 : bp])
				if isAutolinkLabelPIGo(lbl) {
					dropStart := openBr
					if isImg {
						dropStart = openBr - 1
					}
					out.WriteString(work[last:dropStart])
					out.WriteByte(' ')
					last = k + 1
					searchPos = k + 1
					continue
				}
				if isImg {
					out.WriteString(work[last : openBr-1])
					out.WriteByte(' ')
					out.WriteString(lbl)
					out.WriteByte(' ')
					last = k + 1
					searchPos = k + 1
					continue
				}
			}
			out.WriteString(work[last:bp])
			last = k + 1
			searchPos = k + 1
			continue
		}

		if k > bp+2 {
			searchPos = k
		} else {
			searchPos = bp + 2
		}
	}

	unwrapped := work
	if last > 0 {
		out.WriteString(work[last:])
		unwrapped = out.String()
	}
	return stripWordBracketsLinearPIGo(unwrapped)
}

func finishFillerPassPIGo(base string, stripMode bool) string {
	n := len(base)
	if n == 0 {
		return ""
	}
	needsChange := false
	for i := 0; i < n; i++ {
		c := base[i]
		if c == '`' || c == '*' || c == '_' || c == '~' || (c == ' ' && i+1 < n && base[i+1] == ' ') {
			needsChange = true
			break
		}
	}
	if !needsChange {
		return base
	}
	buf := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		c := base[i]
		if stripMode {
			if c == '`' || c == '*' || c == '_' || c == '~' {
				continue
			}
		} else {
			if c == '*' || c == '~' {
				continue
			}
			if c == '`' || c == '_' {
				c = ' '
			}
		}
		if c == ' ' && len(buf) > 0 && buf[len(buf)-1] == ' ' {
			continue
		}
		buf = append(buf, c)
	}
	return string(buf)
}

func isIntraWordSepBytePIGo(c byte) bool {
	return c == '-' || c == '.' || c == '_' || c == '/' || c == '+'
}

func reconstructObfuscatedWordsLinearPIGo(s string) string {
	n := len(s)
	if n < 3 {
		return s
	}

	stage1 := s
	if strings.ContainsAny(s, "-._/+") {
		var sb strings.Builder
		last := 0
		i := 0
		for i < n {
			c0 := s[i]
			if isASCIIAlphaByteSliceGo(c0) &&
				(i == 0 || !isASCIIAlnumExtract(s[i-1])) &&
				i+2 < n &&
				isIntraWordSepBytePIGo(s[i+1]) {
				sep := s[i+1]
				p := i + 1
				var letters []byte
				count := 1
				for p+1 < n && s[p] == sep {
					nc := s[p+1]
					if nc == '_' && p+3 < n && s[p+2] == sep && isASCIIAlphaByteSliceGo(s[p+3]) {
						if letters == nil {
							letters = make([]byte, 0, 16)
							letters = append(letters, c0)
						}
						letters = append(letters, '_')
						p += 2
						continue
					}
					afterNext := byte(' ')
					if p+2 < n {
						afterNext = s[p+2]
					}
					if isASCIIAlphaByteSliceGo(nc) && (!isASCIIAlnumExtract(afterNext) || afterNext == sep) {
						if letters == nil {
							letters = make([]byte, 0, 16)
							letters = append(letters, c0)
						}
						letters = append(letters, nc)
						count++
						p += 2
					} else {
						break
					}
				}
				endPos := p
				if p < n && sep == '.' && s[p] == '.' && (p+1 >= n || !isASCIIAlnumExtract(s[p+1])) {
					endPos = p + 1
				}
				if count >= 2 && (endPos >= n || !isASCIIAlnumExtract(s[endPos])) {
					if last == 0 && sb.Cap() == 0 {
						sb.Grow(n)
					}
					sb.WriteString(s[last:i])
					sb.Write(letters)
					last = endPos
					i = endPos
					continue
				}
			}
			i++
		}
		if last > 0 {
			sb.WriteString(s[last:])
			stage1 = sb.String()
		}
	}

	m := len(stage1)
	if m < 3 || strings.IndexByte(stage1, ' ') < 0 {
		return stage1
	}
	var sb2 strings.Builder
	last2 := 0
	j := 0
	for j < m {
		c := stage1[j]
		if isASCIIAlphaByteSliceGo(c) &&
			(j == 0 || !isASCIIAlnumExtract(stage1[j-1])) &&
			j+2 < m &&
			stage1[j+1] == ' ' &&
			stage1[j+2] != ' ' {
			p := j + 1
			var word []byte
			count := 1
			for p+1 < m && stage1[p] == ' ' && stage1[p+1] != ' ' {
				nc := stage1[p+1]
				after := byte(' ')
				if p+2 < m {
					after = stage1[p+2]
				}
				if isASCIIAlphaByteSliceGo(nc) && !isASCIIAlnumExtract(after) {
					if word == nil {
						word = make([]byte, 0, 16)
						word = append(word, c)
					}
					word = append(word, nc)
					count++
					p += 2
				} else {
					break
				}
			}
			if count >= 2 {
				if last2 == 0 && sb2.Cap() == 0 {
					sb2.Grow(m)
				}
				sb2.WriteString(stage1[last2:j])
				sb2.Write(word)
				last2 = p
				j = p
				continue
			}
		}
		j++
	}
	if last2 == 0 {
		return stage1
	}
	sb2.WriteString(stage1[last2:])
	return sb2.String()
}

func isWordStreamKeepBytePIGo(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '.' || b == ':'
}

func toWordStreamLinearPIGo(raw string) string {
	s := StripMarkdownTableDividerLinesLinear(raw)
	n := len(s)
	if n == 0 {
		return ""
	}
	alreadyClean := true
	for i := 0; i < n; i++ {
		c := s[i]
		if !isWordStreamKeepBytePIGo(c) && c != ' ' {
			alreadyClean = false
			break
		}
		if c == ' ' && i+1 < n && s[i+1] == ' ' {
			alreadyClean = false
			break
		}
	}
	if alreadyClean {
		return s
	}
	initCap := n
	if initCap > 65536 {
		initCap = 65536
	}
	buf := make([]byte, 0, initCap)
	inSpace := false
	for i := 0; i < n; i++ {
		c := s[i]
		if isWordStreamKeepBytePIGo(c) {
			buf = append(buf, c)
			inSpace = false
		} else if !inSpace {
			buf = append(buf, ' ')
			inSpace = true
		}
	}
	return string(buf)
}

func collapseSpacedSingleLettersLinearPIGo(s string) string {
	n := len(s)
	if n < 7 || strings.IndexByte(s, ' ') < 0 {
		return s
	}
	var out []byte
	last := 0
	i := 0
	for i < n {
		c := s[i]
		if isASCIIAlphaByteSliceGo(c) &&
			(i == 0 || !isASCIIAlnumExtract(s[i-1])) &&
			i+2 < n &&
			s[i+1] == ' ' {
			p := i + 1
			count := 1
			for p < n && s[p] == ' ' {
				wsEnd := p + 1
				for wsEnd < n && s[wsEnd] == ' ' {
					wsEnd++
				}
				if wsEnd >= n {
					break
				}
				nc := s[wsEnd]
				nextAfter := byte(' ')
				if wsEnd+1 < n {
					nextAfter = s[wsEnd+1]
				}
				if isASCIIAlphaByteSliceGo(nc) && !isASCIIAlnumExtract(nextAfter) {
					count++
					p = wsEnd + 1
				} else {
					break
				}
			}
			if count >= 4 {
				if out == nil {
					out = make([]byte, 0, n)
				}
				out = append(out, s[last:i]...)
				for k := i; k < p; k++ {
					if s[k] != ' ' {
						out = append(out, s[k])
					}
				}
				last = p
				i = p
				continue
			}
		}
		i++
	}
	if out == nil {
		return s
	}
	out = append(out, s[last:]...)
	return string(out)
}

func normalizeProseBaseForInjectionScanPIGo(prose string, stripFillers bool) string {
	out := decodeEntitiesForInjectionScanPIGo(prose)
	if strings.Contains(out, "<!--") {
		out = stripHtmlCommentsWithGuardSliceGo(out, maxPromptInjectionScanBytesPIGo)
	}
	if strings.IndexByte(out, '<') >= 0 {
		out = stripHtmlTagsLinearSliceGo(out, []string{"script", "style", "noscript", "template"}, " ", maxPromptInjectionScanBytesPIGo)
		out = replaceInlineAndBlockHTMLTagsPIGo(out, maxPromptInjectionScanBytesPIGo)
	}
	out = normalizeNonASCIIForInjectionScanPIGo(out, stripFillers)
	out = stripFenceMarkerLinesLinearPIGo(out)
	out = unwrapBackslashEscapesLinearPIGo(out)
	if strings.IndexByte(out, '[') >= 0 && strings.IndexByte(out, ']') >= 0 {
		out = unwrapMarkdownLinksForScanLinearPIGo(out, stripFillers)
	}
	return out
}

func normalizeProseForInjectionScanPIGo(prose string) string {
	out := normalizeProseBaseForInjectionScanPIGo(prose, false)
	reconstructed := reconstructObfuscatedWordsLinearPIGo(out)
	return finishFillerPassPIGo(reconstructed, false)
}

func hasHangulFillersPIGo(s string) bool {
	if !hasNonASCIIPIGo(s) {
		return false
	}
	for _, r := range s {
		if r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 {
			return true
		}
	}
	return false
}

func normalizeProsePairForInjectionScanPIGo(prose string) (spaced, stripped, reconstructed string) {
	baseSpaced := normalizeProseBaseForInjectionScanPIGo(prose, false)
	spaced = finishFillerPassPIGo(baseSpaced, false)
	rawReconstructed := reconstructObfuscatedWordsLinearPIGo(baseSpaced)
	if rawReconstructed == baseSpaced {
		reconstructed = spaced
	} else {
		reconstructed = finishFillerPassPIGo(rawReconstructed, false)
	}
	needsDistinctStripBase := hasHangulFillersPIGo(prose) ||
		(strings.IndexByte(prose, '[') >= 0 && strings.IndexByte(prose, ']') >= 0 && hasCaseInsensitiveBracketScrubbedPIGo(prose))
	baseStripped := baseSpaced
	if needsDistinctStripBase {
		baseStripped = normalizeProseBaseForInjectionScanPIGo(prose, true)
	}
	if baseStripped == baseSpaced && !strings.ContainsAny(baseSpaced, "`*_~") {
		stripped = spaced
	} else {
		stripped = finishFillerPassPIGo(baseStripped, true)
	}
	return spaced, stripped, reconstructed
}

type variantWithLowerPIGo struct {
	raw   string
	lower string
}

func makeVariantPIGo(s string) variantWithLowerPIGo {
	return variantWithLowerPIGo{
		raw:   s,
		lower: asciiLowerSliceGo(s),
	}
}

func matchRegexBoundedByKeywordsPIGo(re *regexp.Regexp, v variantWithLowerPIGo, keywords []string, requireCh byte, postMargin int) bool {
	if v.raw == "" {
		return false
	}
	if requireCh != 0 && strings.IndexByte(v.raw, requireCh) < 0 {
		return false
	}
	firstHit := -1
	lastHit := -1
	for _, kw := range keywords {
		idx := strings.Index(v.lower, kw)
		if idx < 0 {
			continue
		}
		if firstHit < 0 || idx < firstHit {
			firstHit = idx
		}
		endIdx := strings.LastIndex(v.lower, kw) + len(kw)
		if endIdx > lastHit {
			lastHit = endIdx
		}
	}
	if firstHit < 0 {
		return false
	}
	// Snap start back before firstHit - 128 to preserve ^ / \n / \b boundaries cleanly.
	winStart := 0
	if firstHit > 128 {
		winStart = firstHit - 128
		if nl := strings.LastIndexByte(v.raw[:winStart], '\n'); nl >= 0 {
			winStart = nl
		} else {
			for winStart > 0 && v.raw[winStart] != ' ' && v.raw[winStart] != '\t' {
				winStart--
			}
		}
	}
	winEnd := minIntSliceGo(len(v.raw), lastHit+postMargin)
	for winEnd < len(v.raw) && v.raw[winEnd] != ' ' && v.raw[winEnd] != '\n' && v.raw[winEnd] != '\r' {
		winEnd++
	}
	return re.MatchString(v.raw[winStart:winEnd])
}

func testInjectionPatternAgainstVariantsPIGo(
	pat *injectionPatternSpecPIGo,
	spaced, stripped, reconstructed, wordStream, reconWordStream, collapsed variantWithLowerPIGo,
	rawMd *variantWithLowerPIGo,
) bool {
	if matchRegexBoundedByKeywordsPIGo(pat.re, spaced, pat.keywords, pat.requireCh, 512) {
		return true
	}
	if reconstructed.raw != spaced.raw && matchRegexBoundedByKeywordsPIGo(pat.re, reconstructed, pat.keywords, pat.requireCh, 512) {
		return true
	}
	if wordStream.raw != spaced.raw && matchRegexBoundedByKeywordsPIGo(pat.re, wordStream, pat.keywords, pat.requireCh, 512) {
		return true
	}
	if reconWordStream.raw != wordStream.raw && matchRegexBoundedByKeywordsPIGo(pat.re, reconWordStream, pat.keywords, pat.requireCh, 512) {
		return true
	}
	if stripped.raw != spaced.raw && matchRegexBoundedByKeywordsPIGo(pat.re, stripped, pat.keywords, pat.requireCh, 512) {
		return true
	}
	if collapsed.raw != wordStream.raw {
		if matchRegexBoundedByKeywordsPIGo(pat.re, collapsed, pat.keywords, pat.requireCh, 512) ||
			matchRegexBoundedByKeywordsPIGo(pat.compactRe, collapsed, pat.keywords, pat.requireCh, 512) {
			return true
		}
	}
	if rawMd != nil && rawMd.raw != spaced.raw && (pat.id == "exfiltrate_secrets_or_tools" || pat.id == "new_system_role_override") {
		if matchRegexBoundedByKeywordsPIGo(pat.re, *rawMd, pat.keywords, pat.requireCh, 4096) {
			return true
		}
	}
	return false
}

func stripSimpleQuoteFreeTagsToSpacePIGo(src string) string {
	n := len(src)
	pos := 0
	for pos < n && src[pos] != '<' {
		pos++
	}
	if pos >= n {
		return src
	}
	buf := make([]byte, 0, minIntSliceGo(n, 262144))
	cursor := 0
	for pos < n {
		if pos+2 > n {
			break
		}
		p := pos + 1
		first := src[p]
		validStart := false
		if first == '/' {
			p++
			if p < n && isASCIIAlphaByteSliceGo(src[p]) {
				validStart = true
				p++
			}
		} else if isASCIIAlphaByteSliceGo(first) {
			validStart = true
			p++
		}
		if !validStart {
			pos++
			for pos < n && src[pos] != '<' {
				pos++
			}
			continue
		}
		for p < n && !isTagNameBoundaryByteSliceGo(src[p]) {
			p++
		}
		if p >= n {
			break
		}
		for p < n && src[p] != '>' {
			p++
		}
		if p >= n {
			break
		}
		end := p + 1
		if pos > cursor {
			buf = append(buf, src[cursor:pos]...)
		}
		buf = append(buf, ' ')
		cursor = end
		pos = cursor
		for pos < n && src[pos] != '<' {
			pos++
		}
	}
	if cursor == 0 {
		return src
	}
	if cursor < n {
		buf = append(buf, src[cursor:]...)
	}
	return string(buf)
}

func matchesHiddenSubtreeInjectionPIGo(rawFragment string) bool {
	spacedStr, strippedStr, reconStr := normalizeProsePairForInjectionScanPIGo(rawFragment)
	wsStr := toWordStreamLinearPIGo(spacedStr)
	reconWsStr := wsStr
	if reconStr != spacedStr {
		reconWsStr = toWordStreamLinearPIGo(reconStr)
	}
	collapsedStr := collapseSpacedSingleLettersLinearPIGo(wsStr)

	spaced := makeVariantPIGo(spacedStr)
	stripped := makeVariantPIGo(strippedStr)
	recon := makeVariantPIGo(reconStr)
	ws := makeVariantPIGo(wsStr)
	reconWs := ws
	if reconWsStr != wsStr {
		reconWs = makeVariantPIGo(reconWsStr)
	}
	collapsed := ws
	if collapsedStr != wsStr {
		collapsed = makeVariantPIGo(collapsedStr)
	}

	if matchRegexBoundedByKeywordsPIGo(hiddenDirectiveOverrideRePIGo, ws, hiddenDirectiveKeywordsPIGo, 0, 512) {
		return true
	}
	if reconWs.raw != ws.raw && matchRegexBoundedByKeywordsPIGo(hiddenDirectiveOverrideRePIGo, reconWs, hiddenDirectiveKeywordsPIGo, 0, 512) {
		return true
	}
	if collapsed.raw != ws.raw && matchRegexBoundedByKeywordsPIGo(compactSpacedOverrideRePIGo, collapsed, injectionPatternsPIGo[0].keywords, 0, 512) {
		return true
	}
	for i := range injectionPatternsPIGo {
		if testInjectionPatternAgainstVariantsPIGo(&injectionPatternsPIGo[i], spaced, stripped, recon, ws, reconWs, collapsed, nil) {
			return true
		}
	}
	return false
}

type candidateOpenTagPIGo struct {
	nameStart      int32
	nameEnd        int32
	attrStart      int32
	attrEnd        int32
	end            int32
	immediateClose int32
	isSelfClosing  bool
}

func appendUniqueTriggerPIGo(triggers *[]string, id string) {
	for _, existing := range *triggers {
		if existing == id {
			return
		}
	}
	*triggers = append(*triggers, id)
}

func hasTriggerPIGo(triggers []string, id string) bool {
	for _, existing := range triggers {
		if existing == id {
			return true
		}
	}
	return false
}

// DetectPromptInjection scans extracted Markdown (including code spans and fenced/indented code blocks)
// and raw HTML for indirect prompt-injection payloads (`totalScore >= 3`) in linear O(N) time.
func DetectPromptInjection(markdown, rawHTML string) PromptInjectionResult {
	boundedHTML := truncateValidUTF8SliceGo(rawHTML, maxPromptInjectionScanBytesPIGo)
	boundedMD := truncateValidUTF8SliceGo(markdown, maxPromptInjectionScanBytesPIGo)
	triggers := make([]string, 0)
	totalScore := 0

	// 1. Invisible Unicode Tag ASCII smuggling (`U+E0000`..`U+E007F`) in raw HTML or Markdown.
	if hasUnicodeTagSmugglingPIGo(boundedHTML) || hasUnicodeTagSmugglingPIGo(boundedMD) {
		appendUniqueTriggerPIGo(&triggers, "unicode_tag_ascii_smuggling")
		totalScore += 4
	}

	// 2. Hidden CSS / DOM subtree / `<template>` / `<noscript>` / `alt` / `title` attributes with override directives.
	if boundedHTML != "" {
		rawForHidden := boundedHTML
		lowerForHidden := asciiLowerSliceGo(rawForHidden)

		styleHiddenClasses := map[string]bool{
			"sr-only":            true,
			"visually-hidden":    true,
			"screen-reader-text": true,
			"hidden":             true,
			"d-none":             true,
		}
		if strings.Contains(lowerForHidden, "<style") {
			replaceHtmlTagBlocksLinearSliceGo(rawForHidden, "style", maxPromptInjectionScanBytesPIGo, nil, func(_, _, cssInner string) string {
				cappedCss := truncateValidUTF8SliceGo(cssInner, 65536)
				normCss := normalizeCssStyleForHiddenCheckPIGo(cappedCss)
				for _, m := range cssClassRuleRePIGo.FindAllStringSubmatch(normCss, -1) {
					if hiddenStyleTokenRePIGo.MatchString(m[2]) {
						styleHiddenClasses[asciiLowerSliceGo(m[1])] = true
					}
				}
				return ""
			})
		}

		for _, inertTag := range []string{"template", "noscript"} {
			if hasTriggerPIGo(triggers, "hidden_css_instruction_injection") {
				break
			}
			if strings.Contains(lowerForHidden, "<"+inertTag) {
				foundInert := false
				replaceHtmlTagBlocksLinearSliceGo(rawForHidden, inertTag, maxPromptInjectionScanBytesPIGo, nil, func(_, _, inner string) string {
					if !foundInert && matchesHiddenSubtreeInjectionPIGo(truncateValidUTF8SliceGo(inner, 8192)) {
						foundInert = true
					}
					return ""
				})
				if foundInert {
					appendUniqueTriggerPIGo(&triggers, "hidden_css_instruction_injection")
					totalScore += 5
				}
			}
		}

		if !hasTriggerPIGo(triggers, "hidden_css_instruction_injection") {
			// Zero-allocation char-code tag scanner (`< 15ms` on 2 MiB of `<x-0 hidden>a</x-0>...`).
			var closeFirstByTag map[string]int
			var closeMoreByTag map[string][]int
			var closeCursorByTag map[string]int
			htmlLen := len(rawForHidden)
			candidateOpenTags := make([]candidateOpenTagPIGo, 0, minIntSliceGo(131072, htmlLen/24+8))

			scanPos := 0
			noCloseDbl := false
			noCloseSgl := false

			for scanPos < htmlLen {
				for scanPos < htmlLen && rawForHidden[scanPos] != '<' {
					scanPos++
				}
				if scanPos+1 >= htmlLen {
					break
				}
				lt := scanPos
				p := lt + 1
				c1 := lowerForHidden[p]
				isClosing := false
				if c1 == '/' {
					isClosing = true
					p++
				} else if c1 == '!' || c1 == '?' {
					if p+1 >= htmlLen {
						break
					}
					declEndRel := strings.IndexByte(rawForHidden[p+1:], '>')
					if declEndRel < 0 {
						break
					}
					scanPos = p + 1 + declEndRel + 1
					continue
				}
				if p >= htmlLen {
					break
				}
				n0 := lowerForHidden[p]
				if n0 < 'a' || n0 > 'z' {
					scanPos = lt + 1
					continue
				}
				nameStart := p
				p++
				for p < htmlLen {
					nc := lowerForHidden[p]
					if (nc >= 'a' && nc <= 'z') || (nc >= '0' && nc <= '9') || nc == '-' || nc == ':' {
						p++
					} else {
						break
					}
				}
				if p < htmlLen {
					boundary := rawForHidden[p]
					if boundary != '>' && boundary != '/' && boundary != ' ' && boundary != '\t' && boundary != '\n' && boundary != '\r' && boundary != '\f' {
						scanPos = lt + 1
						continue
					}
				}
				if isClosing {
					gt := p
					for gt < htmlLen && rawForHidden[gt] != '>' {
						gt++
					}
					if gt >= htmlLen {
						break
					}
					tagNameLower := lowerForHidden[nameStart:p]
					if closeFirstByTag == nil {
						closeFirstByTag = make(map[string]int)
					}
					if _, exists := closeFirstByTag[tagNameLower]; !exists {
						closeFirstByTag[tagNameLower] = lt
					} else {
						if closeMoreByTag == nil {
							closeMoreByTag = make(map[string][]int)
						}
						closeMoreByTag[tagNameLower] = append(closeMoreByTag[tagNameLower], lt)
					}
					scanPos = gt + 1
					continue
				}

				// Open tag with zero attributes: skip without slicing.
				if p < htmlLen && rawForHidden[p] == '>' {
					scanPos = p + 1
					continue
				}

				j := p
				quote := byte(0)
				for j < htmlLen {
					ch := rawForHidden[j]
					if quote != 0 {
						if ch == quote {
							quote = 0
						}
					} else if ch == '"' && !noCloseDbl {
						quote = '"'
					} else if ch == '\'' && !noCloseSgl {
						quote = '\''
					} else if ch == '>' {
						break
					}
					j++
				}
				if j >= htmlLen {
					if quote == '"' {
						noCloseDbl = true
						continue
					}
					if quote == '\'' {
						noCloseSgl = true
						continue
					}
					break
				}
				selfClosing := j > p && rawForHidden[j-1] == '/'
				attrEnd := j
				if selfClosing {
					attrEnd = j - 1
				}
				if attrEnd > p {
					nameLen := p - nameStart
					immediateClose := -1
					if !selfClosing && j+1 < htmlLen {
						lim := minIntSliceGo(htmlLen, j+1+257)
						nextLt := j + 1
						for nextLt < lim && rawForHidden[nextLt] != '<' {
							nextLt++
						}
						if nextLt < lim {
							if nextLt+2+nameLen < htmlLen &&
								rawForHidden[nextLt+1] == '/' &&
								rawForHidden[nextLt+2+nameLen] == '>' &&
								lowerForHidden[nameStart:p] == lowerForHidden[nextLt+2:nextLt+2+nameLen] {
								immediateClose = nextLt
							}
						}
					}
					candidateOpenTags = append(candidateOpenTags, candidateOpenTagPIGo{
						nameStart:      int32(nameStart),
						nameEnd:        int32(p),
						attrStart:      int32(p),
						attrEnd:        int32(attrEnd),
						end:            int32(j + 1),
						immediateClose: int32(immediateClose),
						isSelfClosing:  selfClosing,
					})
					if immediateClose >= 0 {
						scanPos = immediateClose + 3 + nameLen
						continue
					}
				}
				scanPos = j + 1
			}

			var attrCandidates []string
			hiddenIntervals := make([][2]int32, 0, minIntSliceGo(131072, len(candidateOpenTags)))

			for ti := 0; ti < len(candidateOpenTags); ti++ {
				tag := candidateOpenTags[ti]
				isHiddenSubtree := false

				aStart := int(tag.attrStart)
				aEnd := int(tag.attrEnd)
				for aStart < aEnd && isASCIIWhitespaceByte(lowerForHidden[aStart]) {
					aStart++
				}
				for aEnd > aStart && isASCIIWhitespaceByte(lowerForHidden[aEnd-1]) {
					aEnd--
				}
				aLen := aEnd - aStart
				if (aLen == 6 || aLen == 9) &&
					lowerForHidden[aStart] == 'h' &&
					lowerForHidden[aStart:aStart+6] == "hidden" &&
					(aLen == 6 || lowerForHidden[aStart+6:aEnd] == `=""` || lowerForHidden[aStart+6:aEnd] == `=''`) {
					isHiddenSubtree = !tag.isSelfClosing
				} else {
					lowerAttrs := lowerForHidden[aStart:aEnd]
					if !strings.Contains(lowerAttrs, "hidden") &&
						!strings.Contains(lowerAttrs, "style") &&
						!strings.Contains(lowerAttrs, "class") &&
						!strings.Contains(lowerAttrs, "alt") &&
						!strings.Contains(lowerAttrs, "title") {
						continue
					}
					attrs := parseOpenTagAttributesSliceGo(rawForHidden[aStart:aEnd])
					if attrs["alt"] != "" || attrs["title"] != "" {
						attrCandidate := strings.TrimSpace(attrs["alt"] + " " + attrs["title"])
						if attrCandidate != "" {
							attrCandidates = append(attrCandidates, attrCandidate)
						}
					}
					if !tag.isSelfClosing {
						normStyle := ""
						if attrs["style"] != "" {
							normStyle = normalizeCssStyleForHiddenCheckPIGo(attrs["style"])
						}
						_, hasHiddenKey := attrs["hidden"]
						isHiddenAttr := hasHiddenKey || asciiLowerSliceGo(strings.TrimSpace(attrs["aria-hidden"])) == "true"
						hasHiddenClass := false
						if cls := attrs["class"]; cls != "" {
							for _, tok := range strings.Fields(asciiLowerSliceGo(cls)) {
								if styleHiddenClasses[tok] {
									hasHiddenClass = true
									break
								}
							}
						}
						isHiddenSubtree = isHiddenAttr || hasHiddenClass || (normStyle != "" && hiddenStyleTokenRePIGo.MatchString(normStyle))
					}
				}

				if !isHiddenSubtree {
					continue
				}

				closeIdx := int(tag.immediateClose)
				tagEnd := int(tag.end)
				if closeIdx < 0 && len(closeFirstByTag) > 0 {
					tagNameLower := lowerForHidden[tag.nameStart:tag.nameEnd]
					if firstClose, ok := closeFirstByTag[tagNameLower]; ok {
						if firstClose >= tagEnd {
							closeIdx = firstClose
						} else if moreList := closeMoreByTag[tagNameLower]; len(moreList) > 0 {
							if closeCursorByTag == nil {
								closeCursorByTag = make(map[string]int)
							}
							cur := closeCursorByTag[tagNameLower]
							for cur < len(moreList) && moreList[cur] < tagEnd {
								cur++
							}
							closeCursorByTag[tagNameLower] = cur
							if cur < len(moreList) {
								closeIdx = moreList[cur]
							}
						}
					}
				}

				maxSearchEnd := minIntSliceGo(htmlLen, tagEnd+16384)
				sliceEnd := minIntSliceGo(htmlLen, tagEnd+8192)
				if closeIdx >= 0 && closeIdx <= maxSearchEnd {
					sliceEnd = closeIdx
				}
				if sliceEnd <= tagEnd {
					continue
				}

				if nInt := len(hiddenIntervals); nInt > 0 && int32(tagEnd) <= hiddenIntervals[nInt-1][1] {
					if int32(sliceEnd) > hiddenIntervals[nInt-1][1] {
						hiddenIntervals[nInt-1][1] = int32(sliceEnd)
					}
				} else {
					hiddenIntervals = append(hiddenIntervals, [2]int32{int32(tagEnd), int32(sliceEnd)})
				}
			}

			if len(attrCandidates) > 0 {
				joinedAttrs := truncateValidUTF8SliceGo(strings.Join(attrCandidates, "\n.\n"), maxPromptInjectionScanBytesPIGo)
				spacedAttrs := makeVariantPIGo(normalizeProseForInjectionScanPIGo(joinedAttrs))
				wordAttrs := makeVariantPIGo(toWordStreamLinearPIGo(spacedAttrs.raw))
				collapsedAttrs := wordAttrs
				if colStr := collapseSpacedSingleLettersLinearPIGo(wordAttrs.raw); colStr != wordAttrs.raw {
					collapsedAttrs = makeVariantPIGo(colStr)
				}
				for i := range injectionPatternsPIGo {
					pat := &injectionPatternsPIGo[i]
					if matchRegexBoundedByKeywordsPIGo(pat.re, spacedAttrs, pat.keywords, pat.requireCh, 512) ||
						matchRegexBoundedByKeywordsPIGo(pat.re, wordAttrs, pat.keywords, pat.requireCh, 512) ||
						matchRegexBoundedByKeywordsPIGo(pat.compactRe, collapsedAttrs, pat.keywords, pat.requireCh, 512) {
						appendUniqueTriggerPIGo(&triggers, "hidden_css_instruction_injection")
						totalScore += 5
						break
					}
				}
			}

			if !hasTriggerPIGo(triggers, "hidden_css_instruction_injection") && len(hiddenIntervals) > 0 {
				totalHiddenBytes := 0
				for _, iv := range hiddenIntervals {
					if iv[1] > iv[0] {
						totalHiddenBytes += int(iv[1]-iv[0]) + 3
						if totalHiddenBytes >= maxPromptInjectionScanBytesPIGo {
							totalHiddenBytes = maxPromptInjectionScanBytesPIGo
							break
						}
					}
				}
				if totalHiddenBytes > 0 {
					var boundedJoinedHidden string
					wroteFirst := false
					if len(hiddenIntervals) == 1 {
						iv := hiddenIntervals[0]
						if iv[1] > iv[0] {
							boundedJoinedHidden = truncateValidUTF8SliceGo(rawForHidden[iv[0]:iv[1]], maxPromptInjectionScanBytesPIGo)
							wroteFirst = boundedJoinedHidden != ""
						}
					} else {
						var hsb strings.Builder
						hsb.Grow(totalHiddenBytes)
						for _, iv := range hiddenIntervals {
							if hsb.Len() >= maxPromptInjectionScanBytesPIGo {
								break
							}
							rawSlice := rawForHidden[iv[0]:iv[1]]
							if rawSlice == "" {
								continue
							}
							if wroteFirst {
								hsb.WriteString("\n.\n")
							}
							hsb.WriteString(rawSlice)
							wroteFirst = true
						}
						if wroteFirst {
							boundedJoinedHidden = truncateValidUTF8SliceGo(hsb.String(), maxPromptInjectionScanBytesPIGo)
						}
					}
					if wroteFirst {
						strippedOnce := boundedJoinedHidden
						if strings.IndexByte(boundedJoinedHidden, '<') >= 0 {
							if strings.IndexByte(boundedJoinedHidden, '"') < 0 &&
								strings.IndexByte(boundedJoinedHidden, '\'') < 0 &&
								!strings.Contains(boundedJoinedHidden, "<!") &&
								!strings.Contains(boundedJoinedHidden, "<?") {
								strippedOnce = stripSimpleQuoteFreeTagsToSpacePIGo(boundedJoinedHidden)
							} else {
								strippedOnce = stripHtmlTagsQuoteAwareLinearSliceGo(boundedJoinedHidden, " ", maxPromptInjectionScanBytesPIGo)
							}
						}
						if matchesHiddenSubtreeInjectionPIGo(strippedOnce) {
							appendUniqueTriggerPIGo(&triggers, "hidden_css_instruction_injection")
							totalScore += 5
						}
					}
				}
			}
		}
	}

	// 3. Full Markdown + code-span / fenced-block scan (`8 MiB` cap, `< 40ms` on `2 MiB`).
	scanSpacedStr, scanStrippedStr, scanReconStr := normalizeProsePairForInjectionScanPIGo(boundedMD)
	scanWsStr := toWordStreamLinearPIGo(scanSpacedStr)
	scanReconWsStr := scanWsStr
	if scanReconStr != scanSpacedStr {
		scanReconWsStr = toWordStreamLinearPIGo(scanReconStr)
	}
	scanCollapsedStr := collapseSpacedSingleLettersLinearPIGo(scanWsStr)

	scanSpaced := makeVariantPIGo(scanSpacedStr)
	scanStripped := scanSpaced
	if scanStrippedStr != scanSpacedStr {
		scanStripped = makeVariantPIGo(scanStrippedStr)
	}
	scanRecon := scanSpaced
	if scanReconStr != scanSpacedStr {
		scanRecon = makeVariantPIGo(scanReconStr)
	}
	scanWs := scanSpaced
	if scanWsStr != scanSpacedStr {
		scanWs = makeVariantPIGo(scanWsStr)
	}
	scanReconWs := scanWs
	if scanReconWsStr != scanWsStr {
		scanReconWs = makeVariantPIGo(scanReconWsStr)
	}
	scanCollapsed := scanWs
	if scanCollapsedStr != scanWsStr {
		scanCollapsed = makeVariantPIGo(scanCollapsedStr)
	}
	rawMdVariant := scanSpaced
	if boundedMD != scanSpacedStr {
		rawMdVariant = makeVariantPIGo(boundedMD)
	}

	for i := range injectionPatternsPIGo {
		pat := &injectionPatternsPIGo[i]
		if testInjectionPatternAgainstVariantsPIGo(
			pat,
			scanSpaced,
			scanStripped,
			scanRecon,
			scanWs,
			scanReconWs,
			scanCollapsed,
			&rawMdVariant,
		) {
			appendUniqueTriggerPIGo(&triggers, pat.id)
			totalScore += pat.weight
		}
	}

	return PromptInjectionResult{
		Detected: totalScore >= 3,
		Triggers: triggers,
	}
}
