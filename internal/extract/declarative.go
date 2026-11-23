package extract

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"math"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

//go:embed manifests/*
var embeddedManifestFS embed.FS

// DeclarativeParamSegment defines a strictly validated URL path segment capture.
type DeclarativeParamSegment struct {
	Param       string   `json:"param"`
	Charset     string   `json:"charset,omitempty"`
	AllowValues []string `json:"allowValues,omitempty"`
	Reserved    []string `json:"reserved,omitempty"`
	StripPrefix string   `json:"stripPrefix,omitempty"`
	StripSuffix string   `json:"stripSuffix,omitempty"`
	MinLen      int      `json:"minLen,omitempty"`
	MaxLen      int      `json:"maxLen,omitempty"`
	Greedy      bool     `json:"greedy,omitempty"`
	Optional    bool     `json:"optional,omitempty"`
	Transform   string   `json:"transform,omitempty"`
}

// DeclarativeSegmentSpec represents either a literal path segment ("gems") or a DeclarativeParamSegment.
type DeclarativeSegmentSpec struct {
	IsLiteral bool
	Literal   string
	ParamSpec DeclarativeParamSegment
}

// UnmarshalJSON decodes a string literal segment or an object parameter segment.
func (s *DeclarativeSegmentSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var lit string
		if err := json.Unmarshal(trimmed, &lit); err != nil {
			return err
		}
		s.IsLiteral = true
		s.Literal = lit
		return nil
	}
	var ps DeclarativeParamSegment
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ps); err != nil {
		return err
	}
	if strings.TrimSpace(ps.Param) == "" {
		return fmt.Errorf("declarative segment object missing param name")
	}
	s.IsLiteral = false
	s.ParamSpec = ps
	return nil
}

// DeclarativeQueryParamSpec defines a query parameter capture and validation rule.
type DeclarativeQueryParamSpec struct {
	Name      string   `json:"name,omitempty"`
	Names     []string `json:"names,omitempty"`
	Param     string   `json:"param"`
	Charset   string   `json:"charset,omitempty"`
	MinLen    int      `json:"minLen,omitempty"`
	MaxLen    int      `json:"maxLen,omitempty"`
	Optional  bool     `json:"optional,omitempty"`
	Default   string   `json:"default,omitempty"`
	Transform string   `json:"transform,omitempty"`
}

// DeclarativeHostSubdomainSpec captures `<sub-label><suffix>` from incoming hostnames.
type DeclarativeHostSubdomainSpec struct {
	Suffix                     string   `json:"suffix"`
	Param                      string   `json:"param"`
	Reserved                   []string `json:"reserved,omitempty"`
	StripOptional2LetterRegion bool     `json:"stripOptional2LetterRegion,omitempty"`
}

// DeclarativeHostMapSpec maps known hostnames or suffix subdomains to an API site parameter.
type DeclarativeHostMapSpec struct {
	Param           string            `json:"param"`
	Exact           map[string]string `json:"exact,omitempty"`
	StripWww        bool              `json:"stripWww,omitempty"`
	SuffixSubdomain string            `json:"suffixSubdomain,omitempty"`
}

// DeclarativeScanSegmentSpec scans path segments for a matching literal-followed or charset-validated segment.
type DeclarativeScanSegmentSpec struct {
	AfterLiteral        string `json:"afterLiteral,omitempty"`
	LastOrBeforeLiteral string `json:"lastOrBeforeLiteral,omitempty"`
	Param               string `json:"param"`
	Charset             string `json:"charset,omitempty"`
	StripPrefix         string `json:"stripPrefix,omitempty"`
	StripSuffix         string `json:"stripSuffix,omitempty"`
	MinLen              int    `json:"minLen,omitempty"`
	MaxLen              int    `json:"maxLen,omitempty"`
	Transform           string `json:"transform,omitempty"`
}

// DeclarativeSplitSegmentSpec splits path segments around a delimiter segment (e.g. GitLab `/-/blob/`).
type DeclarativeSplitSegmentSpec struct {
	Delimiter    string `json:"delimiter"`
	LeftParam    string `json:"leftParam"`
	LeftMinSegs  int    `json:"leftMinSegs,omitempty"`
	AfterLiteral string `json:"afterLiteral,omitempty"`
	RightParam   string `json:"rightParam,omitempty"`
	TailParam    string `json:"tailParam,omitempty"`
}

// DeclarativeDerivedParamSpec computes a derived parameter from an existing captured parameter.
type DeclarativeDerivedParamSpec struct {
	FromParam string `json:"fromParam"`
	Transform string `json:"transform"`
}

// DeclarativeMatchSpec matches incoming HTTPS URLs without regular-expression backtracking.
type DeclarativeMatchSpec struct {
	AnyOf                  []DeclarativeMatchSpec                 `json:"anyOf,omitempty"`
	Hosts                  []string                               `json:"hosts,omitempty"`
	ExcludeHosts           []string                               `json:"excludeHosts,omitempty"`
	SocrataHost            bool                                   `json:"socrataHost,omitempty"`
	HostSubdomain          *DeclarativeHostSubdomainSpec          `json:"hostSubdomain,omitempty"`
	HostMap                *DeclarativeHostMapSpec                `json:"hostMap,omitempty"`
	OptionalLeadingLocale  bool                                   `json:"optionalLeadingLocale,omitempty"`
	ExactSegments          *bool                                  `json:"exactSegments,omitempty"`
	MinSegments            *int                                   `json:"minSegments,omitempty"`
	MaxSegments            *int                                   `json:"maxSegments,omitempty"`
	PathPrefix             string                                 `json:"pathPrefix,omitempty"`
	PathSuffix             string                                 `json:"pathSuffix,omitempty"`
	PathEquals             []string                               `json:"pathEquals,omitempty"`
	PathContainsSegment    string                                 `json:"pathContainsSegment,omitempty"`
	ExcludeSegmentSuffixes []string                               `json:"excludeSegmentSuffixes,omitempty"`
	AllSegmentsCharset     string                                 `json:"allSegmentsCharset,omitempty"`
	ReservedFirstSegment   []string                               `json:"reservedFirstSegment,omitempty"`
	ScanSegment            *DeclarativeScanSegmentSpec            `json:"scanSegment,omitempty"`
	SplitOnSegment         *DeclarativeSplitSegmentSpec           `json:"splitOnSegment,omitempty"`
	ArcgisRestLayer        bool                                   `json:"arcgisRestLayer,omitempty"`
	PathSegments           []DeclarativeSegmentSpec               `json:"pathSegments,omitempty"`
	QueryParams            []DeclarativeQueryParamSpec            `json:"queryParams,omitempty"`
	DerivedParams          map[string]DeclarativeDerivedParamSpec `json:"derivedParams,omitempty"`
	Defaults               map[string]string                      `json:"defaults,omitempty"`
}

// DeclarativePathOverrideSpec rewrites matched paths when `fetchUrl` is `{requestUrl}`.
type DeclarativePathOverrideSpec struct {
	MatchPaths []string `json:"matchPaths"`
	NewPath    string   `json:"newPath"`
}

// DeclarativeTwinSpec describes the 1-hop HTTPS JSON/text endpoint upgrade.
type DeclarativeTwinSpec struct {
	ID                 string                       `json:"id,omitempty"`
	FetchURL           string                       `json:"fetchUrl"`
	RawPathParams      []string                     `json:"rawPathParams,omitempty"`
	OverridePathIf     *DeclarativePathOverrideSpec `json:"overridePathIf,omitempty"`
	SetQueryParams     map[string]string            `json:"setQueryParams,omitempty"`
	DefaultQueryParams map[string]string            `json:"defaultQueryParams,omitempty"`
	Kind               string                       `json:"kind"`
	Accept             string                       `json:"accept"`
}

// DeclarativeDynamicKeyPath looks up root[Base][vars[KeyVar]][SubPath].
type DeclarativeDynamicKeyPath struct {
	Base    string `json:"base"`
	KeyVar  string `json:"keyVar"`
	SubPath string `json:"subPath,omitempty"`
}

// DeclarativeSubFieldsJoin joins subfields from objects inside an array (e.g. Crossref given + family).
type DeclarativeSubFieldsJoin struct {
	Fields        []string `json:"fields"`
	Sep           string   `json:"sep"`
	FallbackField string   `json:"fallbackField,omitempty"`
}

// DeclarativeNestedSubValuesSpec collects unique values across nested sub-arrays (e.g. NIST NVD weaknesses).
type DeclarativeNestedSubValuesSpec struct {
	ArrayPath     string   `json:"arrayPath"`
	SubArrayField string   `json:"subArrayField"`
	ValueField    string   `json:"valueField"`
	ExcludeValues []string `json:"excludeValues,omitempty"`
	Limit         int      `json:"limit,omitempty"`
	Join          string   `json:"join,omitempty"`
}

// DeclarativeFindLangSpec selects a localized string from an array of `{ lang, value }` objects.
type DeclarativeFindLangSpec struct {
	ArrayPath  string `json:"arrayPath"`
	LangField  string `json:"langField"`
	LangValue  string `json:"langValue"`
	ValueField string `json:"valueField"`
}

// DeclarativeReplaceSpec defines a literal substring replacement.
type DeclarativeReplaceSpec struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// DeclarativeVarSpec extracts and formats a named string variable from JSON.
type DeclarativeVarSpec struct {
	Paths               []string                        `json:"paths,omitempty"`
	DynamicKeyPath      *DeclarativeDynamicKeyPath      `json:"dynamicKeyPath,omitempty"`
	NestedSubValues     *DeclarativeNestedSubValuesSpec `json:"nestedSubValues,omitempty"`
	TocHeading          string                          `json:"tocHeading,omitempty"`
	FindInArrayLang     *DeclarativeFindLangSpec        `json:"findInArrayLang,omitempty"`
	Template            string                          `json:"template,omitempty"`
	WhenVars            []string                        `json:"whenVars,omitempty"`
	WhenAnyVars         []string                        `json:"whenAnyVars,omitempty"`
	FallbackVar         string                          `json:"fallbackVar,omitempty"`
	FirstNonMatchingKey string                          `json:"firstNonMatchingKey,omitempty"`
	SubField            string                          `json:"subField,omitempty"`
	SubFieldsJoin       *DeclarativeSubFieldsJoin       `json:"subFieldsJoin,omitempty"`
	ItemWrap            string                          `json:"itemWrap,omitempty"`
	Join                string                          `json:"join,omitempty"`
	Limit               int                             `json:"limit,omitempty"`
	Format              string                          `json:"format,omitempty"`
	TrueValue           string                          `json:"trueValue,omitempty"`
	FalseValue          string                          `json:"falseValue,omitempty"`
	StripFrontmatter    bool                            `json:"stripFrontmatter,omitempty"`
	StripPrefix         string                          `json:"stripPrefix,omitempty"`
	StripSuffix         string                          `json:"stripSuffix,omitempty"`
	ReplaceAll          *DeclarativeReplaceSpec         `json:"replaceAll,omitempty"`
	ExcludeEquals       string                          `json:"excludeEquals,omitempty"`
	EqualsVar           string                          `json:"equalsVar,omitempty"`
	Trim                bool                            `json:"trim,omitempty"`
	Upper               bool                            `json:"upper,omitempty"`
	Lower               bool                            `json:"lower,omitempty"`
	RequireHTTPS        bool                            `json:"requireHttps,omitempty"`
	RequireHTTPPrefix   bool                            `json:"requireHttpPrefix,omitempty"`
	SliceMax            int                             `json:"sliceMax,omitempty"`
	Default             string                          `json:"default,omitempty"`
	FallbackTemplate    string                          `json:"fallbackTemplate,omitempty"`
}

// DeclarativeBulletSpec renders `- **<Label>**: <Template>` (or `**<Label>**: <Template>` in metaLine).
type DeclarativeBulletSpec struct {
	Label     string `json:"label,omitempty"`
	Template  string `json:"template"`
	WhenVar   string `json:"whenVar,omitempty"`
	UnlessVar string `json:"unlessVar,omitempty"`
}

// DeclarativeTableColumn defines a column in a GFM Markdown table section.
type DeclarativeTableColumn struct {
	Header          string   `json:"header"`
	Paths           []string `json:"paths,omitempty"`
	Template        string   `json:"template,omitempty"`
	FallbackVar     string   `json:"fallbackVar,omitempty"`
	Format          string   `json:"format,omitempty"`
	OutcomesField   string   `json:"outcomesField,omitempty"`
	PricesField     string   `json:"pricesField,omitempty"`
	DefaultOutcomes []string `json:"defaultOutcomes,omitempty"`
	StripPrefix     string   `json:"stripPrefix,omitempty"`
	Code            bool     `json:"code,omitempty"`
	SliceMax        int      `json:"sliceMax,omitempty"`
}

// DeclarativeSectionFilterSpec filters array elements prior to table/list rendering.
type DeclarativeSectionFilterSpec struct {
	RequireField       string `json:"requireField,omitempty"`
	ExcludeFieldPrefix *struct {
		Field  string `json:"field"`
		Prefix string `json:"prefix"`
	} `json:"excludeFieldPrefix,omitempty"`
	ExcludeFieldSuffixes *struct {
		Field    string   `json:"field"`
		Suffixes []string `json:"suffixes"`
	} `json:"excludeFieldSuffixes,omitempty"`
	TagFilterParam *struct {
		Param        string `json:"param"`
		SkipIfEquals string `json:"skipIfEquals,omitempty"`
		TagsField    string `json:"tagsField"`
	} `json:"tagFilterParam,omitempty"`
}

// DeclarativeDedupeSpec merges multi-location duplicate rows (e.g. Rippling uuid, Workable shortcode).
type DeclarativeDedupeSpec struct {
	KeyPaths          []string `json:"keyPaths"`
	MergeTextPaths    []string `json:"mergeTextPaths,omitempty"`
	MergeTargetVar    string   `json:"mergeTargetVar,omitempty"`
	MergeSep          string   `json:"mergeSep,omitempty"`
	MergeLimit        int      `json:"mergeLimit,omitempty"`
	OrBoolPaths       []string `json:"orBoolPaths,omitempty"`
	OrBoolTargetField string   `json:"orBoolTargetField,omitempty"`
}

// DeclarativeParallelArraysSpec zips parallel column arrays into row objects (e.g. SEC EDGAR filings.recent).
type DeclarativeParallelArraysSpec struct {
	BasePath            string            `json:"basePath"`
	Fields              map[string]string `json:"fields"`
	PriorityFilterAfter *struct {
		Index       int      `json:"index"`
		Field       string   `json:"field"`
		AllowValues []string `json:"allowValues"`
	} `json:"priorityFilterAfter,omitempty"`
}

// DeclarativeSortSpec sorts array rows before rendering.
type DeclarativeSortSpec struct {
	BoolDescField string `json:"boolDescField,omitempty"`
	NumDescField  string `json:"numDescField,omitempty"`
}

// DeclarativePaginationMetaSpec emits truncation counts for board feeds.
type DeclarativePaginationMetaSpec struct {
	TotalPath  string `json:"totalPath,omitempty"`
	CursorMode string `json:"cursorMode,omitempty"`
	IDField    string `json:"idField,omitempty"`
}

// DeclarativeTreeCommentsSpec renders nested comment trees (e.g. Hacker News Algolia).
type DeclarativeTreeCommentsSpec struct {
	ChildrenPath string `json:"childrenPath"`
	AuthorPath   string `json:"authorPath"`
	HTMLTextPath string `json:"htmlTextPath"`
	MaxDepth     int    `json:"maxDepth,omitempty"`
	MaxItems     int    `json:"maxItems,omitempty"`
}

// DeclarativeSectionSpec renders a `## <Heading>` prose, GFM table, subsection list, or nested bullet list section.
type DeclarativeSectionSpec struct {
	Heading                      string                         `json:"heading"`
	HeadingTemplate              string                         `json:"headingTemplate,omitempty"`
	WhenVar                      string                         `json:"whenVar,omitempty"`
	UnlessVar                    string                         `json:"unlessVar,omitempty"`
	TextVar                      string                         `json:"textVar,omitempty"`
	ArrayPath                    string                         `json:"arrayPath,omitempty"`
	ParallelArrays               *DeclarativeParallelArraysSpec `json:"parallelArrays,omitempty"`
	MinItems                     int                            `json:"minItems,omitempty"`
	EmptyText                    string                         `json:"emptyText,omitempty"`
	Filter                       *DeclarativeSectionFilterSpec  `json:"filter,omitempty"`
	DedupeBy                     *DeclarativeDedupeSpec         `json:"dedupeBy,omitempty"`
	SortBy                       *DeclarativeSortSpec           `json:"sortBy,omitempty"`
	Columns                      []DeclarativeTableColumn       `json:"columns,omitempty"`
	ListArrayPath                string                         `json:"listArrayPath,omitempty"`
	SubsectionsArrayPath         string                         `json:"subsectionsArrayPath,omitempty"`
	SubsectionHeadingTemplate    string                         `json:"subsectionHeadingTemplate,omitempty"`
	SubsectionAltHeadingTemplate string                         `json:"subsectionAltHeadingTemplate,omitempty"`
	SubsectionAltWhenVar         string                         `json:"subsectionAltWhenVar,omitempty"`
	SubsectionBodyVar            string                         `json:"subsectionBodyVar,omitempty"`
	SubsectionSubkeys            []string                       `json:"subsectionSubkeys,omitempty"`
	TreeComments                 *DeclarativeTreeCommentsSpec   `json:"treeComments,omitempty"`
	Limit                        int                            `json:"limit,omitempty"`
	IndentField                  string                         `json:"indentField,omitempty"`
	IndentOffset                 int                            `json:"indentOffset,omitempty"`
	MaxIndent                    int                            `json:"maxIndent,omitempty"`
	ItemTemplate                 string                         `json:"itemTemplate,omitempty"`
	RequireItemVar               string                         `json:"requireItemVar,omitempty"`
	ItemVars                     map[string]DeclarativeVarSpec  `json:"itemVars,omitempty"`
	CollectLinkVars              []string                       `json:"collectLinkVars,omitempty"`
	LinkScanLimit                int                            `json:"linkScanLimit,omitempty"`
	RecordFields                 map[string]string              `json:"recordFields,omitempty"`
	PaginationMeta               *DeclarativePaginationMetaSpec `json:"paginationMeta,omitempty"`
}

// DeclarativeFindInArray selects a matching element from a JSON array to serve as the active root object.
type DeclarativeFindInArray struct {
	ArrayPath        string   `json:"arrayPath"`
	MatchField       string   `json:"matchField,omitempty"`
	MatchFields      []string `json:"matchFields,omitempty"`
	EndsWithField    string   `json:"endsWithField,omitempty"`
	MatchTemplate    string   `json:"matchTemplate"`
	EndsWithTemplate string   `json:"endsWithTemplate,omitempty"`
	IgnoreCase       bool     `json:"ignoreCase,omitempty"`
}

// DeclarativeXMLItemVarSpec extracts a tag value inside an XML/RSS item block.
type DeclarativeXMLItemVarSpec struct {
	Tags           []string `json:"tags"`
	SplitColonPart *int     `json:"splitColonPart,omitempty"`
	SliceMax       int      `json:"sliceMax,omitempty"`
	Default        string   `json:"default,omitempty"`
}

// DeclarativeXMLColumnSpec renders a column in an XML/RSS table.
type DeclarativeXMLColumnSpec struct {
	Header   string `json:"header"`
	Template string `json:"template"`
}

// DeclarativeXMLSpec extracts structured tables or prose from XML, RSS, or JATS payloads.
type DeclarativeXMLSpec struct {
	Mode                      string                               `json:"mode"`
	RequireAnyTags            []string                             `json:"requireAnyTags,omitempty"`
	ItemTag                   string                               `json:"itemTag,omitempty"`
	ChannelTitleFallbackParam string                               `json:"channelTitleFallbackParam,omitempty"`
	FirstItemVars             map[string][]string                  `json:"firstItemVars,omitempty"`
	TitleTemplate             string                               `json:"titleTemplate,omitempty"`
	EmptyText                 string                               `json:"emptyText,omitempty"`
	Limit                     int                                  `json:"limit,omitempty"`
	RequireItemVar            string                               `json:"requireItemVar,omitempty"`
	ItemVars                  map[string]DeclarativeXMLItemVarSpec `json:"itemVars,omitempty"`
	Columns                   []DeclarativeXMLColumnSpec           `json:"columns,omitempty"`
	CollectLinkVar            string                               `json:"collectLinkVar,omitempty"`
	RecordFields              map[string]string                    `json:"recordFields,omitempty"`
	EmitTotals                bool                                 `json:"emitTotals,omitempty"`
}

// DeclarativeCodeByPathSpec formats a code/markdown variable using the file extension from a path parameter.
type DeclarativeCodeByPathSpec struct {
	SourceVar     string `json:"sourceVar"`
	PathParam     string `json:"pathParam"`
	RawIfMarkdown bool   `json:"rawIfMarkdown,omitempty"`
}

// DeclarativeExtractSpec defines how a JSON, XML, or text twin payload is converted into Markdown and metadata.
type DeclarativeExtractSpec struct {
	CommerceMode            string              `json:"commerceMode,omitempty"`
	IcimsPortal             bool                `json:"icimsPortal,omitempty"`
	TextMode                string              `json:"textMode,omitempty"`
	PathParam               string              `json:"pathParam,omitempty"`
	XML                     *DeclarativeXMLSpec `json:"xml,omitempty"`
	JSONSource              string              `json:"jsonSource,omitempty"`
	WrapRootArrayAs         string              `json:"wrapRootArrayAs,omitempty"`
	UnwrapFirstArrayElement bool                `json:"unwrapFirstArrayElement,omitempty"`
	RootPath                string              `json:"rootPath,omitempty"`
	RejectIfFieldTruthy     string              `json:"rejectIfFieldTruthy,omitempty"`
	RequireFieldEquals      *struct {
		Path  string `json:"path"`
		Value string `json:"value"`
	} `json:"requireFieldEquals,omitempty"`
	RequireArrayItemField *struct {
		ArrayPath string `json:"arrayPath"`
		Field     string `json:"field"`
	} `json:"requireArrayItemField,omitempty"`
	FindInArray           *DeclarativeFindInArray       `json:"findInArray,omitempty"`
	FallbackExtract       *DeclarativeExtractSpec       `json:"fallbackExtract,omitempty"`
	RequireFields         []string                      `json:"requireFields,omitempty"`
	RequireAnyFields      []string                      `json:"requireAnyFields,omitempty"`
	RequireVars           []string                      `json:"requireVars,omitempty"`
	Vars                  map[string]DeclarativeVarSpec `json:"vars,omitempty"`
	CodeByPath            *DeclarativeCodeByPathSpec    `json:"codeByPath,omitempty"`
	TitleTemplate         string                        `json:"titleTemplate,omitempty"`
	TitleWhenVar          string                        `json:"titleWhenVar,omitempty"`
	TitleFallbackTemplate string                        `json:"titleFallbackTemplate,omitempty"`
	DescriptionVar        string                        `json:"descriptionVar,omitempty"`
	DescriptionTemplate   string                        `json:"descriptionTemplate,omitempty"`
	AuthorVar             string                        `json:"authorVar,omitempty"`
	AuthorTemplate        string                        `json:"authorTemplate,omitempty"`
	PublishedTimeVar      string                        `json:"publishedTimeVar,omitempty"`
	BlockquoteTemplate    string                        `json:"blockquoteTemplate,omitempty"`
	BlockquoteWhenVar     string                        `json:"blockquoteWhenVar,omitempty"`
	MetaLine              []DeclarativeBulletSpec       `json:"metaLine,omitempty"`
	MetaLineItalic        bool                          `json:"metaLineItalic,omitempty"`
	FooterItalicTemplate  string                        `json:"footerItalicTemplate,omitempty"`
	FooterItalicWhenVar   string                        `json:"footerItalicWhenVar,omitempty"`
	IntroVar              string                        `json:"introVar,omitempty"`
	Bullets               []DeclarativeBulletSpec       `json:"bullets,omitempty"`
	ObjectLinksPath       string                        `json:"objectLinksPath,omitempty"`
	BodyVar               string                        `json:"bodyVar,omitempty"`
	Sections              []DeclarativeSectionSpec      `json:"sections,omitempty"`
	LinksVars             []string                      `json:"linksVars,omitempty"`
	LinkTemplates         []string                      `json:"linkTemplates,omitempty"`
}

// DeclarativeRouteSpec pairs a URL match specification with its twin fetch and extraction contract.
type DeclarativeRouteSpec struct {
	Match   DeclarativeMatchSpec   `json:"match"`
	Twin    DeclarativeTwinSpec    `json:"twin"`
	Extract DeclarativeExtractSpec `json:"extract"`
}

// DeclarativeHTMLVarSpec defines a post-fetch DOM/JSON-LD/Meta extraction variable in `htmlRoutes`.
type DeclarativeHTMLVarSpec struct {
	JSONLdPaths   []string `json:"jsonLdPaths,omitempty"`
	EmbeddedPaths []string `json:"embeddedPaths,omitempty"`
	MetaKeys      []string `json:"metaKeys,omitempty"`
	AllMetaKey    string   `json:"allMetaKey,omitempty"`
	CSSText       []string `json:"cssText,omitempty"`
	CSSAttr       *struct {
		Selector string `json:"selector"`
		Attr     string `json:"attr"`
	} `json:"cssAttr,omitempty"`
	CSSAllText *struct {
		Selector string `json:"selector"`
		Limit    int    `json:"limit,omitempty"`
		Dedupe   *bool  `json:"dedupe,omitempty"`
		Join     string `json:"join,omitempty"`
	} `json:"cssAllText,omitempty"`
	CSSHTMLToMd  []string `json:"cssHtmlToMd,omitempty"`
	RegexExtract *struct {
		Source    string `json:"source"`
		Pattern   string `json:"pattern"`
		Group     int    `json:"group,omitempty"`
		Transform string `json:"transform,omitempty"`
	} `json:"regexExtract,omitempty"`
	Template         string                  `json:"template,omitempty"`
	WhenVars         []string                `json:"whenVars,omitempty"`
	WhenAnyVars      []string                `json:"whenAnyVars,omitempty"`
	FallbackVar      string                  `json:"fallbackVar,omitempty"`
	FallbackTemplate string                  `json:"fallbackTemplate,omitempty"`
	Default          string                  `json:"default,omitempty"`
	Join             string                  `json:"join,omitempty"`
	Limit            int                     `json:"limit,omitempty"`
	Format           string                  `json:"format,omitempty"`
	CurrencyVar      string                  `json:"currencyVar,omitempty"`
	StripPrefix      string                  `json:"stripPrefix,omitempty"`
	StripSuffix      string                  `json:"stripSuffix,omitempty"`
	StripRegexSuffix string                  `json:"stripRegexSuffix,omitempty"`
	ReplaceAll       *DeclarativeReplaceSpec `json:"replaceAll,omitempty"`
	SliceMax         int                     `json:"sliceMax,omitempty"`
	MinLen           int                     `json:"minLen,omitempty"`
	Trim             *bool                   `json:"trim,omitempty"`
}

// DeclarativeHTMLRouteSpec defines a post-fetch HTML extraction rule in YAML manifests.
type DeclarativeHTMLRouteSpec struct {
	ID                    string                            `json:"id,omitempty"`
	Match                 DeclarativeMatchSpec              `json:"match"`
	Mode                  string                            `json:"mode"`
	JSONLdTypes           []string                          `json:"jsonLdTypes,omitempty"`
	EmbeddedBalancedKey   string                            `json:"embeddedBalancedKey,omitempty"`
	Vars                  map[string]DeclarativeHTMLVarSpec `json:"vars,omitempty"`
	RequireVars           []string                          `json:"requireVars,omitempty"`
	RequireBulletsOrVars  []string                          `json:"requireBulletsOrVars,omitempty"`
	TitleTemplate         string                            `json:"titleTemplate,omitempty"`
	TitleWhenVar          string                            `json:"titleWhenVar,omitempty"`
	TitleFallbackTemplate string                            `json:"titleFallbackTemplate,omitempty"`
	DescriptionVar        string                            `json:"descriptionVar,omitempty"`
	AuthorVar             string                            `json:"authorVar,omitempty"`
	PublishedTimeVar      string                            `json:"publishedTimeVar,omitempty"`
	BlockquoteTemplate    string                            `json:"blockquoteTemplate,omitempty"`
	BlockquoteWhenVar     string                            `json:"blockquoteWhenVar,omitempty"`
	MetaItalicTemplate    string                            `json:"metaItalicTemplate,omitempty"`
	MetaItalicWhenVar     string                            `json:"metaItalicWhenVar,omitempty"`
	IntroVar              string                            `json:"introVar,omitempty"`
	Bullets               []DeclarativeBulletSpec           `json:"bullets,omitempty"`
	BodyVar               string                            `json:"bodyVar,omitempty"`
	BodyFallbackHeading   string                            `json:"bodyFallbackHeading,omitempty"`
	Sections              []struct {
		Heading string `json:"heading"`
		TextVar string `json:"textVar"`
	} `json:"sections,omitempty"`
	AppendCurrentMdDelta *struct {
		BaseVar       string `json:"baseVar,omitempty"`
		MinExtraChars int    `json:"minExtraChars"`
	} `json:"appendCurrentMdDelta,omitempty"`
	LinkTemplates            []string                `json:"linkTemplates,omitempty"`
	PreserveBodyLinksFromVar string                  `json:"preserveBodyLinksFromVar,omitempty"`
	ScriptID                 string                  `json:"scriptId,omitempty"`
	DataAttr                 string                  `json:"dataAttr,omitempty"`
	Extract                  *DeclarativeExtractSpec `json:"extract,omitempty"`
	XML                      *DeclarativeXMLSpec     `json:"xml,omitempty"`
	CleanPreset              string                  `json:"cleanPreset,omitempty"`
}

// DeclarativeCatalogConfig defines polite full-store catalog pagination (`shopify`, `woocommerce`).
type DeclarativeCatalogConfig struct {
	Platform               string `json:"platform"`
	PauseMs                int    `json:"pauseMs"`
	PageCap                int    `json:"pageCap"`
	FirstPageTemplate      string `json:"firstPageTemplate,omitempty"`
	CollectionPageTemplate string `json:"collectionPageTemplate,omitempty"`
	PerPage                int    `json:"perPage,omitempty"`
	MaxVariantsPerProduct  int    `json:"maxVariantsPerProduct,omitempty"`
	MaxImagesPerProduct    int    `json:"maxImagesPerProduct,omitempty"`
}

// DeclarativeAdapterManifest is the canonical shared Go + TypeScript declarative YAML v2 adapter contract.
type DeclarativeAdapterManifest struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Category        string                     `json:"category"`
	Description     string                     `json:"description"`
	Domains         []string                   `json:"domains"`
	UniversalEngine bool                       `json:"universalEngine,omitempty"`
	ExampleURLs     []string                   `json:"exampleUrls"`
	Match           *DeclarativeMatchSpec      `json:"match,omitempty"`
	Twin            *DeclarativeTwinSpec       `json:"twin,omitempty"`
	Extract         *DeclarativeExtractSpec    `json:"extract,omitempty"`
	Routes          []DeclarativeRouteSpec     `json:"routes,omitempty"`
	HTMLRoutes      []DeclarativeHTMLRouteSpec `json:"htmlRoutes,omitempty"`
	Catalog         *DeclarativeCatalogConfig  `json:"catalog,omitempty"`
}

// DeclarativeManifest is an alias for DeclarativeAdapterManifest.
type DeclarativeManifest = DeclarativeAdapterManifest

type compiledManifestBundle struct {
	Version   int                          `json:"version"`
	Manifests []DeclarativeAdapterManifest `json:"manifests"`
}

// DeclarativeAdapterSummary describes an embedded declarative site adapter in `GET /v1/extractors` and MCP `find_extractors`.
type DeclarativeAdapterSummary struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	Modes           []string `json:"modes"`
	Domains         []string `json:"domains"`
	UniversalEngine bool     `json:"universalEngine"`
	ExampleURLs     []string `json:"exampleUrls"`
}

// DeclarativeFormattedDoc holds the structured Markdown and metadata produced from a declarative twin payload.
type DeclarativeFormattedDoc struct {
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	Author        string   `json:"author,omitempty"`
	PublishedTime string   `json:"publishedTime,omitempty"`
	Markdown      string   `json:"markdown"`
	Links         []string `json:"links,omitempty"`
}

// DeclarativeTwinMatch represents a resolved 1-hop declarative twin upgrade ready to fetch and format.
type DeclarativeTwinMatch struct {
	ID        string
	AdapterID string
	FetchURL  string
	Kind      classify.Kind
	Accept    string

	route           DeclarativeRouteSpec
	params          map[string]string
	origURL         string
	domains         []string
	universalEngine bool
}

type declarativeWildcard struct {
	kind    string // "suffix", "prefix", or "infix"
	pattern string
	adapter *DeclarativeAdapterManifest
}

type declarativeRegistry struct {
	manifests []*DeclarativeAdapterManifest
	summaries []DeclarativeAdapterSummary
	byHost    map[string][]*DeclarativeAdapterManifest
	wildcards []declarativeWildcard
	universal []*DeclarativeAdapterManifest
}

var (
	regOnce    sync.Once
	defaultReg *declarativeRegistry
	regInitErr error
)

var approvedWildcardDomainPatternsGo = map[string]bool{
	"*.arcgis.com":        true,
	"*.bamboohr.com":      true,
	"*.breezy.hr":         true,
	"*.recruitee.com":     true,
	"*.jobs.personio.de":  true,
	"*.jobs.personio.com": true,
	"*.oraclecloud.com":   true,
	"gitlab.*":            true,
	"*.icims.com":         true,
	"*.applytojob.com":    true,
	"*.legistar.com":      true,
	"*.wikipedia.org":     true,
	"*.openfoodfacts.org": true,
	"*.pinpointhq.com":    true,
	"*.reddit.com":        true,
	"careers.*.com":       true,
	"jobs.*.com":          true,
	"*.myshopify.com":     true,
	"*.socrata.com":       true,
	"*.stackexchange.com": true,
	"*.teamtailor.com":    true,
}

var reservedCoreATSDomainsGo = map[string]bool{
	"jobs.ashbyhq.com":    true,
	"*.myworkdayjobs.com": true,
	"*.myworkdaysite.com": true,
}

var approvedCrossDomainTwinHostsGo = map[string]map[string]bool{
	"doi-crossref": {"api.crossref.org": true},
	"hackernews":   {"hn.algolia.com": true, "hacker-news.firebaseio.com": true},
	"jazzhr":       {"app.jazz.co": true},
	"npm-registry": {"registry.npmjs.org": true},
	"pubmed-pmc":   {"www.ebi.ac.uk": true},
}

var approvedSAPATSExactExemptionsGo = map[string]bool{
	"enterprise-ats:jobs.smartrecruiters.com": true,
	"enterprise-ats:jobs.jobvite.com":         true,
	"gem-ats:jobs.gem.com":                    true,
}

func claimedRegistrableDomainsGo(domains []string) map[string]bool {
	regs := make(map[string]bool, len(domains))
	for _, raw := range domains {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			continue
		}
		probe := ""
		if strings.HasPrefix(d, "*.") && !strings.Contains(d[2:], "*") {
			probe = d[2:]
		} else if !strings.Contains(d, "*") {
			probe = d
		}
		if probe == "" {
			continue
		}
		if reg := GetRegistrableDomain(probe); reg != "" {
			regs[reg] = true
		}
	}
	return regs
}

// MatchesApprovedWildcard reports whether candidate (an exact domain or wildcard pattern) matches
// one of the 3 allowlisted wildcard shapes (`*.suffix`, `gitlab.*`, `careers.*.com` / `jobs.*.com`).
func MatchesApprovedWildcard(rawWildcard, rawCandidate string) bool {
	w := strings.ToLower(strings.TrimSpace(rawWildcard))
	c := strings.ToLower(strings.TrimSpace(rawCandidate))
	if w == "" || c == "" || !strings.Contains(w, "*") {
		return false
	}
	if w == c {
		return true
	}
	if strings.HasPrefix(w, "*.") && !strings.Contains(w[2:], "*") {
		suf := w[2:]
		return c != suf && strings.HasSuffix(c, "."+suf)
	}
	if strings.HasSuffix(w, ".*") && !strings.Contains(w[:len(w)-2], "*") {
		pre := w[:len(w)-2]
		return strings.HasPrefix(c, pre+".") && len(c) > len(pre)+1
	}
	star := strings.IndexByte(w, '*')
	if star > 0 && strings.LastIndexByte(w, '*') == star {
		head := w[:star]
		tail := w[star+1:]
		return strings.HasPrefix(c, head) && strings.HasSuffix(c, tail) && len(c) > len(head)+len(tail)
	}
	return false
}

func isExemptSAPATSExactClaimGo(wildOwnerID, wildPat, exactOwnerID, exactDom string) bool {
	return wildOwnerID == "sap-rmk-jibe" && wildPat == "jobs.*.com" && approvedSAPATSExactExemptionsGo[exactOwnerID+":"+exactDom]
}

var knownSocrataHostsGo = map[string]bool{
	"data.cityofnewyork.us": true, "data.sfgov.org": true, "data.sf.gov": true, "data.seattle.gov": true,
	"data.cityofchicago.org": true, "data.lacity.org": true, "data.wa.gov": true, "data.nj.gov": true,
	"data.colorado.gov": true, "data.texas.gov": true, "data.ny.gov": true, "data.ct.gov": true,
	"data.oregon.gov": true, "data.austintexas.gov": true, "data.nola.gov": true, "data.cincinnati-oh.gov": true,
	"data.cambridgema.gov": true, "data.montgomerycountymd.gov": true, "data.brla.gov": true,
	"data.cdc.gov": true, "data.cms.gov": true, "data.medicare.gov": true,
}

func isValidAdapterIDGo(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLowerNum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 && !isLowerNum {
			return false
		}
		if !isLowerNum && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func checkASCIIPrintableKeyGo(k string) error {
	if k == "" {
		return fmt.Errorf("empty JSON key in manifest")
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return fmt.Errorf("non-ASCII JSON key %q is forbidden", k)
		}
	}
	return nil
}

func validateValueAgainstReflectTypeGo(v any, t reflect.Type, pathLabel string) error {
	if v == nil || t == nil {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(DeclarativeSegmentSpec{}) {
		if _, isStr := v.(string); isStr {
			return nil
		}
		return validateValueAgainstReflectTypeGo(v, reflect.TypeOf(DeclarativeParamSegment{}), pathLabel)
	}

	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON object", pathLabel)
		}
		exactFields := make(map[string]reflect.Type, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			jsonName := strings.Split(tag, ",")[0]
			if jsonName == "" {
				jsonName = f.Name
			}
			exactFields[jsonName] = f.Type
		}
		for k, child := range obj {
			if err := checkASCIIPrintableKeyGo(k); err != nil {
				return err
			}
			ft, found := exactFields[k]
			if !found {
				return fmt.Errorf("%s: unknown or case-mismatched JSON key %q", pathLabel, k)
			}
			if err := validateValueAgainstReflectTypeGo(child, ft, pathLabel+"."+k); err != nil {
				return err
			}
		}
		return nil

	case reflect.Map:
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON object map", pathLabel)
		}
		elemType := t.Elem()
		for k, child := range obj {
			if err := checkASCIIPrintableKeyGo(k); err != nil {
				return err
			}
			if err := validateValueAgainstReflectTypeGo(child, elemType, pathLabel+"."+k); err != nil {
				return err
			}
		}
		return nil

	case reflect.Slice:
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON array", pathLabel)
		}
		elemType := t.Elem()
		for idx, el := range arr {
			if err := validateValueAgainstReflectTypeGo(el, elemType, fmt.Sprintf("%s[%d]", pathLabel, idx)); err != nil {
				return err
			}
		}
		return nil

	default:
		// Ensure any untyped map[string]any / []any still has ASCII-only keys
		switch typed := v.(type) {
		case map[string]any:
			for k, child := range typed {
				if err := checkASCIIPrintableKeyGo(k); err != nil {
					return err
				}
				if err := validateValueAgainstReflectTypeGo(child, t, pathLabel+"."+k); err != nil {
					return err
				}
			}
		case []any:
			for idx, el := range typed {
				if err := validateValueAgainstReflectTypeGo(el, t, fmt.Sprintf("%s[%d]", pathLabel, idx)); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func validateStrictASCIIJSONKeys(raw []byte) error {
	var top map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&top); err != nil {
		return err
	}
	return validateValueAgainstReflectTypeGo(top, reflect.TypeOf(DeclarativeAdapterManifest{}), "manifest")
}

func validateManifestRulesGo(m *DeclarativeAdapterManifest) error {
	if !isValidAdapterIDGo(m.ID) {
		return fmt.Errorf("manifest has invalid id %q", m.ID)
	}
	if strings.TrimSpace(m.Name) == "" || len(m.Domains) == 0 || len(m.ExampleURLs) == 0 {
		return fmt.Errorf("manifest %q missing required metadata", m.ID)
	}
	switch m.Category {
	case "developer", "genai", "jobs", "finance", "public-records", "research-health", "commerce-social":
	default:
		return fmt.Errorf("manifest %q has invalid category %q", m.ID, m.Category)
	}
	for _, rawDom := range m.Domains {
		pat := strings.ToLower(strings.TrimSpace(rawDom))
		if pat == "" || pat == "*" || pat == "*.*" || strings.ContainsAny(pat, " \t\r\n/\\:?#@") {
			return fmt.Errorf("manifest %q has invalid or overly broad domain %q (M2)", m.ID, rawDom)
		}
		for idx := 0; idx < len(pat); idx++ {
			if pat[idx] < 0x20 || pat[idx] > 0x7e {
				return fmt.Errorf("manifest %q has non-ASCII domain %q", m.ID, rawDom)
			}
		}
		if strings.Contains(pat, "*") {
			if strings.HasPrefix(pat, "*.") && !strings.Contains(pat[2:], "*") {
				rest := pat[2:]
				isBuiltInShopify := m.ID == "shopify" && pat == "*.myshopify.com"
				if !isBuiltInShopify && (IsPublicOrPrivateSuffix(rest) || HasPrivateSharedHostingSuffix(rest)) {
					return fmt.Errorf("manifest %q has overly broad TLD/eTLD/hosting wildcard %q (M2)", m.ID, rawDom)
				}
			}
			if strings.HasSuffix(pat, ".*") {
				pre := pat[:len(pat)-2]
				if len(pre) < 3 || strings.Contains(pre, "*") {
					return fmt.Errorf("manifest %q has invalid prefix wildcard %q (M2)", m.ID, rawDom)
				}
			}
		} else if IsPublicOrPrivateSuffix(pat) || HasPrivateSharedHostingSuffix(pat) {
			return fmt.Errorf("manifest %q claims forbidden public or private shared-hosting suffix in domain %q (H7)", m.ID, rawDom)
		}
	}
	for _, ex := range m.ExampleURLs {
		exNoFrag := ex
		if hashIdx := strings.IndexByte(exNoFrag, '#'); hashIdx >= 0 {
			exNoFrag = exNoFrag[:hashIdx]
		}
		if !isSafePublicTwinURL(exNoFrag) {
			return fmt.Errorf("manifest %q exampleUrl %q must be a safe public https:// URL", m.ID, ex)
		}
	}
	if m.Catalog != nil {
		plat := strings.ToLower(strings.TrimSpace(m.Catalog.Platform))
		if plat != "shopify" && plat != "woocommerce" {
			return fmt.Errorf("manifest %q has unsupported catalog.platform %q (expected \"shopify\" or \"woocommerce\")", m.ID, m.Catalog.Platform)
		}
	}

	hasSingle := m.Match != nil || m.Twin != nil || m.Extract != nil
	if hasSingle && (m.Match == nil || m.Twin == nil || m.Extract == nil) {
		return fmt.Errorf("manifest %q single-route shorthand requires match, twin, and extract", m.ID)
	}
	if len(m.Routes) == 0 && hasSingle {
		m.Routes = []DeclarativeRouteSpec{{
			Match:   *m.Match,
			Twin:    *m.Twin,
			Extract: *m.Extract,
		}}
	}
	if len(m.Routes) == 0 && len(m.HTMLRoutes) == 0 && m.Catalog == nil {
		return fmt.Errorf("manifest %q must define routes, match/twin/extract, htmlRoutes, or catalog", m.ID)
	}

	for i, r := range m.Routes {
		if r.Twin.Kind != "json" && r.Twin.Kind != "text" {
			return fmt.Errorf("manifest %q route %d has unsupported twin kind %q", m.ID, i, r.Twin.Kind)
		}
		if r.Twin.ID != "" && !isValidAdapterIDGo(r.Twin.ID) {
			return fmt.Errorf("manifest %q route %d has invalid twin.id %q", m.ID, i, r.Twin.ID)
		}
		fu := r.Twin.FetchURL
		if fu != "{requestUrl}" {
			if !strings.HasPrefix(fu, "https://") && !strings.HasPrefix(fu, "{origin}/") {
				return fmt.Errorf("manifest %q route %d fetchUrl must use https://", m.ID, i)
			}
			if strings.Contains(fu, "{host}") || strings.Contains(fu, "{origin}") {
				if (!strings.HasPrefix(fu, "https://{host}/") && !strings.HasPrefix(fu, "{origin}/")) ||
					strings.HasPrefix(fu, "https://{host}//") || strings.HasPrefix(fu, "{origin}//") {
					return fmt.Errorf("manifest %q route %d cannot interpolate {host}/{origin} into non-origin URL %q (M2)", m.ID, i, fu)
				}
				restAfterOrigin := strings.TrimPrefix(fu, "https://{host}/")
				if strings.HasPrefix(fu, "{origin}/") {
					restAfterOrigin = strings.TrimPrefix(fu, "{origin}/")
				}
				if strings.Contains(restAfterOrigin, "{origin}") {
					return fmt.Errorf("manifest %q route %d cannot repeat {origin} in fetchUrl %q (M2)", m.ID, i, fu)
				}
				dynSample := expandTemplate(fu, func(k string) string {
					switch k {
					case "host":
						return "example.com"
					case "origin":
						return "https://example.com"
					default:
						return "sample"
					}
				})
				parsedDyn, dErr := url.Parse(dynSample)
				if dErr != nil || !isSafePublicTwinURL(dynSample) || strings.ToLower(parsedDyn.Hostname()) != "example.com" {
					return fmt.Errorf("manifest %q route %d fetchUrl failed same-origin public HTTPS check: %q", m.ID, i, fu)
				}
			}
			if !strings.HasPrefix(fu, "https://{host}/") && !strings.HasPrefix(fu, "{origin}/") {
				sample := expandTemplate(fu, func(string) string { return "sample" })
				if !isSafePublicTwinURL(sample) {
					return fmt.Errorf("manifest %q route %d fetchUrl failed public HTTPS check: %q", m.ID, i, fu)
				}
				if parsedSample, err := url.Parse(sample); err == nil {
					h := strings.TrimSuffix(strings.ToLower(parsedSample.Hostname()), ".")
					if IsPublicOrPrivateSuffix(h) || HasPrivateSharedHostingSuffix(h) {
						return fmt.Errorf("manifest %q route %d fetchUrl targets forbidden public or shared-hosting suffix: %q", m.ID, i, fu)
					}
				}
			}
		}
	}
	for i, hr := range m.HTMLRoutes {
		if hr.ID != "" && !isValidAdapterIDGo(hr.ID) {
			return fmt.Errorf("manifest %q htmlRoute %d has invalid id %q", m.ID, i, hr.ID)
		}
	}
	return nil
}

// ParseDeclarativeManifest parses and strictly validates a single declarative JSON manifest.
func ParseDeclarativeManifest(raw []byte) (*DeclarativeAdapterManifest, error) {
	if err := validateStrictASCIIJSONKeys(raw); err != nil {
		return nil, err
	}
	var m DeclarativeAdapterManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if err := validateManifestRulesGo(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ParseDeclarativeYAMLManifest parses and validates a declarative YAML manifest (explicitly rejecting anchors, aliases, merge keys, and non-ASCII keys).
func ParseDeclarativeYAMLManifest(raw []byte) (*DeclarativeAdapterManifest, error) {
	jsonBytes, err := YAMLToJSON(raw)
	if err != nil {
		return nil, err
	}
	return ParseDeclarativeManifest(jsonBytes)
}

// ValidateDeclarativeManifests enforces full compiler-equivalent security invariants across a manifest slice:
// per-manifest schema/host/twin/catalog validation, approved wildcard allowlist, reserved core ATS domains,
// exactOwners uniqueness + MatchesApprovedWildcard collision rejection, and same-registrable-domain twin.fetchUrl checks (H7).
func ValidateDeclarativeManifests(manifests []DeclarativeAdapterManifest) error {
	seenIDs := make(map[string]bool, len(manifests))
	twinOwners := make(map[string]string, len(manifests))
	exactOwners := make(map[string]string, len(manifests)*2)
	wildcardOwners := make(map[string]string, 32)
	catalogOwners := make(map[string]string, 2)
	type domainClaim struct {
		id      string
		pattern string
	}
	wildcardClaims := make([]domainClaim, 0, 32)

	for i := range manifests {
		m := manifests[i]
		if err := validateManifestRulesGo(&m); err != nil {
			return err
		}
		if seenIDs[m.ID] {
			return fmt.Errorf("duplicate declarative manifest id %q (M2)", m.ID)
		}
		seenIDs[m.ID] = true

		if m.Catalog != nil {
			plat := strings.ToLower(strings.TrimSpace(m.Catalog.Platform))
			if plat != "shopify" && plat != "woocommerce" {
				return fmt.Errorf("manifest %q has unsupported catalog.platform %q (H7)", m.ID, m.Catalog.Platform)
			}
			if prev, exists := catalogOwners[plat]; exists && prev != m.ID {
				return fmt.Errorf("duplicate catalog platform %q claimed by both %q and %q (H7)", plat, prev, m.ID)
			}
			catalogOwners[plat] = m.ID
		}

		manifestRegs := claimedRegistrableDomainsGo(m.Domains)
		for _, rawDom := range m.Domains {
			normDom := strings.ToLower(strings.TrimSpace(rawDom))
			if reservedCoreATSDomainsGo[normDom] {
				return fmt.Errorf("manifest %q claims reserved core ATS domain %q (M2)", m.ID, rawDom)
			}
			if strings.Contains(normDom, "*") {
				if !approvedWildcardDomainPatternsGo[normDom] {
					return fmt.Errorf("manifest %q claims unapproved wildcard domain %q (H7)", m.ID, rawDom)
				}
				if prev, exists := wildcardOwners[normDom]; exists && prev != m.ID {
					return fmt.Errorf("manifest %q domain %q overlaps %q already claimed by %q (H7)", m.ID, normDom, normDom, prev)
				}
				for prevExact, prevOwner := range exactOwners {
					if prevOwner == m.ID {
						continue
					}
					if MatchesApprovedWildcard(normDom, prevExact) && !isExemptSAPATSExactClaimGo(m.ID, normDom, prevOwner, prevExact) {
						return fmt.Errorf("manifest %q domain %q overlaps %q already claimed by %q (H7)", m.ID, normDom, prevExact, prevOwner)
					}
				}
				for _, prevWild := range wildcardClaims {
					if prevWild.id == m.ID {
						continue
					}
					if MatchesApprovedWildcard(normDom, prevWild.pattern) || MatchesApprovedWildcard(prevWild.pattern, normDom) {
						return fmt.Errorf("manifest %q domain %q overlaps %q already claimed by %q (H7)", m.ID, normDom, prevWild.pattern, prevWild.id)
					}
				}
				wildcardOwners[normDom] = m.ID
				wildcardClaims = append(wildcardClaims, domainClaim{id: m.ID, pattern: normDom})
			} else {
				if prev, exists := exactOwners[normDom]; exists && prev != m.ID {
					return fmt.Errorf("manifest %q duplicate domain %q overlaps claim by %q (H7)", m.ID, normDom, prev)
				}
				for _, prevWild := range wildcardClaims {
					if prevWild.id == m.ID {
						continue
					}
					if MatchesApprovedWildcard(prevWild.pattern, normDom) && !isExemptSAPATSExactClaimGo(prevWild.id, prevWild.pattern, m.ID, normDom) {
						return fmt.Errorf("manifest %q domain %q overlaps %q already claimed by %q (H7)", m.ID, normDom, prevWild.pattern, prevWild.id)
					}
				}
				exactOwners[normDom] = m.ID
			}
		}

		for rIdx, r := range m.Routes {
			tid := r.Twin.ID
			if tid == "" {
				tid = m.ID
			}
			if prev, exists := twinOwners[tid]; exists && prev != m.ID {
				return fmt.Errorf("duplicate twin id %q claimed by both %q and %q (M2)", tid, prev, m.ID)
			}
			twinOwners[tid] = m.ID

			fu := r.Twin.FetchURL
			if fu != "{requestUrl}" && !strings.HasPrefix(fu, "https://{host}/") && !strings.HasPrefix(fu, "{origin}/") {
				sample := expandTemplate(fu, func(string) string { return "sample" })
				parsedSample, pErr := url.Parse(sample)
				if pErr != nil {
					return fmt.Errorf("manifest %q route %d invalid fetchUrl %q: %w", m.ID, rIdx, fu, pErr)
				}
				targetHost := strings.TrimSuffix(strings.ToLower(parsedSample.Hostname()), ".")
				targetReg := GetRegistrableDomain(targetHost)
				approvedCross := approvedCrossDomainTwinHostsGo[m.ID]
				if (targetReg == "" || !manifestRegs[targetReg]) && (approvedCross == nil || !approvedCross[targetHost]) {
					return fmt.Errorf("manifest %q route %d cross-domain twin host %q does not match manifest registrable domains and is not allowlisted (H7)", m.ID, rIdx, targetHost)
				}
			}
		}
	}
	return nil
}

func registerManifestInRegistry(reg *declarativeRegistry, m *DeclarativeAdapterManifest, seenIDs map[string]bool, twinOwners map[string]string) error {
	if seenIDs[m.ID] {
		return fmt.Errorf("duplicate declarative manifest id %q (M2)", m.ID)
	}
	seenIDs[m.ID] = true

	for _, r := range m.Routes {
		tid := r.Twin.ID
		if tid == "" {
			tid = m.ID
		}
		if prev, exists := twinOwners[tid]; exists && prev != m.ID {
			return fmt.Errorf("duplicate twin id %q claimed by both %q and %q (M2)", tid, prev, m.ID)
		}
		twinOwners[tid] = m.ID
	}

	var modes []string
	if len(m.Routes) > 0 {
		modes = append(modes, "twin")
	}
	if len(m.HTMLRoutes) > 0 {
		modes = append(modes, "html")
	}
	if m.Catalog != nil {
		modes = append(modes, "catalog")
	}

	reg.manifests = append(reg.manifests, m)
	reg.summaries = append(reg.summaries, DeclarativeAdapterSummary{
		ID:              m.ID,
		Name:            m.Name,
		Category:        m.Category,
		Description:     m.Description,
		Modes:           modes,
		Domains:         append([]string(nil), m.Domains...),
		UniversalEngine: m.UniversalEngine,
		ExampleURLs:     append([]string(nil), m.ExampleURLs...),
	})

	for _, d := range m.Domains {
		pat := strings.ToLower(strings.TrimSpace(d))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") && !strings.Contains(pat[2:], "*") {
			reg.wildcards = append(reg.wildcards, declarativeWildcard{kind: "suffix", pattern: pat[1:], adapter: m})
		} else if strings.HasSuffix(pat, ".*") && !strings.Contains(pat[:len(pat)-2], "*") {
			reg.wildcards = append(reg.wildcards, declarativeWildcard{kind: "prefix", pattern: pat[:len(pat)-1], adapter: m})
		} else if strings.Contains(pat, "*") {
			reg.wildcards = append(reg.wildcards, declarativeWildcard{kind: "infix", pattern: pat, adapter: m})
		} else {
			reg.byHost[pat] = append(reg.byHost[pat], m)
		}
	}
	if m.UniversalEngine {
		reg.universal = append(reg.universal, m)
	}
	return nil
}

func loadRegistry() *declarativeRegistry {
	regOnce.Do(func() {
		reg := &declarativeRegistry{
			byHost: make(map[string][]*DeclarativeAdapterManifest),
		}
		seenIDs := make(map[string]bool)
		twinOwners := make(map[string]string)

		// Load canonical pre-compiled bundle (`manifests/compiled.json`) produced by `npm run adapter:compile`.
		rawCompiled, rErr := embeddedManifestFS.ReadFile("manifests/compiled.json")
		if rErr != nil {
			regInitErr = fmt.Errorf("read embedded manifests/compiled.json: %w", rErr)
			defaultReg = reg
			return
		}
		var rawBundleMap map[string]any
		if kErr := json.NewDecoder(bytes.NewReader(rawCompiled)).Decode(&rawBundleMap); kErr != nil {
			regInitErr = fmt.Errorf("decode manifests/compiled.json map: %w", kErr)
			panic("extract: " + regInitErr.Error())
		}
		if sErr := validateValueAgainstReflectTypeGo(rawBundleMap, reflect.TypeOf(compiledManifestBundle{}), "compiledBundle"); sErr != nil {
			regInitErr = sErr
			panic("extract: " + regInitErr.Error())
		}

		var bundle compiledManifestBundle
		dec := json.NewDecoder(bytes.NewReader(rawCompiled))
		dec.DisallowUnknownFields()
		if dErr := dec.Decode(&bundle); dErr != nil {
			regInitErr = fmt.Errorf("decode manifests/compiled.json: %w", dErr)
			panic("extract: " + regInitErr.Error())
		}
		if vSetErr := ValidateDeclarativeManifests(bundle.Manifests); vSetErr != nil {
			regInitErr = vSetErr
			panic("extract: " + regInitErr.Error())
		}
		for i := range bundle.Manifests {
			m := bundle.Manifests[i]
			if vErr := validateManifestRulesGo(&m); vErr != nil {
				regInitErr = vErr
				panic("extract: " + regInitErr.Error())
			}
			mCopy := m
			if regErr := registerManifestInRegistry(reg, &mCopy, seenIDs, twinOwners); regErr != nil {
				regInitErr = regErr
				panic("extract: " + regInitErr.Error())
			}
		}
		defaultReg = reg
	})
	if regInitErr != nil {
		panic("extract: " + regInitErr.Error())
	}
	return defaultReg
}

func loadRegistryFromFS(fsys fs.ReadDirFS) (*declarativeRegistry, error) {
	reg := &declarativeRegistry{
		byHost: make(map[string][]*DeclarativeAdapterManifest),
	}
	entries, err := fsys.ReadDir("manifests")
	if err != nil {
		return reg, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var initErr error
	var parsedManifests []DeclarativeAdapterManifest
	seenIDs := make(map[string]bool)
	twinOwners := make(map[string]string)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		nameLower := strings.ToLower(ent.Name())
		if nameLower == "compiled.json" {
			continue
		}
		isYAML := strings.HasSuffix(nameLower, ".yaml") || strings.HasSuffix(nameLower, ".yml")
		isJSON := strings.HasSuffix(nameLower, ".json")
		if !isYAML && !isJSON {
			continue
		}
		raw, rErr := fs.ReadFile(fsys, "manifests/"+ent.Name())
		if rErr != nil {
			initErr = rErr
			continue
		}
		var m *DeclarativeAdapterManifest
		var pErr error
		if isYAML {
			m, pErr = ParseDeclarativeYAMLManifest(raw)
		} else {
			m, pErr = ParseDeclarativeManifest(raw)
		}
		if pErr != nil {
			initErr = fmt.Errorf("%s: %w", ent.Name(), pErr)
			continue
		}
		parsedManifests = append(parsedManifests, *m)
	}
	if initErr == nil {
		if vErr := ValidateDeclarativeManifests(parsedManifests); vErr != nil {
			return reg, vErr
		}
	}
	for i := range parsedManifests {
		mCopy := parsedManifests[i]
		if regErr := registerManifestInRegistry(reg, &mCopy, seenIDs, twinOwners); regErr != nil {
			initErr = regErr
			continue
		}
	}
	return reg, initErr
}

// ListDeclarativeAdapters returns metadata summaries for all embedded declarative site adapters.
func ListDeclarativeAdapters() []DeclarativeAdapterSummary {
	reg := loadRegistry()
	out := make([]DeclarativeAdapterSummary, len(reg.summaries))
	for i, s := range reg.summaries {
		out[i] = DeclarativeAdapterSummary{
			ID:              s.ID,
			Name:            s.Name,
			Category:        s.Category,
			Description:     s.Description,
			Modes:           append([]string(nil), s.Modes...),
			Domains:         append([]string(nil), s.Domains...),
			UniversalEngine: s.UniversalEngine,
			ExampleURLs:     append([]string(nil), s.ExampleURLs...),
		}
	}
	return out
}

// FindDeclarativeAdapters filters and ranks embedded declarative site adapters by optional query and category.
func FindDeclarativeAdapters(query, category string, limit int) []DeclarativeAdapterSummary {
	all := ListDeclarativeAdapters()
	catNorm := strings.ToLower(strings.TrimSpace(category))
	qNorm := strings.ToLower(strings.TrimSpace(query))
	tokens := strings.Fields(qNorm)

	type scored struct {
		item  DeclarativeAdapterSummary
		score int
	}
	var matches []scored
	for _, a := range all {
		if catNorm != "" && a.Category != catNorm {
			continue
		}
		if len(tokens) == 0 {
			matches = append(matches, scored{item: a, score: 1})
			continue
		}
		haystack := strings.ToLower(a.ID + " " + a.Name + " " + a.Category + " " + a.Description + " " + strings.Join(a.Domains, " "))
		sc := 0
		if qNorm != "" && (a.ID == qNorm || strings.Contains(strings.ToLower(a.Name), qNorm)) {
			sc += 10
		}
		for _, tok := range tokens {
			if a.ID == tok {
				sc += 8
			} else if strings.Contains(a.ID, tok) {
				sc += 5
			}
			for _, dom := range a.Domains {
				if strings.Contains(strings.ToLower(dom), tok) {
					sc += 5
					break
				}
			}
			if strings.Contains(haystack, tok) {
				sc += 2
			}
		}
		if sc > 0 {
			matches = append(matches, scored{item: a, score: sc})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].item.ID < matches[j].item.ID
	})
	if limit > 0 && len(matches) > limit {
		matches = matches[:limit]
	}
	out := make([]DeclarativeAdapterSummary, len(matches))
	for i, m := range matches {
		out[i] = m.item
	}
	return out
}

func matchesHostPatternLinearGo(host, rawPat string) bool {
	pat := strings.ToLower(strings.TrimSpace(rawPat))
	if pat == "" {
		return false
	}
	if !strings.Contains(pat, "*") {
		return host == pat
	}
	if strings.HasPrefix(pat, "*.") && !strings.Contains(pat[2:], "*") {
		suf := pat[1:]
		return strings.HasSuffix(host, suf) && len(host) > len(suf)
	}
	if strings.HasSuffix(pat, ".*") && !strings.Contains(pat[:len(pat)-2], "*") {
		pre := pat[:len(pat)-1]
		return strings.HasPrefix(host, pre) && len(host) > len(pre)
	}
	parts := strings.Split(pat, "*")
	if parts[0] != "" && !strings.HasPrefix(host, parts[0]) {
		return false
	}
	lastPart := parts[len(parts)-1]
	if lastPart != "" && !strings.HasSuffix(host, lastPart) {
		return false
	}
	cursor := len(parts[0])
	endBound := len(host) - len(lastPart)
	if cursor > endBound {
		return false
	}
	for i := 1; i < len(parts)-1; i++ {
		mid := parts[i]
		if mid == "" {
			continue
		}
		idx := strings.Index(host[cursor:endBound], mid)
		if idx < 0 {
			return false
		}
		cursor += idx + len(mid)
	}
	return true
}

// ResolveDeclarativeTwin checks if `rawURL` matches any embedded declarative adapter and returns its 1-hop twin descriptor.
func ResolveDeclarativeTwin(rawURL string) (*DeclarativeTwinMatch, bool) {
	return resolveDeclarativeTwinWithRegistry(loadRegistry(), rawURL)
}

func resolveDeclarativeTwinWithRegistry(reg *declarativeRegistry, rawURL string) (*DeclarativeTwinMatch, bool) {
	trimmed := strings.TrimSpace(rawURL)
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, false
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !isSafePublicHostnameGo(host) {
		return nil, false
	}
	var candidates []*DeclarativeAdapterManifest
	seen := make(map[*DeclarativeAdapterManifest]bool)
	push := func(a *DeclarativeAdapterManifest) {
		if len(a.Routes) > 0 && !seen[a] {
			seen[a] = true
			candidates = append(candidates, a)
		}
	}

	for _, a := range reg.byHost[host] {
		push(a)
	}
	for _, w := range reg.wildcards {
		switch w.kind {
		case "suffix":
			if strings.HasSuffix(host, w.pattern) && len(host) > len(w.pattern) {
				push(w.adapter)
			}
		case "prefix":
			if strings.HasPrefix(host, w.pattern) && len(host) > len(w.pattern) {
				push(w.adapter)
			}
		case "infix":
			if matchesHostPatternLinearGo(host, w.pattern) {
				push(w.adapter)
			}
		}
	}
	for _, uEng := range reg.universal {
		push(uEng)
	}
	if len(candidates) == 0 {
		return nil, false
	}

	rawParts := splitNonEmptyEscapedSegments(u.EscapedPath())
	for _, adapter := range candidates {
		if match, ok := resolveManifestTwinOnParsedURL(adapter, u, host, rawParts); ok {
			return match, true
		}
	}
	return nil, false
}

func resolveManifestTwinOnParsedURL(adapter *DeclarativeAdapterManifest, u *url.URL, host string, rawParts []string) (*DeclarativeTwinMatch, bool) {
	for _, route := range adapter.Routes {
		params, matched := matchDeclarativeRoute(route.Match, u, host, rawParts)
		if !matched {
			continue
		}
		fetchURL, okURL := buildResolvedTwinURLGo(route, u, host, params)
		if !okURL {
			continue
		}
		twinID := route.Twin.ID
		if twinID == "" {
			twinID = adapter.ID
		}
		kind := classify.KindJSON
		if route.Twin.Kind == "text" {
			kind = classify.KindText
		}
		cleanOrig := *u
		cleanOrig.Fragment = ""
		cleanOrig.User = nil
		return &DeclarativeTwinMatch{
			ID:              twinID,
			AdapterID:       adapter.ID,
			FetchURL:        fetchURL,
			Kind:            kind,
			Accept:          normalizeDeclarativeAccept(route.Twin.Kind, route.Twin.Accept),
			route:           route,
			params:          params,
			origURL:         cleanOrig.String(),
			domains:         append([]string(nil), adapter.Domains...),
			universalEngine: adapter.UniversalEngine,
		}, true
	}
	return nil, false
}

// ValidateRedirectTarget verifies that a twin HTTP redirect destination remains a safe public HTTPS URL
// on the exact initial FetchURL host or an explicitly declared non-wildcard manifest domain (matching
// TypeScript `isTrustedTwinRedirectUrl` 1:1 without following redirects to unclaimed same-registrable subdomains
// or across multi-tenant wildcards).
func (m *DeclarativeTwinMatch) ValidateRedirectTarget(finalURL string) bool {
	if m == nil {
		return false
	}
	if finalURL == "" {
		return true
	}
	cleanFinal := finalURL
	if hash := strings.IndexByte(cleanFinal, '#'); hash >= 0 {
		cleanFinal = cleanFinal[:hash]
	}
	if !isSafePublicTwinURL(cleanFinal) {
		return false
	}
	initParsed, err1 := url.Parse(m.FetchURL)
	finalParsed, err2 := url.Parse(cleanFinal)
	if err1 != nil || err2 != nil {
		return false
	}
	initHost := strings.TrimSuffix(strings.ToLower(initParsed.Hostname()), ".")
	finalHost := strings.TrimSuffix(strings.ToLower(finalParsed.Hostname()), ".")
	if finalHost == initHost {
		return true
	}
	if IsPublicOrPrivateSuffix(finalHost) || HasPrivateSharedHostingSuffix(finalHost) {
		return false
	}
	hasWildcard := m.universalEngine
	for _, d := range m.domains {
		if strings.Contains(d, "*") {
			hasWildcard = true
			break
		}
	}
	if hasWildcard {
		// On multi-tenant wildcard / universal adapters (e.g. *.myshopify.com), never follow redirects across tenants.
		return false
	}
	for _, d := range m.domains {
		if matchesHostPatternLinearGo(finalHost, d) {
			return true
		}
	}
	return false
}

func buildResolvedTwinURLGo(route DeclarativeRouteSpec, u *url.URL, host string, params map[string]string) (string, bool) {
	twin := route.Twin
	var candidate string
	if twin.FetchURL == "{requestUrl}" {
		cloned := *u
		cloned.Fragment = ""
		cloned.User = nil
		cloned.Host = host
		if twin.OverridePathIf != nil {
			cleanCur := strings.TrimRight(cloned.Path, "/")
			if cleanCur == "" {
				cleanCur = "/"
			}
			for _, mp := range twin.OverridePathIf.MatchPaths {
				want := strings.TrimRight(mp, "/")
				if want == "" {
					want = "/"
				}
				if strings.EqualFold(cleanCur, want) {
					cloned.Path = twin.OverridePathIf.NewPath
					cloned.RawPath = ""
					break
				}
			}
		}
		if len(twin.DefaultQueryParams) > 0 || len(twin.SetQueryParams) > 0 {
			q := cloned.Query()
			for k, v := range twin.DefaultQueryParams {
				if q.Get(k) == "" {
					q.Set(k, v)
				}
			}
			for k, v := range twin.SetQueryParams {
				q.Set(k, v)
			}
			cloned.RawQuery = q.Encode()
		}
		candidate = cloned.String()
	} else {
		rawSet := make(map[string]bool, len(twin.RawPathParams))
		for _, rp := range twin.RawPathParams {
			rawSet[rp] = true
		}
		candidate = expandTemplate(twin.FetchURL, func(key string) string {
			switch key {
			case "host":
				return host
			case "origin":
				return "https://" + host
			case "baseCleanUrl":
				return "https://" + host + strings.TrimRight(u.Path, "/")
			}
			val := params[key]
			if rawSet[key] {
				return encodeSafeSubpath(val)
			}
			return encodeURIComponent(val)
		})
	}
	if !isSafePublicTwinURL(candidate) {
		return "", false
	}
	return candidate, true
}

func normalizeDeclarativeAccept(kind, rawAccept string) string {
	if kind != "text" {
		if strings.TrimSpace(rawAccept) == "" {
			return "application/json"
		}
		return strings.TrimSpace(rawAccept)
	}
	trimmed := strings.ToLower(strings.TrimSpace(rawAccept))
	switch trimmed {
	case "text/html", "text/markdown", "text/x-markdown", "application/xml", "text/xml", "application/rss+xml", "application/atom+xml", "application/json", "text/calendar", "text/plain":
		return trimmed
	default:
		return "text/plain"
	}
}

func isSafePublicHostnameGo(h string) bool {
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".nip.io") || strings.HasSuffix(h, ".sslip.io") || strings.HasSuffix(h, ".xip.io") ||
		!strings.Contains(h, ".") || strings.Contains(h, ":") {
		return false
	}
	if net.ParseIP(h) != nil {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if tld[0] >= '0' && tld[0] <= '9' {
		return false
	}
	return true
}

func isSafePublicTwinURL(raw string) bool {
	if !strings.HasPrefix(raw, "https://") || strings.ContainsAny(raw, " \t\r\n\\") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !isSafePublicHostnameGo(h) {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func splitNonEmptyEscapedSegments(escapedPath string) []string {
	raw := strings.Split(escapedPath, "/")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isLikelySocrataHostGo(host string) bool {
	if knownSocrataHostsGo[host] {
		return true
	}
	if strings.HasSuffix(host, ".socrata.com") && len(host) > len(".socrata.com") {
		return true
	}
	if !strings.HasPrefix(host, "data.") {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 3 || parts[1] == "" {
		return false
	}
	for i := 0; i < len(parts[1]); i++ {
		c := parts[1][i]
		if !isASCIIAlnum(c) && c != '-' {
			return false
		}
	}
	return parts[2] == "gov" || parts[2] == "org" || parts[2] == "us"
}

func asciiLowerExtractByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func asciiLowerExtractString(s string) string {
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
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = asciiLowerExtractByte(s[i])
	}
	return string(b)
}

func indexFoldASCIIExtract(s, lowerNeedle string) int {
	if lowerNeedle == "" {
		return 0
	}
	if len(s) < len(lowerNeedle) {
		return -1
	}
	for i := 0; i+len(lowerNeedle) <= len(s); i++ {
		match := true
		for j := 0; j < len(lowerNeedle); j++ {
			if asciiLowerExtractByte(s[i+j]) != lowerNeedle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func isArcgisRestLayerPathGo(p string) bool {
	clean := strings.TrimRight(p, "/")
	const marker = "/rest/services/"
	idx := indexFoldASCIIExtract(clean, marker)
	if idx < 0 {
		return false
	}
	tail := clean[idx+len(marker):]
	segs := splitNonEmptyEscapedSegments(tail)
	if len(segs) < 2 {
		return false
	}
	last := asciiLowerExtractString(segs[len(segs)-1])
	prev := asciiLowerExtractString(segs[len(segs)-2])
	if last == "featureserver" || last == "mapserver" {
		return true
	}
	if validateDeclarativeParam(last, "digits", nil, nil, 1, 10) && (prev == "featureserver" || prev == "mapserver") {
		return len(segs) >= 3
	}
	return false
}

func isLocaleSegmentGo(seg string) bool {
	if len(seg) == 2 {
		return seg[0] >= 'a' && seg[0] <= 'z' && seg[1] >= 'a' && seg[1] <= 'z'
	}
	if len(seg) >= 5 && len(seg) <= 7 && seg[2] == '-' {
		if !(seg[0] >= 'a' && seg[0] <= 'z' && seg[1] >= 'a' && seg[1] <= 'z') {
			return false
		}
		for i := 3; i < len(seg); i++ {
			c := seg[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				return false
			}
		}
		return true
	}
	return false
}

func applyParamTransformGo(val, transform string) string {
	switch transform {
	case "lower":
		return strings.ToLower(val)
	case "upper":
		return strings.ToUpper(val)
	case "pad10_zero":
		trimmed := strings.TrimSpace(val)
		if len(trimmed) < 10 {
			return strings.Repeat("0", 10-len(trimmed)) + trimmed
		}
		return trimmed
	case "strip_leading_zeros":
		stripped := strings.TrimLeft(strings.TrimSpace(val), "0")
		if stripped == "" {
			return "0"
		}
		return stripped
	default:
		return val
	}
}

func matchDeclarativeRoute(spec DeclarativeMatchSpec, u *url.URL, host string, rawParts []string) (map[string]string, bool) {
	if len(spec.AnyOf) > 0 {
		for _, sub := range spec.AnyOf {
			if params, ok := matchDeclarativeRoute(sub, u, host, rawParts); ok {
				return params, true
			}
		}
		return nil, false
	}

	if len(spec.Hosts) > 0 {
		matchedHost := false
		for _, hp := range spec.Hosts {
			if matchesHostPatternLinearGo(host, hp) {
				matchedHost = true
				break
			}
		}
		if !matchedHost {
			return nil, false
		}
	}
	for _, ep := range spec.ExcludeHosts {
		if matchesHostPatternLinearGo(host, ep) {
			return nil, false
		}
	}
	if spec.SocrataHost && !isLikelySocrataHostGo(host) {
		return nil, false
	}

	params := map[string]string{
		"host":   host,
		"origin": "https://" + host,
	}
	for k, v := range spec.Defaults {
		params[k] = v
	}

	if spec.HostSubdomain != nil {
		suf := strings.ToLower(spec.HostSubdomain.Suffix)
		if !strings.HasSuffix(host, suf) || len(host) <= len(suf) {
			return nil, false
		}
		sub := host[:len(host)-len(suf)]
		if spec.HostSubdomain.StripOptional2LetterRegion {
			if dotIdx := strings.LastIndexByte(sub, '.'); dotIdx > 0 && len(sub)-dotIdx-1 == 2 {
				sub = sub[:dotIdx]
			}
		}
		if !validateDeclarativeParam(sub, "alnum_dash", nil, spec.HostSubdomain.Reserved, 1, 80) {
			return nil, false
		}
		params[spec.HostSubdomain.Param] = sub
	}

	if spec.HostMap != nil {
		normH := host
		if spec.HostMap.StripWww {
			normH = strings.TrimPrefix(normH, "www.")
		}
		mapped := spec.HostMap.Exact[normH]
		if mapped == "" && spec.HostMap.SuffixSubdomain != "" {
			suf := strings.ToLower(spec.HostMap.SuffixSubdomain)
			if strings.HasSuffix(normH, suf) && len(normH) > len(suf) {
				sub := normH[:len(normH)-len(suf)]
				if validateDeclarativeParam(sub, "pkg", nil, nil, 1, 80) {
					mapped = sub
				}
			}
		}
		if mapped == "" {
			return nil, false
		}
		params[spec.HostMap.Param] = mapped
	}

	pathLower := strings.ToLower(u.Path)
	if spec.PathPrefix != "" && !strings.HasPrefix(pathLower, strings.ToLower(spec.PathPrefix)) {
		return nil, false
	}
	if spec.PathSuffix != "" && !strings.HasSuffix(pathLower, strings.ToLower(spec.PathSuffix)) {
		return nil, false
	}
	if len(spec.PathEquals) > 0 {
		eqHit := false
		for _, pe := range spec.PathEquals {
			if strings.EqualFold(u.Path, pe) {
				eqHit = true
				break
			}
		}
		if !eqHit {
			return nil, false
		}
	}
	if spec.ArcgisRestLayer && !isArcgisRestLayerPathGo(u.Path) {
		return nil, false
	}

	activeParts := rawParts
	if spec.OptionalLeadingLocale && len(activeParts) >= 2 && isLocaleSegmentGo(activeParts[0]) {
		activeParts = activeParts[1:]
	}

	if spec.MinSegments != nil && len(activeParts) < *spec.MinSegments {
		return nil, false
	}
	if spec.MaxSegments != nil && len(activeParts) > *spec.MaxSegments {
		return nil, false
	}

	if len(spec.ReservedFirstSegment) > 0 && len(activeParts) > 0 {
		dec0, err0 := url.PathUnescape(activeParts[0])
		if err0 != nil {
			dec0 = activeParts[0]
		}
		for _, r := range spec.ReservedFirstSegment {
			if strings.EqualFold(dec0, r) {
				return nil, false
			}
		}
	}

	if len(spec.ExcludeSegmentSuffixes) > 0 {
		for _, rp := range activeParts {
			dec, err := url.PathUnescape(rp)
			if err != nil {
				dec = rp
			}
			decLow := strings.ToLower(dec)
			for _, suf := range spec.ExcludeSegmentSuffixes {
				if strings.HasSuffix(decLow, strings.ToLower(suf)) {
					return nil, false
				}
			}
		}
	}

	if spec.AllSegmentsCharset != "" {
		if len(activeParts) == 0 {
			return nil, false
		}
		decodedAll := make([]string, len(activeParts))
		for i, rp := range activeParts {
			dec, err := url.PathUnescape(rp)
			if err != nil || !validateDeclarativeParam(dec, spec.AllSegmentsCharset, nil, nil, 1, 160) {
				return nil, false
			}
			decodedAll[i] = dec
		}
		params["joinedPath"] = strings.Join(decodedAll, "/")
	}

	if spec.PathContainsSegment != "" {
		foundSeg := false
		for _, rp := range activeParts {
			dec, err := url.PathUnescape(rp)
			if err == nil && strings.EqualFold(dec, spec.PathContainsSegment) {
				foundSeg = true
				break
			}
		}
		if !foundSeg {
			return nil, false
		}
	}

	if spec.SplitOnSegment != nil {
		sp := spec.SplitOnSegment
		delimIdx := -1
		for i, rp := range activeParts {
			dec, err := url.PathUnescape(rp)
			if err == nil && dec == sp.Delimiter {
				delimIdx = i
				break
			}
		}
		minLeft := sp.LeftMinSegs
		if minLeft <= 0 {
			minLeft = 1
		}
		if delimIdx < minLeft {
			return nil, false
		}
		leftParts := make([]string, delimIdx)
		for i := 0; i < delimIdx; i++ {
			dec, err := url.PathUnescape(activeParts[i])
			if err != nil || dec == "" {
				return nil, false
			}
			leftParts[i] = dec
		}
		leftVal := strings.Join(leftParts, "/")
		if !isValidSafeSubpath(leftVal) {
			return nil, false
		}
		params[sp.LeftParam] = leftVal

		rightStart := delimIdx + 1
		if sp.AfterLiteral != "" {
			if rightStart >= len(activeParts) {
				return nil, false
			}
			decLit, err := url.PathUnescape(activeParts[rightStart])
			if err != nil || decLit != sp.AfterLiteral {
				return nil, false
			}
			rightStart++
		}
		minTail := 1
		if sp.TailParam != "" {
			minTail = 2
		}
		if len(activeParts) < rightStart+minTail {
			return nil, false
		}
		if sp.RightParam != "" {
			rSegs := make([]string, 0, len(activeParts)-rightStart)
			for i := rightStart; i < len(activeParts); i++ {
				dec, err := url.PathUnescape(activeParts[i])
				if err != nil || dec == "" {
					return nil, false
				}
				rSegs = append(rSegs, dec)
			}
			rVal := strings.Join(rSegs, "/")
			if !isValidSafeSubpath(rVal) {
				return nil, false
			}
			params[sp.RightParam] = rVal
		}
		if sp.TailParam != "" {
			tSegs := make([]string, 0, len(activeParts)-rightStart-1)
			for i := rightStart + 1; i < len(activeParts); i++ {
				dec, err := url.PathUnescape(activeParts[i])
				if err != nil || dec == "" {
					return nil, false
				}
				tSegs = append(tSegs, dec)
			}
			tVal := strings.Join(tSegs, "/")
			if !isValidSafeSubpath(tVal) {
				return nil, false
			}
			params[sp.TailParam] = tVal
		}
	}

	if spec.ScanSegment != nil {
		sc := spec.ScanSegment
		var candRaw string
		hasCand := false
		if sc.LastOrBeforeLiteral != "" {
			if len(activeParts) == 0 {
				return nil, false
			}
			lastDec, _ := url.PathUnescape(activeParts[len(activeParts)-1])
			if strings.EqualFold(lastDec, sc.LastOrBeforeLiteral) {
				if len(activeParts) < 2 {
					return nil, false
				}
				candRaw = activeParts[len(activeParts)-2]
				hasCand = true
			} else {
				candRaw = activeParts[len(activeParts)-1]
				hasCand = true
			}
		} else if sc.AfterLiteral != "" {
			for i, rp := range activeParts {
				dec, err := url.PathUnescape(rp)
				if err == nil && strings.EqualFold(dec, sc.AfterLiteral) && i+1 < len(activeParts) {
					candRaw = activeParts[i+1]
					hasCand = true
					break
				}
			}
		} else {
			for _, rp := range activeParts {
				dec, err := url.PathUnescape(rp)
				if err == nil && validateDeclarativeParam(dec, sc.Charset, nil, nil, sc.MinLen, sc.MaxLen) {
					candRaw = rp
					hasCand = true
					break
				}
			}
		}
		if !hasCand {
			return nil, false
		}
		dec, err := url.PathUnescape(candRaw)
		if err != nil {
			return nil, false
		}
		if sc.StripPrefix != "" && len(dec) >= len(sc.StripPrefix) && strings.EqualFold(dec[:len(sc.StripPrefix)], sc.StripPrefix) {
			dec = dec[len(sc.StripPrefix):]
		}
		if sc.StripSuffix != "" && len(dec) >= len(sc.StripSuffix) && strings.EqualFold(dec[len(dec)-len(sc.StripSuffix):], sc.StripSuffix) {
			dec = dec[:len(dec)-len(sc.StripSuffix)]
		}
		if !validateDeclarativeParam(dec, sc.Charset, nil, nil, sc.MinLen, sc.MaxLen) {
			return nil, false
		}
		params[sc.Param] = applyParamTransformGo(dec, sc.Transform)
	}

	if spec.PathSegments != nil {
		minReq := 0
		for _, s := range spec.PathSegments {
			if s.IsLiteral || !s.ParamSpec.Optional {
				minReq++
			}
		}
		exact := true
		if spec.ExactSegments != nil {
			exact = *spec.ExactSegments
		}
		hasGreedy := len(spec.PathSegments) > 0 && !spec.PathSegments[len(spec.PathSegments)-1].IsLiteral && spec.PathSegments[len(spec.PathSegments)-1].ParamSpec.Greedy
		if hasGreedy {
			if len(activeParts) < minReq {
				return nil, false
			}
		} else if exact {
			if len(activeParts) < minReq || len(activeParts) > len(spec.PathSegments) {
				return nil, false
			}
		} else {
			if len(activeParts) < minReq {
				return nil, false
			}
		}

		for idx, seg := range spec.PathSegments {
			if idx >= len(activeParts) {
				if !seg.IsLiteral && seg.ParamSpec.Optional {
					continue
				}
				return nil, false
			}
			if seg.IsLiteral {
				decPart, err := url.PathUnescape(activeParts[idx])
				if err != nil || decPart != seg.Literal {
					return nil, false
				}
				continue
			}
			ps := seg.ParamSpec
			var candidate string
			if ps.Greedy && idx == len(spec.PathSegments)-1 {
				joinedEscaped := strings.Join(activeParts[idx:], "/")
				unesc, err := url.PathUnescape(joinedEscaped)
				if err != nil {
					return nil, false
				}
				candidate = unesc
			} else {
				unesc, err := url.PathUnescape(activeParts[idx])
				if err != nil {
					return nil, false
				}
				candidate = unesc
			}
			if ps.StripPrefix != "" && len(candidate) >= len(ps.StripPrefix) && strings.EqualFold(candidate[:len(ps.StripPrefix)], ps.StripPrefix) {
				candidate = candidate[len(ps.StripPrefix):]
			}
			if ps.StripSuffix != "" && len(candidate) >= len(ps.StripSuffix) && strings.EqualFold(candidate[len(candidate)-len(ps.StripSuffix):], ps.StripSuffix) {
				candidate = candidate[:len(candidate)-len(ps.StripSuffix)]
			}
			if !validateDeclarativeParam(candidate, ps.Charset, ps.AllowValues, ps.Reserved, ps.MinLen, ps.MaxLen) {
				return nil, false
			}
			params[ps.Param] = applyParamTransformGo(candidate, ps.Transform)
		}
	}

	if len(spec.QueryParams) > 0 {
		q := u.Query()
		for _, qp := range spec.QueryParams {
			keys := qp.Names
			if len(keys) == 0 && qp.Name != "" {
				keys = []string{qp.Name}
			}
			val := ""
			for _, k := range keys {
				if got := q.Get(k); got != "" {
					val = got
					break
				}
			}
			if val == "" {
				if qp.Optional {
					if qp.Default != "" {
						params[qp.Param] = qp.Default
					}
					continue
				}
				return nil, false
			}
			if !validateDeclarativeParam(val, qp.Charset, nil, nil, qp.MinLen, qp.MaxLen) {
				return nil, false
			}
			params[qp.Param] = applyParamTransformGo(val, qp.Transform)
		}
	}

	for dk, dv := range spec.DerivedParams {
		params[dk] = applyParamTransformGo(params[dv.FromParam], dv.Transform)
	}

	return params, true
}

func validateDeclarativeParam(val, charset string, allowValues, reserved []string, minLen, maxLen int) bool {
	if minLen <= 0 {
		minLen = 1
	}
	if maxLen <= 0 {
		maxLen = 160
	}
	if len(val) < minLen || len(val) > maxLen {
		return false
	}
	if len(allowValues) > 0 {
		matched := false
		for _, av := range allowValues {
			if val == av {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(reserved) > 0 {
		lower := strings.ToLower(val)
		for _, r := range reserved {
			if lower == strings.ToLower(r) {
				return false
			}
		}
	}
	cs := charset
	if cs == "" {
		cs = "pkg"
	}
	switch cs {
	case "alnum":
		for i := 0; i < len(val); i++ {
			if !isASCIIAlnum(val[i]) {
				return false
			}
		}
		return true
	case "digits":
		for i := 0; i < len(val); i++ {
			if val[i] < '0' || val[i] > '9' {
				return false
			}
		}
		return true
	case "alnum_dash", "slug":
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '_' && b != '-' {
				return false
			}
		}
		return true
	case "pkg":
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '_' && b != '-' && b != '.' {
				return false
			}
		}
		return val != "." && val != ".."
	case "model_slug", "url_seg":
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '_' && b != '-' && b != '.' && b != ':' && b != '~' {
				return false
			}
		}
		return val != "." && val != ".."
	case "npm_scope":
		if len(val) < 2 || val[0] != '@' {
			return false
		}
		return isValidNpmTokenGo(val[1:])
	case "npm_pkg":
		return isValidNpmTokenGo(val)
	case "at_handle":
		return len(val) >= 2 && val[0] == '@' && !strings.ContainsAny(val, "/ ")
	case "socrata_4x4":
		return isValidSocrata4x4Go(val)
	case "cve_id":
		return isValidCVEIDGo(val)
	case "openalex_work":
		if len(val) < 6 || len(val) > 16 || (val[0] != 'W' && val[0] != 'w') {
			return false
		}
		return validateDeclarativeParam(val[1:], "digits", nil, nil, 5, 15)
	case "pmc_id":
		if len(val) < 4 || !strings.EqualFold(val[:3], "pmc") {
			return false
		}
		return validateDeclarativeParam(val[3:], "digits", nil, nil, 1, 15)
	case "nct_id":
		if len(val) != 11 || !strings.EqualFold(val[:3], "nct") {
			return false
		}
		return validateDeclarativeParam(val[3:], "digits", nil, nil, 8, 8)
	case "arxiv_id":
		if len(val) < 4 || len(val) > 64 || strings.Contains(val, "..") {
			return false
		}
		for i := 0; i < len(val); i++ {
			b := val[i]
			if !isASCIIAlnum(b) && b != '.' && b != '_' && b != '-' && b != '/' {
				return false
			}
		}
		return true
	case "doi_rest":
		return isValidDOIRest(val)
	case "safe_subpath":
		return isValidSafeSubpath(val)
	default:
		return false
	}
}

func isValidNpmTokenGo(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if i == 0 && !isASCIIAlnum(b) && b != '-' && b != '~' {
			return false
		}
		if !isASCIIAlnum(b) && b != '-' && b != '.' && b != '_' && b != '~' {
			return false
		}
	}
	return true
}

func isValidSocrata4x4Go(val string) bool {
	if len(val) != 9 || val[4] != '-' {
		return false
	}
	hasDigit := false
	for i := 0; i < 9; i++ {
		if i == 4 {
			continue
		}
		c := val[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return hasDigit
}

func isValidCVEIDGo(val string) bool {
	if len(val) < 13 || !strings.EqualFold(val[:4], "cve-") || val[8] != '-' {
		return false
	}
	return validateDeclarativeParam(val[4:8], "digits", nil, nil, 4, 4) &&
		validateDeclarativeParam(val[9:], "digits", nil, nil, 4, 16)
}

func isASCIIAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isValidDOIRest(val string) bool {
	if !strings.HasPrefix(val, "10.") {
		return false
	}
	slashIdx := strings.IndexByte(val, '/')
	if slashIdx < 7 || slashIdx > 12 {
		return false
	}
	for i := 3; i < slashIdx; i++ {
		if val[i] < '0' || val[i] > '9' {
			return false
		}
	}
	suffix := val[slashIdx+1:]
	if len(suffix) == 0 {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		b := suffix[i]
		if b <= 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func isValidSafeSubpath(val string) bool {
	parts := strings.Split(val, "/")
	if len(parts) == 0 {
		return false
	}
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			b := seg[i]
			if b <= 0x20 || b >= 0x7f || b == '?' || b == '#' || b == '\\' {
				return false
			}
		}
	}
	return true
}

func encodeURIComponent(s string) string {
	const hexUpper = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if isASCIIAlnum(b) || b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexUpper[b>>4])
			sb.WriteByte(hexUpper[b&0x0f])
		}
	}
	return sb.String()
}

func encodeSafeSubpath(val string) string {
	parts := strings.Split(val, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		out = append(out, encodeURIComponent(p))
	}
	return strings.Join(out, "/")
}

func isIdentChar(b byte) bool {
	return isASCIIAlnum(b) || b == '_'
}

func expandTemplate(tmpl string, lookup func(string) string) string {
	if strings.IndexByte(tmpl, '{') < 0 {
		return tmpl
	}
	var sb strings.Builder
	sb.Grow(len(tmpl) + 16)
	n := len(tmpl)
	i := 0
	for i < n {
		if tmpl[i] != '{' {
			sb.WriteByte(tmpl[i])
			i++
			continue
		}
		j := i + 1
		for j < n && isIdentChar(tmpl[j]) {
			j++
		}
		if j > i+1 && j < n && tmpl[j] == '}' {
			sb.WriteString(lookup(tmpl[i+1 : j]))
			i = j + 1
		} else {
			sb.WriteByte('{')
			i++
		}
	}
	return sb.String()
}

// Format transforms a fetched JSON, XML, or text twin body into clean GitHub-Flavored Markdown and structured metadata.
// Returns `(nil, false)` on malformed, HTML soft-404, or schema-mismatched payloads so callers safely fall back to HTML scraping.
func (m *DeclarativeTwinMatch) Format(rawBody string) (*DeclarativeFormattedDoc, bool) {
	if m == nil {
		return nil, false
	}
	body := strings.TrimPrefix(rawBody, "\ufeff")
	ext := m.route.Extract
	var doc *DeclarativeFormattedDoc
	var ok bool
	if m.route.Twin.Kind == "text" || ext.TextMode != "" || ext.XML != nil || ext.IcimsPortal {
		doc, ok = m.formatTextTwin(body)
	} else {
		doc, ok = m.formatJSONTwin(body, ext)
	}
	if !ok || doc == nil {
		return nil, false
	}
	doc.Title = SanitizeScrapedMeta(doc.Title)
	doc.Description = SanitizeScrapedMeta(doc.Description)
	doc.Author = SanitizeScrapedMeta(doc.Author)
	doc.PublishedTime = SanitizeScrapedMeta(doc.PublishedTime)
	doc.Markdown = SanitizeScrapedMarkdown(doc.Markdown)
	return doc, strings.TrimSpace(doc.Markdown) != ""
}

func isLikelyHTMLSoft404(s string) bool {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed == "" {
		return true
	}
	prefix := trimmed
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	lower := strings.ToLower(prefix)
	return strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html")
}

func findLinearElementInnerGo(src, tagLower string, start int) (string, int, bool) {
	n := len(src)
	tLen := len(tagLower)
	pos := start
	for pos < n {
		rel := strings.IndexByte(src[pos:], '<')
		if rel < 0 {
			return "", -1, false
		}
		lt := pos + rel
		if lt+1+tLen >= n {
			return "", -1, false
		}
		match := true
		for k := 0; k < tLen; k++ {
			c := src[lt+1+k]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != tagLower[k] {
				match = false
				break
			}
		}
		after := lt + 1 + tLen
		if !match || (src[after] != '>' && src[after] != '/' && src[after] != ' ' && src[after] != '\t' && src[after] != '\n' && src[after] != '\r') {
			pos = lt + 1
			continue
		}
		gtRel := strings.IndexByte(src[after:], '>')
		if gtRel < 0 {
			return "", -1, false
		}
		openEnd := after + gtRel + 1
		if src[openEnd-2] == '/' {
			return "", openEnd, true
		}
		// Find close `</tagLower`
		cPos := openEnd
		for cPos < n {
			cRel := strings.Index(src[cPos:], "</")
			if cRel < 0 {
				return "", -1, false
			}
			cLt := cPos + cRel
			if cLt+2+tLen >= n {
				return "", -1, false
			}
			cMatch := true
			for k := 0; k < tLen; k++ {
				c := src[cLt+2+k]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				if c != tagLower[k] {
					cMatch = false
					break
				}
			}
			endName := cLt + 2 + tLen
			for endName < n && (src[endName] == ' ' || src[endName] == '\t' || src[endName] == '\r' || src[endName] == '\n') {
				endName++
			}
			if cMatch && endName < n && src[endName] == '>' {
				return src[openEnd:cLt], endName + 1, true
			}
			cPos = cLt + 2
		}
		return "", -1, false
	}
	return "", -1, false
}

func findAllLinearElementInnersGo(src, tagName string, maxItems int) []string {
	tagLower := strings.ToLower(tagName)
	var out []string
	pos := 0
	for pos < len(src) && len(out) < maxItems {
		inner, nextPos, ok := findLinearElementInnerGo(src, tagLower, pos)
		if !ok {
			break
		}
		out = append(out, inner)
		pos = nextPos
	}
	return out
}

func isSafePublicHTTPSFeedURL(raw string) bool {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "https://") || len(s) > 2048 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f || c == '(' || c == ')' || c == '[' || c == ']' || c == '<' || c == '>' || c == '"' || c == '\'' || c == '`' || c == '\\' {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := politeness.CanonicalHost(u.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return politeness.IsPublicIP(ip)
	}
	return strings.IndexByte(host, '.') > 0
}

func sortedMapKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func extractXMLTagTextGo(xmlSrc, tagName string) string {
	inner, _, ok := findLinearElementInnerGo(xmlSrc, strings.ToLower(tagName), 0)
	if !ok {
		return ""
	}
	trimmed := strings.TrimSpace(inner)
	if strings.HasPrefix(trimmed, "<![CDATA[") && strings.HasSuffix(trimmed, "]]>") {
		trimmed = strings.TrimSpace(trimmed[9 : len(trimmed)-3])
	}
	return stripTagsInlineLinear(trimmed)
}

func formatXMLTwinGo(rawXML string, xmlSpec *DeclarativeXMLSpec, params map[string]string) (*DeclarativeFormattedDoc, bool) {
	clean := stripInvisibleAndNUL(rawXML)
	if strings.TrimSpace(clean) == "" {
		return nil, false
	}
	if len(xmlSpec.RequireAnyTags) > 0 {
		head := clean
		if len(head) > 24000 {
			head = head[:24000]
		}
		headLow := strings.ToLower(head)
		anyHit := false
		for _, t := range xmlSpec.RequireAnyTags {
			if strings.Contains(headLow, "<"+strings.ToLower(t)) {
				anyHit = true
				break
			}
		}
		if !anyHit {
			return nil, false
		}
	}

	if xmlSpec.Mode == "jats_article" {
		title := extractXMLTagTextGo(clean, "article-title")
		if title == "" {
			return nil, false
		}
		abs := extractXMLTagTextGo(clean, "abstract")
		bodyInner, _, _ := findLinearElementInnerGo(clean, "body", 0)
		var bodyBlocks []string
		for _, sec := range findAllLinearElementInnersGo(bodyInner, "sec", 60) {
			secTitle := extractXMLTagTextGo(sec, "title")
			var paras []string
			for _, p := range findAllLinearElementInnersGo(sec, "p", 100) {
				pt := stripTagsInlineLinear(p)
				if pt != "" {
					paras = append(paras, pt)
				}
			}
			if len(paras) > 0 && len(bodyBlocks) < 30 {
				if secTitle != "" {
					bodyBlocks = append(bodyBlocks, "## "+secTitle+"\n\n"+strings.Join(paras, "\n\n"))
				} else {
					bodyBlocks = append(bodyBlocks, strings.Join(paras, "\n\n"))
				}
			}
		}
		sections := []string{"# " + title}
		if pmcid := params["pmcid"]; pmcid != "" {
			sections = append(sections, "- **PMCID**: `"+pmcid+"`")
		}
		if abs != "" {
			sections = append(sections, "## Abstract\n\n"+abs)
		}
		sections = append(sections, bodyBlocks...)
		return &DeclarativeFormattedDoc{
			Title:    title,
			Markdown: strings.Join(sections, "\n\n"),
		}, true
	}

	itemTag := xmlSpec.ItemTag
	if itemTag == "" {
		itemTag = "item"
	}
	blocks := findAllLinearElementInnersGo(clean, itemTag, 500)
	topVars := make(map[string]string, len(params)+4)
	for k, v := range params {
		topVars[k] = v
	}
	topVars["itemCount"] = strconv.Itoa(len(blocks))

	if xmlSpec.ChannelTitleFallbackParam != "" {
		head := clean
		if len(head) > 4000 {
			head = head[:4000]
		}
		if idx := indexFoldASCIIExtract(head, "<"+asciiLowerExtractString(itemTag)); idx >= 0 {
			head = head[:idx]
		}
		ct := extractXMLTagTextGo(head, "title")
		if ct == "" {
			ct = params[xmlSpec.ChannelTitleFallbackParam]
		}
		topVars["channelTitle"] = ct
	}
	if len(xmlSpec.FirstItemVars) > 0 && len(blocks) > 0 {
		for _, vn := range sortedMapKeys(xmlSpec.FirstItemVars) {
			tList := xmlSpec.FirstItemVars[vn]
			got := ""
			for _, tg := range tList {
				got = extractXMLTagTextGo(blocks[0], tg)
				if got != "" {
					break
				}
			}
			if got == "" {
				got = params["host"]
			}
			topVars[vn] = got
		}
	}

	tpl := xmlSpec.TitleTemplate
	if tpl == "" {
		tpl = "{host} ({itemCount})"
	}
	title := SanitizeScrapedMeta(strings.TrimSpace(expandTemplate(tpl, func(k string) string { return topVars[k] })))
	if title == "" {
		return nil, false
	}
	if len(blocks) == 0 {
		if xmlSpec.EmptyText == "" {
			return nil, false
		}
		return &DeclarativeFormattedDoc{
			Title:    title,
			Markdown: SanitizeScrapedMarkdown("# " + title + "\n\n" + xmlSpec.EmptyText),
		}, true
	}

	limit := xmlSpec.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if limit > len(blocks) {
		limit = len(blocks)
	}
	xmlItemVarKeys := sortedMapKeys(xmlSpec.ItemVars)
	var rows [][]string
	var links []string
	for _, b := range blocks[:limit] {
		rowVars := make(map[string]string, len(topVars)+len(xmlSpec.ItemVars))
		for k, v := range topVars {
			rowVars[k] = v
		}
		for _, ivName := range xmlItemVarKeys {
			ivSpec := xmlSpec.ItemVars[ivName]
			val := ""
			for _, tg := range ivSpec.Tags {
				val = extractXMLTagTextGo(b, tg)
				if val != "" {
					break
				}
			}
			if val != "" && ivSpec.SplitColonPart != nil {
				if cIdx := strings.IndexByte(val, ':'); cIdx > 0 {
					if *ivSpec.SplitColonPart == 0 {
						val = strings.TrimSpace(val[:cIdx])
					} else {
						val = strings.TrimSpace(val[cIdx+1:])
					}
				} else if *ivSpec.SplitColonPart == 0 {
					val = ivSpec.Default
				}
			}
			if ivSpec.SliceMax > 0 && val != "" {
				val = sliceRunesMax(val, ivSpec.SliceMax)
			}
			if val == "" {
				val = ivSpec.Default
			}
			rowVars[ivName] = val
		}
		if xmlSpec.RequireItemVar != "" && strings.TrimSpace(rowVars[xmlSpec.RequireItemVar]) == "" {
			continue
		}
		if xmlSpec.CollectLinkVar != "" {
			lv := strings.TrimSpace(rowVars[xmlSpec.CollectLinkVar])
			if isSafePublicHTTPSFeedURL(lv) {
				links = append(links, lv)
			}
		}
		row := make([]string, len(xmlSpec.Columns))
		for cIdx, c := range xmlSpec.Columns {
			cell := ""
			if strings.HasPrefix(c.Template, "[{") && strings.HasSuffix(c.Template, "})") {
				mid := strings.Index(c.Template, "}]({")
				if mid > 2 && strings.Index(c.Template[mid+4:], "}") == len(c.Template)-(mid+4)-2 {
					labelVar := c.Template[2:mid]
					urlVar := c.Template[mid+4 : len(c.Template)-2]
					lTxt := strings.TrimSpace(rowVars[labelVar])
					uTxt := strings.TrimSpace(rowVars[urlVar])
					if isSafePublicHTTPSFeedURL(uTxt) {
						cell = "[" + lTxt + "](" + uTxt + ")"
					} else {
						cell = lTxt
					}
				} else {
					cell = strings.TrimSpace(expandTemplate(c.Template, func(k string) string { return rowVars[k] }))
				}
			} else {
				cell = strings.TrimSpace(expandTemplate(c.Template, func(k string) string { return rowVars[k] }))
			}
			if cell == "" {
				cell = "-"
			}
			row[cIdx] = cell
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, false
	}
	headers := make([]string, len(xmlSpec.Columns))
	for i, c := range xmlSpec.Columns {
		headers[i] = c.Header
	}
	return &DeclarativeFormattedDoc{
		Title:    title,
		Markdown: SanitizeScrapedMarkdown("# " + title + "\n\n" + formatDeclarativeGFMTable(headers, rows)),
		Links:    links,
	}, true
}

func extractInertiaDataPageBytesGo(rawHTML string) ([]byte, bool) {
	idx := strings.Index(rawHTML, "data-page=")
	if idx < 0 {
		return nil, false
	}
	rest := rawHTML[idx+len("data-page="):]
	if len(rest) < 2 || (rest[0] != '"' && rest[0] != '\'') {
		return nil, false
	}
	q := rest[0]
	end := strings.IndexByte(rest[1:], q)
	if end < 0 {
		return nil, false
	}
	unesc := html.UnescapeString(rest[1 : 1+end])
	return []byte(unesc), true
}

func (m *DeclarativeTwinMatch) formatTextTwin(rawBody string) (*DeclarativeFormattedDoc, bool) {
	ext := m.route.Extract
	if ext.IcimsPortal {
		out := ExtractHTML(rawBody, ExtractOptions{BaseURL: m.origURL, OnlyMainContent: true})
		if strings.TrimSpace(out.Markdown) == "" {
			return nil, false
		}
		return &DeclarativeFormattedDoc{
			Title:    out.Title,
			Markdown: out.Markdown,
			Links:    out.Links,
		}, true
	}
	if ext.XML != nil {
		return formatXMLTwinGo(rawBody, ext.XML, m.params)
	}
	if ext.JSONSource == "inertia_data_page" {
		jsonBytes, ok := extractInertiaDataPageBytesGo(rawBody)
		if !ok {
			return nil, false
		}
		return m.formatJSONBytesTwin(jsonBytes, ext)
	}
	if isLikelyHTMLSoft404(rawBody) {
		return nil, false
	}
	fallbackTitle := strings.TrimSpace(expandTemplate(ext.TitleTemplate, func(k string) string { return m.params[k] }))
	cleanRaw := stripInvisibleAndNUL(rawBody)

	switch ext.TextMode {
	case "yaml_frontmatter_card":
		card := formatDeclarativeYAMLFrontmatterCard(cleanRaw, fallbackTitle)
		return card, card != nil && strings.TrimSpace(card.Markdown) != ""
	case "code_or_markdown_by_path":
		filePath := m.params[ext.PathParam]
		lang, isMd := detectDeclarativeFenceLang(filePath)
		if isMd {
			card := formatDeclarativeYAMLFrontmatterCard(cleanRaw, fallbackTitle)
			return card, card != nil && strings.TrimSpace(card.Markdown) != ""
		}
		return &DeclarativeFormattedDoc{
			Title:    fallbackTitle,
			Markdown: fmt.Sprintf("# %s\n\n%s", fallbackTitle, safeDeclarativeFence(cleanRaw, lang)),
		}, true
	default:
		trimmed := strings.TrimSpace(cleanRaw)
		if trimmed == "" {
			return nil, false
		}
		md := trimmed
		if fallbackTitle != "" && !strings.HasPrefix(trimmed, "# ") {
			md = "# " + fallbackTitle + "\n\n" + trimmed
		}
		return &DeclarativeFormattedDoc{
			Title:    fallbackTitle,
			Markdown: md,
		}, true
	}
}

func escapeCommerceTextGo(raw string, maxRunes int, unescapeEntities bool) string {
	if raw == "" {
		return ""
	}
	s := stripInvisibleAndNUL(raw)
	if unescapeEntities && strings.IndexByte(s, '&') >= 0 {
		s = html.UnescapeString(s)
		s = stripInvisibleAndNUL(s)
	}
	var flat strings.Builder
	flat.Grow(len(s))
	prevSpace := true
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' || r == 0x0085 || r == 0x2028 || r == 0x2029 || r == ' ' {
			if !prevSpace {
				flat.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		flat.WriteRune(r)
	}
	clean := strings.TrimSpace(flat.String())
	if clean == "" {
		return ""
	}
	if maxRunes > 0 {
		clean = strings.TrimSpace(sliceRunesMax(clean, maxRunes))
		if clean == "" {
			return ""
		}
	}

	var out strings.Builder
	out.Grow(len(clean) + 8)
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		switch c {
		case '<':
			out.WriteString("&lt;")
		case '[':
			out.WriteString(`\[`)
		case ']':
			out.WriteString(`\]`)
		case '`':
			out.WriteString("\\`")
		case '#':
			if i == 0 || clean[i-1] == ' ' {
				out.WriteString(`\#`)
			} else {
				out.WriteByte('#')
			}
		case '>':
			if i == 0 {
				out.WriteString(`\>`)
			} else {
				out.WriteByte('>')
			}
		case '-', '*', '+', '=':
			if i == 0 && (i+1 == len(clean) || clean[i+1] == ' ' || clean[i+1] == c) {
				out.WriteByte('\\')
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return escapeBareProtocolRelativeUrlsLinearGo(out.String())
}

func escapeCommerceDescriptionGo(rawHTML string, maxRunes int) string {
	if strings.TrimSpace(rawHTML) == "" {
		return ""
	}
	s := stripInvisibleAndNUL(rawHTML)
	if strings.IndexByte(s, '<') >= 0 && strings.IndexByte(s, '>') >= 0 {
		s = stripDangerousHTMLSubtreesGo(s)
	}
	plain := stripTagsInlineLinear(s)
	return escapeCommerceTextGo(plain, maxRunes, false)
}

func formatCommerceSKUSpanGo(raw string) string {
	if raw == "" {
		return "`-`"
	}
	s := stripInvisibleAndNUL(raw)
	var flat strings.Builder
	flat.Grow(len(s))
	prevSpace := true
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' || r == 0x0085 || r == 0x2028 || r == 0x2029 || r == ' ' {
			if !prevSpace {
				flat.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		flat.WriteRune(r)
	}
	clean := strings.TrimSpace(sliceRunesMax(flat.String(), 160))
	if clean == "" {
		return "`-`"
	}
	// Escape `<`, `[`, `]` without stripping any SKU characters (`|`, `` ` ``, `#`, `<`, `[`, `]` all preserved!).
	var esc strings.Builder
	esc.Grow(len(clean) + 4)
	maxTickRun := 0
	curTickRun := 0
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c == '`' {
			curTickRun++
			if curTickRun > maxTickRun {
				maxTickRun = curTickRun
			}
			esc.WriteByte('`')
			continue
		}
		curTickRun = 0
		switch c {
		case '<':
			esc.WriteString("&lt;")
		case '[':
			esc.WriteString(`\[`)
		case ']':
			esc.WriteString(`\]`)
		default:
			esc.WriteByte(c)
		}
	}
	body := esc.String()
	fence := strings.Repeat("`", maxTickRun+1)
	if body[0] == '`' || body[len(body)-1] == '`' || body[0] == ' ' || body[len(body)-1] == ' ' {
		return fence + " " + body + " " + fence
	}
	return fence + body + fence
}

func sanitizeCommerceDateGo(raw string) string {
	return escapeCommerceTextGo(raw, 64, false)
}

func normalizeSafePublicCommerceImageURLGo(raw string) string {
	s := strings.TrimSpace(stripInvisibleAndNUL(raw))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "//") {
		s = "https:" + s
	}
	if !isSafePublicTwinURL(s) || !isSafePublicHTTPSFeedURL(s) {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if IsPublicOrPrivateSuffix(h) {
		return ""
	}
	return s
}

func collectSafeCommerceImagesGo(rawImages any, maxImages int) []string {
	arr, isArr := rawImages.([]any)
	if !isArr || len(arr) == 0 {
		return nil
	}
	if maxImages <= 0 || maxImages > 50 {
		maxImages = 20
	}
	var out []string
	seen := make(map[string]bool)
	for _, item := range arr {
		var cand string
		switch tv := item.(type) {
		case string:
			cand = tv
		case map[string]any:
			cand = jsonScalarToString(tv["src"])
			if cand == "" {
				cand = jsonScalarToString(tv["url"])
			}
		}
		u := normalizeSafePublicCommerceImageURLGo(cand)
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
			if len(out) >= maxImages {
				break
			}
		}
	}
	return out
}

func formatCommerceTagsGo(rawTags any) string {
	var parts []string
	switch tv := rawTags.(type) {
	case string:
		for _, tok := range strings.Split(tv, ",") {
			if clean := escapeCommerceTextGo(tok, 120, false); clean != "" {
				parts = append(parts, clean)
				if len(parts) >= 30 {
					break
				}
			}
		}
	case []any:
		for _, el := range tv {
			var cand string
			if m, isM := el.(map[string]any); isM {
				cand = jsonScalarToString(m["name"])
			} else {
				cand = jsonScalarToString(el)
			}
			if clean := escapeCommerceTextGo(cand, 120, true); clean != "" {
				parts = append(parts, clean)
				if len(parts) >= 30 {
					break
				}
			}
		}
	}
	return strings.Join(parts, ", ")
}

func formatCommerceOptionsGo(rawOpts any) []string {
	arr, isArr := rawOpts.([]any)
	if !isArr || len(arr) == 0 {
		return nil
	}
	var lines []string
	for i, el := range arr {
		if i >= 20 {
			break
		}
		switch tv := el.(type) {
		case string:
			clean := escapeCommerceTextGo(tv, 120, false)
			if clean != "" && !strings.EqualFold(clean, "Title") {
				lines = append(lines, clean)
			}
		case map[string]any:
			name := escapeCommerceTextGo(jsonScalarToString(tv["name"]), 120, true)
			if name == "" {
				continue
			}
			var vals []string
			if vArr, okV := tv["values"].([]any); okV {
				for j, rv := range vArr {
					if j >= 30 {
						break
					}
					cv := escapeCommerceTextGo(jsonScalarToString(rv), 120, true)
					if cv != "" && !strings.EqualFold(cv, "Default Title") {
						vals = append(vals, cv)
					}
				}
			} else if tArr, okT := tv["terms"].([]any); okT {
				for j, rt := range tArr {
					if j >= 30 {
						break
					}
					if tm, isM := rt.(map[string]any); isM {
						cv := escapeCommerceTextGo(jsonScalarToString(tm["name"]), 120, true)
						if cv != "" {
							vals = append(vals, cv)
						}
					}
				}
			}
			if strings.EqualFold(name, "Title") && len(vals) == 0 {
				continue
			}
			if len(vals) > 0 {
				lines = append(lines, name+": "+strings.Join(vals, ", "))
			} else {
				lines = append(lines, name)
			}
		}
	}
	return lines
}

func safeCommerceHostLabelGo(origURL string) string {
	u, err := url.Parse(origURL)
	if err == nil && u != nil && u.Hostname() != "" {
		if h := escapeCommerceTextGo(strings.ToLower(u.Hostname()), 120, false); h != "" {
			return h
		}
	}
	return "store"
}

func formatCommerceTwinGo(rawBytes []byte, mode, origURL string) (*DeclarativeFormattedDoc, bool) {
	parsed, ok := decodeJSONWithNumbers(rawBytes)
	if !ok || parsed == nil {
		return nil, false
	}
	switch mode {
	case "shopify_product", "shopify_product_js":
		obj, isObj := parsed.(map[string]any)
		if !isObj {
			return nil, false
		}
		if sub, subOK := obj["product"].(map[string]any); subOK {
			obj = sub
		}
		title := escapeCommerceTextGo(jsonScalarToString(obj["title"]), 400, false)
		if title == "" {
			return nil, false
		}
		vendor := escapeCommerceTextGo(jsonScalarToString(obj["vendor"]), 200, false)
		prodTypeRaw := jsonScalarToString(obj["product_type"])
		if prodTypeRaw == "" {
			prodTypeRaw = jsonScalarToString(obj["type"])
		}
		prodType := escapeCommerceTextGo(prodTypeRaw, 200, false)
		tagsStr := formatCommerceTagsGo(obj["tags"])
		optSummaries := formatCommerceOptionsGo(obj["options"])
		pubDate := sanitizeCommerceDateGo(jsonScalarToString(obj["published_at"]))
		updDate := sanitizeCommerceDateGo(jsonScalarToString(obj["updated_at"]))
		safeImgs := collectSafeCommerceImagesGo(obj["images"], 20)

		bodyHTML := jsonScalarToString(obj["body_html"])
		if bodyHTML == "" {
			bodyHTML = jsonScalarToString(obj["description"])
		}
		desc := escapeCommerceDescriptionGo(bodyHTML, 4000)

		var rows [][]string
		if vars, isArr := obj["variants"].([]any); isArr {
			for i, rv := range vars {
				if i >= 60 {
					break
				}
				vo, okV := rv.(map[string]any)
				if !okV {
					continue
				}
				rawVT := strings.TrimSpace(jsonScalarToString(vo["title"]))
				vt := escapeCommerceTextGo(rawVT, 240, false)
				if vt == "" || strings.EqualFold(rawVT, "Default Title") || strings.EqualFold(vt, "Default Title") {
					vt = title
				}
				skuSpan := formatCommerceSKUSpanGo(jsonScalarToString(vo["sku"]))
				price := "-"
				if f, okP := jsonValueToFloat(vo["price"]); okP && f >= 0 {
					if mode == "shopify_product_js" {
						f = f / 100.0
					}
					price = fmt.Sprintf("$%.2f", f)
				}
				avail := "-"
				if b, isB := vo["available"].(bool); isB {
					if b {
						avail = "Available"
					} else {
						avail = "Out of Stock"
					}
				}
				rows = append(rows, []string{vt, skuSpan, price, avail})
			}
		}
		var bullets []string
		if vendor != "" {
			bullets = append(bullets, "- **Brand / Vendor**: "+vendor)
		}
		if prodType != "" {
			bullets = append(bullets, "- **Product Type**: "+prodType)
		}
		if tagsStr != "" {
			bullets = append(bullets, "- **Tags**: "+tagsStr)
		}
		if len(optSummaries) > 0 {
			bullets = append(bullets, "- **Options**: "+strings.Join(optSummaries, " · "))
		}
		if pubDate != "" {
			bullets = append(bullets, "- **Published**: "+pubDate)
		} else if updDate != "" {
			bullets = append(bullets, "- **Updated**: "+updDate)
		}
		if len(safeImgs) > 0 {
			bullets = append(bullets, "- **Primary Image**: "+safeImgs[0])
		}

		blocks := []string{"# " + title}
		if len(bullets) > 0 {
			blocks = append(blocks, strings.Join(bullets, "\n"))
		}
		if len(rows) > 0 {
			blocks = append(blocks, "## Variants & Pricing\n\n"+formatDeclarativeGFMTable([]string{"Variant", "SKU", "Price", "Availability"}, rows))
		}
		if desc != "" {
			blocks = append(blocks, "## Product Details\n\n"+desc)
		}
		return &DeclarativeFormattedDoc{
			Title:         title,
			Description:   sliceRunesMax(desc, 260),
			Author:        vendor,
			PublishedTime: pubDate,
			Markdown:      strings.Join(blocks, "\n\n"),
		}, true

	case "shopify_catalog_page":
		obj, isObj := parsed.(map[string]any)
		if !isObj {
			return nil, false
		}
		prods, isArr := obj["products"].([]any)
		if !isArr {
			return nil, false
		}
		host := safeCommerceHostLabelGo(origURL)
		title := fmt.Sprintf("%s — Shopify Catalog Inventory (%d products)", host, len(prods))
		var rows [][]string
		for i, rp := range prods {
			if i >= 120 {
				break
			}
			po, okP := rp.(map[string]any)
			if !okP {
				continue
			}
			pt := escapeCommerceTextGo(jsonScalarToString(po["title"]), 400, false)
			if pt == "" {
				continue
			}
			pv := escapeCommerceTextGo(jsonScalarToString(po["vendor"]), 200, false)
			pType := escapeCommerceTextGo(jsonScalarToString(po["product_type"]), 200, false)
			pUpd := sanitizeCommerceDateGo(sliceRunesMax(strings.TrimSpace(jsonScalarToString(po["updated_at"])), 10))
			if pUpd == "" {
				pUpd = "-"
			}
			rows = append(rows, []string{pt, pv, pType, pUpd})
		}
		tbl := "No products returned on this page."
		if len(rows) > 0 {
			tbl = formatDeclarativeGFMTable([]string{"Product", "Vendor", "Type", "Updated"}, rows)
		}
		return &DeclarativeFormattedDoc{Title: title, Markdown: "# " + title + "\n\n" + tbl}, true

	case "woocommerce_catalog_page":
		arr, isArr := parsed.([]any)
		if !isArr {
			return nil, false
		}
		host := safeCommerceHostLabelGo(origURL)
		title := fmt.Sprintf("%s — WooCommerce Catalog (%d products)", host, len(arr))
		var rows [][]string
		for i, rp := range arr {
			if i >= 120 {
				break
			}
			po, okP := rp.(map[string]any)
			if !okP {
				continue
			}
			pt := escapeCommerceTextGo(jsonScalarToString(po["name"]), 400, true)
			if pt == "" {
				continue
			}
			skuSpan := formatCommerceSKUSpanGo(jsonScalarToString(po["sku"]))
			rows = append(rows, []string{pt, skuSpan})
		}
		tbl := "No products returned on this page."
		if len(rows) > 0 {
			tbl = formatDeclarativeGFMTable([]string{"Product", "SKU"}, rows)
		}
		return &DeclarativeFormattedDoc{Title: title, Markdown: "# " + title + "\n\n" + tbl}, true

	case "woocommerce_product":
		po, isObj := parsed.(map[string]any)
		if !isObj {
			return nil, false
		}
		rawName := jsonScalarToString(po["name"])
		if rawName == "" {
			rawName = jsonScalarToString(po["title"])
		}
		title := escapeCommerceTextGo(rawName, 400, true)
		if title == "" {
			return nil, false
		}
		vendor := ""
		if brands, isB := po["brands"].([]any); isB && len(brands) > 0 {
			if bm, okB := brands[0].(map[string]any); okB {
				vendor = escapeCommerceTextGo(jsonScalarToString(bm["name"]), 200, true)
			}
		}
		catName := ""
		if cats, isC := po["categories"].([]any); isC && len(cats) > 0 {
			if cm, okC := cats[0].(map[string]any); okC {
				catName = escapeCommerceTextGo(jsonScalarToString(cm["name"]), 200, true)
			}
		}
		tagsStr := formatCommerceTagsGo(po["tags"])
		optSummaries := formatCommerceOptionsGo(po["attributes"])
		pubDate := sanitizeCommerceDateGo(jsonScalarToString(po["date_created"]))
		safeImgs := collectSafeCommerceImagesGo(po["images"], 20)
		topSKUSpan := formatCommerceSKUSpanGo(jsonScalarToString(po["sku"]))

		descRaw := jsonScalarToString(po["description"])
		if descRaw == "" {
			descRaw = jsonScalarToString(po["short_description"])
		}
		desc := escapeCommerceDescriptionGo(descRaw, 4000)

		var bullets []string
		if vendor != "" {
			bullets = append(bullets, "- **Brand / Vendor**: "+vendor)
		}
		if catName != "" {
			bullets = append(bullets, "- **Category**: "+catName)
		}
		if topSKUSpan != "`-`" {
			bullets = append(bullets, "- **SKU**: "+topSKUSpan)
		}
		if tagsStr != "" {
			bullets = append(bullets, "- **Tags**: "+tagsStr)
		}
		if len(optSummaries) > 0 {
			bullets = append(bullets, "- **Options**: "+strings.Join(optSummaries, " · "))
		}
		if pubDate != "" {
			bullets = append(bullets, "- **Published**: "+pubDate)
		}
		if len(safeImgs) > 0 {
			bullets = append(bullets, "- **Primary Image**: "+safeImgs[0])
		}

		var rows [][]string
		if vars, isV := po["variations"].([]any); isV && len(vars) > 0 {
			for i, rv := range vars {
				if i >= 60 {
					break
				}
				vo, okVO := rv.(map[string]any)
				if !okVO {
					continue
				}
				var attrVals []string
				if aArr, okA := vo["attributes"].([]any); okA {
					for _, ra := range aArr {
						if am, okAM := ra.(map[string]any); okAM {
							if av := escapeCommerceTextGo(jsonScalarToString(am["value"]), 120, true); av != "" {
								attrVals = append(attrVals, av)
							}
						}
					}
				}
				vt := title
				if len(attrVals) > 0 {
					vt = strings.Join(attrVals, " / ")
				}
				vSKU := jsonScalarToString(vo["sku"])
				skuCell := topSKUSpan
				if strings.TrimSpace(vSKU) != "" {
					skuCell = formatCommerceSKUSpanGo(vSKU)
				}
				stock := "-"
				if b, isB := vo["is_in_stock"].(bool); isB {
					if b {
						stock = "In Stock"
					} else {
						stock = "Out of Stock"
					}
				}
				rows = append(rows, []string{vt, skuCell, stock})
			}
		}

		blocks := []string{"# " + title}
		if len(bullets) > 0 {
			blocks = append(blocks, strings.Join(bullets, "\n"))
		}
		if len(rows) > 0 {
			blocks = append(blocks, "## Variants\n\n"+formatDeclarativeGFMTable([]string{"Variant", "SKU", "Stock"}, rows))
		}
		if desc != "" {
			blocks = append(blocks, "## Description\n\n"+desc)
		}
		return &DeclarativeFormattedDoc{
			Title:         title,
			Description:   sliceRunesMax(desc, 260),
			Author:        vendor,
			PublishedTime: pubDate,
			Markdown:      strings.Join(blocks, "\n\n"),
		}, true
	}
	return nil, false
}

func (m *DeclarativeTwinMatch) formatJSONTwin(rawBody string, ext DeclarativeExtractSpec) (*DeclarativeFormattedDoc, bool) {
	if ext.JSONSource == "inertia_data_page" {
		jb, ok := extractInertiaDataPageBytesGo(rawBody)
		if !ok {
			return nil, false
		}
		return m.formatJSONBytesTwin(jb, ext)
	}
	return m.formatJSONBytesTwin([]byte(rawBody), ext)
}

func (m *DeclarativeTwinMatch) formatJSONBytesTwin(rawBytes []byte, ext DeclarativeExtractSpec) (*DeclarativeFormattedDoc, bool) {
	if ext.CommerceMode != "" {
		return formatCommerceTwinGo(rawBytes, ext.CommerceMode, m.origURL)
	}
	parsed, ok := decodeJSONWithNumbers(rawBytes)
	if !ok || parsed == nil {
		return nil, false
	}
	rootVal := parsed
	unwrappedArray := false
	if ext.WrapRootArrayAs != "" {
		if arr, isArr := rootVal.([]any); isArr {
			rootVal = map[string]any{ext.WrapRootArrayAs: arr}
		}
	}
	if ext.UnwrapFirstArrayElement {
		if arr, isArr := rootVal.([]any); isArr {
			if len(arr) == 0 {
				return nil, false
			}
			rootVal = arr[0]
			unwrappedArray = true
		}
	}
	rootObj, isObj := rootVal.(map[string]any)
	if !isObj {
		return nil, false
	}
	if ext.RootPath != "" {
		sub, subOK := getByDotPath(rootObj, ext.RootPath).(map[string]any)
		if !subOK || sub == nil {
			return nil, false
		}
		rootObj = sub
	}
	if ext.RejectIfFieldTruthy != "" && isJSONTruthy(getByDotPath(rootObj, ext.RejectIfFieldTruthy)) {
		return nil, false
	}
	if ext.RequireFieldEquals != nil {
		if jsonScalarToString(getByDotPath(rootObj, ext.RequireFieldEquals.Path)) != ext.RequireFieldEquals.Value {
			return nil, false
		}
	}
	if ext.RequireArrayItemField != nil {
		arr, isArr := getByDotPath(rootObj, ext.RequireArrayItemField.ArrayPath).([]any)
		if !isArr {
			return nil, false
		}
		if len(arr) > 0 {
			firstObj, okO := arr[0].(map[string]any)
			if !okO || !isJSONTruthy(getByDotPath(firstObj, ext.RequireArrayItemField.Field)) {
				return nil, false
			}
		}
	}

	usedFindInArray := false
	if ext.FindInArray != nil {
		fia := ext.FindInArray
		arr, isArr := getByDotPath(rootObj, fia.ArrayPath).([]any)
		if !isArr {
			return nil, false
		}
		want := expandTemplate(fia.MatchTemplate, func(k string) string { return m.params[k] })
		if want == "" {
			if ext.FallbackExtract != nil {
				return m.formatJSONBytesTwin(rawBytes, *ext.FallbackExtract)
			}
			return nil, false
		}
		wantEnds := ""
		if fia.EndsWithTemplate != "" {
			wantEnds = expandTemplate(fia.EndsWithTemplate, func(k string) string { return m.params[k] })
		}
		mFields := fia.MatchFields
		if len(mFields) == 0 && fia.MatchField != "" {
			mFields = []string{fia.MatchField}
		}
		var matched map[string]any
		for _, item := range arr {
			obj, okObj := item.(map[string]any)
			if !okObj {
				continue
			}
			hit := false
			for _, mf := range mFields {
				got := jsonScalarToString(getByDotPath(obj, mf))
				if got != "" && ((fia.IgnoreCase && strings.EqualFold(got, want)) || (!fia.IgnoreCase && got == want)) {
					hit = true
					break
				}
			}
			if !hit && fia.EndsWithField != "" && wantEnds != "" {
				gotEnd := jsonScalarToString(getByDotPath(obj, fia.EndsWithField))
				if strings.HasSuffix(gotEnd, wantEnds) {
					hit = true
				}
			}
			if hit {
				matched = obj
				break
			}
		}
		if matched == nil {
			if ext.FallbackExtract != nil {
				return m.formatJSONBytesTwin(rawBytes, *ext.FallbackExtract)
			}
			return nil, false
		}
		rootObj = matched
		usedFindInArray = true
	}

	for _, reqField := range ext.RequireFields {
		v := getByDotPath(rootObj, reqField)
		switch tv := v.(type) {
		case string:
			if tv == "" {
				return nil, false
			}
		case json.Number, float64:
		default:
			return nil, false
		}
	}
	if len(ext.RequireAnyFields) > 0 {
		anyOK := false
		for _, f := range ext.RequireAnyFields {
			v := getByDotPath(rootObj, f)
			if arr, isA := v.([]any); isA {
				if len(arr) > 0 {
					anyOK = true
					break
				}
			} else if isJSONTruthy(v) {
				anyOK = true
				break
			}
		}
		if !anyOK {
			return nil, false
		}
	}

	resolved := make(map[string]string, len(ext.Vars))
	visiting := make(map[string]bool)

	var lookup func(string) string
	var evalVar func(DeclarativeVarSpec, map[string]any, func(string) string) string

	lookup = func(name string) string {
		if val, done := resolved[name]; done {
			return val
		}
		if spec, exists := ext.Vars[name]; exists {
			if visiting[name] {
				return ""
			}
			visiting[name] = true
			v := evalVar(spec, rootObj, lookup)
			delete(visiting, name)
			resolved[name] = v
			return v
		}
		return m.params[name]
	}

	orderedKeysFor := func(relPath string) []string {
		if !usedFindInArray && ext.WrapRootArrayAs == "" {
			var fullSegs []string
			if unwrappedArray {
				fullSegs = append(fullSegs, "0")
			}
			if ext.RootPath != "" {
				fullSegs = append(fullSegs, strings.Split(ext.RootPath, ".")...)
			}
			if relPath != "" {
				fullSegs = append(fullSegs, strings.Split(relPath, ".")...)
			}
			if keys := extractOrderedObjectKeys(rawBytes, fullSegs); len(keys) > 0 {
				return keys
			}
		}
		obj, okObj := getByDotPath(rootObj, relPath).(map[string]any)
		if !okObj {
			return nil
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}

	evalVar = func(spec DeclarativeVarSpec, activeObj map[string]any, varLookup func(string) string) string {
		var val string
		if spec.Template != "" {
			allPresent := true
			for _, w := range spec.WhenVars {
				if varLookup(w) == "" {
					allPresent = false
					break
				}
			}
			anyPresent := len(spec.WhenAnyVars) == 0
			for _, w := range spec.WhenAnyVars {
				if varLookup(w) != "" {
					anyPresent = true
					break
				}
			}
			if allPresent && anyPresent {
				val = expandTemplate(spec.Template, varLookup)
			} else if spec.FallbackVar != "" {
				val = varLookup(spec.FallbackVar)
			}
		} else if spec.Format == "bool_map" {
			truthy := false
			for _, p := range spec.Paths {
				raw := getByDotPath(activeObj, p)
				if s, isS := raw.(string); isS && strings.HasSuffix(p, "exports") {
					if strings.Contains(s, "types") {
						truthy = true
						break
					}
				} else if isJSONTruthy(raw) {
					truthy = true
					break
				}
			}
			if truthy {
				val = spec.TrueValue
			} else {
				val = spec.FalseValue
			}
		} else if spec.Format == "pubchem_toc" && spec.TocHeading != "" {
			val = lookupPubchemTocFieldGo(activeObj, spec.TocHeading, 0)
		} else if spec.NestedSubValues != nil {
			nsv := spec.NestedSubValues
			if outer, isA := getByDotPath(activeObj, nsv.ArrayPath).([]any); isA {
				excl := make(map[string]bool, len(nsv.ExcludeValues))
				for _, ev := range nsv.ExcludeValues {
					excl[ev] = true
				}
				seenV := make(map[string]bool)
				var collected []string
				maxLim := nsv.Limit
				if maxLim <= 0 {
					maxLim = 30
				}
				for i, w := range outer {
					if i >= 100 || len(collected) >= maxLim {
						break
					}
					wo, okW := w.(map[string]any)
					if !okW {
						continue
					}
					inner, isI := getByDotPath(wo, nsv.SubArrayField).([]any)
					if !isI {
						continue
					}
					for j, d := range inner {
						if j >= 50 || len(collected) >= maxLim {
							break
						}
						do, okD := d.(map[string]any)
						if !okD {
							continue
						}
						sv := strings.TrimSpace(jsonScalarToString(getByDotPath(do, nsv.ValueField)))
						if sv != "" && !excl[sv] && !seenV[sv] {
							seenV[sv] = true
							collected = append(collected, sv)
						}
					}
				}
				joinSep := nsv.Join
				if joinSep == "" {
					joinSep = ", "
				}
				val = strings.Join(collected, joinSep)
			}
		} else if spec.FindInArrayLang != nil {
			fl := spec.FindInArrayLang
			if arr, isA := getByDotPath(activeObj, fl.ArrayPath).([]any); isA {
				var fallback string
				for _, el := range arr {
					eo, okE := el.(map[string]any)
					if !okE {
						continue
					}
					vv := jsonScalarToString(eo[fl.ValueField])
					if vv != "" && fallback == "" {
						fallback = vv
					}
					if jsonScalarToString(eo[fl.LangField]) == fl.LangValue && vv != "" {
						val = vv
						break
					}
				}
				if val == "" {
					val = fallback
				}
			}
		} else if spec.DynamicKeyPath != nil {
			keyVal := varLookup(spec.DynamicKeyPath.KeyVar)
			if keyVal != "" {
				baseObj, okBase := getByDotPath(activeObj, spec.DynamicKeyPath.Base).(map[string]any)
				if okBase {
					entry := baseObj[keyVal]
					if spec.DynamicKeyPath.SubPath != "" {
						if entryObj, okEntry := entry.(map[string]any); okEntry {
							entry = getByDotPath(entryObj, spec.DynamicKeyPath.SubPath)
						} else {
							entry = nil
						}
					}
					val = formatExtractedJSONValue(entry, spec, m.origURL)
				}
			}
		} else {
			for _, p := range spec.Paths {
				raw := getByDotPath(activeObj, p)
				if raw == nil {
					continue
				}
				if spec.FirstNonMatchingKey != "" {
					keys := orderedKeysFor(p)
					for _, k := range keys {
						if !strings.Contains(k, spec.FirstNonMatchingKey) {
							val = k
							break
						}
					}
					if val == "" && len(keys) > 0 {
						val = keys[0]
					}
					if val != "" {
						break
					}
					continue
				}
				formatted := formatExtractedJSONValue(raw, spec, m.origURL)
				if spec.ExcludeEquals != "" && formatted == spec.ExcludeEquals {
					continue
				}
				if spec.EqualsVar != "" {
					wantEq := varLookup(spec.EqualsVar)
					if wantEq == "" || formatted != wantEq {
						continue
					}
				}
				if formatted != "" {
					val = formatted
					break
				}
			}
		}

		if val == "" {
			if spec.FallbackTemplate != "" {
				val = expandTemplate(spec.FallbackTemplate, varLookup)
			} else if spec.Default != "" {
				val = spec.Default
			}
		}
		if spec.StripPrefix != "" && strings.HasPrefix(val, spec.StripPrefix) {
			val = val[len(spec.StripPrefix):]
		}
		if spec.StripSuffix != "" && strings.HasSuffix(val, spec.StripSuffix) {
			val = val[:len(val)-len(spec.StripSuffix)]
		}
		if spec.ReplaceAll != nil && val != "" {
			val = strings.ReplaceAll(val, spec.ReplaceAll.From, spec.ReplaceAll.To)
		}
		if spec.StripFrontmatter && val != "" {
			val = stripLeadingYAMLFrontmatter(val)
		}
		if spec.Format != "" &&
			spec.Format != "bool_map" && spec.Format != "int_comma" &&
			spec.Format != "usd_compact" && spec.Format != "usd_per_million_tokens" &&
			spec.Format != "date_parts" && spec.Format != "array_len" &&
			spec.Format != "array_len_comma" && spec.Format != "object_keys" &&
			spec.Format != "epoch_sec_date" && spec.Format != "bytes_human" &&
			spec.Format != "inverted_abstract" && spec.Format != "gitlab_blob_html" &&
			spec.Format != "html_to_md" && spec.Format != "se_markdown" &&
			spec.Format != "fiscal_mmdd" && spec.Format != "pubchem_toc" {
			val = applyStringFormat(val, spec.Format)
		}
		if spec.Trim {
			val = strings.TrimSpace(val)
		}
		if spec.Upper {
			val = strings.ToUpper(val)
		}
		if spec.Lower {
			val = strings.ToLower(val)
		}
		val = stripInvisibleAndNUL(val)
		if spec.RequireHTTPS && !strings.HasPrefix(val, "https://") {
			val = ""
		}
		if spec.RequireHTTPPrefix && !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
			val = ""
		}
		if spec.SliceMax > 0 && val != "" {
			val = sliceRunesMax(val, spec.SliceMax)
		}
		return val
	}

	for _, name := range sortedMapKeys(ext.Vars) {
		_ = lookup(name)
	}
	for _, reqVar := range ext.RequireVars {
		if strings.TrimSpace(lookup(reqVar)) == "" {
			return nil, false
		}
	}

	title := ""
	if ext.TitleWhenVar != "" {
		if lookup(ext.TitleWhenVar) != "" {
			title = expandTemplate(ext.TitleTemplate, lookup)
		} else {
			title = expandTemplate(ext.TitleFallbackTemplate, lookup)
		}
	} else {
		title = expandTemplate(ext.TitleTemplate, lookup)
		if strings.TrimSpace(title) == "" && ext.TitleFallbackTemplate != "" {
			title = expandTemplate(ext.TitleFallbackTemplate, lookup)
		}
	}
	title = SanitizeScrapedMeta(title)
	if title == "" {
		return nil, false
	}

	if ext.CodeByPath != nil {
		plain := lookup(ext.CodeByPath.SourceVar)
		if strings.TrimSpace(plain) == "" {
			return nil, false
		}
		fp := m.params[ext.CodeByPath.PathParam]
		lang, isMd := detectDeclarativeFenceLang(fp)
		if isMd && ext.CodeByPath.RawIfMarkdown {
			return &DeclarativeFormattedDoc{Title: title, Markdown: strings.TrimSpace(plain)}, true
		}
		return &DeclarativeFormattedDoc{
			Title:    title,
			Markdown: fmt.Sprintf("# %s\n\n%s", title, safeDeclarativeFence(plain, lang)),
		}, true
	}

	var links []string
	seenLinks := make(map[string]bool)
	pushLink := func(uStr string) {
		clean := strings.TrimSpace(uStr)
		if strings.HasPrefix(clean, "https://") && !strings.ContainsAny(clean, " \t\r\n<>") && !seenLinks[clean] && len(links) < 2000 {
			seenLinks[clean] = true
			links = append(links, clean)
		}
	}

	var metaParts []string
	for _, ml := range ext.MetaLine {
		if ml.WhenVar != "" && lookup(ml.WhenVar) == "" {
			continue
		}
		if ml.UnlessVar != "" && lookup(ml.UnlessVar) != "" {
			continue
		}
		rendered := strings.TrimSpace(expandTemplate(ml.Template, lookup))
		if rendered != "" {
			if ml.Label != "" {
				metaParts = append(metaParts, fmt.Sprintf("**%s**: %s", ml.Label, rendered))
			} else {
				metaParts = append(metaParts, rendered)
			}
		}
	}

	var bulletLines []string
	for _, b := range ext.Bullets {
		if b.WhenVar != "" && lookup(b.WhenVar) == "" {
			continue
		}
		if b.UnlessVar != "" && lookup(b.UnlessVar) != "" {
			continue
		}
		rendered := strings.TrimSpace(expandTemplate(b.Template, lookup))
		if rendered != "" {
			if b.Label != "" {
				bulletLines = append(bulletLines, fmt.Sprintf("- **%s**: %s", b.Label, rendered))
			} else {
				bulletLines = append(bulletLines, "- "+rendered)
			}
		}
	}
	if ext.ObjectLinksPath != "" {
		if linksObj, okObj := getByDotPath(rootObj, ext.ObjectLinksPath).(map[string]any); okObj {
			ordered := orderedKeysFor(ext.ObjectLinksPath)
			if len(ordered) > 50 {
				ordered = ordered[:50]
			}
			for _, label := range ordered {
				href, isStr := linksObj[label].(string)
				if isStr && strings.HasPrefix(href, "https://") && !strings.ContainsAny(href, " \t\r\n<>") {
					bulletLines = append(bulletLines, fmt.Sprintf("- **%s**: %s", SanitizeScrapedMeta(label), href))
				}
			}
		}
	}

	blockquote := ""
	if ext.BlockquoteTemplate != "" && (ext.BlockquoteWhenVar == "" || lookup(ext.BlockquoteWhenVar) != "") {
		blockquote = strings.TrimSpace(expandTemplate(ext.BlockquoteTemplate, lookup))
	}
	footerItalic := ""
	if ext.FooterItalicTemplate != "" && (ext.FooterItalicWhenVar == "" || lookup(ext.FooterItalicWhenVar) != "") {
		footerItalic = strings.TrimSpace(expandTemplate(ext.FooterItalicTemplate, lookup))
	}
	intro := ""
	if ext.IntroVar != "" {
		intro = strings.TrimSpace(lookup(ext.IntroVar))
	}
	bodyText := ""
	if ext.BodyVar != "" {
		bodyText = strings.TrimSpace(lookup(ext.BodyVar))
	}

	var renderedSections []string
	for _, sec := range ext.Sections {
		if sec.WhenVar != "" && lookup(sec.WhenVar) == "" {
			continue
		}
		if sec.UnlessVar != "" && lookup(sec.UnlessVar) != "" {
			continue
		}
		resolveHeading := func(extra map[string]string) string {
			tpl := sec.HeadingTemplate
			if tpl == "" {
				tpl = sec.Heading
			}
			if tpl == "" {
				return ""
			}
			return SanitizeScrapedMeta(expandTemplate(tpl, func(k string) string {
				if v, okE := extra[k]; okE {
					return v
				}
				return lookup(k)
			}))
		}

		if sec.TextVar != "" {
			txt := strings.TrimSpace(lookup(sec.TextVar))
			if txt != "" {
				h := resolveHeading(nil)
				if h != "" {
					renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", h, txt))
				} else {
					renderedSections = append(renderedSections, txt)
				}
			}
			continue
		}

		if sec.TreeComments != nil {
			tc := sec.TreeComments
			topChildren, isA := getByDotPath(rootObj, tc.ChildrenPath).([]any)
			if !isA || len(topChildren) == 0 {
				continue
			}
			maxDepth := tc.MaxDepth
			if maxDepth <= 0 {
				maxDepth = 2
			}
			maxItems := tc.MaxItems
			if maxItems <= 0 || maxItems > 200 {
				maxItems = 60
			}
			var commentLines []string
			var walkComments func([]any, int)
			walkComments = func(nodes []any, depth int) {
				for _, rn := range nodes {
					if len(commentLines) >= maxItems {
						return
					}
					co, okC := rn.(map[string]any)
					if !okC {
						continue
					}
					cHTML := jsonScalarToString(getByDotPath(co, tc.HTMLTextPath))
					if strings.TrimSpace(cHTML) == "" {
						continue
					}
					cAuth := SanitizeScrapedMeta(jsonScalarToString(getByDotPath(co, tc.AuthorPath)))
					if cAuth == "" {
						cAuth = "user"
					}
					cTxt := stripTagsInlineLinear(cHTML)
					if cTxt != "" {
						indDepth := depth
						if indDepth > 4 {
							indDepth = 4
						}
						indent := strings.Repeat("  ", indDepth)
						commentLines = append(commentLines, fmt.Sprintf("%s- **%s**: %s", indent, cAuth, cTxt))
					}
					if depth < maxDepth {
						if sub, isSub := getByDotPath(co, tc.ChildrenPath).([]any); isSub {
							walkComments(sub, depth+1)
						}
					}
				}
			}
			walkComments(topChildren, 0)
			if len(commentLines) > 0 {
				h := resolveHeading(map[string]string{"topCount": strconv.Itoa(len(topChildren))})
				if h != "" {
					renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", h, strings.Join(commentLines, "\n")))
				} else {
					renderedSections = append(renderedSections, strings.Join(commentLines, "\n"))
				}
			}
			continue
		}

		// Gather array items
		var rawArr []map[string]any
		hasArray := false
		if sec.ParallelArrays != nil {
			pa := sec.ParallelArrays
			base := any(rootObj)
			if pa.BasePath != "" {
				base = getByDotPath(rootObj, pa.BasePath)
			}
			if baseMap, okB := base.(map[string]any); okB {
				hasArray = true
				colMap := make(map[string][]any, len(pa.Fields))
				maxLen := 0
				for alias, srcKey := range pa.Fields {
					if a, isA := getByDotPath(baseMap, srcKey).([]any); isA {
						colMap[alias] = a
						if len(a) > maxLen {
							maxLen = len(a)
						}
					}
				}
				if maxLen > 500 {
					maxLen = 500
				}
				allowSet := make(map[string]bool)
				if pa.PriorityFilterAfter != nil {
					for _, av := range pa.PriorityFilterAfter.AllowValues {
						allowSet[av] = true
					}
				}
				for i := 0; i < maxLen; i++ {
					rowObj := make(map[string]any, len(pa.Fields))
					for alias := range pa.Fields {
						if i < len(colMap[alias]) {
							rowObj[alias] = colMap[alias][i]
						}
					}
					if pa.PriorityFilterAfter != nil && len(rawArr) >= pa.PriorityFilterAfter.Index {
						if !allowSet[jsonScalarToString(rowObj[pa.PriorityFilterAfter.Field])] {
							continue
						}
					}
					rawArr = append(rawArr, rowObj)
					if sec.Limit > 0 && len(rawArr) >= sec.Limit {
						break
					}
				}
			}
		} else {
			arrSource := sec.ArrayPath
			if arrSource == "" {
				arrSource = sec.ListArrayPath
			}
			if arrSource == "" {
				arrSource = sec.SubsectionsArrayPath
			}
			if arrSource != "" {
				if got, isA := getByDotPath(rootObj, arrSource).([]any); isA {
					hasArray = true
					for _, el := range got {
						if obj, okO := el.(map[string]any); okO {
							rawArr = append(rawArr, obj)
						}
					}
				}
			}
		}
		if !hasArray {
			continue
		}

		// Filter
		if sec.Filter != nil {
			flt := sec.Filter
			filtered := rawArr[:0]
			for _, it := range rawArr {
				if flt.RequireField != "" {
					v := getByDotPath(it, flt.RequireField)
					if s, isS := v.(string); isS {
						if strings.TrimSpace(s) == "" {
							continue
						}
					} else if !isJSONTruthy(v) {
						continue
					}
				}
				if flt.ExcludeFieldPrefix != nil {
					if strings.HasPrefix(jsonScalarToString(getByDotPath(it, flt.ExcludeFieldPrefix.Field)), flt.ExcludeFieldPrefix.Prefix) {
						continue
					}
				}
				if flt.ExcludeFieldSuffixes != nil {
					sv := jsonScalarToString(getByDotPath(it, flt.ExcludeFieldSuffixes.Field))
					if sv == "" {
						continue
					}
					badSuf := false
					for _, sf := range flt.ExcludeFieldSuffixes.Suffixes {
						if strings.HasSuffix(sv, sf) {
							badSuf = true
							break
						}
					}
					if badSuf {
						continue
					}
				}
				filtered = append(filtered, it)
			}
			rawArr = filtered
			if flt.TagFilterParam != nil {
				tagVal := strings.ToLower(m.params[flt.TagFilterParam.Param])
				if tagVal != "" && !strings.EqualFold(tagVal, flt.TagFilterParam.SkipIfEquals) {
					var subF []map[string]any
					for _, it := range rawArr {
						if tArr, isT := getByDotPath(it, flt.TagFilterParam.TagsField).([]any); isT {
							for _, t := range tArr {
								if strings.Contains(strings.ToLower(jsonScalarToString(t)), tagVal) {
									subF = append(subF, it)
									break
								}
							}
						}
					}
					if len(subF) > 0 {
						rawArr = subF
					}
				}
			}
		}

		// DedupeBy
		if sec.DedupeBy != nil {
			dd := sec.DedupeBy
			type mergedEntry struct {
				item  map[string]any
				texts []string
				seen  map[string]bool
				flag  bool
			}
			var order []string
			byKey := make(map[string]*mergedEntry)
			for _, it := range rawArr {
				key := ""
				for _, kp := range dd.KeyPaths {
					key = strings.TrimSpace(jsonScalarToString(getByDotPath(it, kp)))
					if key != "" {
						break
					}
				}
				if key == "" {
					continue
				}
				locPiece := ""
				for _, mp := range dd.MergeTextPaths {
					if strings.Contains(mp, "+") {
						var subP []string
						for _, f := range strings.Split(mp, "+") {
							sv := strings.TrimSpace(jsonScalarToString(getByDotPath(it, strings.TrimSpace(f))))
							if sv != "" {
								subP = append(subP, sv)
							}
						}
						locPiece = strings.Join(subP, ", ")
					} else {
						locPiece = strings.TrimSpace(jsonScalarToString(getByDotPath(it, mp)))
					}
					if locPiece != "" {
						break
					}
				}
				boolHit := false
				for _, bp := range dd.OrBoolPaths {
					bv := getByDotPath(it, bp)
					if s, isS := bv.(string); isS {
						if strings.Contains(strings.ToLower(s), "remote") {
							boolHit = true
							break
						}
					} else if isJSONTruthy(bv) {
						boolHit = true
						break
					}
				}
				if ex, okE := byKey[key]; okE {
					if locPiece != "" && !ex.seen[locPiece] {
						ex.seen[locPiece] = true
						ex.texts = append(ex.texts, locPiece)
					}
					if boolHit {
						ex.flag = true
					}
				} else {
					clone := make(map[string]any, len(it)+2)
					for k, v := range it {
						clone[k] = v
					}
					ent := &mergedEntry{item: clone, seen: make(map[string]bool), flag: boolHit}
					if locPiece != "" {
						ent.seen[locPiece] = true
						ent.texts = append(ent.texts, locPiece)
					}
					byKey[key] = ent
					order = append(order, key)
				}
			}
			sep := dd.MergeSep
			if sep == "" {
				sep = "; "
			}
			mLim := dd.MergeLimit
			if mLim <= 0 {
				mLim = 4
			}
			deduped := make([]map[string]any, 0, len(order))
			for _, k := range order {
				ent := byKey[k]
				txts := ent.texts
				if len(txts) > mLim {
					txts = txts[:mLim]
				}
				if dd.MergeTargetVar != "" {
					ent.item[dd.MergeTargetVar] = strings.Join(txts, sep)
				}
				if dd.OrBoolTargetField != "" {
					ent.item[dd.OrBoolTargetField] = ent.flag
				}
				deduped = append(deduped, ent.item)
			}
			rawArr = deduped
		}

		// SortBy
		if sec.SortBy != nil {
			sb := sec.SortBy
			sort.SliceStable(rawArr, func(i, j int) bool {
				if sb.BoolDescField != "" {
					bi := isJSONTruthy(getByDotPath(rawArr[i], sb.BoolDescField))
					bj := isJSONTruthy(getByDotPath(rawArr[j], sb.BoolDescField))
					if bi != bj {
						return bi
					}
				}
				if sb.NumDescField != "" {
					ni, _ := jsonValueToFloat(getByDotPath(rawArr[i], sb.NumDescField))
					nj, _ := jsonValueToFloat(getByDotPath(rawArr[j], sb.NumDescField))
					return ni > nj
				}
				return false
			})
		}

		if sec.MinItems > 0 && len(rawArr) < sec.MinItems {
			continue
		}
		if strings.Contains(title, "{dedupCount}") {
			title = SanitizeScrapedMeta(strings.ReplaceAll(title, "{dedupCount}", strconv.Itoa(len(rawArr))))
		}

		if len(rawArr) == 0 {
			if sec.EmptyText != "" {
				h := resolveHeading(map[string]string{"count": "0"})
				if h != "" {
					renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", h, sec.EmptyText))
				} else {
					renderedSections = append(renderedSections, sec.EmptyText)
				}
			}
			continue
		}

		lim := sec.Limit
		if lim <= 0 || lim > 500 {
			lim = 500
		}
		if lim > len(rawArr) {
			lim = len(rawArr)
		}
		sliced := rawArr[:lim]

		secItemVarKeys := sortedMapKeys(sec.ItemVars)
		evalRowMap := func(itemObj map[string]any, idx int) map[string]string {
			itemMap := make(map[string]string, len(sec.ItemVars)+1)
			itemMap["index1"] = strconv.Itoa(idx + 1)
			rowVisiting := make(map[string]bool, len(sec.ItemVars))
			var rowLookup func(string) string
			rowLookup = func(k string) string {
				if v, has := itemMap[k]; has {
					return v
				}
				if ivSpec, isRowVar := sec.ItemVars[k]; isRowVar {
					if rowVisiting[k] {
						return ""
					}
					rowVisiting[k] = true
					v := evalVar(ivSpec, itemObj, rowLookup)
					delete(rowVisiting, k)
					itemMap[k] = v
					return v
				}
				return lookup(k)
			}
			for _, ivName := range secItemVarKeys {
				_ = rowLookup(ivName)
			}
			return itemMap
		}

		if len(sec.Columns) > 0 {
			headers := make([]string, len(sec.Columns))
			for i, col := range sec.Columns {
				headers[i] = col.Header
			}
			var rows [][]string
			for i, itemObj := range sliced {
				itemMap := evalRowMap(itemObj, i)
				if sec.RequireItemVar != "" && strings.TrimSpace(itemMap[sec.RequireItemVar]) == "" {
					continue
				}
				rowLookup := func(k string) string {
					if v, has := itemMap[k]; has {
						return v
					}
					return lookup(k)
				}
				for _, lv := range sec.CollectLinkVars {
					pushLink(itemMap[lv])
				}
				row := make([]string, len(sec.Columns))
				for cIdx, col := range sec.Columns {
					row[cIdx] = renderTableColumnCell(itemObj, col, rowLookup)
				}
				rows = append(rows, row)
			}
			if len(rows) > 0 {
				h := resolveHeading(map[string]string{"count": strconv.Itoa(len(rawArr)), "shownCount": strconv.Itoa(len(rows))})
				tbl := formatDeclarativeGFMTable(headers, rows)
				if h != "" {
					renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", h, tbl))
				} else {
					renderedSections = append(renderedSections, tbl)
				}
			}
			continue
		}

		if sec.SubsectionsArrayPath != "" {
			for i, itemObj := range sliced {
				itemMap := evalRowMap(itemObj, i)
				if sec.RequireItemVar != "" && strings.TrimSpace(itemMap[sec.RequireItemVar]) == "" {
					continue
				}
				rowLookup := func(k string) string {
					if v, has := itemMap[k]; has {
						return v
					}
					return lookup(k)
				}
				headTpl := sec.SubsectionHeadingTemplate
				if sec.SubsectionAltWhenVar != "" && rowLookup(sec.SubsectionAltWhenVar) != "" && sec.SubsectionAltHeadingTemplate != "" {
					headTpl = sec.SubsectionAltHeadingTemplate
				}
				subH := SanitizeScrapedMeta(expandTemplate(headTpl, rowLookup))
				if len(sec.SubsectionSubkeys) > 0 {
					var subLines []string
					if subH != "" {
						subLines = append(subLines, "## "+subH)
					}
					for _, sk := range sec.SubsectionSubkeys {
						rawV := itemObj[sk]
						txt := ""
						if a, isA := rawV.([]any); isA && len(a) > 0 {
							txt = strings.TrimSpace(jsonScalarToString(a[0]))
						} else if s, isS := rawV.(string); isS {
							txt = strings.TrimSpace(s)
						}
						if txt != "" {
							subLines = append(subLines, "### "+strings.ReplaceAll(sk, "_", " ")+"\n\n"+sliceRunesMax(txt, 1200))
						}
					}
					if len(subLines) > 1 {
						renderedSections = append(renderedSections, strings.Join(subLines, "\n\n"))
					}
				} else if sec.SubsectionBodyVar != "" {
					bodyVal := strings.TrimSpace(rowLookup(sec.SubsectionBodyVar))
					if bodyVal != "" {
						if subH != "" {
							renderedSections = append(renderedSections, fmt.Sprintf("## %s\n\n%s", subH, bodyVal))
						} else {
							renderedSections = append(renderedSections, bodyVal)
						}
					}
				}
			}
			continue
		}

		if sec.ItemTemplate != "" {
			maxInd := sec.MaxIndent
			if maxInd <= 0 {
				maxInd = 6
			}
			h := resolveHeading(map[string]string{"count": strconv.Itoa(len(rawArr))})
			var lines []string
			if h != "" {
				lines = append(lines, "## "+h)
			}
			for i, itemObj := range sliced {
				itemMap := evalRowMap(itemObj, i)
				if sec.RequireItemVar != "" && strings.TrimSpace(itemMap[sec.RequireItemVar]) == "" {
					continue
				}
				for _, lv := range sec.CollectLinkVars {
					pushLink(itemMap[lv])
				}
				depth := 0
				if sec.IndentField != "" {
					if n, okNum := jsonValueToFloat(getByDotPath(itemObj, sec.IndentField)); okNum {
						depth = int(n) + sec.IndentOffset
						if depth < 0 {
							depth = 0
						}
						if depth > maxInd {
							depth = maxInd
						}
					}
				}
				indent := strings.Repeat("  ", depth)
				if sec.RequireItemVar != "" {
					itemMap[sec.RequireItemVar] = collapseNewlinesWithIndent(itemMap[sec.RequireItemVar], indent+"  ")
				}
				rendered := expandTemplate(sec.ItemTemplate, func(k string) string {
					if v, has := itemMap[k]; has {
						return v
					}
					return lookup(k)
				})
				lines = append(lines, fmt.Sprintf("%s- %s", indent, rendered))
			}
			minLines := 1
			if h != "" {
				minLines = 2
			}
			if len(lines) >= minLines {
				renderedSections = append(renderedSections, strings.Join(lines, "\n"))
			}
		}
	}

	var blocks []string
	onlyBodyAlreadyTitled := bodyText != "" && strings.HasPrefix(bodyText, "# ") &&
		len(metaParts) == 0 && blockquote == "" && intro == "" && len(bulletLines) == 0 && len(renderedSections) == 0
	if !onlyBodyAlreadyTitled {
		blocks = append(blocks, "# "+title)
	}
	if len(metaParts) > 0 {
		joinedMeta := strings.Join(metaParts, " · ")
		if ext.MetaLineItalic {
			blocks = append(blocks, "*"+joinedMeta+"*")
		} else {
			blocks = append(blocks, joinedMeta)
		}
	}
	if blockquote != "" {
		blocks = append(blocks, blockquote)
	}
	if intro != "" {
		blocks = append(blocks, intro)
	}
	if len(bulletLines) > 0 {
		blocks = append(blocks, strings.Join(bulletLines, "\n"))
	}
	if bodyText != "" {
		blocks = append(blocks, bodyText)
	}
	if footerItalic != "" {
		blocks = append(blocks, "*"+footerItalic+"*")
	}
	blocks = append(blocks, renderedSections...)

	for _, lv := range ext.LinksVars {
		pushLink(lookup(lv))
	}
	for _, lt := range ext.LinkTemplates {
		pushLink(expandTemplate(lt, lookup))
	}

	doc := &DeclarativeFormattedDoc{
		Title:    title,
		Markdown: strings.Join(blocks, "\n\n"),
		Links:    links,
	}
	if ext.DescriptionTemplate != "" {
		doc.Description = expandTemplate(ext.DescriptionTemplate, lookup)
	} else if ext.DescriptionVar != "" {
		doc.Description = lookup(ext.DescriptionVar)
	}
	if ext.AuthorTemplate != "" {
		doc.Author = expandTemplate(ext.AuthorTemplate, lookup)
	} else if ext.AuthorVar != "" {
		doc.Author = lookup(ext.AuthorVar)
	}
	if ext.PublishedTimeVar != "" {
		doc.PublishedTime = lookup(ext.PublishedTimeVar)
	}
	return doc, true
}

func renderTableColumnCell(itemObj map[string]any, col DeclarativeTableColumn, lookup func(string) string) string {
	if col.Template != "" {
		rendered := stripInvisibleAndNUL(strings.TrimSpace(expandTemplate(col.Template, lookup)))
		if rendered == "" {
			return "-"
		}
		if col.Code {
			return "`" + rendered + "`"
		}
		return rendered
	}
	if col.Format == "paired_percent" {
		outcomes := parseJSONStringArrayField(itemObj[col.OutcomesField], col.DefaultOutcomes)
		prices := parseJSONFloatArrayField(itemObj[col.PricesField])
		parts := make([]string, 0, len(outcomes))
		for idx, o := range outcomes {
			if idx < len(prices) && !math.IsNaN(prices[idx]) && !math.IsInf(prices[idx], 0) {
				parts = append(parts, fmt.Sprintf("%s: %.1f%%", o, prices[idx]*100.0))
			} else {
				parts = append(parts, o)
			}
		}
		if len(parts) == 0 {
			return "-"
		}
		return strings.Join(parts, " · ")
	}

	val := ""
	for _, p := range col.Paths {
		raw := getByDotPath(itemObj, p)
		if raw == nil {
			continue
		}
		switch col.Format {
		case "usd_compact":
			val = formatUSDCompact(raw)
		case "int_comma":
			if f, ok := jsonValueToFloat(raw); ok {
				val = formatIntComma(int64(math.Round(f)))
			}
		case "bytes_human":
			val = formatBytesHumanGo(raw)
		case "strip_tags":
			val = stripTagsInlineLinear(jsonScalarToString(raw))
		default:
			val = strings.TrimSpace(jsonScalarToString(raw))
		}
		if val != "" {
			break
		}
	}
	if col.StripPrefix != "" && len(val) >= len(col.StripPrefix) && strings.EqualFold(val[:len(col.StripPrefix)], col.StripPrefix) {
		val = val[len(col.StripPrefix):]
	}
	if val == "" && col.FallbackVar != "" {
		val = strings.TrimSpace(lookup(col.FallbackVar))
	}
	val = stripInvisibleAndNUL(val)
	if col.SliceMax > 0 && val != "" {
		val = sliceRunesMax(val, col.SliceMax)
	}
	if val == "" {
		return "-"
	}
	if col.Code {
		return "`" + val + "`"
	}
	return val
}

func parseJSONStringArrayField(raw any, fallback []string) []string {
	var v = raw
	if s, isStr := raw.(string); isStr {
		if dec, ok := decodeJSONWithNumbers([]byte(s)); ok {
			v = dec
		}
	}
	if arr, isArr := v.([]any); isArr {
		capLen := len(arr)
		if capLen > 50 {
			capLen = 50
		}
		out := make([]string, 0, capLen)
		for _, el := range arr[:capLen] {
			out = append(out, jsonScalarToString(el))
		}
		return out
	}
	return append([]string(nil), fallback...)
}

func parseJSONFloatArrayField(raw any) []float64 {
	var v = raw
	if s, isStr := raw.(string); isStr {
		if dec, ok := decodeJSONWithNumbers([]byte(s)); ok {
			v = dec
		}
	}
	if arr, isArr := v.([]any); isArr {
		capLen := len(arr)
		if capLen > 50 {
			capLen = 50
		}
		out := make([]float64, capLen)
		for i, el := range arr[:capLen] {
			if f, ok := jsonValueToFloat(el); ok {
				out[i] = f
			} else {
				out[i] = math.NaN()
			}
		}
		return out
	}
	return nil
}

func formatBytesHumanGo(raw any) string {
	f, ok := jsonValueToFloat(raw)
	if !ok || f <= 0 {
		return "-"
	}
	if f > 1048576 {
		return fmt.Sprintf("%.1f MB", f/1048576.0)
	}
	return fmt.Sprintf("%d KB", int64(math.Round(f/1024.0)))
}

func reconstructInvertedAbstractGo(raw any) string {
	obj, isObj := raw.(map[string]any)
	if !isObj {
		return ""
	}
	words := make([]string, 10000)
	maxIdx := -1
	entries := 0
	for _, token := range sortedMapKeys(obj) {
		posAny := obj[token]
		entries++
		if entries > 5000 {
			break
		}
		arr, isA := posAny.([]any)
		if !isA {
			continue
		}
		for _, p := range arr {
			if pf, ok := jsonValueToFloat(p); ok {
				idx := int(pf)
				if idx >= 0 && idx < len(words) {
					words[idx] = token
					if idx > maxIdx {
						maxIdx = idx
					}
				}
			}
		}
	}
	if maxIdx < 0 {
		return ""
	}
	var nonEmpty []string
	for i := 0; i <= maxIdx; i++ {
		if words[i] != "" {
			nonEmpty = append(nonEmpty, words[i])
		}
	}
	return strings.TrimSpace(strings.Join(nonEmpty, " "))
}

func extractGitlabBlobPlainSourceGo(raw any) string {
	s, isS := raw.(string)
	if !isS || s == "" {
		return ""
	}
	preInner, _, ok := findLinearElementInnerGo(s, "pre", 0)
	if !ok {
		return ""
	}
	codeInner, _, okC := findLinearElementInnerGo(preInner, "code", 0)
	if !okC {
		codeInner = preInner
	}
	var sb strings.Builder
	sb.Grow(len(codeInner))
	i := 0
	n := len(codeInner)
	cachedGt := strings.IndexByte(codeInner, '>')
	for i < n {
		if codeInner[i] != '<' {
			sb.WriteByte(codeInner[i])
			i++
			continue
		}
		if cachedGt < i+1 {
			rel := strings.IndexByte(codeInner[i+1:], '>')
			if rel < 0 {
				sb.WriteString(codeInner[i:])
				break
			}
			cachedGt = i + 1 + rel
		}
		i = cachedGt + 1
	}
	plain := html.UnescapeString(strings.ReplaceAll(sb.String(), "&#x000A;", "\n"))
	plain = strings.TrimRight(strings.ReplaceAll(plain, "\r\n", "\n"), " \t\n")
	if strings.TrimSpace(plain) == "" {
		return ""
	}
	return plain
}

func cleanStackExchangeMarkdownGo(raw any) string {
	s, isS := raw.(string)
	if !isS || strings.TrimSpace(s) == "" {
		return ""
	}
	decoded := html.UnescapeString(strings.ReplaceAll(s, "\r\n", "\n"))
	lines := strings.Split(decoded, "\n")
	inFence := false
	for i, line := range lines {
		tr := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(tr, "```") || strings.HasPrefix(tr, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			continue
		}
		for _, tag := range []string{"<sub>", "</sub>", "<sup>", "</sup>", "<kbd>", "</kbd>"} {
			line = strings.ReplaceAll(line, tag, "")
		}
		lines[i] = line
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func lookupPubchemTocFieldGo(obj map[string]any, targetHeading string, depth int) string {
	if depth > 8 {
		return ""
	}
	secs, isA := obj["Section"].([]any)
	if !isA {
		return ""
	}
	for _, rs := range secs {
		so, okS := rs.(map[string]any)
		if !okS {
			continue
		}
		if jsonScalarToString(so["TOCHeading"]) == targetHeading {
			if infoArr, isI := so["Information"].([]any); isI && len(infoArr) > 0 {
				if ioObj, okIO := infoArr[0].(map[string]any); okIO {
					if valObj, okVO := ioObj["Value"].(map[string]any); okVO {
						if smArr, isSM := valObj["StringWithMarkup"].([]any); isSM && len(smArr) > 0 {
							if sm0, ok0 := smArr[0].(map[string]any); ok0 {
								if s := strings.TrimSpace(jsonScalarToString(sm0["String"])); s != "" {
									return s
								}
							}
						}
					}
				}
			}
		}
		if sub := lookupPubchemTocFieldGo(so, targetHeading, depth+1); sub != "" {
			return sub
		}
	}
	return ""
}

func formatExtractedJSONValue(raw any, spec DeclarativeVarSpec, origURL string) string {
	if raw == nil {
		return ""
	}
	switch spec.Format {
	case "int_comma":
		if f, ok := jsonValueToFloat(raw); ok {
			return formatIntComma(int64(math.Round(f)))
		}
		return ""
	case "usd_compact":
		return formatUSDCompact(raw)
	case "usd_per_million_tokens":
		return formatUSDPerMillionTokens(raw)
	case "date_parts":
		arr, isArr := raw.([]any)
		if !isArr || len(arr) == 0 {
			return ""
		}
		parts := make([]string, 0, len(arr))
		for idx, el := range arr {
			f, ok := jsonValueToFloat(el)
			if !ok {
				continue
			}
			n := int64(f)
			if idx == 0 {
				parts = append(parts, strconv.FormatInt(n, 10))
			} else {
				parts = append(parts, fmt.Sprintf("%02d", n))
			}
		}
		return strings.Join(parts, "-")
	case "array_len":
		if arr, isA := raw.([]any); isA {
			return strconv.Itoa(len(arr))
		}
		return ""
	case "array_len_comma":
		if arr, isA := raw.([]any); isA {
			return formatIntComma(int64(len(arr)))
		}
		return ""
	case "object_keys":
		obj, isO := raw.(map[string]any)
		if !isO || len(obj) == 0 {
			return ""
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if spec.Limit > 0 && len(keys) > spec.Limit {
			keys = keys[:spec.Limit]
		} else if len(keys) > 200 {
			keys = keys[:200]
		}
		if spec.ItemWrap != "" {
			for i, k := range keys {
				keys[i] = spec.ItemWrap + k + spec.ItemWrap
			}
		}
		sep := spec.Join
		if sep == "" {
			sep = ", "
		}
		return strings.Join(keys, sep)
	case "epoch_sec_date":
		if f, ok := jsonValueToFloat(raw); ok && f > 0 {
			return time.Unix(int64(f), 0).UTC().Format("2006-01-02")
		}
		return ""
	case "bytes_human":
		return formatBytesHumanGo(raw)
	case "inverted_abstract":
		return reconstructInvertedAbstractGo(raw)
	case "gitlab_blob_html":
		return extractGitlabBlobPlainSourceGo(raw)
	case "html_to_md":
		s, isS := raw.(string)
		if !isS || strings.TrimSpace(s) == "" {
			return ""
		}
		doc := ExtractHTML("<html><body>"+s+"</body></html>", ExtractOptions{BaseURL: origURL, OnlyMainContent: false})
		if strings.TrimSpace(doc.Markdown) != "" {
			return strings.TrimSpace(doc.Markdown)
		}
		return stripTagsInlineLinear(s)
	case "se_markdown":
		return cleanStackExchangeMarkdownGo(raw)
	case "fiscal_mmdd":
		s := strings.TrimSpace(jsonScalarToString(raw))
		if len(s) == 4 {
			return s[:2] + "/" + s[2:]
		}
		return ""
	}

	if arr, isArr := raw.([]any); isArr {
		lim := spec.Limit
		if lim <= 0 || lim > 500 {
			lim = 500
		}
		if lim > len(arr) {
			lim = len(arr)
		}
		var items []string
		for _, el := range arr[:lim] {
			itemStr := ""
			if spec.SubFieldsJoin != nil {
				if obj, okObj := el.(map[string]any); okObj {
					var subParts []string
					for _, sf := range spec.SubFieldsJoin.Fields {
						if sv, isS := obj[sf].(string); isS && sv != "" {
							subParts = append(subParts, sv)
						}
					}
					if len(subParts) > 0 {
						itemStr = strings.Join(subParts, spec.SubFieldsJoin.Sep)
					} else if spec.SubFieldsJoin.FallbackField != "" {
						itemStr = jsonScalarToString(obj[spec.SubFieldsJoin.FallbackField])
					}
				}
			} else if spec.SubField != "" {
				if obj, okObj := el.(map[string]any); okObj {
					itemStr = jsonScalarToString(getByDotPath(obj, spec.SubField))
				}
			} else {
				itemStr = jsonScalarToString(el)
			}
			if itemStr != "" {
				if spec.ItemWrap != "" {
					itemStr = spec.ItemWrap + itemStr + spec.ItemWrap
				}
				items = append(items, itemStr)
			}
		}
		if len(items) == 0 {
			return ""
		}
		if spec.Join != "" {
			return strings.Join(items, spec.Join)
		}
		return items[0]
	}

	return jsonScalarToString(raw)
}

func decodeJSONWithNumbers(raw []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func extractOrderedObjectKeys(raw []byte, pathSegs []string) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	keys, _ := walkOrderedJSONKeys(dec, pathSegs)
	if len(keys) > 500 {
		keys = keys[:500]
	}
	return keys
}

func walkOrderedJSONKeys(dec *json.Decoder, segs []string) ([]string, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil, nil
	}
	if len(segs) == 0 {
		if delim != '{' {
			return nil, skipJSONCompositeRest(dec, delim)
		}
		var keys []string
		for dec.More() {
			kt, kErr := dec.Token()
			if kErr != nil {
				return keys, kErr
			}
			if ks, ok := kt.(string); ok {
				keys = append(keys, ks)
			}
			if err := skipJSONValue(dec); err != nil {
				return keys, err
			}
		}
		_, _ = dec.Token()
		return keys, nil
	}

	head := segs[0]
	switch delim {
	case '{':
		var found []string
		for dec.More() {
			kt, kErr := dec.Token()
			if kErr != nil {
				return nil, kErr
			}
			ks, _ := kt.(string)
			if ks == head && found == nil {
				res, rErr := walkOrderedJSONKeys(dec, segs[1:])
				if rErr != nil {
					return res, rErr
				}
				found = res
			} else {
				if err := skipJSONValue(dec); err != nil {
					return nil, err
				}
			}
		}
		_, _ = dec.Token()
		return found, nil
	case '[':
		wantIdx, convErr := strconv.Atoi(head)
		if convErr != nil || wantIdx < 0 {
			return nil, skipJSONCompositeRest(dec, '[')
		}
		idx := 0
		var found []string
		for dec.More() {
			if idx == wantIdx {
				res, rErr := walkOrderedJSONKeys(dec, segs[1:])
				if rErr != nil {
					return res, rErr
				}
				found = res
			} else {
				if err := skipJSONValue(dec); err != nil {
					return nil, err
				}
			}
			idx++
		}
		_, _ = dec.Token()
		return found, nil
	}
	return nil, nil
}

func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, isDelim := tok.(json.Delim); isDelim {
		return skipJSONCompositeRest(dec, delim)
	}
	return nil
}

func skipJSONCompositeRest(dec *json.Decoder, open json.Delim) error {
	depth := 1
	_ = open
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			if d == '{' || d == '[' {
				depth++
			} else if d == '}' || d == ']' {
				depth--
			}
		}
	}
	return nil
}

func getByDotPath(root any, dotPath string) any {
	if dotPath == "" || root == nil {
		return root
	}
	cur := root
	for _, seg := range strings.Split(dotPath, ".") {
		if cur == nil {
			return nil
		}
		switch typed := cur.(type) {
		case map[string]any:
			cur = typed[seg]
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(typed) {
				return nil
			}
			cur = typed[idx]
		default:
			return nil
		}
	}
	return cur
}

func jsonScalarToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func jsonValueToFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case float64:
		return t, !math.IsNaN(t) && !math.IsInf(t, 0)
	case string:
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(trimmed, 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

func isJSONTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0 && !math.IsNaN(f)
	case float64:
		return t != 0 && !math.IsNaN(t)
	default:
		return true
	}
}

func formatIntComma(n int64) string {
	neg := n < 0
	if neg {
		if n == math.MinInt64 {
			return strconv.FormatInt(n, 10)
		}
		n = -n
	}
	raw := strconv.FormatInt(n, 10)
	if len(raw) <= 3 {
		if neg {
			return "-" + raw
		}
		return raw
	}
	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	rem := len(raw) % 3
	if rem > 0 {
		sb.WriteString(raw[:rem])
		if len(raw) > rem {
			sb.WriteByte(',')
		}
	}
	for i := rem; i < len(raw); i += 3 {
		if i > rem {
			sb.WriteByte(',')
		}
		sb.WriteString(raw[i : i+3])
	}
	return sb.String()
}

func formatUSDCompact(v any) string {
	num, ok := jsonValueToFloat(v)
	if !ok {
		return ""
	}
	abs := math.Abs(num)
	sign := ""
	if num < 0 {
		sign = "-"
	}
	if abs >= 1e9 {
		return fmt.Sprintf("%s$%.2fB", sign, abs/1e9)
	}
	if abs >= 1e6 {
		return fmt.Sprintf("%s$%.2fM", sign, abs/1e6)
	}
	if abs >= 1e3 {
		return fmt.Sprintf("%s$%s", sign, formatIntComma(int64(math.Round(abs))))
	}
	return fmt.Sprintf("%s$%.2f", sign, abs)
}

func formatUSDPerMillionTokens(v any) string {
	num, ok := jsonValueToFloat(v)
	if !ok || num < 0 {
		return ""
	}
	if num == 0 {
		return "$0.00 / 1M tokens"
	}
	return fmt.Sprintf("$%.2f / 1M tokens", num*1_000_000.0)
}

func stripLeadingMarkdownH1Go(md string) string {
	norm := strings.ReplaceAll(md, "\r\n", "\n")
	if !strings.HasPrefix(norm, "# ") {
		return md
	}
	nl := strings.IndexByte(norm, '\n')
	if nl < 0 {
		return md
	}
	trimmed := strings.TrimSpace(norm[nl+1:])
	if trimmed == "" {
		return md
	}
	return trimmed
}

func applyStringFormat(s, format string) string {
	switch format {
	case "trim":
		return strings.TrimSpace(s)
	case "strip_tags":
		return stripTagsInlineLinear(s)
	case "strip_leading_h1":
		return stripLeadingMarkdownH1Go(s)
	case "jats_abstract":
		cleaned := stripTagsInlineLinear(s)
		if len(cleaned) >= 9 && strings.EqualFold(cleaned[:8], "abstract") && (cleaned[8] == ' ' || cleaned[8] == '\t') {
			cleaned = strings.TrimSpace(cleaned[9:])
		}
		return cleaned
	default:
		return s
	}
}

func stripLeadingYAMLFrontmatter(s string) string {
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.HasPrefix(norm, "---") {
		return s
	}
	searchCap := len(norm)
	if searchCap > 1510 {
		searchCap = 1510
	}
	window := norm[:searchCap]
	closeIdx := strings.Index(window[3:], "\n---")
	if closeIdx < 0 {
		return s
	}
	afterDash := 3 + closeIdx + 4
	if afterDash >= len(norm) || norm[afterDash] != '\n' {
		return s
	}
	for afterDash < len(norm) && norm[afterDash] == '\n' {
		afterDash++
	}
	return norm[afterDash:]
}

func collapseNewlinesWithIndent(s, indent string) string {
	var out strings.Builder
	out.Grow(len(s) + 8)
	prevNL := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' {
			continue
		}
		if s[i] == '\n' {
			if !prevNL {
				out.WriteByte('\n')
				out.WriteString(indent)
				prevNL = true
			}
			continue
		}
		prevNL = false
		out.WriteByte(s[i])
	}
	return out.String()
}

func sliceRunesMax(s string, maxUnits int) string {
	if maxUnits <= 0 || len(s) <= maxUnits {
		return s
	}
	units := 0
	for byteIdx := 0; byteIdx < len(s); {
		r, width := utf8.DecodeRuneInString(s[byteIdx:])
		uLen := 1
		if r > 0xFFFF {
			uLen = 2
		}
		if units+uLen > maxUnits {
			return s[:byteIdx]
		}
		units += uLen
		byteIdx += width
	}
	return s
}

func escapeDeclarativeGFMCell(val string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 180
	}
	clean := strings.ReplaceAll(val, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "|", "\\|")
	clean = strings.Join(strings.Fields(clean), " ")
	if clean == "" {
		return "-"
	}
	if utf8.RuneCountInString(clean) > maxLen {
		return sliceRunesMax(clean, maxLen-1) + "…"
	}
	return clean
}

func formatDeclarativeGFMTable(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return ""
	}
	headCells := make([]string, len(headers))
	sepCells := make([]string, len(headers))
	for i, h := range headers {
		headCells[i] = escapeDeclarativeGFMCell(h, 80)
		sepCells[i] = "---"
	}
	lines := make([]string, 0, len(rows)+2)
	lines = append(lines, "| "+strings.Join(headCells, " | ")+" |")
	lines = append(lines, "| "+strings.Join(sepCells, " | ")+" |")
	for _, r := range rows {
		cells := make([]string, len(headers))
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			cells[i] = escapeDeclarativeGFMCell(v, 180)
		}
		lines = append(lines, "| "+strings.Join(cells, " | ")+" |")
	}
	return strings.Join(lines, "\n")
}

func safeDeclarativeFence(code, lang string) string {
	maxTicks := 2
	run := 0
	for i := 0; i < len(code); i++ {
		if code[i] == '`' {
			run++
			if run > maxTicks {
				maxTicks = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", maxTicks+1)
	norm := strings.TrimRight(strings.ReplaceAll(code, "\r\n", "\n"), " \t\n")
	return fence + lang + "\n" + norm + "\n" + fence
}

var declarativeCodeFenceMap = map[string]string{
	"ts": "ts", "tsx": "tsx", "js": "js", "jsx": "jsx", "mjs": "js", "cjs": "js",
	"py": "python", "go": "go", "rs": "rust", "rb": "ruby", "java": "java", "kt": "kotlin",
	"swift": "swift", "c": "c", "h": "c", "cpp": "cpp", "hpp": "cpp", "cs": "csharp",
	"php": "php", "sh": "bash", "bash": "bash", "zsh": "zsh", "ps1": "powershell",
	"yaml": "yaml", "yml": "yaml", "toml": "toml", "json": "json", "sql": "sql",
	"graphql": "graphql", "proto": "protobuf", "tf": "hcl", "hcl": "hcl", "nix": "nix",
	"zig": "zig", "lua": "lua", "ex": "elixir", "exs": "elixir", "erl": "erlang",
	"css": "css", "scss": "scss", "html": "html", "xml": "xml",
}

func detectDeclarativeFenceLang(filePath string) (string, bool) {
	base := filePath
	if idx := strings.LastIndexByte(filePath, '/'); idx >= 0 {
		base = filePath[idx+1:]
	}
	lower := strings.ToLower(base)
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return "dockerfile", false
	}
	if lower == "makefile" || lower == "gnumakefile" {
		return "makefile", false
	}
	dot := strings.LastIndexByte(lower, '.')
	if dot < 0 || dot == len(lower)-1 {
		return "", false
	}
	ext := lower[dot+1:]
	if ext == "md" || ext == "mdx" || ext == "markdown" {
		return "markdown", true
	}
	if mapped, ok := declarativeCodeFenceMap[ext]; ok {
		return mapped, false
	}
	return ext, false
}

func firstMarkdownH1(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "# ") {
			h := strings.TrimSpace(line[2:])
			if h != "" {
				return h
			}
		}
	}
	return ""
}

func formatDeclarativeYAMLFrontmatterCard(rawMd, fallbackTitle string) *DeclarativeFormattedDoc {
	norm := strings.ReplaceAll(rawMd, "\r\n", "\n")
	if !strings.HasPrefix(norm, "---\n") {
		title := firstMarkdownH1(norm)
		if title == "" {
			title = fallbackTitle
		}
		trimmed := strings.TrimSpace(norm)
		md := trimmed
		if !strings.HasPrefix(trimmed, "# ") {
			md = "# " + title + "\n\n" + trimmed
		}
		return &DeclarativeFormattedDoc{Title: title, Markdown: md}
	}

	windowEnd := len(norm)
	if windowEnd > 8012 {
		windowEnd = 8012
	}
	closeRel := strings.Index(norm[4:windowEnd], "\n---\n")
	if closeRel < 0 {
		title := firstMarkdownH1(norm)
		if title == "" {
			title = fallbackTitle
		}
		trimmed := strings.TrimSpace(norm)
		md := trimmed
		if !strings.HasPrefix(trimmed, "# ") {
			md = "# " + title + "\n\n" + trimmed
		}
		return &DeclarativeFormattedDoc{Title: title, Markdown: md}
	}

	yamlBlock := norm[4 : 4+closeRel]
	afterFM := 4 + closeRel + 5
	for afterFM < len(norm) && norm[afterFM] == '\n' {
		afterFM++
	}
	body := strings.TrimSpace(norm[afterFM:])

	type kvPair struct{ k, v string }
	var kvPairs []kvPair
	currentKey := ""
	var listItems []string
	flushList := func() {
		if currentKey != "" && len(listItems) > 0 {
			capLen := len(listItems)
			if capLen > 12 {
				capLen = 12
			}
			kvPairs = append(kvPairs, kvPair{k: currentKey, v: strings.Join(listItems[:capLen], ", ")})
		}
		currentKey = ""
		listItems = nil
	}

	for _, line := range strings.Split(yamlBlock, "\n") {
		trimLeft := strings.TrimLeft(line, " \t")
		if currentKey != "" && strings.HasPrefix(trimLeft, "- ") {
			item := strings.TrimSpace(trimLeft[2:])
			item = strings.Trim(item, `"'`)
			item = strings.TrimSpace(item)
			if item != "" && !strings.Contains(item, ":") && len(listItems) < 16 {
				listItems = append(listItems, item)
			}
			continue
		}
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx > 0 {
			keyCand := line[:colonIdx]
			validKey := true
			for i := 0; i < len(keyCand); i++ {
				b := keyCand[i]
				if !isASCIIAlnum(b) && b != '_' && b != '-' {
					validKey = false
					break
				}
			}
			if validKey {
				flushList()
				val := strings.TrimSpace(line[colonIdx+1:])
				val = strings.Trim(val, `"'`)
				val = strings.TrimSpace(val)
				if val == "" {
					currentKey = keyCand
				} else if len(val) <= 140 && !strings.HasPrefix(val, "{") {
					kvPairs = append(kvPairs, kvPair{k: keyCand, v: val})
				}
			}
		}
	}
	flushList()

	title := firstMarkdownH1(body)
	if title == "" {
		for _, kv := range kvPairs {
			if kv.k == "pretty_name" || kv.k == "title" {
				title = kv.v
				break
			}
		}
	}
	if title == "" {
		title = fallbackTitle
	}

	keepKeys := map[string]bool{
		"license": true, "pipeline_tag": true, "library_name": true, "base_model": true,
		"language": true, "tags": true, "datasets": true, "sdk": true,
		"task_categories": true, "size_categories": true,
	}
	var rows [][]string
	for _, kv := range kvPairs {
		if keepKeys[kv.k] {
			rows = append(rows, []string{"**" + kv.k + "**", kv.v})
			if len(rows) >= 10 {
				break
			}
		}
	}
	tableLines := ""
	if len(rows) > 0 {
		tableLines = formatDeclarativeGFMTable([]string{"Property", "Value"}, rows)
	}

	var parts []string
	if !strings.HasPrefix(body, "# ") {
		parts = append(parts, "# "+title)
	}
	if tableLines != "" {
		parts = append(parts, tableLines)
	}
	if body != "" {
		parts = append(parts, body)
	}
	var desc string
	for _, kv := range kvPairs {
		if kv.k == "description" || kv.k == "summary" {
			desc = kv.v
			break
		}
	}
	return &DeclarativeFormattedDoc{
		Title:       title,
		Description: desc,
		Markdown:    strings.TrimSpace(strings.Join(parts, "\n\n")),
	}
}

var _ = io.EOF
