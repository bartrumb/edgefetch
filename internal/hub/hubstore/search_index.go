package hubstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const (
	bm25K1           = 1.2
	bm25B            = 0.75
	targetChunkChars = 1000
)

// CollectionHit represents one BM25-ranked Markdown chunk hit from a local collection.
type CollectionHit struct {
	URL        string  `json:"url"`
	Title      string  `json:"title"`
	Snippet    string  `json:"snippet"`
	Score      float64 `json:"score"`
	ChunkIndex int     `json:"chunkIndex"`
	Collection string  `json:"collection"`
}

type persistedPageRecord struct {
	PageID            string   `json:"pageId"`
	URL               string   `json:"url"`
	Host              string   `json:"host"`
	Title             string   `json:"title"`
	DisplayCollection string   `json:"displayCollection"`
	Chunks            []string `json:"chunks"`
	UpdatedAt         int64    `json:"updatedAt"`
}

type persistedBM25State struct {
	Collections map[string]map[string]*persistedPageRecord `json:"collections"`
}

type bm25Posting struct {
	docIdx int
	tf     int
}

type indexedChunkDoc struct {
	pageID     string
	url        string
	host       string
	title      string
	collection string
	chunkIdx   int
	text       string
	docLen     int
}

type memCollectionIndex struct {
	docs        []indexedChunkDoc
	postings    map[string][]bm25Posting
	totalTokens int
}

// CollectionIndex implements a thread-safe, tenant-isolated pure-Go BM25 inverted index.
type CollectionIndex struct {
	mu          sync.RWMutex
	persistPath string
	pages       map[string]map[string]*persistedPageRecord
	built       map[string]*memCollectionIndex
}

// ResolveCollectionKey resolves a raw collection identifier into a tenant-isolated storage key and clean display name.
func ResolveCollectionKey(userID string, isOwner bool, rawCollection string) (storageKey, displayCollection string) {
	clean := sanitizeIdentifier(rawCollection, "default", 64)
	trimmedUser := strings.TrimSpace(userID)
	if isOwner || trimmedUser == "" || trimmedUser == "owner" {
		return clean, clean
	}
	safeUser := sanitizeIdentifier(trimmedUser, "member", 64)
	return "u:" + safeUser + ":" + clean, clean
}

// NewCollectionIndex initializes a BM25 collection index backed by `<dataDir>/state/collections_bm25.json` when dataDir != "".
func NewCollectionIndex(dataDir string) (*CollectionIndex, error) {
	idx := &CollectionIndex{
		pages: make(map[string]map[string]*persistedPageRecord),
		built: make(map[string]*memCollectionIndex),
	}
	trimmed := strings.TrimSpace(dataDir)
	if trimmed == "" {
		return idx, nil
	}
	cleanDir := filepath.Clean(trimmed)
	stateDir := filepath.Join(cleanDir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("hubstore: create bm25 state dir: %w", err)
	}
	idx.persistPath = filepath.Join(stateDir, "collections_bm25.json")
	raw, err := os.ReadFile(idx.persistPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return idx, nil
		}
		return nil, fmt.Errorf("hubstore: read bm25 index %s: %w", idx.persistPath, err)
	}
	if len(raw) > 0 {
		var st persistedBM25State
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("hubstore: decode bm25 index %s: %w", idx.persistPath, err)
		}
		if st.Collections != nil {
			idx.pages = st.Collections
		}
		for storageKey := range idx.pages {
			idx.rebuildCollectionLocked(storageKey)
		}
	}
	return idx, nil
}

func (idx *CollectionIndex) saveLocked() error {
	if idx.persistPath == "" {
		return nil
	}
	raw, err := json.Marshal(persistedBM25State{Collections: idx.pages})
	if err != nil {
		return err
	}
	return atomicWriteFile(idx.persistPath, raw)
}

func extractURLHostname(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.TrimRight(strings.ToLower(u.Hostname()), ".")
}

func tokenizeBM25(text string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tok := cur.String()
			if utf8.RuneCountInString(tok) >= 2 {
				tokens = append(tokens, tok)
			}
			cur.Reset()
		}
	}
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(unicode.ToLower(r))
		} else {
			flush()
		}
	}
	flush()
	return tokens
}

func splitMarkdownIntoChunks(md string, targetChars int) []string {
	clean := strings.TrimSpace(strings.ReplaceAll(md, "\r\n", "\n"))
	if clean == "" {
		return nil
	}
	if targetChars < 200 {
		targetChars = targetChunkChars
	}
	if len(clean) <= targetChars {
		return []string{clean}
	}

	lines := strings.Split(clean, "\n")
	var blocks []string
	var curBlock []string
	inFence := false
	curHeading := ""

	flushBlock := func() {
		if len(curBlock) == 0 {
			return
		}
		joined := strings.TrimSpace(strings.Join(curBlock, "\n"))
		curBlock = curBlock[:0]
		if joined != "" {
			blocks = append(blocks, joined)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			curBlock = append(curBlock, line)
			if !inFence {
				flushBlock()
			}
			continue
		}
		if inFence {
			curBlock = append(curBlock, line)
			continue
		}
		if trimmed == "" {
			flushBlock()
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			flushBlock()
			curHeading = trimmed
			curBlock = append(curBlock, line)
			continue
		}
		curBlock = append(curBlock, line)
		_ = curHeading
	}
	flushBlock()

	var chunks []string
	var acc strings.Builder
	activeHeading := ""

	emitAcc := func() {
		s := strings.TrimSpace(acc.String())
		acc.Reset()
		if s != "" {
			chunks = append(chunks, s)
		}
	}

	for _, b := range blocks {
		if strings.HasPrefix(b, "#") {
			firstNl := strings.IndexByte(b, '\n')
			if firstNl < 0 {
				activeHeading = b
			} else {
				activeHeading = strings.TrimSpace(b[:firstNl])
			}
		}
		if len(b) > targetChars {
			emitAcc()
			rem := b
			for len(rem) > targetChars {
				cut := targetChars
				for cut > 0 && !utf8.RuneStart(rem[cut]) {
					cut--
				}
				minCut := targetChars / 2
				if nl := strings.LastIndexByte(rem[:cut], '\n'); nl >= minCut {
					cut = nl
				} else if sp := strings.LastIndexByte(rem[:cut], ' '); sp >= minCut {
					cut = sp
				}
				piece := strings.TrimSpace(rem[:cut])
				if piece != "" {
					if activeHeading != "" && !strings.HasPrefix(piece, "#") {
						chunks = append(chunks, activeHeading+"\n\n"+piece)
					} else {
						chunks = append(chunks, piece)
					}
				}
				rem = strings.TrimSpace(rem[cut:])
			}
			if rem != "" {
				if activeHeading != "" && !strings.HasPrefix(rem, "#") {
					acc.WriteString(activeHeading + "\n\n" + rem)
				} else {
					acc.WriteString(rem)
				}
			}
			continue
		}
		addLen := len(b)
		if acc.Len() > 0 {
			addLen += 2
		}
		if acc.Len() > 0 && acc.Len()+addLen > targetChars {
			// Avoid stranding a standalone heading without its following paragraph.
			curStr := strings.TrimSpace(acc.String())
			if !strings.HasPrefix(curStr, "#") || strings.Contains(curStr, "\n") {
				emitAcc()
				if activeHeading != "" && !strings.HasPrefix(b, "#") {
					acc.WriteString(activeHeading + "\n\n")
				}
			}
		}
		if acc.Len() > 0 && !strings.HasSuffix(acc.String(), "\n\n") {
			acc.WriteString("\n\n")
		}
		acc.WriteString(b)
	}
	emitAcc()
	return chunks
}

func (idx *CollectionIndex) rebuildCollectionLocked(storageKey string) {
	pageMap := idx.pages[storageKey]
	if len(pageMap) == 0 {
		delete(idx.built, storageKey)
		return
	}
	pageKeys := make([]string, 0, len(pageMap))
	for k := range pageMap {
		pageKeys = append(pageKeys, k)
	}
	slices.Sort(pageKeys)

	mc := &memCollectionIndex{
		postings: make(map[string][]bm25Posting),
	}
	for _, pk := range pageKeys {
		pr := pageMap[pk]
		for ci, chText := range pr.Chunks {
			docIdx := len(mc.docs)
			titleToks := tokenizeBM25(pr.Title)
			bodyToks := tokenizeBM25(chText)
			tfMap := make(map[string]int, len(titleToks)+len(bodyToks))
			for _, t := range titleToks {
				tfMap[t] += 2
			}
			for _, t := range bodyToks {
				tfMap[t]++
			}
			docLen := len(titleToks)*2 + len(bodyToks)
			if docLen == 0 {
				docLen = 1
			}
			mc.totalTokens += docLen
			mc.docs = append(mc.docs, indexedChunkDoc{
				pageID:     pr.PageID,
				url:        pr.URL,
				host:       pr.Host,
				title:      pr.Title,
				collection: pr.DisplayCollection,
				chunkIdx:   ci,
				text:       chText,
				docLen:     docLen,
			})
			for tok, tf := range tfMap {
				mc.postings[tok] = append(mc.postings[tok], bm25Posting{docIdx: docIdx, tf: tf})
			}
		}
	}
	idx.built[storageKey] = mc
}

// ReplacePageChunks sanitizes title & Markdown, splits into ~1,000-char chunks, and atomically replaces prior chunks for (storageKey, pageURL).
func (idx *CollectionIndex) ReplacePageChunks(storageKey, displayCollection, pageURL, title, markdown string) (chunkCount int, pageID string) {
	if strings.TrimSpace(storageKey) == "" {
		storageKey = "default"
	}
	if strings.TrimSpace(displayCollection) == "" {
		displayCollection = "default"
	}
	cleanURL := strings.TrimSpace(pageURL)
	pageID = sha256Hex([]byte(storageKey + "\x00" + cleanURL))
	cleanTitle := extract.SanitizeScrapedMeta(title)
	cleanMD := extract.SanitizeScrapedMarkdown(markdown)
	chunks := splitMarkdownIntoChunks(cleanMD, targetChunkChars)
	if len(chunks) == 0 && cleanTitle != "" {
		chunks = []string{cleanTitle}
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()
	collPages, ok := idx.pages[storageKey]
	if !ok {
		collPages = make(map[string]*persistedPageRecord)
		idx.pages[storageKey] = collPages
	}
	if len(chunks) == 0 {
		delete(collPages, pageID)
	} else {
		collPages[pageID] = &persistedPageRecord{
			PageID:            pageID,
			URL:               cleanURL,
			Host:              extractURLHostname(cleanURL),
			Title:             cleanTitle,
			DisplayCollection: displayCollection,
			Chunks:            chunks,
			UpdatedAt:         time.Now().UnixMilli(),
		}
	}
	idx.rebuildCollectionLocked(storageKey)
	_ = idx.saveLocked()
	return len(chunks), pageID
}

func buildHitSnippet(text string, queryTerms []string) string {
	collapsed := strings.Join(strings.Fields(text), " ")
	if len(collapsed) <= 240 {
		return extract.SanitizeScrapedMeta(collapsed)
	}
	lower := strings.ToLower(collapsed)
	bestIdx := -1
	for _, qt := range queryTerms {
		if pos := strings.Index(lower, qt); pos >= 0 && (bestIdx < 0 || pos < bestIdx) {
			bestIdx = pos
		}
	}
	start := 0
	if bestIdx > 60 {
		start = bestIdx - 60
		for start > 0 && !utf8.RuneStart(collapsed[start]) {
			start--
		}
		if sp := strings.IndexByte(collapsed[start:], ' '); sp > 0 && sp < 24 {
			start += sp + 1
		}
	}
	end := min(len(collapsed), start+240)
	for end > start && end < len(collapsed) && !utf8.RuneStart(collapsed[end]) {
		end--
	}
	snippet := collapsed[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(collapsed) {
		snippet = snippet + "..."
	}
	return extract.SanitizeScrapedMeta(snippet)
}

// Search ranks chunks in storageKey via BM25 (`k1=1.2`, `b=0.75`) with prefix-match fallback and optional host filtering.
func (idx *CollectionIndex) Search(storageKey, query string, limit int, hostFilter string) []CollectionHit {
	if strings.TrimSpace(storageKey) == "" {
		storageKey = "default"
	}
	if limit <= 0 {
		limit = 10
	} else if limit > 100 {
		limit = 100
	}
	rawTerms := tokenizeBM25(query)
	if len(rawTerms) == 0 {
		return []CollectionHit{}
	}
	seenQ := make(map[string]bool, len(rawTerms))
	qTerms := make([]string, 0, min(16, len(rawTerms)))
	for _, t := range rawTerms {
		if !seenQ[t] {
			seenQ[t] = true
			qTerms = append(qTerms, t)
			if len(qTerms) >= 16 {
				break
			}
		}
	}

	wantHost := strings.TrimRight(strings.ToLower(strings.TrimSpace(hostFilter)), ".")
	if strings.Contains(wantHost, "://") {
		wantHost = extractURLHostname(wantHost)
	}

	idx.mu.RLock()
	mc := idx.built[storageKey]
	if mc == nil || len(mc.docs) == 0 {
		idx.mu.RUnlock()
		return []CollectionHit{}
	}
	totalDocs := len(mc.docs)
	avgDocLen := float64(mc.totalTokens) / float64(totalDocs)
	if avgDocLen <= 0 {
		avgDocLen = 1
	}

	scores := make(map[int]float64)
	for _, qt := range qTerms {
		if plist, ok := mc.postings[qt]; ok && len(plist) > 0 {
			df := float64(len(plist))
			idf := math.Log(1.0 + (float64(totalDocs)-df+0.5)/(df+0.5))
			for _, p := range plist {
				dl := float64(mc.docs[p.docIdx].docLen)
				tf := float64(p.tf)
				tfNorm := (tf * (bm25K1 + 1.0)) / (tf + bm25K1*(1.0-bm25B+bm25B*(dl/avgDocLen)))
				scores[p.docIdx] += idf * tfNorm
			}
			continue
		}
		// Prefix match fallback when exact postings are empty.
		mergedTF := make(map[int]int)
		for tok, plist := range mc.postings {
			if strings.HasPrefix(tok, qt) {
				for _, p := range plist {
					mergedTF[p.docIdx] += p.tf
				}
			}
		}
		if len(mergedTF) > 0 {
			df := float64(len(mergedTF))
			idf := 0.85 * math.Log(1.0+(float64(totalDocs)-df+0.5)/(df+0.5))
			for docIdx, tfInt := range mergedTF {
				dl := float64(mc.docs[docIdx].docLen)
				tf := float64(tfInt)
				tfNorm := (tf * (bm25K1 + 1.0)) / (tf + bm25K1*(1.0-bm25B+bm25B*(dl/avgDocLen)))
				scores[docIdx] += idf * tfNorm
			}
		}
	}

	hits := make([]CollectionHit, 0, len(scores))
	for docIdx, sc := range scores {
		if sc <= 0 {
			continue
		}
		d := mc.docs[docIdx]
		if wantHost != "" && d.host != wantHost && !strings.HasSuffix(d.host, "."+wantHost) {
			continue
		}
		hits = append(hits, CollectionHit{
			URL:        d.url,
			Title:      d.title,
			Snippet:    buildHitSnippet(d.text, qTerms),
			Score:      math.Round(sc*10000) / 10000,
			ChunkIndex: d.chunkIdx,
			Collection: d.collection,
		})
	}
	idx.mu.RUnlock()

	slices.SortFunc(hits, func(a, b CollectionHit) int {
		if a.Score != b.Score {
			if b.Score > a.Score {
				return 1
			}
			return -1
		}
		if c := strings.Compare(a.URL, b.URL); c != 0 {
			return c
		}
		return a.ChunkIndex - b.ChunkIndex
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}
