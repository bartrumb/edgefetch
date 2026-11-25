package hubstore

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

type blobMeta struct {
	Namespace, BlobSHA, ContentSHA string
	ContentBytes, StoredBytes      int
	CreatedAt                      int64
}

type markdownArtifactRecord struct {
	ID, OwnerID, URL, Title, Namespace, BlobSHA, ContentSHA string
	IsPrivate                                               bool
	TotalChars                                              int
	Checkpoints                                             []int
	SliceCheckpoints                                        []extract.MarkdownSliceCheckpoint
	CreatedAt                                               int64
}

type scrapeCacheEntry struct {
	ETag       string
	StoredAtMs int64
	Payload    map[string]any
}

type hostTelemetryRecord struct {
	Host, LastOutcome, WAFVendor, ContentState, AdapterID string
	OKCount, BlockedCount, ChallengeCount, ErrorCount     int
	LastStatus                                            int
	TotalLatencyMs, LastLatencyMs, UpdatedAt              int64
}

type jobRecord struct {
	Kind, ID, OwnerID string
	Data              map[string]any
	UpdatedAt         int64
}

type persistedStoreState struct {
	Blobs       map[string]blobMeta
	Artifacts   map[string]*markdownArtifactRecord
	ScrapeCache map[string]*scrapeCacheEntry
	Hosts       map[string]*hostTelemetryRecord
	Jobs        map[string]*jobRecord
	Settings    map[string]string
	Events      []map[string]any
}

// Store manages persistent disk-backed or bounded in-memory Hub state and gzipped artifacts.
type Store struct {
	mu                       sync.RWMutex
	dataDir, statePath       string
	maxMemBytes, curMemBytes int
	memRing                  []string
	memBlobs                 map[string][]byte
	state                    persistedStoreState
}

func evictOldestEntry[V any](m map[string]V, capLimit int, tsOf func(V) int64) {
	for len(m) >= capLimit {
		oldestK, oldestT := "", int64(1<<63-1)
		for k, v := range m {
			if t := tsOf(v); t < oldestT {
				oldestT, oldestK = t, k
			}
		}
		if oldestK == "" {
			break
		}
		delete(m, oldestK)
	}
}

func canAccessTenant(ownerID, callerID string, callerIsOwner bool) bool {
	c := strings.TrimSpace(callerID)
	return callerIsOwner || (c != "" && ownerID == c)
}

// NewStore initializes a Hub store rooted at dataDir (or pure in-memory when dataDir == "").
func NewStore(dataDir string, maxMemBytes int) (*Store, error) {
	if maxMemBytes <= 0 {
		maxMemBytes = DefaultMaxMemBytes
	}
	s := &Store{maxMemBytes: maxMemBytes, memBlobs: make(map[string][]byte)}
	if trimmed := strings.TrimSpace(dataDir); trimmed != "" {
		clean := filepath.Clean(trimmed)
		if err := errors.Join(
			os.MkdirAll(filepath.Join(clean, "artifacts"), 0o700),
			os.MkdirAll(filepath.Join(clean, "state"), 0o700),
		); err != nil {
			return nil, fmt.Errorf("hubstore: create dirs: %w", err)
		}
		s.dataDir, s.statePath = clean, filepath.Join(clean, "state", "hub_state.json")
		raw, err := os.ReadFile(s.statePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("hubstore: read state: %w", err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &s.state); err != nil {
				return nil, fmt.Errorf("hubstore: unmarshal state: %w", err)
			}
		}
	}
	s.state.Blobs, s.state.Artifacts = nonNilMap(s.state.Blobs), nonNilMap(s.state.Artifacts)
	s.state.ScrapeCache, s.state.Hosts = nonNilMap(s.state.ScrapeCache), nonNilMap(s.state.Hosts)
	s.state.Jobs, s.state.Settings = nonNilMap(s.state.Jobs), nonNilMap(s.state.Settings)
	return s, nil
}

// DataDir returns the configured persistent root directory, or "" in memory-only mode.
func (s *Store) DataDir() string { return s.dataDir }

func (s *Store) saveStateLocked() error {
	if s.dataDir == "" {
		return nil
	}
	raw, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return atomicWriteFile(s.statePath, raw)
}

// PutGzipBlob verifies compressed + uncompressed SHA-256 digests and stores gzBytes under namespace.
func (s *Store) PutGzipBlob(namespace, blobSHA, contentSHA string, gzBytes []byte) error {
	ns, cleanBlob, cleanContent := sanitizeIdentifier(namespace, "default", 64), strings.ToLower(strings.TrimSpace(blobSHA)), strings.ToLower(strings.TrimSpace(contentSHA))
	if !isValidSHA256Hex(cleanBlob) || (cleanContent != "" && !isValidSHA256Hex(cleanContent)) {
		return ErrInvalidSHA256
	}
	if len(gzBytes) == 0 || len(gzBytes) > MaxArtifactStoredBytes {
		return ErrBlobTooLarge
	}
	if sha256Hex(gzBytes) != cleanBlob {
		return ErrBlobDigestMismatch
	}
	decoded, err := gunzipCapped(gzBytes, MaxArtifactContentBytes)
	if err != nil {
		return err
	}
	actualContent := sha256Hex(decoded)
	if cleanContent != "" && actualContent != cleanContent {
		return ErrContentHashMismatch
	}
	key := ns + "\x00" + cleanBlob
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dataDir != "" {
		if err := atomicWriteFile(filepath.Join(s.dataDir, "artifacts", ns, cleanBlob[:2], cleanBlob+".gz"), gzBytes); err != nil {
			return err
		}
	} else {
		if len(gzBytes) > s.maxMemBytes {
			return ErrBlobTooLarge
		}
		if prev, exists := s.memBlobs[key]; exists {
			s.curMemBytes -= len(prev)
			delete(s.memBlobs, key)
		}
		for s.curMemBytes+len(gzBytes) > s.maxMemBytes && len(s.memRing) > 0 {
			oldest := s.memRing[0]
			s.memRing = s.memRing[1:]
			s.curMemBytes -= len(s.memBlobs[oldest])
			delete(s.memBlobs, oldest)
			delete(s.state.Blobs, oldest)
		}
		cp := bytes.Clone(gzBytes)
		s.memBlobs[key], s.memRing, s.curMemBytes = cp, append(s.memRing, key), s.curMemBytes+len(cp)
	}
	s.state.Blobs[key] = blobMeta{ns, cleanBlob, actualContent, len(decoded), len(gzBytes), time.Now().UnixMilli()}
	return s.saveStateLocked()
}

// PutRawBlob compresses raw with gzip and persists the verified blob.
func (s *Store) PutRawBlob(namespace string, raw []byte) (blobSHA, contentSHA string, contentBytes, storedBytes int, err error) {
	if len(raw) > MaxArtifactContentBytes {
		return "", "", 0, 0, ErrBlobTooLarge
	}
	gzBytes, err := gzipCompressBytes(raw)
	if err != nil {
		return "", "", 0, 0, err
	}
	blobSHA, contentSHA = sha256Hex(gzBytes), sha256Hex(raw)
	if err := s.PutGzipBlob(namespace, blobSHA, contentSHA, gzBytes); err != nil {
		return "", "", 0, 0, err
	}
	return blobSHA, contentSHA, len(raw), len(gzBytes), nil
}

// GetGzipBlob retrieves and hash-verifies a stored gzip blob.
func (s *Store) GetGzipBlob(namespace, blobSHA string) ([]byte, bool, error) {
	ns, cleanBlob := sanitizeIdentifier(namespace, "default", 64), strings.ToLower(strings.TrimSpace(blobSHA))
	if !isValidSHA256Hex(cleanBlob) {
		return nil, false, ErrInvalidSHA256
	}
	if s.dataDir == "" {
		s.mu.RLock()
		b, ok := s.memBlobs[ns+"\x00"+cleanBlob]
		cp := bytes.Clone(b)
		s.mu.RUnlock()
		return cp, ok, nil
	}
	b, err := os.ReadFile(filepath.Join(s.dataDir, "artifacts", ns, cleanBlob[:2], cleanBlob+".gz"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if sha256Hex(b) != cleanBlob {
		return nil, false, ErrBlobDigestMismatch
	}
	return b, true, nil
}

// GetDecodedBlob retrieves, gunzips (capped at maxBytes), and verifies a stored blob.
func (s *Store) GetDecodedBlob(namespace, blobSHA string, maxBytes int) ([]byte, bool, error) {
	gzBytes, ok, err := s.GetGzipBlob(namespace, blobSHA)
	if !ok || err != nil {
		return nil, ok, err
	}
	decoded, err := gunzipCapped(gzBytes, maxBytes)
	if err != nil {
		return nil, false, err
	}
	s.mu.RLock()
	meta, hasMeta := s.state.Blobs[sanitizeIdentifier(namespace, "default", 64)+"\x00"+strings.ToLower(strings.TrimSpace(blobSHA))]
	s.mu.RUnlock()
	if hasMeta && meta.ContentSHA != "" && sha256Hex(decoded) != meta.ContentSHA {
		return nil, false, ErrContentHashMismatch
	}
	return decoded, true, nil
}

// PersistMarkdownArtifact sanitizes and stores a derived Markdown document + slice checkpoints.
func (s *Store) PersistMarkdownArtifact(ownerID, urlStr, title, markdown string, isPrivate bool) (artifactID string, totalChars int, checkpoints []int, err error) {
	cleanOwner, ownerNS := strings.TrimSpace(ownerID), "pub"
	if isPrivate {
		ownerNS = "priv:" + sanitizeIdentifier(cleanOwner, "owner", 64)
	}
	artifactID, cleanMD := sha256Hex([]byte(ownerNS+"\x00"+urlStr+"\x00"+markdown)), extract.SanitizeFullMarkdownDocumentForArtifact(markdown)
	sliceCps := extract.ComputeMarkdownSliceCheckpoints(cleanMD, 0)
	checkpoints = make([]int, len(sliceCps))
	for i, cp := range sliceCps {
		checkpoints[i] = cp.Pos
	}
	blobNS := sanitizeIdentifier("md_"+ownerNS, "md_pub", 64)
	blobSHA, contentSHA, _, _, err := s.PutRawBlob(blobNS, []byte(cleanMD))
	if err != nil {
		return "", 0, nil, err
	}
	s.mu.Lock()
	s.state.Artifacts[artifactID] = &markdownArtifactRecord{artifactID, cleanOwner, urlStr, extract.SanitizeScrapedMeta(title), blobNS, blobSHA, contentSHA, isPrivate, len(cleanMD), checkpoints, sliceCps, time.Now().UnixMilli()}
	err = s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		return "", 0, nil, err
	}
	return artifactID, len(cleanMD), slices.Clone(checkpoints), nil
}

// ReadArtifactPage returns a fence-safe sanitized Markdown slice page enforcing private tenant isolation.
func (s *Store) ReadArtifactPage(callerOwnerID string, callerIsOwner bool, artifactID string, offset, maxChars int) (page map[string]any, status int, errCode string) {
	cleanID := strings.ToLower(strings.TrimSpace(artifactID))
	if strings.HasPrefix(cleanID, "md:") && isValidSHA256Hex(cleanID[3:]) {
		cleanID = cleanID[3:]
	}
	if !isValidSHA256Hex(cleanID) {
		return nil, 404, "not_found"
	}
	s.mu.RLock()
	art, ok := s.state.Artifacts[cleanID]
	s.mu.RUnlock()
	if !ok || (art.IsPrivate && !canAccessTenant(art.OwnerID, callerOwnerID, callerIsOwner)) {
		return nil, 404, "not_found"
	}
	rawBytes, found, err := s.GetDecodedBlob(art.Namespace, art.BlobSHA, MaxArtifactContentBytes)
	if !found || err != nil {
		return nil, 404, "not_found"
	}
	if maxChars <= 0 {
		maxChars = DefaultArtifactPageSize
	}
	maxChars = min(maxChars, MaxArtifactPageSize)
	fullMD, sliceText := string(rawBytes), ""
	total := len(fullMD)
	actualStart := max(0, min(offset, total))
	for actualStart > 0 && actualStart < total && !utf8.RuneStart(fullMD[actualStart]) {
		actualStart--
	}
	end := min(total, actualStart+maxChars)
	if end < total {
		for ; end > actualStart && !utf8.RuneStart(fullMD[end]); end-- {
		}
		if end == actualStart {
			_, w := utf8.DecodeRuneInString(fullMD[actualStart:])
			end = min(total, actualStart+w)
		}
	}
	if actualStart < end {
		cps := art.SliceCheckpoints
		if len(cps) == 0 && total > 16384 {
			cps = extract.ComputeMarkdownSliceCheckpoints(fullMD, 0)
		}
		sliceText = extract.SanitizeMarkdownPageSlice(fullMD, actualStart, fullMD[actualStart:end], false, cps)
	}
	var nextOffset any
	if end < total {
		nextOffset = end
	}
	out := map[string]any{"ok": true, "id": cleanID, "artifactId": cleanID, "url": art.URL, "title": art.Title}
	out["offset"], out["maxChars"], out["totalChars"] = actualStart, maxChars, total
	out["content"], out["markdown"], out["nextOffset"], out["hasMore"] = sliceText, sliceText, nextOffset, end < total
	return out, 200, ""
}

func etagMatches(ifNoneMatch, targetETag string) bool {
	trimmed, bareTarget := strings.TrimSpace(ifNoneMatch), strings.Trim(targetETag, `"`)
	if trimmed == "" || targetETag == "" {
		return false
	}
	if trimmed == "*" {
		return true
	}
	for _, part := range strings.Split(trimmed, ",") {
		cand := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(part), "W/"), "w/"))
		if cand == targetETag || strings.Trim(cand, `"`) == bareTarget {
			return true
		}
	}
	return false
}

// PutScrapeCache stores a scrape response payload and returns its strong HTTP ETag.
func (s *Store) PutScrapeCache(cacheKey string, payload map[string]any) (etag string) {
	if strings.TrimSpace(cacheKey) == "" {
		return ""
	}
	cloned := cloneMap(payload)
	rawJSON, _ := json.Marshal(cloned)
	etag = fmt.Sprintf(`"ef-%s"`, sha256Hex(rawJSON)[:32])
	s.mu.Lock()
	if _, exists := s.state.ScrapeCache[cacheKey]; !exists {
		evictOldestEntry(s.state.ScrapeCache, MaxScrapeCacheEntries, func(v *scrapeCacheEntry) int64 { return v.StoredAtMs })
	}
	s.state.ScrapeCache[cacheKey] = &scrapeCacheEntry{etag, time.Now().UnixMilli(), cloned}
	_ = s.saveStateLocked()
	s.mu.Unlock()
	return etag
}

// GetScrapeCache looks up a cached scrape response honoring maxAgeMs and If-None-Match (304).
func (s *Store) GetScrapeCache(cacheKey string, maxAgeMs int64, ifNoneMatch string) (payload map[string]any, etag string, notModified bool, hit bool) {
	if cacheKey == "" || maxAgeMs <= 0 {
		return nil, "", false, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.state.ScrapeCache[cacheKey]
	if !ok || max(int64(0), time.Now().UnixMilli()-entry.StoredAtMs) > maxAgeMs {
		return nil, "", false, false
	}
	if etagMatches(ifNoneMatch, entry.ETag) {
		return nil, entry.ETag, true, true
	}
	return cloneMap(entry.Payload), entry.ETag, false, true
}

// RecordHostTelemetry records per-host outcome, WAF classification, adapter hit, and latency.
func (s *Store) RecordHostTelemetry(host, outcome string, status int, wafVendor, contentState, adapterID string, latencyMs int64) {
	clean := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(clean); err == nil {
		clean = h
	}
	if clean = strings.TrimRight(clean, "."); clean == "" {
		return
	}
	outNorm := strings.ToLower(strings.TrimSpace(outcome))
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.Hosts[clean]
	if !ok {
		evictOldestEntry(s.state.Hosts, MaxTrackedHostRecords, func(v *hostTelemetryRecord) int64 { return v.UpdatedAt })
		rec = &hostTelemetryRecord{Host: clean}
		s.state.Hosts[clean] = rec
	}
	switch outNorm {
	case "ok", "success":
		rec.OKCount++
	case "blocked", "waf_blocked", "forbidden":
		rec.BlockedCount++
	case "challenge", "captcha", "turnstile", "waf_challenge":
		rec.ChallengeCount++
	default:
		if outNorm == "" && status >= 200 && status < 400 {
			rec.OKCount, outNorm = rec.OKCount+1, "ok"
		} else {
			rec.ErrorCount, outNorm = rec.ErrorCount+1, cmp.Or(outNorm, "error")
		}
	}
	rec.LastStatus, rec.LastOutcome, rec.UpdatedAt = status, outNorm, time.Now().UnixMilli()
	rec.WAFVendor = cmp.Or(wafVendor, rec.WAFVendor)
	rec.ContentState = cmp.Or(contentState, rec.ContentState)
	rec.AdapterID = cmp.Or(adapterID, rec.AdapterID)
	if latencyMs > 0 {
		rec.TotalLatencyMs, rec.LastLatencyMs = rec.TotalLatencyMs+latencyMs, latencyMs
	}
	_ = s.saveStateLocked()
}

func (s *Store) queryHosts(limit, defLim, maxLim int, gapsOnly bool) []map[string]any {
	if limit <= 0 {
		limit = defLim
	}
	limit = min(limit, maxLim)
	s.mu.RLock()
	rows := make([]hostTelemetryRecord, 0, len(s.state.Hosts))
	for _, v := range s.state.Hosts {
		if !gapsOnly || (v.AdapterID == "" && (v.BlockedCount+v.ChallengeCount > 0 || v.OKCount >= 1)) {
			rows = append(rows, *v)
		}
	}
	s.mu.RUnlock()
	totalOf := func(r hostTelemetryRecord) int { return r.OKCount + r.BlockedCount + r.ChallengeCount + r.ErrorCount }
	slices.SortFunc(rows, func(a, b hostTelemetryRecord) int {
		if gapsOnly && (b.BlockedCount+b.ChallengeCount) != (a.BlockedCount+a.ChallengeCount) {
			return (b.BlockedCount + b.ChallengeCount) - (a.BlockedCount + a.ChallengeCount)
		}
		if d := totalOf(b) - totalOf(a); d != 0 {
			return d
		}
		if !gapsOnly && a.UpdatedAt != b.UpdatedAt {
			return int(b.UpdatedAt - a.UpdatedAt)
		}
		return strings.Compare(a.Host, b.Host)
	})
	rows = rows[:min(len(rows), limit)]
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		reqs := totalOf(r)
		m := map[string]any{"host": r.Host, "requests": reqs, "okCount": r.OKCount, "blockedCount": r.BlockedCount}
		m["challengeCount"], m["errorCount"], m["wafVendor"], m["contentState"], m["updatedAt"] = r.ChallengeCount, r.ErrorCount, r.WAFVendor, r.ContentState, r.UpdatedAt
		if !gapsOnly {
			avgLat := int64(0)
			if reqs > 0 {
				avgLat = r.TotalLatencyMs / int64(reqs)
			}
			m["lastStatus"], m["lastOutcome"], m["adapterId"], m["avgLatencyMs"] = r.LastStatus, r.LastOutcome, r.AdapterID, avgLat
		}
		out[i] = m
	}
	return out
}

// ListHosts returns host telemetry sorted by total requests descending.
func (s *Store) ListHosts(limit int) []map[string]any { return s.queryHosts(limit, 100, 1000, false) }

// ListHostGaps returns unadapted hosts ranked by WAF/challenge friction and request volume.
func (s *Store) ListHostGaps(limit int) []map[string]any { return s.queryHosts(limit, 50, 500, true) }

// PutJob stores or updates an async job (`batch_scrape`, `crawl`, `agent`, `catalog`).
func (s *Store) PutJob(kind, id, ownerID string, data map[string]any) {
	if kind != "" && id != "" {
		s.mu.Lock()
		s.state.Jobs[kind+"\x00"+id] = &jobRecord{kind, id, strings.TrimSpace(ownerID), cloneMap(data), time.Now().UnixMilli()}
		_ = s.saveStateLocked()
		s.mu.Unlock()
	}
}

// GetJob retrieves an async job enforcing strict tenant owner isolation.
func (s *Store) GetJob(kind, id, callerOwnerID string, callerIsOwner bool) (map[string]any, bool) {
	s.mu.RLock()
	rec, ok := s.state.Jobs[kind+"\x00"+id]
	var out map[string]any
	if ok && canAccessTenant(rec.OwnerID, callerOwnerID, callerIsOwner) {
		out = cloneMap(rec.Data)
	} else {
		ok = false
	}
	s.mu.RUnlock()
	return out, ok
}

// DeleteOrCancelJob marks an authorized async job as cancelled (`"status": "cancelled"`, `"cancelled": true`).
func (s *Store) DeleteOrCancelJob(kind, id, callerOwnerID string, callerIsOwner bool) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.Jobs[kind+"\x00"+id]
	if !ok || !canAccessTenant(rec.OwnerID, callerOwnerID, callerIsOwner) {
		return nil, false
	}
	rec.Data = nonNilMap(rec.Data)
	rec.Data["status"], rec.Data["cancelled"], rec.UpdatedAt = "cancelled", true, time.Now().UnixMilli()
	_ = s.saveStateLocked()
	return cloneMap(rec.Data), true
}

// GetSetting returns a Hub setting value by key.
func (s *Store) GetSetting(key string) (string, bool) {
	s.mu.RLock()
	v, ok := s.state.Settings[key]
	s.mu.RUnlock()
	return v, ok
}

// SetSetting updates and persists a Hub setting value.
func (s *Store) SetSetting(key, val string) {
	if strings.TrimSpace(key) != "" {
		s.mu.Lock()
		s.state.Settings[key] = val
		_ = s.saveStateLocked()
		s.mu.Unlock()
	}
}

// AppendEvent appends an operational event to the bounded ring (`MaxRetainedEvents`).
func (s *Store) AppendEvent(ev map[string]any) {
	cloned := nonNilMap(cloneMap(ev))
	if _, hasTS := cloned["ts"]; !hasTS {
		cloned["ts"] = time.Now().UnixMilli()
	}
	s.mu.Lock()
	if len(s.state.Events) >= MaxRetainedEvents {
		s.state.Events = append([]map[string]any(nil), s.state.Events[len(s.state.Events)-MaxRetainedEvents+1:]...)
	}
	s.state.Events = append(s.state.Events, cloned)
	_ = s.saveStateLocked()
	s.mu.Unlock()
}

// ListEvents returns up to limit most recent events (newest first).
func (s *Store) ListEvents(limit int) []map[string]any {
	if limit <= 0 {
		limit = 100
	}
	s.mu.RLock()
	n := len(s.state.Events)
	out := make([]map[string]any, min(limit, n))
	for i := range out {
		out[i] = cloneMap(s.state.Events[n-1-i])
	}
	s.mu.RUnlock()
	return out
}

// ClearEvents removes all retained operational events.
func (s *Store) ClearEvents() {
	s.mu.Lock()
	s.state.Events = make([]map[string]any, 0)
	_ = s.saveStateLocked()
	s.mu.Unlock()
}
