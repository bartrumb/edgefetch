package catalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// FetchRequest describes a polite single-URL outbound request for native Go `--mode=hub` catalog runs.
type FetchRequest struct {
	URL       string
	Kind      string // "json" | "text"
	Accept    string
	MaxBytes  int
	TimeoutMs int
}

// FetchResponse holds a transport-agnostic response returned by FetchFunc (no net/http dependency).
type FetchResponse struct {
	Status       int
	Outcome      string
	Problem      string
	Headers      map[string]string
	Body         string
	FinalURL     string
	RetryAfterMs *float64
}

// FetchFunc executes a polite, robots/SSRF-checked fetch for Phase 3's Go `--mode=hub`.
type FetchFunc func(ctx context.Context, req FetchRequest) (*FetchResponse, error)

// StoredCatalogRun represents an in-memory catalog run entry managed by CatalogStore.
type StoredCatalogRun struct {
	UserID           string
	Summary          CatalogStatusSummary
	Hashes           *SnapshotHashBundle
	HashesBytes      int
	HashesArtifactID string
	Records          []CatalogRecord // nil when evicted or flushed to object storage
	HasRecords       bool
	RetainedBytes    int
}

// MemoryUsageStats reports live memory and reload concurrency counters for CatalogStore.
type MemoryUsageStats struct {
	RunsCount         int
	RecordsBytes      int
	HashesBytes       int
	ReloadCacheBytes  int
	TotalBytes        int
	MaxBytes          int
	ActiveReloads     int
	PeakReloadsSeen   int
	ActiveGlobalRuns  int
	ActiveNonOwnerRun int
}

type reloadCacheItem struct {
	key     string
	records []CatalogRecord
	bytes   int
}

// CatalogStore manages bounded 32 MiB multi-tenant LRU state, per-principal/owner concurrency slots,
// and singleflight `<= 2` artifact reload admission for Phase 3's native Go `--mode=hub`.
type CatalogStore struct {
	mu              sync.Mutex
	order           []string
	runs            map[string]*StoredCatalogRun
	reloadOrder     []string
	reloadCache     map[string]*reloadCacheItem
	activeByBucket  map[string]int
	activeGlobal    int
	activeNonOwner  int
	reloadSem       chan struct{}
	activeReloads   int
	peakReloadsSeen int
	inflightMu      sync.Mutex
	inflightReloads map[string]*inflightCall
	currencyCache   map[string]cachedOriginCurrency
}

type cachedOriginCurrency struct {
	currency  string
	expiresAt time.Time
}

type inflightCall struct {
	done chan struct{}
	recs []CatalogRecord
	err  error
}

// NewCatalogStore creates an isolated bounded CatalogStore (`32 MiB` global ceiling, `<= 2` reload semaphore).
func NewCatalogStore() *CatalogStore {
	return &CatalogStore{
		runs:            make(map[string]*StoredCatalogRun),
		reloadCache:     make(map[string]*reloadCacheItem),
		activeByBucket:  make(map[string]int),
		reloadSem:       make(chan struct{}, MaxConcurrentR2Reloads),
		inflightReloads: make(map[string]*inflightCall),
		currencyCache:   make(map[string]cachedOriginCurrency),
	}
}

// GenerateCatalogID produces a `cat_<16hex>` run identifier.
func GenerateCatalogID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "cat_fallback00000001"
	}
	return "cat_" + hex.EncodeToString(b[:])
}

// AcquireConcurrencySlot enforces per-principal (`<= 2`), non-owner (`<= 6`), and global (`<= 8`) run caps,
// reserving 2 global slots exclusively for `owner`.
func (s *CatalogStore) AcquireConcurrencySlot(tenant CatalogTenantInfo) (func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	curForBucket := s.activeByBucket[tenant.ConcurrencyBucketKey]
	nonOwnerFull := !tenant.IsOwner && s.activeNonOwner >= MaxConcurrentCatalogNonOwner
	if s.activeGlobal >= MaxConcurrentCatalogGlobal || nonOwnerFull || curForBucket >= MaxConcurrentCatalogPerPrincipal {
		return nil, false
	}
	s.activeGlobal++
	if !tenant.IsOwner {
		s.activeNonOwner++
	}
	s.activeByBucket[tenant.ConcurrencyBucketKey] = curForBucket + 1

	var once sync.Once
	release := func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.activeGlobal > 0 {
				s.activeGlobal--
			}
			if !tenant.IsOwner && s.activeNonOwner > 0 {
				s.activeNonOwner--
			}
			cur := s.activeByBucket[tenant.ConcurrencyBucketKey]
			if cur <= 1 {
				delete(s.activeByBucket, tenant.ConcurrencyBucketKey)
			} else {
				s.activeByBucket[tenant.ConcurrencyBucketKey] = cur - 1
			}
		})
	}
	return release, true
}

// RememberRun inserts or updates a catalog run and enforces per-user fair-share + global 32 MiB LRU caps.
func (s *CatalogStore) RememberRun(entry StoredCatalogRun) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := entry.Summary.CatalogID
	entry.HashesBytes = ApproxHashBundleBytes(entry.Hashes)
	if _, exists := s.runs[id]; exists {
		s.removeOrderKeyLocked(id)
	}
	cp := entry
	s.runs[id] = &cp
	s.order = append(s.order, id)
	s.enforceMemoryBudgetLocked(id)
}

func (s *CatalogStore) removeOrderKeyLocked(id string) {
	for i, k := range s.order {
		if k == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

func (s *CatalogStore) enforceMemoryBudgetLocked(protectedID string) {
	prot := s.runs[protectedID]
	if prot != nil && prot.UserID != "" {
		uid := prot.UserID
		perUserCachedCap := MaxCachedCatalogRunsPerUser
		perUserByteCap := MaxPerUserCatalogBytes
		if uid == "owner" {
			perUserCachedCap = MaxCachedCatalogRunsPerUser * 2
			perUserByteCap = MaxGlobalCatalogBytes
		}
		userRuns, userCached, userBytes := 0, 0, 0
		for _, id := range s.order {
			v := s.runs[id]
			if v == nil || v.UserID != uid {
				continue
			}
			userRuns++
			if v.HasRecords {
				userCached++
				userBytes += v.RetainedBytes
			}
			if v.Hashes != nil {
				userBytes += v.HashesBytes
			}
		}
		if userCached > perUserCachedCap || userBytes > perUserByteCap {
			for _, id := range s.order {
				v := s.runs[id]
				if id == protectedID || v == nil || v.UserID != uid || !v.HasRecords {
					continue
				}
				userBytes -= v.RetainedBytes
				userCached--
				v.Records = nil
				v.HasRecords = false
				v.RetainedBytes = 0
				if userCached <= perUserCachedCap && userBytes <= perUserByteCap {
					break
				}
			}
		}
		if userBytes > perUserByteCap {
			for _, id := range s.order {
				v := s.runs[id]
				if id == protectedID || v == nil || v.UserID != uid || v.Hashes == nil {
					continue
				}
				userBytes -= v.HashesBytes
				v.Hashes = nil
				v.HashesBytes = 0
				if userBytes <= perUserByteCap {
					break
				}
			}
		}
		if userRuns > MaxCompactHistoryRunsPerUser {
			var kept []string
			for _, id := range s.order {
				v := s.runs[id]
				if userRuns > MaxCompactHistoryRunsPerUser && id != protectedID && v != nil && v.UserID == uid {
					delete(s.runs, id)
					userRuns--
					continue
				}
				kept = append(kept, id)
			}
			s.order = kept
		}
	}

	cachedBodyRuns := 0
	globalBytes := 0
	cachedByUser := make(map[string]int)
	bytesByUser := make(map[string]int)
	for _, id := range s.order {
		v := s.runs[id]
		if v == nil {
			continue
		}
		if v.HasRecords {
			cachedBodyRuns++
			globalBytes += v.RetainedBytes
			cachedByUser[v.UserID]++
			bytesByUser[v.UserID] += v.RetainedBytes
		}
		if v.Hashes != nil {
			globalBytes += v.HashesBytes
			bytesByUser[v.UserID] += v.HashesBytes
		}
	}
	for _, rc := range s.reloadCache {
		globalBytes += rc.bytes
	}

	for globalBytes > MaxGlobalCatalogBytes && len(s.reloadOrder) > 0 {
		oldest := s.reloadOrder[0]
		s.reloadOrder = s.reloadOrder[1:]
		if rc, ok := s.reloadCache[oldest]; ok {
			globalBytes -= rc.bytes
			delete(s.reloadCache, oldest)
		}
	}

	for cachedBodyRuns > MaxCachedCatalogRuns || globalBytes > MaxGlobalCatalogBytes {
		heaviestUser := ""
		maxCnt := 1
		for uid, cnt := range cachedByUser {
			if cnt > maxCnt {
				maxCnt = cnt
				heaviestUser = uid
			}
		}
		var victim *StoredCatalogRun
		for _, id := range s.order {
			v := s.runs[id]
			if id == protectedID || v == nil || !v.HasRecords {
				continue
			}
			if heaviestUser != "" && v.UserID != heaviestUser {
				continue
			}
			victim = v
			break
		}
		if victim == nil {
			for _, id := range s.order {
				v := s.runs[id]
				if id != protectedID && v != nil && v.HasRecords {
					victim = v
					break
				}
			}
		}
		if victim == nil {
			break
		}
		globalBytes -= victim.RetainedBytes
		cachedBodyRuns--
		cachedByUser[victim.UserID]--
		bytesByUser[victim.UserID] -= victim.RetainedBytes
		victim.Records = nil
		victim.HasRecords = false
		victim.RetainedBytes = 0
	}

	for globalBytes > MaxGlobalCatalogBytes {
		heaviestUser := ""
		maxB := 0
		for uid, b := range bytesByUser {
			if b > maxB {
				maxB = b
				heaviestUser = uid
			}
		}
		var victim *StoredCatalogRun
		for _, id := range s.order {
			v := s.runs[id]
			if id == protectedID || v == nil || v.Hashes == nil {
				continue
			}
			if heaviestUser != "" && v.UserID != heaviestUser {
				continue
			}
			victim = v
			break
		}
		if victim == nil {
			for _, id := range s.order {
				v := s.runs[id]
				if id != protectedID && v != nil && v.Hashes != nil {
					victim = v
					break
				}
			}
		}
		if victim == nil {
			break
		}
		globalBytes -= victim.HashesBytes
		bytesByUser[victim.UserID] -= victim.HashesBytes
		victim.Hashes = nil
		victim.HashesBytes = 0
	}

	if globalBytes > MaxGlobalCatalogBytes && prot != nil {
		if prot.HasRecords && prot.Summary.ArtifactID != "" {
			globalBytes -= prot.RetainedBytes
			prot.Records = nil
			prot.HasRecords = false
			prot.RetainedBytes = 0
		}
		if globalBytes > MaxGlobalCatalogBytes && prot.Hashes != nil {
			prot.Hashes = nil
			prot.HashesBytes = 0
		}
	}

	for len(s.order) > MaxCompactHistoryRuns {
		victimIdx := -1
		for i, id := range s.order {
			if id != protectedID {
				victimIdx = i
				break
			}
		}
		if victimIdx < 0 {
			break
		}
		vid := s.order[victimIdx]
		s.order = append(s.order[:victimIdx], s.order[victimIdx+1:]...)
		delete(s.runs, vid)
	}
}

// GetRun looks up a tenant-owned run in memory.
func (s *CatalogStore) GetRun(catalogID, ownerKey string) (*StoredCatalogRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[catalogID]
	if !ok || r.UserID != ownerKey {
		return nil, false
	}
	cp := *r
	return &cp, true
}

// FindPreviousCompleteBaseline returns the latest non-shrunk `complete` run for `(userID, origin, collection)`.
func (s *CatalogStore) FindPreviousCompleteBaseline(userID, origin, collection, excludeCatalogID string) (int, *SnapshotHashBundle, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.order) - 1; i >= 0; i-- {
		r := s.runs[s.order[i]]
		if r == nil || r.UserID != userID || r.Summary.CatalogID == excludeCatalogID {
			continue
		}
		if r.Summary.Origin == origin && r.Summary.Collection == collection && r.Summary.Status == StatusComplete && r.Summary.Warning != "shrink" {
			return r.Summary.Products, r.Hashes, true
		}
	}
	return 0, nil, false
}

// ReloadRecordsCoalesced coalesces concurrent cold artifact reads onto 1 singleflight call and bounds
// concurrent decompressions to `<= 2` (`MaxConcurrentR2Reloads`).
func (s *CatalogStore) ReloadRecordsCoalesced(ctx context.Context, artifactID string, loader func(context.Context) ([]byte, error)) ([]CatalogRecord, error) {
	s.mu.Lock()
	if hit, ok := s.reloadCache[artifactID]; ok {
		for i, k := range s.reloadOrder {
			if k == artifactID {
				s.reloadOrder = append(s.reloadOrder[:i], s.reloadOrder[i+1:]...)
				break
			}
		}
		s.reloadOrder = append(s.reloadOrder, artifactID)
		recs := hit.records
		s.mu.Unlock()
		return recs, nil
	}
	s.mu.Unlock()

	s.inflightMu.Lock()
	if call, exists := s.inflightReloads[artifactID]; exists {
		s.inflightMu.Unlock()
		select {
		case <-call.done:
			return call.recs, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	s.inflightReloads[artifactID] = call
	s.inflightMu.Unlock()

	defer func() {
		close(call.done)
		s.inflightMu.Lock()
		delete(s.inflightReloads, artifactID)
		s.inflightMu.Unlock()
	}()

	select {
	case s.reloadSem <- struct{}{}:
	case <-ctx.Done():
		call.err = ctx.Err()
		return nil, call.err
	}
	s.mu.Lock()
	s.activeReloads++
	if s.activeReloads > s.peakReloadsSeen {
		s.peakReloadsSeen = s.activeReloads
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.activeReloads > 0 {
			s.activeReloads--
		}
		s.mu.Unlock()
		<-s.reloadSem
	}()

	rawBytes, err := loader(ctx)
	if err != nil {
		call.err = err
		return nil, err
	}
	if rawBytes == nil {
		return nil, errors.New("artifact_not_found")
	}
	plainBytes, err := DecompressGzipBounded(rawBytes, MaxR2DecompressedBytes)
	if err != nil {
		call.err = err
		return nil, err
	}
	recs, approxBytes := ParseRecordsNDJSON(string(plainBytes))
	call.recs = recs

	if len(recs) > 0 && approxBytes <= MaxR2CacheableArtifactBytes {
		s.mu.Lock()
		s.reloadCache[artifactID] = &reloadCacheItem{key: artifactID, records: recs, bytes: approxBytes}
		s.reloadOrder = append(s.reloadOrder, artifactID)
		s.enforceMemoryBudgetLocked("")
		s.mu.Unlock()
	}
	return recs, nil
}

// MemoryStats returns live memory and concurrency usage metrics.
func (s *CatalogStore) MemoryStats() MemoryUsageStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	recBytes, hashBytes, reloadBytes := 0, 0, 0
	for _, r := range s.runs {
		if r.HasRecords {
			recBytes += r.RetainedBytes
		}
		if r.Hashes != nil {
			hashBytes += r.HashesBytes
		}
	}
	for _, rc := range s.reloadCache {
		reloadBytes += rc.bytes
	}
	return MemoryUsageStats{
		RunsCount:         len(s.runs),
		RecordsBytes:      recBytes,
		HashesBytes:       hashBytes,
		ReloadCacheBytes:  reloadBytes,
		TotalBytes:        recBytes + hashBytes + reloadBytes,
		MaxBytes:          MaxGlobalCatalogBytes,
		ActiveReloads:     s.activeReloads,
		PeakReloadsSeen:   s.peakReloadsSeen,
		ActiveGlobalRuns:  s.activeGlobal,
		ActiveNonOwnerRun: s.activeNonOwner,
	}
}

// GetCachedOriginCurrency returns a cached 3-letter ISO currency (or negative `""` probe) for a Shopify origin.
func (s *CatalogStore) GetCachedOriginCurrency(origin string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ent, ok := s.currencyCache[origin]
	if !ok {
		return "", false
	}
	if !now.Before(ent.expiresAt) {
		delete(s.currencyCache, origin)
		return "", false
	}
	return ent.currency, true
}

// SetCachedOriginCurrency stores a positive or negative Shopify origin currency lookup in a bounded (`<= 256`) cache.
func (s *CatalogStore) SetCachedOriginCurrency(origin, currency string, ttl time.Duration, now time.Time) {
	if origin == "" || ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.currencyCache[origin]; !exists && len(s.currencyCache) >= 256 {
		for k := range s.currencyCache {
			delete(s.currencyCache, k)
			break
		}
	}
	s.currencyCache[origin] = cachedOriginCurrency{
		currency:  currency,
		expiresAt: now.Add(ttl),
	}
}
