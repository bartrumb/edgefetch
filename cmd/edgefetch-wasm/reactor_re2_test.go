package main

import (
	"fmt"
	"math"
	"testing"
)

func compileRe2ForTest(t *testing.T, pat string) int32 {
	t.Helper()
	b := []byte(pat)
	efInPtr(uint32(len(b)))
	copy(wasmInBuf[:len(b)], b)
	id := efRe2Compile(uint32(len(b)))
	if id <= 0 {
		t.Fatalf("efRe2Compile(%q) returned %d", pat, id)
	}
	return id
}

func testRe2Subject(id int32, subj string) int32 {
	b := []byte(subj)
	efInPtr(uint32(len(b)))
	copy(wasmInBuf[:len(b)], b)
	return efRe2Test(id, uint32(len(b)))
}

func execRe2Subject(id int32, subj string) string {
	b := []byte(subj)
	efInPtr(uint32(len(b)))
	copy(wasmInBuf[:len(b)], b)
	n := efRe2Exec(id, uint32(len(b)))
	if n == 0 {
		return ""
	}
	return string(wasmOutBuf[:n])
}

func TestRe2RingSlotIDPreventsStaleOverwriteAndInt32Wraparound(t *testing.T) {
	firstID := compileRe2ForTest(t, `^allow-only-0000$`)
	if got := testRe2Subject(firstID, "allow-only-0000"); got != 1 {
		t.Fatalf("expected initial match=1, got %d", got)
	}

	// Compile re2RingCapacity additional patterns so `(firstID - 1) % re2RingCapacity` is overwritten.
	var overwroteID int32
	for i := 1; i <= re2RingCapacity; i++ {
		overwroteID = compileRe2ForTest(t, fmt.Sprintf(`^overwrite-pattern-%04d$`, i))
	}
	if (firstID-1)%re2RingCapacity != (overwroteID-1)%re2RingCapacity {
		t.Fatalf("expected same ring slot for %d and %d", firstID, overwroteID)
	}

	// Stale firstID MUST report -1 (evicted) on efRe2Test and 0 on efRe2Exec — NEVER match the overwriting pattern!
	if got := testRe2Subject(firstID, fmt.Sprintf("overwrite-pattern-%04d", re2RingCapacity)); got != -1 {
		t.Fatalf("expected evicted handle %d to return -1 after ring wraparound, got %d", firstID, got)
	}
	if out := execRe2Subject(firstID, fmt.Sprintf("overwrite-pattern-%04d", re2RingCapacity)); out != "" {
		t.Fatalf("expected evicted handle %d exec to return empty, got %q", firstID, out)
	}
	if got := testRe2Subject(overwroteID, fmt.Sprintf("overwrite-pattern-%04d", re2RingCapacity)); got != 1 {
		t.Fatalf("expected current slot owner %d to return 1, got %d", overwroteID, got)
	}

	// Simulate int32 counter wraparound (`re2NextID = math.MaxInt32`) -> wraps to 1 without false-matching prior high IDs.
	savedNext := re2NextID
	defer func() { re2NextID = savedNext }()
	re2NextID = math.MaxInt32
	maxID := compileRe2ForTest(t, `^max-int32-pattern$`)
	wrappedID := compileRe2ForTest(t, `^wrapped-id-one-pattern$`)
	if maxID != math.MaxInt32 || wrappedID != 1 {
		t.Fatalf("expected maxID=%d wrappedID=1, got maxID=%d wrappedID=%d", int32(math.MaxInt32), maxID, wrappedID)
	}
	if got := testRe2Subject(wrappedID, "wrapped-id-one-pattern"); got != 1 {
		t.Fatalf("expected wrappedID=1 to match its own pattern, got %d", got)
	}
	// Overwrite maxID's slot `(math.MaxInt32 - 1) % 1024 == 1022` and ensure maxID returns -1 even though re2NextID < maxID!
	slotTarget := int((maxID - 1) % re2RingCapacity)
	re2Table[slotTarget] = re2Slot{id: 42, re: lookupRe2Handle(wrappedID)}
	if got := testRe2Subject(maxID, "wrapped-id-one-pattern"); got != -1 {
		t.Fatalf("expected stale maxID after int32 wraparound to return -1, got %d", got)
	}
}
